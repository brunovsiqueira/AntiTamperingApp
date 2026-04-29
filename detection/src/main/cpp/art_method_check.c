#include <jni.h>
#include <android/log.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>

#define TAG "ArtMethodCheck"

/*
 * ArtMethod hotness_count inspection for virtual container detection.
 *
 * ArtMethod struct layout (stable across Android 12–16, API 31–36):
 *   Offset 0:  declaring_class_    (GcRoot<Class> = uint32_t, 4 bytes)
 *   Offset 4:  access_flags_       (atomic<uint32_t>, 4 bytes)
 *   Offset 8:  dex_method_index_   (uint32_t, 4 bytes)
 *   Offset 12: method_index_       (uint16_t, 2 bytes)
 *   Offset 14: hotness_count_      (uint16_t, 2 bytes)  <-- target field
 *
 * Sources:
 *   - AOSP art_method.h: https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h
 *   - Mascara paper: https://arxiv.org/abs/2010.10639
 *   - Matrioska (ACSAC 2024): https://ieeexplore.ieee.org/document/10917506/
 *
 * Safety: jmethodID may not always be a direct pointer to ArtMethod
 * (can be indirect/encoded on some OEM ART builds). We use a SIGSEGV
 * signal handler to catch invalid memory reads and return RESULT_ERROR
 * instead of crashing. This pattern is used by AntiVirtualApp and
 * similar production libraries (https://github.com/nicehash/AntiVirtualApp).
 */

#define HOTNESS_COUNT_OFFSET 14

// Source: AOSP art_method.h, verified for API 31-36
#define RESULT_VIRTUAL_CONTAINER_DETECTED 1
#define RESULT_LOOKS_NORMAL 0
#define RESULT_ERROR -1

// Thread-local jump buffer for signal recovery
static __thread sigjmp_buf s_jump_buf;
static __thread volatile int s_in_check = 0;

static struct sigaction s_old_action;

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    if (s_in_check) {
        // We caused the segfault during our pointer read — recover gracefully
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "SIGSEGV caught during ArtMethod read (addr=%p) — returning error safely",
            info ? info->si_addr : NULL);
        siglongjmp(s_jump_buf, 1);
    }

    // Not our fault — call the previous handler
    if (s_old_action.sa_flags & SA_SIGINFO) {
        if (s_old_action.sa_sigaction) {
            s_old_action.sa_sigaction(sig, info, ucontext);
        }
    } else {
        if (s_old_action.sa_handler != SIG_DFL && s_old_action.sa_handler != SIG_IGN) {
            s_old_action.sa_handler(sig);
        } else {
            // Re-raise with default handler
            signal(sig, SIG_DFL);
            raise(sig);
        }
    }
}

/**
 * Safely reads a uint16_t from a potentially invalid memory address.
 * Returns the value on success, or -1 if the read caused a SIGSEGV.
 */
static int32_t safe_read_uint16(const void *addr) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = sigsegv_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);

    // Install our handler, saving the old one
    if (sigaction(SIGSEGV, &action, &s_old_action) != 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Failed to install signal handler");
        return -1;
    }

    int32_t result;
    s_in_check = 1;

    if (sigsetjmp(s_jump_buf, 1) == 0) {
        // Normal path: try to read the value
        result = (int32_t)(*((const volatile uint16_t *)addr));
    } else {
        // Recovery path: SIGSEGV was caught
        result = -1;
    }

    s_in_check = 0;

    // Restore the old handler
    sigaction(SIGSEGV, &s_old_action, NULL);

    return result;
}

JNIEXPORT jint JNICALL
Java_com_bruno_antitamperingapp_detection_detectors_ArtMethodChecker_checkHotnessCount(
    JNIEnv *env, jobject thiz, jobject method_obj) {

    if (method_obj == NULL) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Method object is null");
        return RESULT_ERROR;
    }

    jmethodID method_id = (*env)->FromReflectedMethod(env, method_obj);
    if (method_id == NULL) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "FromReflectedMethod returned null");
        return RESULT_ERROR;
    }

    // Debug: log the raw pointer value to understand the layout
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "jmethodID raw pointer: %p (decimal: %lu)",
        method_id, (unsigned long)method_id);

    // On AOSP ART, jmethodID == ArtMethod* (direct pointer to heap/image).
    // On some OEM builds (Samsung, Huawei), jmethodID may be an index or
    // indirect reference. A valid ArtMethod* should be a large address
    // (in the process address space), not a small number.
    // Source: AOSP art/runtime/jni/jni_internal.cc
    uintptr_t ptr_value = (uintptr_t)method_id;
    if (ptr_value < 0x10000) {
        // Pointer is suspiciously small — likely an index, not a real pointer.
        // Samsung's ART implementation may use method indices instead of pointers.
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "jmethodID value %p is too small to be a valid pointer — "
            "likely an index/handle (OEM ART variant). Skipping.",
            method_id);
        return RESULT_ERROR;
    }

    const void *hotness_addr = (const char *)method_id + HOTNESS_COUNT_OFFSET;

    int32_t hotness_count = safe_read_uint16(hotness_addr);

    if (hotness_count < 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
            "Could not read hotness_count safely (pointer may be indirect/encoded)");
        return RESULT_ERROR;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
        "hotness_count = %d (0 = AOT-only/suspicious, >0 = normal)",
        hotness_count);

    if (hotness_count == 0) {
        return RESULT_VIRTUAL_CONTAINER_DETECTED;
    }

    return RESULT_LOOKS_NORMAL;
}
