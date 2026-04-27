#include <jni.h>
#include <android/log.h>
#include <stdint.h>

#define TAG "ArtMethodCheck"

/*
 * ArtMethod hotness_count inspection for virtual container detection.
 *
 * Virtual containers (VirtualApp, Parallel Space, etc.) load apps via DexClassLoader
 * rather than the system installer. Methods loaded this way are AOT-compiled only,
 * producing hotness_count == 0. In normal execution, frequently-called framework
 * methods like ActivityThread.currentActivityThread() accumulate hotness > 0.
 *
 * ArtMethod struct layout (stable across Android 12–16, API 31–36):
 *   Offset 0:  declaring_class_    (GcRoot<Class> = uint32_t, 4 bytes)
 *   Offset 4:  access_flags_       (atomic<uint32_t>, 4 bytes)
 *   Offset 8:  dex_method_index_   (uint32_t, 4 bytes)
 *   Offset 12: method_index_       (uint16_t, 2 bytes)
 *   Offset 14: hotness_count_      (uint16_t, 2 bytes)  <-- target field
 *
 * Layout stability enforced by AOSP test: ValidateFieldOrderOfJavaCppUnionClasses
 *
 * Sources:
 *   - AOSP art_method.h: https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h
 *   - Mascara paper (defense via ArtMethod): https://arxiv.org/abs/2010.10639
 *   - Matrioska (ACSAC 2024, 99% accuracy): https://ieeexplore.ieee.org/document/10917506/
 */

// Offset of hotness_count_ within ArtMethod struct.
// Verified identical across Android 12 (API 31) through Android 16 (API 36).
// Source: AOSP art_method.h tags android-12.0.0_r1 through android-16.0.0_r1
#define HOTNESS_COUNT_OFFSET 14

// Return values
#define RESULT_VIRTUAL_CONTAINER_DETECTED 1  // hotness_count == 0 → likely virtual container
#define RESULT_LOOKS_NORMAL 0                // hotness_count > 0 → normal execution
#define RESULT_ERROR -1                      // could not perform check

JNIEXPORT jint JNICALL
Java_com_bruno_antitamperingapp_detection_detectors_ArtMethodChecker_checkHotnessCount(
    JNIEnv *env, jobject thiz, jobject method_obj) {

    if (method_obj == NULL) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Method object is null");
        return RESULT_ERROR;
    }

    // FromReflectedMethod returns a jmethodID which is a pointer to the ArtMethod struct.
    // Source: JNI spec + AOSP jni_internal.cc
    jmethodID method_id = (*env)->FromReflectedMethod(env, method_obj);
    if (method_id == NULL) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "FromReflectedMethod returned null");
        return RESULT_ERROR;
    }

    // Read hotness_count_ (uint16_t) at offset 14 from the ArtMethod pointer.
    // jmethodID is effectively ArtMethod* in ART.
    // Source: AOSP art_method.h, field layout verified for API 31-36
    uint16_t hotness_count = *((uint16_t *)((char *)method_id + HOTNESS_COUNT_OFFSET));

    __android_log_print(ANDROID_LOG_INFO, TAG,
        "hotness_count for method: %u (0 = AOT-only, suspicious in virtual container)",
        hotness_count);

    if (hotness_count == 0) {
        return RESULT_VIRTUAL_CONTAINER_DETECTED;
    }

    return RESULT_LOOKS_NORMAL;
}
