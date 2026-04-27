package com.bruno.antitamperingapp.detection.detectors

import android.os.Build
import android.util.Log
import java.lang.reflect.Method

/**
 * JNI bridge for ArtMethod hotness_count inspection.
 *
 * Reads the hotness_count field from the ART runtime's internal ArtMethod struct
 * to detect virtual container class loading. Only runs on API 31–36 where the
 * struct layout is verified. Returns inconclusive on unsupported API levels.
 *
 * Sources:
 * - Mascara paper (arXiv 2010.10639): identified ArtMethod as only unbypassable defense
 * - Matrioska (ACSAC 2024, IEEE 10917506): 99% accuracy with this technique
 * - AOSP art_method.h: struct layout verified stable across Android 12–16
 */
internal class ArtMethodChecker {

    companion object {
        private const val TAG = "ArtMethodChecker"

        // API range where ArtMethod struct layout is verified.
        // Source: AOSP art_method.h tags android-12.0.0_r1 through main branch (API 36)
        private const val MIN_SUPPORTED_API = Build.VERSION_CODES.S // API 31 (Android 12)
        private const val MAX_SUPPORTED_API = 36

        private const val RESULT_VIRTUAL_CONTAINER = 1
        private const val RESULT_NORMAL = 0
        private const val RESULT_ERROR = -1

        private var libraryLoaded = false

        init {
            try {
                System.loadLibrary("antitamper_native")
                libraryLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                Log.w(TAG, "Native library not available: ${e.message}")
            }
        }
    }

    /**
     * Checks the hotness_count of ActivityThread.currentActivityThread().
     *
     * @return [CheckResult.Detected] if hotness_count == 0 (virtual container),
     *         [CheckResult.Normal] if hotness_count > 0 (normal execution),
     *         [CheckResult.Inconclusive] if the check cannot run on this device.
     */
    fun check(): CheckResult {
        if (!libraryLoaded) {
            return CheckResult.Inconclusive("Native library not loaded")
        }

        val sdkInt = Build.VERSION.SDK_INT
        if (sdkInt < MIN_SUPPORTED_API || sdkInt > MAX_SUPPORTED_API) {
            return CheckResult.Inconclusive(
                "API $sdkInt outside verified range ($MIN_SUPPORTED_API–$MAX_SUPPORTED_API)"
            )
        }

        return try {
            // ActivityThread.currentActivityThread() is called frequently by the Android
            // framework during normal execution, so its hotness_count should be > 0.
            // In a virtual container, it's loaded via DexClassLoader → AOT-only → hotness_count == 0.
            // Source: Mascara paper §5.2 (arXiv 2010.10639)
            val activityThreadClass = Class.forName("android.app.ActivityThread")
            val method: Method = activityThreadClass.getDeclaredMethod("currentActivityThread")

            when (checkHotnessCount(method)) {
                RESULT_VIRTUAL_CONTAINER -> CheckResult.Detected(
                    "ActivityThread.currentActivityThread() hotness_count == 0 (AOT-only, " +
                        "characteristic of virtual container class loading)"
                )
                RESULT_NORMAL -> CheckResult.Normal
                else -> CheckResult.Inconclusive("Native check returned error")
            }
        } catch (e: ClassNotFoundException) {
            CheckResult.Inconclusive("ActivityThread class not found: ${e.message}")
        } catch (e: NoSuchMethodException) {
            CheckResult.Inconclusive("currentActivityThread method not found: ${e.message}")
        } catch (e: Exception) {
            CheckResult.Inconclusive("Unexpected error: ${e.message}")
        }
    }

    // Native method implemented in art_method_check.c
    private external fun checkHotnessCount(method: Any): Int

    sealed class CheckResult {
        /** hotness_count == 0 → strong indicator of virtual container. */
        data class Detected(val detail: String) : CheckResult()

        /** hotness_count > 0 → normal execution. Does NOT rule out virtualization. */
        data object Normal : CheckResult()

        /** Check could not run (wrong API level, library missing, etc.). No signal either way. */
        data class Inconclusive(val reason: String) : CheckResult()
    }
}
