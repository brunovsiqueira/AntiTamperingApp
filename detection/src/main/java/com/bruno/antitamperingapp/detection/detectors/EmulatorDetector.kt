package com.bruno.antitamperingapp.detection.detectors

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.GLES20
import android.os.BatteryManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.telephony.TelephonyManager
import com.bruno.antitamperingapp.detection.DetectionCategory
import com.bruno.antitamperingapp.detection.DetectionResult
import com.bruno.antitamperingapp.detection.Evidence
import com.bruno.antitamperingapp.detection.TamperDetector
import com.bruno.antitamperingapp.detection.error.DetectionError
import com.bruno.antitamperingapp.detection.util.SafeExec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.coroutines.resume
import kotlin.math.sqrt

/**
 * Detects whether the app is running on an Android emulator.
 *
 * Uses 9 check groups split into two phases:
 * - **Instant checks** (~50ms): Build properties, system properties, sensor strings,
 *   sensor absence, battery, GL renderer, file artifacts, telephony.
 * - **Extended checks** (~2-3s): Accelerometer and gyroscope noise analysis via sensor sampling.
 *
 * Call [detect] for full detection (instant + extended).
 * Call [detectInstant] for fast-path detection without sensor sampling.
 */
class EmulatorDetector : TamperDetector {

    override val name: String = "EmulatorDetector"
    override val category: DetectionCategory = DetectionCategory.EMULATOR
    override val weight: Float = 1.0f

    override suspend fun detect(context: Context): DetectionResult {
        val errors = mutableListOf<DetectionError>()
        val evidence = mutableListOf<Evidence>()

        runInstantChecks(context, evidence, errors)
        runSensorNoiseAnalysis(context, evidence, errors)

        return buildResult(evidence, errors)
    }

    /**
     * Fast-path detection using only instant checks (no sensor sampling delay).
     * Useful when latency is critical.
     */
    suspend fun detectInstant(context: Context): DetectionResult {
        val errors = mutableListOf<DetectionError>()
        val evidence = mutableListOf<Evidence>()

        runInstantChecks(context, evidence, errors)

        return buildResult(evidence, errors)
    }

    private suspend fun runInstantChecks(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        checkBuildProperties(evidence, errors)
        checkSystemProperties(evidence, errors)
        checkSensorHardwareStrings(context, evidence, errors)
        checkSensorAbsence(context, evidence, errors)
        checkBattery(context, evidence, errors)
        checkGlRenderer(evidence, errors)
        checkFileArtifacts(evidence, errors)
        checkTelephony(context, evidence, errors)
    }

    // ──────────────────────────────────────────────
    // Check 1: Build Property Cross-Validation
    // Weight: 0.7
    // ──────────────────────────────────────────────

    private fun checkBuildProperties(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching("build_properties", name, errors) {
            val checks = listOf(
                BuildCheck("build_hardware", "Build.HARDWARE", Build.HARDWARE) {
                    it.equals("ranchu", ignoreCase = true) ||
                        it.equals("goldfish", ignoreCase = true)
                },
                BuildCheck("build_fingerprint", "Build.FINGERPRINT", Build.FINGERPRINT) {
                    it.contains("sdk_gphone", ignoreCase = true) ||
                        it.contains("generic/", ignoreCase = true) ||
                        it.startsWith("generic", ignoreCase = true)
                },
                BuildCheck("build_device", "Build.DEVICE", Build.DEVICE) {
                    it.contains("emu64", ignoreCase = true) ||
                        it.equals("generic", ignoreCase = true)
                },
                BuildCheck("build_model", "Build.MODEL", Build.MODEL) {
                    it.contains("sdk_gphone", ignoreCase = true) ||
                        it.contains("Android SDK built for", ignoreCase = true) ||
                        it.contains("google_sdk", ignoreCase = true)
                },
                BuildCheck("build_product", "Build.PRODUCT", Build.PRODUCT) {
                    it.contains("sdk_gphone", ignoreCase = true) ||
                        it.contains("sdk_phone", ignoreCase = true) ||
                        it.equals("sdk", ignoreCase = true)
                },
                BuildCheck("build_manufacturer", "Build.MANUFACTURER", Build.MANUFACTURER) {
                    it.equals("Genymotion", ignoreCase = true)
                },
                BuildCheck("build_type", "Build.TYPE", Build.TYPE) {
                    it.equals("userdebug", ignoreCase = true)
                },
                BuildCheck("build_tags", "Build.TAGS", Build.TAGS) {
                    it.equals("dev-keys", ignoreCase = true) ||
                        it.equals("test-keys", ignoreCase = true)
                },
            )

            for (check in checks) {
                val suspicious = check.isSuspicious(check.value)
                evidence.add(
                    Evidence(
                        checkName = check.id,
                        description = if (suspicious) {
                            "${check.label} indicates emulator: '${check.value}'"
                        } else {
                            "${check.label} appears legitimate"
                        },
                        rawValue = check.value,
                        suspicious = suspicious,
                    )
                )
            }
        }
    }

    // ──────────────────────────────────────────────
    // Check 2: System Properties
    // Weight: 0.6
    // ──────────────────────────────────────────────

    private fun checkSystemProperties(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        val props = listOf(
            "ro.kernel.qemu" to "1",
            "ro.hardware" to "ranchu",
            "init.svc.qemud" to "running",
            "ro.kernel.android.qemud" to null, // any non-empty value is suspicious
        )

        for ((propName, suspiciousValue) in props) {
            SafeExec.runCatching("sysprop_$propName", name, errors) {
                val value = getSystemProperty(propName)
                val suspicious = if (suspiciousValue != null) {
                    value.equals(suspiciousValue, ignoreCase = true)
                } else {
                    value.isNotEmpty()
                }
                evidence.add(
                    Evidence(
                        checkName = "sysprop_${propName.replace(".", "_")}",
                        description = if (suspicious) {
                            "System property '$propName' = '$value' indicates emulator"
                        } else {
                            "System property '$propName' appears normal"
                        },
                        rawValue = value.ifEmpty { "(empty)" },
                        suspicious = suspicious,
                    )
                )
            }
        }
    }

    // ──────────────────────────────────────────────
    // Check 3: Sensor Hardware Strings
    // Weight: 0.9
    // ──────────────────────────────────────────────

    private fun checkSensorHardwareStrings(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching("sensor_strings", name, errors) {
            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            if (sensorManager == null) {
                errors.add(
                    DetectionError.ApiUnavailable(
                        detectorName = name,
                        api = "SensorManager",
                        requiredSdk = 1,
                        currentSdk = Build.VERSION.SDK_INT,
                    )
                )
                return@runCatching
            }

            val sensorsToCheck = listOf(
                Sensor.TYPE_ACCELEROMETER to "Accelerometer",
                Sensor.TYPE_GYROSCOPE to "Gyroscope",
            )

            for ((type, label) in sensorsToCheck) {
                val sensor = sensorManager.getDefaultSensor(type)
                if (sensor != null) {
                    val sensorName = sensor.name ?: ""
                    val sensorVendor = sensor.vendor ?: ""
                    val nameGoldfish = sensorName.contains("Goldfish", ignoreCase = true)
                    val vendorAosp = sensorVendor == "The Android Open Source Project"
                    val suspicious = nameGoldfish || vendorAosp
                    evidence.add(
                        Evidence(
                            checkName = "sensor_string_${label.lowercase()}",
                            description = if (suspicious) {
                                "$label sensor '$sensorName' by '$sensorVendor' is emulated"
                            } else {
                                "$label sensor '$sensorName' by '$sensorVendor' appears physical"
                            },
                            rawValue = "$sensorName | $sensorVendor",
                            suspicious = suspicious,
                        )
                    )
                }
            }
        }
    }

    // ──────────────────────────────────────────────
    // Check 4: Sensor Absence
    // Weight: 0.5
    // ──────────────────────────────────────────────

    private fun checkSensorAbsence(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching("sensor_absence", name, errors) {
            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
                ?: return@runCatching

            val sensorsExpectedOnRealDevices = listOf(
                Sensor.TYPE_STEP_COUNTER to "Step Counter",
                Sensor.TYPE_SIGNIFICANT_MOTION to "Significant Motion",
            )

            for ((type, label) in sensorsExpectedOnRealDevices) {
                val present = sensorManager.getDefaultSensor(type) != null
                evidence.add(
                    Evidence(
                        checkName = "sensor_absence_${label.lowercase().replace(" ", "_")}",
                        description = if (present) {
                            "$label sensor present (expected on real devices)"
                        } else {
                            "$label sensor absent (common in emulators)"
                        },
                        rawValue = if (present) "present" else "absent",
                        suspicious = !present,
                    )
                )
            }
        }
    }

    // ──────────────────────────────────────────────
    // Check 5: Sensor Noise Analysis (Extended)
    // Weight: 0.8
    //
    // Samples both accelerometer and gyroscope for
    // ~2s, then checks standard deviation per axis.
    // Real MEMS sensors always produce characteristic
    // noise; emulated sensors are unnaturally stable.
    //
    // References:
    // - PMC10490716: real accel stddev 0.004-0.011 m/s²
    // - EmuDetLib: static-value detection heuristic
    // ──────────────────────────────────────────────

    private suspend fun runSensorNoiseAnalysis(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.withTimeout(SENSOR_SAMPLING_TIMEOUT_MS, "sensor_noise", name, errors) {
            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            if (sensorManager == null) {
                errors.add(
                    DetectionError.ApiUnavailable(
                        detectorName = name,
                        api = "SensorManager",
                        requiredSdk = 1,
                        currentSdk = Build.VERSION.SDK_INT,
                    )
                )
                return@withTimeout
            }

            val sensorsToSample = buildList {
                sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)?.let {
                    add(SensorSamplingTarget(it, "accelerometer", ACCEL_NOISE_THRESHOLD))
                }
                sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE)?.let {
                    add(SensorSamplingTarget(it, "gyroscope", GYRO_NOISE_THRESHOLD))
                }
            }

            if (sensorsToSample.isEmpty()) {
                evidence.add(
                    Evidence(
                        checkName = "sensor_noise",
                        description = "No accelerometer or gyroscope available for noise analysis",
                        rawValue = null,
                        suspicious = true,
                    )
                )
                return@withTimeout
            }

            val sampleResults = collectSensorSamples(
                sensorManager,
                sensorsToSample,
                SENSOR_SAMPLING_DURATION_MS,
            )

            for ((target, samples) in sampleResults) {
                analyzeSensorNoise(target, samples, evidence)
            }
        }
    }

    private fun analyzeSensorNoise(
        target: SensorSamplingTarget,
        samples: List<FloatArray>,
        evidence: MutableList<Evidence>,
    ) {
        if (samples.size < MIN_SAMPLES_FOR_ANALYSIS) {
            evidence.add(
                Evidence(
                    checkName = "sensor_noise_${target.label}",
                    description = "Insufficient ${target.label} samples for noise analysis " +
                        "(${samples.size}/${MIN_SAMPLES_FOR_ANALYSIS} required)",
                    rawValue = samples.size.toString(),
                    suspicious = false,
                )
            )
            return
        }

        val axisCount = samples.first().size.coerceAtMost(3)
        val stdDevs = computeStdDevPerAxis(samples, axisCount)
        val avgStdDev = stdDevs.take(axisCount).average().toFloat()
        val allAxesStatic = stdDevs.take(axisCount).all { it < target.noiseThreshold }
        val suspicious = allAxesStatic

        evidence.add(
            Evidence(
                checkName = "sensor_noise_${target.label}",
                description = if (suspicious) {
                    "${target.label.replaceFirstChar { it.uppercase() }} noise too low " +
                        "(avg stddev=${"%.6f".format(avgStdDev)}). " +
                        "Threshold: ${target.noiseThreshold}"
                } else {
                    "${target.label.replaceFirstChar { it.uppercase() }} noise consistent with " +
                        "physical hardware (avg stddev=${"%.6f".format(avgStdDev)})"
                },
                rawValue = buildString {
                    append("stddev=[")
                    for (i in 0 until axisCount) {
                        if (i > 0) append(", ")
                        append("${"%.6f".format(stdDevs[i])}")
                    }
                    append("] samples=${samples.size}")
                },
                suspicious = suspicious,
            )
        )
    }

    /**
     * Collects sensor samples from multiple sensors concurrently over [durationMs].
     * Returns a map from each [SensorSamplingTarget] to its collected samples.
     *
     * Runs on [Dispatchers.Main] because [SensorManager.registerListener] requires
     * a Looper thread for callbacks.
     */
    private suspend fun collectSensorSamples(
        sensorManager: SensorManager,
        targets: List<SensorSamplingTarget>,
        durationMs: Long,
    ): Map<SensorSamplingTarget, List<FloatArray>> = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { continuation ->
            val sampleMap = targets.associateWithTo(mutableMapOf()) {
                mutableListOf<FloatArray>()
            }
            val listeners = mutableListOf<SensorEventListener>()

            for (target in targets) {
                val listener = object : SensorEventListener {
                    override fun onSensorChanged(event: SensorEvent) {
                        sampleMap[target]?.add(event.values.copyOf())
                    }

                    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
                }
                listeners.add(listener)

                // Use SENSOR_DELAY_GAME (~50Hz) instead of SENSOR_DELAY_FASTEST.
                // FASTEST (0μs) requires HIGH_SAMPLING_RATE_SENSORS permission on API 31+.
                // GAME rate gives ~100 samples in 2s — more than sufficient for noise analysis.
                val registered = sensorManager.registerListener(
                    listener,
                    target.sensor,
                    SensorManager.SENSOR_DELAY_GAME,
                )
                if (!registered) {
                    sampleMap.remove(target)
                }
            }

            fun unregisterAll() {
                for (listener in listeners) {
                    try {
                        sensorManager.unregisterListener(listener)
                    } catch (_: Exception) {
                        // Defensive: unregister should never throw, but don't let it crash
                    }
                }
            }

            continuation.invokeOnCancellation { unregisterAll() }

            Handler(Looper.getMainLooper()).postDelayed({
                unregisterAll()
                if (continuation.isActive) {
                    val immutableResults = sampleMap.mapValues { it.value.toList() }
                    continuation.resume(immutableResults)
                }
            }, durationMs)
        }
    }

    /**
     * Computes standard deviation per axis for a list of sensor samples.
     *
     * @param samples Non-empty list of float arrays (each array = one reading).
     * @param axisCount Number of axes to analyze (typically 3 for x/y/z).
     * @return FloatArray of standard deviations, one per axis.
     */
    private fun computeStdDevPerAxis(samples: List<FloatArray>, axisCount: Int): FloatArray {
        if (samples.isEmpty()) return FloatArray(axisCount) { 0f }

        val n = samples.size.toFloat()
        val means = FloatArray(axisCount)
        for (sample in samples) {
            for (axis in 0 until axisCount) {
                means[axis] += sample.getOrElse(axis) { 0f }
            }
        }
        for (axis in 0 until axisCount) {
            means[axis] /= n
        }

        val variances = FloatArray(axisCount)
        for (sample in samples) {
            for (axis in 0 until axisCount) {
                val delta = sample.getOrElse(axis) { 0f } - means[axis]
                variances[axis] += delta * delta
            }
        }
        for (axis in 0 until axisCount) {
            variances[axis] /= n
        }

        return FloatArray(axisCount) { sqrt(variances[it]) }
    }

    // ──────────────────────────────────────────────
    // Check 6: Battery Anomalies
    // Weight: 0.85
    // ──────────────────────────────────────────────

    private fun checkBattery(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching("battery", name, errors) {
            val intent: Intent? = try {
                context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            } catch (_: Exception) {
                null
            }

            if (intent == null) {
                evidence.add(
                    Evidence(
                        checkName = "battery_profile",
                        description = "Could not read battery status",
                        rawValue = null,
                        suspicious = false,
                    )
                )
                return@runCatching
            }

            val temperature = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1)
            val voltage = intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1)
            val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            val plugged = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1)
            val present = intent.getBooleanExtra(BatteryManager.EXTRA_PRESENT, true)

            // Temperature = 0 means 0.0°C — virtually impossible for a real device battery
            val tempSuspicious = temperature == 0
            // Voltage = 0 mV — no real battery reports this
            val voltageSuspicious = voltage == 0

            evidence.add(
                Evidence(
                    checkName = "battery_temperature",
                    description = if (tempSuspicious) {
                        "Battery temperature is 0 (0.0°C) — indicates emulator"
                    } else {
                        "Battery temperature is ${temperature / 10.0}°C — normal range"
                    },
                    rawValue = temperature.toString(),
                    suspicious = tempSuspicious,
                )
            )
            evidence.add(
                Evidence(
                    checkName = "battery_voltage",
                    description = if (voltageSuspicious) {
                        "Battery voltage is 0 mV — no real battery reports this"
                    } else {
                        "Battery voltage is $voltage mV — normal range"
                    },
                    rawValue = voltage.toString(),
                    suspicious = voltageSuspicious,
                )
            )
            evidence.add(
                Evidence(
                    checkName = "battery_profile",
                    description = "Battery: level=$level%, status=$status, " +
                        "plugged=$plugged, present=$present",
                    rawValue = "level=$level status=$status plugged=$plugged present=$present",
                    suspicious = tempSuspicious && voltageSuspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 7: GL Renderer
    // Weight: 0.9
    // ──────────────────────────────────────────────

    private suspend fun checkGlRenderer(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        withContext(Dispatchers.Main) {
            SafeExec.runCatching("gl_renderer", name, errors) {
                val renderer = queryGlRenderer()

                if (renderer == null) {
                    evidence.add(
                        Evidence(
                            checkName = "gl_renderer",
                            description = "Could not query GL renderer (EGL context creation failed)",
                            rawValue = null,
                            suspicious = false,
                        )
                    )
                    return@runCatching
                }

                val suspicious = EMULATOR_GL_RENDERERS.any {
                    renderer.contains(it, ignoreCase = true)
                }

                evidence.add(
                    Evidence(
                        checkName = "gl_renderer",
                        description = if (suspicious) {
                            "GL renderer '$renderer' indicates emulator"
                        } else {
                            "GL renderer '$renderer' appears to be real hardware"
                        },
                        rawValue = renderer,
                        suspicious = suspicious,
                    )
                )
            }
        }
    }

    /**
     * Creates a headless EGL PBuffer context to query the GL renderer string
     * without needing a visible GLSurfaceView. Properly cleans up all EGL
     * resources in the finally block even if intermediate steps fail.
     */
    private fun queryGlRenderer(): String? {
        var display = EGL14.EGL_NO_DISPLAY
        var context = EGL14.EGL_NO_CONTEXT
        var surface = EGL14.EGL_NO_SURFACE

        try {
            display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
            if (display == EGL14.EGL_NO_DISPLAY) return null

            val version = IntArray(2)
            if (!EGL14.eglInitialize(display, version, 0, version, 1)) return null

            val configAttribs = intArrayOf(
                EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                EGL14.EGL_NONE,
            )
            val configs = arrayOfNulls<EGLConfig>(1)
            val numConfigs = IntArray(1)
            if (!EGL14.eglChooseConfig(
                    display, configAttribs, 0, configs, 0, 1, numConfigs, 0,
                )
            ) {
                return null
            }
            val config = configs[0] ?: return null

            val contextAttribs = intArrayOf(
                EGL14.EGL_CONTEXT_CLIENT_VERSION, 2,
                EGL14.EGL_NONE,
            )
            context = EGL14.eglCreateContext(
                display, config, EGL14.EGL_NO_CONTEXT, contextAttribs, 0,
            )
            if (context == EGL14.EGL_NO_CONTEXT) return null

            val surfaceAttribs = intArrayOf(
                EGL14.EGL_WIDTH, 1,
                EGL14.EGL_HEIGHT, 1,
                EGL14.EGL_NONE,
            )
            surface = EGL14.eglCreatePbufferSurface(display, config, surfaceAttribs, 0)
            if (surface == EGL14.EGL_NO_SURFACE) return null

            if (!EGL14.eglMakeCurrent(display, surface, surface, context)) return null

            return GLES20.glGetString(GLES20.GL_RENDERER)
        } finally {
            cleanupEgl(display, surface, context)
        }
    }

    private fun cleanupEgl(
        display: android.opengl.EGLDisplay,
        surface: android.opengl.EGLSurface,
        context: android.opengl.EGLContext,
    ) {
        try {
            if (display != EGL14.EGL_NO_DISPLAY) {
                EGL14.eglMakeCurrent(
                    display,
                    EGL14.EGL_NO_SURFACE,
                    EGL14.EGL_NO_SURFACE,
                    EGL14.EGL_NO_CONTEXT,
                )
                if (surface != EGL14.EGL_NO_SURFACE) {
                    EGL14.eglDestroySurface(display, surface)
                }
                if (context != EGL14.EGL_NO_CONTEXT) {
                    EGL14.eglDestroyContext(display, context)
                }
                EGL14.eglTerminate(display)
            }
        } catch (_: Exception) {
            // Defensive: EGL cleanup should not crash the detector
        }
    }

    // ──────────────────────────────────────────────
    // Check 8: File System Artifacts
    // Weight: 0.6
    // ──────────────────────────────────────────────

    private fun checkFileArtifacts(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        val paths = listOf(
            "/system/bin/qemu-props" to "QEMU properties binary",
            "/dev/qemu_pipe" to "QEMU communication pipe",
            "/dev/goldfish_pipe" to "Goldfish communication pipe",
            "/dev/socket/qemud" to "QEMU daemon socket",
            "/system/lib/libc_malloc_debug_qemu.so" to "QEMU malloc debug library",
        )

        for ((path, description) in paths) {
            SafeExec.runCatching("file_$path", name, errors) {
                val exists = File(path).exists()
                evidence.add(
                    Evidence(
                        checkName = "file_artifact",
                        description = if (exists) {
                            "$description found at '$path'"
                        } else {
                            "$description not found at '$path'"
                        },
                        rawValue = path,
                        suspicious = exists,
                    )
                )
            }
        }
    }

    // ──────────────────────────────────────────────
    // Check 9: Telephony Operator
    // Weight: 0.55
    // ──────────────────────────────────────────────

    private fun checkTelephony(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching("telephony", name, errors) {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            if (tm == null) {
                errors.add(
                    DetectionError.ApiUnavailable(
                        detectorName = name,
                        api = "TelephonyManager",
                        requiredSdk = 1,
                        currentSdk = Build.VERSION.SDK_INT,
                    )
                )
                return@runCatching
            }

            val networkOp = try {
                tm.networkOperatorName ?: ""
            } catch (_: Exception) {
                ""
            }
            val simOp = try {
                tm.simOperatorName ?: ""
            } catch (_: Exception) {
                ""
            }

            val networkSuspicious = networkOp.equals("Android", ignoreCase = true)
            val simSuspicious = simOp.equals("Android", ignoreCase = true)

            evidence.add(
                Evidence(
                    checkName = "telephony_network_operator",
                    description = if (networkSuspicious) {
                        "Network operator name is 'Android' — emulator default"
                    } else if (networkOp.isEmpty()) {
                        "Network operator name is empty (no SIM or WiFi-only device)"
                    } else {
                        "Network operator name '$networkOp' appears legitimate"
                    },
                    rawValue = networkOp.ifEmpty { "(empty)" },
                    suspicious = networkSuspicious,
                )
            )
            evidence.add(
                Evidence(
                    checkName = "telephony_sim_operator",
                    description = if (simSuspicious) {
                        "SIM operator name is 'Android' — emulator default"
                    } else if (simOp.isEmpty()) {
                        "SIM operator name is empty (no SIM or WiFi-only device)"
                    } else {
                        "SIM operator name '$simOp' appears legitimate"
                    },
                    rawValue = simOp.ifEmpty { "(empty)" },
                    suspicious = simSuspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Result Building
    // ──────────────────────────────────────────────

    private fun buildResult(
        evidence: List<Evidence>,
        errors: List<DetectionError>,
    ): DetectionResult {
        val confidence = computeConfidence(evidence)
        return DetectionResult(
            detected = confidence >= DETECTION_THRESHOLD,
            confidence = confidence,
            evidence = evidence,
            errors = errors,
        )
    }

    /**
     * Computes confidence using a weighted scheme where each check group
     * contributes its weight to the overall score when triggered.
     *
     * Partial credit: if 3/8 build props are suspicious, that group
     * contributes 3/8 of its weight.
     */
    private fun computeConfidence(evidence: List<Evidence>): Float {
        var triggeredWeight = 0f
        val totalWeight = CHECK_WEIGHTS.values.sum()
        if (totalWeight == 0f) return 0f

        for ((group, weight) in CHECK_WEIGHTS) {
            val groupEvidence = evidence.filter { it.checkName.startsWith(group) }
            if (groupEvidence.isEmpty()) continue

            val suspiciousCount = groupEvidence.count { it.suspicious }
            val totalCount = groupEvidence.size

            if (suspiciousCount > 0) {
                val ratio = suspiciousCount.toFloat() / totalCount.toFloat()
                triggeredWeight += weight * ratio
            }
        }

        return (triggeredWeight / totalWeight).coerceIn(0f, 1f)
    }

    // ──────────────────────────────────────────────
    // Utilities
    // ──────────────────────────────────────────────

    @Suppress("PrivateApi")
    private fun getSystemProperty(name: String): String {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, name) as? String) ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    private data class BuildCheck(
        val id: String,
        val label: String,
        val value: String,
        val isSuspicious: (String) -> Boolean,
    )

    private data class SensorSamplingTarget(
        val sensor: Sensor,
        val label: String,
        val noiseThreshold: Float,
    )

    companion object {
        private const val DETECTION_THRESHOLD = 0.35f

        // Accelerometer noise threshold: real devices show 0.004-0.011 m/s² (PMC10490716)
        private const val ACCEL_NOISE_THRESHOLD = 0.002f
        // Gyroscope noise threshold: real devices show measurable drift noise;
        // emulators return near-zero or perfectly stable values
        private const val GYRO_NOISE_THRESHOLD = 0.001f

        private const val SENSOR_SAMPLING_DURATION_MS = 2000L
        private const val SENSOR_SAMPLING_TIMEOUT_MS = 4000L
        private const val MIN_SAMPLES_FOR_ANALYSIS = 20

        private val EMULATOR_GL_RENDERERS = listOf(
            "Android Emulator",
            "SwiftShader",
            "Bluestacks",
            "Translator",
        )

        // Check group name prefix -> weight
        private val CHECK_WEIGHTS = mapOf(
            "build_" to 0.7f,
            "sysprop_" to 0.6f,
            "sensor_string_" to 0.9f,
            "sensor_absence_" to 0.5f,
            "sensor_noise_" to 0.8f,
            "battery_" to 0.85f,
            "gl_renderer" to 0.9f,
            "file_artifact" to 0.6f,
            "telephony_" to 0.55f,
        )
    }
}
