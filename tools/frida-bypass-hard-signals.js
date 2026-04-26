/**
 * Frida script to spoof HARD SIGNAL emulator indicators.
 *
 * Purpose: Test that the soft signal tier (Tier 2) still catches the emulator
 * when an attacker bypasses the deterministic hard signals.
 *
 * Usage:
 *   frida -D emulator-5554 -l tools/frida-bypass-hard-signals.js -f com.bruno.antitamperingapp
 *
 * What it spoofs:
 * - Build.HARDWARE: "ranchu" -> "qcom"
 * - Build.FINGERPRINT: sdk_gphone -> samsung fingerprint
 * - Build.DEVICE: "emu64a" -> "starqltechn"
 * - Build.MODEL: sdk_gphone -> "SM-G960F"
 * - Build.PRODUCT: sdk_gphone -> "starltexx"
 * - Build.MANUFACTURER: "Google" -> "samsung"
 * - SystemProperties.get("ro.kernel.qemu") -> ""
 * - Sensor.getName() / Sensor.getVendor() -> real hardware names
 * - GLES20.glGetString(GL_RENDERER) -> real GPU name
 */

Java.perform(function () {
    console.log("[*] Frida bypass script loaded — spoofing hard signals");

    // ── Spoof Build.* fields ──
    var Build = Java.use("android.os.Build");
    Build.HARDWARE.value = "qcom";
    Build.FINGERPRINT.value = "samsung/starltexx/starqltechn:10/QP1A.190711.020/G960FXXSDFUG5:user/release-keys";
    Build.DEVICE.value = "starqltechn";
    Build.MODEL.value = "SM-G960F";
    Build.PRODUCT.value = "starltexx";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    console.log("[+] Build.* properties spoofed to Samsung Galaxy S9");

    // ── Spoof SystemProperties.get() ──
    var SystemProperties = Java.use("android.os.SystemProperties");
    var originalGet = SystemProperties.get.overload("java.lang.String");
    SystemProperties.get.overload("java.lang.String").implementation = function (key) {
        if (key === "ro.kernel.qemu") {
            console.log("[+] Spoofed ro.kernel.qemu: '' (empty)");
            return "";
        }
        if (key === "ro.hardware") {
            console.log("[+] Spoofed ro.hardware: 'qcom'");
            return "qcom";
        }
        if (key === "init.svc.qemud") {
            return "";
        }
        if (key === "ro.kernel.android.qemud") {
            return "";
        }
        return originalGet.call(this, key);
    };
    // Also handle the 2-arg overload
    SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
        if (key === "ro.kernel.qemu") return "";
        if (key === "ro.hardware") return "qcom";
        if (key === "init.svc.qemud") return def;
        if (key === "ro.kernel.android.qemud") return def;
        return this.get(key, def);
    };
    console.log("[+] SystemProperties.get() hooked");

    // ── Spoof Sensor names ──
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.getName.implementation = function () {
        var original = this.getName();
        if (original.indexOf("Goldfish") !== -1) {
            var spoofed = original.replace("Goldfish 3-axis Accelerometer", "LSM6DSO Accelerometer")
                                   .replace("Goldfish 3-axis Gyroscope", "LSM6DSO Gyroscope")
                                   .replace("Goldfish", "STMicro");
            console.log("[+] Spoofed sensor name: " + original + " -> " + spoofed);
            return spoofed;
        }
        return original;
    };
    Sensor.getVendor.implementation = function () {
        var original = this.getVendor();
        if (original === "The Android Open Source Project") {
            console.log("[+] Spoofed sensor vendor: AOSP -> STMicroelectronics");
            return "STMicroelectronics";
        }
        return original;
    };
    console.log("[+] Sensor.getName()/getVendor() hooked");

    // ── Spoof GL Renderer ──
    var GLES20 = Java.use("android.opengl.GLES20");
    GLES20.glGetString.implementation = function (name) {
        var result = this.glGetString(name);
        // GL_RENDERER = 0x1F01
        if (name === 0x1F01 && result && result.indexOf("Android Emulator") !== -1) {
            var spoofed = "Adreno (TM) 630";
            console.log("[+] Spoofed GL_RENDERER: " + result + " -> " + spoofed);
            return spoofed;
        }
        return result;
    };
    console.log("[+] GLES20.glGetString() hooked");

    console.log("[*] All hard signals spoofed. Soft signals should still catch the emulator.");
});
