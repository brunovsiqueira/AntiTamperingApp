/**
 * FULL BYPASS ATTEMPT — Attacker perspective
 *
 * Goal: Make all 4 detectors return CLEAN on an emulator running
 * inside Parallel Space with Frida attached.
 *
 * This script attempts to bypass ALL detection categories simultaneously:
 * 1. EmulatorDetector — spoof Build.*, sensors, GL renderer, system props
 * 2. CloningDetector — fake paths, hide cloner packages, strip stack traces
 * 3. IntegrityDetector — spoof signing certificate, hide debug flag, fake installer
 * 4. HookingDetector — hide Frida from /proc/self/maps, close ports, hide classes
 *
 * Usage:
 *   frida -D <device> -p <PID> -l tools/frida-full-bypass.js
 *
 * After running: press scan and check what STILL gets detected.
 * Anything that survives = resilient check.
 */

Java.perform(function () {
    console.log("========================================");
    console.log("[ATTACKER] Full bypass script loaded");
    console.log("========================================");

    var targetPackage = "com.bruno.antitamperingapp";

    // ════════════════════════════════════════════
    // 1. EMULATOR BYPASS
    // ════════════════════════════════════════════

    // 1a. Build.* properties
    var Build = Java.use("android.os.Build");
    Build.HARDWARE.value = "qcom";
    Build.FINGERPRINT.value = "samsung/starltexx/starqltechn:14/UP1A.231005.007/S960FXXSGHXC1:user/release-keys";
    Build.DEVICE.value = "starqltechn";
    Build.MODEL.value = "SM-G960F";
    Build.PRODUCT.value = "starltexx";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    console.log("[+] Build.* spoofed to Samsung Galaxy S9");

    // 1b. System properties
    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload("java.lang.String").implementation = function (key) {
        var spoofed = {
            "ro.kernel.qemu": "",
            "ro.hardware": "qcom",
            "init.svc.qemud": "",
            "ro.kernel.android.qemud": "",
        };
        if (key in spoofed) return spoofed[key];
        return this.get(key);
    };
    SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
        var spoofed = {
            "ro.kernel.qemu": "",
            "ro.hardware": "qcom",
            "init.svc.qemud": def,
            "ro.kernel.android.qemud": def,
        };
        if (key in spoofed) return spoofed[key];
        return this.get(key, def);
    };
    console.log("[+] SystemProperties spoofed");

    // 1c. Sensor names/vendors
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.getName.implementation = function () {
        var orig = this.getName();
        if (orig.indexOf("Goldfish") !== -1) {
            return orig.replace(/Goldfish 3-axis /g, "LSM6DSO ");
        }
        return orig;
    };
    Sensor.getVendor.implementation = function () {
        var orig = this.getVendor();
        if (orig === "The Android Open Source Project") return "STMicroelectronics";
        return orig;
    };
    console.log("[+] Sensor names/vendors spoofed");

    // 1d. GL Renderer
    var GLES20 = Java.use("android.opengl.GLES20");
    GLES20.glGetString.implementation = function (name) {
        var result = this.glGetString(name);
        if (name === 0x1F01 && result && result.indexOf("Android Emulator") !== -1) {
            return "Adreno (TM) 630";
        }
        return result;
    };
    console.log("[+] GL renderer spoofed");

    // 1e. Telephony
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getNetworkOperatorName.implementation = function () {
        var orig = this.getNetworkOperatorName();
        if (orig === "Android") return "T-Mobile";
        return orig;
    };
    TelephonyManager.getSimOperatorName.implementation = function () {
        var orig = this.getSimOperatorName();
        if (orig === "Android") return "T-Mobile";
        return orig;
    };
    console.log("[+] Telephony operator spoofed");

    // NOTE: Cannot spoof sensor noise patterns (physical MEMS characteristic)
    // NOTE: Cannot spoof sensor absence (step counter/significant motion)
    // NOTE: Cannot spoof battery temperature/voltage easily

    // ════════════════════════════════════════════
    // 2. CLONING BYPASS
    // ════════════════════════════════════════════

    // 2a. Block /proc/self/maps reading entirely
    var File = Java.use("java.io.File");
    File.$init.overload("java.lang.String").implementation = function (path) {
        if (path === "/proc/self/maps" || path === "/proc/self/status") {
            this.$init("/dev/null");
            return;
        }
        this.$init(path);
    };
    console.log("[+] /proc/self/maps and /proc/self/status blocked");

    // 2b. Fake filesDir and dataDir
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    ContextWrapper.getFilesDir.implementation = function () {
        return Java.use("java.io.File").$new("/data/user/0/" + targetPackage + "/files");
    };
    ContextWrapper.getDataDir.implementation = function () {
        return Java.use("java.io.File").$new("/data/user/0/" + targetPackage);
    };
    console.log("[+] Data directory paths spoofed");

    // 2c. Fake sourceDir
    ContextWrapper.getApplicationInfo.implementation = function () {
        var info = this.getApplicationInfo();
        info.sourceDir.value = "/data/app/~~fake~~/" + targetPackage + "-fake/base.apk";
        return info;
    };
    console.log("[+] APK source dir spoofed");

    // 2d. Strip cloner classes from stack traces
    var Throwable = Java.use("java.lang.Throwable");
    Throwable.getStackTrace.implementation = function () {
        var stack = this.getStackTrace();
        var filtered = [];
        var bad = ["com.lody", "com.doubleagent", "io.va", "com.excelliance",
                   "com.lbe.parallel", "com.polestar", "io.tt", "org.nl", "com.estrongs"];
        for (var i = 0; i < stack.length; i++) {
            var cn = stack[i].getClassName();
            var isCloner = false;
            for (var j = 0; j < bad.length; j++) {
                if (cn.indexOf(bad[j]) === 0) { isCloner = true; break; }
            }
            if (!isCloner) filtered.push(stack[i]);
        }
        return filtered;
    };
    console.log("[+] Stack traces cleaned");

    // 2e. Hide cloner packages
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var NameNotFound = Java.use("android.content.pm.PackageManager$NameNotFoundException");
    var clonerPkgs = ["com.lbe.parallel.intl", "com.lbe.parallel", "com.ludashi.dualspace",
                      "com.applisto.appcloner", "com.virtualapp", "io.virtualapp"];
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (name, flags) {
        for (var i = 0; i < clonerPkgs.length; i++) {
            if (name === clonerPkgs[i]) throw NameNotFound.$new(name);
        }
        return this.getPackageInfo(name, flags);
    };
    console.log("[+] Cloner packages hidden");

    // 2f. Hide VirtualApp env vars
    var System = Java.use("java.lang.System");
    var blockedVars = ["V_REPLACE_ITEM", "V_KEEP_ITEM", "V_SO_PATH",
                       "REPLACE_ITEM_ORIG", "REPLACE_ITEM_DST", "V_API_LEVEL", "V_PREVIEW_API_LEVEL"];
    System.getenv.overload("java.lang.String").implementation = function (name) {
        for (var i = 0; i < blockedVars.length; i++) {
            if (name === blockedVars[i]) return null;
        }
        var result = this.getenv(name);
        if (name === "LD_PRELOAD" && result && result.indexOf("/data/data/") !== -1) return null;
        return result;
    };
    console.log("[+] VirtualApp env vars hidden");

    // NOTE: Cannot bypass ArtMethod hotness_count (reads native ART memory)

    // ════════════════════════════════════════════
    // 3. INTEGRITY BYPASS
    // ════════════════════════════════════════════

    // 3a. Spoof signing certificate — return the expected hash
    // This is the most critical bypass: we hook getPackageInfo to return
    // the original app's signing certificate bytes
    // NOTE: We'd need the actual certificate bytes to do this properly.
    // For now, we can't fully bypass this without knowing the expected cert.
    console.log("[!] Integrity: cannot fully bypass signature check without cert bytes");

    // 3b. Hide debug flag
    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    // Hook the flags field access - tricky since it's a field not a method
    // We hook getApplicationInfo instead to clear the flag
    var origGetAppInfo = ContextWrapper.getApplicationInfo;
    // Already hooked above for sourceDir, extend it:
    // (the previous hook already replaces getApplicationInfo, so flags would need
    //  to be cleared there — but modifying .flags.value on the returned object
    //  would affect our sourceDir hook. Skip for now.)
    console.log("[!] Integrity: debug flag bypass skipped (complex interaction with sourceDir hook)");

    // 3c. Fake installer source
    // Would need to hook getInstallSourceInfo — but this is API 30+ specific
    console.log("[!] Integrity: installer source bypass not implemented");

    // ════════════════════════════════════════════
    // 4. HOOKING DETECTOR BYPASS
    // ════════════════════════════════════════════

    // 4a. /proc/self/maps is already blocked (see 2a above)
    // This also hides Frida libraries from the hooking detector!
    console.log("[+] Hooking: /proc/self/maps already blocked (shared with cloning bypass)");

    // 4b. Frida ports — we can't close our own port from JS
    // The attacker would start frida-server on a non-default port instead
    console.log("[!] Hooking: Frida port bypass requires starting frida on non-default port");

    // 4c. Hide Xposed classes
    var originalForName = Java.use("java.lang.Class").forName.overload("java.lang.String");
    Java.use("java.lang.Class").forName.overload("java.lang.String").implementation = function (name) {
        if (name.indexOf("de.robv.android.xposed") === 0) {
            throw Java.use("java.lang.ClassNotFoundException").$new(name);
        }
        return originalForName.call(this, name);
    };
    console.log("[+] Xposed classes hidden from Class.forName");

    // 4d. Hide debugger
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        return false;
    };
    console.log("[+] Debug.isDebuggerConnected spoofed to false");

    // 4e. TracerPid — blocked via /proc/self/status redirect (see 2a)
    console.log("[+] TracerPid blocked via /proc/self/status redirect");

    // NOTE: Cannot bypass rwxp detection — Frida fundamentally needs RWX pages
    // NOTE: Cannot bypass sensor noise (physical characteristic)
    // NOTE: Cannot bypass ArtMethod hotness_count (native ART memory)

    console.log("");
    console.log("========================================");
    console.log("[ATTACKER] Summary of what CANNOT be bypassed:");
    console.log("  - Sensor noise analysis (MEMS physics)");
    console.log("  - Sensor absence (step counter/significant motion)");
    console.log("  - Battery temp/voltage (emulator-specific)");
    console.log("  - rwxp memory segments (Frida JIT requirement)");
    console.log("  - ArtMethod hotness_count (native ART memory)");
    console.log("  - Signing certificate (need original cert bytes)");
    console.log("========================================");
});
