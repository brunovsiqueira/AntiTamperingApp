/**
 * Frida script to bypass CloningDetector signals.
 *
 * Replicates the bypass techniques from Matrioska's DeceivingContainer
 * (github.com/samudoria/Matrioska/RQ1/antivirtualization_libraries/DeceivingContainer/)
 * to test whether our soft signal fallback (and ArtMethod check) still catches
 * the virtual container when Java-level checks are hooked.
 *
 * Must be run INSIDE Parallel Space on the cloned app instance.
 *
 * Usage:
 *   # Find the cloned app's PID (runs under Parallel Space's process)
 *   frida-ps -D <device> | grep -i anti
 *   frida -D <device> -p <PID> -l tools/frida-bypass-cloning-signals.js
 *
 * What it hooks (matches Matrioska DeceivingContainer):
 *   1. File("<init>") — blocks /proc/self/maps reading
 *   2. Context.getFilesDir() — returns fake path without container package
 *   3. Context.getDataDir() — returns fake path
 *   4. ApplicationInfo.sourceDir — returns /data/app/ path
 *   5. Throwable.getStackTrace() — strips cloner class names
 *   6. PackageManager.getPackageInfo() — hides cloner packages
 */

Java.perform(function () {
    console.log("[*] Cloning bypass script loaded");

    var targetPackage = "com.bruno.antitamperingapp";

    // ── 1. Block /proc/self/maps reading ──
    // Source: Matrioska Hook_File.java
    // Prevents clone_proc_maps check from finding foreign paths
    var File = Java.use("java.io.File");
    File.$init.overload("java.lang.String").implementation = function (path) {
        if (path === "/proc/self/maps") {
            console.log("[+] Blocked /proc/self/maps access → redirecting to /dev/null");
            this.$init("/dev/null");
            return;
        }
        this.$init(path);
    };
    console.log("[+] File.<init> hooked (blocks /proc/self/maps)");

    // ── 2. Fake filesDir path ──
    // Source: Matrioska Hook_getDataDir.java
    // Prevents clone_data_dir check from seeing container package in path
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    ContextWrapper.getFilesDir.implementation = function () {
        var real = this.getFilesDir();
        var fakePath = "/data/user/0/" + targetPackage + "/files";
        console.log("[+] Spoofed getFilesDir: " + real + " → " + fakePath);
        return Java.use("java.io.File").$new(fakePath);
    };
    console.log("[+] getFilesDir() hooked");

    // ── 3. Fake dataDir ──
    ContextWrapper.getDataDir.implementation = function () {
        var fakePath = "/data/user/0/" + targetPackage;
        console.log("[+] Spoofed getDataDir → " + fakePath);
        return Java.use("java.io.File").$new(fakePath);
    };
    console.log("[+] getDataDir() hooked");

    // ── 4. Fake sourceDir ──
    // Source: Matrioska Hook_PackageCodePath.java
    // Prevents clone_apk_source check from seeing /data/data/ path
    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    var originalSourceDir = ApplicationInfo.sourceDir;
    // Hook via Context.getApplicationInfo() to intercept sourceDir access
    ContextWrapper.getApplicationInfo.implementation = function () {
        var info = this.getApplicationInfo();
        var fakeSource = "/data/app/~~fake~~/" + targetPackage + "-fake/base.apk";
        info.sourceDir.value = fakeSource;
        console.log("[+] Spoofed sourceDir → " + fakeSource);
        return info;
    };
    console.log("[+] getApplicationInfo().sourceDir hooked");

    // ── 5. Strip cloner classes from stack traces ──
    // Source: Matrioska Hook_getStackTrace.java
    // Prevents clone_stack_trace check from finding cloner class prefixes
    var Throwable = Java.use("java.lang.Throwable");
    Throwable.getStackTrace.implementation = function () {
        var stack = this.getStackTrace();
        var filtered = [];
        var clonerPrefixes = [
            "com.lody.virtual",
            "com.doubleagent",
            "io.va.exposed",
            "com.excelliance",
            "io.tt",
            "com.estrongs.vbox",
            "org.nl",
            "com.polestar",
            "com.lbe.parallel",
        ];
        for (var i = 0; i < stack.length; i++) {
            var className = stack[i].getClassName();
            var isCloner = false;
            for (var j = 0; j < clonerPrefixes.length; j++) {
                if (className.indexOf(clonerPrefixes[j]) === 0) {
                    isCloner = true;
                    break;
                }
            }
            if (!isCloner) {
                filtered.push(stack[i]);
            }
        }
        if (filtered.length !== stack.length) {
            console.log("[+] Stripped " + (stack.length - filtered.length) + " cloner frames from stack trace");
        }
        return filtered;
    };
    console.log("[+] getStackTrace() hooked (strips cloner classes)");

    // ── 6. Hide cloner packages from PackageManager ──
    // Prevents clone_packages check from finding installed cloners
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (name, flags) {
        var clonerPackages = [
            "com.lbe.parallel.intl", "com.lbe.parallel",
            "com.ludashi.dualspace", "com.applisto.appcloner",
            "com.virtualapp", "io.virtualapp",
        ];
        for (var i = 0; i < clonerPackages.length; i++) {
            if (name === clonerPackages[i]) {
                console.log("[+] Hiding cloner package: " + name);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(name);
            }
        }
        return this.getPackageInfo(name, flags);
    };
    console.log("[+] getPackageInfo() hooked (hides cloner packages)");

    // ── 7. Clear VirtualApp environment variables ──
    // Prevents clone_env_vars check from finding V_REPLACE_ITEM etc.
    // Note: System.getenv() returns an unmodifiable map, so we hook the method directly
    var System = Java.use("java.lang.System");
    System.getenv.overload("java.lang.String").implementation = function (name) {
        var blockedVars = [
            "V_REPLACE_ITEM", "V_KEEP_ITEM", "V_SO_PATH",
            "REPLACE_ITEM_ORIG", "REPLACE_ITEM_DST",
            "V_API_LEVEL", "V_PREVIEW_API_LEVEL",
        ];
        for (var i = 0; i < blockedVars.length; i++) {
            if (name === blockedVars[i]) {
                console.log("[+] Hiding env var: " + name);
                return null;
            }
        }
        var result = this.getenv(name);
        // Also hide LD_PRELOAD if it points to container
        if (name === "LD_PRELOAD" && result && result.indexOf("/data/data/") !== -1) {
            console.log("[+] Hiding LD_PRELOAD: " + result);
            return null;
        }
        return result;
    };
    console.log("[+] System.getenv() hooked (hides VirtualApp env vars)");

    console.log("[*] All cloning signals bypassed. Only ArtMethod check should still detect.");
    console.log("[*] ArtMethod operates below the Java hooking layer — Frida cannot intercept it.");
});
