# Consumer ProGuard rules for the detection SDK.
# Only keep the PUBLIC API surface — internal detection logic gets obfuscated.
# Source: https://developer.android.com/topic/performance/app-optimization/library-optimization

# Public API — data classes accessed by the consuming app's UI
-keep class com.bruno.antitamperingapp.detection.DetectionEngine { public *; }
-keep class com.bruno.antitamperingapp.detection.DetectionEngine$Builder { public *; }
-keep class com.bruno.antitamperingapp.detection.DetectionResult { *; }
-keep class com.bruno.antitamperingapp.detection.DetectionResult$Companion { *; }
-keep class com.bruno.antitamperingapp.detection.Evidence { *; }
-keep class com.bruno.antitamperingapp.detection.TamperVerdict { *; }
-keep class com.bruno.antitamperingapp.detection.TamperStatus { *; }
-keep class com.bruno.antitamperingapp.detection.TamperDetector { *; }
-keep class com.bruno.antitamperingapp.detection.DetectionCategory { *; }
-keep class com.bruno.antitamperingapp.detection.error.DetectionError { *; }
-keep class com.bruno.antitamperingapp.detection.error.DetectionError$* { *; }
-keep class com.bruno.antitamperingapp.detection.util.DetectionLogger { public *; }

# Public detector constructors — consumers instantiate these directly
-keep class com.bruno.antitamperingapp.detection.detectors.EmulatorDetector { public <init>(...); }
-keep class com.bruno.antitamperingapp.detection.detectors.CloningDetector { public <init>(...); }
-keep class com.bruno.antitamperingapp.detection.detectors.IntegrityDetector { public <init>(...); }
-keep class com.bruno.antitamperingapp.detection.detectors.HookingDetector { public <init>(...); }

# JNI — native method names must be preserved
-keep class com.bruno.antitamperingapp.detection.detectors.ArtMethodChecker {
    native <methods>;
    *** check*(...);
}

# Keep Kotlin coroutine internals needed by detectors
-keepclassmembers class * implements com.bruno.antitamperingapp.detection.TamperDetector {
    public suspend detect(android.content.Context);
}
