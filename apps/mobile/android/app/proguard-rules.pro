# R8 rules for release builds.
#
# libsecwet_ffi.so (crates/secwet-ffi/android/jni_bridge.c) looks these up by
# name with GetStaticMethodID, so R8 sees no callers and would strip or rename
# them. Without them the platform never registers and every FFI call answers
# not_ready. build.gradle.kts checks seeds.txt after every minified build.
-keep class app.secwet.secwet_mobile.SecwetNative {
    public static <methods>;
    native <methods>;
}
