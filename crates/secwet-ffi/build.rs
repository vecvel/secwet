// Compiles the JNI bridge for Android targets. Other targets need nothing.
fn main() {
    println!("cargo:rerun-if-changed=android/jni_bridge.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        cc::Build::new()
            .file("android/jni_bridge.c")
            .flag_if_supported("-Wall")
            .flag_if_supported("-Wextra")
            .compile("secwet_jni");
    }
}
