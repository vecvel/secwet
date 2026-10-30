fn main() {
    // The target, not the host: cross checks for Windows and Linux skip it.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=src/biometric/macos.m");
        cc::Build::new()
            .file("src/biometric/macos.m")
            .flag("-fobjc-arc")
            .compile("secwet_biometric");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }
    tauri_build::build();
}
