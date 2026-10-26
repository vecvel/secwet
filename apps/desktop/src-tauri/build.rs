fn main() {
    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .file("src/biometric.m")
            .flag("-fobjc-arc")
            .compile("secwet_biometric");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }
    tauri_build::build();
}
