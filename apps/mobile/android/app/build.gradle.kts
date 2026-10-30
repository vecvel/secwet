import org.gradle.api.tasks.Exec

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val rustJniLibs: File = layout.buildDirectory.get().asFile.resolve("rustJniLibs")

android {
    namespace = "app.secwet.secwet_mobile"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "app.secwet.secwet_mobile"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    // libsecwet_ffi.so for each ABI, built by the buildRust task below.
    sourceSets.getByName("main").jniLibs.srcDir(rustJniLibs)

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
            // Keeps the Kotlin methods the JNI bridge calls by name.
            proguardFiles("proguard-rules.pro")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    // BiometricPrompt: fingerprint, face or iris, whichever the phone has enrolled.
    implementation("androidx.biometric:biometric:1.1.0")
    // QR scanning for pairing, run by Google Play services (no camera permission).
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
}

// The Rust app layer (crates/secwet-ffi) as libsecwet_ffi.so, built with
// cargo-ndk for arm64-v8a, armeabi-v7a and x86_64. Cargo is incremental, so an
// unchanged tree costs a few seconds. Always release: the crypto is slow
// unoptimized.
val buildRust by tasks.registering(Exec::class) {
    val repoRoot = rootProject.projectDir.resolve("../../..").canonicalFile
    val home = System.getProperty("user.home")
    val cargo = File(home, ".cargo/bin/cargo").takeIf { it.exists() }?.path ?: "cargo"
    workingDir = repoRoot
    environment("PATH", "$home/.cargo/bin:" + System.getenv("PATH"))
    environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
    commandLine(
        cargo, "ndk",
        "-t", "arm64-v8a", "-t", "armeabi-v7a", "-t", "x86_64",
        "--platform", flutter.minSdkVersion.toString(),
        "-o", rustJniLibs.absolutePath,
        "build", "-p", "secwet-ffi", "--release",
    )
}

tasks.named("preBuild") { dependsOn(buildRust) }

// Fails a minified build when R8 would drop or rename a method that
// jni_bridge.c looks up by name: a release APK would otherwise start but never
// register the platform. R8's seeds.txt lists every member a keep rule kept,
// as "app.secwet.secwet_mobile.SecwetNative: <type> <name>(<args>)".
val jniMethods = listOf(
    "keystoreGet", "keystoreSet", "keystoreDelete",
    "clipboardWrite", "clipboardRead", "clipboardClear",
    "biometricKind", "biometricVerify", "deviceLock", "endSession", "nativeInstall",
)
tasks.matching { it.name == "minifyReleaseWithR8" }.configureEach {
    val seeds = layout.buildDirectory.file("outputs/mapping/release/seeds.txt")
    doLast {
        val kept = seeds.get().asFile.readLines()
            .filter { it.startsWith("app.secwet.secwet_mobile.SecwetNative: ") }
        val missing = jniMethods.filter { name -> kept.none { it.contains(" $name(") } }
        check(missing.isEmpty()) { "R8 does not keep the JNI methods $missing; check proguard-rules.pro" }
    }
}
