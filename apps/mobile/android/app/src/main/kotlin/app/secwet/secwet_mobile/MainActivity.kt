package app.secwet.secwet_mobile

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine

// FlutterFragmentActivity: BiometricPrompt needs a FragmentActivity.
class MainActivity : FlutterFragmentActivity() {
    private var channel: SecwetPlatformChannel? = null
    private var links: SecwetLinksChannel? = null
    private var scanner: SecwetScannerChannel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        // Rust needs secure storage, clipboard and biometrics before Dart runs.
        SecwetNative.install(this)
        SecwetNative.attach(this)
        // Keep secrets out of screenshots and the recent-apps preview.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }

    override fun onResume() {
        super.onResume()
        SecwetNative.attach(this)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // The clipboard is readable again only once the window has focus.
        if (hasFocus) SecwetNative.focused()
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        channel = SecwetPlatformChannel(this, flutterEngine.dartExecutor.binaryMessenger)
        scanner = SecwetScannerChannel(this, flutterEngine.dartExecutor.binaryMessenger)
        links = SecwetLinksChannel(flutterEngine.dartExecutor.binaryMessenger).also { it.receive(intent) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        links?.receive(intent)
    }
}
