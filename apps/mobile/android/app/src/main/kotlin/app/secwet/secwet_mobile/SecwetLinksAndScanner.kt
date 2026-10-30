package app.secwet.secwet_mobile

import android.content.Intent
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel

/**
 * `app.secwet/links`: `secwet://invite` and `secwet://pair` links the app was
 * opened with. Dart asks for the launch link with `initialLink`; later links
 * (singleTop, onNewIntent) arrive as `link` calls.
 */
class SecwetLinksChannel(messenger: BinaryMessenger) {
    private val channel = MethodChannel(messenger, "app.secwet/links")
    private var pending: String? = null

    init {
        channel.setMethodCallHandler { call, result ->
            if (call.method == "initialLink") {
                result.success(pending)
                pending = null
            } else {
                result.notImplemented()
            }
        }
    }

    /** Keeps the link of [intent] if it is a secwet:// link and hands it to Dart. */
    fun receive(intent: Intent?) {
        val uri = intent?.takeIf { it.action == Intent.ACTION_VIEW }?.data ?: return
        if (uri.scheme?.lowercase() != "secwet") return
        val link = uri.toString()
        pending = link
        channel.invokeMethod("link", link, object : MethodChannel.Result {
            // Dart answers true once it took the link; before its handler is
            // set (cold start) the link waits for `initialLink`.
            override fun success(reply: Any?) {
                if (reply == true) pending = null
            }

            override fun error(code: String, message: String?, details: Any?) {}

            override fun notImplemented() {}
        })
    }
}

/**
 * `app.secwet/scanner`: `scan` opens Google Play services' code scanner for
 * QR codes and returns the text (null when cancelled). The scanner runs in
 * Play services, so Secwet needs no camera permission and never sees frames.
 */
class SecwetScannerChannel(private val activity: FlutterFragmentActivity, messenger: BinaryMessenger) {
    private var busy = false

    init {
        MethodChannel(messenger, "app.secwet/scanner").setMethodCallHandler { call, result ->
            if (call.method != "scan") {
                result.notImplemented()
                return@setMethodCallHandler
            }
            if (busy) {
                result.error("busy", "The scanner is already open.", null)
                return@setMethodCallHandler
            }
            busy = true
            val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
            GmsBarcodeScanning.getClient(activity, options).startScan()
                .addOnSuccessListener { code ->
                    busy = false
                    result.success(code.rawValue)
                }
                .addOnCanceledListener {
                    busy = false
                    result.success(null)
                }
                .addOnFailureListener { e ->
                    busy = false
                    result.error("camera_unavailable", e.message ?: "Couldn't open the scanner.", null)
                }
        }
    }
}
