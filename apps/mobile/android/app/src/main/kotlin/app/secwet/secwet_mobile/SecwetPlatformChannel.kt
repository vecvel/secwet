package app.secwet.secwet_mobile

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.provider.Settings
import android.system.Os
import android.system.OsConstants
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Arrays

/**
 * `app.secwet/platform` channel: the Storage Access Framework document picker
 * and save dialog, the app's private temp folder, PDF page rendering for
 * asset previews, and the phone's security settings.
 */
class SecwetPlatformChannel(
    private val activity: FragmentActivity,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler {
    private var pending: MethodChannel.Result? = null
    private var exportSource: File? = null
    // Decrypted asset bytes waiting for the user to pick where they go. Kept
    // only in memory: nothing plaintext is staged on disk.
    private var exportBytes: ByteArray? = null

    private val openLauncher: ActivityResultLauncher<Array<String>> =
        activity.activityResultRegistry.register("secwet-open", ActivityResultContracts.OpenDocument()) { uri ->
            finish(uri?.let { copyIn(it) })
        }

    private val createLauncher: ActivityResultLauncher<String> =
        activity.activityResultRegistry.register(
            "secwet-create",
            ActivityResultContracts.CreateDocument("application/octet-stream"),
        ) { uri -> finish(uri?.let { copyOut(it) } ?: false) }

    init {
        // Once per process, before Dart runs: a file left in the temp folder by
        // a process that died with a dialog open never outlives the next
        // launch. Not on activity re-creation, which can happen mid-dialog.
        if (!swept) {
            swept = true
            clearTempDir()
        }
        MethodChannel(messenger, "app.secwet/platform").setMethodCallHandler(this)
    }

    private fun tempDir(): File = File(activity.cacheDir, "secwet-files").apply { mkdirs() }

    private fun clearTempDir() {
        tempDir().listFiles()?.forEach { it.deleteRecursively() }
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "tempDirectory" -> result.success(tempDir().absolutePath)
            "clearTempDirectory" -> {
                if (pending == null) clearTempDir()
                result.success(null)
            }
            "openSecuritySettings" -> {
                val intent = Intent(Settings.ACTION_SECURITY_SETTINGS)
                try {
                    activity.startActivity(intent)
                } catch (_: Exception) {
                    activity.startActivity(Intent(Settings.ACTION_SETTINGS))
                }
                result.success(null)
            }
            "saveBytes" -> {
                val bytes = call.argument<ByteArray>("bytes")
                val name = call.argument<String>("name")
                if (bytes == null || name.isNullOrEmpty()) {
                    result.error("invalid", "Missing bytes or name.", null)
                    return
                }
                if (!begin(result)) {
                    Arrays.fill(bytes, 0)
                    return
                }
                exportBytes = bytes
                createLauncher.launch(name)
            }
            "pickFile" -> {
                if (!begin(result)) return
                openLauncher.launch(arrayOf("*/*"))
            }
            "saveFile" -> {
                val path = call.argument<String>("path")
                if (path == null) {
                    result.error("invalid", "Missing path.", null)
                    return
                }
                if (!begin(result)) return
                val source = File(path)
                exportSource = source
                createLauncher.launch(call.argument<String>("name") ?: source.name)
            }
            "renderPdf" -> {
                val bytes = call.argument<ByteArray>("bytes")
                if (bytes == null) {
                    result.error("invalid", "Missing bytes.", null)
                    return
                }
                val maxPages = call.argument<Int>("maxPages") ?: 20
                val width = call.argument<Int>("width") ?: 1080
                Thread {
                    val pages = try {
                        renderPdf(bytes, maxPages, width)
                    } catch (_: Exception) {
                        emptyList()
                    }
                    activity.runOnUiThread { result.success(pages) }
                }.start()
            }
            else -> result.notImplemented()
        }
    }

    private fun begin(result: MethodChannel.Result): Boolean {
        if (pending != null) {
            result.error("busy", "Another file dialog is open.", null)
            return false
        }
        pending = result
        return true
    }

    private fun finish(value: Any?) {
        exportSource?.delete()
        exportSource = null
        exportBytes?.let { Arrays.fill(it, 0) }
        exportBytes = null
        pending?.success(value)
        pending = null
    }

    /** Copies a picked document into the app's private temp folder. */
    private fun copyIn(uri: Uri): Map<String, String>? {
        val resolver = activity.contentResolver
        val name = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        } ?: "backup.secwet"
        val target = File(tempDir(), File(name).name)
        val input = resolver.openInputStream(uri) ?: return null
        input.use { inp -> target.outputStream().use { inp.copyTo(it) } }
        return mapOf("path" to target.absolutePath, "name" to name)
    }

    /**
     * Draws PDF pages with PdfRenderer. It needs a seekable file descriptor:
     * an anonymous in-memory file on Android 11 and later, so the document
     * never touches the disk. Older versions use a file in the private cache
     * that is deleted after rendering (and by the launch sweep).
     */
    private fun renderPdf(bytes: ByteArray, maxPages: Int, width: Int): List<ByteArray> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val memory = Os.memfd_create("secwet-preview", 0)
            try {
                var written = 0
                while (written < bytes.size) written += Os.write(memory, bytes, written, bytes.size - written)
                Os.lseek(memory, 0, OsConstants.SEEK_SET)
                return renderPages(ParcelFileDescriptor.dup(memory), maxPages, width)
            } finally {
                Os.close(memory)
            }
        }
        val file = File.createTempFile("preview", ".pdf", tempDir())
        try {
            file.writeBytes(bytes)
            return renderPages(ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY), maxPages, width)
        } finally {
            file.delete()
        }
    }

    private fun renderPages(fd: ParcelFileDescriptor, maxPages: Int, width: Int): List<ByteArray> {
        try {
            val renderer = PdfRenderer(fd)
            try {
                return (0 until minOf(renderer.pageCount, maxPages)).map { index ->
                    val page = renderer.openPage(index)
                    try {
                        val height = (width.toFloat() * page.height / page.width).toInt().coerceAtLeast(1)
                        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                        bitmap.eraseColor(Color.WHITE)
                        page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        val out = ByteArrayOutputStream()
                        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
                        bitmap.recycle()
                        out.toByteArray()
                    } finally {
                        page.close()
                    }
                }
            } finally {
                renderer.close()
            }
        } finally {
            fd.close()
        }
    }

    /** Writes the exported archive, or the asset bytes, to the document the user created. */
    private fun copyOut(uri: Uri): Boolean {
        val output = activity.contentResolver.openOutputStream(uri, "w") ?: return false
        exportBytes?.let { bytes ->
            output.use { it.write(bytes) }
            return true
        }
        val source = exportSource ?: run {
            output.close()
            return false
        }
        output.use { out -> source.inputStream().use { it.copyTo(out) } }
        return true
    }

    private companion object {
        @Volatile var swept = false
    }
}
