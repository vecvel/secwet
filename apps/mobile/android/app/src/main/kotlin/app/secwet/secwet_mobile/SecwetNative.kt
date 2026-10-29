package app.secwet.secwet_mobile

import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import java.io.File
import java.lang.ref.WeakReference
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * Android platform services for the Rust app layer (crates/secwet-ffi). The
 * JNI bridge (crates/secwet-ffi/android/jni_bridge.c) calls these static
 * methods from Rust threads. Keys pass only between Rust and the Android
 * Keystore wrapper below; they never reach Dart.
 */
object SecwetNative {
    private lateinit var appContext: Context
    private var activityRef = WeakReference<FragmentActivity>(null)
    private val main = Handler(Looper.getMainLooper())

    @Volatile private var installed = false

    init {
        System.loadLibrary("secwet_ffi")
    }

    /**
     * Implemented in Rust (Java_app_secwet_secwet_1mobile_SecwetNative_nativeInstall).
     * Both arguments are UTF-8: JNI's own string conversion produces modified
     * UTF-8, which Rust rejects for names with emoji. 0 registered, 1 already
     * registered, -1 failed.
     */
    @JvmStatic private external fun nativeInstall(dataDir: ByteArray, deviceName: ByteArray): Int

    /** Registers the services with Rust. Call before the Flutter engine starts Dart. */
    fun install(context: Context) {
        if (installed) return
        appContext = context.applicationContext
        val dir = File(appContext.noBackupFilesDir, "secwet").apply { mkdirs() }
        val rc = nativeInstall(dir.absolutePath.toByteArray(Charsets.UTF_8), deviceName().toByteArray(Charsets.UTF_8))
        // On failure the next activity start tries again.
        installed = rc == 0 || rc == 1
        if (installed) clipboard.addPrimaryClipChangedListener { onClipChanged() }
    }

    /** The activity that shows the biometric prompt. */
    fun attach(activity: FragmentActivity) {
        activityRef = WeakReference(activity)
    }

    /** Back in focus: clears a copied value whose timer could not run (a frozen background process). */
    fun focused() {
        if (installed) sweepClipboard()
    }

    private fun deviceName(): String =
        Settings.Global.getString(appContext.contentResolver, Settings.Global.DEVICE_NAME)
            ?.takeIf { it.isNotBlank() }
            ?: Build.MODEL

    /** Runs [body] on the main thread and waits for its result. */
    private fun <T> onMain(timeoutSeconds: Long, fallback: T, body: () -> T): T {
        if (Looper.myLooper() == Looper.getMainLooper()) return body()
        var result = fallback
        val done = CountDownLatch(1)
        main.post {
            try {
                result = body()
            } finally {
                done.countDown()
            }
        }
        done.await(timeoutSeconds, TimeUnit.SECONDS)
        return result
    }

    // ------------------------------------------------------------------
    // Key storage. Entries are sealed with AES-256-GCM under a random data
    // key. The data key is stored only wrapped (RSA-OAEP) by a key pair that
    // never leaves the Android Keystore; on a phone with a screen lock the
    // private key needs the user's authentication (strong biometric or the
    // device PIN, pattern or password). On Android 11+ it is an auth-per-use
    // key: only the unlock prompt (biometricVerify), which carries the
    // unwrap cipher as its CryptoObject, can authorize it; unlocking the
    // phone itself does not. Older versions accept any authentication in
    // the last few seconds. The prompt unwraps the data key into memory for
    // one session; endSession wipes it. Wrapping uses the public key, which
    // needs no authentication, so new stores and new entries never prompt.
    // Without a screen lock the key pair cannot require authentication; it is
    // replaced by a protected one on the first unlock after a lock is set.
    // Removing the screen lock makes Android delete the protected key pair.
    // ------------------------------------------------------------------

    private const val PAIR_ALIAS = "app.secwet.keystore.v2"
    private const val PREFS = "secwet_keystore"
    private const val DATA_KEY_PREF = "data_key.v2"
    private const val PROTECTED_PREF = "data_key.protected"
    private const val PER_USE_PREF = "data_key.per_use"
    private const val IV_BYTES = 12
    private const val AUTH_SECONDS = 15

    private val prefs: SharedPreferences by lazy { appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE) }
    private val keyLock = Any()
    private var dataKey: ByteArray? = null

    private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** The phone has a PIN, pattern or password. */
    @JvmStatic
    fun deviceLock(): Boolean =
        (appContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

    private fun generatePair(protect: Boolean) {
        val spec = KeyGenParameterSpec.Builder(PAIR_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(3072)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        if (protect) {
            spec.setUserAuthenticationRequired(true)
            if (perUseKeys) {
                // 0 seconds: every unwrap needs its own prompt.
                spec.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
                // Enrolling another fingerprint must not destroy the stored keys.
                spec.setInvalidatedByBiometricEnrollment(false)
            } else {
                @Suppress("DEPRECATION")
                spec.setUserAuthenticationValidityDurationSeconds(AUTH_SECONDS)
            }
        }
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").run {
            initialize(spec.build())
            generateKeyPair()
        }
    }

    /** Android 11+ prompts can carry a CryptoObject together with the device credential. */
    private val perUseKeys: Boolean
        get() = Build.VERSION.SDK_INT >= 30

    /** Wraps [key] with the public key (a software copy, so no prompt). */
    private fun wrap(key: ByteArray): Boolean {
        val cert = androidKeyStore().getCertificate(PAIR_ALIAS) ?: return false
        val publicKey = KeyFactory.getInstance(cert.publicKey.algorithm).generatePublic(X509EncodedKeySpec(cert.publicKey.encoded))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaep)
        val wrapped = cipher.doFinal(key)
        return prefs.edit().putString(DATA_KEY_PREF, Base64.encodeToString(wrapped, Base64.NO_WRAP)).commit()
    }

    /** A decrypt cipher over the private key; null without a stored data key. */
    private fun unwrapCipher(): Cipher? {
        if (prefs.getString(DATA_KEY_PREF, null) == null) return null
        val privateKey = androidKeyStore().getKey(PAIR_ALIAS, null) as? PrivateKey ?: return null
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply {
            init(Cipher.DECRYPT_MODE, privateKey, oaep)
        }
    }

    /**
     * Unwraps the data key into memory with [cipher] (the prompt's, for an
     * auth-per-use key) or a fresh one. A protected key throws unless the
     * user just authenticated for it.
     */
    private fun unwrap(cipher: Cipher? = null): ByteArray? {
        val stored = prefs.getString(DATA_KEY_PREF, null) ?: return null
        val use = cipher ?: unwrapCipher() ?: return null
        return use.doFinal(Base64.decode(stored, Base64.NO_WRAP))
    }

    /** The stored pair needs the prompt's own cipher to unwrap. */
    private fun needsPromptCipher(): Boolean =
        prefs.getBoolean(PROTECTED_PREF, false) && prefs.getBoolean(PER_USE_PREF, false)

    /** The session's data key; a new store creates one (no prompt needed). */
    private fun sessionKey(): ByteArray? {
        synchronized(keyLock) { return openSessionKey() }
    }

    private fun openSessionKey(): ByteArray? {
        dataKey?.let { return it }
        if (prefs.getString(DATA_KEY_PREF, null) == null) {
            val protect = deviceLock()
            androidKeyStore().deleteEntry(PAIR_ALIAS)
            generatePair(protect)
            val fresh = ByteArray(32).also { SecureRandom().nextBytes(it) }
            if (!wrap(fresh)) {
                Arrays.fill(fresh, 0)
                return null
            }
            prefs.edit().putBoolean(PROTECTED_PREF, protect).putBoolean(PER_USE_PREF, protect && perUseKeys).commit()
            dataKey = fresh
            return fresh
        }
        // An unprotected pair (no screen lock) opens without a prompt.
        if (!prefs.getBoolean(PROTECTED_PREF, false)) {
            dataKey = unwrap()
        }
        return dataKey
    }

    /**
     * Called after a successful prompt: opens the session. [cipher] is the
     * prompt's authorized CryptoObject cipher (null when it carried none).
     */
    private fun beginSession(cipher: Cipher?): Boolean {
        synchronized(keyLock) { return openSession(cipher) }
    }

    private fun openSession(cipher: Cipher?): Boolean {
        if (prefs.getString(DATA_KEY_PREF, null) == null) return true
        // An auth-per-use key opens only through the prompt that authorized it.
        if (needsPromptCipher() && cipher == null) return false
        val key = try {
            unwrap(cipher)
        } catch (e: Exception) {
            null
        } ?: return false
        dataKey?.let { Arrays.fill(it, 0) }
        dataKey = key
        // A screen lock was set since this store was created, or the pair is
        // still the older time-bound kind: protect it the current way now.
        val upgrade = !prefs.getBoolean(PROTECTED_PREF, false) || (perUseKeys && !prefs.getBoolean(PER_USE_PREF, false))
        if (upgrade && deviceLock()) {
            try {
                androidKeyStore().deleteEntry(PAIR_ALIAS)
                generatePair(true)
                if (wrap(key)) {
                    prefs.edit().putBoolean(PROTECTED_PREF, true).putBoolean(PER_USE_PREF, perUseKeys).commit()
                }
            } catch (e: Exception) {
                // Keep working this session; the next unlock tries again.
            }
        }
        return true
    }

    @JvmStatic
    fun endSession() {
        synchronized(keyLock) {
            dataKey?.let { Arrays.fill(it, 0) }
            dataKey = null
        }
    }

    private fun prefKey(entry: String) = Base64.encodeToString(entry.toByteArray(), Base64.NO_WRAP or Base64.URL_SAFE)

    @JvmStatic
    fun keystoreGet(entry: String): ByteArray? {
        val stored = prefs.getString(prefKey(entry), null) ?: return null
        val blob = Base64.decode(stored, Base64.NO_WRAP)
        if (blob.size <= IV_BYTES) return null
        val key = sessionKey() ?: throw IllegalStateException("Secwet is locked")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob, 0, IV_BYTES))
        return cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
    }

    @JvmStatic
    fun keystoreSet(entry: String, value: ByteArray): Boolean {
        val key = sessionKey() ?: return false
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val sealed = cipher.doFinal(value)
        val blob = cipher.iv + sealed
        val ok = prefs.edit().putString(prefKey(entry), Base64.encodeToString(blob, Base64.NO_WRAP)).commit()
        Arrays.fill(blob, 0)
        return ok
    }

    @JvmStatic
    fun keystoreDelete(entry: String): Boolean = prefs.edit().remove(prefKey(entry)).commit()

    // ------------------------------------------------------------------
    // Clipboard: marked sensitive so it stays out of the clipboard preview
    // and keyboard suggestions (Android 13+).
    //
    // Since Android 10 an app without focus reads the clipboard as empty,
    // and that is exactly when the 30-second clear runs: the user copied a
    // value in Secwet and switched apps to paste it. So Secwet remembers
    // what it wrote and answers with that while it cannot read the
    // clipboard itself, unless it has seen something else being copied
    // since. A change it cannot read counts as someone else's, so it is
    // never cleared. Clearing works without focus (Android 9+).
    // ------------------------------------------------------------------

    /** Matches the app layer's auto-clear delay (secwet-app state.rs). */
    private const val CLEAR_AFTER_MS = 30_000L

    private val clipboard: ClipboardManager
        get() = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    // Main thread only.
    private var ownedClip: ByteArray? = null
    private var ownedAt = 0L

    private fun dropOwnedClip() {
        ownedClip?.let { Arrays.fill(it, 0) }
        ownedClip = null
    }

    /** Secwet's window has focus, so clipboard reads are real. */
    private fun canReadClipboard(): Boolean = activityRef.get()?.hasWindowFocus() == true

    private fun currentClipText(): ByteArray? =
        clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()?.toByteArray(Charsets.UTF_8)

    private fun onClipChanged() {
        val owned = ownedClip ?: return
        if (!canReadClipboard()) {
            // Secwet only writes while in front: a change now is someone else's.
            dropOwnedClip()
            return
        }
        val current = currentClipText()
        if (current == null || !current.contentEquals(owned)) dropOwnedClip()
        current?.let { Arrays.fill(it, 0) }
    }

    /** Clears Secwet's own value once its time is up (the timer may not have run in the background). */
    private fun sweepClipboard() {
        val owned = ownedClip ?: return
        if (SystemClock.elapsedRealtime() - ownedAt < CLEAR_AFTER_MS) return
        val current = currentClipText()
        if (current != null && current.contentEquals(owned)) clearClip()
        current?.let { Arrays.fill(it, 0) }
        dropOwnedClip()
    }

    private fun clearClip() {
        if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip() else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
    }

    @JvmStatic
    fun clipboardWrite(text: ByteArray): Boolean = onMain(5, false) {
        val clip = ClipData.newPlainText("Secwet", String(text, Charsets.UTF_8))
        clip.description.extras = PersistableBundle().apply {
            val key = if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
            putBoolean(key, true)
        }
        dropOwnedClip()
        clipboard.setPrimaryClip(clip)
        // The change listener runs later and finds this value: still ours.
        ownedClip = text.copyOf()
        ownedAt = SystemClock.elapsedRealtime()
        true
    }

    /**
     * The clipboard text; null when it is empty. Throws when the clipboard
     * cannot be read and holds no value Secwet knows to be its own, so the
     * caller leaves it alone.
     */
    @JvmStatic
    fun clipboardRead(): ByteArray? = onMain<Result<ByteArray?>>(5, Result.failure(IllegalStateException("timed out"))) {
        if (canReadClipboard()) {
            Result.success(currentClipText())
        } else {
            ownedClip?.let { Result.success(it.copyOf()) }
                ?: Result.failure(IllegalStateException("The clipboard is not readable without focus"))
        }
    }.getOrThrow()

    @JvmStatic
    fun clipboardClear(): Boolean = onMain(5, false) {
        dropOwnedClip()
        clearClip()
        true
    }

    // ------------------------------------------------------------------
    // Unlock prompt: BiometricPrompt with a strong biometric or the device
    // PIN, pattern or password. Success opens the key session above.
    // ------------------------------------------------------------------

    /** Authenticators the prompt offers (STRONG with a credential needs Android 11). */
    private val unlockAuthenticators: Int
        get() = if (Build.VERSION.SDK_INT >= 30) BIOMETRIC_STRONG or DEVICE_CREDENTIAL else BIOMETRIC_WEAK or DEVICE_CREDENTIAL

    /** 0 none, 4 fingerprint, 5 face, 6 iris, 7 several (secwet_ffi.h). */
    @JvmStatic
    fun biometricKind(): Int {
        val strong = if (Build.VERSION.SDK_INT >= 30) BIOMETRIC_STRONG else BIOMETRIC_WEAK
        val status = BiometricManager.from(appContext).canAuthenticate(strong)
        // Temporarily unavailable hardware still counts; the prompt then offers the PIN.
        if (status != BiometricManager.BIOMETRIC_SUCCESS &&
            status != BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
        ) {
            return 0
        }
        val pm = appContext.packageManager
        val kinds = buildList {
            if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) add(4)
            if (Build.VERSION.SDK_INT >= 29 && pm.hasSystemFeature(PackageManager.FEATURE_FACE)) add(5)
            if (Build.VERSION.SDK_INT >= 29 && pm.hasSystemFeature(PackageManager.FEATURE_IRIS)) add(6)
        }
        return when (kinds.size) {
            0 -> if (status == BiometricManager.BIOMETRIC_SUCCESS) 7 else 0
            1 -> kinds[0]
            else -> 7
        }
    }

    /** Longest a prompt may stay open before the waiting thread gives up. */
    private const val PROMPT_TIMEOUT_MINUTES = 5L

    /** Shows the prompt on the main thread; blocks this (background) thread until it ends. */
    @JvmStatic
    fun biometricVerify(reason: ByteArray): Int {
        val activity = activityRef.get() ?: return 3
        if (!deviceLock()) return 3
        val subtitle = String(reason, Charsets.UTF_8).replaceFirstChar { it.uppercase() }
        // An auth-per-use key is unwrapped by the prompt's own cipher.
        val crypto = if (needsPromptCipher()) {
            try {
                unwrapCipher()?.let { BiometricPrompt.CryptoObject(it) } ?: return 2
            } catch (e: Exception) {
                // The key pair is gone (screen lock removed) or unusable.
                return 2
            }
        } else {
            null
        }
        val done = CountDownLatch(1)
        var result = -2
        var authorized: Cipher? = null
        var prompt: BiometricPrompt? = null
        main.post {
            // androidx.biometric ignores authenticate() without any callback
            // once the activity has saved its state; never wait on that.
            if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) ||
                activity.supportFragmentManager.isStateSaved
            ) {
                result = 1
                done.countDown()
                return@post
            }
            val shown = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        authorized = r.cryptoObject?.cipher
                        result = 0
                        done.countDown()
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        result = when (code) {
                            BiometricPrompt.ERROR_USER_CANCELED,
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_CANCELED -> 1
                            BiometricPrompt.ERROR_LOCKOUT,
                            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> 2
                            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                            BiometricPrompt.ERROR_HW_NOT_PRESENT -> 3
                            BiometricPrompt.ERROR_HW_UNAVAILABLE -> 4
                            else -> -2
                        }
                        done.countDown()
                    }

                    // A single failed match keeps the prompt open for another try.
                    override fun onAuthenticationFailed() {}
                },
            )
            prompt = shown
            // With a device credential allowed the prompt has its own
            // "Use PIN" action and no negative button.
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Secwet")
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(unlockAuthenticators)
                .build()
            try {
                if (crypto != null) shown.authenticate(info, crypto) else shown.authenticate(info)
            } catch (e: IllegalStateException) {
                result = -2
                done.countDown()
            } catch (e: IllegalArgumentException) {
                result = -2
                done.countDown()
            }
        }
        if (!done.await(PROMPT_TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
            main.post { prompt?.cancelAuthentication() }
            return 1
        }
        // Only this prompt's cipher (or, before Android 11, its time window)
        // authorizes the unwrap.
        if (result == 0 && !beginSession(authorized)) result = 2
        return result
    }
}
