// JNI side of the Android platform services. Rust calls these C functions
// (registered as SecwetPlatform) from any thread; each one attaches the thread
// to the JVM when needed and calls a static method of
// app.secwet.secwet_mobile.SecwetNative (Kotlin), which talks to the Android
// Keystore, the clipboard and BiometricPrompt.
//
// Byte arrays that carried key material are overwritten with zeros before
// they are released.

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct SecwetPlatform {
  int64_t (*keystore_get)(const char *entry, uint8_t *out, size_t cap);
  int32_t (*keystore_set)(const char *entry, const uint8_t *value, size_t len);
  int32_t (*keystore_delete)(const char *entry);
  int32_t (*clipboard_write)(const uint8_t *text, size_t len);
  int64_t (*clipboard_read)(uint8_t *out, size_t cap);
  int32_t (*clipboard_clear)(void);
  int32_t (*biometric_kind)(void);
  int32_t (*biometric_verify)(const uint8_t *reason, size_t len);
  int32_t (*device_lock)(void);
  void (*keystore_end_session)(void);
} SecwetPlatform;

extern int32_t secwet_ffi_register_platform(const SecwetPlatform *platform,
                                            const uint8_t *data_dir, size_t data_dir_len,
                                            const uint8_t *device_name, size_t device_name_len);

static JavaVM *g_vm = NULL;
static jclass g_class = NULL;
static jmethodID g_ks_get, g_ks_set, g_ks_delete;
static jmethodID g_clip_write, g_clip_read, g_clip_clear;
static jmethodID g_bio_kind, g_bio_verify, g_device_lock, g_end_session;

// Returns an env for this thread; *attached tells the caller to detach.
static JNIEnv *env_for_thread(int *attached) {
  JNIEnv *env = NULL;
  *attached = 0;
  if (g_vm == NULL) return NULL;
  jint rc = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
  if (rc == JNI_EDETACHED) {
    if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return NULL;
    *attached = 1;
  } else if (rc != JNI_OK) {
    return NULL;
  }
  return env;
}

static void done(int attached) {
  if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

// Clears a pending Java exception; returns 1 when there was one.
static int failed(JNIEnv *env) {
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionClear(env);
    return 1;
  }
  return 0;
}

static void wipe_array(JNIEnv *env, jbyteArray array, jsize len) {
  if (array == NULL || len <= 0) return;
  jbyte *zeros = calloc((size_t)len, 1);
  if (zeros == NULL) return;
  (*env)->SetByteArrayRegion(env, array, 0, len, zeros);
  free(zeros);
}

static jbyteArray new_bytes(JNIEnv *env, const uint8_t *data, size_t len) {
  jbyteArray array = (*env)->NewByteArray(env, (jsize)len);
  if (array != NULL && len > 0) (*env)->SetByteArrayRegion(env, array, 0, (jsize)len, (const jbyte *)data);
  return array;
}

// Copies a returned byte[] into out; -1 for null, -2 on exception.
static int64_t copy_result(JNIEnv *env, jbyteArray array, uint8_t *out, size_t cap) {
  if (failed(env)) return -2;
  if (array == NULL) return -1;
  jsize n = (*env)->GetArrayLength(env, array);
  if ((size_t)n <= cap && n > 0) (*env)->GetByteArrayRegion(env, array, 0, n, (jbyte *)out);
  wipe_array(env, array, n);
  (*env)->DeleteLocalRef(env, array);
  return (int64_t)n;
}

static int64_t ks_get(const char *entry, uint8_t *out, size_t cap) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return -2;
  jstring name = (*env)->NewStringUTF(env, entry);
  jbyteArray value = (jbyteArray)(*env)->CallStaticObjectMethod(env, g_class, g_ks_get, name);
  int64_t n = copy_result(env, value, out, cap);
  (*env)->DeleteLocalRef(env, name);
  done(attached);
  return n;
}

static int32_t ks_set(const char *entry, const uint8_t *value, size_t len) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return -2;
  jstring name = (*env)->NewStringUTF(env, entry);
  jbyteArray bytes = new_bytes(env, value, len);
  jboolean ok = (*env)->CallStaticBooleanMethod(env, g_class, g_ks_set, name, bytes);
  int32_t rc = (failed(env) || !ok) ? -2 : 0;
  wipe_array(env, bytes, (jsize)len);
  (*env)->DeleteLocalRef(env, bytes);
  (*env)->DeleteLocalRef(env, name);
  done(attached);
  return rc;
}

static int32_t ks_delete(const char *entry) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return -2;
  jstring name = (*env)->NewStringUTF(env, entry);
  jboolean ok = (*env)->CallStaticBooleanMethod(env, g_class, g_ks_delete, name);
  int32_t rc = (failed(env) || !ok) ? -2 : 0;
  (*env)->DeleteLocalRef(env, name);
  done(attached);
  return rc;
}

static int32_t clip_write(const uint8_t *text, size_t len) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return -2;
  jbyteArray bytes = new_bytes(env, text, len);
  jboolean ok = (*env)->CallStaticBooleanMethod(env, g_class, g_clip_write, bytes);
  int32_t rc = (failed(env) || !ok) ? -2 : 0;
  wipe_array(env, bytes, (jsize)len);
  (*env)->DeleteLocalRef(env, bytes);
  done(attached);
  return rc;
}

static int64_t clip_read(uint8_t *out, size_t cap) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return -2;
  jbyteArray value = (jbyteArray)(*env)->CallStaticObjectMethod(env, g_class, g_clip_read);
  int64_t n = copy_result(env, value, out, cap);
  done(attached);
  return n;
}

static int32_t clip_clear(void) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return -2;
  jboolean ok = (*env)->CallStaticBooleanMethod(env, g_class, g_clip_clear);
  int32_t rc = (failed(env) || !ok) ? -2 : 0;
  done(attached);
  return rc;
}

static int32_t bio_kind(void) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return 0;
  jint kind = (*env)->CallStaticIntMethod(env, g_class, g_bio_kind);
  if (failed(env)) kind = 0;
  done(attached);
  return (int32_t)kind;
}

static int32_t bio_verify(const uint8_t *reason, size_t len) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return -2;
  jbyteArray bytes = new_bytes(env, reason, len);
  jint rc = (*env)->CallStaticIntMethod(env, g_class, g_bio_verify, bytes);
  if (failed(env)) rc = -2;
  (*env)->DeleteLocalRef(env, bytes);
  done(attached);
  return (int32_t)rc;
}

static int32_t device_lock(void) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return 1;
  jboolean secure = (*env)->CallStaticBooleanMethod(env, g_class, g_device_lock);
  // When unsure, assume a screen lock: the prompt then decides.
  int32_t rc = failed(env) ? 1 : (secure ? 1 : 0);
  done(attached);
  return rc;
}

static void end_session(void) {
  int attached;
  JNIEnv *env = env_for_thread(&attached);
  if (env == NULL) return;
  (*env)->CallStaticVoidMethod(env, g_class, g_end_session);
  failed(env);
  done(attached);
}

static const SecwetPlatform PLATFORM = {
    ks_get, ks_set, ks_delete, clip_write, clip_read, clip_clear,
    bio_kind, bio_verify, device_lock, end_session,
};

// Copies a Java byte[] into a fresh malloc'd buffer (*len bytes, may be 0).
// Kotlin passes String.toByteArray(UTF_8): real UTF-8, unlike the modified
// UTF-8 of GetStringUTFChars, which encodes emoji as surrogate pairs.
static uint8_t *dup_bytes(JNIEnv *env, jbyteArray array, size_t *len) {
  *len = 0;
  if (array == NULL) return NULL;
  jsize n = (*env)->GetArrayLength(env, array);
  uint8_t *copy = malloc(n > 0 ? (size_t)n : 1);
  if (copy == NULL) return NULL;
  if (n > 0) (*env)->GetByteArrayRegion(env, array, 0, n, (jbyte *)copy);
  if (failed(env)) {
    free(copy);
    return NULL;
  }
  *len = (size_t)n;
  return copy;
}

// Called through Java_..._SecwetNative_nativeInstall (exported by Rust).
int32_t secwet_jni_install(JNIEnv *env, jclass class, jbyteArray data_dir, jbyteArray device_name) {
  if (g_class == NULL) {
    if ((*env)->GetJavaVM(env, &g_vm) != JNI_OK) return -1;
    g_class = (jclass)(*env)->NewGlobalRef(env, class);
    g_ks_get = (*env)->GetStaticMethodID(env, class, "keystoreGet", "(Ljava/lang/String;)[B");
    g_ks_set = (*env)->GetStaticMethodID(env, class, "keystoreSet", "(Ljava/lang/String;[B)Z");
    g_ks_delete = (*env)->GetStaticMethodID(env, class, "keystoreDelete", "(Ljava/lang/String;)Z");
    g_clip_write = (*env)->GetStaticMethodID(env, class, "clipboardWrite", "([B)Z");
    g_clip_read = (*env)->GetStaticMethodID(env, class, "clipboardRead", "()[B");
    g_clip_clear = (*env)->GetStaticMethodID(env, class, "clipboardClear", "()Z");
    g_bio_kind = (*env)->GetStaticMethodID(env, class, "biometricKind", "()I");
    g_bio_verify = (*env)->GetStaticMethodID(env, class, "biometricVerify", "([B)I");
    g_device_lock = (*env)->GetStaticMethodID(env, class, "deviceLock", "()Z");
    g_end_session = (*env)->GetStaticMethodID(env, class, "endSession", "()V");
    if (failed(env) || !g_ks_get || !g_ks_set || !g_ks_delete || !g_clip_write || !g_clip_read ||
        !g_clip_clear || !g_bio_kind || !g_bio_verify || !g_device_lock || !g_end_session) {
      (*env)->DeleteGlobalRef(env, g_class);
      g_class = NULL;
      return -1;
    }
  }

  size_t dir_len, name_len;
  uint8_t *dir = dup_bytes(env, data_dir, &dir_len);
  uint8_t *name = dup_bytes(env, device_name, &name_len);
  int32_t rc = -1;
  if (dir != NULL) {
    // A missing name is fine: Rust then uses "Phone".
    rc = secwet_ffi_register_platform(&PLATFORM, dir, dir_len, name, name != NULL ? name_len : 0);
  }
  free(dir);
  free(name);
  return rc;
}
