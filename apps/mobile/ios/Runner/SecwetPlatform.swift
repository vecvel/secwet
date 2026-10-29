import Flutter
import LocalAuthentication
import PDFKit
import Security
import UIKit
import UniformTypeIdentifiers

/// iOS platform services for the Rust app layer (crates/secwet-ffi):
/// Keychain key storage, the clipboard and LocalAuthentication, registered
/// as C callbacks before Dart starts. Keys pass only between Rust and the
/// Keychain; they never reach Dart.
enum SecwetNative {
  static func install() {
    var platform = SecwetPlatform(
      keystore_get: { entry, out, cap in SecwetKeychain.get(entry, out, cap) },
      keystore_set: { entry, value, len in SecwetKeychain.set(entry, value, len) },
      keystore_delete: { entry in SecwetKeychain.delete(entry) },
      clipboard_write: { text, len in SecwetClipboard.write(text, len) },
      clipboard_read: { out, cap in SecwetClipboard.read(out, cap) },
      clipboard_clear: { SecwetClipboard.clear() },
      biometric_kind: { SecwetBiometrics.kind() },
      biometric_verify: { reason, len in SecwetBiometrics.verify(reason, len) },
      device_lock: { SecwetKeychain.deviceLock() ? 1 : 0 },
      keystore_end_session: { SecwetKeychain.endSession() }
    )
    let dir = Array(dataDirectory().path.utf8)
    // iOS 16+ returns only the model ("iPhone") without the
    // user-assigned-device-name entitlement, which needs Apple's approval.
    // Onboarding shows the name in an editable field, and Settings >
    // General changes it later (docs/mobile-ffi.md).
    let name = Array(UIDevice.current.name.utf8)
    _ = secwet_ffi_register_platform(&platform, dir, dir.count, name, name.count)
  }

  /// Application Support/Secwet, kept out of iCloud and device backups: the
  /// keys are this-device-only, so a restored copy could never be opened.
  static func dataDirectory() -> URL {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    var dir = base.appendingPathComponent("Secwet", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try? dir.setResourceValues(values)
    return dir
  }
}

/// Generic-password items that never leave this device. On a phone with a
/// passcode every item sits behind `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
/// and the `.userPresence` access control, so reading it needs Face ID,
/// Touch ID or the passcode. The unlock prompt (`SecwetBiometrics.verify`)
/// opens one session: its evaluated LAContext authorizes every read until
/// Rust ends the session on lock. Without a session, protected items cannot
/// be read and the Keychain never draws a prompt of its own.
///
/// A phone without a passcode cannot protect them this way; items are then
/// stored readable while the phone is unlocked, and upgraded to the
/// protected form on the first unlock after a passcode is set. Removing the
/// passcode makes iOS delete the protected items.
enum SecwetKeychain {
  static let service = "app.secwet.mobile.keys"
  private static let lock = NSLock()
  private static var session: LAContext?

  /// The phone has a passcode (with or without a biometric).
  static func deviceLock() -> Bool {
    LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
  }

  static func beginSession(_ context: LAContext) {
    // The context is evaluated; later Keychain reads reuse it without UI.
    context.interactionNotAllowed = true
    lock.lock()
    session?.invalidate()
    session = context
    lock.unlock()
    protectExisting(context)
  }

  static func endSession() {
    lock.lock()
    session?.invalidate()
    session = nil
    lock.unlock()
  }

  /// The session context, or one that refuses any prompt.
  private static func context() -> LAContext {
    lock.lock()
    defer { lock.unlock() }
    if let session { return session }
    let none = LAContext()
    none.interactionNotAllowed = true
    return none
  }

  private static func base(_ entry: UnsafePointer<CChar>) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: String(cString: entry),
    ]
  }

  /// Protection attributes for a new or rewritten item.
  private static func protection() -> [String: Any]? {
    guard deviceLock() else {
      return [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    }
    guard let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, nil
    ) else { return nil }
    return [kSecAttrAccessControl as String: access]
  }

  static func get(_ entry: UnsafePointer<CChar>?, _ out: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int64 {
    guard let entry else { return -2 }
    var query = base(entry)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecUseAuthenticationContext as String] = context()
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return -1 }
    guard status == errSecSuccess, var data = item as? Data else { return -2 }
    let n = data.count
    if n <= cap, let out { data.copyBytes(to: out, count: n) }
    data.resetBytes(in: 0..<n)
    return Int64(n)
  }

  static func set(_ entry: UnsafePointer<CChar>?, _ value: UnsafePointer<UInt8>?, _ len: Int) -> Int32 {
    guard let entry, value != nil || len == 0, let protection = protection() else { return -2 }
    var data = len == 0 ? Data() : Data(bytes: value!, count: len)
    defer { data.resetBytes(in: 0..<data.count) }
    // Adding a protected item needs no prompt; replacing one uses the session.
    var attrs = protection
    attrs[kSecValueData as String] = data
    var status = SecItemAdd(base(entry).merging(attrs) { $1 } as CFDictionary, nil)
    if status == errSecDuplicateItem {
      var query = base(entry)
      query[kSecUseAuthenticationContext as String] = context()
      status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
    }
    return status == errSecSuccess ? 0 : -2
  }

  static func delete(_ entry: UnsafePointer<CChar>?) -> Int32 {
    guard let entry else { return -2 }
    let status = SecItemDelete(base(entry) as CFDictionary)
    return status == errSecSuccess || status == errSecItemNotFound ? 0 : -2
  }

  /// Moves items written before the phone had a passcode behind the
  /// passcode and user presence. Best effort; runs inside a session.
  private static func protectExisting(_ context: LAContext) {
    guard deviceLock(), let protection = protection() else { return }
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecUseAuthenticationContext as String: context,
    ]
    var items: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess,
          let list = items as? [[String: Any]] else { return }
    for attributes in list {
      let accessible = attributes[kSecAttrAccessible as String] as? String
      guard accessible != (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String),
            let account = attributes[kSecAttrAccount as String] as? String else { continue }
      let item: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseAuthenticationContext as String: context,
      ]
      _ = SecItemUpdate(item as CFDictionary, protection as CFDictionary)
    }
  }
}

/// Local-only pasteboard items that expire after 30 seconds, the same span
/// as the app layer's own clear timer (which cannot run while iOS suspends
/// the app). Only text this app wrote is ever read back, so iOS never shows
/// a paste notice for another app's content.
enum SecwetClipboard {
  private static var ownChangeCount: Int?

  private static func onMain<T>(_ body: () -> T) -> T {
    Thread.isMainThread ? body() : DispatchQueue.main.sync(execute: body)
  }

  static func write(_ text: UnsafePointer<UInt8>?, _ len: Int) -> Int32 {
    guard let text, let value = String(bytes: UnsafeBufferPointer(start: text, count: len), encoding: .utf8) else {
      return -2
    }
    onMain {
      UIPasteboard.general.setItems(
        [[UTType.utf8PlainText.identifier: value]],
        options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(30)]
      )
      ownChangeCount = UIPasteboard.general.changeCount
    }
    return 0
  }

  static func read(_ out: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int64 {
    let text: String? = onMain {
      guard UIPasteboard.general.changeCount == ownChangeCount else { return nil }
      return UIPasteboard.general.string
    }
    guard let text else { return -1 }
    let bytes = Array(text.utf8)
    if bytes.count <= cap, let out { out.update(from: bytes, count: bytes.count) }
    return Int64(bytes.count)
  }

  static func clear() -> Int32 {
    onMain {
      if UIPasteboard.general.changeCount == ownChangeCount {
        UIPasteboard.general.items = []
        ownChangeCount = nil
      }
    }
    return 0
  }
}

/// Face ID, Touch ID or Optic ID through LocalAuthentication.
enum SecwetBiometrics {
  /// 0 none, 1 Touch ID, 2 Face ID, 3 Optic ID (secwet_ffi.h). Lockout after
  /// failed attempts still counts as available; the prompt then asks for
  /// the passcode.
  static func kind() -> Int32 {
    let context = LAContext()
    var error: NSError?
    let usable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    if !usable, (error as? LAError)?.code != .biometryLockout { return 0 }
    if #available(iOS 17.0, *), context.biometryType == .opticID { return 3 }
    switch context.biometryType {
    case .touchID: return 1
    case .faceID: return 2
    default: return 0
    }
  }

  /// The unlock prompt: the biometric with the passcode as fallback
  /// (`.deviceOwnerAuthentication`), or the passcode alone when no biometric
  /// is enrolled. Success opens the Keychain session. Blocks the calling
  /// (background) thread while the prompt is open.
  static func verify(_ reason: UnsafePointer<UInt8>?, _ len: Int) -> Int32 {
    var text = "Unlock Secwet"
    if let reason, let s = String(bytes: UnsafeBufferPointer(start: reason, count: len), encoding: .utf8), !s.isEmpty {
      text = s.prefix(1).uppercased() + s.dropFirst()
    }
    let context = LAContext()
    let done = DispatchSemaphore(value: 0)
    var result: Int32 = -2
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: text) { ok, error in
      if ok {
        result = 0
      } else {
        let code = (error as NSError?)?.code ?? 0
        switch (error as? LAError)?.code {
        case .userCancel, .systemCancel, .appCancel, .userFallback: result = 1
        // The prompt could not come up right now (app not in front, a stale
        // context, the system UI timing out, -1000): nothing to report, the
        // user just tries again.
        case .notInteractive, .invalidContext: result = 1
        case .authenticationFailed, .biometryLockout: result = 2
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet: result = 3
        default:
          // -1000 "UI activation timed out" is not an LAError case.
          result = code == -1000 ? 1 : 2
          #if DEBUG
          print("Secwet: unlock check ended with LocalAuthentication code \(code)")
          #endif
        }
      }
      done.signal()
    }
    done.wait()
    if result == 0 { SecwetKeychain.beginSession(context) }
    return result
  }
}

/// `app.secwet/platform` channel: document picker, save dialog, temp folder,
/// PDF page rendering for asset previews, and the phone's settings.
final class SecwetPlatformChannel: NSObject, UIDocumentPickerDelegate {
  private var pending: FlutterResult?
  private var exportedCopy: URL?

  /// Files on their way in or out: picked backups, exports, decrypted assets
  /// while the save dialog is open. Excluded from backups.
  static func tempDirectory() -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("secwet-files", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var target = dir
    try? target.setResourceValues(values)
    return dir
  }

  /// Deletes everything in the temp folder. Runs before Dart starts, so a
  /// file left by a process that died with a save dialog open never
  /// outlives the next launch, and again on every lock.
  static func clearTempDirectory() {
    let dir = tempDirectory()
    let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
    for file in files { try? FileManager.default.removeItem(at: file) }
  }

  static func register(with messenger: FlutterBinaryMessenger) -> SecwetPlatformChannel {
    clearTempDirectory()
    let instance = SecwetPlatformChannel()
    let channel = FlutterMethodChannel(name: "app.secwet/platform", binaryMessenger: messenger)
    channel.setMethodCallHandler { call, result in instance.handle(call, result) }
    return instance
  }

  private func handle(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
    switch call.method {
    case "tempDirectory":
      result(Self.tempDirectory().path)
    case "clearTempDirectory":
      if pending == nil { Self.clearTempDirectory() }
      result(nil)
    case "openSecuritySettings":
      // iOS has no public link to Face ID & Passcode; this opens Settings
      // at Secwet's page, one step from it.
      if let url = URL(string: UIApplication.openSettingsURLString) {
        UIApplication.shared.open(url)
      }
      result(nil)
    case "saveBytes":
      guard let args = call.arguments as? [String: Any],
            let bytes = args["bytes"] as? FlutterStandardTypedData,
            let name = args["name"] as? String, !name.isEmpty else {
        result(FlutterError(code: "invalid", message: "Missing bytes or name.", details: nil))
        return
      }
      guard pending == nil else {
        result(FlutterError(code: "busy", message: "Another file dialog is open.", details: nil))
        return
      }
      // The export dialog needs a file. It is readable only while the phone
      // is unlocked, lives only while the dialog is open, and the launch
      // sweep removes it if the app dies meanwhile.
      let safe = name.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
      let url = Self.tempDirectory().appendingPathComponent(safe)
      try? FileManager.default.removeItem(at: url)
      do {
        try bytes.data.write(to: url, options: [.completeFileProtection])
      } catch {
        result(FlutterError(code: "io", message: "Could not prepare the file.", details: nil))
        return
      }
      exportedCopy = url
      present(UIDocumentPickerViewController(forExporting: [url], asCopy: true), result)
    case "pickFile":
      let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
      present(picker, result)
    case "saveFile":
      guard let args = call.arguments as? [String: Any], let path = args["path"] as? String else {
        result(FlutterError(code: "invalid", message: "Missing path.", details: nil))
        return
      }
      guard pending == nil else {
        result(FlutterError(code: "busy", message: "Another file dialog is open.", details: nil))
        return
      }
      var url = URL(fileURLWithPath: path)
      if let name = args["name"] as? String, !name.isEmpty, name != url.lastPathComponent {
        let renamed = url.deletingLastPathComponent().appendingPathComponent(name)
        try? FileManager.default.removeItem(at: renamed)
        if (try? FileManager.default.moveItem(at: url, to: renamed)) != nil { url = renamed }
      }
      exportedCopy = url
      present(UIDocumentPickerViewController(forExporting: [url], asCopy: true), result)
    case "renderPdf":
      guard let args = call.arguments as? [String: Any], let data = (args["bytes"] as? FlutterStandardTypedData)?.data else {
        result(FlutterError(code: "invalid", message: "Missing bytes.", details: nil))
        return
      }
      let maxPages = args["maxPages"] as? Int ?? 20
      let width = CGFloat(args["width"] as? Int ?? 1080)
      DispatchQueue.global(qos: .userInitiated).async {
        let pages = Self.renderPdf(data, maxPages: maxPages, width: width)
        DispatchQueue.main.async { result(pages) }
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func present(_ picker: UIDocumentPickerViewController, _ result: @escaping FlutterResult) {
    guard pending == nil, let top = Self.topViewController() else {
      if pending == nil, let copy = exportedCopy {
        try? FileManager.default.removeItem(at: copy)
        exportedCopy = nil
      }
      result(FlutterError(code: "busy", message: "Another file dialog is open.", details: nil))
      return
    }
    pending = result
    picker.delegate = self
    top.present(picker, animated: true)
  }

  private func finish(_ value: Any?) {
    if let copy = exportedCopy {
      try? FileManager.default.removeItem(at: copy)
      exportedCopy = nil
    }
    pending?(value)
    pending = nil
  }

  func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
    if exportedCopy != nil {
      finish(true)
    } else if let url = urls.first {
      finish(["path": url.path, "name": url.lastPathComponent])
    } else {
      finish(nil)
    }
  }

  func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
    finish(exportedCopy != nil ? false : nil)
  }

  /// Draws PDF pages in memory; the document never touches the disk.
  private static func renderPdf(_ data: Data, maxPages: Int, width: CGFloat) -> [FlutterStandardTypedData] {
    guard let document = PDFDocument(data: data) else { return [] }
    var pages: [FlutterStandardTypedData] = []
    for index in 0..<min(document.pageCount, maxPages) {
      guard let page = document.page(at: index) else { continue }
      let bounds = page.bounds(for: .mediaBox)
      let scale = width / max(bounds.width, 1)
      let image = page.thumbnail(of: CGSize(width: bounds.width * scale, height: bounds.height * scale), for: .mediaBox)
      if let png = image.pngData() { pages.append(FlutterStandardTypedData(bytes: png)) }
    }
    return pages
  }

  private static func topViewController() -> UIViewController? {
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    let window = scenes.flatMap(\.windows).first { $0.isKeyWindow } ?? scenes.first?.windows.first
    var top = window?.rootViewController
    while let presented = top?.presentedViewController { top = presented }
    return top
  }
}
