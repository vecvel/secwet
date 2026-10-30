import AVFoundation
import Flutter
import UIKit

class SceneDelegate: FlutterSceneDelegate {

}

/// Scene services Secwet adds on top of Flutter, registered as a scene
/// life-cycle delegate (`registrar.addSceneDelegate`) so Flutter's own
/// handling stays untouched:
///
/// - `app.secwet/links`: `secwet://invite` and `secwet://pair` links the app
///   was opened with. Dart asks for the launch link with `initialLink`; later
///   links arrive as `link` calls.
/// - `app.secwet/scanner`: `scan` shows the camera and returns the first QR
///   code's text (nil when cancelled).
/// - Privacy cover: an opaque view over the window while the app is in the
///   background, so the app switcher snapshot never shows content.
final class SecwetSceneServices: NSObject, FlutterSceneLifeCycleDelegate {
  private let links: FlutterMethodChannel
  private var pendingLink: String?
  private var cover: UIView?
  private var scanResult: FlutterResult?

  private init(messenger: FlutterBinaryMessenger) {
    links = FlutterMethodChannel(name: "app.secwet/links", binaryMessenger: messenger)
    super.init()
  }

  static func register(with registrar: FlutterPluginRegistrar) -> SecwetSceneServices {
    let instance = SecwetSceneServices(messenger: registrar.messenger())
    instance.links.setMethodCallHandler { call, result in
      if call.method == "initialLink" {
        result(instance.pendingLink)
        instance.pendingLink = nil
      } else {
        result(FlutterMethodNotImplemented)
      }
    }
    let scanner = FlutterMethodChannel(name: "app.secwet/scanner", binaryMessenger: registrar.messenger())
    scanner.setMethodCallHandler { call, result in
      if call.method == "scan" {
        instance.scan(result)
      } else {
        result(FlutterMethodNotImplemented)
      }
    }
    registrar.addSceneDelegate(instance)
    return instance
  }

  // MARK: Links

  private func receive(_ contexts: Set<UIOpenURLContext>) -> Bool {
    guard let url = contexts.first?.url, url.scheme?.lowercased() == "secwet" else { return false }
    let link = url.absoluteString
    pendingLink = link
    links.invokeMethod("link", arguments: link) { [weak self] reply in
      // Dart answers true once it took the link; until its handler is set
      // (cold start) the link waits for `initialLink`.
      if (reply as? Bool) == true { self?.pendingLink = nil }
    }
    return true
  }

  func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions?) -> Bool {
    guard let contexts = connectionOptions?.urlContexts, !contexts.isEmpty else { return false }
    return receive(contexts)
  }

  func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) -> Bool {
    receive(URLContexts)
  }

  // MARK: Privacy cover

  func sceneDidEnterBackground(_ scene: UIScene) {
    guard cover == nil, let window = (scene as? UIWindowScene)?.windows.first(where: \.isKeyWindow) else { return }
    let view = UIView(frame: window.bounds)
    view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    // The page background tokens (light #FFFFFF, dark #131210).
    view.backgroundColor = UIColor { traits in
      traits.userInterfaceStyle == .dark ? UIColor(red: 0x13 / 255, green: 0x12 / 255, blue: 0x10 / 255, alpha: 1) : .white
    }
    window.addSubview(view)
    cover = view
  }

  func sceneWillEnterForeground(_ scene: UIScene) {
    cover?.removeFromSuperview()
    cover = nil
  }

  // MARK: Scanner

  private func scan(_ result: @escaping FlutterResult) {
    guard scanResult == nil else {
      result(FlutterError(code: "busy", message: "The scanner is already open.", details: nil))
      return
    }
    guard AVCaptureDevice.default(for: .video) != nil else {
      result(FlutterError(code: "camera_unavailable", message: "This device has no camera.", details: nil))
      return
    }
    switch AVCaptureDevice.authorizationStatus(for: .video) {
    case .authorized:
      present(result)
    case .notDetermined:
      AVCaptureDevice.requestAccess(for: .video) { granted in
        DispatchQueue.main.async {
          if granted { self.present(result) } else { result(Self.denied()) }
        }
      }
    default:
      result(Self.denied())
    }
  }

  private static func denied() -> FlutterError {
    FlutterError(code: "camera_denied", message: "Allow camera access for Secwet in Settings to scan a code.", details: nil)
  }

  private func present(_ result: @escaping FlutterResult) {
    guard let top = Self.topViewController() else {
      result(FlutterError(code: "unavailable", message: "Couldn't open the camera.", details: nil))
      return
    }
    scanResult = result
    let scanner = SecwetScannerViewController { [weak self] text in
      self?.scanResult?(text)
      self?.scanResult = nil
    }
    scanner.modalPresentationStyle = .fullScreen
    top.present(scanner, animated: true)
  }

  private static func topViewController() -> UIViewController? {
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    let window = scenes.flatMap(\.windows).first { $0.isKeyWindow } ?? scenes.first?.windows.first
    var top = window?.rootViewController
    while let presented = top?.presentedViewController { top = presented }
    return top
  }
}

/// Full-screen camera that reads one QR code with AVFoundation's metadata
/// output. No image is kept; frames never leave the capture session.
final class SecwetScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
  private let session = AVCaptureSession()
  private let onDone: (String?) -> Void
  private var finished = false

  init(onDone: @escaping (String?) -> Void) {
    self.onDone = onDone
    super.init(nibName: nil, bundle: nil)
  }

  required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .black

    if let device = AVCaptureDevice.default(for: .video),
       let input = try? AVCaptureDeviceInput(device: device),
       session.canAddInput(input) {
      session.addInput(input)
      let output = AVCaptureMetadataOutput()
      if session.canAddOutput(output) {
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
      }
    }
    let preview = AVCaptureVideoPreviewLayer(session: session)
    preview.videoGravity = .resizeAspectFill
    preview.frame = view.bounds
    view.layer.addSublayer(preview)

    // A square guide with the app's control rounding.
    let guide = UIView()
    guide.translatesAutoresizingMaskIntoConstraints = false
    guide.layer.borderColor = UIColor.white.cgColor
    guide.layer.borderWidth = 2
    guide.layer.cornerRadius = 12
    view.addSubview(guide)

    let hint = UILabel()
    hint.translatesAutoresizingMaskIntoConstraints = false
    hint.text = "Point the camera at the code on your other device."
    hint.textColor = .white
    hint.font = .systemFont(ofSize: 14)
    hint.numberOfLines = 0
    hint.textAlignment = .center
    view.addSubview(hint)

    var config = UIButton.Configuration.filled()
    config.title = "Cancel"
    config.baseBackgroundColor = UIColor(white: 0.12, alpha: 1)
    config.baseForegroundColor = .white
    config.cornerStyle = .medium
    config.contentInsets = NSDirectionalEdgeInsets(top: 12, leading: 24, bottom: 12, trailing: 24)
    let cancel = UIButton(configuration: config)
    cancel.translatesAutoresizingMaskIntoConstraints = false
    cancel.addAction(UIAction { [weak self] _ in self?.finish(nil) }, for: .touchUpInside)
    view.addSubview(cancel)

    NSLayoutConstraint.activate([
      guide.centerXAnchor.constraint(equalTo: view.centerXAnchor),
      guide.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -24),
      guide.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.68),
      guide.heightAnchor.constraint(equalTo: guide.widthAnchor),
      hint.topAnchor.constraint(equalTo: guide.bottomAnchor, constant: 24),
      hint.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
      hint.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
      cancel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
      cancel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
      cancel.heightAnchor.constraint(greaterThanOrEqualToConstant: 44),
    ])
  }

  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    view.layer.sublayers?.compactMap { $0 as? AVCaptureVideoPreviewLayer }.forEach { $0.frame = view.bounds }
  }

  override func viewWillAppear(_ animated: Bool) {
    super.viewWillAppear(animated)
    let session = self.session
    DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
  }

  override func viewWillDisappear(_ animated: Bool) {
    super.viewWillDisappear(animated)
    let session = self.session
    DispatchQueue.global(qos: .userInitiated).async { session.stopRunning() }
  }

  func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
    guard let code = metadataObjects.compactMap({ $0 as? AVMetadataMachineReadableCodeObject }).first?.stringValue else { return }
    finish(code)
  }

  private func finish(_ value: String?) {
    guard !finished else { return }
    finished = true
    dismiss(animated: true) { self.onDone(value) }
  }
}
