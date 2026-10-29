import type { BiometryKind } from "./api";

/** Name of the biometric, as the OS calls it. */
export function biometricName(kind: BiometryKind): string {
  switch (kind) {
    case "touch_id":
      return "Touch ID";
    case "face_id":
      return "Face ID";
    case "optic_id":
      return "Optic ID";
    case "windows_hello_face":
    case "windows_hello_fingerprint":
    case "windows_hello_iris":
      return "Windows Hello";
    case "fingerprint":
      return "fingerprint";
    case "face":
      return "face unlock";
    case "iris":
      return "iris unlock";
    case "multiple":
    case "none":
      return "biometrics";
  }
}

/** Short description of what Windows Hello will use. */
export function biometricDetail(kind: BiometryKind): string | null {
  switch (kind) {
    case "windows_hello_face":
      return "face recognition";
    case "windows_hello_fingerprint":
      return "fingerprint";
    case "windows_hello_iris":
      return "iris recognition";
    default:
      return null;
  }
}

/** What still opens Secwet when the biometric can't read the user. */
export function biometricFallback(kind: BiometryKind): string {
  switch (kind) {
    case "touch_id":
    case "face_id":
    case "optic_id":
      return "Your Mac password still works when it can't read you.";
    case "windows_hello_face":
    case "windows_hello_fingerprint":
    case "windows_hello_iris":
      return "Your Windows Hello PIN still works when it can't read you.";
    default:
      return "If the reader stops working, your recovery key still opens Secwet.";
  }
}

/** fprintd has no system prompt; the app asks for the finger itself. */
export function biometricPromptIsInApp(kind: BiometryKind): boolean {
  return kind === "fingerprint";
}

/** The check was dismissed by the user: no error to show. */
export function isBiometricCancel(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === "biometric_cancelled";
}
