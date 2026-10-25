//! Development builds run unbundled, so macOS shows the icon embedded in the binary and never a dark
//! variant. This swaps the Dock icon to match the system appearance at launch and on every theme change.
//! Bundled builds use the adaptive Icon Composer icon (Assets.car) instead and skip this.

use tauri::Theme;

#[cfg(target_os = "macos")]
pub fn apply(theme: Theme) {
    use objc2::AnyThread;
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::{MainThreadMarker, NSData};

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let bytes: &[u8] = match theme {
        Theme::Dark => include_bytes!("../icons/dock-dark.png"),
        _ => include_bytes!("../icons/dock-light.png"),
    };
    let data = NSData::with_bytes(bytes);
    if let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) {
        // SAFETY: called on the main thread (checked above) with a valid image.
        unsafe { NSApplication::sharedApplication(mtm).setApplicationIconImage(Some(&image)) };
    }
}

#[cfg(not(target_os = "macos"))]
pub fn apply(_theme: Theme) {}
