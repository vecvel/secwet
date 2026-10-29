//! Clipboard copy with OS history suppression and 30-second auto-clear.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §7 F5, §9.1, §9.2.
//!
//! Security Invariants:
//! 1. The webview never receives the plaintext secret value for a copy operation.
//! 2. `write_secret` sets OS-level hints (ConcealedType/CLIPBOARD_HIST_DONT_RECORD)
//!    to prevent third-party clipboard managers from indexing the secret.
//! 3. Plaintext secret memory is hashed immediately at copy time and dropped.
//!    Only the 32-byte SHA-256 fingerprint survives into the async timer closure.
//! 4. Atomic generation counters prevent race conditions when multiple secrets are copied.
//! 5. Foreign content is preserved: constant-time hash check ensures unrelated text is not wiped.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub use secwet_proto::extract_plain_text;

/// Platform clipboard. Hosts implement it over their native clipboard:
/// `write_secret` must ask the OS not to record the value in clipboard
/// history (macOS ConcealedType, Windows CLIPBOARD_HIST_DONT_RECORD, iOS
/// local-only with expiry, Android EXTRA_IS_SENSITIVE).
pub trait ClipboardPort: Send + Sync + 'static {
    fn write_secret(&self, text: &str) -> Result<(), String>;
    fn read_text(&self) -> Result<String, String>;
    fn clear(&self) -> Result<(), String>;
}

/// Manages clipboard copy and atomic generation-based auto-clearing.
pub struct AutoClearManager<C: ClipboardPort + ?Sized> {
    clipboard: Arc<C>,
    generation: Arc<AtomicU64>,
    duration: Duration,
}

impl<C: ClipboardPort + ?Sized> AutoClearManager<C> {
    pub fn new(clipboard: Arc<C>, generation: Arc<AtomicU64>, duration: Duration) -> Self {
        Self {
            clipboard,
            generation,
            duration,
        }
    }

    /// Sets the secret onto the clipboard and schedules an auto-clear task.
    ///
    /// Plaintext is hashed and dropped immediately; only the SHA-256 digest
    /// is retained in the async closure.
    pub fn copy_secret(&self, secret_plain: &str) -> Result<(), String> {
        // 1. Write secret to OS clipboard with history-exclusion hints
        self.clipboard.write_secret(secret_plain)?;

        // 2. Compute SHA-256 fingerprint of the secret
        let mut hasher = Sha256::new();
        hasher.update(secret_plain.as_bytes());
        let expected_hash: [u8; 32] = hasher.finalize().into();

        // 3. Monotonically increment generation token
        let token = self.generation.fetch_add(1, Ordering::SeqCst) + 1;

        // 4. Spawn background timer task
        let clipboard = Arc::clone(&self.clipboard);
        let generation = Arc::clone(&self.generation);
        let duration = self.duration;

        crate::runtime::spawn(async move {
            tokio::time::sleep(duration).await;

            // Step A: Check if a newer copy superseded this timer
            if generation.load(Ordering::SeqCst) != token {
                return;
            }

            // Step B: Read clipboard in a worker thread to prevent main-thread deadlocks
            let read_result = tokio::task::spawn_blocking({
                let cb = Arc::clone(&clipboard);
                move || cb.read_text()
            })
            .await;

            if let Ok(Ok(current_text)) = read_result {
                let mut current_hasher = Sha256::new();
                current_hasher.update(current_text.as_bytes());
                let current_hash: [u8; 32] = current_hasher.finalize().into();

                // Step C: Constant-time comparison ensures we only wipe our own secret
                if bool::from(current_hash.ct_eq(&expected_hash)) {
                    let _ = tokio::task::spawn_blocking({
                        let cb = Arc::clone(&clipboard);
                        move || cb.clear()
                    })
                    .await;
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockClipboard {
        data: Mutex<Option<String>>,
    }

    impl ClipboardPort for MockClipboard {
        fn write_secret(&self, text: &str) -> Result<(), String> {
            *self.data.lock().unwrap() = Some(text.to_string());
            Ok(())
        }
        fn read_text(&self) -> Result<String, String> {
            self.data
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| "Empty".to_string())
        }
        fn clear(&self) -> Result<(), String> {
            *self.data.lock().unwrap() = None;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_auto_clear_clears_matching_content() {
        let clipboard = Arc::new(MockClipboard::default());
        let generation = Arc::new(AtomicU64::new(0));
        let manager = AutoClearManager::new(
            Arc::clone(&clipboard),
            generation,
            Duration::from_millis(50),
        );

        manager.copy_secret("super_secret_token").unwrap();
        assert_eq!(clipboard.read_text().unwrap(), "super_secret_token");

        // After timeout, clipboard should be cleared
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(clipboard.read_text().is_err());
    }

    #[tokio::test]
    async fn test_foreign_content_preserved() {
        let clipboard = Arc::new(MockClipboard::default());
        let generation = Arc::new(AtomicU64::new(0));
        let manager = AutoClearManager::new(
            Arc::clone(&clipboard),
            generation,
            Duration::from_millis(50),
        );

        manager.copy_secret("secret_to_wipe").unwrap();

        // User copies foreign content at t=20ms
        tokio::time::sleep(Duration::from_millis(20)).await;
        *clipboard.data.lock().unwrap() = Some("user_browser_url".to_string());

        // When timer fires at t=50ms, foreign content must NOT be wiped
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(clipboard.read_text().unwrap(), "user_browser_url");
    }

    #[tokio::test]
    async fn test_subsequent_copy_cancels_previous_timer() {
        let clipboard = Arc::new(MockClipboard::default());
        let generation = Arc::new(AtomicU64::new(0));
        let manager = AutoClearManager::new(
            Arc::clone(&clipboard),
            generation,
            Duration::from_millis(50),
        );

        // Copy Secret 1 at t=0
        manager.copy_secret("secret_1").unwrap();

        // Copy Secret 2 at t=25ms
        tokio::time::sleep(Duration::from_millis(25)).await;
        manager.copy_secret("secret_2").unwrap();

        // At t=60ms (Timer 1 has fired), Secret 2 must NOT be cleared
        tokio::time::sleep(Duration::from_millis(35)).await;
        assert_eq!(clipboard.read_text().unwrap(), "secret_2");

        // At t=90ms+ (Timer 2 has fired), Secret 2 should be cleared
        let start = std::time::Instant::now();
        while clipboard.read_text().is_ok() && start.elapsed() < Duration::from_millis(500) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(clipboard.read_text().is_err());
    }

    #[tokio::test]
    async fn test_recopy_same_secret_extends_timer() {
        let clipboard = Arc::new(MockClipboard::default());
        let generation = Arc::new(AtomicU64::new(0));
        let manager = AutoClearManager::new(
            Arc::clone(&clipboard),
            generation,
            Duration::from_millis(50),
        );

        manager.copy_secret("secret_alpha").unwrap();

        // Recopy identical secret at t=30ms
        tokio::time::sleep(Duration::from_millis(30)).await;
        manager.copy_secret("secret_alpha").unwrap();

        // At t=60ms (Timer 1 would have expired), secret must still be present
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(clipboard.read_text().unwrap(), "secret_alpha");

        // At t=95ms+ (Timer 2 expires), secret is cleared
        let start = std::time::Instant::now();
        while clipboard.read_text().is_ok() && start.elapsed() < Duration::from_millis(500) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(clipboard.read_text().is_err());
    }

    #[test]
    fn test_extract_plain_text_strips_html_and_preserves_structure() {
        let html = "<p>First paragraph</p><p>Second paragraph with <b>bold</b> and <i>italic</i></p>";
        let plain = extract_plain_text(html);
        assert_eq!(plain, "First paragraph\n\nSecond paragraph with bold and italic");

        let html_list = "<ul><li>Item 1</li><li>Item 2</li></ul>";
        let plain_list = extract_plain_text(html_list);
        assert!(plain_list.contains("Item 1"));
        assert!(plain_list.contains("Item 2"));

        let entities = "Foo &amp; Bar &lt; Baz &gt; &quot;Q&quot;";
        assert_eq!(extract_plain_text(entities), "Foo & Bar < Baz > \"Q\"");
    }
}
