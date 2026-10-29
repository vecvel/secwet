//! Async runtime used for background work started by the app layer (the
//! clipboard auto-clear timer).
//!
//! A host that already runs tokio installs its handle with [`install`] before
//! the first command (the desktop passes Tauri's runtime). Otherwise the app
//! layer starts its own multi-thread runtime on first use, so plain threads
//! (FFI callers, unit tests) work as well.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Handle, Runtime};

static INSTALLED: OnceLock<Handle> = OnceLock::new();
static OWN: OnceLock<Runtime> = OnceLock::new();

/// Uses `handle` for all app-layer background work. Returns false when a
/// handle was already installed (the first one stays).
pub fn install(handle: Handle) -> bool {
    INSTALLED.set(handle).is_ok()
}

/// The installed runtime handle, or the app layer's own runtime.
pub fn handle() -> Handle {
    if let Some(h) = INSTALLED.get() {
        return h.clone();
    }
    OWN.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("secwet-app")
            .build()
            .expect("failed to start the Secwet async runtime")
    })
    .handle()
    .clone()
}

/// Runs `fut` in the background on [`handle`].
pub fn spawn<F>(fut: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    drop(handle().spawn(fut));
}

/// Runs `fut` to completion from synchronous code (FFI entry points).
/// Must not be called from inside the runtime.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    handle().block_on(fut)
}
