//! Minimal SIGINT (Ctrl+C) handling.
//!
//! The handler sets an atomic flag. The engine checks the flag and stops the
//! run so that the summary is still printed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

static INTERRUPTED: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Install the SIGINT handler. Call once at startup.
pub fn install() {
    let flag = Arc::new(AtomicBool::new(false));
    // Registration only fails if the signal cannot be handled; in that case the
    // run simply behaves as before (SIGINT terminates the process).
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag));
    let _ = INTERRUPTED.set(flag);
}

/// True once SIGINT has been received.
pub fn interrupted() -> bool {
    INTERRUPTED
        .get()
        .map(|flag| flag.load(Ordering::SeqCst))
        .unwrap_or(false)
}
