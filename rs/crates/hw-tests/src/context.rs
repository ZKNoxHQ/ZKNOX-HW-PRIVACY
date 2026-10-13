//! Port of `js/lib/test-context.js` — one shared transport for every suite.
//!
//! `node --test --test-concurrency=1` runs the JavaScript suites one at a time
//! over a single device handle. Rust runs test functions on parallel threads,
//! so the same serialization comes from a global mutex: [`acquire`] hands out
//! the one transport and holds it for the length of the test.
//!
//! When no backend is available at all — no simulator built, `SIM_BIN` unset,
//! no `hid` feature — [`acquire`] returns `None`, the test prints the reason
//! and returns: this harness's equivalent of `t.skip()`. When a backend *is*
//! named and does not answer, the test fails instead. A silent green run
//! against nothing would hide exactly what these suites exist to catch, and it
//! is the same asymmetry `js/README.md` describes for a firmware built without
//! `FROST=1`.

use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::ledger::{open_transport, Transport};

struct Shared {
    transport: Option<Transport>,
    error: Option<String>,
}

fn shared() -> &'static Mutex<Shared> {
    static SHARED: OnceLock<Mutex<Shared>> = OnceLock::new();
    SHARED.get_or_init(|| {
        let (transport, error) = match open_transport() {
            Ok(t) => (Some(t), None),
            Err(e) => (None, Some(e)),
        };
        Mutex::new(Shared { transport, error })
    })
}

/// Holds the shared transport for the duration of one test.
pub struct DeviceGuard {
    guard: MutexGuard<'static, Shared>,
}

impl DeviceGuard {
    /// The open transport.
    pub fn transport(&mut self) -> &mut Transport {
        self.guard.transport.as_mut().expect("device present")
    }
}

/// `requireDevice` — the transport, or `None` when there is no device.
pub fn acquire() -> Option<DeviceGuard> {
    let guard = shared().lock().unwrap_or_else(|e| e.into_inner());
    if guard.transport.is_none() {
        return None;
    }
    Some(DeviceGuard { guard })
}

/// The reason [`acquire`] returned `None`.
pub fn open_error() -> String {
    let guard = shared().lock().unwrap_or_else(|e| e.into_inner());
    guard
        .error
        .clone()
        .unwrap_or_else(|| "no Ledger device available".to_string())
}

/// True when a backend was named or is present: `SIM_BIN` is set, the
/// simulator has been built at its default path, or the crate was built with
/// the `hid` feature.
pub fn backend_configured() -> bool {
    if crate::ledger::hw_device_requested() {
        return true;
    }
    if std::env::var("SIM_BIN").is_ok() {
        return true;
    }
    if crate::ledger::default_sim_binary().exists() {
        return true;
    }
    cfg!(feature = "hid")
}

/// `requireDevice` with the skip message already printed.
///
/// Returns `None` (skip) when no backend is configured, and panics when one is
/// configured but unreachable.
///
/// ```ignore
/// let Some(mut dev) = device_or_skip("my test") else { return };
/// ```
pub fn device_or_skip(test: &str) -> Option<DeviceGuard> {
    match acquire() {
        Some(d) => Some(d),
        None if backend_configured() => {
            panic!(
                "{test}: {} (a configured backend that does not answer is a failure, not a skip)",
                open_error()
            )
        }
        None => {
            eprintln!("SKIP {test}: {}", open_error());
            None
        }
    }
}

/// True when the device holds the default yellow×12 seed, mirroring the
/// `SEED` checks in the JavaScript suites.
///
/// The simulator seeds itself from `SIM_SEED` (128 hex characters) and
/// defaults to yellow×12, so either variable can move the suite off its
/// seed-bound oracles.
pub fn default_seed() -> bool {
    if std::env::var("SIM_SEED").is_ok() {
        return false;
    }
    match std::env::var("SEED") {
        Ok(v) => v == "yellow" || v == crate::fixtures::TEST_MNEMONIC,
        Err(_) => true,
    }
}

/// True when the backend is the simulator, whose UI auto-approves: the tests
/// that need a button press on real hardware can run unattended here.
///
/// This takes the transport mutex, which is not reentrant: call it before
/// [`device_or_skip`], never while holding the guard.
pub fn using_sim() -> bool {
    match acquire() {
        Some(mut d) => matches!(d.transport(), crate::ledger::Transport::Sim(_)),
        None => false,
    }
}

/// True when `INTERACTIVE=1`, for the tests needing a button press.
pub fn interactive() -> bool {
    std::env::var("INTERACTIVE").is_ok_and(|v| !v.is_empty() && v != "0")
}
