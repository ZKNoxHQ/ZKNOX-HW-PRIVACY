//! The `sim/` host simulator, linked in rather than spawned.
//!
//! `rs/crates/hw-tests` drives the simulator as a child process over the line
//! protocol: one hex APDU per line in, one hex response per line out. That is
//! what makes a multi-participant ceremony possible, because the firmware's
//! state is global and a participant therefore has to be a process. It also
//! costs a `fork` and two pipes per device and makes the APDU surface
//! expensive to sweep.
//!
//! This crate is the other end of that trade. It links the same objects into
//! the test binary and calls `zkn_sim_exchange` directly: no process, no
//! pipe, no hex, about a microsecond per APDU. What that buys is the tests in
//! this crate's `tests/`, which the other two sets cannot afford:
//!
//! - the whole `(INS, P1, P2)` space, swept, against the RFU contract
//!   `src/apdu/dispatcher.c` states instruction by instruction;
//! - key derivation under many seeds in one run, the seed being a setter here
//!   rather than an environment variable read once at startup;
//! - the approval and refusal paths in a single session, same reason;
//! - random APDUs by the ten thousand, checking the dispatcher always answers
//!   with a status word it is allowed to answer.
//!
//! What it costs is the process boundary. The firmware's ceremony state
//! (`handler_dkg.c`), its FROST state (`handler_frost_sign.c`), the `cx_bn`
//! pool and the seed cache are file statics, so:
//!
//! - **one process is one device.** There is no way to run a t-of-n ceremony
//!   here; that stays in `hw-tests`.
//! - a crash in the firmware takes the test runner with it, where the child
//!   process would have surfaced it as a transport error. The upside of the
//!   same property is that `cargo test` under ASan or UBSan now instruments
//!   the dispatcher.
//!
//! [`Sim`] is the handle, and it is exclusive: it holds a process-wide mutex
//! for as long as it lives, so tests need no `--test-threads=1`. Acquiring it
//! resets the device.
//!
//! ```no_run
//! let mut sim = zknox_sim::Sim::lock();
//! let resp = sim.exchange(&[0xe0, 0x03, 0, 0, 0], "GET_VERSION").unwrap();
//! assert_eq!(resp, [0, 1, 0]);
//! ```

use std::ffi::CStr;
use std::fmt;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The C entry points of `sim/src/sim_core.h`.
pub mod ffi {
    use std::os::raw::{c_char, c_int, c_uchar};

    /// Largest response `shim_io.c` can hold, plus the status word.
    pub const ZKN_SIM_RESP_MAX: usize = 4098;

    extern "C" {
        /// One APDU in, `data || SW` out.
        pub fn zkn_sim_exchange(
            apdu: *const c_uchar,
            len: usize,
            out: *mut c_uchar,
            out_len: *mut usize,
        ) -> c_int;

        /// `SIM_VERSION`.
        pub fn zkn_sim_version() -> *const c_char;
        /// Non-zero when built `ZKNOX_MODE_DEBUG`.
        pub fn zkn_sim_has_debug_ins() -> c_int;
        /// Non-zero when built `ZKN_FROST`.
        pub fn zkn_sim_has_frost() -> c_int;

        /// Sets the 64-byte BIP39 seed.
        pub fn zkn_sim_set_seed(seed: *const c_uchar);
        /// Back to the built-in yellow×12 seed.
        pub fn zkn_sim_set_seed_default();
        /// 1 approve, 0 reject, -1 defer to `SIM_REJECT`.
        pub fn zkn_sim_set_ui_decision(decision: c_int);
        /// Deterministic RNG.
        pub fn zkn_sim_set_rng_seed(seed: u64);
        /// Back to `/dev/urandom`.
        pub fn zkn_sim_set_rng_os();
    }
}

/// `SIM_VERSION` of the linked simulator.
pub fn version() -> &'static str {
    // Safety: a string literal in the C, static for the program's lifetime.
    unsafe { CStr::from_ptr(ffi::zkn_sim_version()) }
        .to_str()
        .unwrap_or("?")
}

/// True when the linked simulator was built `MODE=debug`: the silent
/// `SIGNING_PUBKEY` P1=0, `BLIND_SIGN_NO_DISPLAY` (0x02),
/// `SIGN_WITH_PRIVKEY` (0x50) and the DKG key-extraction instructions exist.
pub fn has_debug_ins() -> bool {
    unsafe { ffi::zkn_sim_has_debug_ins() != 0 }
}

/// True when it was built `FROST=1`: the DKG (0x60–0x6b) and FROST
/// (0x70–0x72) instructions exist.
pub fn has_frost() -> bool {
    unsafe { ffi::zkn_sim_has_frost() != 0 }
}

/// A non-9000 status word. The counterpart of `hw-tests`'s `ApduError`, down
/// to the `[label] SW=...` message, so a test reads the same either side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduError {
    /// Label passed to [`Sim::exchange`].
    pub label: String,
    /// The four hex digits of the status word.
    pub sw: String,
    /// Full message.
    pub message: String,
}

impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApduError {}

fn lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Exclusive handle on the linked simulator.
///
/// One process is one device, so this is a guard rather than a constructor:
/// while it lives no other thread can reach the firmware's state. It is
/// released on drop.
pub struct Sim {
    _guard: MutexGuard<'static, ()>,
}

impl Sim {
    /// Takes the device, blocking until it is free, and resets it.
    ///
    /// A test that panicked while holding it poisoned the mutex; that is
    /// recovered from rather than cascading, since the next test resets the
    /// device anyway.
    pub fn lock() -> Sim {
        let guard = lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut sim = Sim { _guard: guard };
        sim.reset();
        sim
    }

    /// Takes the device and puts it on `seed`.
    pub fn with_seed(seed: &[u8; 64]) -> Sim {
        let mut sim = Sim::lock();
        sim.set_seed(seed);
        sim
    }

    /// Back to a known state: default seed, approving UI, OS randomness, and
    /// the DKG and FROST state machines wiped where they exist.
    pub fn reset(&mut self) {
        self.set_seed_default();
        self.set_ui(true);
        self.set_rng_os();
        if has_frost() {
            // 0x72 FROST_HW_RESET then 0x66 DKG_ABORT: the firmware's own way
            // back to IDLE, which is why no C-side reset is needed for state
            // the handlers keep private.
            let _ = self.exchange_raw(&[0xe0, 0x72, 0, 0, 0]);
            let _ = self.exchange_raw(&[0xe0, 0x66, 0, 0, 0]);
        }
    }

    /// Sends one APDU and returns the raw response, status word included.
    pub fn exchange_raw(&mut self, apdu: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; ffi::ZKN_SIM_RESP_MAX];
        let mut out_len: usize = 0;
        // Safety: `apdu` is a readable slice of `apdu.len()` bytes, `out` is
        // writable for ZKN_SIM_RESP_MAX bytes, which is the most the C writes,
        // and `self` proves no other thread is inside the firmware.
        let rc = unsafe {
            ffi::zkn_sim_exchange(
                apdu.as_ptr(),
                apdu.len(),
                out.as_mut_ptr(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(rc, 0, "zkn_sim_exchange returned {rc}");
        assert!(
            (2..=ffi::ZKN_SIM_RESP_MAX).contains(&out_len),
            "zkn_sim_exchange reported {out_len} bytes"
        );
        out.truncate(out_len);
        out
    }

    /// The status word of the last response, as four hex digits.
    fn sw_of(resp: &[u8]) -> String {
        let n = resp.len();
        format!("{:02x}{:02x}", resp[n - 2], resp[n - 1])
    }

    /// Sends one APDU and fails on any status word other than 9000.
    pub fn exchange(&mut self, apdu: &[u8], label: &str) -> Result<Vec<u8>, ApduError> {
        let resp = self.exchange_raw(apdu);
        let sw = Self::sw_of(&resp);
        if sw != "9000" {
            return Err(ApduError {
                label: label.to_string(),
                message: format!("[{label}] SW={sw}"),
                sw,
            });
        }
        Ok(resp[..resp.len() - 2].to_vec())
    }

    /// The status word instead of a failure, for the guard tests.
    pub fn try_exchange(&mut self, apdu: &[u8], label: &str) -> Result<Vec<u8>, String> {
        self.exchange(apdu, label).map_err(|e| e.sw)
    }

    /// Just the status word, data discarded.
    pub fn sw(&mut self, apdu: &[u8]) -> String {
        Self::sw_of(&self.exchange_raw(apdu))
    }

    /// Puts the device on a 64-byte BIP39 seed. Every derivation after this
    /// starts from it, which `SIM_SEED` cannot do more than once per process.
    pub fn set_seed(&mut self, seed: &[u8; 64]) {
        unsafe { ffi::zkn_sim_set_seed(seed.as_ptr()) }
    }

    /// Back to the built-in seed, mnemonic "yellow" ×12.
    pub fn set_seed_default(&mut self) {
        unsafe { ffi::zkn_sim_set_seed_default() }
    }

    /// What the review screens answer from now on.
    pub fn set_ui(&mut self, approve: bool) {
        unsafe { ffi::zkn_sim_set_ui_decision(i32::from(approve)) }
    }

    /// Hands the decision back to `SIM_REJECT`.
    pub fn set_ui_from_env(&mut self) {
        unsafe { ffi::zkn_sim_set_ui_decision(-1) }
    }

    /// Deterministic randomness, so an epoch or a nonce can be replayed.
    pub fn set_rng_seed(&mut self, seed: u64) {
        unsafe { ffi::zkn_sim_set_rng_seed(seed) }
    }

    /// Back to the OS source.
    pub fn set_rng_os(&mut self) {
        unsafe { ffi::zkn_sim_set_rng_os() }
    }
}
