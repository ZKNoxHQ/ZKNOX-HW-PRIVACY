//! Rust port of the `js/` functional suite: APDU-level tests driving the app
//! over Speculos or a physical Ledger, with the cryptographic oracles computed
//! host-side in Rust instead of circomlib.
//!
//! Module map against the JavaScript it replaces:
//!
//! | JavaScript             | Rust            |
//! |------------------------|-----------------|
//! | `js/apdu-constants.js` | [`apdu`]        |
//! | `js/lib/hex.js`        | [`hex`]         |
//! | `js/lib/ledger.js`     | [`ledger`]      |
//! | `js/lib/test-context.js` | [`context`]   |
//! | `js/lib/slip0010.js`   | [`slip0010`]    |
//! | `js/fixtures/test-mnemonic.js` | [`fixtures`] |
//! | `circomlibjs` reference in `sign.test.js` | [`oracle`] |
//!
//! The suites themselves are in `tests/`: `dkg.rs`, `frost_hw.rs`, `sign.rs`.

pub mod apdu;
pub mod context;
pub mod hex;
pub mod ledger;
pub mod oracle;
pub mod slip0010;

/// Port of `js/fixtures/test-mnemonic.js`.
pub mod fixtures {
    /// `TEST_MNEMONIC` — every suite assumes the device holds this seed.
    pub const TEST_MNEMONIC: &str =
        "yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow";
    /// `TEST_ACCOUNT`.
    pub const TEST_ACCOUNT: u32 = 0;

    /// Absolute path of a file under `js/test/fixtures/`, so the Rust suite
    /// reads the very fixtures the JavaScript one uses.
    pub fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../js/test/fixtures")
            .join(name)
    }
}
