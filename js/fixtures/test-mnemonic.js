// fixtures/test-mnemonic.js — Canonical test seed and the keys that derive from it.
//
// Most device tests assume the Ledger is initialised with this mnemonic.
// Expected-key constants are derived here too, so each test can assert
// against a single source of truth instead of re-deriving from the seed.

export const TEST_MNEMONIC =
    "yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow";

// Conventional test account index for single-account flows.
export const TEST_ACCOUNT = 0;
