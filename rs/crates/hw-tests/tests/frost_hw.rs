//! Port of `js/test/frost-hw.test.js` — EXPORT_SHARE and FROST HW signing
//! (INS 0x70–0x72) on a device provisioned via RESTORE_SHARE. Needs a
//! `FROST=1` build.
//!
//! RESTORE is the bridge: it brings the device to PROVISIONED from a captured
//! blob (validated separately in `dkg.rs`), so these tests exercise what sits
//! on top of a provisioned share without running the full sequential ceremony:
//!   - EXPORT_SHARE     → real AES-GCM encrypt + fresh RNG nonce
//!   - FROST_HW_COMMIT  → `zkn_frost_commit`, two on-curve commitments
//!   - FROST_HW_SIGN    → the state/quorum/membership guards a single device
//!                        can hit (SW_BAD_STATE, SW_WRONG_DATA_LENGTH)
//!
//! A valid FROST signature needs t co-signers' commitments (FS_REC records),
//! so the happy-path SIGN is intentionally not here: it belongs to a 2-device
//! setup. Guards are where handler bugs hide, and they are single-device.
//!
//! The fixture is a 2-of-3 blob (t=2).
//!
//! `node --test` runs a `before` hook once per suite; Rust has no shared
//! fixture across test functions, and the suites are serialized by the shared
//! transport anyway, so each test provisions the device itself through
//! [`provision`]. That is also more robust: a test cannot inherit the state
//! another one left behind.

use zknox_hw_tests::apdu::{dkg_state, *};
use zknox_hw_tests::context::{default_seed, device_or_skip, DeviceGuard};
use zknox_hw_tests::fixtures::fixture_path;
use zknox_hw_tests::hex::hex2buf;
use zknox_hw_tests::ledger::{exchange, try_exchange};

fn restore_blob() -> Option<Vec<u8>> {
    let path = fixture_path("restore-blob-yellow.hex");
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(hex2buf(s.trim())),
        Err(_) => {
            eprintln!("SKIP: no blob fixture at {}", path.display());
            None
        }
    }
}

/// ABORT → RESTORE → STATUS, returning `(t, n)` from the status word layout
/// `state|id|t|n|mask(2)`.
fn provision(dev: &mut DeviceGuard) -> (u8, u8, u8) {
    let blob = restore_blob().expect("fixture checked by the caller");
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "ABORT").expect("ABORT");
    let mut payload = account_be(0).to_vec();
    payload.extend_from_slice(&blob);
    let a = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_RESTORE_SHARE, 0, 0, &payload),
        "RESTORE",
    )
    .expect("RESTORE");
    assert_eq!(a.len(), 64, "RESTORE returns 64-byte A");
    let s = exchange(dev.transport(), &build_apdu0(INS_DKG_STATUS), "STATUS").expect("STATUS");
    assert_eq!(s[0], dkg_state::PROVISIONED, "device must be PROVISIONED");
    (s[1], s[2], s[3]) // id, t, n
}

/// Guard: the fixture and the seed both have to be right before provisioning.
fn provisioned(test: &str) -> Option<(DeviceGuard, u8, u8, u8)> {
    if !default_seed() {
        eprintln!("SKIP {test}: blob is bound to yellow×12");
        return None;
    }
    restore_blob()?;
    let mut dev = device_or_skip(test)?;
    let (id, t, n) = provision(&mut dev);
    Some((dev, id, t, n))
}

/// The `signStreamed` of the JavaScript suite.
///
/// FROST_HW_SIGN streams its payload: a single APDU's Lc is one byte (≤255),
/// but msg(32) + t×160 exceeds that for t ≥ 2. The handler accumulates chunks:
/// P1_FIRST resets the buffer, any non-LAST chunk appends and returns OK,
/// P1_LAST appends then finalizes. We send msg + signer[0] as FIRST, then each
/// remaining signer, the last one as LAST. Every chunk stays under 255 bytes.
fn sign_streamed(
    dev: &mut DeviceGuard,
    msg: &[u8],
    signer_recs: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let mut first = msg.to_vec();
    first.extend_from_slice(&signer_recs[0]);
    try_exchange(
        dev.transport(),
        &build_apdu(INS_FROST_HW_SIGN, FROST_P1_FIRST, 0, &first),
        "SIGN[first]",
    )?;
    // Middle signers (none for t=2): P1 must be neither FIRST (would reset the
    // buffer) nor LAST (would finalize early).
    for (i, rec) in signer_recs
        .iter()
        .enumerate()
        .take(signer_recs.len().saturating_sub(1))
        .skip(1)
    {
        try_exchange(
            dev.transport(),
            &build_apdu(INS_FROST_HW_SIGN, FROST_P1_NEXT, 0, rec),
            &format!("SIGN[{i}]"),
        )?;
    }
    try_exchange(
        dev.transport(),
        &build_apdu(
            INS_FROST_HW_SIGN,
            FROST_P1_LAST,
            0,
            &signer_recs[signer_recs.len() - 1],
        ),
        "SIGN[last]",
    )
}

fn signer_rec(id: u8) -> Vec<u8> {
    let mut r = vec![0u8; FROST_FS_REC];
    r[31] = id;
    r
}

#[test]
fn export_share_returns_a_well_formed_blob() {
    let Some((mut dev, _id, _t, _n)) = provisioned("export_share_shape") else {
        return;
    };
    let blob = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_EXPORT_SHARE, 0, 0, &account_be(0)),
        "EXPORT",
    )
    .expect("EXPORT");
    let magic = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
    assert_eq!(magic, 0x5a4b_4253, "blob must carry the ZKBS magic");
    assert!(
        blob.len() >= 4 + 12 + 32 + 16,
        "blob must fit aad+nonce+ct+tag"
    );
    // The nonce (12 B) sits after the aad; it must not be all-zero (the RNG ran).
    let tail = &blob[blob.len() - (12 + 32 + 16)..];
    assert!(tail[..12].iter().any(|b| *b != 0), "nonce must be non-zero");
}

#[test]
fn two_exports_differ_but_restore_the_same_group_key() {
    let Some((mut dev, _id, _t, _n)) = provisioned("export_roundtrip") else {
        return;
    };
    let b1 = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_EXPORT_SHARE, 0, 0, &account_be(0)),
        "EXPORT#1",
    )
    .expect("EXPORT#1");
    let b2 = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_EXPORT_SHARE, 0, 0, &account_be(0)),
        "EXPORT#2",
    )
    .expect("EXPORT#2");
    assert_ne!(b1, b2, "fresh nonce → different ciphertext each time");

    // The device is PROVISIONED, and RESTORE requires IDLE, so ABORT first.
    // Restore twice from the same blob and check A is stable.
    let mut payload = account_be(0).to_vec();
    payload.extend_from_slice(&b2);
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "ABORT").expect("ABORT");
    let a0 = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_RESTORE_SHARE, 0, 0, &payload),
        "RESTORE(A0)",
    )
    .expect("RESTORE(A0)");
    exchange(dev.transport(), &build_apdu0(INS_DKG_ABORT), "ABORT").expect("ABORT");
    let a1 = exchange(
        dev.transport(),
        &build_apdu(INS_DKG_RESTORE_SHARE, 0, 0, &payload),
        "RESTORE(A1)",
    )
    .expect("RESTORE(A1)");
    assert_eq!(
        a0, a1,
        "same share → same A across an export/restore round-trip"
    );
}

#[test]
fn frost_commit_returns_two_commitments() {
    let Some((mut dev, _id, _t, _n)) = provisioned("frost_commit") else {
        return;
    };
    let out = exchange(
        dev.transport(),
        &build_apdu0(INS_FROST_HW_COMMIT),
        "FROST_COMMIT",
    )
    .expect("COMMIT");
    assert_eq!(
        out.len(),
        128,
        "COMMIT returns 2x64-byte points (hiding, binding)"
    );
    assert!(
        out[..64].iter().any(|b| *b != 0),
        "hiding commitment non-zero"
    );
    assert!(
        out[64..].iter().any(|b| *b != 0),
        "binding commitment non-zero"
    );
}

#[test]
fn sign_without_a_prior_commit_is_refused() {
    let Some((mut dev, _id, _t, _n)) = provisioned("sign_state_guard") else {
        return;
    };
    // Reset FROST state to FS_IDLE, so no COMMIT is pending. SIGN must then
    // fail on the state guard regardless of what ran before.
    exchange(
        dev.transport(),
        &build_apdu0(INS_FROST_HW_RESET),
        "FROST_RESET",
    )
    .expect("RESET");
    let msg = vec![0x11u8; 32];
    let sw = try_exchange(
        dev.transport(),
        &build_apdu(INS_FROST_HW_SIGN, FROST_P1_LAST, 0, &msg),
        "SIGN/no-commit",
    )
    .expect_err("SIGN without COMMIT must fail");
    assert_eq!(sw, SW_BAD_STATE, "must be SW_BAD_STATE");
}

#[test]
fn sign_with_the_wrong_signer_count_is_refused() {
    let Some((mut dev, _id, t, _n)) = provisioned("sign_quorum_guard") else {
        return;
    };
    assert!(t >= 2, "fixture is a 2-of-3 blob");
    // COMMIT first to reach FS_NONCED, then send a signer list of size != t.
    exchange(dev.transport(), &build_apdu0(INS_FROST_HW_COMMIT), "COMMIT").expect("COMMIT");
    let mut payload = vec![0x22u8; 32];
    payload.extend_from_slice(&signer_rec(1)); // one signer while t == 2
    let sw = try_exchange(
        dev.transport(),
        &build_apdu(INS_FROST_HW_SIGN, FROST_P1_LAST, 0, &payload),
        "SIGN/nsig!=t",
    )
    .expect_err("wrong signer count must fail");
    assert_eq!(sw, SW_WRONG_DATA_LENGTH, "must be SW_WRONG_DATA_LENGTH");
}

#[test]
fn sign_for_a_quorum_without_this_device_is_refused() {
    let Some((mut dev, my_id, t, n)) = provisioned("sign_membership_guard") else {
        return;
    };
    exchange(dev.transport(), &build_apdu0(INS_FROST_HW_COMMIT), "COMMIT").expect("COMMIT");
    // Build a size-t signer list that deliberately excludes this device's id,
    // so the handler must reject on membership (me < 0).
    let mut others = Vec::new();
    for id in 1..=n {
        if others.len() == t as usize {
            break;
        }
        if id != my_id {
            others.push(id);
        }
    }
    assert_eq!(
        others.len(),
        t as usize,
        "need {t} ids excluding self; got {others:?}"
    );
    let recs: Vec<Vec<u8>> = others.iter().map(|id| signer_rec(*id)).collect();
    let sw = sign_streamed(&mut dev, &[0x33u8; 32], &recs)
        .expect_err("signing outside our quorum must fail");
    assert_eq!(
        sw, SW_WRONG_DATA_LENGTH,
        "must be SW_WRONG_DATA_LENGTH (me < 0)"
    );
}
