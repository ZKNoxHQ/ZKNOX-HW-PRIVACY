//! The build gates, checked against the build.
//!
//! `src/zkn_features.h` splits `ZKN_FROST` from `ZKNOX_DEBUG` so the
//! threshold feature can ship without the key-extraction instructions. The
//! `sim/Makefile` comment is blunt about why it mirrors the split: that is
//! "the only way to find out whether the split actually holds".
//!
//! Here the question is answerable without reading the Makefile, because the
//! C reports what it was compiled with and the dispatcher reports what it
//! maps. The two must agree in both directions, which is what catches a case
//! guarded on one gate while its handler sits behind two.
//!
//!   ZKNOX_SIM_MODE=prod ZKNOX_SIM_FROST=1 cargo test -p zknox-sim
//!
//! rebuilds the simulator for the configuration this file exists to check.

use zknox_hw_tests::apdu::*;
use zknox_sim::Sim;

/// Instructions behind `ZKN_FROST` alone.
const FROST_INS: &[u8] = &[
    INS_DKG_GET_COMM_PUBKEY,
    INS_DKG_DEAL,
    INS_DKG_SET_COMMITS,
    INS_DKG_GET_SHARE,
    INS_DKG_PUT_SHARE,
    INS_DKG_FINALIZE,
    INS_DKG_ABORT,
    INS_DKG_STATUS,
    INS_DKG_EXPORT_SHARE,
    INS_DKG_RESTORE_SHARE,
    INS_FROST_HW_COMMIT,
    INS_FROST_HW_SIGN,
    INS_FROST_HW_RESET,
];

/// Instructions behind `ZKNOX_DEBUG` alone.
const DEBUG_INS: &[u8] = &[INS_BLIND_SIGN_NO_DISPLAY, INS_SIGN_WITH_PRIVKEY];

/// Instructions that need both gates: key extraction never leaves
/// `ZKNOX_DEBUG`, even once `ZKN_FROST` ships.
const FROST_AND_DEBUG_INS: &[u8] = &[INS_DKG_DEBUG_SKSHARE, INS_DKG_DEBUG_COMM_PRIVKEY];

/// True when the dispatcher maps `ins` at all, whatever the handler then
/// decides.
fn mapped(sim: &mut Sim, ins: u8) -> bool {
    sim.sw(&[CLA, ins, 0, 0, 0]) != "6d00"
}

#[test]
fn the_frost_gate_matches_the_compiled_build() {
    let mut sim = Sim::lock();
    let on = zknox_sim::has_frost();
    for &ins in FROST_INS {
        assert_eq!(
            mapped(&mut sim, ins),
            on,
            "INS {ins:#04x} is behind ZKN_FROST, which is {}",
            if on { "on" } else { "off" }
        );
    }
}

#[test]
fn the_debug_gate_matches_the_compiled_build() {
    let mut sim = Sim::lock();
    let on = zknox_sim::has_debug_ins();
    for &ins in DEBUG_INS {
        assert_eq!(
            mapped(&mut sim, ins),
            on,
            "INS {ins:#04x} is behind ZKNOX_DEBUG, which is {}",
            if on { "on" } else { "off" }
        );
    }
}

#[test]
fn key_extraction_needs_both_gates() {
    let mut sim = Sim::lock();
    let on = zknox_sim::has_frost() && zknox_sim::has_debug_ins();
    for &ins in FROST_AND_DEBUG_INS {
        assert_eq!(
            mapped(&mut sim, ins),
            on,
            "INS {ins:#04x} needs ZKN_FROST and ZKNOX_DEBUG together"
        );
    }
}

/// `SIGNING_PUBKEY` ships in every build, but its silent P1=0 variant is the
/// debug one: a prod build must not hand out a key without the review screen.
#[test]
fn the_silent_pubkey_variant_is_debug_only() {
    let mut sim = Sim::lock();
    let mut apdu = vec![CLA, INS_SIGNING_PUBKEY, PUBKEY_P1_SILENT, 0, 4];
    apdu.extend_from_slice(&account_be(0));
    let sw = sim.sw(&apdu);
    if zknox_sim::has_debug_ins() {
        assert_eq!(sw, "9000", "a debug build answers the silent variant");
    } else {
        assert_ne!(
            sw, "9000",
            "a prod build must not export a key without the review screen"
        );
    }
    // The confirming variant is in every build.
    apdu[2] = PUBKEY_P1_CONFIRM;
    assert_eq!(sim.sw(&apdu), "9000", "P1=1 goes through the review screen");
}
