//! The link itself: the firmware answers when called as a function.
//!
//! If this file fails to build, the archive `sim/Makefile`'s `lib` target
//! produced is incomplete; if it fails to run, the shim and the dispatcher
//! disagree about something before any contract is even asserted.

use zknox_hw_tests::apdu::*;
use zknox_hw_tests::hex::buf2hex;
use zknox_sim::Sim;

#[test]
fn the_linked_firmware_answers_get_version_and_app_name() {
    let mut sim = Sim::lock();
    eprintln!(
        "linked simulator {} (debug_ins={}, frost={})",
        zknox_sim::version(),
        zknox_sim::has_debug_ins(),
        zknox_sim::has_frost()
    );

    let v = sim
        .exchange(&build_apdu0(INS_GET_VERSION), "GET_VERSION")
        .expect("GET_VERSION");
    assert_eq!(v, vec![0, 1, 0], "MAJOR.MINOR.PATCH");

    let name = sim
        .exchange(&build_apdu0(INS_GET_APP_NAME), "GET_APP_NAME")
        .expect("GET_APP_NAME");
    assert_eq!(name, b"ZKNOX", "APPNAME, no length prefix");
}

/// The same vector `sim/test/selftest.sh` and `rs/.../dkg.rs` check, now
/// through a function call: the two transports must agree byte for byte, or
/// one of them is not driving the firmware.
#[test]
fn the_yellow_transport_key_is_the_one_the_other_transports_see() {
    if !zknox_sim::has_frost() {
        eprintln!("SKIP: built FROST=0, no DKG instructions");
        return;
    }
    let mut sim = Sim::lock();
    let hk = sim
        .exchange(
            &build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account_be(0)),
            "DKG_GET_COMM_PUBKEY",
        )
        .expect("GET_COMM_PUBKEY");
    assert_eq!(
        buf2hex(&hk),
        "9fc8d2779ee5bfb7662e02b5c8e23c71a4de3045621b15e031cbe481687de081"
    );
}
