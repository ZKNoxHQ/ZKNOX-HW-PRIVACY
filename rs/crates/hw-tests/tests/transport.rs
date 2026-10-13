//! Transport and APDU encoding, checked against a mock simulator.
//!
//! The device suites need the real `sim/` binary; the framing itself is
//! checked here against a two-line shell script that speaks the same
//! protocol — one hex APDU per line in, one hex response per line out. The
//! echo mock returns the APDU it received as the response payload, so the
//! test can assert the exact bytes that crossed the pipe.
//!
//! Runs without a device and without building the simulator.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use zknox_hw_tests::apdu::*;
use zknox_hw_tests::hex::buf2hex;
use zknox_hw_tests::ledger::{exchange, spawn_sim, try_exchange, Transport};

/// Writes a shell script that answers every line with `body`, where `$l` is
/// the line just read.
fn mock(name: &str, body: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("zknox-mock-sim-{name}-{}.sh", std::process::id()));
    fs::write(
        &path,
        format!("#!/bin/sh\nwhile IFS= read -r l; do {body}\ndone\n"),
    )
    .expect("write mock");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod mock");
    path
}

/// A mock that echoes the APDU back as response data with SW 9000.
fn echo_mock() -> Transport {
    spawn_sim(mock("echo", r#"printf '%s9000\n' "$l";"#)).expect("spawn echo mock")
}

/// A mock that always answers the given status word with no data.
fn sw_mock(sw: &str) -> Transport {
    spawn_sim(mock(sw, &format!("printf '{sw}\\n';"))).expect("spawn sw mock")
}

#[test]
fn an_apdu_crosses_the_pipe_unchanged() {
    let mut t = echo_mock();
    let apdu = build_apdu0(INS_DKG_STATUS);
    let echoed = exchange(&mut t, &apdu, "STATUS").expect("STATUS");
    assert_eq!(buf2hex(&apdu), "e067000000", "CLA INS P1 P2 Lc, empty body");
    assert_eq!(echoed, apdu, "the simulator must receive those exact bytes");
}

/// The FIRST chunk of a streamed FROST signature is msg(32) + one FS_REC(160)
/// = 192 bytes, which must still fit a single-byte Lc.
#[test]
fn a_192_byte_sign_chunk_crosses_the_pipe_whole() {
    let mut payload = vec![0x33u8; 32];
    payload.extend_from_slice(&vec![0u8; FROST_FS_REC]);
    let apdu = build_apdu(INS_FROST_HW_SIGN, FROST_P1_FIRST, 0, &payload);
    assert_eq!(apdu.len(), 5 + 192);
    assert_eq!(apdu[4], 0xc0, "Lc = 192");

    let mut t = echo_mock();
    let echoed = exchange(&mut t, &apdu, "SIGN").expect("SIGN");
    assert_eq!(echoed, apdu, "the whole chunk must arrive unchanged");
}

#[test]
fn a_non_9000_status_word_surfaces_as_an_error() {
    let mut t = sw_mock("b007");
    let err = exchange(
        &mut t,
        &build_apdu(INS_DKG_GET_SHARE, 0, 0, &[2]),
        "GET_SHARE",
    )
    .expect_err("b007 must not be swallowed");
    assert_eq!(err.sw, SW_BAD_STATE);
    assert_eq!(err.message, "[GET_SHARE] SW=b007");
}

#[test]
fn try_exchange_returns_the_status_word() {
    let mut t = sw_mock("6a87");
    let sw = try_exchange(&mut t, &build_apdu0(INS_FROST_HW_SIGN), "SIGN")
        .expect_err("6a87 must be reported");
    assert_eq!(sw, SW_WRONG_DATA_LENGTH);
}

/// A simulator that dies mid-exchange must surface as an error rather than
/// block the suite forever.
#[test]
fn a_simulator_that_exits_is_reported_not_awaited() {
    let path = mock("exit", "exit 0;");
    let mut t = spawn_sim(path).expect("spawn exiting mock");
    let err = exchange(&mut t, &build_apdu0(INS_DKG_STATUS), "STATUS")
        .expect_err("a closed pipe must be an error");
    assert_eq!(err.sw, "????");
    assert!(err.message.contains("transport error"), "{}", err.message);
}

#[test]
fn apdu_builders_match_the_javascript_layout() {
    assert_eq!(account_be(0), [0, 0, 0, 0]);
    assert_eq!(account_be(0x0102_0304), [1, 2, 3, 4]);
    assert_eq!(
        buf2hex(&build_apdu(INS_DKG_GET_COMM_PUBKEY, 0, 0, &account_be(7))),
        "e06000000400000007"
    );
    // account(4 BE) || id || t || n || name_len || name
    assert_eq!(
        buf2hex(&build_dkg_deal_payload(0, 1, 2, 3, "unit-test")),
        "00000000".to_string() + "01" + "02" + "03" + "09" + &buf2hex(b"unit-test")
    );
}
