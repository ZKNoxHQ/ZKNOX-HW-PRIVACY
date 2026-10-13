//! The dispatcher's contract, swept rather than sampled.
//!
//! `src/apdu/dispatcher.c` states an RFU rule per instruction, in a comment
//! that gives the reason: "avoids a fingerprinting / forward-compat hazard
//! from silently accepting non-zero RFU values". A rule stated per instruction
//! is a rule that can be forgotten on the next instruction, and sampling a few
//! values does not catch that. So the table below is transcribed from the
//! switch, and the whole `(INS, P1, P2)` space is checked against it: 16.7
//! million exchanges, about two seconds in-process.
//!
//! The assertion is deliberately not a map of handler outcomes, which would
//! break whenever a handler legitimately changed. It is the three claims that
//! belong to the dispatcher:
//!
//! - `6a86` appears on exactly the RFU violations, and nowhere else;
//! - `6d00` appears on exactly the instructions this build does not map;
//! - every answer, anywhere in the space, is a status word `src/sw.h`
//!   declares.
//!
//! Over the line protocol the same sweep takes eight and a half minutes, which
//! is why `hw-tests` checks a handful of values instead.

use std::time::Instant;

use zknox_hw_tests::apdu::*;
use zknox_sim::Sim;

/// How the dispatcher validates the RFU bytes before invoking a handler.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rfu {
    /// `if (p1 != 0 || p2 != 0) return io_send_sw(SW_WRONG_P1P2);`
    Both,
    /// `if (p2 != 0) return io_send_sw(SW_WRONG_P1P2);` — P1 carries a value
    /// (a curve id, a display gate, a chunk marker).
    P2Only,
    /// Neither is validated here: the handler takes both.
    Neither,
}

/// Which build gate an instruction sits behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Gate {
    /// Always compiled.
    Always,
    /// `#if defined(ZKN_FROST)`.
    Frost,
    /// `#ifdef ZKNOX_DEBUG`.
    Debug,
    /// Both, as the key-extraction instructions are.
    FrostAndDebug,
}

impl Gate {
    fn compiled(self) -> bool {
        match self {
            Gate::Always => true,
            Gate::Frost => zknox_sim::has_frost(),
            Gate::Debug => zknox_sim::has_debug_ins(),
            Gate::FrostAndDebug => zknox_sim::has_frost() && zknox_sim::has_debug_ins(),
        }
    }
}

/// The switch of `apdu_dispatcher`, transcribed. A new instruction that does
/// not appear here fails the sweep, which is the point.
const TABLE: &[(u8, Rfu, Gate)] = &[
    (INS_SIGNING_PUBKEY, Rfu::P2Only, Gate::Always),
    (INS_BLIND_SIGN, Rfu::P2Only, Gate::Always),
    (INS_VIEWING_PUBKEY, Rfu::P2Only, Gate::Always),
    (INS_VIEWING_PRIVKEY, Rfu::Both, Gate::Always),
    (INS_RAILGUN_ADDRESS, Rfu::Neither, Gate::Always),
    (INS_GET_VERSION, Rfu::Both, Gate::Always),
    (INS_GET_APP_NAME, Rfu::Both, Gate::Always),
    (INS_DKG_GET_COMM_PUBKEY, Rfu::Both, Gate::Frost),
    (INS_DKG_DEAL, Rfu::Both, Gate::Frost),
    (INS_DKG_SET_COMMITS, Rfu::P2Only, Gate::Frost),
    (INS_DKG_GET_SHARE, Rfu::Both, Gate::Frost),
    (INS_DKG_PUT_SHARE, Rfu::Both, Gate::Frost),
    (INS_DKG_FINALIZE, Rfu::Both, Gate::Frost),
    (INS_DKG_ABORT, Rfu::Both, Gate::Frost),
    (INS_DKG_STATUS, Rfu::Both, Gate::Frost),
    (INS_DKG_EXPORT_SHARE, Rfu::Both, Gate::Frost),
    (INS_DKG_RESTORE_SHARE, Rfu::Both, Gate::Frost),
    (INS_FROST_HW_COMMIT, Rfu::Both, Gate::Frost),
    (INS_FROST_HW_SIGN, Rfu::P2Only, Gate::Frost),
    (INS_FROST_HW_RESET, Rfu::Both, Gate::Frost),
    (INS_BLIND_SIGN_NO_DISPLAY, Rfu::P2Only, Gate::Debug),
    (INS_SIGN_WITH_PRIVKEY, Rfu::Both, Gate::Debug),
    (INS_DKG_DEBUG_SKSHARE, Rfu::Both, Gate::FrostAndDebug),
    (INS_DKG_DEBUG_COMM_PRIVKEY, Rfu::Both, Gate::FrostAndDebug),
];

/// Every status word `src/sw.h` declares.
const DOCUMENTED: &[&str] = &[
    "9000", // SW_OK
    "6985", // SW_DENY
    "6a80", // SW_INCORRECT_DATA
    "6a86", // SW_WRONG_P1P2
    "6a87", // SW_WRONG_DATA_LENGTH
    "6d00", // SW_INS_NOT_SUPPORTED
    "6e00", // SW_CLA_NOT_SUPPORTED
    "b000", // SW_WRONG_RESPONSE_LENGTH
    "b001", // SW_DISPLAY_BIP32_PATH_FAIL
    "b002", // SW_DISPLAY_ADDRESS_FAIL
    "b007", // SW_BAD_STATE
    "b008", // SW_SIGNATURE_FAIL
    "6700", // the length check in sim_core.c, as a Ledger's transport would
    "6f00", // a handler that returned without replying — must never appear
];

/// The entry for `ins` in this build, or `None` when the build does not map
/// it.
fn mapped(ins: u8) -> Option<(Rfu, Gate)> {
    TABLE
        .iter()
        .find(|(i, _, g)| *i == ins && g.compiled())
        .map(|(_, r, g)| (*r, *g))
}

#[test]
fn the_whole_instruction_space_answers_a_documented_status_word() {
    let mut sim = Sim::lock();
    let t0 = Instant::now();
    let mut n: u64 = 0;
    let mut undocumented: Vec<(u8, u8, u8, String)> = Vec::new();

    for ins in 0..=255u8 {
        let entry = mapped(ins);
        for p1 in 0..=255u8 {
            for p2 in 0..=255u8 {
                // Lc = 0 and no body: an instruction that wants data stops at
                // INIT_BUF_OR_FAIL, so no handler signs anything and the sweep
                // stays a dispatcher test.
                let sw = sim.sw(&[CLA, ins, p1, p2, 0]);
                n += 1;

                if !DOCUMENTED.contains(&sw.as_str()) && undocumented.len() < 8 {
                    undocumented.push((ins, p1, p2, sw.clone()));
                    continue;
                }

                match entry {
                    None => assert_eq!(
                        sw, "6d00",
                        "INS {ins:#04x} is not mapped in this build, so it must \
                         answer SW_INS_NOT_SUPPORTED (P1={p1:#04x} P2={p2:#04x})"
                    ),
                    Some((rfu, _)) => {
                        let violated = match rfu {
                            Rfu::Both => p1 != 0 || p2 != 0,
                            Rfu::P2Only => p2 != 0,
                            Rfu::Neither => false,
                        };
                        if violated {
                            assert_eq!(
                                sw, "6a86",
                                "INS {ins:#04x} P1={p1:#04x} P2={p2:#04x} breaks its \
                                 {rfu:?} RFU rule and must answer SW_WRONG_P1P2"
                            );
                        } else {
                            assert_ne!(
                                sw, "6a86",
                                "INS {ins:#04x} P1={p1:#04x} P2={p2:#04x} respects its \
                                 {rfu:?} RFU rule, so SW_WRONG_P1P2 is wrong"
                            );
                            assert_ne!(
                                sw, "6d00",
                                "INS {ins:#04x} is mapped in this build but answers \
                                 SW_INS_NOT_SUPPORTED"
                            );
                        }
                    }
                }
            }
        }
    }

    assert!(
        undocumented.is_empty(),
        "status words outside src/sw.h: {undocumented:?}"
    );
    let dt = t0.elapsed();
    eprintln!(
        "swept {n} APDUs in {:.2}s ({:.0}/s)",
        dt.as_secs_f64(),
        n as f64 / dt.as_secs_f64()
    );
}

#[test]
fn a_foreign_class_byte_is_refused_whatever_follows() {
    let mut sim = Sim::lock();
    for cla in 0..=255u8 {
        if cla == CLA {
            continue;
        }
        for ins in 0..=255u8 {
            let sw = sim.sw(&[cla, ins, 0, 0, 0]);
            assert_eq!(
                sw, "6e00",
                "CLA {cla:#04x} INS {ins:#04x} must answer SW_CLA_NOT_SUPPORTED"
            );
        }
    }
}

/// `sim_core.c` answers a truncated header itself, as the transport layer does
/// on a device. Worth pinning: it is the one status word in the sweep that
/// does not come from the firmware.
#[test]
fn a_header_shorter_than_five_bytes_is_a_length_error() {
    let mut sim = Sim::lock();
    let full = [CLA, INS_GET_VERSION, 0, 0, 0];
    for len in 0..4 {
        assert_eq!(
            sim.sw(&full[..len]),
            "6700",
            "a {len}-byte APDU has no header"
        );
    }
    // Four bytes is a header with no Lc, which is a valid case-1 APDU.
    assert_eq!(sim.sw(&full[..4]), "9000", "CLA INS P1 P2 with no Lc");
    assert_eq!(sim.sw(&full), "9000");
}

#[test]
fn an_lc_that_overruns_the_body_is_a_length_error() {
    let mut sim = Sim::lock();
    for lc in 1..=255u8 {
        for body in 0..std::cmp::min(lc as usize, 8) {
            let mut apdu = vec![CLA, INS_DKG_STATUS, 0, 0, lc];
            apdu.extend(std::iter::repeat_n(0xaa, body));
            assert_eq!(
                sim.sw(&apdu),
                "6700",
                "Lc={lc} with a {body}-byte body must be refused"
            );
        }
    }
}

/// The same sweep with a plausible body, so the handlers actually run and
/// their own P1 validation is reached. Only the documented-status-word claim
/// is asserted here: what each handler decides is its own business, and the
/// other two suites check that.
#[test]
fn every_instruction_with_a_four_byte_body_stays_inside_the_documented_status_words() {
    let mut sim = Sim::lock();
    let account = account_be(0);
    for ins in 0..=255u8 {
        for p1 in 0..=255u8 {
            let mut apdu = vec![CLA, ins, p1, 0, 4];
            apdu.extend_from_slice(&account);
            let sw = sim.sw(&apdu);
            assert!(
                DOCUMENTED.contains(&sw.as_str()),
                "INS {ins:#04x} P1={p1:#04x} with a 4-byte body answered {sw}"
            );
            assert_ne!(
                sw, "6f00",
                "INS {ins:#04x} P1={p1:#04x} returned without replying"
            );
        }
        // Instructions that change state are swept too, so put the device
        // back before the next one.
        sim.reset();
    }
}
