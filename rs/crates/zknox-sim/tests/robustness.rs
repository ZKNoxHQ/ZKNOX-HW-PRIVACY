//! Random APDUs by the hundred thousand, against the one invariant that has
//! to hold for all of them: the dispatcher answers, and it answers a status
//! word `src/sw.h` declares.
//!
//! This is the shape a fuzzer wants, and `zkn_sim_exchange` is already the
//! signature libFuzzer takes — `(data, len)` in, deterministic work, no
//! global teardown. What is here is the part that can run on stable Rust in
//! a normal `cargo test`: inputs from the OS CSPRNG, a fixed budget, and the
//! seed printed so a failure can be replayed. Pointing `cargo-fuzz` at the
//! same function, for coverage-guided input generation, needs nothing from
//! the C side that is not already exported.
//!
//! `ZKNOX_SIM_FUZZ_CASES` moves the budget; the default keeps the suite under
//! a second.

use frost_babyjubjub::rng::{Drbg, Rng};

use zknox_hw_tests::apdu::CLA;
use zknox_hw_tests::hex::buf2hex;
use zknox_sim::Sim;

/// Every status word `src/sw.h` declares, plus the two the front-end can
/// produce. `6f00` is in the list so the response parses, and asserted
/// against separately: it means a handler returned without replying.
const DOCUMENTED: &[&str] = &[
    "9000", "6985", "6a80", "6a86", "6a87", "6d00", "6e00", "b000", "b001", "b002", "b007", "b008",
    "6700", "6f00",
];

fn cases() -> usize {
    std::env::var("ZKNOX_SIM_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

#[test]
fn random_apdus_never_escape_the_documented_status_words() {
    // Drawn from the OS CSPRNG, then expanded by the DRBG so one printed seed
    // replays the whole run.
    let mut seed = [0u8; 32];
    frost_babyjubjub::rng::OsRng.fill_bytes(&mut seed);
    if let Ok(hex) = std::env::var("ZKNOX_SIM_FUZZ_SEED") {
        let bytes = zknox_hw_tests::hex::hex2buf(&hex);
        assert_eq!(bytes.len(), 32, "ZKNOX_SIM_FUZZ_SEED is 64 hex characters");
        seed.copy_from_slice(&bytes);
    }
    eprintln!("ZKNOX_SIM_FUZZ_SEED={}", buf2hex(&seed));
    let mut rng = Drbg::new(seed);

    let n = cases();
    let mut sim = Sim::lock();
    let mut replied = [0usize; 256];

    for case in 0..n {
        // A quarter of the cases are a well-formed header with a body whose
        // length matches Lc, so handlers are actually reached; the rest are
        // arbitrary, including truncated and over-long ones.
        let mut pick = [0u8; 4];
        rng.fill_bytes(&mut pick);
        let well_formed = pick[0] & 0x03 == 0;
        let len = if well_formed {
            5 + pick[1] as usize
        } else {
            (pick[1] as usize * 300) / 256
        };
        let mut apdu = rng.random_bytes(len.max(1));
        if !apdu.is_empty() && pick[2] & 0x07 != 0 {
            apdu[0] = CLA; // mostly our class, or everything would be 6e00
        }
        if well_formed && apdu.len() >= 5 {
            apdu[4] = (apdu.len() - 5) as u8;
        }

        let resp = sim.exchange_raw(&apdu);
        assert!(resp.len() >= 2, "case {case}: no status word");
        let sw = buf2hex(&resp[resp.len() - 2..]);
        assert!(
            DOCUMENTED.contains(&sw.as_str()),
            "case {case}: APDU {} answered {sw}, which src/sw.h does not declare",
            buf2hex(&apdu)
        );
        assert_ne!(
            sw,
            "6f00",
            "case {case}: APDU {} returned without replying",
            buf2hex(&apdu)
        );
        if apdu.len() >= 2 {
            replied[apdu[1] as usize] += 1;
        }

        // The device is driven into arbitrary states; put it back regularly so
        // the run keeps reaching handlers rather than collecting b007.
        if case % 512 == 511 {
            sim.reset();
        }
    }

    let touched = replied.iter().filter(|c| **c > 0).count();
    eprintln!("{n} random APDUs, {touched}/256 instruction bytes reached");
    assert!(touched > 200, "the draw should cover the instruction byte");
}

/// The same budget spent entirely on the instructions that take a body, with
/// bodies of every length from 0 to 255. Length handling is where a handler
/// reads past its own buffer, and `6a87` is the answer that says it did not.
#[test]
fn every_body_length_is_handled_for_every_instruction() {
    let mut sim = Sim::lock();
    let mut rng = Drbg::new([0x5a; 32]);
    for ins in 0..=255u8 {
        for lc in 0..=255u8 {
            let mut apdu = vec![CLA, ins, 0, 0, lc];
            apdu.extend_from_slice(&rng.random_bytes(lc as usize));
            let resp = sim.exchange_raw(&apdu);
            let sw = buf2hex(&resp[resp.len() - 2..]);
            assert!(
                DOCUMENTED.contains(&sw.as_str()),
                "INS {ins:#04x} with a {lc}-byte body answered {sw}"
            );
            assert_ne!(
                sw, "6f00",
                "INS {ins:#04x} Lc={lc} returned without replying"
            );
        }
        sim.reset();
    }
}
