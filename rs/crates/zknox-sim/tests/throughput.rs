//! What the two transports cost, measured rather than asserted.
//!
//! Ignored by default: it is the evidence behind the numbers in
//! `rs/VERSION.md` and the reason the sweeps in `dispatcher.rs` are
//! affordable here and not over the pipe.
//!
//!   cargo test -p zknox-sim --test throughput -- --ignored --nocapture

use std::time::Instant;

use zknox_hw_tests::ledger::{default_sim_binary, spawn_sim};
use zknox_sim::Sim;

#[test]
#[ignore = "a measurement, not a check"]
fn linked_against_piped() {
    let n = 200_000u64;
    let apdu = [0xe0u8, 0x03, 0, 0, 0]; // GET_VERSION, the cheapest handler

    let mut sim = Sim::lock();
    let t0 = Instant::now();
    for _ in 0..n {
        sim.exchange_raw(&apdu);
    }
    let linked = t0.elapsed();

    let binary = default_sim_binary();
    if !binary.exists() {
        eprintln!(
            "linked {:.0}/s; no simulator binary at {} to compare against \
             (cd sim && make MODE=debug)",
            n as f64 / linked.as_secs_f64(),
            binary.display()
        );
        return;
    }
    let mut t = spawn_sim(&binary).expect("spawn the simulator");
    let t0 = Instant::now();
    for _ in 0..n {
        t.exchange_raw(&apdu).expect("exchange");
    }
    let piped = t0.elapsed();

    let sweep = 16_777_216.0;
    eprintln!(
        "linked {:.0} APDU/s, piped {:.0} APDU/s, ratio {:.0}x",
        n as f64 / linked.as_secs_f64(),
        n as f64 / piped.as_secs_f64(),
        piped.as_secs_f64() / linked.as_secs_f64()
    );
    eprintln!(
        "the (INS,P1,P2) sweep: {:.1}s linked, {:.0}s piped",
        sweep * linked.as_secs_f64() / n as f64,
        sweep * piped.as_secs_f64() / n as f64
    );
}
