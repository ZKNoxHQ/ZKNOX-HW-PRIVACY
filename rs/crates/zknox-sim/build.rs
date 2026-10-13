//! Builds `sim/` as a static library and links it into this crate.
//!
//! The flags that make the simulator the firmware rather than something like
//! it — `-DZKN_BN_BACKEND_SW`, `-DAPPNAME`, the `MODE`/`FROST` gates, the
//! forced `-include sim_compat.h`, fifteen include paths into the libC — live
//! in `sim/Makefile`, which mirrors the app Makefile. Re-deriving them here
//! would mean two places to keep in step and a silent divergence the day one
//! moves, so this script shells out to `make lib` and links what comes out.
//! The libC's own Makefile is part of that chain, as it is for the binary.
//!
//! `ZKNOX_SIM_MODE` (debug|prod) and `ZKNOX_SIM_FROST` (0|1) choose the
//! configuration; the defaults are `debug` and `1`, the pair the test suites
//! need. `MODE=prod FROST=1` is the interesting one for checking that the
//! feature split holds, and `tests/config.rs` adapts to whatever it finds.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo = crate_dir
        .join("../../..")
        .canonicalize()
        .expect("repository root");
    let sim = repo.join("sim");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    let mode = std::env::var("ZKNOX_SIM_MODE").unwrap_or_else(|_| "debug".to_string());
    let frost = std::env::var("ZKNOX_SIM_FROST").unwrap_or_else(|_| "1".to_string());
    assert!(
        mode == "debug" || mode == "prod",
        "ZKNOX_SIM_MODE must be debug or prod, got {mode:?}"
    );
    assert!(
        frost == "0" || frost == "1",
        "ZKNOX_SIM_FROST must be 0 or 1, got {frost:?}"
    );

    // ZKNOX_SIM_ASAN=1 compiles the simulator's own sources under
    // AddressSanitizer and UBSan and links the runtime into the test binary.
    // Only the C is instrumented, which is the half that can read past a
    // buffer; the Rust side needs no nightly toolchain for that.
    let san = std::env::var("ZKNOX_SIM_ASAN").is_ok_and(|v| !v.is_empty() && v != "0");

    println!("cargo:rerun-if-env-changed=ZKNOX_SIM_MODE");
    println!("cargo:rerun-if-env-changed=ZKNOX_SIM_FROST");
    println!("cargo:rerun-if-env-changed=ZKNOX_SIM_ASAN");
    println!("cargo:rerun-if-changed=build.rs");
    for p in [
        "sim/Makefile",
        "sim/src",
        "sim/shim",
        "sim/vendor",
        "src/apdu",
        "src/handler",
        "src/helper",
        "src/ui",
        "src/zknox/src",
        "src/zknox/Makefile",
    ] {
        println!("cargo:rerun-if-changed={}", repo.join(p).display());
    }

    if !sim.join("Makefile").exists() {
        panic!(
            "no simulator at {}: this crate links the host simulator of this \
             repository and cannot be built on its own",
            sim.display()
        );
    }

    let make = std::env::var("MAKE").unwrap_or_else(|_| "make".to_string());
    let status = Command::new(&make)
        .arg("-C")
        .arg(&sim)
        .arg(format!("MODE={mode}"))
        .arg(format!("FROST={frost}"))
        .arg(format!("SAN={}", if san { 1 } else { 0 }))
        .arg("lib")
        .status()
        .unwrap_or_else(|e| panic!("{make} -C {}: {e}", sim.display()));
    if !status.success() {
        panic!(
            "{make} -C {} MODE={mode} FROST={frost} lib failed ({status}). \
             A C toolchain and the src/zknox submodule are required; \
             `git submodule update --init --recursive` if it is missing.",
            sim.display()
        );
    }

    // Where the Makefile puts a configuration's archive.
    let built = sim
        .join("build/.config")
        .join(&mode)
        .join(format!("frost-{frost}{}", if san { "-san" } else { "" }))
        .join("libzknoxsim.a");
    if !built.exists() {
        panic!("{} was not produced", built.display());
    }
    // Copied into OUT_DIR so two cargo profiles, or a `make clean` in sim/,
    // cannot pull the archive out from under a built test binary.
    let staged = out.join("libzknoxsim.a");
    std::fs::copy(&built, &staged)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", built.display(), staged.display()));

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=zknoxsim");
    if san {
        // The sanitizer runtimes have to reach the final link of every target
        // of this package, the integration tests included.
        for lib in ["asan", "ubsan"] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }
    // The archive carries libzknox's members, so nothing is needed at run
    // time. Which gates it was built with is not reported here on purpose:
    // `has_debug_ins()` and `has_frost()` answer from the compiled C, which is
    // evidence rather than an assumption about what this script asked for.
}
