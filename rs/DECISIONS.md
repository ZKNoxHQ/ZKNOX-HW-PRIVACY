# Architecture decisions

## ADR-001 — `num-bigint` for the field and group layer, not arkworks

The reference is a bigint implementation whose observable behaviour (reduction
points, error cases, unreduced exponents) is part of the contract. Mirroring it
on `num_bigint::BigInt` keeps the port line for line and the dependency set at
six crates. kohaku's `crates/crypto` was considered first, but its BabyJubJub
has no scalar field, no inversion, no serialization, no negation and no
equality, so the missing half would have had to be written anyway; its edition
2024 manifest also does not build on the toolchain available here.
Consequence: scalar multiplication is variable time. Acceptable for a wallet
and for the test harness, not for a hardware signer; see ADR-006.

## ADR-002 — Poseidon parameters taken from kohaku, permutation rewritten

`src/params/*.bin` are the parameter files of kohaku's `crates/poseidon-rust`
(TACEO, MIT/Apache-2.0), 32-byte little-endian field elements, embedded
verbatim. The permutation is the unoptimized circomlib loop rather than
TACEO's optimized one, because that is the form whose intermediate state
matches `poseidon-lite`. Verified against the KAT shipped in the parameter
file and against `poseidon-lite` on random inputs.

## ADR-003 — randomness is an explicit parameter

The TypeScript calls `randomBytes` inside the primitives. In Rust every
randomized function takes `&mut dyn Rng`. This is what lets the cross-check
drive both implementations from the same byte stream and compare `commit`,
`generateNonce`, `trustedDealerKeygen`, `RandomScalar` and the AES-GCM nonces
directly, instead of only checking algebraic relations.

## ADR-004 — BLAKE-512 is the default hasher

The GitLab source hashes H1/H3/H4/H5/H6/H7 with BLAKE-512, the SHA-3 finalist,
matching the `FROST-EDBABYJUJUB-BLAKE512-v1` ciphersuite string. BLAKE2b-512,
the pre-`fix/blake512-hasher` default, stays reachable through
`HashKind::Blake2b512` so a peer still on the old GitHub branch can be talked
to without a fork.

## ADR-005 — a malformed AEAD nonce is rejected, never repaired

`decryptShareAESGCMWithAAD` no longer truncates or zero-pads a nonce of the
wrong length, following the GitLab source: repairing it would decrypt a forged
envelope under a nonce the sender never used.

## ADR-006 — the participant contract is synchronous

The TypeScript lets every step of `DKGParticipant` return a value or a Promise
so a device round trip fits without making the software manager asynchronous.
One Rust trait cannot carry both. `participant::DkgParticipant` is the
synchronous contract; a transport-backed implementation blocks inside its own
methods, or the caller mirrors the trait with `async fn` in its own crate.
`run_ceremony` is written against the synchronous trait and keeps the same
seven steps and the same per-step state assertions.

## ADR-007 — both snapshot formats are ported

`DKGManager.toJSON` / `fromJSON` turned out to be plain hex-encoded JSON, not
msgpack, so it is ported as `snapshot::DkgSnapshot` and cross-tested both ways:
each side restores the other's mid-flow snapshots, finalizes, and must land on
the same share, group key and viewing key. This is what lets a Rust
participant join or resume a session started in TypeScript.

`FROSTSigningManager` and its session snapshots are ported too, `safe` /
`mid-round` distinction included, and cross-tested the same way: each side
restores the other's mid-round payload and must produce the same aggregate
signature. The shareable-key payloads of `module-index.ts` are ported as
well, so nothing of the library is left out.

## ADR-008 — `zeroize` pinned to 1.8.1

`zeroize` 1.9 requires edition 2024, which the rustc 1.75 used here does not
support. The pin is a build-environment artefact, not a design choice: drop it
when the crate moves into a workspace on a current toolchain.

## ADR-009 — the factor 8 stays as the TypeScript has it

`finalizeParticipant` returns `skShare = 8 * skShareDiv8` and the signing round
uses `skShare`, so the aggregate satisfies the circomlib verification equation
`S*B8 == R8 + 8*hm*A` against the group key rebuilt from the Feldman
commitments. Changing the convention on the Rust side would break interop, so
it is preserved and asserted in both test suites.

## ADR-010 — the manager owns its sessions

The TypeScript `SigningSession` holds a back-reference to its manager, which
Rust cannot express without interior mutability or reference counting. The
manager owns a `Vec<SigningSession>` instead and the session operations are
manager methods taking the session id, with the flat single-session API
delegating to a lazily created `default` session as upstream does. Sessions,
partials and remote commitments are kept in insertion order rather than a map,
so a snapshot written here matches the one the TypeScript writes from the same
state, key for key.

## ADR-011 — msgpack through rmp-serde, struct as map

`getShareableViewingKey` / `getShareableMultisigKey` must produce the exact
bytes `@msgpack/msgpack` writes from the equivalent object, since the payload
is shared between wallets as an opaque hex string. rmp-serde in
`with_struct_map()` mode writes a map with string keys in declaration order,
and both libraries pick the shortest encoding for strings and integers, so the
outputs match byte for byte; the cross-check compares 32 random payloads of
each kind. Decoding goes through `serde_json::Value` rather than a typed
struct, because the payload is caller-controlled and the TypeScript validates
field types one by one; that keeps the same error for the same bad input
without adding a dependency.

Two upstream quirks are preserved rather than corrected: `poseidon()` reverses
each input before handing it to `poseidon-lite`, which reads a byte array
big-endian, so the value hashed is the little-endian reading of the input; and
`poseidonHex()` builds those inputs with a minimal-length big-endian buffer, so
the hashed value is the byte reversal of the parsed number. Changing either
would break interoperability with payloads already in circulation.

## ADR-012 — the test oracle is `frost-babyjubjub`, frozen against circomlib

`js/test/sign.test.js` checks the device against `circomlibjs`. The Rust suite
cannot depend on node at test time, so the oracle is this workspace's own
EdDSA-Poseidon. To keep that from becoming a second, unchecked opinion,
`js/tools/gen-rust-oracle-vectors.mjs` freezes what circomlib says for 32
random inputs drawn from the OS CSPRNG, and `tests/oracle.rs` replays them
without a device. A drift between the two implementations then shows up as a
failing unit test rather than as a mysterious device mismatch.

The port also had to match one detail of the JavaScript reference:
`F.toMontgomery(msg)` reduces the message modulo the BabyJubJub base prime, so
a message at or above the prime signs as its residue. The suite's own message
is below the prime and would never have shown it; three quarters of the random
vectors are above it.

## ADR-015 — the Rust suite targets `sim/`, not Speculos

The JavaScript suite drives Speculos, which means Docker, the Ledger dev
container and a built `.elf`. `sim/` compiles the same `dispatcher.c` and the
same handlers against an SDK shim and the software backend of libzknox, and
speaks a line protocol over a pipe, so the Rust suite spawns it directly: no
container, no emulator, no port, seconds per run. What is being tested is the
firmware's own C, not a reimplementation of it.

What this gives up is the device's real cx layer and its real RNG, which the
shim replaces; a signature that matches the host oracle on the simulator is
evidence about the handlers and the derivation, not about the secure element.
The JavaScript suite still runs against Speculos and a physical device, and
the `hid` feature keeps the Rust suite able to do the same.

Bringing `sim/` back to this app was part of the work: its Makefile still
listed the RAILGUN app's sources (7702 auth, tx hash, delegates, note
encryption, the debug-only handlers) and its UI shim still answered that app's
review screens. Both now follow this app's surface, and the DKG and FROST
handlers are gated on `FROST` rather than on `MODE`, as in the app Makefile,
so `MODE=prod FROST=1` stays testable.

## ADR-016 — the multi-device ceremony is a test, not a demo

A FROST signature needs t participants, so the JavaScript suite leaves the
happy path untested and keeps only the guards: one Speculos instance is one
device. With the simulator a participant is a process, so `tests/ceremony.rs`
runs several of them and drives the real APDU sequence.

The verification is deliberately asymmetric: the host never learns a share,
and checks the result with `frost-babyjubjub` rather than with anything the
device said. Each `z_i` is verified against the public share rebuilt from the
Feldman commitments, so a wrong device is named rather than hidden in the sum,
and the aggregate is verified under the circomlib equation. A pass is evidence
that the firmware's FROST and the TypeScript library agree on the binding
factors, the group commitment, the challenge and the interpolation.

## ADR-017 — hardware and simulators in the same ceremony

A FROST ceremony does not care what its participants run on, which makes the
interesting configuration one real device among simulated peers: it exercises
the device's own DKG and signing against an independent implementation of the
same protocol, without needing three Ledgers. `HW_DEVICE=1` selects it and
`HW_PARTICIPANT_ID` says which participant the device plays.

A physical device's seed is the one input the suite cannot set, so the
configuration with hardware in it is the one where every participant runs on
yellow×12 — see ADR-018, which is why that is no longer a problem.

## ADR-018 — two ceremonies, and the transport key is derived, not announced

The first version of the ceremony gave every simulated participant its own
fixed seed and asserted that the transport keys differed. The reasoning was
that participants sharing a key would make the ceremony meaningless. That was
wrong about what the keys are for.

A verifier's whole input is the message, the signature and the group public
key. Nothing per-participant enters it, so whether two participants derive
from the same seed is invisible to verification; the DKG binds the dealer
polynomial to the participant id as well as the seed, so even identical seeds
deal different polynomials. The seeds therefore cannot be the thing to assert.

What matters is the opposite direction: that the key a participant announces
is the key its seed derives. `handler_dkg.c` explains the attack — a
coordinator that substitutes its own key for HK_j derives the same AES key the
victim does and reads every share addressed to j, and nothing downstream
notices because A still comes out of the genuine commitments. The device
defends its own entry by rederiving it in `SET_COMMITS`. The host now defends
all of them: `oracle::dkg_comm_pubkey_from_seed` recomputes each key from the
seed (SLIP-0010 with the `"babyjubjub seed"` HMAC key down
`m/421'/1984'/account'/0'/0'`, then the Ed25519 public key of the node) and the
ceremony compares. A frozen yellow×12 vector in `tests/oracle.rs`, captured
before that derivation existed, keeps the host and the device from agreeing on
a wrong answer.

So the suite runs the ceremony twice. Once on the canonical seed, every
participant on yellow×12, which is the shape `run-rs-device-tests.sh`
reproduces with a Ledger standing in for one of them. Once in pure software
with a fresh 64-byte seed per participant and n, t, the quorum, the name and
the message drawn from the OS CSPRNG. The pair is the evidence: unrelated
seeds work, a shared seed works, and in both cases the signature verifies
under the group public key alone.

The random one stays pure software even under `HW_DEVICE` — a Ledger cannot be
handed a seed — and prints its draws so a failure can be replayed with the
same `SIM_SEED`s. Its bounds are the firmware's: `DKG_MAX_N` 5, `DKG_MAX_T` 3,
and exactly `t` signature records because `handler_frost_sign.c` refuses any
other count.

## ADR-013 — a configured backend that does not answer is a failure

The JavaScript suite skips when no device is connected. Translated literally,
that would make a Rust run with no backend look exactly like a passing run with
one, since `cargo test` reports a skipped test as `ok`. So the rule is split:
nothing available at all → skip and say so; a backend named or present
(`SIM_BIN`, a built simulator, the `hid` feature) that does not answer → fail. This is the asymmetry
`js/README.md` already describes for a firmware built without `FROST=1`.

## ADR-014 — one shared transport behind a mutex, provisioning per test

`node --test --test-concurrency=1` runs the JavaScript suites one at a time
over a single device handle. Rust runs test functions on parallel threads, so
the transport is a global behind a mutex that each test holds for its whole
body; `--test-threads=1` then only avoids pointless blocking.

The `before` hook that provisions the device once per JavaScript suite has no
Rust equivalent, so each test in `frost_hw.rs` provisions itself through
`provision()`. That costs a RESTORE per test and buys independence: no test
inherits the state another one left behind.

## ADR-019 — the simulator as a library, and what that third set is for

`sim/src/main.c` held a 40-line `process_apdu`: fill a `command_t`, call
`apdu_dispatcher`, read back what the shim's `io_send_*` left in its
accumulator. Everything around it was the hex-line transport. That function is
the only seam the firmware needs, so it moved to `sim/src/sim_core.c` as
`zkn_sim_exchange` and `main.c` became one caller of it.

`rs/crates/zknox-sim` is the other caller. It links the same objects into the
test binary, which makes an APDU a function call: 9.8 million a second against
31 thousand through the pipe. The factor of three hundred is the whole point,
because it changes which tests are affordable rather than which are possible.
The third set is therefore the sweeps: the entire `(INS, P1, P2)` space against
the RFU rule the dispatcher states instruction by instruction, every body
length for every instruction, a hundred thousand random APDUs, and key
derivation under 32 seeds in one run. Over the pipe the first of those alone
is nine minutes, which is why `hw-tests` samples instead.

Two decisions inside it are worth recording.

`build.rs` shells out to `sim/Makefile` rather than rebuilding the compile
line with the `cc` crate. The flags that make the simulator the firmware and
not something like it — `-DZKN_BN_BACKEND_SW`, the `MODE`/`FROST` gates, the
forced `-include sim_compat.h`, fifteen include paths into the libC, and the
libC's own Makefile — mirror the app Makefile. Two copies of that would
diverge silently the day one moved. The cost is that `cargo test` now needs a
C toolchain and the submodule, which is why this is a separate crate and a
separate script: `run-rs-tests.sh` keeps working without them.

The seed, the review decision and the RNG became C setters
(`zkn_sim_set_seed`, `zkn_sim_set_ui_decision`, `zkn_sim_set_rng_seed`). The
`SIM_*` variables stay, because a spawned process has no other way in, but
they are read once at startup and that is a real limit: `hw-tests` spawns a
whole second simulator so that one UI answer can be no. With setters, approve
and refuse happen in one session, and 32 seeds in one run. The first run of
those tests found that `SIM_RNG_SEED` was not injective — the shim did
`state = seed | 1`, so 2 and 3 drove the same stream — which no amount of
sampling from one process would have shown.

What the linked simulator gives up is the process boundary. The DKG and FROST
state, the `cx_bn` pool and the seed cache are file statics, so one process is
one device and a t-of-n ceremony is out of reach; `Sim::lock` hands out that
single device behind a mutex. A firmware crash now takes the test runner with
it instead of surfacing as a transport error. The same property is what makes
`ZKNOX_SIM_ASAN=1` work: only the C is instrumented, so AddressSanitizer and
UBSan run under stable Rust, and the full set passes in 31 s with the sweep
included.
