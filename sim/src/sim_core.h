/* sim/src/sim_core.h — the simulator as a callable library.
 *
 * `main.c` is one caller of this: it turns stdin lines of hex into
 * `zkn_sim_exchange` calls. `rs/crates/zknox-sim` is the other, linking the
 * same objects into a Rust test binary and calling the function directly.
 *
 * Everything below is process-global, because the firmware it drives is: the
 * DKG ceremony state in `handler_dkg.c`, the FROST state in
 * `handler_frost_sign.c`, the `cx_bn` pool and the seed cache are all file
 * statics. One process is one device. A caller that needs several
 * participants at once needs several processes, which is what the line
 * protocol is for.
 *
 * The setters are the in-process counterpart of the `SIM_*` environment
 * variables, which can only be read once at startup. A caller that uses them
 * takes over: `zkn_sim_set_seed` overrides `SIM_SEED` whether or not it was
 * set, and the environment is read only for whatever has not been set
 * explicitly.
 */
#ifndef ZKN_SIM_CORE_H
#define ZKN_SIM_CORE_H

#include <stdint.h>
#include <stddef.h>

/* Largest response the shim can hold: the 4096-byte accumulator of
 * `shim_io.c` plus the two status bytes. */
#define ZKN_SIM_RESP_MAX 4098

/* Feeds one APDU to the real dispatcher and writes `data || SW` to `out`,
 * which must have room for ZKN_SIM_RESP_MAX bytes.
 *
 * Returns 0 and a two-byte `6700` for an APDU shorter than its own header,
 * as a Ledger would. A handler that returns without replying (which should
 * not happen) is reported as `6f00`. */
int zkn_sim_exchange(const uint8_t *apdu, size_t len, uint8_t *out, size_t *out_len);

/* ── build configuration, so a caller can skip rather than guess ───────── */

/* SIM_VERSION. */
const char *zkn_sim_version(void);
/* 1 when built ZKNOX_MODE_DEBUG: BLIND_SIGN_NO_DISPLAY (0x02),
 * SIGN_WITH_PRIVKEY (0x50), the silent SIGNING_PUBKEY P1=0 and the DKG
 * key-extraction instructions exist. */
int zkn_sim_has_debug_ins(void);
/* 1 when built ZKN_FROST: the DKG (0x60–0x6b) and FROST (0x70–0x72)
 * instructions exist. */
int zkn_sim_has_frost(void);

/* ── control surface ───────────────────────────────────────────────────── */

/* Sets the 64-byte BIP39 seed every derivation starts from. */
void zkn_sim_set_seed(const uint8_t seed[64]);
/* Back to the built-in seed, the one of mnemonic "yellow" x12. Also the
 * state a process starts in when `SIM_SEED` is unset. */
void zkn_sim_set_seed_default(void);

/* What the UI answers: 1 approve, 0 reject, -1 defer to `SIM_REJECT`. */
void zkn_sim_set_ui_decision(int decision);

/* Deterministic RNG from `seed`, the in-process `SIM_RNG_SEED`. */
void zkn_sim_set_rng_seed(uint64_t seed);
/* Back to /dev/urandom. */
void zkn_sim_set_rng_os(void);

#endif /* ZKN_SIM_CORE_H */
