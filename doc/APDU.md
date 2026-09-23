# ZKNOX-HW-PRIVACY — APDU protocol

Generated from the app source (`src/apdu/dispatcher.c`, `src/types.h`,
`src/sw.h`, `src/handler/*`). Authoritative host-side reference: every
instruction listed here exists in this repository, and formats are taken from
the handlers, not from prose. App name is `"ZKNOX"`.

This app is a **FROST threshold-signing / DKG** privacy device. Its surface has
three tiers, gated by build flags (`src/zkn_features.h`, `Makefile`):

- **Core** — always compiled.
- **Threshold (`ZKN_FROST`)** — the VSS/DKG ceremony and FROST signing.
  **Not shippable yet:** a `MODE=prod FROST=1` build is a hard error
  (`Makefile`), pending the BLOCKING list in `src/zkn_features.h`. Present in
  `MODE=debug` builds, where `FROST` defaults to `1`.
- **Debug (`ZKNOX_DEBUG`)** — test/introspection surface: no-UI signing,
  raw-scalar signing, key extraction. Never in a production build.

## Framing

| Field | Length | Value |
|-------|-------:|-------|
| CLA   | 1 | `0xE0` (`constants.h`). Otherwise `SW_CLA_NOT_SUPPORTED`. |
| INS   | 1 | Instruction, see below. Unknown → `SW_INS_NOT_SUPPORTED`. |
| P1/P2 | 1+1 | Per-instruction; `0x00` unless stated. |
| Lc    | 1 | Length of `CData` (0–255). |
| CData | Lc | Command data. |

Response: `RData` (may be empty) then the 2-byte status word `SW`.

## Account addressing and derivation

Every key instruction addresses an account by a **4-byte big-endian account
index** — not a serialized BIP-32 path. The firmware pins the paths (all levels
hardened); the account index is substituted at the third level. Matches the
RAILGUN Ledger app so a shared host derives the same 0zk identity.

| Key | Curve | Path | Used by |
|-----|-------|------|---------|
| Spending | BabyJubJub | `m/44'/1984'/account'/0'/0'` | `SIGNING_PUBKEY` (0x01), `BLIND_SIGN` (0x12) |
| Viewing  | Ed25519 | `m/420'/1984'/account'/0'/0'` | `VIEWING_PUBKEY` (0x10), `VIEWING_PRIVKEY` (0x13), `RAILGUN_ADDRESS` (0x14) |
| DKG comm | Ed25519 | `m/421'/1984'/account'/0'/0'` | `ZKN_FROST` ceremony (non-exported) |

All three use SLIP-0010 extended derivation with the HMAC seed key
`"babyjubjub seed"`. The path prefixes must be declared in the app's
`PATH_APP_LOAD_PARAMS` (`Makefile`) — `"44'/1984'" "420'/1984'" "421'/1984'"` —
or BOLOS refuses the corresponding `os_derive` with a signing error.

## Status words (`src/sw.h`)

| SW | Name | Meaning |
|----|------|---------|
| `0x9000` | `SW_OK` | Success. |
| `0x6985` | `SW_DENY` | User rejected on the device. |
| `0x6A80` | `SW_INCORRECT_DATA` | Malformed payload. |
| `0x6A86` | `SW_WRONG_P1P2` | Invalid P1/P2. |
| `0x6A87` | `SW_WRONG_DATA_LENGTH` | `Lc` not the expected length. |
| `0x6D00` | `SW_INS_NOT_SUPPORTED` | Unknown instruction (or a flag-gated INS absent from this build). |
| `0x6E00` | `SW_CLA_NOT_SUPPORTED` | CLA ≠ `0xE0`. |
| `0xB000` | `SW_WRONG_RESPONSE_LENGTH` | Internal length mismatch. |
| `0xB001` | `SW_DISPLAY_BIP32_PATH_FAIL` | UI failure. |
| `0xB002` | `SW_DISPLAY_ADDRESS_FAIL` | UI failure. |
| `0xB007` | `SW_BAD_STATE` | Instruction issued in the wrong ceremony/session state. |
| `0xB008` | `SW_SIGNATURE_FAIL` | Signing/derivation/crypto error. |

## Core instructions

Always present.

### `0x01` SIGNING_PUBKEY

Twisted-Edwards signing public key for an account — the key `BLIND_SIGN` (0x12)
signs with. Account is a 4-byte big-endian index; the firmware pins the path.

- **P1**: `0x01` display-and-confirm (required in production; `0x00` silent is
  `ZKNOX_DEBUG`-only and rejected otherwise). **P2**: `0x00`.
- **CData** (4): `account(4 BE)`.
- **Response** (on approve): `x(32) || y(32)` — 64 bytes, big-endian each.

### `0x03` GET_VERSION

- **P1/P2**: `0x00`. **CData**: none.
- **Response**: `major(1) || minor(1) || patch(1)`. No UI.

### `0x04` GET_APP_NAME

- **P1/P2**: `0x00`. **CData**: none.
- **Response**: ASCII app name (`"ZKNOX"`), no length prefix. No UI.

### `0x12` BLIND_SIGN

EdDSA-Poseidon signature over an opaque 32-byte message, with a blind-sign
approval (shows account index + message).

- **P1** = curve id: `0x00` BabyJubJub (default), `0x01` Bandersnatch, `0x02`
  BabyJubJub. **P2**: `0x00`.
- **CData** (36): `account(4 BE) || msg(32)`.
- **Response** (on approve, 129 bytes): `sigLen(1) = 96 || R8x(32) || R8y(32) ||
  S(32) || msg(32)`. The trailing 32 bytes echo the signed message.

### `0x10` VIEWING_PUBKEY

Ed25519 viewing public key for an account — part of the user's 0zk address.
INS/format identical to the RAILGUN Ledger app.

- **P1**: `0x01` display-and-confirm (required in production; `0x00` silent is
  `ZKNOX_DEBUG`-only and rejected otherwise). **P2**: `0x00`.
- **CData** (4): `account(4 BE)`.
- **Response** (on approve): 32 bytes, RFC 8032 compressed.

### `0x13` VIEWING_PRIVKEY

Export the Ed25519 viewing private key, gated by mandatory user approval. The
secret is derived only after Approve and never staged.

- **P1**: `0x00`. **P2**: `0x00`.
- **CData** (4): `account(4 BE)`.
- **Response** (on approve): 32 bytes — the raw SLIP-0010 derived viewing seed
  (the value scanning software needs). **Not** a clamped scalar.

### `0x14` RAILGUN_ADDRESS

Derive the canonical `0zk1…` address for an account and show it on the trusted
screen before returning it. Master key is `Poseidon3(spendX, spendY,
Poseidon1(viewingSeed))`; the encoded network id is the all-chains wildcard.

- **P1**: `0x01` display-and-confirm (required in production; `0x00` silent is
  `ZKNOX_DEBUG`-only and rejected otherwise). **P2**: `0x00`.
- **CData** (4): `account(4 BE)`.
- **Response** (on approve): 127 ASCII bytes, the `0zk1…` string (not
  NUL-terminated).

## Threshold instructions (`ZKN_FROST`)

Two-round Pedersen VSS/DKG (every participant is a dealer, no trusted dealer),
then FROST signing (RFC 9591 §5) on the resulting share. **Not in production
builds yet** (see the tier note above). Ceremony state machine:

```
IDLE → DEALT → COMMITTED → COLLECTED → PROVISIONED
DKG_ABORT returns to IDLE from any transient state.
```

The round barrier is protocol-enforced: the share AAD is
`id || commitmentsDigest`, so `DKG_GET_SHARE` before `COMMITTED` is refused.

### DKG ceremony

| INS | Name | CData | Response |
|-----|------|-------|----------|
| `0x60` | DKG_GET_COMM_PUBKEY | `account(4 BE)` | `HK_i(32)` Ed25519 comm pubkey, RFC 8032 compressed |
| `0x61` | DKG_DEAL | `account(4 BE) id(1) t(1) n(1) name_len(1) name(≤32)` | `epoch(16) || C_i(t*64, x‖y BE)` |
| `0x62` | DKG_SET_COMMITS | per dealer: `id_j(1) HK_j(32) C_j(t*64)`; **P1** `0x00` FIRST / `0x01` NEXT / `0x02` LAST | (LAST only) `commitmentsDigest(32)` |
| `0x63` | DKG_GET_SHARE | `j(1)` | `nonce(12) || ct(32) || tag(16)` |
| `0x64` | DKG_PUT_SHARE | `j(1) C_j(t*64) nonce(12) ct(32) tag(16)` | — |
| `0x65` | DKG_FINALIZE | — | `A(64, x‖y BE)`, user confirms on screen |
| `0x66` | DKG_ABORT | — | wipes transient state |
| `0x67` | DKG_STATUS | — | `state(1) id(1) t(1) n(1) recv_bitmap(2 BE)` |
| `0x6a` | DKG_EXPORT_SHARE | `account(4 BE)` | `aad(var) || nonce(12) || ct(32) || tag(16)` — encrypted share backup |
| `0x6b` | DKG_RESTORE_SHARE | `account(4 BE) || aad(var) || nonce(12) || ct(32) || tag(16)` | — (GCM tag gates; jumps to PROVISIONED) |

`DKG_SET_COMMITS` dealers MUST arrive sorted by `sortKey(C_{j,0})`; the device
checks monotonicity so the host cannot reorder and change the digest. All P1/P2
are `0x00` except `DKG_SET_COMMITS` P1 (chunk selector).

### FROST signing

State: `PROVISIONED --FROST_HW_COMMIT--> NONCED --FROST_HW_SIGN--> PROVISIONED`.
The signing share is read from the DKG state, never supplied over the wire;
`lambda` is derived on-device from the signer ids. Nonces are single-use:
`FROST_HW_SIGN` wipes `(d_i, e_i)` before returning, and a second sign without a
fresh commit is refused (reuse would leak the share).

| INS | Name | CData | Response |
|-----|------|-------|----------|
| `0x70` | FROST_HW_COMMIT | — | `D_i(64) || E_i(64)`, x‖y big-endian |
| `0x71` | FROST_HW_SIGN | across chunks: `msg(32) || [ id(32) D.x(32) D.y(32) E.x(32) E.y(32) ] * t`; **P1** `0x00` FIRST / `0x01` NEXT / `0x02` LAST | (LAST only) `z_i(32)` |
| `0x72` | FROST_HW_RESET | — | drops the nonces |

## Debug-only instructions (`ZKNOX_DEBUG`)

Compiled **only** with `ZKNOX_DEBUG`; a production build returns
`SW_INS_NOT_SUPPORTED`. The two key-extraction handlers additionally require
`ZKN_FROST`.

| INS | Name | CData | Response | Notes |
|-----|------|-------|----------|-------|
| `0x02` | BLIND_SIGN_NO_DISPLAY | `account(4 BE) || msg(32)` | `R8x(32) || R8y(32) || S(32)` (96 B) | `BLIND_SIGN` without UI. P1 = curve id. |
| `0x50` | SIGN_WITH_PRIVKEY | `curveID(1) || prv(32) || msg(32)` (65 B) | `R8x‖R8y‖S` (96 B) | Signs with a host-supplied raw scalar. |
| `0x68` | DKG_DEBUG_COMM_PRIVKEY | `account(4 BE)` | `32 B` | TEST ONLY — exports the Ed25519 comm private key. Requires `ZKN_FROST`. |
| `0x69` | DKG_DEBUG_SKSHARE | — | `skShare(32) || skShare_div8(32)` (64 B) | TEST ONLY — exports the signing share. Requires `ZKN_FROST`. |
