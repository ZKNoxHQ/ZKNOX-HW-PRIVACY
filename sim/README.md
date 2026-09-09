# sim/ — simulateur APDU host-side

**Version 0.4.0**

| Version | Contenu |
|---|---|
| 0.4.0 | interface stdin/stdout pure (réseau supprimé), fix event-loop node (ref/unref) |
| 0.3.0 | fix build prod vs main courant (`sim_compat.h`) |
| 0.2.0 | couverture 0x08 (`--auth`), cible `test-sim-js` |
| 0.1.0 | simulateur initial, validation KAT device + suite JS |

Compile les **vrais** `dispatcher.c` + handlers de l'app contre un shim
SDK minimal et la libzknox host (`ZKN_BN_BACKEND_SW`), pour simuler le
comportement de la librairie à l'intégration avant portage device.

## Périmètre

- `MODE=prod` (défaut) : INS de production — 0x01, 0x03, 0x04, 0x07,
  0x08, 0x09, 0x10, 0x12, 0x13, 0x14.
- `MODE=debug` : ajoute les INS `ZKNOX_DEBUG` (poseidon, keccak,
  blake512, scalar-mul, encrypt-note, FROST, viewing privkey…), pour
  câbler la suite JS existante.
- **CLEAR_SIGN (0x11) exclu** (session stateful NBGL) → `6D00`.
- UI = *yay-sayer* : toute review est auto-approuvée. `SIM_REJECT=1`
  bascule en auto-refus (teste les chemins `SW_DENY`).

## Build & test

    cd sim
    make                # -> build/prod/apdu_sim
    make MODE=debug     # -> build/debug/apdu_sim
    make test           # self-test KAT (mode --stdin, sans deps)

Le Makefile pinne les mêmes `PATH_7702_L*_H` que le Makefile app
(m/44'/60'/1984'/7702'). `APP` et `ZKNOX` pointent par défaut sur la
racine du repo et `src/zknox` (build host `make` requis une fois).

## Interface

    ./build/prod/apdu_sim    # 1 APDU hex par ligne sur stdin ->
                             # 1 réponse hex (data||SW) par ligne sur stdout

C'est tout : pas de réseau, pas de serveur, pas de framing. Le JS
spawn le binaire et pipe les lignes.

Env : `SIM_SEED` (128 hex, seed BIP39 ; défaut = "yellow"×12),
`SIM_REJECT`, `SIM_VERBOSE`, `SIM_RNG_SEED` (RNG déterministe pour
reproductibilité).

## `make test-sim-js`

Build en `MODE=debug` puis exécute les 8 fichiers de la suite JS
compatibles + `test_7702_address.cjs --sign --auth --random 3`, chaque
test spawnant lui-même le binaire. Aucun prérequis au-delà des
node_modules existants de `js/`.

## Câblage sur les tests JS existants

`js/lib/ledger.js` et `test_7702_address.cjs` acceptent `SIM_BIN` : la
suite spawn alors le simulateur au lieu d'ouvrir le device, sans autre
modification.

    cd sim && make MODE=debug
    cd ../js && SIM_BIN=../sim/build/debug/apdu_sim \
        node --test test/keys.test.js

## Fidélité validée

- Dérivation 7702 : 8/8 KAT pubkey bit-exacts vs Nano S+ (et le sim
  pré-patch reproduisait exactement les anciens KAT device — double
  preuve).
- Signatures 0x09/0x08 : RFC6979 low-s + parité, vérifiées par
  ecrecover sur les adresses device.
- SLIP-0010 seed custom "babyjubjub seed", BabyJubjub (circomlibjs),
  Ed25519 (noble), adresse 0zk bech32m : suites `keys`, `0zk-address`,
  `0zk-derivations` vertes.
- `encrypt-note` : reproduction octet-par-octet des blocs on-chain
  (bundle Sepolia), AES-256-GCM vérifié vs node crypto.

## Architecture

    sim/
    ├── Makefile
    ├── src/main.c            # serveur TCP Speculos + mode --stdin
    ├── shim/
    │   ├── include/          # cx.h, os.h, io.h, buffer.h, … (sous-ensemble SDK)
    │   ├── shim_crypto.c     # BIP32/SLIP10 sw, ECDSA RFC6979, ed25519,
    │   │                     # hashes, cx_bn minimal, RNG
    │   ├── shim_crypto_ext.c # (debug) ed25519 decompress/scalarmult, AES-GCM
    │   ├── shim_io.c         # io_send_*, G_context, globals
    │   ├── sim_ui.c          # ui_display_* -> validate_*(auto-approve)
    │   └── sim_stubs.c       # handler_clear_sign -> 6D00
    ├── vendor/trezor/        # bignum, ecdsa secp256k1, sha2/3, hmac, blake2b…
    ├── vendor/ed25519/       # orlp/ed25519 (fe, ge, sc, sha512)
    ├── vendor/aes/           # Gladman AES-GCM (via trezor-firmware)
    └── test/selftest.sh

## Vendors (provenance à figer — voir note)

- `vendor/trezor/` : sous-ensemble de trezor-firmware/crypto (**master,
  non pinné** — à figer sur un commit + LICENSE lors d'une passe dédiée)
- `vendor/ed25519/` : orlp/ed25519 (zlib)
- `vendor/aes/` : AES-GCM Brian Gladman via trezor-firmware/crypto/aes

Ces vendors ne servent QUE le simulateur host ; rien n'est lié dans le
firmware.

Conventions BOLOS reproduites à l'identique (pièges connus) :
`cx_ecfp_generate_pair(Ed25519)` retourne `04||X_be||Y_be` ;
`cx_hash_sha512` retourne le nombre d'octets écrits (64), pas `CX_OK` ;
`cx_bn_*` : représentation big-endian alignée à droite.
