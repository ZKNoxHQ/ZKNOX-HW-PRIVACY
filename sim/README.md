# sim/ — simulateur APDU host-side

**Version 0.5.0**

| Version | Contenu |
|---|---|
| 0.5.0 | adapté à cette app (sources, UI, INS de ZKNOX-HW-PRIVACY), DKG/FROST gatés sur `FROST` et non sur `MODE`, self-test réécrit, suite Rust `rs/` branchée |
| 0.4.0 | interface stdin/stdout pure (réseau supprimé), fix event-loop node (ref/unref) |
| 0.3.0 | fix build prod vs main courant (`sim_compat.h`) |
| 0.2.0 | couverture 0x08 (`--auth`), cible `test-sim-js` |
| 0.1.0 | simulateur initial, validation KAT device + suite JS |

Compile les **vrais** `dispatcher.c` + handlers de l'app contre un shim
SDK minimal et la libzknox host (`ZKN_BN_BACKEND_SW`), pour simuler le
comportement de la librairie à l'intégration avant portage device.

## Périmètre

La surface est celle de cette app, pas celle de l'app RAILGUN dont le
simulateur est issu : ni clear-sign, ni 7702, ni chiffrement de note.

- `MODE=prod` (défaut) : INS de production — 0x01 (P1=1 seulement), 0x03,
  0x04, 0x12.
- `MODE=debug` : ajoute `BLIND_SIGN_NO_DISPLAY` (0x02), `SIGN_WITH_PRIVKEY`
  (0x50) et le `SIGNING_PUBKEY` silencieux (P1=0).
- `FROST=1` (impliqué par `MODE=debug`, réglable seul) : DKG/VSS 0x60–0x6b
  et FROST 0x70–0x72. Le gate suit celui du Makefile de l'app, donc
  `MODE=prod FROST=1` est testable.
- UI = *yay-sayer* : toute review est auto-approuvée. `SIM_REJECT=1`
  bascule en auto-refus (teste les chemins `SW_DENY`, qui répondent `6985`).

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
reproductibilité). Ces variables sont lues une seule fois, au premier usage :
un appelant qui a besoin d'en changer en cours de route lie la bibliothèque
plutôt que de spawner le binaire (voir ci-dessous).

## `make lib` — le simulateur comme bibliothèque

    make MODE=debug lib        # build/.config/debug/frost-1/libzknoxsim.a
    make MODE=debug SAN=1 lib  # la même chose sous ASan + UBSan

Une seule archive : les objets du simulateur, ceux de l'app et les membres de
`libzknox.a`. Fusionnée et pas livrée en deux archives parce que la dépendance
va dans les deux sens — `libzknox` appelle les `cx_*` du shim, le shim appelle
`libzknox` — ce qu'un linker résout à l'intérieur d'une archive mais pas entre
deux en une passe.

Le point d'entrée est `src/sim_core.h` : `zkn_sim_exchange(apdu, len, out,
&out_len)`, plus les setters qui remplacent les variables d'environnement
(`zkn_sim_set_seed`, `zkn_sim_set_ui_decision`, `zkn_sim_set_rng_seed`) et les
accesseurs de configuration (`zkn_sim_has_debug_ins`, `zkn_sim_has_frost`).
`src/main.c` n'est qu'un appelant parmi d'autres : il traduit les lignes hex
de stdin en appels à cette fonction.

`rs/crates/zknox-sim` est l'autre appelant, et c'est le troisième jeu de tests
du dépôt : `../run-sim-tests.sh`.

## `make test-sim-rs`

Build en `MODE=debug` puis exécute la suite Rust `rs/crates/hw-tests`
contre le simulateur. Chaque binaire de test spawn lui-même le simulateur :
pas de serveur, pas de port, pas de conteneur.

## Câblage

C'est la suite Rust qui consomme le simulateur : `rs/crates/hw-tests`
le spawn par défaut depuis `sim/build/debug/apdu_sim`, surchargeable par
`SIM_BIN`. Voir `rs/README.md`.

    cd sim && make MODE=debug
    cd ../rs && cargo test -p zknox-hw-tests -- --test-threads=1

Côté JS, `js/lib/ledger.js` de ce dépôt ne connaît que la socket Speculos
et l'USB : le câblage `SIM_BIN` décrit dans les versions précédentes de ce
README n'existe plus ici.

## Fidélité validée

- `DKG_GET_COMM_PUBKEY` : bit-exact avec l'oracle yellow×12 capturé sur
  Speculos, que la suite JS asserte aussi sur device
  (`9fc8d277…687de081`).
- `BLIND_SIGN_NO_DISPLAY` / `SIGN_WITH_PRIVKEY` : signature EdDSA-Poseidon
  bit-exacte avec l'oracle host (circomlib côté JS, `frost-babyjubjub`
  côté Rust), sur la clé dérivée m/44'/1984'/0'/0'/0'.
- `BLIND_SIGN` : chemin d'approbation (`60||sig||echo`) et chemin de refus
  (`SIM_REJECT=1` → `6985`), que ni Speculos ni le device ne donnent sans
  intervention humaine.
- `RESTORE_SHARE` : le blob de backup 2-sur-3 de `js/test/fixtures/`
  déchiffre et provisionne, et un bit de tag retourné est rejeté.

## Architecture

    sim/
    ├── Makefile
    ├── src/main.c            # boucle stdin/stdout, une APDU hex par ligne
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
