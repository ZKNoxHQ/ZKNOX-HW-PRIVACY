#pragma once

#include <stddef.h> // size_t
#include <stdint.h> // uint*_t
#include <stdbool.h>

#include "bip32.h"

#include "constants.h"

/**
 * Enumeration with expected INS of APDU commands.
 *
 * The values are a strict subset of the ZKNOX APDU namespace, so a host
 * client written against one ZKNOX app talks to this one unchanged for
 * the instructions it does implement.
 */
typedef enum
{
    // ─── Keys ────────────────────────────────────────────────────────
    //
    // SIGNING_PUBKEY (0x01) — twisted-Edwards signing pubkey for an
    // account index. This is the key BLIND_SIGN (0x12) signs with.
    //   APDU data (4 B): account(4 BE)
    //   P1 = 0x00  silent (DEBUG builds only)
    //   P1 = 0x01  display-and-confirm; returns the key on Approve
    //   P2 = 0x00  reserved
    //   Response: x(32) || y(32), big-endian
    SIGNING_PUBKEY = 0x01,

    // Standard Ledger app identification APDUs (boilerplate convention).
    // Also reachable via the BOLOS default handler at CLA=0xB0 INS=0x01.
    GET_VERSION = 0x03,  // returns MAJOR(1) || MINOR(1) || PATCH(1)
    GET_APP_NAME = 0x04, // returns APPNAME bytes (no length prefix)

    // BLIND_SIGN (0x12) — EdDSA-Poseidon over an opaque 32-byte message.
    // Stages the request, shows the blind-signing review, and signs only
    // on Approve.
    //   APDU data (36 B): account(4 BE) || msg(32)
    //   P1 = curve id (0x00 legacy = BabyJubjub, 0x01 Bandersnatch,
    //        0x02 BabyJubjub); P2 = 0x00 reserved
    //   Response: sig_len(1) || R8x||R8y||S (96) || msg(32)
    BLIND_SIGN = 0x12,

#ifdef ZKNOX_DEBUG

    // BLIND_SIGN_NO_DISPLAY (0x02) — BLIND_SIGN without the approval UI.
    // Integration-test handler: it is the one path that lets a host suite
    // check signatures against reference vectors without driving a screen.
    BLIND_SIGN_NO_DISPLAY = 0x02,

    // SIGN_WITH_PRIVKEY (0x50) — sign with a host-supplied raw scalar.
    // Exists to cross-check the on-device EdDSA-Poseidon against a
    // reference implementation on shared test vectors.
    //   APDU data (65 B): curve_id(1) || prv(32) || msg(32)
    SIGN_WITH_PRIVKEY = 0x50,

    // The two DKG INSes that hand out secrets outright. They stay behind
    // ZKNOX_DEBUG whatever ZKN_FROST is set to.
    DKG_DEBUG_COMM_PRIVKEY = 0x68, // TEST ONLY — exports the comm privkey
    DKG_DEBUG_SKSHARE      = 0x69, // TEST ONLY — exports the signing share

#endif

/* Threshold signing. Gated on ZKN_FROST rather than ZKNOX_DEBUG so the
 * ceremony can ship without the debug surface — an enum body may be split
 * across preprocessor blocks, and the values stay explicit either way.
 *
 * 0x68 and 0x69 are deliberately NOT here: they export the comm private key
 * and the signing share, and stay behind ZKNOX_DEBUG. */
#if defined(ZKNOX_DEBUG) || defined(ZKN_FROST)

    // Two-round VSS/DKG (see handler_dkg.h). 0x60..0x67, 0x6a..0x6b.
    DKG_GET_COMM_PUBKEY = 0x60,
    DKG_DEAL            = 0x61,
    DKG_SET_COMMITS     = 0x62,
    DKG_GET_SHARE       = 0x63,
    DKG_PUT_SHARE       = 0x64,
    DKG_FINALIZE        = 0x65,
    DKG_ABORT           = 0x66,
    DKG_STATUS          = 0x67,
    DKG_EXPORT_SHARE    = 0x6a, // encrypted share backup
    DKG_RESTORE_SHARE   = 0x6b, // restore from backup

    // FROST signing on top of the DKG (see handler_frost_sign.h). 0x70..0x72.
    FROST_HW_COMMIT = 0x70,
    FROST_HW_SIGN   = 0x71,
    FROST_HW_RESET  = 0x72,

#endif
} command_e;

/**
 * Enumeration with parsing state.
 */
typedef enum
{
    STATE_NONE,    /// No state
    STATE_PARSED,  /// Request data parsed, awaiting user approval
    STATE_APPROVED /// Request data approved
} state_e;

/**
 * Enumeration with user request type. Discriminates the union in
 * global_ctx_t: a display callback that finds a req_type it does not
 * own refuses to paint rather than reading another flow's bytes.
 */
typedef enum
{
    CONFIRM_SIGN,         /// confirm an EdDSA-Poseidon blind-sign request
    CONFIRM_PUBKEY_EXPORT /// confirm export of the signing pubkey (INS 0x01)
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct
{
    uint8_t raw_public_key[64]; /// twisted-Edwards signing key, x||y
    size_t  raw_public_key_len; /// actual length of raw_public_key
} pubkey_ctx_t;

/**
 * Structure for a deferred signing request.
 *
 * Populated by handler_blind_sign before user confirmation, read back by
 * handler_eddsa_poseidon_sign_stored once the user approves.
 */
typedef struct
{
    uint8_t payload[SIGN_PAYLOAD_LEN];         /// account(4 BE) || msg(32)
    uint8_t m_hash[32];                        /// the message, for display + echo
    uint8_t signature[EDDSA_POSEIDON_SIG_LEN]; /// R8x || R8y || S
    uint8_t signature_len;                     /// length of the signature
    uint8_t curveID;                           /// twisted-Edwards curve selector
} sign_ctx_t;

/**
 * Structure for global context.
 *
 * The discriminating tag is `req_type`:
 *   CONFIRM_SIGN           → read sign_info
 *   CONFIRM_PUBKEY_EXPORT  → read pk_info
 */
typedef struct
{
    state_e state; /// state of the context
    union
    {
        pubkey_ctx_t pk_info;  /// public key context
        sign_ctx_t   sign_info; /// deferred signing context
    };
    request_type_e req_type;             /// user request
    uint32_t bip32_path[MAX_BIP32_PATH]; /// BIP32 path (bip32_path[0] = account)
    uint8_t bip32_path_len;              /// length of BIP32 path
} global_ctx_t;
