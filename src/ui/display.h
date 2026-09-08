#pragma once

#include <stdbool.h> // bool
#include "constants.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_MAIN C_app_zknox_14px
#define ICON_APP_HOME C_home_zknox_14px
#define ICON_APP_WARNING C_icon_warning
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_MAIN C_app_zknox_64px
#define ICON_APP_HOME ICON_APP_MAIN
#define ICON_APP_WARNING C_Warning_64px
#elif defined(TARGET_APEX_P)
#define ICON_APP_MAIN C_app_zknox_48px
#define ICON_APP_HOME ICON_APP_MAIN
#define ICON_APP_WARNING LARGE_WARNING_ICON
#endif

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display an EdDSA-Poseidon blind-sign request (account index + the
 * 32-byte message) and ask the user to confirm.
 *
 * The message is opaque to this app by construction — giving it meaning
 * is the job of whatever protocol sits on top — so the review goes
 * through nbgl_useCaseReviewBlindSigning, warning chrome included.
 * Reads G_context.sign_info, staged by handler_blind_sign.
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_display_blind_sign_eddsa_poseidon(void);

/**
 * Display the signing-pubkey export approval screen. Reads
 * pk_info.raw_public_key + .raw_public_key_len plus the account index
 * from bip32_path[0]. Shows the account and the hex of the pubkey so the
 * user can compare it against an out-of-band source.
 *
 * On Approve, validate_pubkey_export sends the pubkey bytes back. On
 * Reject, sends SW_DENY.
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_display_pubkey_export(void);
