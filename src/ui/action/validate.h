#pragma once

#include <stdbool.h> // bool
#include "constants.h"

/**
 * Action for EdDSA-Poseidon blind-sign validation.
 *
 * On Approve, derives the key for the staged account and signs the staged
 * message, then emits len(1) || sig(96) || msg(32). On Reject, SW_DENY.
 * G_context is wiped on both paths, so STATE_APPROVED never survives the
 * callback and no signing token is left armed for a later APDU.
 *
 * @param[in] choice
 *   User choice (either approved or rejected).
 */
void validate_eddsa_poseidon_sign(bool choice);

/**
 * Action for signing-pubkey export approval. On Approve, sends the
 * G_context.pk_info.raw_public_key_len bytes of
 * G_context.pk_info.raw_public_key back to the host. On Reject, sends
 * SW_DENY. Wipes G_context on both paths.
 *
 * @param[in] choice  user choice (approved or rejected).
 */
void validate_pubkey_export(bool choice);
