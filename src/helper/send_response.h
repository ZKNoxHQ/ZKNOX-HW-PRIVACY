#pragma once

#include "os.h"
#include "macros.h"

/**
 * Helper to send the APDU response for an approved EdDSA-Poseidon signature.
 *
 * response = G_context.sign_info.signature_len (1) ||
 *            G_context.sign_info.signature (96) ||
 *            G_context.sign_info.m_hash (32)
 *
 * The message is echoed back so a host that batches requests can match a
 * response to the request it approved, without trusting APDU ordering.
 *
 * @return zero or positive integer if success, -1 otherwise.
 */
int helper_send_response_sig(void);
