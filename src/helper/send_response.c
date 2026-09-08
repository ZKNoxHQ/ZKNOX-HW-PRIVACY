/*****************************************************************************
 *   ZKNOX
 *   (c) 2025 ZKNOX SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stddef.h> // size_t
#include <stdint.h> // uint*_t
#include <string.h> // memmove

#include "buffer.h"

#include "send_response.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"

int helper_send_response_sig()
{
    // LEN_SIG | SIG | MSG
    uint8_t resp[1 + EDDSA_POSEIDON_SIG_LEN + 32] = {0};
    size_t offset = 0;

    if (G_context.sign_info.signature_len != EDDSA_POSEIDON_SIG_LEN)
    {
        return io_send_sw(SW_WRONG_RESPONSE_LENGTH);
    }

    resp[offset++] = G_context.sign_info.signature_len;
    memmove(resp + offset, G_context.sign_info.signature, EDDSA_POSEIDON_SIG_LEN);
    offset += EDDSA_POSEIDON_SIG_LEN;
    memmove(resp + offset, G_context.sign_info.m_hash, 32);
    offset += 32;

    return io_send_response_pointer(resp, offset, SW_OK);
}
