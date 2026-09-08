"""Response unpackers, one per instruction that returns structured data."""

from typing import Tuple


# Unpack from response:
# response = app_name (var)
def unpack_get_app_name_response(response: bytes) -> str:
    return response.decode("ascii")


# Unpack from response:
# response = MAJOR (1) || MINOR (1) || PATCH (1)
def unpack_get_version_response(response: bytes) -> Tuple[int, int, int]:
    assert len(response) == 3, f"expected 3 bytes, got {len(response)}"
    return (response[0], response[1], response[2])


# Unpack from response:
# response = format_id (1) || len(1) app_name || len(1) version || len(1) unused
def unpack_get_app_and_version_response(response: bytes) -> Tuple[str, str]:
    offset = 1
    name_len = response[offset]
    offset += 1
    name = response[offset:offset + name_len].decode("ascii")
    offset += name_len
    version_len = response[offset]
    offset += 1
    version = response[offset:offset + version_len].decode("ascii")
    return name, version


# Unpack from response:
# response = sig_len (1) || R8x||R8y||S (96) || msg (32)
def unpack_blind_sign_response(response: bytes) -> Tuple[bytes, bytes]:
    assert len(response) == 1 + 96 + 32, \
        f"expected 129 bytes (1+96+32), got {len(response)}"
    assert response[0] == 96, f"sig_len byte should be 96, got {response[0]}"
    return response[1:97], response[97:129]


# Unpack from response:
# response = x (32 BE) || y (32 BE)
def unpack_point(response: bytes) -> Tuple[int, int]:
    assert len(response) == 64, f"expected a 64-byte point, got {len(response)}"
    return (int.from_bytes(response[0:32], "big"),
            int.from_bytes(response[32:64], "big"))


# Unpack from response:
# response = state (1) || id (1) || t (1) || n (1) || recv_bitmap (2 BE)
def unpack_dkg_status_response(response: bytes) -> Tuple[int, int, int, int, int]:
    assert len(response) == 6, f"expected 6 bytes, got {len(response)}"
    return (response[0], response[1], response[2], response[3],
            int.from_bytes(response[4:6], "big"))


# Unpack from response:
# response = epoch (16) || C_0..C_{t-1} (t * 64)
def unpack_dkg_deal_response(response: bytes, t: int) -> Tuple[bytes, list]:
    assert len(response) == 16 + t * 64, \
        f"expected {16 + t * 64} bytes for t={t}, got {len(response)}"
    epoch = response[:16]
    commitments = [response[16 + k * 64: 16 + (k + 1) * 64] for k in range(t)]
    return epoch, commitments
