"""FROST signing on the DKG output (INS 0x70–0x72) — FROST=1 builds only.

Producing a real partial signature needs a provisioned share, which needs a
completed ceremony, which needs n devices. So what is testable from one
device is the guard rail — and the guard rail is the security property:

  * COMMIT is refused unless a DKG has actually provisioned a share, so the
    device cannot be talked into publishing nonces for a key it does not
    hold.
  * SIGN is refused unless COMMIT drew nonces first.
  * The nonces are single-use. Signing twice with the same (d_i, e_i) is
    two equations in two unknowns and hands over skShare_i outright, so a
    second SIGN without a fresh COMMIT must fail — and it does, because
    SIGN burns the nonces before it returns.

The partial-signature arithmetic itself is covered by the libC host tests
(tests/test_frost_host.c, test_rfc9591frost.c) and the JS reference suite.
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from application_client.zknox_command_sender import (
    ZknoxCommandSender, Chunk, Errors,
)


# msg(32) || [ id(32) D.x(32) D.y(32) E.x(32) E.y(32) ] — one signer record.
FS_REC = 160
DUMMY_SIGN_PAYLOAD = b"\x00" * (32 + FS_REC)


@pytest.fixture(autouse=True)
def clean_state(backend: BackendInterface, has_frost: bool):
    """Both the ceremony state and the FROST nonces are device globals that
    outlive an APDU."""
    if not has_frost:
        yield
        return
    client = ZknoxCommandSender(backend)
    client.frost_reset()
    client.dkg_abort()
    yield
    client.frost_reset()
    client.dkg_abort()


def test_commit_without_provisioned_share_refused(backend: BackendInterface,
                                                  frost_only: None) -> None:
    """No DKG output means no key to sign with. Publishing nonces anyway
    would be leaking commitments for a share the device does not have."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.frost_commit()
    assert exc_info.value.status == Errors.SW_BAD_STATE


def test_sign_without_commit_refused(backend: BackendInterface,
                                     frost_only: None) -> None:
    """SIGN consumes nonces COMMIT drew. Without them there is nothing to
    consume, and the state machine says so before it reads the payload."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.frost_sign(DUMMY_SIGN_PAYLOAD, chunk=Chunk.LAST)
    assert exc_info.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("chunk", [Chunk.FIRST, Chunk.NEXT, Chunk.LAST])
def test_sign_refused_from_idle_for_every_chunk(backend: BackendInterface,
                                                frost_only: None,
                                                chunk: int) -> None:
    """The state check comes before the chunk accumulation, so no chunk —
    not even a FIRST that only buffers — is accepted from IDLE. Otherwise a
    host could stage a payload and wait for a future COMMIT to pick it up."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.frost_sign(b"\x00" * 64, chunk=chunk)
    assert exc_info.value.status == Errors.SW_BAD_STATE


def test_sign_rejects_bad_chunk_marker(backend: BackendInterface,
                                       frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x71, p1=0x03, p2=0x00, data=b"\x00" * 32)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_sign_rejects_nonzero_p2(backend: BackendInterface,
                                 frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x71, p1=0x00, p2=0x01, data=b"\x00" * 32)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_reset_is_idempotent(backend: BackendInterface, frost_only: None) -> None:
    """RESET drops the nonces. Calling it from IDLE is a no-op, not an
    error — a host recovering from a failed round should not have to know
    which state it was in."""
    client = ZknoxCommandSender(backend)
    assert client.frost_reset().status == Errors.SW_OK
    assert client.frost_reset().status == Errors.SW_OK


@pytest.mark.parametrize("ins", [0x70, 0x72])
def test_frost_rejects_nonzero_rfu(backend: BackendInterface, frost_only: None,
                                   ins: int) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=ins, p1=0x01, p2=0x00)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_commit_rejects_payload(backend: BackendInterface,
                                frost_only: None) -> None:
    """COMMIT takes no data. Accepting some would invite a host to think it
    was influencing the nonces, which are drawn on-device by design."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x70, data=b"\x00" * 8)
    assert exc_info.value.status in (Errors.SW_WRONG_DATA_LENGTH,
                                     Errors.SW_BAD_STATE)


def test_abort_clears_frost_nonces(backend: BackendInterface,
                                   frost_only: None) -> None:
    """DKG_ABORT wipes the FROST nonces too: (d_i, e_i) belong to the share
    being wiped, and there is no state where the device holds nonces without
    a share to use them with."""
    client = ZknoxCommandSender(backend)
    assert client.dkg_abort().status == Errors.SW_OK
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.frost_sign(DUMMY_SIGN_PAYLOAD, chunk=Chunk.LAST)
    assert exc_info.value.status == Errors.SW_BAD_STATE
