"""Dispatcher-level behaviour: class byte, unknown instructions, and the
guarantee that the debug surface really is absent from a prod build.

These are cheap tests that catch an expensive class of mistake — an
instruction reachable in a configuration where it was meant to be
compiled out.
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from application_client.zknox_command_sender import (
    ZknoxCommandSender, InsType, Errors,
)


@pytest.mark.parametrize("cla", [0x00, 0xE1, 0xB1, 0xFF])
def test_wrong_cla_rejected(backend: BackendInterface, cla: int) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=InsType.GET_VERSION, cla=cla)
    assert exc_info.value.status == Errors.SW_CLA_NOT_SUPPORTED


@pytest.mark.parametrize("ins", [0x00, 0x05, 0x11, 0x14, 0x30, 0x7F, 0xFF])
def test_unknown_ins_rejected(backend: BackendInterface, ins: int) -> None:
    """Instructions this app does not implement — including ones neighbouring
    apps in the ZKNOX namespace do — must be refused, not silently absorbed."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=ins)
    assert exc_info.value.status == Errors.SW_INS_NOT_SUPPORTED


DEBUG_ONLY_INSTRUCTIONS = [
    InsType.BLIND_SIGN_NO_DISPLAY,
    InsType.SIGN_WITH_PRIVKEY,
    InsType.DKG_DEBUG_COMM_PRIVKEY,
    InsType.DKG_DEBUG_SKSHARE,
]


@pytest.mark.parametrize("ins", DEBUG_ONLY_INSTRUCTIONS)
def test_debug_instructions_absent_in_prod(backend: BackendInterface,
                                           is_debug_build: bool,
                                           ins: int) -> None:
    """Every instruction that signs without a screen or hands out a secret
    must be gone from a production binary. This is the assertion the
    MODE=prod / ZKNOX_DEBUG guard in constants.h exists to back up."""
    if is_debug_build:
        pytest.skip("MODE=debug build — these instructions are meant to exist")

    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=ins, data=b"\x00" * 4)
    assert exc_info.value.status == Errors.SW_INS_NOT_SUPPORTED


def test_silent_pubkey_absent_in_prod(backend: BackendInterface,
                                      is_debug_build: bool) -> None:
    """A production build must not hand out the signing pubkey without the
    user seeing the request: P1=0x00 is debug-only."""
    if is_debug_build:
        pytest.skip("MODE=debug build — the silent path is meant to exist")

    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.get_signing_pubkey_silent()
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_device_alive_after_error_storm(backend: BackendInterface) -> None:
    """Burn through a batch of rejected APDUs, then confirm the device still
    answers normally. Catches a dispatcher path that leaves the transport or
    the global context wedged after an error."""
    client = ZknoxCommandSender(backend)

    for ins, p1, p2, data in [
        (0xFF, 0x00, 0x00, b""),                 # unknown INS
        (InsType.GET_VERSION, 0x01, 0x00, b""),  # RFU set
        (InsType.BLIND_SIGN, 0xFF, 0x00, b"\x00" * 36),  # bad curve
        (InsType.BLIND_SIGN, 0x02, 0x00, b"\x00" * 4),   # short data
        (InsType.SIGNING_PUBKEY, 0x01, 0x00, b"\x00" * 8),  # wrong length
    ]:
        with pytest.raises(ExceptionRAPDU):
            client.raw(ins=ins, p1=p1, p2=p2, data=data)

    assert client.get_version().status == Errors.SW_OK
