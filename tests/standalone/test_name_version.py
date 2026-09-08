"""App identification: GET_APP_NAME (0x04), GET_VERSION (0x03), and the
BOLOS-level get_app_and_version at CLA=0xB0.

The expected values are read out of the Makefile rather than hardcoded, so
a version bump does not require editing the tests.
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from application_client.zknox_command_sender import ZknoxCommandSender, Errors
from application_client.zknox_response_unpacker import (
    unpack_get_app_name_response,
    unpack_get_version_response,
    unpack_get_app_and_version_response,
)

from .utils import verify_name, verify_version, makefile_version


def test_app_name(backend: BackendInterface) -> None:
    client = ZknoxCommandSender(backend)
    response = client.get_app_name()
    assert response.status == Errors.SW_OK
    verify_name(unpack_get_app_name_response(response.data))


def test_app_name_is_protocol_neutral(backend: BackendInterface) -> None:
    """The app is a primitives library, not a protocol wallet. If the name
    ever picks up a protocol, this repo has grown something that belongs in
    a downstream app instead."""
    client = ZknoxCommandSender(backend)
    name = unpack_get_app_name_response(client.get_app_name().data).lower()
    for protocol in ("railgun", "zcash", "monero", "tornado", "aztec"):
        assert protocol not in name, \
            f"app name {name!r} names a protocol — this app is generic"


def test_version(backend: BackendInterface) -> None:
    client = ZknoxCommandSender(backend)
    response = client.get_version()
    assert response.status == Errors.SW_OK
    major, minor, patch = unpack_get_version_response(response.data)
    assert (major, minor, patch) == makefile_version()


def test_app_and_version(backend: BackendInterface) -> None:
    """The BOLOS default handler must agree with the app's own INSes."""
    client = ZknoxCommandSender(backend)
    response = client.get_app_and_version()
    assert response.status == Errors.SW_OK
    app_name, version = unpack_get_app_and_version_response(response.data)
    verify_name(app_name)
    verify_version(version)


@pytest.mark.parametrize("ins", [0x03, 0x04])
@pytest.mark.parametrize("p1,p2", [(0x01, 0x00), (0x00, 0x01), (0xFF, 0xFF)])
def test_identification_rejects_nonzero_rfu(backend: BackendInterface,
                                            ins: int, p1: int, p2: int) -> None:
    """P1/P2 are RFU for these two instructions. Accepting a non-zero value
    silently would make a future meaning for them unusable."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=ins, p1=p1, p2=p2)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2
