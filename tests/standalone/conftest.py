
###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of
# ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and
# accepted values

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from application_client.zknox_command_sender import InsType, Errors


def _ins_present(backend: BackendInterface, ins: int, p1: int = 0, p2: int = 0,
                 data: bytes = b"") -> bool:
    """True unless the app answers SW_INS_NOT_SUPPORTED.

    Any other status word — including a rejection of these particular
    arguments — still proves the instruction is compiled in, which is the
    only thing being asked.
    """
    try:
        backend.exchange(cla=0xE0, ins=ins, p1=p1, p2=p2, data=data)
        return True
    except ExceptionRAPDU as exc:
        return exc.status != Errors.SW_INS_NOT_SUPPORTED


@pytest.fixture
def is_debug_build(backend: BackendInterface) -> bool:
    """Whether the app under test was built with MODE=debug.

    Probed rather than configured: the test suite has no view of the make
    flags the binary was produced with, and a suite that assumed the wrong
    one would report a missing instruction as a failure.
    """
    return _ins_present(backend, InsType.SIGN_WITH_PRIVKEY)


@pytest.fixture
def has_frost(backend: BackendInterface) -> bool:
    """Whether the app under test was built with FROST=1."""
    return _ins_present(backend, InsType.DKG_STATUS)


@pytest.fixture
def debug_only(is_debug_build: bool) -> None:
    if not is_debug_build:
        pytest.skip("requires a MODE=debug build")


@pytest.fixture
def frost_only(has_frost: bool) -> None:
    if not has_frost:
        pytest.skip("requires a FROST=1 build")
