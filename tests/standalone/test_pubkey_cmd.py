"""SIGNING_PUBKEY (INS 0x01) — twisted-Edwards signing pubkey export.

Covers the approve and reject paths of the confirmation screen, the
input-validation paths, and the two properties a caller actually relies on:
the returned bytes are a point on the curve, and the same account always
yields the same key.

Snapshot comparison is off (`do_comparison=False`): the tests still walk
every UI page, so a handler that crashes mid-review still fails, but they
do not check pixel-exact golden images. To enable it, drop the argument and
run once with `--golden_run`.
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.zknox_command_sender import ZknoxCommandSender, Errors

from .utils import check_point_bytes


def test_signing_pubkey_approve(backend: BackendInterface,
                                scenario_navigator: NavigateWithScenario) -> None:
    """User approves → 64-byte point, on the curve."""
    client = ZknoxCommandSender(backend)

    with client.get_signing_pubkey_with_confirmation(account=0):
        scenario_navigator.address_review_approve(do_comparison=False)

    response = backend.last_async_response
    assert response.status == Errors.SW_OK
    assert len(response.data) == 64, \
        f"expected x||y = 64 bytes, got {len(response.data)}"
    check_point_bytes(response.data)


def test_signing_pubkey_reject(backend: BackendInterface,
                               scenario_navigator: NavigateWithScenario) -> None:
    """User rejects → SW_DENY and no key material in the body."""
    client = ZknoxCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.get_signing_pubkey_with_confirmation(account=0):
            scenario_navigator.address_review_reject(do_comparison=False)

    assert exc_info.value.status == Errors.SW_DENY
    assert exc_info.value.data == b"", "no body on reject"


def test_signing_pubkey_is_deterministic(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """The same account must always derive the same key — the path is
    firmware-fixed and the seed does not change between calls."""
    client = ZknoxCommandSender(backend)

    keys = []
    for _ in range(2):
        with client.get_signing_pubkey_with_confirmation(account=0):
            scenario_navigator.address_review_approve(do_comparison=False)
        keys.append(backend.last_async_response.data)

    assert keys[0] == keys[1], "same account derived two different keys"


def test_signing_pubkey_accounts_differ(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """Distinct account indices must derive distinct keys. If they did not,
    the account field would be decorative and every account would share one
    identity."""
    client = ZknoxCommandSender(backend)

    keys = []
    for account in (0, 1):
        with client.get_signing_pubkey_with_confirmation(account=account):
            scenario_navigator.address_review_approve(do_comparison=False)
        keys.append(backend.last_async_response.data)

    assert keys[0] != keys[1], "accounts 0 and 1 derived the same key"


@pytest.mark.parametrize("data_len", [0, 3, 5, 8, 32])
def test_signing_pubkey_wrong_length_rejected(backend: BackendInterface,
                                              data_len: int) -> None:
    """The handler wants exactly account(4). Anything else is refused before
    the UI is invoked, so this stays a synchronous exchange."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x01, p1=0x01, p2=0x00, data=b"\x00" * data_len)
    assert exc_info.value.status in (Errors.SW_WRONG_DATA_LENGTH,
                                     Errors.SW_INCORRECT_DATA)


@pytest.mark.parametrize("p1", [0x02, 0x10, 0xFF])
def test_signing_pubkey_wrong_p1_rejected(backend: BackendInterface,
                                          p1: int) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x01, p1=p1, p2=0x00, data=b"\x00" * 4)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_signing_pubkey_wrong_p2_rejected(backend: BackendInterface) -> None:
    """P2 is RFU for this instruction."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x01, p1=0x01, p2=0x01, data=b"\x00" * 4)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_signing_pubkey_silent_matches_confirmed(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario,
    debug_only: None,
) -> None:
    """DEBUG builds only. The silent path must return exactly what the
    reviewed path returns — otherwise the key the user approved on screen
    is not the key the tests exercise everywhere else."""
    client = ZknoxCommandSender(backend)

    silent = client.get_signing_pubkey_silent(account=0)
    assert silent.status == Errors.SW_OK

    with client.get_signing_pubkey_with_confirmation(account=0):
        scenario_navigator.address_review_approve(do_comparison=False)

    assert silent.data == backend.last_async_response.data
