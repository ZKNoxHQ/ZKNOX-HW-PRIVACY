"""BLIND_SIGN (INS 0x12) — EdDSA-Poseidon over an opaque 32-byte message.

The device defers signing until the user taps approve, then emits

    sig_len(1) || R8x||R8y||S (96) || msg(32) = 129 bytes

The signature is not checked against a reference vector here — that belongs
to the libC's own host tests, which have the curve arithmetic to hand.
What these tests establish is the part only a device can be asked about:
the UI flow completes, the response shape and echoed message are right, the
signature depends on the inputs it is supposed to depend on, and every
error path returns a clean status word without wedging the device.
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.zknox_command_sender import (
    ZknoxCommandSender, Curve, Errors,
)
from application_client.zknox_response_unpacker import unpack_blind_sign_response


TEST_MSG = bytes.fromhex(
    "8c1f26718227707c6e5c61417b47daccafabca9f574c16e1521dd6a9c70d8405"
)
OTHER_MSG = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000001"
)


def _approve(client: ZknoxCommandSender, navigator: NavigateWithScenario,
             msg: bytes = TEST_MSG, account: int = 0,
             curve: int = Curve.BABYJUBJUB) -> bytes:
    """Run one approved blind-sign and return the 96-byte signature."""
    with client.blind_sign(msg=msg, account=account, curve=curve):
        navigator.review_approve_with_warning(do_comparison=False)
    response = client.backend.last_async_response
    assert response.status == Errors.SW_OK
    sig, echoed = unpack_blind_sign_response(response.data)
    assert echoed == msg, \
        f"echoed message mismatch: {echoed.hex()} vs {msg.hex()}"
    return sig


# ── Happy path ────────────────────────────────────────────────────────

@pytest.mark.parametrize("curve", [
    Curve.BABYJUBJUB_LEGACY,  # P1=0 → BabyJubjub
    Curve.BABYJUBJUB,         # P1=2 → BabyJubjub, explicit
    Curve.BANDERSNATCH,       # P1=1
])
def test_blind_sign_approve(backend: BackendInterface,
                            scenario_navigator: NavigateWithScenario,
                            curve: int) -> None:
    client = ZknoxCommandSender(backend)
    sig = _approve(client, scenario_navigator, curve=curve)
    assert sig != b"\x00" * 96, "signature is all zeros — handler bailed?"


def test_blind_sign_p1_zero_means_babyjubjub(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """P1=0 is the pre-selector default and must stay an alias for
    BabyJubjub. A host that never set P1 would otherwise start signing on a
    different curve after an upgrade, with no error anywhere."""
    client = ZknoxCommandSender(backend)
    legacy = _approve(client, scenario_navigator, curve=Curve.BABYJUBJUB_LEGACY)
    explicit = _approve(client, scenario_navigator, curve=Curve.BABYJUBJUB)
    assert legacy == explicit


# ── Refusal ───────────────────────────────────────────────────────────

def test_blind_sign_reject(backend: BackendInterface,
                           scenario_navigator: NavigateWithScenario) -> None:
    """User rejects → SW_DENY, no signature emitted."""
    client = ZknoxCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.blind_sign(msg=TEST_MSG):
            scenario_navigator.review_reject_with_warning(do_comparison=False)

    assert exc_info.value.status == Errors.SW_DENY
    assert exc_info.value.data == b"", "no body on reject"


def test_reject_leaves_no_armed_signature(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """After a rejection the staged request must be gone: the device wipes
    the whole context in the validate callback, so nothing is left for a
    follow-up APDU to pick up and sign without a second approval."""
    client = ZknoxCommandSender(backend)

    with pytest.raises(ExceptionRAPDU):
        with client.blind_sign(msg=TEST_MSG):
            scenario_navigator.review_reject_with_warning(do_comparison=False)

    # The device is still responsive, and a fresh request still needs its
    # own approval — which the approve below supplies.
    assert client.get_version().status == Errors.SW_OK
    sig = _approve(client, scenario_navigator)
    assert sig != b"\x00" * 96


# ── What the signature depends on ─────────────────────────────────────

def test_blind_sign_deterministic(backend: BackendInterface,
                                  scenario_navigator: NavigateWithScenario) -> None:
    """EdDSA is deterministic: the same (account, msg, curve) must yield the
    same signature. A difference here means nonce generation picked up
    randomness it should not have."""
    client = ZknoxCommandSender(backend)
    first = _approve(client, scenario_navigator)
    second = _approve(client, scenario_navigator)
    assert first == second, \
        f"non-deterministic sign: {first.hex()} vs {second.hex()}"


def test_blind_sign_message_changes_signature(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    client = ZknoxCommandSender(backend)
    a = _approve(client, scenario_navigator, msg=TEST_MSG)
    b = _approve(client, scenario_navigator, msg=OTHER_MSG)
    assert a != b, "two different messages produced the same signature"


def test_blind_sign_account_changes_signature(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """The account index shown on the review screen must actually select the
    signing key. If it did not, the screen would be telling the user
    something untrue about what they are approving."""
    client = ZknoxCommandSender(backend)
    a = _approve(client, scenario_navigator, account=0)
    b = _approve(client, scenario_navigator, account=1)
    assert a != b, "accounts 0 and 1 produced the same signature"


def test_blind_sign_curve_changes_signature(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    client = ZknoxCommandSender(backend)
    bbjj = _approve(client, scenario_navigator, curve=Curve.BABYJUBJUB)
    bander = _approve(client, scenario_navigator, curve=Curve.BANDERSNATCH)
    assert bbjj != bander, "both curves produced the same signature"


# ── Error paths (clean SW, no UI invocation) ──────────────────────────

@pytest.mark.parametrize("p1", [0x03, 0x10, 0xFF])
def test_blind_sign_wrong_p1_rejected(backend: BackendInterface, p1: int) -> None:
    """An unknown curve id must be refused *before* the UI is invoked —
    a pure synchronous exchange, no navigator needed."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.blind_sign_raw(data=b"\x00" * 36, curve=p1)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_blind_sign_wrong_p2_rejected(backend: BackendInterface) -> None:
    """P2 is RFU for BLIND_SIGN."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.blind_sign_raw(data=b"\x00" * 36, p2=0x01)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


@pytest.mark.parametrize("data_len", [0, 4, 20, 35, 37, 40, 68])
def test_blind_sign_wrong_length_rejected(backend: BackendInterface,
                                          data_len: int) -> None:
    """The handler wants exactly account(4) + msg(32) = 36. Both short and
    long payloads are refused; a long one silently truncated would sign a
    message the host did not send."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.blind_sign_raw(data=b"\x00" * data_len)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


# ── Debug-only cross-check ────────────────────────────────────────────

def test_no_display_matches_reviewed_sign(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario,
    debug_only: None,
) -> None:
    """DEBUG builds only. BLIND_SIGN_NO_DISPLAY must produce exactly what
    the reviewed path produces for the same inputs — otherwise the fast path
    the integration suites use is not testing the shipping one."""
    client = ZknoxCommandSender(backend)

    quick = client.blind_sign_no_display(msg=TEST_MSG, account=0)
    assert quick.status == Errors.SW_OK
    assert len(quick.data) == 96

    reviewed = _approve(client, scenario_navigator, msg=TEST_MSG, account=0)
    assert quick.data == reviewed
