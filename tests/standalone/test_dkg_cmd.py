"""VSS/DKG ceremony (INS 0x60–0x6b) — FROST=1 builds only.

A full t-of-n ceremony needs n devices, so these tests do not run one. What
they pin down is everything a single device is answerable for on its own:

  * the state machine, including every transition it must refuse. The
    barrier between round 1 and round 2 is the interesting one — the share
    AAD is id || commitmentsDigest, so a share encrypted before every
    dealer has published its commitments would be bound to nothing.
  * the wire shapes, so a host implementation has something to code against.
  * that the device's own published commitments are points on the curve.
  * that the device refuses a commitment record claiming to be its own but
    carrying someone else's transport key — the anchor that stops a
    coordinator from man-in-the-middling the share encryption.

Cross-implementation agreement (does the device's digest match the host
reference?) belongs to the libC's host tests and the JS suite, which have
the curve arithmetic to hand.
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from application_client.zknox_command_sender import (
    ZknoxCommandSender, Chunk, DkgState, Errors,
)
from application_client.zknox_response_unpacker import (
    unpack_dkg_status_response, unpack_dkg_deal_response,
)

from .utils import check_point_bytes


ACCOUNT = 0
MY_ID = 1
T = 2
N = 3
NAME = b"primitives-test"

# Synthetic commitment blocks for the two dealers this device is not.
# SET_COMMITS only hashes and orders the other dealers' points — it has no
# way to validate them, and is not supposed to: they are checked later, at
# PUT_SHARE, against the Feldman relation. These two are chosen to bracket
# any real commitment under memcmp: a genuine x-coordinate is below the
# field prime, whose top byte is 0x30.
LOW_C0 = b"\x00" * 63 + b"\x01"
HIGH_C0 = b"\xff" * 64


@pytest.fixture(autouse=True)
def clean_dkg_state(backend: BackendInterface, has_frost: bool):
    """Every test starts and ends at IDLE. The ceremony state is a device
    global that outlives an APDU, so without this a failure in one test
    would cascade into the next."""
    if not has_frost:
        yield
        return
    client = ZknoxCommandSender(backend)
    client.dkg_abort()
    yield
    client.dkg_abort()


def _deal(client: ZknoxCommandSender, t: int = T, n: int = N):
    response = client.dkg_deal(account=ACCOUNT, participant_id=MY_ID,
                               t=t, n=n, name=NAME)
    assert response.status == Errors.SW_OK
    return unpack_dkg_deal_response(response.data, t)


def _record(dealer_id: int, hk: bytes, commitments: bytes) -> bytes:
    """One dealer record: id(1) || HK_j(32) || C_j(t*64)."""
    return bytes([dealer_id]) + hk + commitments


def _commit_records(my_hk: bytes, my_commitments: list, t: int = T) -> list:
    """The n dealer records, ordered by C_{j,0} as the device requires."""
    low = LOW_C0 + b"\x11" * 64 * (t - 1)
    high = HIGH_C0 + b"\x22" * 64 * (t - 1)
    return [_record(2, b"\xaa" * 32, low),
            _record(MY_ID, my_hk, b"".join(my_commitments)),
            _record(3, b"\xbb" * 32, high)]


def _send_commit_records(client: ZknoxCommandSender, records: list):
    """Feed the records one APDU at a time.

    A record is 1 + 32 + t*64 = 161 bytes at t=2, so two of them already
    overflow an APDU — which is why the instruction is chunked at all. A
    single record still goes as LAST: FIRST only exists to reset the
    accumulator, and DEAL has already done that.
    """
    if len(records) == 1:
        return client.dkg_set_commits(records[0], chunk=Chunk.LAST)

    response = None
    for i, rec in enumerate(records):
        if i == 0:
            chunk = Chunk.FIRST
        elif i == len(records) - 1:
            chunk = Chunk.LAST
        else:
            chunk = Chunk.NEXT
        response = client.dkg_set_commits(rec, chunk=chunk)
    return response


def _reach_committed(client: ZknoxCommandSender) -> bytes:
    """Drive the device to COMMITTED and return the commitments digest."""
    _epoch, commitments = _deal(client)
    my_hk = client.dkg_get_comm_pubkey(ACCOUNT).data
    response = _send_commit_records(client, _commit_records(my_hk, commitments))
    assert response.status == Errors.SW_OK
    return response.data


# ── Comm identity ─────────────────────────────────────────────────────

def test_comm_pubkey_shape_and_determinism(backend: BackendInterface,
                                           frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    first = client.dkg_get_comm_pubkey(ACCOUNT)
    assert first.status == Errors.SW_OK
    assert len(first.data) == 32, "Ed25519 compressed point is 32 bytes"
    assert first.data == client.dkg_get_comm_pubkey(ACCOUNT).data


def test_comm_pubkey_differs_per_account(backend: BackendInterface,
                                         frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    assert (client.dkg_get_comm_pubkey(0).data
            != client.dkg_get_comm_pubkey(1).data)


def test_comm_pubkey_wrong_length_rejected(backend: BackendInterface,
                                           frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x60, data=b"\x00" * 8)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


# ── Status and abort ──────────────────────────────────────────────────

def test_status_starts_idle(backend: BackendInterface, frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    state, _id, _t, _n, mask = unpack_dkg_status_response(client.dkg_status().data)
    assert state == DkgState.IDLE
    assert mask == 0


def test_deal_advances_status(backend: BackendInterface, frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    _deal(client)
    state, participant_id, t, n, _mask = unpack_dkg_status_response(
        client.dkg_status().data)
    assert state == DkgState.DEALT
    assert (participant_id, t, n) == (MY_ID, T, N)


def test_abort_returns_to_idle(backend: BackendInterface, frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    _deal(client)
    assert client.dkg_abort().status == Errors.SW_OK
    state, participant_id, t, n, mask = unpack_dkg_status_response(
        client.dkg_status().data)
    assert (state, participant_id, t, n, mask) == (DkgState.IDLE, 0, 0, 0, 0)


# ── Round 1: DEAL ─────────────────────────────────────────────────────

def test_deal_commitments_are_on_curve(backend: BackendInterface,
                                       frost_only: None) -> None:
    """The published C_i are what every other participant will verify shares
    against. An off-curve point here poisons the whole ceremony."""
    client = ZknoxCommandSender(backend)
    _epoch, commitments = _deal(client)
    assert len(commitments) == T
    for c in commitments:
        check_point_bytes(c)


def test_deal_epoch_is_fresh(backend: BackendInterface, frost_only: None) -> None:
    """The epoch is the only randomness in DEAL — the coefficients are
    derived deterministically so a share can be recovered. Two ceremonies
    over the same (account, t, n, name) must not reuse a polynomial, and the
    epoch is what stops them."""
    client = ZknoxCommandSender(backend)
    epoch_a, commitments_a = _deal(client)
    client.dkg_abort()
    epoch_b, commitments_b = _deal(client)

    assert epoch_a != epoch_b, "epoch repeated across two ceremonies"
    assert commitments_a != commitments_b, \
        "same polynomial dealt twice — the epoch is not reaching the coefficients"


@pytest.mark.parametrize("participant_id,t,n", [
    (0, 2, 3),   # id must be >= 1
    (4, 2, 3),   # id > n
    (1, 0, 3),   # t must be >= 1
    (1, 4, 3),   # t > n
    (1, 2, 6),   # n > DKG_MAX_N (5)
    (1, 4, 4),   # t > DKG_MAX_T (3)
])
def test_deal_rejects_impossible_parameters(backend: BackendInterface,
                                            frost_only: None,
                                            participant_id: int, t: int,
                                            n: int) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_deal(account=ACCOUNT, participant_id=participant_id,
                        t=t, n=n, name=NAME)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


def test_deal_rejects_truncated_payload(backend: BackendInterface,
                                        frost_only: None) -> None:
    """The name length byte must agree with what actually follows."""
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        # claims a 32-byte name, sends 4
        client.raw(ins=0x61, data=b"\x00" * 4 + bytes([1, 2, 3, 32]) + b"abcd")
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


# ── Round 1: SET_COMMITS ──────────────────────────────────────────────

def test_set_commits_before_deal_refused(backend: BackendInterface,
                                         frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_set_commits(b"\x01" + b"\x00" * (32 + 128), chunk=Chunk.FIRST)
    assert exc_info.value.status == Errors.SW_BAD_STATE


def test_set_commits_reaches_committed(backend: BackendInterface,
                                       frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    digest = _reach_committed(client)
    assert len(digest) == 32, "commitmentsDigest is 32 bytes"

    state, _id, _t, _n, _mask = unpack_dkg_status_response(client.dkg_status().data)
    assert state == DkgState.COMMITTED


def test_set_commits_digest_is_stable(backend: BackendInterface,
                                      frost_only: None) -> None:
    """The digest is a pure function of the commitment bytes. Two runs over
    the same input must agree, or no two devices could ever agree either."""
    client = ZknoxCommandSender(backend)
    my_hk = client.dkg_get_comm_pubkey(ACCOUNT).data

    # Our own commitments are re-dealt each round and would differ, so this
    # run uses fixed stand-ins for every dealer: the digest is a function of
    # the commitment bytes alone, which is exactly the claim being tested.
    records = [_record(MY_ID, my_hk, LOW_C0 + b"\x11" * 64),
               _record(2, b"\xaa" * 32, HIGH_C0[:63] + b"\xfe" + b"\x22" * 64),
               _record(3, b"\xbb" * 32, HIGH_C0 + b"\x33" * 64)]

    digests = []
    for _ in range(2):
        client.dkg_abort()
        _deal(client)
        digests.append(_send_commit_records(client, records).data)

    assert digests[0] == digests[1]


def test_set_commits_rejects_wrong_own_transport_key(backend: BackendInterface,
                                                     frost_only: None) -> None:
    """A record for our own id must carry the transport key our seed derives.

    This is the anchor that breaks the man-in-the-middle: ECDH against an
    unauthenticated peer key means a coordinator that swaps HK_j for its own
    derives the very key we do, and reads every share addressed to j.
    Nothing downstream would notice — the group key is still computed from
    the genuine commitments. Refusing here is what makes the victim notice.
    """
    client = ZknoxCommandSender(backend)
    _epoch, commitments = _deal(client)
    forged_hk = bytes(32)  # not the key this seed derives

    with pytest.raises(ExceptionRAPDU) as exc_info:
        _send_commit_records(client, _commit_records(forged_hk, commitments))
    assert exc_info.value.status == Errors.SW_SIGNATURE_FAIL


def test_set_commits_rejects_unsorted_dealers(backend: BackendInterface,
                                              frost_only: None) -> None:
    """Dealers must arrive sorted by C_{j,0}. Sorted order is what makes the
    digest canonical — a host free to reorder could hand two devices the
    same commitments and two different digests."""
    client = ZknoxCommandSender(backend)
    _deal(client)

    # HIGH first, then LOW — strictly decreasing across two chunks.
    records = [_record(3, b"\xbb" * 32, HIGH_C0 + b"\x22" * 64),
               _record(2, b"\xaa" * 32, LOW_C0 + b"\x11" * 64)]

    with pytest.raises(ExceptionRAPDU) as exc_info:
        _send_commit_records(client, records)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


def test_set_commits_rejects_duplicate_dealer(backend: BackendInterface,
                                              frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    _deal(client)
    # Same id twice; the second C_0 is strictly greater, so the ordering
    # check passes and the duplicate check is what has to catch it.
    records = [_record(2, b"\xaa" * 32, LOW_C0 + b"\x11" * 64),
               _record(2, b"\xaa" * 32, HIGH_C0 + b"\x11" * 64)]

    with pytest.raises(ExceptionRAPDU) as exc_info:
        _send_commit_records(client, records)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


def test_set_commits_rejects_short_dealer_count(backend: BackendInterface,
                                                frost_only: None) -> None:
    """LAST with fewer than n dealers must fail: a missing dealer yields a
    digest everyone else disagrees with, and later a wrong group key."""
    client = ZknoxCommandSender(backend)
    _epoch, commitments = _deal(client)
    my_hk = client.dkg_get_comm_pubkey(ACCOUNT).data
    only_mine = _record(MY_ID, my_hk, b"".join(commitments))

    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_set_commits(only_mine, chunk=Chunk.LAST)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


def test_set_commits_rejects_misaligned_record(backend: BackendInterface,
                                               frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    _deal(client)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_set_commits(b"\x01" * 100, chunk=Chunk.LAST)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


# ── Round 2: the barrier ──────────────────────────────────────────────

def test_get_share_before_committed_refused(backend: BackendInterface,
                                            frost_only: None) -> None:
    """This is the round-1 barrier, and the reason the two rounds cannot be
    collapsed: without a frozen digest there is no AAD to bind the share to
    this ceremony."""
    client = ZknoxCommandSender(backend)
    _deal(client)  # DEALT, not COMMITTED

    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_get_share(2)
    assert exc_info.value.status == Errors.SW_BAD_STATE


def test_get_share_shape(backend: BackendInterface, frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    _reach_committed(client)

    response = client.dkg_get_share(2)
    assert response.status == Errors.SW_OK
    assert len(response.data) == 12 + 32 + 16, \
        "share blob is nonce(12) || ct(32) || tag(16)"


def test_get_share_uses_a_fresh_nonce(backend: BackendInterface,
                                      frost_only: None) -> None:
    """The ECDH key is fixed per pair, so a repeated GCM nonce would break
    authentication outright."""
    client = ZknoxCommandSender(backend)
    _reach_committed(client)

    first = client.dkg_get_share(2).data[:12]
    second = client.dkg_get_share(2).data[:12]
    assert first != second, "GCM nonce repeated across two encryptions"


@pytest.mark.parametrize("j", [0, MY_ID, N + 1, 255])
def test_get_share_rejects_bad_recipient(backend: BackendInterface,
                                         frost_only: None, j: int) -> None:
    """j must be a real dealer other than ourselves."""
    client = ZknoxCommandSender(backend)
    _reach_committed(client)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_get_share(j)
    assert exc_info.value.status == Errors.SW_WRONG_DATA_LENGTH


def test_put_share_rejects_forged_blob(backend: BackendInterface,
                                       frost_only: None) -> None:
    """A share that does not decrypt under the pair's ECDH key — or that
    decrypts but contradicts the dealer's published commitments — must be
    refused. GCM proves who sent it; Feldman proves it is consistent with
    what they committed to."""
    client = ZknoxCommandSender(backend)
    _reach_committed(client)

    blob = bytes([2]) + LOW_C0 + b"\x11" * 64 + b"\x00" * (12 + 32 + 16)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_put_share(blob)
    assert exc_info.value.status == Errors.SW_SIGNATURE_FAIL


# ── FINALIZE and the backup path ──────────────────────────────────────

def test_finalize_before_collected_refused(backend: BackendInterface,
                                           frost_only: None) -> None:
    """A missing share yields a silently wrong skShare, so FINALIZE must
    refuse rather than sum what it happens to have."""
    client = ZknoxCommandSender(backend)
    _reach_committed(client)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_finalize()
    assert exc_info.value.status == Errors.SW_BAD_STATE


def test_export_share_before_provisioned_refused(backend: BackendInterface,
                                                 frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.dkg_export_share(ACCOUNT)
    assert exc_info.value.status == Errors.SW_BAD_STATE


def test_restore_share_rejects_garbage(backend: BackendInterface,
                                       frost_only: None) -> None:
    """The GCM tag is the only gate on RESTORE: a wrong seed, a tampered
    blob or the wrong group must all leave the device untouched."""
    client = ZknoxCommandSender(backend)
    blob = b"\x00" * 4 + b"\x00" * (8 + 64 + 1 + 12 + 32 + 16)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x6B, data=blob)
    assert exc_info.value.status in (Errors.SW_WRONG_DATA_LENGTH,
                                     Errors.SW_SIGNATURE_FAIL)

    state, *_ = unpack_dkg_status_response(client.dkg_status().data)
    assert state == DkgState.IDLE, "a rejected restore must change nothing"


def test_deal_over_provisioned_state_is_guarded(backend: BackendInterface,
                                                frost_only: None) -> None:
    """Re-dealing over a provisioned signer would destroy it, so DEAL refuses
    from PROVISIONED and demands an explicit ABORT first. The device cannot
    be driven to PROVISIONED from here, so this checks the milder property
    the same code path gives us: a second DEAL from DEALT is accepted and
    starts a genuinely new ceremony rather than merging with the old one."""
    client = ZknoxCommandSender(backend)
    _epoch_a, commitments_a = _deal(client)
    _epoch_b, commitments_b = _deal(client)
    assert commitments_a != commitments_b


# ── RFU bytes ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("ins", [0x60, 0x61, 0x63, 0x64, 0x65, 0x66, 0x67,
                                 0x6A, 0x6B])
def test_dkg_rejects_nonzero_rfu(backend: BackendInterface, frost_only: None,
                                 ins: int) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=ins, p1=0x01, p2=0x00, data=b"\x00" * 4)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2


def test_set_commits_rejects_bad_chunk_marker(backend: BackendInterface,
                                              frost_only: None) -> None:
    client = ZknoxCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        client.raw(ins=0x62, p1=0x03, p2=0x00, data=b"\x00" * 4)
    assert exc_info.value.status == Errors.SW_WRONG_P1P2
