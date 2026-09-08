"""APDU client for the ZKNOX-HW-PRIVACY app.

One method per instruction, plus the enums the tests assert against. The
`_async` variants return the ragger context manager, so a test can drive
the review screens while the exchange is in flight.
"""

from enum import IntEnum
from typing import Generator, Optional
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU


MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class InsType(IntEnum):
    """Instruction bytes. Debug-only INSes are marked; they answer
    SW_INS_NOT_SUPPORTED on a MODE=prod build."""

    SIGNING_PUBKEY        = 0x01
    BLIND_SIGN_NO_DISPLAY = 0x02  # DEBUG only
    GET_VERSION           = 0x03
    GET_APP_NAME          = 0x04
    BLIND_SIGN            = 0x12
    SIGN_WITH_PRIVKEY     = 0x50  # DEBUG only

    # VSS/DKG ceremony (FROST=1 builds)
    DKG_GET_COMM_PUBKEY = 0x60
    DKG_DEAL            = 0x61
    DKG_SET_COMMITS     = 0x62
    DKG_GET_SHARE       = 0x63
    DKG_PUT_SHARE       = 0x64
    DKG_FINALIZE        = 0x65
    DKG_ABORT           = 0x66
    DKG_STATUS          = 0x67
    DKG_DEBUG_COMM_PRIVKEY = 0x68  # DEBUG only
    DKG_DEBUG_SKSHARE      = 0x69  # DEBUG only
    DKG_EXPORT_SHARE       = 0x6A
    DKG_RESTORE_SHARE      = 0x6B

    # FROST signing on the DKG output (FROST=1 builds)
    FROST_HW_COMMIT = 0x70
    FROST_HW_SIGN   = 0x71
    FROST_HW_RESET  = 0x72


class Curve(IntEnum):
    """P1 of the signing instructions."""

    BABYJUBJUB_LEGACY = 0x00  # P1=0 keeps the pre-selector default
    BANDERSNATCH      = 0x01
    BABYJUBJUB        = 0x02


class Chunk(IntEnum):
    """P1 of the chunked instructions (DKG_SET_COMMITS, FROST_HW_SIGN)."""

    FIRST = 0x00
    NEXT  = 0x01
    LAST  = 0x02


class DkgState(IntEnum):
    """First byte of the DKG_STATUS response."""

    IDLE        = 0
    DEALT       = 1
    COMMITTED   = 2
    COLLECTED   = 3
    PROVISIONED = 4


class Errors(IntEnum):
    SW_OK                    = 0x9000
    SW_DENY                  = 0x6985
    SW_INCORRECT_DATA        = 0x6A80
    SW_WRONG_P1P2            = 0x6A86
    SW_WRONG_DATA_LENGTH     = 0x6A87
    SW_INS_NOT_SUPPORTED     = 0x6D00
    SW_CLA_NOT_SUPPORTED     = 0x6E00
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_ADDRESS_FAIL  = 0xB002
    SW_BAD_STATE             = 0xB007
    SW_SIGNATURE_FAIL        = 0xB008


def account_bytes(account: int) -> bytes:
    return account.to_bytes(4, "big")


class ZknoxCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    # ── App identification ───────────────────────────────────────────

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(cla=0xB0,  # BOLOS CLA
                                     ins=0x01,  # get_app_and_version
                                     p1=0, p2=0, data=b"")

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_VERSION,
                                     p1=0, p2=0, data=b"")

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_APP_NAME,
                                     p1=0, p2=0, data=b"")

    # ── Keys ─────────────────────────────────────────────────────────

    def get_signing_pubkey_silent(self, account: int = 0) -> RAPDU:
        """P1=0x00. DEBUG builds only — prod answers SW_WRONG_P1P2."""
        return self.backend.exchange(cla=CLA, ins=InsType.SIGNING_PUBKEY,
                                     p1=0x00, p2=0x00,
                                     data=account_bytes(account))

    @contextmanager
    def get_signing_pubkey_with_confirmation(
        self, account: int = 0
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=InsType.SIGNING_PUBKEY,
                                         p1=0x01, p2=0x00,
                                         data=account_bytes(account)):
            yield

    # ── Signing ──────────────────────────────────────────────────────

    @contextmanager
    def blind_sign(self, msg: bytes, account: int = 0,
                   curve: int = Curve.BABYJUBJUB) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=InsType.BLIND_SIGN,
                                         p1=curve, p2=0x00,
                                         data=account_bytes(account) + msg):
            yield

    def blind_sign_raw(self, data: bytes, curve: int = Curve.BABYJUBJUB,
                       p2: int = 0x00) -> RAPDU:
        """Synchronous BLIND_SIGN, for the input-validation paths that are
        rejected before the UI is ever invoked."""
        return self.backend.exchange(cla=CLA, ins=InsType.BLIND_SIGN,
                                     p1=curve, p2=p2, data=data)

    def blind_sign_no_display(self, msg: bytes, account: int = 0,
                              curve: int = Curve.BABYJUBJUB) -> RAPDU:
        """DEBUG builds only."""
        return self.backend.exchange(cla=CLA, ins=InsType.BLIND_SIGN_NO_DISPLAY,
                                     p1=curve, p2=0x00,
                                     data=account_bytes(account) + msg)

    def sign_with_privkey(self, privkey: bytes, msg: bytes,
                          curve: int = Curve.BABYJUBJUB) -> RAPDU:
        """DEBUG builds only."""
        return self.backend.exchange(cla=CLA, ins=InsType.SIGN_WITH_PRIVKEY,
                                     p1=0x00, p2=0x00,
                                     data=bytes([curve]) + privkey + msg)

    # ── DKG ──────────────────────────────────────────────────────────

    def dkg_get_comm_pubkey(self, account: int = 0) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_GET_COMM_PUBKEY,
                                     p1=0, p2=0, data=account_bytes(account))

    def dkg_deal(self, account: int = 0, participant_id: int = 1,
                 t: int = 2, n: int = 3, name: bytes = b"test") -> RAPDU:
        data = (account_bytes(account)
                + bytes([participant_id, t, n, len(name)])
                + name)
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_DEAL,
                                     p1=0, p2=0, data=data)

    def dkg_set_commits(self, records: bytes, chunk: int = Chunk.LAST) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_SET_COMMITS,
                                     p1=chunk, p2=0, data=records)

    def dkg_get_share(self, j: int) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_GET_SHARE,
                                     p1=0, p2=0, data=bytes([j]))

    def dkg_put_share(self, blob: bytes) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_PUT_SHARE,
                                     p1=0, p2=0, data=blob)

    def dkg_finalize(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_FINALIZE,
                                     p1=0, p2=0, data=b"")

    def dkg_abort(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_ABORT,
                                     p1=0, p2=0, data=b"")

    def dkg_status(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_STATUS,
                                     p1=0, p2=0, data=b"")

    def dkg_export_share(self, account: int = 0) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.DKG_EXPORT_SHARE,
                                     p1=0, p2=0, data=account_bytes(account))

    # ── FROST ────────────────────────────────────────────────────────

    def frost_commit(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.FROST_HW_COMMIT,
                                     p1=0, p2=0, data=b"")

    def frost_sign(self, data: bytes, chunk: int = Chunk.LAST) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.FROST_HW_SIGN,
                                     p1=chunk, p2=0, data=data)

    def frost_reset(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.FROST_HW_RESET,
                                     p1=0, p2=0, data=b"")

    # ── Raw escape hatch, for the RFU / bad-CLA checks ───────────────

    def raw(self, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"",
            cla: int = CLA) -> RAPDU:
        return self.backend.exchange(cla=cla, ins=ins, p1=p1, p2=p2, data=data)

    @property
    def last_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
