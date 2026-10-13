"""Small independent Python reference, used only to build *valid* inputs for the
cross-check vectors (and, where cheap, the expected output).

It is not a port: it implements just enough BabyJubJub / Poseidon / RFC9591
hashing to produce well-formed FROST and VSS material. BLAKE-512 is missing
from hashlib, so EdDSA key derivation is not reproduced here; those vectors are
compared Rust-vs-JS only.
"""

import hashlib
import os
import shutil
import subprocess
from typing import List, Sequence, Tuple

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ORDER = 21888242871839275222246405745257275088614511777268538073601725287587578984328
L = ORDER >> 3
A = 168700
D = 168696
B8 = (
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
)
IDENTITY = (0, 1)
CONTEXT = "FROST-EDBABYJUJUB-BLAKE512-v1"

PARAMS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "crates",
    "frost-babyjubjub",
    "src",
    "params",
)

_POS_CACHE = {}


def _poseidon_params(t: int):
    if t not in _POS_CACHE:
        def load(name):
            raw = open(os.path.join(PARAMS_DIR, name), "rb").read()
            return [int.from_bytes(raw[i:i + 32], "little") for i in range(0, len(raw), 32)]
        mds = load(f"mds_t{t}.bin")
        rc = load(f"rc_t{t}.bin")
        _POS_CACHE[t] = (mds, rc, len(rc) // t)
    return _POS_CACHE[t]


def poseidon(inputs: Sequence[int], n_outs: int = 1):
    """circomlib Poseidon, state [0, *inputs]."""
    t = len(inputs) + 1
    mds, rc, rounds = _poseidon_params(t)
    rf, rp = 8, rounds - 8
    st = [0] + [x % P for x in inputs]
    for r in range(rounds):
        st = [(st[i] + rc[r * t + i]) % P for i in range(t)]
        if r < rf // 2 or r >= rf // 2 + rp:
            st = [pow(x, 5, P) for x in st]
        else:
            st[0] = pow(st[0], 5, P)
        st = [sum(mds[i * t + j] * st[j] for j in range(t)) % P for i in range(t)]
    return st[0] if n_outs == 1 else st[:n_outs]


def add(p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
    beta = p1[0] * p2[1] % P
    gamma = p1[1] * p2[0] % P
    delta = (p1[1] - A * p1[0]) * (p2[0] + p2[1]) % P
    tau = beta * gamma % P
    dtau = D * tau % P
    x3 = (beta + gamma) * pow(1 + dtau, -1, P) % P
    y3 = (delta + A * beta - gamma) * pow(1 - dtau, -1, P) % P
    return (x3, y3)


def mul(base: Tuple[int, int], e: int) -> Tuple[int, int]:
    res = IDENTITY
    exp = base
    while e:
        if e & 1:
            res = add(res, exp)
        exp = add(exp, exp)
        e >>= 1
    return res


def base_mult(k: int) -> Tuple[int, int]:
    return mul(B8, k % L)


def ser_scalar(s: int) -> bytes:
    assert 0 <= s < L
    out = bytearray(s.to_bytes(32, "little"))
    out[31] &= 0x1F
    return bytes(out)


def to_bytes(x: int) -> bytes:
    return x.to_bytes(32, "little")


def ser_element(pt: Tuple[int, int]) -> bytes:
    assert pt != IDENTITY
    packed = pt[1] | ((pt[0] & 1) << 255)
    return packed.to_bytes(32, "little")


_BLAKE_PROC = None


def blake512(data: bytes) -> bytes:
    """BLAKE-512 through a persistent node oracle.

    hashlib has no BLAKE-1, and the GitLab hasher uses BLAKE-512, so the
    generator borrows @noble/hashes rather than carrying its own copy.
    """
    global _BLAKE_PROC
    if _BLAKE_PROC is None:
        curves_dir = os.environ.get("CURVES_DIR")
        if curves_dir is None:
            raise RuntimeError("CURVES_DIR must point at the curves package")
        # node resolves bare imports from the script's own directory, so the
        # oracle has to sit inside the curves package
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blake512_pipe.mjs")
        dst = os.path.join(curves_dir, ".blake512_pipe.mjs")
        shutil.copyfile(src, dst)
        _BLAKE_PROC = subprocess.Popen(
            ["node", dst], cwd=curves_dir,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
    _BLAKE_PROC.stdin.write(data.hex() + "\n")
    _BLAKE_PROC.stdin.flush()
    return bytes.fromhex(_BLAKE_PROC.stdout.readline().strip())


def tagged(tag: str, data: bytes) -> bytes:
    return blake512(CONTEXT.encode() + tag.encode() + data)


def derive_hashed(tag: str, data: bytes) -> int:
    return int.from_bytes(tagged(tag, data), "little") % L


def h1(m: bytes) -> int:
    return derive_hashed("rho", m)


def h2(r8, a, msg_hash: int) -> int:
    return poseidon([r8[0], r8[1], a[0], a[1], msg_hash]) % L


def h4(m: bytes) -> int:
    return derive_hashed("msg", m)


def h5(m: bytes) -> int:
    return derive_hashed("com", m)


def h7(m: bytes) -> int:
    return derive_hashed("view", m)


def lambda_coeff(ids: Sequence[int], x_i: int) -> int:
    num, dom = 1, 1
    for x_j in ids:
        if x_j == x_i:
            continue
        num = num * (x_j % L) % L
        dom = dom * ((x_j - x_i) % L) % L
    return num * pow(dom, -1, L) % L


def encode_commitment_list(clist) -> bytes:
    out = b""
    for c in clist:
        out += ser_scalar(c["identifier"])
        out += ser_element(c["hiding"])
        out += ser_element(c["binding"])
    return out


def binding_factors(pk, clist, msg: bytes):
    prefix = ser_element(pk) + to_bytes(h4(msg)) + to_bytes(h5(encode_commitment_list(clist)))
    return [(c["identifier"], h1(prefix + ser_scalar(c["identifier"]))) for c in clist]


def group_commitment(clist, bfs):
    gc = IDENTITY
    factors = dict(bfs)
    for c in clist:
        gc = add(add(gc, c["hiding"]), mul(c["binding"], factors[c["identifier"]] % L))
    return gc


def sig_share(identifier, sk_i, pk, nonces, msg_scalar, clist) -> int:
    msg = to_bytes(msg_scalar)
    bfs = binding_factors(pk, clist, msg)
    rho = dict(bfs)[identifier]
    gc = group_commitment(clist, bfs)
    lam = lambda_coeff([c["identifier"] for c in clist], identifier)
    ch = h2(gc, pk, msg_scalar)
    return (nonces[0] + nonces[1] * rho + lam * sk_i * ch) % L


def sort_key(pt) -> str:
    return f"{pt[0]:064x}:{pt[1]:064x}"


def commitments_digest(all_commitments: List[List[Tuple[int, int]]]) -> int:
    dealers = [d for d in all_commitments if d]
    dealers = sorted(dealers, key=lambda d: sort_key(d[0]))
    out = b""
    for dealer in dealers:
        for cj in dealer:
            out += ser_element(cj)
    return h5(out)


def poly_eval(x: int, coeffs: Sequence[int]) -> int:
    value = 0
    for c in reversed(coeffs):
        value = value * x + c
    return value % L
