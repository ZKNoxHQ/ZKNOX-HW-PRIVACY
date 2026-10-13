#!/usr/bin/env python3
"""Generates the cross-check vectors: 32 random inputs per function.

Randomness comes from `secrets` (the OS CSPRNG), never from a model or a
seeded PRNG. Functions that consume randomness internally get a 32-byte `seed`
instead; both runners install the same deterministic DRBG for that case, so
their outputs stay comparable.

Usage: python3 gen_vectors.py <out.json> [cases-per-op]
"""

import json
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import reference as R

N = 32


def rs() -> int:
    """Random scalar in [0, L)."""
    return secrets.randbelow(R.L)


def rb(n: int) -> str:
    return secrets.token_bytes(n).hex()


def rp():
    return R.base_mult(rs())


def pt(p):
    return {"x": str(p[0]), "y": str(p[1])}


def onein(n: int) -> bool:
    return secrets.randbelow(n) == 0


def rand_ids(k: int):
    """k strictly increasing positive ids."""
    ids = []
    cur = 0
    for _ in range(k):
        cur += 1 + secrets.randbelow(3)
        ids.append(cur)
    return ids


def commitment_list(k: int):
    ids = rand_ids(k)
    return [{"identifier": i, "hiding": rp(), "binding": rp()} for i in ids]


def enc_clist(clist):
    return [
        {
            "identifier": str(c["identifier"]),
            "hidingNonceCommitment": pt(c["hiding"]),
            "bindingNonceCommitment": pt(c["binding"]),
        }
        for c in clist
    ]


def dealer_set(n_dealers: int, degree: int):
    """n dealers, each with `degree` commitments of the same length."""
    return [[rp() for _ in range(degree)] for _ in range(n_dealers)]


# --------------------------------------------------------------- generators

def gen_leBufferToBigInt(_):
    return {"bytes": rb(secrets.randbelow(64) + 1)}


def gen_leBigIntToBuffer(_):
    size = 1 + secrets.randbelow(48)
    if onein(6):
        return {"value": str((1 << (8 * size)) + secrets.randbelow(1 << 16)), "size": size}
    return {"value": str(secrets.randbelow(1 << (8 * size))), "size": size}


def gen_bigIntToBuffer(_):
    return {"value": str(secrets.randbelow(1 << (8 * (1 + secrets.randbelow(40)))))}


def gen_bytesToBigInt(_):
    return {"bytes": rb(secrets.randbelow(48) + 1)}


def _rand_signed():
    v = secrets.randbelow(1 << 300)
    return -v if onein(2) else v


def gen_modOrder(_):
    return {"x": str(_rand_signed())}


gen_modCurveOrder = gen_modOrder


def gen_invModOrder(_):
    if onein(8):
        return {"a": "0"}
    return {"a": str(rs())}


def gen_toBytes(_):
    if onein(8):
        return {"a": str((1 << 256) + secrets.randbelow(1 << 32))}
    return {"a": str(secrets.randbelow(1 << 256))}


def gen_fromBytes(_):
    return {"bytes": rb(32)}


def gen_serializeScalar(_):
    if onein(6):
        return {"s": str(R.L + secrets.randbelow(1 << 32))}
    return {"s": str(rs())}


def gen_deserializeScalar(_):
    r = secrets.randbelow(6)
    if r == 0:
        return {"bytes": rb(31)}
    if r == 1:
        return {"bytes": rb(32)}
    b = bytearray(rs().to_bytes(32, "little"))
    if r == 2:
        b[31] |= 0x80
    return {"bytes": bytes(b).hex()}


def gen_pruneBuffer(_):
    return {"bytes": rb(secrets.choice([16, 32, 64]))}


def gen_prvToSubScalar(_):
    return {"bytes": rb(32)}


def gen_blake512(_):
    return {"bytes": rb(secrets.randbelow(128) + 1)}


def gen_serializeElement(_):
    if onein(10):
        return {"point": pt(R.IDENTITY)}
    return {"point": pt(rp())}


def gen_deserializeElement(_):
    r = secrets.randbelow(5)
    if r == 0:
        return {"bytes": rb(32)}
    if r == 1:
        return {"bytes": rb(31)}
    enc = bytearray(R.ser_element(rp()))
    if r == 2:
        enc[secrets.randbelow(32)] ^= 1 << secrets.randbelow(8)
    return {"bytes": bytes(enc).hex()}


def gen_scalarBaseMult(_):
    return {"k": str(_rand_signed() if onein(4) else rs())}


def gen_scalarMult(_):
    return {"point": pt(rp()), "k": str(_rand_signed() if onein(4) else rs())}


def gen_pointsEqual(_):
    p = rp()
    return {"a": pt(p), "b": pt(p if onein(3) else rp())}


def gen_inCurve(_):
    if onein(3):
        return {"point": {"x": str(secrets.randbelow(R.P)), "y": str(secrets.randbelow(R.P))}}
    return {"point": pt(rp())}


def gen_addPoint(_):
    return {"a": pt(rp()), "b": pt(rp())}


def gen_mulPointEscalar(_):
    # never negative: the JS double-and-add loops forever on negative scalars
    return {"point": pt(rp()), "k": str(rs())}


def gen_toMontgomery(_):
    if onein(10):
        return {"point": pt(R.IDENTITY)}
    return {"point": pt(rp())}


def gen_packPoint(_):
    return {"point": pt(rp())}


def gen_unpackPoint(_):
    p = rp()
    packed = p[1] | ((1 << 255) if p[0] > R.P // 2 else 0)
    b = bytearray(packed.to_bytes(32, "big"))
    if onein(5):
        b[secrets.randbelow(32)] ^= 1 << secrets.randbelow(8)
    return {"bytes": bytes(b).hex()}


def gen_randomScalar(_):
    return {"seed": rb(32), "rejection": not onein(3)}


def gen_wideBytes(_):
    return {"seed": rb(32)}


def gen_prv2pub(_):
    return {"prv": rb(32)}


def gen_signPoseidon(_):
    # 31-byte messages stay below the field prime
    return {"prv": rb(32), "msg": rb(31)}


def gen_verifyPoseidon(_):
    # build a valid signature algebraically: S*B8 == R8 + 8*hm*A
    k = rs()
    a = R.base_mult(k)
    r = rs()
    r8 = R.base_mult(r)
    msg_i = secrets.randbelow(1 << 240)
    msg = msg_i.to_bytes(31, "big")
    hm = R.poseidon([r8[0], r8[1], a[0], a[1], int.from_bytes(msg, "big")])
    s = (r + 8 * hm * k) % R.L
    if onein(4):
        s = (s + 1) % R.L
    return {"msg": msg.hex(), "sig": {"R8": pt(r8), "S": str(s)}, "A": pt(a)}


def gen_hash(_):
    return {"bytes": rb(secrets.randbelow(96) + 1)}


def gen_taggedHash(_):
    return {"tag": secrets.choice(["rho", "nonce", "msg", "com", "coeff", "view", "zknox"]),
            "bytes": rb(secrets.randbelow(96) + 1)}


gen_deriveHashed = gen_taggedHash


def gen_H1(_):
    return {"bytes": rb(secrets.randbelow(96) + 1)}


gen_H3 = gen_H4 = gen_H5 = gen_H6 = gen_H7 = gen_H1


def gen_H2(_):
    return {"R8": pt(rp()), "A": pt(rp()), "msgHash": str(secrets.randbelow(R.P))}


def gen_poseidon(_):
    n = 1 + secrets.randbelow(5)
    n_outs = 1 if not onein(4) else 2
    return {"inputs": [str(secrets.randbelow(R.P)) for _ in range(n)], "nOuts": n_outs}


def gen_generateNonce(_):
    return {"seed": rb(32), "secret": str(rs())}


def gen_deriveInterpolatingValue(_):
    ids = rand_ids(2 + secrets.randbelow(4))
    xi = secrets.choice(ids) if not onein(6) else max(ids) + 7
    return {"L": [str(i) for i in ids], "xi": str(xi)}


def gen_encodeGroupCommitmentList(_):
    return {"list": enc_clist(commitment_list(1 + secrets.randbelow(4)))}


gen_participantsFromCommitmentList = gen_encodeGroupCommitmentList


def gen_bindingFactorForParticipant(_):
    ids = rand_ids(1 + secrets.randbelow(4))
    bfl = [{"identifier": str(i), "bindingFactor": str(rs())} for i in ids]
    target = secrets.choice(ids) if not onein(5) else max(ids) + 9
    return {"bfList": bfl, "id": str(target)}


def gen_computeBindingFactors(_):
    return {"pk": pt(rp()), "list": enc_clist(commitment_list(1 + secrets.randbelow(4))),
            "msg": rb(32)}


def gen_computeGroupCommitment(_):
    clist = commitment_list(1 + secrets.randbelow(4))
    bfl = [{"identifier": str(c["identifier"]), "bindingFactor": str(rs())} for c in clist]
    return {"list": enc_clist(clist), "bfList": bfl}


def gen_computeChallenge(_):
    return {"R8": pt(rp()), "pk": pt(rp()), "msg": str(secrets.randbelow(R.P))}


def gen_commit(_):
    return {"seed": rb(32), "sk": str(rs()), "id": str(1 + secrets.randbelow(12))}


def _frost_setup():
    """A consistent signing set: shares, nonces, commitments, group key."""
    k = 2 + secrets.randbelow(3)
    ids = rand_ids(k)
    sks = {i: rs() for i in ids}
    nonces = {i: (rs(), rs()) for i in ids}
    clist = [
        {
            "identifier": i,
            "hiding": R.base_mult(nonces[i][0]),
            "binding": R.base_mult(nonces[i][1]),
        }
        for i in ids
    ]
    pk = rp()
    msg = secrets.randbelow(R.P)
    return ids, sks, nonces, clist, pk, msg


def gen_frostSign(_):
    ids, sks, nonces, clist, pk, msg = _frost_setup()
    i = secrets.choice(ids)
    return {
        "id": str(i),
        "sk": str(sks[i]),
        "pk": pt(pk),
        "nonce": {"hidingNonce": str(nonces[i][0]), "bindingNonce": str(nonces[i][1])},
        "msg": str(msg),
        "list": enc_clist(clist),
    }


def gen_aggregate(_):
    ids, _sks, _n, clist, pk, msg = _frost_setup()
    return {
        "list": enc_clist(clist),
        "msg": str(msg),
        "pk": pt(pk),
        "shares": [str(rs()) for _ in ids],
    }


def gen_verifySignatureShare(_):
    ids, sks, nonces, clist, pk, msg = _frost_setup()
    i = secrets.choice(ids)
    share = R.sig_share(i, sks[i], pk, nonces[i], msg, clist)
    if onein(4):
        share = (share + 1) % R.L
    ci = next(c for c in clist if c["identifier"] == i)
    return {
        "id": str(i),
        "sk": str(sks[i]),
        "commitment": enc_clist([ci])[0],
        "sigShare": str(share),
        "list": enc_clist(clist),
        "pk": pt(pk),
        "msg": str(msg),
    }


def gen_polynomialEvaluate(_):
    return {"x": str(1 + secrets.randbelow(50)),
            "coefficients": [str(rs()) for _ in range(1 + secrets.randbelow(5))]}


def gen_secretShareShard(_):
    return {"s": str(rs()),
            "coefficients": [str(rs()) for _ in range(secrets.randbelow(4))],
            "max": 1 + secrets.randbelow(6)}


def gen_trustedDealerKeygen(_):
    mn = 2 + secrets.randbelow(3)
    return {"seed": rb(32), "sk": str(rs()), "max": mn + secrets.randbelow(3), "min": mn}


def gen_vssCommit(_):
    return {"coefficients": [str(rs()) for _ in range(1 + secrets.randbelow(5))]}


def gen_vssVerify(_):
    coeffs = [rs() for _ in range(2 + secrets.randbelow(3))]
    i = 1 + secrets.randbelow(6)
    sk = R.poly_eval(i, coeffs)
    if onein(4):
        sk = (sk + 1) % R.L
    return {"i": str(i), "sk": str(sk),
            "vssCommitment": [pt(R.base_mult(c)) for c in coeffs],
            "min": len(coeffs)}


def gen_deriveGroupInfo(_):
    mn = 2 + secrets.randbelow(3)
    coeffs = [rs() for _ in range(mn)]
    return {"max": mn + secrets.randbelow(3), "min": mn,
            "vssCommitment": [pt(R.base_mult(c)) for c in coeffs]}


def gen_computeSharesForIds(_):
    ids = rand_ids(1 + secrets.randbelow(5))
    if onein(6):
        ids = list(reversed(ids))
    return {"coefficients": [str(rs()) for _ in range(1 + secrets.randbelow(4))], "ids": ids}


def gen_combineGroupPubkeyFromCommitments(_):
    return {"all": [[pt(p) for p in d] for d in dealer_set(1 + secrets.randbelow(4),
                                                           1 + secrets.randbelow(3))]}


gen_verifyAllCommitmentsSubgroup = gen_combineGroupPubkeyFromCommitments


def gen_verifyFeldmanShare(_):
    coeffs = [rs() for _ in range(2 + secrets.randbelow(3))]
    i = 1 + secrets.randbelow(6)
    sk = R.poly_eval(i, coeffs)
    if onein(4):
        sk = (sk + 1) % R.L
    return {"id": i, "sk": str(sk), "commitments": [pt(R.base_mult(c)) for c in coeffs]}


def gen_dkgDeriveInterpolatingValue(_):
    g = gen_deriveInterpolatingValue(_)
    return {"ids": g["L"], "xi": g["xi"]}


def gen_reconstructConstantFromShares(_):
    t = 2 + secrets.randbelow(3)
    coeffs = [rs() for _ in range(t)]
    ids = rand_ids(t)
    return {"subset": [{"id": i, "s_i": str(R.poly_eval(i, coeffs))} for i in ids]}


def gen_deriveViewKeyFromPK(_):
    return {"all": [[pt(p) for p in d] for d in dealer_set(1 + secrets.randbelow(4),
                                                           1 + secrets.randbelow(3))]}


def gen_finalizeParticipant(_):
    n = 1 + secrets.randbelow(4)
    degree = 1 + secrets.randbelow(3)
    all_c = dealer_set(n, degree)
    dealer_ids = rand_ids(n)
    return {
        "id": 1 + secrets.randbelow(6),
        "byDealer": [{"dealerId": d, "s_ki": str(rs())} for d in dealer_ids],
        "all": [[pt(p) for p in d] for d in all_c],
    }


def gen_commitmentsDigest(_):
    return gen_deriveViewKeyFromPK(_)


def _shares_keys(n):
    ids = rand_ids(n)
    shares = {str(i): str(rs()) for i in ids}
    keys = {str(i): rb(32) for i in ids}
    return ids, shares, keys


def gen_encryptShares(_):
    n = 1 + secrets.randbelow(4)
    ids, shares, keys = _shares_keys(n)
    if onein(8):
        keys[str(ids[0])] = rb(16)
    all_c = dealer_set(1 + secrets.randbelow(3), 1 + secrets.randbelow(3))
    return {"seed": rb(32), "shares": shares, "keys": keys,
            "all": [[pt(p) for p in d] for d in all_c]}


def gen_decryptShare(_):
    all_c = dealer_set(1 + secrets.randbelow(3), 1 + secrets.randbelow(3))
    digest = R.commitments_digest(all_c)
    pid = 1 + secrets.randbelow(6)
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    share = rs()
    aad = R.ser_scalar(pid) + R.to_bytes(digest)
    ct = AESGCM(key).encrypt(nonce, R.to_bytes(share), aad)
    if onein(6):
        ct = bytearray(ct)
        ct[secrets.randbelow(len(ct))] ^= 1
        ct = bytes(ct)
    return {"enc": {"nonce": nonce.hex(), "ciphertext": ct.hex()}, "key": key.hex(),
            "id": pid, "all": [[pt(p) for p in d] for d in all_c]}


# --- minimal msgpack writer, to build decode() inputs independently ---

def mp_str(x: str) -> bytes:
    b = x.encode()
    if len(b) < 32:
        return bytes([0xA0 | len(b)]) + b
    if len(b) < 256:
        return b"\xd9" + bytes([len(b)]) + b
    return b"\xda" + len(b).to_bytes(2, "big") + b


def mp_uint(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    if n < 256:
        return b"\xcc" + bytes([n])
    if n < 65536:
        return b"\xcd" + n.to_bytes(2, "big")
    return b"\xce" + n.to_bytes(4, "big")


def mp_map(pairs) -> bytes:
    return bytes([0x80 | len(pairs)]) + b"".join(mp_str(k) + v for k, v in pairs)


def pack_point_hex(p) -> str:
    """spub field: hex of the packed point read back little-endian."""
    packed = p[1] | ((1 << 255) if p[0] > R.P // 2 else 0)
    be = packed.to_bytes(32, "big")
    return bytes(reversed(be)).hex()


def shareable_payload(multisig: bool, corrupt: bool = False) -> str:
    p = rp()
    pairs = [
        ("vpriv", mp_str(secrets.token_bytes(32).hex())),
        ("spub", mp_str(pack_point_hex(p))),
    ]
    if multisig:
        pairs += [
            ("sid", mp_str(f"sess-{secrets.randbelow(1 << 32)}")),
            ("sk", mp_str(secrets.token_bytes(32).hex())),
            ("pid", mp_uint(1 + secrets.randbelow(20))),
        ]
    if corrupt:
        r = secrets.randbelow(4)
        if r == 0:
            pairs[0] = ("vpriv", mp_uint(7))
        elif r == 1 and multisig:
            pairs[4] = ("pid", mp_str("3"))
        elif r == 2:
            pairs = pairs[1:]
        else:
            return secrets.token_bytes(1 + secrets.randbelow(12)).hex()
    return mp_map(pairs).hex()


def gen_getShareableViewingKey(_):
    return {"point": pt(rp()), "vpriv": rb(32) if not onein(8) else rb(16)}


def gen_getShareableMultisigKey(_):
    return {
        "point": pt(rp()),
        "vpriv": rb(32),
        "sid": "" if onein(8) else f"sess-{secrets.randbelow(1 << 32)}",
        "sk": ("0x" if onein(2) else "") + rb(32),
        "pid": 1 + secrets.randbelow(20) if not onein(8) else 0,
    }


def gen_decodeShareableKey(_):
    return {"hex": shareable_payload(onein(2), corrupt=onein(4))}


def gen_decodeMultisigKey(_):
    return {"hex": shareable_payload(not onein(5), corrupt=onein(5))}


def gen_poseidonBytes(_):
    n = 1 + secrets.randbelow(4)
    return {"inputs": [secrets.randbelow(R.P).to_bytes(32, "little").hex() for _ in range(n)]}


def gen_poseidonHex(_):
    n = 1 + secrets.randbelow(4)
    inputs = []
    for _ in range(n):
        v = secrets.randbelow(R.P)
        inputs.append(hex(v) if onein(2) else str(v))
    if onein(8):
        inputs.append("not-a-number")
    return {"inputs": inputs, "outputHex": onein(2)}


def gen_getPublicSpendingKey(_):
    return {"prv": rb(32) if not onein(8) else rb(31)}


def gen_getPublicViewingKey(_):
    return {"prv": rb(32) if not onein(8) else rb(31)}


def gen_signEDDSA(_):
    return {"prv": rb(32), "message": str(secrets.randbelow(1 << 240))}


def gen_verifyEDDSA(j):
    k = rs()
    a = R.base_mult(k)
    r = rs()
    r8 = R.base_mult(r)
    msg = secrets.randbelow(1 << 240)
    hm = R.poseidon([r8[0], r8[1], a[0], a[1], msg])
    s_val = (r + 8 * hm * k) % R.L
    if onein(4):
        s_val = (s_val + 1) % R.L
    return {"message": str(msg), "sig": {"R8": pt(r8), "S": str(s_val)}, "pubkey": pt(a)}


SCHEMES = ["x25519", "railgun-engine-ed25519-sha256"]


def gen_kaPublicKey(_):
    return {"scheme": secrets.choice(SCHEMES), "sk": rb(32)}


def gen_kaSharedSecret(j):
    # half the cases use a real peer public key of the same scheme, half a
    # random 32-byte string (a valid u-coordinate for x25519, almost never a
    # valid point for ed25519)
    scheme = SCHEMES[j % 2]
    if onein(3):
        return {"scheme": scheme, "sk": rb(32), "theirPub": rb(32)}
    peer = secrets.token_bytes(32)
    if scheme == "x25519":
        pub = X25519PrivateKey.from_private_bytes(peer).public_key().public_bytes_raw()
    else:
        pub = Ed25519PrivateKey.from_private_bytes(peer).public_key().public_bytes_raw()
    return {"scheme": scheme, "sk": rb(32), "theirPub": pub.hex()}


def gen_assertSortedConsecutiveIds(_):
    ids = rand_ids(1 + secrets.randbelow(5))
    r = secrets.randbelow(6)
    if r == 0:
        ids = list(reversed(ids))
    elif r == 1:
        ids = ids + [ids[-1]]
    elif r == 2:
        ids = [0] + ids
    return {"ids": ids}


OPS = [name[4:] for name in sorted(globals()) if name.startswith("gen_")]


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "vectors.json"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else N
    cases = []
    cid = 0
    for op in OPS:
        fn = globals()[f"gen_{op}"]
        for j in range(n):
            cases.append({"id": cid, "op": op, "in": fn(j)})
            cid += 1
    with open(out_path, "w") as f:
        json.dump({"ops": OPS, "casesPerOp": n, "cases": cases}, f)
    print(f"{len(OPS)} ops x {n} cases = {len(cases)} vectors -> {out_path}")


if __name__ == "__main__":
    main()
