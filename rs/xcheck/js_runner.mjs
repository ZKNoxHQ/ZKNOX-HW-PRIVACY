// Cross-check runner, JavaScript side.
//
// Runs from inside the @railgun-reloaded/curves package root (run.sh copies it
// there so that bare imports resolve) and evaluates the same cases as the Rust
// binary `xcheck`.
//
// Usage: node js_runner.mjs <vectors.json> <results.json>

import { readFileSync, writeFileSync } from 'node:fs'
import { blake2b } from '@noble/hashes/blake2.js'
import { sha512 } from '@noble/hashes/sha2.js'
import * as ed25519 from '@noble/ed25519'
import { addPoint, inCurve, mulPointEscalar } from '@zk-kit/baby-jubjub'

import { RailJubCurvePoint } from './src/curve.js'
import { eddsaBuild } from './src/eddsa/babyposeidon.js'
import { RFC9591Hasher } from './src/hashing.js'
import { BabyFROST } from './src/frost/babyfrost.js'
import { TrustedDKG } from './src/frost/trusted-dkg.js'
import { poseidonFn } from './src/poseidon/poseidon-lite-wrapper.js'
import { keyAgreementFromScheme } from './src/manager/key-agreement.js'
import {
  decodeMultisigKey, decodeShareableKey, getPublicSpendingKey, getPublicViewingKey,
  getShareableMultisigKey, getShareableViewingKey, poseidon as poseidonBytesFn,
  poseidonHex, signEDDSA, verifyEDDSA,
} from './src/module-index.js'
import { bigIntToBuffer, leBigIntToBuffer, leBufferToBigInt } from './src/bytes.js'
import { bigIntToBytes, bytesToBigInt } from '@railgun-reloaded/bytes'

// ---------------------------------------------------------------- DRBG

// Byte-identical to frost_babyjubjub::rng::Drbg: each request of n bytes emits
// ceil(n/64) blocks blake2b512(seed || u64le(counter++)) and keeps the first n.
const makeDrbg = (seed) => {
  let counter = 0n
  return (out) => {
    let done = 0
    while (done < out.length) {
      const ctr = new Uint8Array(8)
      let c = counter
      for (let i = 0; i < 8; i++) { ctr[i] = Number(c & 0xffn); c >>= 8n }
      counter += 1n
      const block = blake2b(new Uint8Array([...seed, ...ctr]), { dkLen: 64 })
      const take = Math.min(64, out.length - done)
      out.set(block.subarray(0, take), done)
      done += take
    }
    return out
  }
}

const realGetRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto)
const installDrbg = (seedHex) => { globalThis.crypto.getRandomValues = makeDrbg(hexToBytes(seedHex)) }
const restoreRandom = () => { globalThis.crypto.getRandomValues = realGetRandomValues }

// ---------------------------------------------------------------- codecs

const hexToBytes = (h) => {
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}
const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const P = (v) => [BigInt(v.x), BigInt(v.y)]
const Ps = (v) => v.map(P)
const PP = (v) => v.map(Ps)
const Bs = (v) => v.map(BigInt)
const C = (v) => ({
  identifier: BigInt(v.identifier),
  hidingNonceCommitment: P(v.hidingNonceCommitment),
  bindingNonceCommitment: P(v.bindingNonceCommitment),
})
const Cs = (v) => v.map(C)
const BF = (v) => v.map((b) => ({ identifier: BigInt(b.identifier), bindingFactor: BigInt(b.bindingFactor) }))

const ePoint = (p) => ({ x: p[0].toString(), y: p[1].toString() })
const ePoints = (ps) => ps.map(ePoint)
const eBig = (b) => b.toString()
const eBytes = (b) => bytesToHex(b)
const eCommitment = (c) => ({
  identifier: c.identifier.toString(),
  hidingNonceCommitment: ePoint(c.hidingNonceCommitment),
  bindingNonceCommitment: ePoint(c.bindingNonceCommitment),
})

// ---------------------------------------------------------------- context

// @noble/ed25519 v3 needs its hash wired by the caller; getPublicViewingKey
// throws otherwise. The curves package leaves this to the application.
if (ed25519.hashes !== undefined) ed25519.hashes.sha512 = sha512
else if (ed25519.etc !== undefined) ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m))

const curve = new RailJubCurvePoint()
const frost = new BabyFROST()
const dkg = new TrustedDKG()
const hasher = new RFC9591Hasher('FROST-EDBABYJUJUB-BLAKE512-v1', curve.order)

const ops = {
  // bytes
  leBufferToBigInt: (i) => eBig(leBufferToBigInt(hexToBytes(i.bytes))),
  leBigIntToBuffer: (i) => eBytes(leBigIntToBuffer(BigInt(i.value), i.size)),
  bigIntToBuffer: (i) => eBytes(bigIntToBuffer(BigInt(i.value))),
  bytesToBigInt: (i) => eBig(bytesToBigInt(hexToBytes(i.bytes))),

  // curve scalars
  modOrder: (i) => eBig(curve.modOrder(BigInt(i.x))),
  modCurveOrder: (i) => eBig(curve.modCurveOrder(BigInt(i.x))),
  invModOrder: (i) => eBig(curve.invModOrder(BigInt(i.a))),
  toBytes: (i) => eBytes(curve.toBytes(BigInt(i.a))),
  fromBytes: (i) => eBig(curve.fromBytes(hexToBytes(i.bytes))),
  serializeScalar: (i) => eBytes(curve.SerializeScalar(BigInt(i.s))),
  deserializeScalar: (i) => eBig(curve.DeserializeScalar(hexToBytes(i.bytes))),
  pruneBuffer: (i) => eBytes(curve.pruneBuffer(hexToBytes(i.bytes))),
  prvToSubScalar: (i) => eBig(curve.prvToSubScalar(hexToBytes(i.bytes))),
  blake512: (i) => eBytes(curve.blake512(hexToBytes(i.bytes))),

  // curve points
  serializeElement: (i) => eBytes(curve.SerializeElement(P(i.point))),
  deserializeElement: (i) => ePoint(curve.DeserializeElement(hexToBytes(i.bytes))),
  scalarBaseMult: (i) => ePoint(curve.ScalarBaseMult(BigInt(i.k))),
  scalarMult: (i) => ePoint(curve.ScalarMult(P(i.point), BigInt(i.k))),
  pointsEqual: (i) => curve.pointsEqual(P(i.a), P(i.b)),
  inCurve: (i) => inCurve(P(i.point)),
  addPoint: (i) => ePoint(addPoint(P(i.a), P(i.b))),
  mulPointEscalar: (i) => ePoint(mulPointEscalar(P(i.point), BigInt(i.k))),
  toMontgomery: (i) => {
    const p = P(i.point)
    const { u, v } = curve.toMontgomery({ x: p[0], y: p[1] })
    return { u: u.toString(), v: v.toString() }
  },
  packPoint: (i) => eBytes(eddsaBuild.packPoint(P(i.point))),
  unpackPoint: (i) => {
    const p = eddsaBuild.unpackPoint(hexToBytes(i.bytes))
    return p === null ? null : ePoint(p)
  },

  // randomness-driven
  randomScalar: (i) => eBig(curve.RandomScalar(i.rejection)),
  wideBytes: () => eBig(curve.wideBytes()),

  // eddsa
  prv2pub: (i) => ePoint(eddsaBuild.prv2pub(hexToBytes(i.prv))),
  signPoseidon: (i) => {
    const s = eddsaBuild.signPoseidon(hexToBytes(i.prv), hexToBytes(i.msg))
    return { R8: ePoint(s.R8), S: s.S.toString() }
  },
  verifyPoseidon: (i) =>
    eddsaBuild.verifyPoseidon(hexToBytes(i.msg), { R8: P(i.sig.R8), S: BigInt(i.sig.S) }, P(i.A)),

  // hashing
  hash: (i) => eBytes(hasher.Hash(hexToBytes(i.bytes))),
  taggedHash: (i) => eBytes(hasher.taggedHash(i.tag, hexToBytes(i.bytes))),
  deriveHashed: (i) => eBig(hasher.deriveHashed(i.tag, hexToBytes(i.bytes))),
  H1: (i) => eBig(hasher.H1(hexToBytes(i.bytes))),
  H3: (i) => eBig(hasher.H3(hexToBytes(i.bytes))),
  H4: (i) => eBig(hasher.H4(hexToBytes(i.bytes))),
  H5: (i) => eBig(hasher.H5(hexToBytes(i.bytes))),
  H6: (i) => eBig(hasher.H6(hexToBytes(i.bytes))),
  H7: (i) => eBig(hasher.H7(hexToBytes(i.bytes))),
  H2: (i) => eBig(hasher.H2(P(i.R8), P(i.A), BigInt(i.msgHash))),

  // poseidon
  poseidon: (i) => {
    const out = poseidonFn(Bs(i.inputs), true, i.nOuts ?? 1)
    return (i.nOuts ?? 1) === 1 ? eBig(out) : out.map(eBig)
  },

  // frost
  generateNonce: (i) => eBig(frost.generateNonce(BigInt(i.secret))),
  deriveInterpolatingValue: (i) => eBig(frost.deriveInterpolatingValue(Bs(i.L), BigInt(i.xi))),
  encodeGroupCommitmentList: (i) => eBytes(frost.encodeGroupCommitmentList(Cs(i.list))),
  participantsFromCommitmentList: (i) => frost.participantsFromCommitmentList(Cs(i.list)).map(eBig),
  bindingFactorForParticipant: (i) => eBig(frost.bindingFactorForParticipant(BF(i.bfList), BigInt(i.id))),
  computeBindingFactors: (i) =>
    frost.computeBindingFactors(P(i.pk), Cs(i.list), hexToBytes(i.msg)).map((b) => ({
      identifier: b.identifier.toString(),
      bindingFactor: b.bindingFactor.toString(),
    })),
  computeGroupCommitment: (i) => ePoint(frost.computeGroupCommitment(Cs(i.list), BF(i.bfList))),
  computeChallenge: (i) => eBig(frost.computeChallenge(P(i.R8), P(i.pk), BigInt(i.msg))),
  commit: (i) => {
    const b = frost.commit(BigInt(i.sk), BigInt(i.id))
    return {
      nonces: {
        hidingNonce: b.nonces.hidingNonce.toString(),
        bindingNonce: b.nonces.bindingNonce.toString(),
      },
      commitments: eCommitment(b.commitments),
    }
  },
  frostSign: (i) =>
    eBig(frost.sign(
      BigInt(i.id),
      BigInt(i.sk),
      P(i.pk),
      { hidingNonce: BigInt(i.nonce.hidingNonce), bindingNonce: BigInt(i.nonce.bindingNonce) },
      BigInt(i.msg),
      Cs(i.list)
    )),
  aggregate: (i) => {
    const s = frost.aggregate(Cs(i.list), BigInt(i.msg), P(i.pk), Bs(i.shares))
    return { R8: ePoint(s.R8), S: s.S.toString() }
  },
  verifySignatureShare: (i) =>
    frost.verifySignatureShare(
      BigInt(i.id),
      BigInt(i.sk),
      C(i.commitment),
      BigInt(i.sigShare),
      Cs(i.list),
      P(i.pk),
      BigInt(i.msg)
    ),

  // dkg
  polynomialEvaluate: (i) => eBig(dkg.polynomialEvaluate(BigInt(i.x), Bs(i.coefficients))),
  secretShareShard: (i) => {
    const r = dkg.secretShareShard(BigInt(i.s), Bs(i.coefficients), i.max)
    return {
      secretKeyShares: r.secretKeyShares.map((s) => ({ x_i: s.x_i, y_i: s.y_i.toString() })),
      coefficients: r.coefficients.map(eBig),
    }
  },
  trustedDealerKeygen: (i) => {
    const r = dkg.trustedDealerKeygen(BigInt(i.sk), i.max, i.min)
    return {
      participantPrivateKeys: r.participantPrivateKeys.map((s) => ({ x_i: s.x_i, y_i: s.y_i.toString() })),
      coefficients: r.coefficients.map(eBig),
      base: ePoint(r.base),
      vssCommitment: ePoints(r.vssCommitment),
    }
  },
  vssCommit: (i) => ePoints(dkg.vssCommit(Bs(i.coefficients))),
  vssVerify: (i) => dkg.vssVerify({ i: BigInt(i.i), sk_i: BigInt(i.sk) }, Ps(i.vssCommitment), i.min),
  deriveGroupInfo: (i) => {
    const g = dkg.deriveGroupInfo(i.max, i.min, Ps(i.vssCommitment))
    return {
      PK: ePoint(g.PK),
      participantPublicKeys: ePoints(g.participantPublicKeys),
      viewingPrivateKey: eBytes(g.viewingPrivateKey),
    }
  },
  computeSharesForIds: (i) => {
    const m = dkg.computeSharesForIds(Bs(i.coefficients), i.ids)
    const out = {}
    for (const k of Object.keys(m).map(Number).sort((a, b) => a - b)) out[k] = m[k].toString()
    return out
  },
  combineGroupPubkeyFromCommitments: (i) => ePoint(dkg.combineGroupPubkeyFromCommitments(PP(i.all))),
  verifyAllCommitmentsSubgroup: (i) => dkg.verifyAllCommitmentsSubgroup(PP(i.all)),
  verifyFeldmanShare: (i) => dkg.verifyFeldmanShare(i.id, BigInt(i.sk), Ps(i.commitments)),
  dkgDeriveInterpolatingValue: (i) => eBig(dkg.deriveInterpolatingValue(Bs(i.ids), BigInt(i.xi))),
  reconstructConstantFromShares: (i) =>
    eBig(dkg.reconstructConstantFromShares(i.subset.map((s) => ({ id: s.id, s_i: BigInt(s.s_i) })))),
  deriveViewKeyFromPK: (i) => eBytes(dkg.deriveViewKeyFromPK(PP(i.all))),
  finalizeParticipant: (i) => {
    const f = dkg.finalizeParticipant(
      i.id,
      i.byDealer.map((d) => ({ dealerId: d.dealerId, s_ki: BigInt(d.s_ki) })),
      PP(i.all)
    )
    return {
      share: {
        id: f.share.id,
        skShare: f.share.skShare.toString(),
        skShareDiv8: f.share.skShareDiv8.toString(),
      },
      PKGroup: ePoint(f.PKGroup),
      viewingPrivateKey: eBytes(f.viewingPrivateKey),
    }
  },
  commitmentsDigest: (i) => eBig(dkg.commitmentsDigest(PP(i.all))),
  encryptShares: (i) => {
    const shares = {}
    for (const k of Object.keys(i.shares).map(Number).sort((a, b) => a - b)) shares[k] = BigInt(i.shares[k])
    const keys = {}
    for (const k of Object.keys(i.keys)) keys[Number(k)] = hexToBytes(i.keys[k])
    const enc = dkg.encryptSharesAESGCMWithAAD(shares, keys, PP(i.all))
    const out = {}
    for (const k of Object.keys(enc).map(Number).sort((a, b) => a - b)) {
      out[k] = { nonce: eBytes(enc[k].nonce), ciphertext: eBytes(enc[k].ciphertext) }
    }
    return out
  },
  decryptShare: (i) =>
    eBig(dkg.decryptShareAESGCMWithAAD(
      { nonce: hexToBytes(i.enc.nonce), ciphertext: hexToBytes(i.enc.ciphertext) },
      hexToBytes(i.key),
      i.id,
      PP(i.all)
    )),
  // shareable keys (module-index.ts)
  getShareableViewingKey: (i) => getShareableViewingKey(P(i.point), hexToBytes(i.vpriv)),
  getShareableMultisigKey: (i) =>
    getShareableMultisigKey(P(i.point), hexToBytes(i.vpriv), i.sid, i.sk, i.pid),
  decodeShareableKey: (i) => decodeShareableKey(i.hex),
  decodeMultisigKey: (i) => {
    const d = decodeMultisigKey(i.hex)
    return { vpriv: bytesToHex(d.vpriv), spub: ePoint(d.spub), sid: d.sid, sk: d.sk, pid: d.pid }
  },
  poseidonBytes: (i) => eBytes(poseidonBytesFn(i.inputs.map(hexToBytes))),
  poseidonHex: (i) => {
    const out = poseidonHex(i.inputs, i.outputHex === true)
    return i.outputHex === true ? out : out.toString()
  },
  getPublicSpendingKey: (i) => ePoint(getPublicSpendingKey(hexToBytes(i.prv))),
  getPublicViewingKey: async (i) => eBytes(await getPublicViewingKey(hexToBytes(i.prv))),
  signEDDSA: (i) => {
    const s = signEDDSA(hexToBytes(i.prv), BigInt(i.message))
    return { R8: ePoint(s.R8), S: s.S.toString() }
  },
  verifyEDDSA: (i) =>
    verifyEDDSA(BigInt(i.message), { R8: P(i.sig.R8), S: BigInt(i.sig.S) }, P(i.pubkey)),

  // key agreement
  kaPublicKey: (i) => eBytes(keyAgreementFromScheme(i.scheme).getPublicKey(hexToBytes(i.sk))),
  kaSharedSecret: (i) =>
    eBytes(keyAgreementFromScheme(i.scheme).getSharedSecret(hexToBytes(i.sk), hexToBytes(i.theirPub))),

  assertSortedConsecutiveIds: (i) => {
    TrustedDKG.assertSortedConsecutiveIds(i.ids)
    return null
  },
}

// ---------------------------------------------------------------- main

const vectors = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const results = []
for (const c of vectors.cases) {
  const fn = ops[c.op]
  if (fn === undefined) {
    results.push({ id: c.id, op: c.op, ok: false, err: `unknown op ${c.op}` })
    continue
  }
  if (c.in.seed !== undefined) installDrbg(c.in.seed)
  try {
    results.push({ id: c.id, op: c.op, ok: true, out: await fn(c.in) })
  } catch (e) {
    results.push({ id: c.id, op: c.op, ok: false, err: String(e?.message ?? e) })
  }
  if (c.in.seed !== undefined) restoreRandom()
}
writeFileSync(process.argv[3], JSON.stringify(results))
// keep the unused import referenced so linters do not drop it
void bigIntToBytes
