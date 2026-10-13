// End-to-end ceremony harness, JavaScript side. Mirrors `ceremony.rs`.
// Runs from inside the curves package root (run.sh copies it there).
//
//   node ceremony_js.mjs run <runs> <transcript.json>
//   node ceremony_js.mjs verify <transcript.json>

import { readFileSync, writeFileSync } from 'node:fs'
import { randomBytes } from '@noble/hashes/utils.js'

import { RailJubCurvePoint } from './src/curve.js'
import { eddsaBuild } from './src/eddsa/babyposeidon.js'
import { BabyFROST } from './src/frost/babyfrost.js'
import { TrustedDKG } from './src/frost/trusted-dkg.js'
import { bigIntToBuffer } from './src/bytes.js'
import { DKGManager } from './src/manager/dkg.js'
import { FROSTSigningManager } from './src/manager/signing.js'

const curve = new RailJubCurvePoint()
const frost = new BabyFROST()
const dkg = new TrustedDKG()

const hexToBytes = (h) => {
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}
const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const eP = (p) => ({ x: p[0].toString(), y: p[1].toString() })
const dP = (v) => [BigInt(v.x), BigInt(v.y)]
const eq = (a, b) => a[0] === b[0] && a[1] === b[1]
const randBelow = (n) => {
  const b = randomBytes(4)
  return ((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0) % n
}

// ------------------------------------------------------------------ run

const run = (runs) => {
  const out = []
  for (let iter = 0; iter < runs; iter++) {
    const n = 3 + randBelow(3)
    const t = 2 + randBelow(n - 1)
    const ids = Array.from({ length: n }, (_, i) => i + 1)

    const coefficients = {}
    const allCommitments = []
    for (const d of ids) {
      const coeffs = Array.from({ length: t }, () => curve.RandomScalar())
      coefficients[d] = coeffs
      allCommitments.push(dkg.vssCommit(coeffs))
    }

    const keys = {}
    for (const d of ids) {
      keys[d] = {}
      for (const r of ids) keys[d][r] = randomBytes(32)
    }

    const bundles = {}
    for (const d of ids) {
      const shares = dkg.computeSharesForIds(coefficients[d], ids)
      bundles[d] = dkg.encryptSharesAESGCMWithAAD(shares, keys[d], allCommitments)
    }

    const finalized = []
    const skShares = {}
    const div8 = {}
    for (const r of ids) {
      const byDealer = []
      for (const d of ids) {
        const s = dkg.decryptShareAESGCMWithAAD(bundles[d][r], keys[d][r], r, allCommitments)
        if (!dkg.verifyFeldmanShare(r, s, allCommitments[d - 1])) throw new Error('feldman failed')
        byDealer.push({ dealerId: d, s_ki: s })
      }
      const f = dkg.finalizeParticipant(r, byDealer, allCommitments)
      skShares[r] = f.share.skShare
      div8[r] = f.share.skShareDiv8
      finalized.push({
        id: f.share.id,
        skShare: f.share.skShare.toString(),
        skShareDiv8: f.share.skShareDiv8.toString(),
        PKGroup: eP(f.PKGroup),
        viewingPrivateKey: bytesToHex(f.viewingPrivateKey),
      })
    }
    const pkGroup = dkg.combineGroupPubkeyFromCommitments(allCommitments)

    const pool = [...ids]
    const signers = []
    for (let k = 0; k < t; k++) signers.push(pool.splice(randBelow(pool.length), 1)[0])
    signers.sort((a, b) => a - b)

    const msg = curve.RandomScalar()
    const nonces = {}
    const commitmentList = []
    for (const s of signers) {
      const b = frost.commit(skShares[s], BigInt(s))
      nonces[s] = b.nonces
      commitmentList.push(b.commitments)
    }

    const sigShares = []
    for (const s of signers) {
      const share = frost.sign(BigInt(s), skShares[s], pkGroup, nonces[s], msg, commitmentList)
      const ci = commitmentList.find((c) => c.identifier === BigInt(s))
      if (!frost.verifySignatureShare(BigInt(s), skShares[s], ci, share, commitmentList, pkGroup, msg)) {
        throw new Error('share verification failed')
      }
      sigShares.push(share)
    }
    const sig = frost.aggregate(commitmentList, msg, pkGroup, sigShares)
    if (!eddsaBuild.verifyPoseidon(bigIntToBuffer(msg), sig, pkGroup)) {
      throw new Error('aggregate verification failed')
    }

    let secretSum = 0n
    for (const d of ids) secretSum = curve.modOrder(secretSum + coefficients[d][0])

    const coeffJson = {}
    for (const d of ids) coeffJson[d] = coefficients[d].map((c) => c.toString())
    const keysJson = {}
    for (const d of ids) {
      keysJson[d] = {}
      for (const r of ids) keysJson[d][r] = bytesToHex(keys[d][r])
    }
    const bundlesJson = {}
    for (const d of ids) {
      bundlesJson[d] = {}
      for (const r of ids) {
        bundlesJson[d][r] = {
          nonce: bytesToHex(bundles[d][r].nonce),
          ciphertext: bytesToHex(bundles[d][r].ciphertext),
        }
      }
    }
    const noncesJson = {}
    for (const s of signers) {
      noncesJson[s] = {
        hidingNonce: nonces[s].hidingNonce.toString(),
        bindingNonce: nonces[s].bindingNonce.toString(),
      }
    }

    out.push({
      n,
      t,
      coefficients: coeffJson,
      commitments: allCommitments.map((d) => d.map(eP)),
      keys: keysJson,
      bundles: bundlesJson,
      finalized,
      PKGroup: eP(pkGroup),
      secretSum: secretSum.toString(),
      signers,
      msg: msg.toString(),
      nonces: noncesJson,
      commitmentList: commitmentList.map((c) => ({
        identifier: c.identifier.toString(),
        hidingNonceCommitment: eP(c.hidingNonceCommitment),
        bindingNonceCommitment: eP(c.bindingNonceCommitment),
      })),
      sigShares: sigShares.map((s) => s.toString()),
      signature: { R8: eP(sig.R8), S: sig.S.toString() },
    })
  }
  return { producer: 'js', runs: out }
}

// --------------------------------------------------------------- verify

const verify = (transcript) => {
  let passed = 0
  let total = 0
  const failures = []
  const check = (ri, name, ok) => {
    total += 1
    if (ok) passed += 1
    else failures.push(`run ${ri}: ${name}`)
  }

  transcript.runs.forEach((run, ri) => {
    const n = run.n
    const ids = Array.from({ length: n }, (_, i) => i + 1)
    const allCommitments = run.commitments.map((d) => d.map(dP))

    for (const d of ids) {
      const coeffs = run.coefficients[d].map(BigInt)
      const recomputed = dkg.vssCommit(coeffs)
      check(ri, 'vssCommit reproduces the dealer commitments',
        recomputed.length === allCommitments[d - 1].length &&
        recomputed.every((p, k) => eq(p, allCommitments[d - 1][k])))

      for (const r of ids) {
        const enc = run.bundles[d][r]
        const key = hexToBytes(run.keys[d][r])
        try {
          const s = dkg.decryptShareAESGCMWithAAD(
            { nonce: hexToBytes(enc.nonce), ciphertext: hexToBytes(enc.ciphertext) },
            key, r, allCommitments)
          check(ri, 'decrypted share equals the polynomial evaluation',
            s === dkg.polynomialEvaluate(BigInt(r), coeffs))
          check(ri, 'Feldman check passes', dkg.verifyFeldmanShare(r, s, allCommitments[d - 1]))
          check(ri, 'Feldman check rejects a tampered share',
            !dkg.verifyFeldmanShare(r, curve.modOrder(s + 1n), allCommitments[d - 1]))
        } catch (e) {
          check(ri, `decrypt share (${e.message})`, false)
        }
      }
    }

    const pkGroup = dP(run.PKGroup)
    const secretSum = BigInt(run.secretSum)
    check(ri, 'group key is the sum of the constant-term commitments',
      eq(dkg.combineGroupPubkeyFromCommitments(allCommitments), pkGroup))
    check(ri, 'group key equals ScalarBaseMult of the summed secrets',
      eq(curve.ScalarBaseMult(secretSum), pkGroup))

    const skShares = {}
    const div8 = {}
    for (const entry of run.finalized) {
      const id = entry.id
      const byDealer = ids.map((d) => ({
        dealerId: d,
        s_ki: dkg.polynomialEvaluate(BigInt(id), run.coefficients[d].map(BigInt)),
      }))
      const f = dkg.finalizeParticipant(id, byDealer, allCommitments)
      check(ri, 'finalized skShare matches', f.share.skShare === BigInt(entry.skShare))
      check(ri, 'finalized skShareDiv8 matches', f.share.skShareDiv8 === BigInt(entry.skShareDiv8))
      check(ri, 'finalized PKGroup matches', eq(f.PKGroup, dP(entry.PKGroup)))
      check(ri, 'viewing key matches', bytesToHex(f.viewingPrivateKey) === entry.viewingPrivateKey)
      check(ri, 'skShare is 8 x skShareDiv8',
        f.share.skShare === curve.modOrder(8n * f.share.skShareDiv8))
      skShares[id] = f.share.skShare
      div8[id] = f.share.skShareDiv8
    }

    const signers = run.signers
    const msg = BigInt(run.msg)
    const commitmentList = run.commitmentList.map((c) => ({
      identifier: BigInt(c.identifier),
      hidingNonceCommitment: dP(c.hidingNonceCommitment),
      bindingNonceCommitment: dP(c.bindingNonceCommitment),
    }))
    const recorded = run.sigShares.map(BigInt)

    signers.forEach((s, k) => {
      const np = {
        hidingNonce: BigInt(run.nonces[s].hidingNonce),
        bindingNonce: BigInt(run.nonces[s].bindingNonce),
      }
      const ci = commitmentList.find((c) => c.identifier === BigInt(s))
      check(ri, 'commitment matches the recorded nonces',
        eq(ci.hidingNonceCommitment, curve.ScalarBaseMult(np.hidingNonce)) &&
        eq(ci.bindingNonceCommitment, curve.ScalarBaseMult(np.bindingNonce)))
      const share = frost.sign(BigInt(s), skShares[s], pkGroup, np, msg, commitmentList)
      check(ri, 'recomputed signature share matches', share === recorded[k])
      check(ri, 'signature share verifies',
        frost.verifySignatureShare(BigInt(s), skShares[s], ci, share, commitmentList, pkGroup, msg))
      check(ri, 'a tampered signature share is rejected',
        !frost.verifySignatureShare(BigInt(s), skShares[s], ci, curve.modOrder(share + 1n),
          commitmentList, pkGroup, msg))
    })

    const sig = frost.aggregate(commitmentList, msg, pkGroup, recorded)
    const recSig = { R8: dP(run.signature.R8), S: BigInt(run.signature.S) }
    check(ri, 'aggregate reproduces the recorded signature',
      eq(sig.R8, recSig.R8) && sig.S === recSig.S)
    check(ri, 'aggregate verifies as EdDSA-Poseidon under the group key',
      eddsaBuild.verifyPoseidon(bigIntToBuffer(msg), recSig, pkGroup))
    check(ri, 'a tampered signature is rejected',
      !eddsaBuild.verifyPoseidon(bigIntToBuffer(msg),
        { R8: recSig.R8, S: curve.modOrder(recSig.S + 1n) }, pkGroup))

    const subset = signers.map((s) => ({ id: s, s_i: div8[s] }))
    check(ri, 'threshold subset reconstructs the group secret',
      dkg.reconstructConstantFromShares(subset) === secretSum)
  })

  return { passed, total, failures }
}

// ------------------------------------------------------- snapshot interop

const canon = (v) => {
  if (Array.isArray(v)) return v.map(canon)
  if (v && typeof v === 'object') {
    const out = {}
    for (const k of Object.keys(v).sort()) out[k] = canon(v[k])
    return out
  }
  return v
}

const snapshots = (runs) => {
  const out = []
  for (let iter = 0; iter < runs; iter++) {
    const n = 3 + randBelow(3)
    const t = 2 + randBelow(n - 1)
    const ids = Array.from({ length: n }, (_, i) => i + 1)
    const managers = ids.map((i) => new DKGManager(`p${i}`, randomBytes(32)))

    const roster = {}
    managers.forEach((m, i) => { roster[ids[i]] = m.getAnnouncement().pubKey })
    for (const m of managers) m.assignRoster(roster)

    const commitments = {}
    managers.forEach((m, i) => {
      commitments[ids[i]] = m.commitmentRound({
        secret: curve.RandomScalar(), desiredShares: n, threshold: t,
      }).commitments
    })
    for (const m of managers) for (const id of ids) m.addParticipantCommitments(id, commitments[id])

    const bundles = {}
    managers.forEach((m, i) => { bundles[ids[i]] = m.getEncryptedShares() })
    for (const m of managers) for (const id of ids) m.addEncryptedShares(id, bundles[id])

    const snaps = managers.map((m) => m.toJSON())
    const expected = managers.map((m) => {
      const f = m.finalize()
      return {
        id: f.share.id,
        skShare: f.share.skShare.toString(),
        skShareDiv8: f.share.skShareDiv8.toString(),
        PKGroup: eP(f.PKGroup),
        viewingPrivateKey: bytesToHex(f.viewingPrivateKey),
      }
    })
    out.push({ snapshots: snaps, expected })
  }
  return { producer: 'js', runs: out }
}

const verifySnapshots = (transcript) => {
  let passed = 0
  let total = 0
  const failures = []
  transcript.runs.forEach((run, ri) => {
    run.snapshots.forEach((raw, k) => {
      const check = (name, ok) => {
        total += 1
        if (ok) passed += 1
        else failures.push(`run ${ri} participant ${k}: ${name}`)
      }
      let m
      try {
        m = DKGManager.fromJSON(raw)
      } catch (e) {
        check(`restore snapshot (${e.message})`, false)
        return
      }
      check('snapshot round trips unchanged',
        JSON.stringify(canon(m.toJSON())) === JSON.stringify(canon(raw)))
      try {
        const f = m.finalize()
        const e = run.expected[k]
        check('restored participant finalizes to the same share',
          f.share.skShare.toString() === e.skShare && f.share.skShareDiv8.toString() === e.skShareDiv8)
        check('restored participant finalizes to the same group key',
          JSON.stringify(eP(f.PKGroup)) === JSON.stringify(e.PKGroup))
        check('restored participant derives the same viewing key',
          bytesToHex(f.viewingPrivateKey) === e.viewingPrivateKey)
      } catch (e) {
        check(`finalize restored participant (${e.message})`, false)
      }
    })
  })
  return { passed, total, failures }
}

// ------------------------------------------------- signing manager interop

const signingSnapshots = (runs) => {
  const out = []
  for (let iter = 0; iter < runs; iter++) {
    const n = 3 + randBelow(3)
    const t = 2 + randBelow(n - 1)
    const keygen = dkg.trustedDealerKeygen(curve.RandomScalar(), n, t)
    const pk = keygen.vssCommitment[0]

    const mgr = new FROSTSigningManager(pk, t)
    for (const s of keygen.participantPrivateKeys.slice(0, t)) {
      mgr.addSigner({ id: s.x_i, skShare: curve.modOrder(8n * s.y_i) })
    }
    mgr.startSession()
    const safeBefore = mgr.toJSON()
    mgr.round1()
    const safeAfterCommit = mgr.toJSON()
    const message = curve.RandomScalar()
    const partials = mgr.sign(message)
    mgr.receivePartials(partials)
    const midRound = mgr.toMidRoundJSON()
    const sig = mgr.finalize(message)

    out.push({
      safeBefore,
      safeAfterCommit,
      midRound,
      message: message.toString(),
      groupPublicKey: eP(pk),
      expected: { R8: eP(sig.R8), S: sig.S.toString() },
    })
  }
  return { producer: 'js', runs: out }
}

const verifySigningSnapshots = (transcript) => {
  let passed = 0
  let total = 0
  const failures = []
  transcript.runs.forEach((run, ri) => {
    const check = (name, ok) => {
      total += 1
      if (ok) passed += 1
      else failures.push(`run ${ri}: ${name}`)
    }
    const message = BigInt(run.message)

    try {
      const m = FROSTSigningManager.fromJSON(run.safeBefore)
      check('safe snapshot round trips unchanged',
        JSON.stringify(canon(m.toJSON())) === JSON.stringify(canon(run.safeBefore)))
      check('restored manager keeps its signers and threshold',
        m.signers.length === run.safeBefore.signers.length && m.threshold === run.safeBefore.threshold)
    } catch (e) {
      check(`restore safe snapshot (${e.message})`, false)
    }

    check('a committed session is dropped from a safe snapshot',
      run.safeAfterCommit.sessions.length === 0 &&
      JSON.stringify(run.safeAfterCommit.omittedSessions) === JSON.stringify(['default']))

    let refusedMid = false
    try { FROSTSigningManager.fromJSON(run.midRound) } catch { refusedMid = true }
    check('a mid-round payload is refused by fromJSON', refusedMid)

    let refusedSafe = false
    try { FROSTSigningManager.fromMidRoundJSON(run.safeBefore) } catch { refusedSafe = true }
    check('a safe payload is refused by fromMidRoundJSON', refusedSafe)

    try {
      const m = FROSTSigningManager.fromMidRoundJSON(run.midRound)
      check('mid-round snapshot round trips unchanged',
        JSON.stringify(canon(m.toMidRoundJSON())) === JSON.stringify(canon(run.midRound)))
      const sig = m.finalize(message)
      check('restored manager finalizes to the same signature',
        JSON.stringify(eP(sig.R8)) === JSON.stringify(run.expected.R8) &&
        sig.S.toString() === run.expected.S)
      check('the signature verifies under the group key',
        eddsaBuild.verifyPoseidon(bigIntToBuffer(message), sig, dP(run.groupPublicKey)))
    } catch (e) {
      check(`restore mid-round snapshot (${e.message})`, false)
    }
  })
  return { passed, total, failures }
}

// ----------------------------------------------------------------- main

const mode = process.argv[2]
if (mode === 'run') {
  const runs = Number(process.argv[3])
  writeFileSync(process.argv[4], JSON.stringify(run(runs)))
  console.log(`js: ${runs} ceremonies -> ${process.argv[4]}`)
} else if (mode === 'snapshots') {
  const runs = Number(process.argv[3])
  writeFileSync(process.argv[4], JSON.stringify(snapshots(runs)))
  console.log(`js: ${runs} snapshot sets -> ${process.argv[4]}`)
} else if (mode === 'signing-snapshots') {
  const runs = Number(process.argv[3])
  writeFileSync(process.argv[4], JSON.stringify(signingSnapshots(runs)))
  console.log(`js: ${runs} signing snapshot sets -> ${process.argv[4]}`)
} else if (mode === 'verify-signing-snapshots') {
  const transcript = JSON.parse(readFileSync(process.argv[3], 'utf8'))
  const { passed, total, failures } = verifySigningSnapshots(transcript)
  console.log(`js restores ${transcript.runs.length} signing snapshot sets produced by ${transcript.producer}: ${passed}/${total} checks`)
  for (const f of failures.slice(0, 20)) console.log(`  FAIL ${f}`)
  if (passed !== total) process.exit(1)
} else if (mode === 'verify-snapshots') {
  const transcript = JSON.parse(readFileSync(process.argv[3], 'utf8'))
  const { passed, total, failures } = verifySnapshots(transcript)
  console.log(`js restores ${transcript.runs.length} snapshot sets produced by ${transcript.producer}: ${passed}/${total} checks`)
  for (const f of failures.slice(0, 20)) console.log(`  FAIL ${f}`)
  if (passed !== total) process.exit(1)
} else if (mode === 'verify') {
  const transcript = JSON.parse(readFileSync(process.argv[3], 'utf8'))
  const { passed, total, failures } = verify(transcript)
  console.log(`js verifies ${transcript.runs.length} ceremonies produced by ${transcript.producer}: ${passed}/${total} checks`)
  for (const f of failures.slice(0, 20)) console.log(`  FAIL ${f}`)
  if (passed !== total) process.exit(1)
} else {
  console.error('usage: ceremony_js.mjs run <runs> <out.json> | verify <in.json>')
  process.exit(2)
}
