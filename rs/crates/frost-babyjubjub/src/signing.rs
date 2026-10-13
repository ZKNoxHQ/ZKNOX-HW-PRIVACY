//! Port of `src/manager/signing.ts` (`FROSTSigningManager`, `SigningSession`).
//!
//! The TypeScript session holds a back-reference to its manager. Rust cannot,
//! so the manager owns its sessions and the session methods live on the
//! manager, taking the session id; the flat single-session API delegates to a
//! lazily created `default` session exactly as upstream does. Sessions,
//! partials and remote commitments keep insertion order, so a snapshot written
//! here is byte-identical to the one the TypeScript writes from the same
//! state.

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

use crate::bytes::bigint_to_buffer;
use crate::curve::Point;
use crate::eddsa::{EddsaPoseidon, Signature};
use crate::error::{Error, Result};
use crate::frost::{AggregateSignature, BabyFrost, Bindings, Commitment};
use crate::rng::Rng;
use crate::snapshot::{big_hex, parse_big_hex};

/// `DEFAULT_SESSION`.
pub const DEFAULT_SESSION: &str = "default";
/// `SNAPSHOT_VERSION` of `manager/signing.ts`.
pub const SNAPSHOT_VERSION: u32 = 2;

/// `SignerShare`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerShare {
    /// `id`.
    pub id: u32,
    /// `skShare` — the 8-multiplied share `finalizeParticipant` returns.
    pub sk_share: BigInt,
}

/// `SessionBinding`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBinding {
    /// `bindings`.
    pub bindings: Bindings,
    /// `share`.
    pub share: SignerShare,
}

/// `PartialSignature`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature {
    /// `identifier`.
    pub identifier: u32,
    /// `partial`.
    pub partial: BigInt,
}

// ------------------------------------------------------------- snapshot types

/// Hex-encoded `[x, y]` curve point.
pub type HexPoint = [String; 2];

/// `CommitmentSnapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentSnapshot {
    /// `identifier`.
    pub identifier: String,
    /// `hidingNonceCommitment`.
    #[serde(rename = "hidingNonceCommitment")]
    pub hiding_nonce_commitment: HexPoint,
    /// `bindingNonceCommitment`.
    #[serde(rename = "bindingNonceCommitment")]
    pub binding_nonce_commitment: HexPoint,
}

/// `SessionBindingSnapshot.nonces`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceSnapshot {
    /// `hidingNonce`.
    #[serde(rename = "hidingNonce")]
    pub hiding_nonce: String,
    /// `bindingNonce`.
    #[serde(rename = "bindingNonce")]
    pub binding_nonce: String,
}

/// `SessionBindingSnapshot.share`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareSnapshot {
    /// `id`.
    pub id: u32,
    /// `skShare`.
    #[serde(rename = "skShare")]
    pub sk_share: String,
}

/// `SessionBindingSnapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBindingSnapshot {
    /// `nonces`.
    pub nonces: NonceSnapshot,
    /// `commitments`.
    pub commitments: CommitmentSnapshot,
    /// `share`.
    pub share: ShareSnapshot,
}

/// `SigningSessionSnapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningSessionSnapshot {
    /// `id`.
    pub id: String,
    /// `committed`.
    pub committed: bool,
    /// `message`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// `localBindings`.
    #[serde(rename = "localBindings")]
    pub local_bindings: Vec<SessionBindingSnapshot>,
    /// `remoteSigners`.
    #[serde(rename = "remoteSigners")]
    pub remote_signers: Vec<CommitmentSnapshot>,
    /// `partials`, as `[id, hex]` pairs in insertion order.
    pub partials: Vec<(u32, String)>,
}

/// `SnapshotKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotKind {
    /// `safe` — carries no live nonces, sound to restore any number of times.
    #[serde(rename = "safe")]
    Safe,
    /// `mid-round` — carries the local nonces of committed sessions, single use.
    #[serde(rename = "mid-round")]
    MidRound,
}

impl SnapshotKind {
    fn as_str(&self) -> &'static str {
        match self {
            SnapshotKind::Safe => "safe",
            SnapshotKind::MidRound => "mid-round",
        }
    }
}

/// `SigningManagerSnapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningManagerSnapshot {
    /// `version`.
    pub version: u32,
    /// `kind`.
    pub kind: SnapshotKind,
    /// `threshold`.
    pub threshold: usize,
    /// `groupPublicKey`.
    #[serde(rename = "groupPublicKey")]
    pub group_public_key: HexPoint,
    /// `signers`.
    pub signers: Vec<ShareSnapshot>,
    /// `sessions`.
    pub sessions: Vec<SigningSessionSnapshot>,
    /// `omittedSessions` — committed sessions dropped from a `safe` snapshot.
    #[serde(rename = "omittedSessions", skip_serializing_if = "Option::is_none")]
    pub omitted_sessions: Option<Vec<String>>,
}

fn point_to_hex(p: &Point) -> HexPoint {
    [big_hex(&p.x), big_hex(&p.y)]
}

fn hex_to_point(h: &HexPoint) -> Result<Point> {
    Ok(Point::new(parse_big_hex(&h[0])?, parse_big_hex(&h[1])?))
}

fn commitment_to_snapshot(c: &Commitment) -> CommitmentSnapshot {
    CommitmentSnapshot {
        identifier: big_hex(&c.identifier),
        hiding_nonce_commitment: point_to_hex(&c.hiding_nonce_commitment),
        binding_nonce_commitment: point_to_hex(&c.binding_nonce_commitment),
    }
}

fn snapshot_to_commitment(s: &CommitmentSnapshot) -> Result<Commitment> {
    Ok(Commitment {
        identifier: parse_big_hex(&s.identifier)?,
        hiding_nonce_commitment: hex_to_point(&s.hiding_nonce_commitment)?,
        binding_nonce_commitment: hex_to_point(&s.binding_nonce_commitment)?,
    })
}

// -------------------------------------------------------------------- session

/// `SigningSession` — one isolated two-round FROST signing of one message.
#[derive(Clone, Debug)]
pub struct SigningSession {
    /// `id`.
    pub id: String,
    /// `localBindings`.
    pub local_bindings: Vec<SessionBinding>,
    /// `remoteSigners`.
    pub remote_signers: Vec<Commitment>,
    /// `partialsById`, insertion ordered as the JavaScript `Map` is.
    pub partials: Vec<(u32, BigInt)>,
    committed: bool,
    message: Option<BigInt>,
}

impl SigningSession {
    fn new(id: &str) -> Self {
        SigningSession {
            id: id.to_string(),
            local_bindings: Vec::new(),
            remote_signers: Vec::new(),
            partials: Vec::new(),
            committed: false,
            message: None,
        }
    }

    /// `hasCommitted`.
    pub fn has_committed(&self) -> bool {
        self.committed
    }

    /// Partial signature of one identifier, if collected.
    pub fn partial(&self, id: u32) -> Option<&BigInt> {
        self.partials.iter().find(|(i, _)| *i == id).map(|(_, v)| v)
    }

    /// `reset`.
    pub fn reset(&mut self) {
        self.local_bindings.clear();
        self.remote_signers.clear();
        self.partials.clear();
        self.committed = false;
        self.message = None;
    }

    /// `exportRound1`.
    pub fn export_round1(&self) -> Vec<Commitment> {
        self.local_bindings
            .iter()
            .map(|sb| sb.bindings.commitments.clone())
            .collect()
    }

    /// `addRemoteSigner`.
    pub fn add_remote_signer(&mut self, commitment: &Commitment) -> Result<()> {
        if commitment.identifier <= BigInt::from(0u32) {
            return Err(Error::new(format!(
                "invalid commitment identifier {}: participant identifiers must be positive integers",
                commitment.identifier
            )));
        }
        if !self
            .remote_signers
            .iter()
            .any(|c| c.identifier == commitment.identifier)
        {
            self.remote_signers.push(commitment.clone());
        }
        Ok(())
    }

    /// `receivePartials`.
    pub fn receive_partials(&mut self, partials: &[PartialSignature]) {
        for p in partials {
            if self.partial(p.identifier).is_none() {
                self.partials.push((p.identifier, p.partial.clone()));
            }
        }
    }

    fn commitment_list(&self, threshold: usize) -> Result<Vec<Commitment>> {
        let mut list: Vec<Commitment> = Vec::new();
        for c in self.export_round1() {
            if !list.iter().any(|x| x.identifier == c.identifier) {
                list.push(c);
            }
        }
        for c in &self.remote_signers {
            if !list.iter().any(|x| x.identifier == c.identifier) {
                list.push(c.clone());
            }
        }
        list.sort_by(|a, b| a.identifier.cmp(&b.identifier));
        if list.len() < threshold {
            return Err(Error::new(format!(
                "Insufficient commitments: have {}, need >= {threshold}",
                list.len()
            )));
        }
        Ok(list)
    }

    /// `toSnapshot`.
    pub fn to_snapshot(&self) -> SigningSessionSnapshot {
        SigningSessionSnapshot {
            id: self.id.clone(),
            committed: self.committed,
            message: self.message.as_ref().map(big_hex),
            local_bindings: self
                .local_bindings
                .iter()
                .map(|sb| SessionBindingSnapshot {
                    nonces: NonceSnapshot {
                        hiding_nonce: big_hex(&sb.bindings.nonces.hiding_nonce),
                        binding_nonce: big_hex(&sb.bindings.nonces.binding_nonce),
                    },
                    commitments: commitment_to_snapshot(&sb.bindings.commitments),
                    share: ShareSnapshot {
                        id: sb.share.id,
                        sk_share: big_hex(&sb.share.sk_share),
                    },
                })
                .collect(),
            remote_signers: self.remote_signers.iter().map(commitment_to_snapshot).collect(),
            partials: self
                .partials
                .iter()
                .map(|(id, v)| (*id, big_hex(v)))
                .collect(),
        }
    }

    /// `SigningSession.fromSnapshot`.
    pub fn from_snapshot(snap: &SigningSessionSnapshot) -> Result<Self> {
        let mut session = SigningSession::new(&snap.id);
        session.committed = snap.committed;
        session.message = match &snap.message {
            Some(m) => Some(parse_big_hex(m)?),
            None => None,
        };
        for b in &snap.local_bindings {
            session.local_bindings.push(SessionBinding {
                bindings: Bindings {
                    nonces: crate::frost::NoncePair {
                        hiding_nonce: parse_big_hex(&b.nonces.hiding_nonce)?,
                        binding_nonce: parse_big_hex(&b.nonces.binding_nonce)?,
                    },
                    commitments: snapshot_to_commitment(&b.commitments)?,
                },
                share: SignerShare {
                    id: b.share.id,
                    sk_share: parse_big_hex(&b.share.sk_share)?,
                },
            });
        }
        for c in &snap.remote_signers {
            session.remote_signers.push(snapshot_to_commitment(c)?);
        }
        for (id, v) in &snap.partials {
            session.partials.push((*id, parse_big_hex(v)?));
        }
        Ok(session)
    }
}

// -------------------------------------------------------------------- manager

/// `FROSTSigningManager`.
pub struct FrostSigningManager {
    /// `frost`.
    pub frost: BabyFrost,
    /// `signers`.
    pub signers: Vec<SignerShare>,
    /// `groupPublicKey`.
    pub group_public_key: Point,
    /// `threshold`.
    pub threshold: usize,
    sessions: Vec<SigningSession>,
    eddsa: EddsaPoseidon,
}

impl FrostSigningManager {
    /// `new FROSTSigningManager(publicKey, threshold)`.
    pub fn new(public_key: Point, threshold: usize) -> Self {
        FrostSigningManager {
            frost: BabyFrost::new(),
            signers: Vec::new(),
            group_public_key: public_key,
            threshold,
            sessions: Vec::new(),
            eddsa: EddsaPoseidon::new(),
        }
    }

    /// `hasId`.
    pub fn has_id(&self, identifier: u32) -> bool {
        self.signers.iter().any(|s| s.id == identifier)
    }

    /// `addSigner`.
    pub fn add_signer(&mut self, signer: SignerShare) -> Result<()> {
        if signer.id == 0 {
            return Err(Error::new(format!(
                "invalid signer id {}: participant identifiers must be positive integers",
                signer.id
            )));
        }
        if self.signers.iter().any(|s| s.id == signer.id) {
            return Err(Error::new(format!("signer {} already added", signer.id)));
        }
        self.signers.push(signer);
        Ok(())
    }

    // --- session lifecycle

    /// `startSession`.
    pub fn start_session(&mut self, id: &str) -> Result<()> {
        if self.has_session(id) {
            return Err(Error::new(format!("signing session {id} already exists")));
        }
        self.sessions.push(SigningSession::new(id));
        Ok(())
    }

    /// `hasSession`.
    pub fn has_session(&self, id: &str) -> bool {
        self.sessions.iter().any(|s| s.id == id)
    }

    /// `session`.
    pub fn session(&self, id: &str) -> Result<&SigningSession> {
        self.sessions
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| Error::new(format!("unknown signing session {id}")))
    }

    fn session_mut(&mut self, id: &str) -> Result<&mut SigningSession> {
        self.sessions
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| Error::new(format!("unknown signing session {id}")))
    }

    /// `endSession`.
    pub fn end_session(&mut self, id: &str) {
        self.sessions.retain(|s| s.id != id);
    }

    fn ensure_default(&mut self) {
        if !self.has_session(DEFAULT_SESSION) {
            self.sessions.push(SigningSession::new(DEFAULT_SESSION));
        }
    }

    // --- rounds, session scoped

    /// `session.round1`.
    pub fn session_round1(&mut self, rng: &mut dyn Rng, id: &str) -> Result<()> {
        let signers = self.signers.clone();
        let frost = self.frost.clone();
        let session = self.session_mut(id)?;
        if session.committed {
            return Err(Error::new(format!(
                "session {id} already committed; reset() it or start a new session to sign again"
            )));
        }
        session.local_bindings.clear();
        session.partials.clear();
        for signer in &signers {
            let bindings = frost.commit(rng, &signer.sk_share, &BigInt::from(signer.id))?;
            session.local_bindings.push(SessionBinding {
                bindings,
                share: signer.clone(),
            });
        }
        session.committed = true;
        Ok(())
    }

    /// `session.exportRound1`.
    pub fn session_export_round1(&self, id: &str) -> Result<Vec<Commitment>> {
        Ok(self.session(id)?.export_round1())
    }

    /// `session.addRemoteSigner`.
    pub fn session_add_remote_signer(&mut self, id: &str, commitment: &Commitment) -> Result<()> {
        self.session_mut(id)?.add_remote_signer(commitment)
    }

    /// `session.getCommitmentList`.
    pub fn session_commitment_list(&self, id: &str) -> Result<Vec<Commitment>> {
        self.session(id)?.commitment_list(self.threshold)
    }

    /// `session.sign`.
    pub fn session_sign(&mut self, id: &str, message: &BigInt) -> Result<Vec<PartialSignature>> {
        let threshold = self.threshold;
        let group_public_key = self.group_public_key.clone();
        let frost = self.frost.clone();
        let session = self.session_mut(id)?;
        if session.local_bindings.is_empty() {
            return Err(Error::new("No local commitments; run round1 first"));
        }
        let commitment_list = session.commitment_list(threshold)?;
        if commitment_list.is_empty() {
            return Err(Error::new(
                "No commitments available; run round1 and collect remotes first",
            ));
        }
        session.message = Some(message.clone());
        let mut partials = Vec::new();
        for signer in &session.local_bindings {
            let partial = frost.sign(
                &signer.bindings.commitments.identifier,
                &signer.share.sk_share,
                &group_public_key,
                &signer.bindings.nonces,
                message,
                &commitment_list,
            )?;
            partials.push(PartialSignature {
                identifier: signer.share.id,
                partial,
            });
        }
        Ok(partials)
    }

    /// `session.receivePartials`.
    pub fn session_receive_partials(
        &mut self,
        id: &str,
        partials: &[PartialSignature],
    ) -> Result<()> {
        self.session_mut(id)?.receive_partials(partials);
        Ok(())
    }

    /// `session.expectedParticipantIds`.
    pub fn session_expected_participant_ids(&self, id: &str) -> Result<Vec<u32>> {
        Ok(self
            .session_commitment_list(id)?
            .iter()
            .map(|c| c.identifier.to_string().parse::<u32>().unwrap_or(0))
            .collect())
    }

    /// `session.getMissingPartials`.
    pub fn session_missing_partials(&self, id: &str) -> Result<Vec<u32>> {
        let session = self.session(id)?;
        Ok(self
            .session_expected_participant_ids(id)?
            .into_iter()
            .filter(|pid| session.partial(*pid).is_none())
            .collect())
    }

    /// `session.readyToFinalize`.
    pub fn session_ready_to_finalize(&self, id: &str) -> Result<bool> {
        Ok(self.session_missing_partials(id)?.is_empty())
    }

    /// `session.finalize`.
    pub fn session_finalize(&self, id: &str, message: &BigInt) -> Result<AggregateSignature> {
        let session = self.session(id)?;
        if let Some(m) = &session.message {
            if m != message {
                return Err(Error::new(format!(
                    "finalize message does not match the message signed in session {id}"
                )));
            }
        }
        let commitment_list = session.commitment_list(self.threshold)?;
        if commitment_list.is_empty() {
            return Err(Error::new("No commitments available; cannot finalize"));
        }
        let expected_ids = self.session_expected_participant_ids(id)?;
        let missing: Vec<String> = expected_ids
            .iter()
            .filter(|pid| session.partial(**pid).is_none())
            .map(|pid| pid.to_string())
            .collect();
        if !missing.is_empty() {
            return Err(Error::new(format!(
                "Missing partials for identifiers: {}",
                missing.join(", ")
            )));
        }

        for binding in &session.local_bindings {
            let local_id = binding.share.id;
            let sig_share = match session.partial(local_id) {
                Some(v) => v,
                None => continue,
            };
            let commitment_local = commitment_list
                .iter()
                .find(|c| c.identifier == BigInt::from(local_id))
                .ok_or_else(|| Error::new(format!("Missing commitment for local id {local_id}")))?;
            let ok = self.frost.verify_signature_share(
                &BigInt::from(local_id),
                &binding.share.sk_share,
                commitment_local,
                sig_share,
                &commitment_list,
                &self.group_public_key,
                message,
            )?;
            if !ok {
                return Err(Error::new(format!(
                    "Local signature share failed verification for local signer {local_id}"
                )));
            }
        }

        let sig_shares: Vec<BigInt> = expected_ids
            .iter()
            .map(|pid| session.partial(*pid).cloned().unwrap())
            .collect();
        let sig = self.frost.aggregate(
            &commitment_list,
            message,
            &self.group_public_key,
            &sig_shares,
        )?;
        // Only local shares can be checked above, so a forged remote partial
        // would otherwise return an invalid aggregate without complaint.
        let ok = self.eddsa.verify_poseidon(
            &bigint_to_buffer(message),
            &Signature {
                r8: sig.r8.clone(),
                s: sig.s.clone(),
            },
            &self.group_public_key,
        );
        if !ok {
            return Err(Error::new(
                "Aggregate signature failed verification; a partial signature is invalid",
            ));
        }
        Ok(sig)
    }

    /// `session.reset`.
    pub fn session_reset(&mut self, id: &str) -> Result<()> {
        self.session_mut(id)?.reset();
        Ok(())
    }

    // --- flat single-session API

    /// `round1`.
    pub fn round1(&mut self, rng: &mut dyn Rng) -> Result<()> {
        self.ensure_default();
        self.session_round1(rng, DEFAULT_SESSION)
    }

    /// `exportRound1`.
    pub fn export_round1(&mut self) -> Result<Vec<Commitment>> {
        self.ensure_default();
        self.session_export_round1(DEFAULT_SESSION)
    }

    /// `addRemoteSigner`.
    pub fn add_remote_signer(&mut self, commitment: &Commitment) -> Result<()> {
        self.ensure_default();
        self.session_add_remote_signer(DEFAULT_SESSION, commitment)
    }

    /// `sign`.
    pub fn sign(&mut self, message: &BigInt) -> Result<Vec<PartialSignature>> {
        self.ensure_default();
        self.session_sign(DEFAULT_SESSION, message)
    }

    /// `receivePartials`.
    pub fn receive_partials(&mut self, partials: &[PartialSignature]) -> Result<()> {
        self.ensure_default();
        self.session_receive_partials(DEFAULT_SESSION, partials)
    }

    /// `finalize`.
    pub fn finalize(&mut self, message: &BigInt) -> Result<AggregateSignature> {
        self.ensure_default();
        self.session_finalize(DEFAULT_SESSION, message)
    }

    /// `expectedParticipantIds`.
    pub fn expected_participant_ids(&mut self) -> Result<Vec<u32>> {
        self.ensure_default();
        self.session_expected_participant_ids(DEFAULT_SESSION)
    }

    /// `getMissingPartials`.
    pub fn get_missing_partials(&mut self) -> Result<Vec<u32>> {
        self.ensure_default();
        self.session_missing_partials(DEFAULT_SESSION)
    }

    /// `readyToFinalize`.
    pub fn ready_to_finalize(&mut self) -> Result<bool> {
        self.ensure_default();
        self.session_ready_to_finalize(DEFAULT_SESSION)
    }

    /// `resetRoundState`.
    pub fn reset_round_state(&mut self) -> Result<()> {
        self.ensure_default();
        self.session_reset(DEFAULT_SESSION)
    }

    // --- persistence

    /// `toJSON` — the `safe` snapshot: committed sessions are dropped and
    /// listed in `omittedSessions`, because serializing their nonces is what
    /// creates the single-use hazard.
    pub fn to_snapshot(&self) -> SigningManagerSnapshot {
        let omitted: Vec<String> = self
            .sessions
            .iter()
            .filter(|s| s.has_committed())
            .map(|s| s.id.clone())
            .collect();
        SigningManagerSnapshot {
            version: SNAPSHOT_VERSION,
            kind: SnapshotKind::Safe,
            threshold: self.threshold,
            group_public_key: point_to_hex(&self.group_public_key),
            signers: self
                .signers
                .iter()
                .map(|s| ShareSnapshot {
                    id: s.id,
                    sk_share: big_hex(&s.sk_share),
                })
                .collect(),
            sessions: self
                .sessions
                .iter()
                .filter(|s| !s.has_committed())
                .map(|s| s.to_snapshot())
                .collect(),
            omitted_sessions: if omitted.is_empty() { None } else { Some(omitted) },
        }
    }

    /// `toMidRoundJSON` — includes the local nonces of committed sessions.
    ///
    /// Single use. The nonces it carries must sign at most one message:
    /// restoring the same payload twice and signing different messages reuses
    /// `(hidingNonce, bindingNonce)` across distinct challenges, and enough
    /// such partials solve for the signer's secret share. Mark the stored
    /// payload consumed before signing from it.
    pub fn to_mid_round_snapshot(&self) -> SigningManagerSnapshot {
        SigningManagerSnapshot {
            version: SNAPSHOT_VERSION,
            kind: SnapshotKind::MidRound,
            threshold: self.threshold,
            group_public_key: point_to_hex(&self.group_public_key),
            signers: self
                .signers
                .iter()
                .map(|s| ShareSnapshot {
                    id: s.id,
                    sk_share: big_hex(&s.sk_share),
                })
                .collect(),
            sessions: self.sessions.iter().map(|s| s.to_snapshot()).collect(),
            omitted_sessions: None,
        }
    }

    /// `fromJSON` — rejects a `mid-round` payload.
    pub fn from_snapshot(snapshot: &SigningManagerSnapshot) -> Result<Self> {
        if snapshot.kind == SnapshotKind::MidRound {
            return Err(Error::new(
                "this is a mid-round snapshot and carries live nonces; restore it with \
                 fromMidRoundJSON(), which must be used at most once per snapshot",
            ));
        }
        Self::restore(snapshot, SnapshotKind::Safe)
    }

    /// `fromMidRoundJSON` — use at most once per snapshot.
    pub fn from_mid_round_snapshot(snapshot: &SigningManagerSnapshot) -> Result<Self> {
        Self::restore(snapshot, SnapshotKind::MidRound)
    }

    fn restore(snapshot: &SigningManagerSnapshot, expected: SnapshotKind) -> Result<Self> {
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(Error::new(format!(
                "unsupported signing snapshot version: {}",
                snapshot.version
            )));
        }
        if snapshot.kind != expected {
            let use_ = if expected == SnapshotKind::MidRound {
                "fromJSON()"
            } else {
                "fromMidRoundJSON()"
            };
            return Err(Error::new(format!(
                "expected a {} snapshot, got kind '{}'; restore that payload with {use_}",
                expected.as_str(),
                snapshot.kind.as_str()
            )));
        }
        let mut manager = FrostSigningManager::new(
            hex_to_point(&snapshot.group_public_key)?,
            snapshot.threshold,
        );
        for s in &snapshot.signers {
            manager.signers.push(SignerShare {
                id: s.id,
                sk_share: parse_big_hex(&s.sk_share)?,
            });
        }
        for sess in &snapshot.sessions {
            manager.sessions.push(SigningSession::from_snapshot(sess)?);
        }
        Ok(manager)
    }
}
