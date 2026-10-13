//! Software DKG participant: the DKG half of `src/manager/dkg.ts`
//! (`DKGManager`) implementing the [`DkgParticipant`] contract.
//!
//! Not ported: the msgpack snapshot (`toSnapshot`/`fromSnapshot`) and the
//! signing manager. State is derived from the collected data exactly as in the
//! TypeScript, so a caller that skips a step fails at the same place.

use std::collections::BTreeMap;

use num_bigint::BigInt;

use crate::curve::{Curve, Point};
use crate::dkg::{EncryptedShare, TrustedDkg};
use crate::error::{Error, Result};
use crate::key_agreement::{KeyAgreement, X25519KeyAgreement};
use crate::participant::{
    DkgAnnouncement, DkgCommitInput, DkgFinalized, DkgFlowState, DkgParticipant,
    SoftwareCommitInput,
};
use crate::rng::Rng;
use crate::snapshot::{
    big_hex, bytes_hex, parse_big_hex, parse_bytes_hex, DkgSnapshot, DkgSteps, EncryptedShareHex,
    SNAPSHOT_VERSION,
};

/// `DKGManager`, DKG half only.
pub struct SoftwareParticipant<'a> {
    name: String,
    secret_com_key: Vec<u8>,
    pub_com_key: Vec<u8>,
    key_agreement: Box<dyn KeyAgreement>,
    rng: &'a mut dyn Rng,
    curve: Curve,
    dkg: TrustedDkg,

    participant_id: Option<u32>,
    roster: BTreeMap<u32, Vec<u8>>,
    keys_by_id: BTreeMap<u32, Vec<u8>>,
    shares: BTreeMap<i64, BigInt>,
    recipient_ids: Vec<u32>,
    commitments_by_dealer: BTreeMap<u32, Vec<Point>>,
    encrypted_shares: BTreeMap<u32, BTreeMap<u32, EncryptedShare>>,
    roster_assigned: bool,
    self_commitments_created: bool,
    self_shares_encrypted: bool,
    finalized: bool,
}

impl<'a> SoftwareParticipant<'a> {
    /// Creates a participant with the given communication secret; the default
    /// key agreement is X25519, as in the TypeScript.
    pub fn new(name: &str, secret_com_key: &[u8], rng: &'a mut dyn Rng) -> Result<Self> {
        Self::with_key_agreement(name, secret_com_key, Box::new(X25519KeyAgreement), rng)
    }

    /// Same, with an explicit key-agreement scheme.
    pub fn with_key_agreement(
        name: &str,
        secret_com_key: &[u8],
        key_agreement: Box<dyn KeyAgreement>,
        rng: &'a mut dyn Rng,
    ) -> Result<Self> {
        let pub_com_key = key_agreement.public_key(secret_com_key)?.to_vec();
        Ok(SoftwareParticipant {
            name: name.to_string(),
            secret_com_key: secret_com_key.to_vec(),
            pub_com_key,
            key_agreement,
            rng,
            curve: Curve::new(),
            dkg: TrustedDkg::new(),
            participant_id: None,
            roster: BTreeMap::new(),
            keys_by_id: BTreeMap::new(),
            shares: BTreeMap::new(),
            recipient_ids: Vec::new(),
            commitments_by_dealer: BTreeMap::new(),
            encrypted_shares: BTreeMap::new(),
            roster_assigned: false,
            self_commitments_created: false,
            self_shares_encrypted: false,
            finalized: false,
        })
    }

    /// This participant's identifier, once the roster fixed it.
    pub fn participant_id(&self) -> Option<u32> {
        self.participant_id
    }

    fn roster_covers<T>(&self, map: &BTreeMap<u32, T>) -> bool {
        if self.roster.is_empty() {
            return false;
        }
        map.len() == self.roster.len() && self.roster.keys().all(|id| map.contains_key(id))
    }

    fn ensure_state_in(&self, whence: &str, allowed: &[DkgFlowState]) -> Result<()> {
        let state = self.get_state();
        if !allowed.contains(&state) {
            return Err(Error::new(format!(
                "{whence}: not allowed in state \"{}\"",
                state.as_str()
            )));
        }
        Ok(())
    }

    fn all_dealer_commitments(&self) -> Vec<Vec<Point>> {
        self.commitments_by_dealer.values().cloned().collect()
    }

    /// `getDecryptedShares` — this participant's share from every dealer,
    /// checked against that dealer's commitments before it is returned.
    pub fn decrypted_shares(&self) -> Result<BTreeMap<u32, BigInt>> {
        let id = self
            .participant_id
            .ok_or_else(|| Error::new("missing participant identifier"))?;
        let all = self.all_dealer_commitments();
        let mut out = BTreeMap::new();
        for (dealer, bundle) in &self.encrypted_shares {
            let enc = bundle
                .get(&id)
                .ok_or_else(|| Error::new(format!("dealer {dealer} sent no share for id {id}")))?;
            let key = self
                .keys_by_id
                .get(dealer)
                .ok_or_else(|| Error::new(format!("missing shared key for participant {dealer}")))?;
            let s = self
                .dkg
                .decrypt_share_aes_gcm_with_aad(enc, key, id as i64, &all)?;
            let commitments = self
                .commitments_by_dealer
                .get(dealer)
                .ok_or_else(|| Error::new(format!("missing commitments for dealer {dealer}")))?;
            if !self.dkg.verify_feldman_share(id as i64, &s, commitments) {
                return Err(Error::new(format!(
                    "share from dealer {dealer} fails its Feldman check"
                )));
            }
            out.insert(*dealer, s);
        }
        Ok(out)
    }
}

impl<'a> DkgParticipant for SoftwareParticipant<'a> {
    type CommitInput = SoftwareCommitInput;

    fn get_announcement(&self) -> DkgAnnouncement {
        DkgAnnouncement {
            pub_key: self.pub_com_key.clone(),
            name: self.name.clone(),
        }
    }

    fn assign_roster(&mut self, roster: &BTreeMap<u32, Vec<u8>>) -> Result<()> {
        self.ensure_state_in("assignRoster", &[DkgFlowState::Init])?;
        if roster.is_empty() {
            return Err(Error::new("empty roster"));
        }
        self.roster.clear();
        self.keys_by_id.clear();
        let mut matched_self = false;
        for (id, key) in roster {
            if *id == 0 {
                return Err(Error::new(format!("bad roster id: {id}")));
            }
            if key.len() != 32 {
                return Err(Error::new(format!("bad roster pubkey for id {id}")));
            }
            self.roster.insert(*id, key.clone());
            if key == &self.pub_com_key {
                self.participant_id = Some(*id);
                matched_self = true;
            }
            let shared = self.key_agreement.shared_secret(&self.secret_com_key, key)?;
            self.keys_by_id.insert(*id, shared.to_vec());
        }
        if !matched_self {
            return Err(Error::new("roster does not contain this participant"));
        }
        self.roster_assigned = true;
        Ok(())
    }

    fn commitment_round(&mut self, input: &SoftwareCommitInput) -> Result<Vec<Point>> {
        let DkgCommitInput {
            desired_shares,
            threshold,
        } = input.base;
        self.participant_id
            .ok_or_else(|| Error::new("missing participant identifier"))?;
        self.ensure_state_in("commitmentRound", &[DkgFlowState::RosterAssigned])?;
        if desired_shares == 0 {
            return Err(Error::new("desiredShares must be a positive integer"));
        }
        if threshold == 0 {
            return Err(Error::new("threshold must be a positive integer"));
        }
        if threshold > desired_shares {
            return Err(Error::new("threshold cannot exceed desiredShares"));
        }
        if self.roster.len() != desired_shares as usize {
            return Err(Error::new("roster size does not match desiredShares"));
        }
        let keygen =
            self.dkg
                .trusted_dealer_keygen(self.rng, &input.secret, desired_shares, threshold)?;
        let recipient_ids: Vec<i64> = (1..=desired_shares as i64).collect();
        self.recipient_ids = recipient_ids.iter().map(|id| *id as u32).collect();
        self.shares = self
            .dkg
            .compute_shares_for_ids(&keygen.coefficients, &recipient_ids)?;
        self.self_commitments_created = true;
        Ok(keygen.vss_commitment)
    }

    fn add_participant_commitments(&mut self, dealer_id: u32, commitments: &[Point]) -> Result<()> {
        self.ensure_state_in(
            "addParticipantCommitments",
            &[
                DkgFlowState::CommitmentsCreated,
                DkgFlowState::CommitmentsCollected,
            ],
        )?;
        if dealer_id == 0 {
            return Err(Error::new("bad participant id for commitments"));
        }
        if commitments.is_empty() {
            return Err(Error::new("empty commitments from participant"));
        }
        self.commitments_by_dealer
            .insert(dealer_id, commitments.to_vec());
        Ok(())
    }

    fn get_encrypted_shares(&mut self) -> Result<BTreeMap<u32, EncryptedShare>> {
        if let Some(id) = self.participant_id {
            if self.self_commitments_created && !self.commitments_by_dealer.contains_key(&id) {
                return Err(Error::new(format!(
                    "getEncryptedShares is still awaiting this participant's own commitments \
                     (id {id}); commitmentRound() does not self-add, feed its commitments back \
                     via addParticipantCommitments()"
                )));
            }
        }
        self.ensure_state_in("getEncryptedShares", &[DkgFlowState::CommitmentsCollected])?;
        if self.shares.is_empty() {
            return Err(Error::new("no local shares computed; run commitmentRound first"));
        }
        let all = self.all_dealer_commitments();
        let mut keys: BTreeMap<i64, Vec<u8>> = BTreeMap::new();
        for id in self.roster.keys() {
            let k = self
                .keys_by_id
                .get(id)
                .filter(|k| k.len() == 32)
                .ok_or_else(|| Error::new(format!("missing shared key for participant {id}")))?;
            keys.insert(*id as i64, k.clone());
        }
        let out = self.dkg.encrypt_shares_aes_gcm_with_aad(
            self.rng,
            &self.shares,
            &keys,
            &all,
        )?;
        self.self_shares_encrypted = true;
        Ok(out.into_iter().map(|(k, v)| (k as u32, v)).collect())
    }

    fn add_encrypted_shares(
        &mut self,
        dealer_id: u32,
        shares: &BTreeMap<u32, EncryptedShare>,
    ) -> Result<()> {
        if self.get_state() < DkgFlowState::CommitmentsCollected {
            return Err(Error::new(format!(
                "addEncryptedShares: not allowed in state \"{}\"",
                self.get_state().as_str()
            )));
        }
        if dealer_id == 0 {
            return Err(Error::new("bad dealer id for encrypted shares"));
        }
        self.encrypted_shares.insert(dealer_id, shares.clone());
        Ok(())
    }

    fn finalize(&mut self) -> Result<DkgFinalized> {
        let id = self
            .participant_id
            .ok_or_else(|| Error::new("missing participant identifier"))?;
        self.ensure_state_in("finalize", &[DkgFlowState::EncryptedSharesCollected])?;
        let dec = self.decrypted_shares()?;
        let by_dealer: Vec<(i64, BigInt)> =
            dec.into_iter().map(|(d, s)| (d as i64, s)).collect();
        let all = self.all_dealer_commitments();
        let res = self.dkg.finalize_participant(id as i64, &by_dealer, &all)?;
        self.finalized = true;
        Ok(DkgFinalized {
            id: res.share.id,
            sk_share: Some(res.share.sk_share),
            sk_share_div8: Some(res.share.sk_share_div8),
            pk_group: res.pk_group,
            viewing_private_key: res.viewing_private_key,
        })
    }

    fn get_state(&self) -> DkgFlowState {
        if self.finalized {
            return DkgFlowState::Finalized;
        }
        if self.roster_covers(&self.encrypted_shares) {
            return DkgFlowState::EncryptedSharesCollected;
        }
        if self.self_shares_encrypted {
            return DkgFlowState::SharesEncrypted;
        }
        if self.roster_covers(&self.commitments_by_dealer) {
            return DkgFlowState::CommitmentsCollected;
        }
        if self.self_commitments_created {
            return DkgFlowState::CommitmentsCreated;
        }
        if self.roster_assigned {
            return DkgFlowState::RosterAssigned;
        }
        DkgFlowState::Init
    }
}

impl<'a> SoftwareParticipant<'a> {
    /// The curve helper this participant uses.
    pub fn curve(&self) -> &Curve {
        &self.curve
    }

    /// `toJSON` — the resumable snapshot of `manager/dkg.ts`.
    pub fn to_snapshot(&self) -> DkgSnapshot {
        let mut shares = BTreeMap::new();
        for (id, v) in &self.shares {
            shares.insert(*id as u32, big_hex(v));
        }
        let mut encrypted_shares = BTreeMap::new();
        for (dealer, bundle) in &self.encrypted_shares {
            let mut out = BTreeMap::new();
            for (rid, e) in bundle {
                out.insert(
                    *rid,
                    EncryptedShareHex {
                        nonce: bytes_hex(&e.nonce),
                        ciphertext: bytes_hex(&e.ciphertext),
                    },
                );
            }
            encrypted_shares.insert(*dealer, out);
        }
        let mut commitments_by_dealer_id = BTreeMap::new();
        for (dealer, pts) in &self.commitments_by_dealer {
            commitments_by_dealer_id.insert(
                *dealer,
                pts.iter()
                    .map(|p| [big_hex(&p.x), big_hex(&p.y)])
                    .collect::<Vec<_>>(),
            );
        }
        DkgSnapshot {
            version: SNAPSHOT_VERSION,
            name: self.name.clone(),
            key_agreement: Some(self.key_agreement.scheme().to_string()),
            secret_com_key: bytes_hex(&self.secret_com_key),
            participant_id: self.participant_id,
            roster: self
                .roster
                .iter()
                .map(|(id, k)| (*id, bytes_hex(k)))
                .collect(),
            keys_by_id: self
                .keys_by_id
                .iter()
                .map(|(id, k)| (*id, bytes_hex(k)))
                .collect(),
            shares,
            recipient_ids: self.recipient_ids.clone(),
            encrypted_shares,
            commitments_by_dealer_id,
            steps: DkgSteps {
                roster_assigned: self.roster_assigned,
                self_commitments_created: self.self_commitments_created,
                self_shares_encrypted: self.self_shares_encrypted,
                finalized: self.finalized,
            },
        }
    }

    /// `fromJSON` — restores a participant to the snapshot's exact state.
    ///
    /// The scheme comes from the snapshot; one written before that field
    /// existed is X25519, as in the TypeScript.
    pub fn from_snapshot(snapshot: &DkgSnapshot, rng: &'a mut dyn Rng) -> Result<Self> {
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(Error::new(format!(
                "unsupported DKG snapshot version: {}",
                snapshot.version
            )));
        }
        let scheme = snapshot.key_agreement.clone().unwrap_or_else(|| "x25519".to_string());
        let ka = crate::key_agreement::key_agreement_from_scheme(&scheme)?;
        let secret = parse_bytes_hex(&snapshot.secret_com_key)?;
        let mut p = Self::with_key_agreement(&snapshot.name, &secret, ka, rng)?;
        p.participant_id = snapshot.participant_id;
        for (id, hex) in &snapshot.roster {
            p.roster.insert(*id, parse_bytes_hex(hex)?);
        }
        for (id, hex) in &snapshot.keys_by_id {
            p.keys_by_id.insert(*id, parse_bytes_hex(hex)?);
        }
        for (id, hex) in &snapshot.shares {
            p.shares.insert(*id as i64, parse_big_hex(hex)?);
        }
        p.recipient_ids = snapshot.recipient_ids.clone();
        for (dealer, bundle) in &snapshot.encrypted_shares {
            let mut out = BTreeMap::new();
            for (rid, e) in bundle {
                out.insert(
                    *rid,
                    EncryptedShare {
                        nonce: parse_bytes_hex(&e.nonce)?,
                        ciphertext: parse_bytes_hex(&e.ciphertext)?,
                    },
                );
            }
            p.encrypted_shares.insert(*dealer, out);
        }
        for (dealer, pts) in &snapshot.commitments_by_dealer_id {
            let mut out = Vec::with_capacity(pts.len());
            for pt in pts {
                out.push(Point::new(parse_big_hex(&pt[0])?, parse_big_hex(&pt[1])?));
            }
            p.commitments_by_dealer.insert(*dealer, out);
        }
        p.roster_assigned = snapshot.steps.roster_assigned;
        p.self_commitments_created = snapshot.steps.self_commitments_created;
        p.self_shares_encrypted = snapshot.steps.self_shares_encrypted;
        p.finalized = snapshot.steps.finalized;
        Ok(p)
    }
}
