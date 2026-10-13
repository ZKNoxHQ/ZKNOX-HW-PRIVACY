//! Port of `src/manager/ceremony.ts` (`runCeremony`, MR !11).

use std::collections::BTreeMap;

use crate::curve::Point;
use crate::dkg::EncryptedShare;
use crate::error::{Error, Result};
use crate::participant::{DkgFinalized, DkgFlowState, DkgParticipant};

/// `CeremonyTrace` — everything one DKG round produced, keyed by participant
/// identifier where a per-participant artefact is meant.
#[derive(Debug)]
pub struct CeremonyTrace {
    /// `roster` — participant id to public communication key.
    pub roster: BTreeMap<u32, Vec<u8>>,
    /// `commitments` — participant id to the commitment vector it dealt.
    pub commitments: BTreeMap<u32, Vec<Point>>,
    /// `bundles` — dealer id to its encrypted bundle (recipient id to share).
    pub bundles: BTreeMap<u32, BTreeMap<u32, EncryptedShare>>,
    /// `results` — finalized results, in participant order.
    pub results: Vec<DkgFinalized>,
}

fn expect_state<P: DkgParticipant + ?Sized>(p: &P, id: u32, expected: DkgFlowState) -> Result<()> {
    let actual = p.get_state();
    if actual != expected {
        return Err(Error::new(format!(
            "participant {id} is in state \"{}\", expected \"{}\"",
            actual.as_str(),
            expected.as_str()
        )));
    }
    Ok(())
}

/// `runCeremony` — one DKG round over a roster held in one process, in the
/// order the contract fixes: announce, assign the roster, commit, exchange the
/// commitments, encrypt the shares, exchange the bundles, finalize.
///
/// Identifiers are positions in `participants` plus one; `inputs[i]` is the
/// commitment input of `participants[i]`. Every participant's state is checked
/// after every step, so an implementation that self-adds its commitments or
/// encrypts before the commitment set is frozen fails here with its id.
pub fn run_ceremony<P>(participants: &mut [P], inputs: &[P::CommitInput]) -> Result<CeremonyTrace>
where
    P: DkgParticipant,
{
    if participants.is_empty() {
        return Err(Error::new("runCeremony: empty roster"));
    }
    if inputs.len() != participants.len() {
        return Err(Error::new(format!(
            "runCeremony: {} participants but {} inputs",
            participants.len(),
            inputs.len()
        )));
    }
    let ids: Vec<u32> = (1..=participants.len() as u32).collect();

    let mut roster: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for (i, p) in participants.iter().enumerate() {
        roster.insert(ids[i], p.get_announcement().pub_key);
    }
    for (i, p) in participants.iter_mut().enumerate() {
        p.assign_roster(&roster)?;
        expect_state(p, ids[i], DkgFlowState::RosterAssigned)?;
    }

    let mut commitments: BTreeMap<u32, Vec<Point>> = BTreeMap::new();
    for (i, p) in participants.iter_mut().enumerate() {
        commitments.insert(ids[i], p.commitment_round(&inputs[i])?);
        expect_state(p, ids[i], DkgFlowState::CommitmentsCreated)?;
    }
    for (i, p) in participants.iter_mut().enumerate() {
        for id in &ids {
            p.add_participant_commitments(*id, &commitments[id])?;
        }
        expect_state(p, ids[i], DkgFlowState::CommitmentsCollected)?;
    }

    let mut bundles: BTreeMap<u32, BTreeMap<u32, EncryptedShare>> = BTreeMap::new();
    for (i, p) in participants.iter_mut().enumerate() {
        bundles.insert(ids[i], p.get_encrypted_shares()?);
    }
    for (i, p) in participants.iter_mut().enumerate() {
        for id in &ids {
            p.add_encrypted_shares(*id, &bundles[id])?;
        }
        expect_state(p, ids[i], DkgFlowState::EncryptedSharesCollected)?;
    }

    let mut results = Vec::with_capacity(participants.len());
    for (i, p) in participants.iter_mut().enumerate() {
        results.push(p.finalize()?);
        expect_state(p, ids[i], DkgFlowState::Finalized)?;
    }

    Ok(CeremonyTrace {
        roster,
        commitments,
        bundles,
        results,
    })
}
