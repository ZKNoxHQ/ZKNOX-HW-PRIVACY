//! Port of `src/manager/participant.ts`: the call sequence of one DKG
//! participant, whatever runs it (software manager, hardware signer behind a
//! transport, remote process).
//!
//! The TypeScript lets every step return a value or a Promise so a device
//! round trip fits without making the software manager asynchronous. Rust has
//! no such duality in one trait: this is the synchronous contract, and an
//! asynchronous transport wraps it (block on the device call inside the
//! implementation, or mirror this trait with `async fn` in the caller's crate).

use std::collections::BTreeMap;

use num_bigint::BigInt;

use crate::curve::Point;
use crate::dkg::EncryptedShare;
use crate::error::Result;

/// `DKGFlowState` — linear view of where a participant stands, always derived
/// from the collected data, never tracked imperatively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DkgFlowState {
    /// `init`
    Init,
    /// `roster-assigned`
    RosterAssigned,
    /// `commitments-created`
    CommitmentsCreated,
    /// `commitments-collected`
    CommitmentsCollected,
    /// `shares-encrypted`
    SharesEncrypted,
    /// `encrypted-shares-collected`
    EncryptedSharesCollected,
    /// `finalized`
    Finalized,
}

impl DkgFlowState {
    /// The string the TypeScript enum carries, used in error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            DkgFlowState::Init => "init",
            DkgFlowState::RosterAssigned => "roster-assigned",
            DkgFlowState::CommitmentsCreated => "commitments-created",
            DkgFlowState::CommitmentsCollected => "commitments-collected",
            DkgFlowState::SharesEncrypted => "shares-encrypted",
            DkgFlowState::EncryptedSharesCollected => "encrypted-shares-collected",
            DkgFlowState::Finalized => "finalized",
        }
    }
}

/// `DKGCommitInput` — what every participant needs for its commitment round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DkgCommitInput {
    /// `desiredShares` (n).
    pub desired_shares: u32,
    /// `threshold` (t).
    pub threshold: u32,
}

/// `SoftwareCommitInput` — the software participant also brings its secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftwareCommitInput {
    /// Round parameters.
    pub base: DkgCommitInput,
    /// `secret` — dealer secret used as the constant polynomial term.
    pub secret: BigInt,
}

/// `DKGAnnouncement`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgAnnouncement {
    /// `pubKey` — public communication key under the ceremony's scheme.
    pub pub_key: Vec<u8>,
    /// `name`.
    pub name: String,
}

/// `DKGFinalized`. Secret fields are absent on a device that keeps its share.
#[derive(Clone, Debug)]
pub struct DkgFinalized {
    /// `share.id`.
    pub id: u32,
    /// `share.skShare`.
    pub sk_share: Option<BigInt>,
    /// `share.skShareDiv8`.
    pub sk_share_div8: Option<BigInt>,
    /// `PKGroup`.
    pub pk_group: Point,
    /// `viewingPrivateKey`.
    pub viewing_private_key: Vec<u8>,
}

/// `DKGParticipant<C>` — the fixed six-call sequence plus the derived state.
///
/// Semantics every implementation honours, as in the TypeScript:
/// - `commitment_round` produces and does not self-add; the caller feeds the
///   commitments back through `add_participant_commitments` under this
///   participant's own id, exactly as for a peer;
/// - `get_encrypted_shares` is legal only once every roster member's
///   commitments have been added, because the AAD binds the whole set;
/// - `finalize` is legal only once every bundle has been added, and verifies
///   each received share against its dealer's commitments before aggregating.
pub trait DkgParticipant {
    /// Commitment input this implementation expects.
    type CommitInput;

    /// `getAnnouncement`.
    fn get_announcement(&self) -> DkgAnnouncement;

    /// `assignRoster`.
    fn assign_roster(&mut self, roster: &BTreeMap<u32, Vec<u8>>) -> Result<()>;

    /// `commitmentRound`.
    fn commitment_round(&mut self, input: &Self::CommitInput) -> Result<Vec<Point>>;

    /// `addParticipantCommitments`.
    fn add_participant_commitments(
        &mut self,
        dealer_id: u32,
        commitments: &[Point],
    ) -> Result<()>;

    /// `getEncryptedShares`.
    fn get_encrypted_shares(&mut self) -> Result<BTreeMap<u32, EncryptedShare>>;

    /// `addEncryptedShares`.
    fn add_encrypted_shares(
        &mut self,
        dealer_id: u32,
        shares: &BTreeMap<u32, EncryptedShare>,
    ) -> Result<()>;

    /// `finalize`.
    fn finalize(&mut self) -> Result<DkgFinalized>;

    /// `getState`.
    fn get_state(&self) -> DkgFlowState;
}
