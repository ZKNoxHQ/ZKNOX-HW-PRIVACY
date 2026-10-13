//! Resumable DKG snapshot, the `DKGSnapshot` of `src/manager/dkg.ts`.
//!
//! JSON, hex-encoded, version 1: the same object a TypeScript `DKGManager`
//! writes with `toJSON()` and reads with `fromJSON()`, so a session started on
//! one side can be finished on the other. It carries the participant's secret
//! communication key and its decrypted local shares; treat it as secret.

use std::collections::BTreeMap;

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// `SNAPSHOT_VERSION` of `manager/dkg.ts`.
pub const SNAPSHOT_VERSION: u32 = 1;

/// `DKGSteps` — the steps this participant has itself performed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DkgSteps {
    /// `rosterAssigned`.
    pub roster_assigned: bool,
    /// `selfCommitmentsCreated`.
    pub self_commitments_created: bool,
    /// `selfSharesEncrypted`.
    pub self_shares_encrypted: bool,
    /// `finalized`.
    pub finalized: bool,
}

/// One encrypted share, hex-encoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedShareHex {
    /// `nonce`.
    pub nonce: String,
    /// `ciphertext`.
    pub ciphertext: String,
}

/// `DKGSnapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgSnapshot {
    /// `version`.
    pub version: u32,
    /// `name`.
    pub name: String,
    /// `keyAgreement` — absent in snapshots written before the field existed.
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<String>,
    /// `secretComKey`.
    #[serde(rename = "secretComKey")]
    pub secret_com_key: String,
    /// `participantID`.
    #[serde(rename = "participantID", skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<u32>,
    /// `roster`.
    pub roster: BTreeMap<u32, String>,
    /// `keysByID`.
    #[serde(rename = "keysByID")]
    pub keys_by_id: BTreeMap<u32, String>,
    /// `shares`.
    pub shares: BTreeMap<u32, String>,
    /// `recipientIds`.
    #[serde(rename = "recipientIds")]
    pub recipient_ids: Vec<u32>,
    /// `encryptedShares`.
    #[serde(rename = "encryptedShares")]
    pub encrypted_shares: BTreeMap<u32, BTreeMap<u32, EncryptedShareHex>>,
    /// `commitmentsByDealerId`, each point a `[x, y]` hex pair.
    #[serde(rename = "commitmentsByDealerId")]
    pub commitments_by_dealer_id: BTreeMap<u32, Vec<[String; 2]>>,
    /// `steps`.
    pub steps: DkgSteps,
}

/// `bigHex` — `'0x' + v.toString(16)`, no zero padding.
pub fn big_hex(v: &BigInt) -> String {
    format!("0x{:x}", v)
}

/// Parses a `bigHex` value.
pub fn parse_big_hex(s: &str) -> Result<BigInt> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    BigInt::parse_bytes(body.as_bytes(), 16)
        .ok_or_else(|| Error::new(format!("bad hex bigint: {s}")))
}

/// `bytesToHex`.
pub fn bytes_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `hexToBytes`.
pub fn parse_bytes_hex(s: &str) -> Result<Vec<u8>> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    if body.len() % 2 != 0 {
        return Err(Error::new(format!("bad hex bytes: {s}")));
    }
    (0..body.len() / 2)
        .map(|i| {
            u8::from_str_radix(&body[2 * i..2 * i + 2], 16)
                .map_err(|_| Error::new(format!("bad hex bytes: {s}")))
        })
        .collect()
}
