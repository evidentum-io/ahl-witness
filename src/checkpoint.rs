//! The signed AHL checkpoint object, its ATL binary form, and signature verification
//! (adaptor profile §6).
//!
//! A witness must reconstruct the *exact* 98-byte blob a log signed in order to check its
//! signature (adaptor profile §6.1, §6.5) — the same reconstruction `ahl-mirror` performs.
//! The two components MUST NOT disagree about these bytes, since a checkpoint the mirror
//! accepts as authenticated but the witness rejects (or vice versa) would itself be a kind
//! of split view.

use atl_core::core::merkle::Hash;
use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::error::{WitnessError, WitnessResult};

/// ATL's fixed 98-byte checkpoint magic (adaptor profile §6.1).
const CHECKPOINT_MAGIC: &[u8; 18] = b"ATL-Protocol-v1-CP";

/// The 98-byte signed checkpoint blob layout (adaptor profile §6.1).
const CHECKPOINT_BLOB_LEN: usize = 98;

/// A signed AHL checkpoint object (adaptor profile §6.2), field for field.
///
/// These six fields are also, exactly, the cosigned object of §11.1 — "contains exactly
/// `{log_id, tree_size, root_hash, checkpoint_time, key_id, signature}`... and nothing else" —
/// so a value of this type is by construction cosignable, and [`Checkpoint::cosigned`] maps it
/// onto [`ahl_core::CosignedCheckpoint`] without a decision of its own.
///
/// `deny_unknown_fields` is what makes that hold for material arriving from outside. Serde's
/// default is to deserialize past a member it does not know, which would let a submission
/// carrying `raw` — or anything else — be accepted, cosigned over six members, and returned to
/// a submitter who believes the witness signed what it sent. §11.1 makes any other checkpoint
/// member `invalid`, and silently dropping one is not a way of refusing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// `"sha256:" || hex(Origin ID)`.
    pub log_id: String,
    /// Number of entries this checkpoint commits, `[0, tree_size)`.
    pub tree_size: u64,
    /// `"sha256:" || hex(root)`.
    pub root_hash: String,
    /// The exact nine-fractional-digit RFC 3339 rendering of §6.3.
    pub checkpoint_time: String,
    /// `"sha256:" || hex(SHA-256(raw pubkey))` of the signing key.
    pub key_id: String,
    /// `"base64:" || base64(raw 64-byte Ed25519 signature)`.
    pub signature: String,
}

impl Checkpoint {
    /// This checkpoint as the six-member object a witness cosigns (adaptor profile §11.1).
    ///
    /// The single place the witness crosses into `ahl-core`'s cosignature preimage, so the
    /// bytes this witness signs and the bytes a verifier reconstructs come from one
    /// constructor. The round trip through JSON is what `ahl_core::CosignedCheckpoint::project`
    /// accepts; it cannot fail for a value of this type, whose fields ARE the six members, and
    /// the error is propagated rather than asserted away because a type is not a proof.
    ///
    /// # Errors
    ///
    /// [`WitnessError::Json`] if the value does not serialize, or [`WitnessError::Ahl`] if the
    /// projection rejects it.
    pub fn cosigned(&self) -> WitnessResult<ahl_core::CosignedCheckpoint> {
        Ok(ahl_core::CosignedCheckpoint::project(&serde_json::to_value(self)?)?)
    }
}

const CHECKPOINT_TIME_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:9]Z");

/// The literal layout adaptor profile §6.3 fixes, as a mask: `0` stands for "one ASCII
/// digit here", every other byte for itself.
const CHECKPOINT_TIME_MASK: &[u8] = b"0000-00-00T00:00:00.000000000Z";

/// Whether `value` has the exact byte layout of §6.3 — the same length, digits where §6.3
/// puts digits, and the same separators everywhere else.
///
/// Checked before `value` reaches a datetime parser, and not only as an optimisation: a
/// value whose fixed-width subsecond field is cut short by a non-digit drives the parser's
/// digit combinator into an underflowing subtraction, which aborts the process under
/// overflow checks. Nothing outside this layout is a §6.3 rendering, so rejecting it here
/// costs no accepted input.
fn has_profile_layout(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == CHECKPOINT_TIME_MASK.len()
        && bytes.iter().zip(CHECKPOINT_TIME_MASK).all(|(byte, mask)| {
            if *mask == b'0' {
                byte.is_ascii_digit()
            } else {
                byte == mask
            }
        })
}

/// Render a unix-nanosecond value in the exact form adaptor profile §6.3 requires.
///
/// # Errors
///
/// Returns [`WitnessError::BadCheckpointTime`] if `nanos` is outside the range a calendar
/// date can represent (it never is, for any value a real checkpoint carries).
pub fn render_checkpoint_time(nanos: u64) -> WitnessResult<String> {
    let dt = OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
        .map_err(|_| WitnessError::BadCheckpointTime { value: nanos.to_string() })?;
    dt.format(CHECKPOINT_TIME_FORMAT)
        .map_err(|_| WitnessError::BadCheckpointTime { value: nanos.to_string() })
}

/// Parse `checkpoint_time` to its exact unix-nanosecond value.
///
/// Rejects anything that is not exactly the rendering adaptor profile §6.3 specifies —
/// including a value that parses but whose canonical re-rendering differs from the input.
///
/// # Errors
///
/// Returns [`WitnessError::BadCheckpointTime`] if `value` does not parse, or does not
/// round-trip back to itself.
pub fn parse_checkpoint_time(value: &str) -> WitnessResult<u64> {
    let bad = || WitnessError::BadCheckpointTime { value: value.to_owned() };
    if !has_profile_layout(value) {
        return Err(bad());
    }
    let parsed = PrimitiveDateTime::parse(value, CHECKPOINT_TIME_FORMAT).map_err(|_| bad())?;
    let nanos = parsed.assume_utc().unix_timestamp_nanos();
    let nanos = u64::try_from(nanos).map_err(|_| bad())?;
    if render_checkpoint_time(nanos)? != value {
        return Err(bad());
    }
    Ok(nanos)
}

/// Assemble the 98-byte signed blob for `cp` (adaptor profile §6.1).
///
/// # Errors
///
/// Returns [`WitnessError::Ahl`] if `log_id` or `root_hash` are not well-formed
/// `sha256:<hex>` family strings, or [`WitnessError::BadCheckpointTime`] if
/// `checkpoint_time` is not the exact form §6.3 requires.
pub fn checkpoint_blob(cp: &Checkpoint) -> WitnessResult<[u8; CHECKPOINT_BLOB_LEN]> {
    let origin: Hash = ahl_core::parse_hash_hex(&cp.log_id)?;
    let root: Hash = ahl_core::parse_hash_hex(&cp.root_hash)?;
    let nanos = parse_checkpoint_time(&cp.checkpoint_time)?;

    let mut blob = [0u8; CHECKPOINT_BLOB_LEN];
    blob[0..18].copy_from_slice(CHECKPOINT_MAGIC);
    blob[18..50].copy_from_slice(&origin);
    blob[50..58].copy_from_slice(&cp.tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&nanos.to_le_bytes());
    blob[66..98].copy_from_slice(&root);
    Ok(blob)
}

/// Verify `cp`'s identity and signature against a specific, already-resolved key (adaptor
/// profile §6.5, steps 1-5).
///
/// This function performs no key *resolution* — see [`crate::governance`] for that — and no
/// series-level checks; see [`crate::witness::witness_checkpoint`] for the full pipeline.
///
/// If `raw` is given, it is checked byte for byte against the assembled blob first (§6.4).
///
/// # Errors
///
/// [`WitnessError::WrongLogId`], [`WitnessError::RawBlobMismatch`],
/// [`WitnessError::SignatureInvalid`], or a parsing error from [`checkpoint_blob`].
pub fn verify_checkpoint_signature(
    cp: &Checkpoint,
    raw: Option<&[u8]>,
    log_id: &str,
    key: &ed25519_dalek::VerifyingKey,
) -> WitnessResult<()> {
    if cp.log_id != log_id {
        return Err(WitnessError::WrongLogId {
            expected: log_id.to_owned(),
            got: cp.log_id.clone(),
        });
    }
    let blob = checkpoint_blob(cp)?;
    if let Some(raw) = raw {
        if raw != blob {
            return Err(WitnessError::RawBlobMismatch);
        }
    }
    if !ahl_core::verify_signature(key, &blob, &cp.signature)? {
        return Err(WitnessError::SignatureInvalid { key_id: cp.key_id.clone() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_checkpoint(
        key: &ahl_core::TestKey,
        log_id: &str,
        tree_size: u64,
        root_hash: &str,
        checkpoint_time: &str,
    ) -> Checkpoint {
        let mut cp = Checkpoint {
            log_id: log_id.to_owned(),
            tree_size,
            root_hash: root_hash.to_owned(),
            checkpoint_time: checkpoint_time.to_owned(),
            key_id: key.key_id(),
            signature: String::new(),
        };
        let blob = checkpoint_blob(&cp).expect("well-formed fields");
        cp.signature = key.sign(&blob);
        cp
    }

    #[test]
    fn checkpoint_time_matches_the_profile_worked_example() {
        let nanos = 1_767_225_600_123_456_789u64;
        let rendered = render_checkpoint_time(nanos).expect("in-range value");
        assert_eq!(rendered, "2026-01-01T00:00:00.123456789Z");
        assert_eq!(parse_checkpoint_time(&rendered).expect("well-formed"), nanos);
    }

    #[test]
    fn checkpoint_time_round_trips_at_the_epoch_and_with_trailing_zeros() {
        assert_eq!(render_checkpoint_time(0).expect("epoch"), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(parse_checkpoint_time("1970-01-01T00:00:00.000000000Z").expect("epoch"), 0);
    }

    /// A non-digit inside the fixed-width subsecond field, which used to reach the datetime
    /// parser's digit combinator and abort there on a subtraction overflow. Found by the
    /// `checkpoint` fuzz target and reachable from a submitted checkpoint's
    /// `checkpoint_time`, so it is a rejection, not an abort. The second case is the shape
    /// the `witness_request` target reached the same site with.
    #[test]
    fn a_non_digit_inside_the_subsecond_field_is_rejected() {
        assert!(parse_checkpoint_time("2026-01-01T00:00:00.00000/0000Z").is_err());
        assert!(parse_checkpoint_time("2026-01-01T00:00:00.000+000000Z").is_err());
    }

    #[test]
    fn checkpoint_times_outside_the_profile_layout_are_rejected() {
        // Right length, wrong separators.
        assert!(parse_checkpoint_time("2026-01-01 00:00:00.000000000Z").is_err());
        assert!(parse_checkpoint_time("2026/01/01T00:00:00.000000000z").is_err());
        // A trailing offset instead of `Z`, and a value that is simply too long.
        assert!(parse_checkpoint_time("2026-01-01T00:00:00.000000000+00:00").is_err());
        assert!(parse_checkpoint_time("").is_err());
    }

    #[test]
    fn truncated_or_malformed_checkpoint_times_are_rejected() {
        assert!(parse_checkpoint_time("2026-01-01T00:00:00.123Z").is_err());
        assert!(parse_checkpoint_time("2026-01-01T00:00:00Z").is_err());
        assert!(parse_checkpoint_time("not-a-time").is_err());
    }

    #[test]
    fn blob_assembly_matches_the_documented_layout() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"01".repeat(32)).expect("seed");
        let cp = signed_checkpoint(
            &key,
            &format!("sha256:{}", "22".repeat(32)),
            10,
            &format!("sha256:{}", "33".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        let blob = checkpoint_blob(&cp).expect("well-formed");
        assert_eq!(&blob[0..18], CHECKPOINT_MAGIC);
        assert_eq!(&blob[18..50], [0x22u8; 32]);
        assert_eq!(&blob[50..58], 10u64.to_le_bytes());
        assert_eq!(&blob[66..98], [0x33u8; 32]);
    }

    #[test]
    fn a_correctly_signed_checkpoint_verifies() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"04".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "55".repeat(32));
        let cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "66".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        verify_checkpoint_signature(&cp, None, &log_id, &key.verifying_key())
            .expect("valid signature and log_id");
    }

    #[test]
    fn a_wrong_log_id_is_rejected() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"05".repeat(32)).expect("seed");
        let cp = signed_checkpoint(
            &key,
            &format!("sha256:{}", "aa".repeat(32)),
            10,
            &format!("sha256:{}", "bb".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        let other_log_id = format!("sha256:{}", "cc".repeat(32));
        assert!(matches!(
            verify_checkpoint_signature(&cp, None, &other_log_id, &key.verifying_key()),
            Err(WitnessError::WrongLogId { .. })
        ));
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"08".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "ff".repeat(32));
        let mut cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "11".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        cp.tree_size = 11;
        assert!(matches!(
            verify_checkpoint_signature(&cp, None, &log_id, &key.verifying_key()),
            Err(WitnessError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn a_mismatched_raw_blob_is_rejected() {
        let key = ahl_core::TestKey::from_seed_hex("log-1", &"09".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "12".repeat(32));
        let cp = signed_checkpoint(
            &key,
            &log_id,
            10,
            &format!("sha256:{}", "13".repeat(32)),
            "2026-01-01T00:00:00.000000000Z",
        );
        let bad_raw = [0u8; CHECKPOINT_BLOB_LEN];
        assert!(matches!(
            verify_checkpoint_signature(&cp, Some(&bad_raw), &log_id, &key.verifying_key()),
            Err(WitnessError::RawBlobMismatch)
        ));
    }
}
