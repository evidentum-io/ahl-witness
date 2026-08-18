//! The core spec §3.3 witness state machine.
//!
//! ```text
//! 1. Witness retains, per log, the latest checkpoint it has cosigned.
//! 2. On receiving a new checkpoint: verify the log's signature; verify a consistency proof
//!    from the retained checkpoint; on success, cosign, retain, and publish.
//! 3. On failure — inconsistency or missing proof — MUST refuse to cosign and MUST publish
//!    signed refusal evidence containing both conflicting checkpoints.
//! 4. Freshness: a witness whose latest cosigned checkpoint is older than the declared
//!    cadence by more than the declared grace period is stale; verifiers treat staleness as
//!    a finding.
//! ```
//!
//! Core spec §3.3 also states, normatively, the **"obligations that make the machine
//! sound"** this module is built around (commit `92f8fc4`):
//!
//! - **Compare against the whole retained history, not the newest member.** An offered
//!   checkpoint whose `(log_id, tree_size)` matches one already cosigned with a different
//!   `root_hash` is equivocation, whatever its size relative to the newest retained member.
//!   [`witness_checkpoint`] queries the crate-private `store::find_cosigned_at_size` for the
//!   *exact* offered size, every time, before falling back to comparing against only the
//!   latest retained checkpoint.
//! - **Serialize and make atomic.** The retain–verify–classify–cosign transition MUST be
//!   serialized per log and atomic; state MUST be re-read inside the critical section, and an
//!   equivocation record MUST be persisted in the same atomic step as the refusal it
//!   justifies. See the crate-private `Store::with_lock` and the module docs of
//!   [`crate::store`].
//! - **Equivocation is permanent for that log.** A later well-formed checkpoint does not
//!   clear an equivocation record, and cosigning MUST NOT resume past a recorded floor.
//! - **Every refusal reason MUST be independently checkable** from the evidence it carries; a
//!   reason whose verification procedure is undefined MUST NOT be emitted. See "Refusal
//!   reason taxonomy" below and [`verify_refusal_claim`].
//! - **Grace resolves like cadence**: `witness_grace_period` is taken from the manifest
//!   version governing the checkpoint in question, never the newest version — this crate
//!   already stores cadence and grace alongside each cosigned checkpoint at cosign time (see
//!   [`crate::store::RetainedCheckpoint`]), which is exactly this rule.
//!
//! # Authentication failures are not refusal evidence
//!
//! Adaptor profile §11.2 rule 2 requires refusal evidence to carry **two validly signed**
//! checkpoints ("an unsigned or badly signed checkpoint proves nothing about the log").
//! A candidate that never authenticates at all — unresolvable governance, a signature that
//! does not verify, a key used outside its validity window — is therefore not a "checkpoint
//! the log offered" in the protocol's sense; there is nothing to pair it with in refusal
//! evidence, and [`witness_checkpoint`] reports it as an ordinary [`WitnessError`] instead.
//!
//! # Bootstrap refusal carries no evidence (core spec §3.3, confirmed)
//!
//! "Before a first checkpoint is retained there is no partner to pair with, so a refusal at
//! bootstrap carries no two-checkpoint evidence and MUST be reported as such rather than
//! fabricating a partner." [`witness_checkpoint`] reports a bad first checkpoint as
//! [`WitnessError::CheckpointRootMismatch`] — a hard error, not [`WitnessOutcome::Refused`] —
//! for exactly this reason.
//!
//! # Refusal reason taxonomy
//!
//! [`RefusalReason`] has exactly three members, each independently checkable from the
//! evidence its refusal carries without trusting this witness's classification:
//!
//! | reason | when | what a verifier rechecks |
//! | --- | --- | --- |
//! | `equivocation` | `retained`/`offered` share a `tree_size` with different `root_hash` (found either at the offered size directly, or — once found once — cited again for every later candidate while the log's floor stands) | `retained.tree_size == offered.tree_size && retained.root_hash != offered.root_hash` |
//! | `size-regression` | `offered.tree_size` is smaller than an already-cosigned size, and no history entry exists at the offered size itself | `offered.tree_size < retained.tree_size` |
//! | `extension-failed` | `offered.tree_size > retained.tree_size` and a consistency proof was generated but does not verify | reconstruct `consistency_proof` and rerun RFC 9162 verification against the two carried roots — see [`crate::consistency::verify_extension_failure`] |
//!
//! `missing-consistency-proof` (adaptor profile §11.2's other named reason) is deliberately
//! **not** part of this taxonomy: this crate always supplies the complete
//! `[0, offered.tree_size)` entry range before classifying anything (adaptor profile §10.6),
//! so a consistency proof between two sizes it already holds can only fail to *generate* for
//! reasons that are not claims about the log's checkpoints and are therefore not
//! independently checkable from carried evidence — see [`crate::consistency`]'s module docs.
//! Such a failure is propagated as a [`WitnessError`], not emitted as a refusal reason.

use atl_core::core::merkle::{compute_root, Hash};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::checkpoint::{verify_checkpoint_signature, Checkpoint};
use crate::config::{LogAnchor, WitnessSigner};
use crate::consistency::{self, ConsistencyOutcome, ConsistencyProofEvidence};
use crate::error::{WitnessError, WitnessResult};
use crate::governance::{self, GovernanceState};
use crate::metadata::log_leaf_hash;
use crate::store::{self, Store};

/// A checkpoint this witness has cosigned (adaptor profile §11.1).
///
/// Deliberately **not** flattened: `checkpoint` carries its own `key_id` (the log's signing
/// key) and this struct's own `key_id` names the witness's signing key — merging the two
/// into one JSON object would silently collide the two meanings under one name. Nesting also
/// matches the profile's own cosigned-bytes construction directly: `JCS({ "checkpoint": <the
/// signed checkpoint, including its own "signature">, "witness_id": <id> })` (§11.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosignedCheckpoint {
    /// The checkpoint the log signed.
    pub checkpoint: Checkpoint,
    /// This witness's identifier.
    pub witness_id: String,
    /// This witness's signing key id.
    pub key_id: String,
    /// `"base64:" || base64(raw 64-byte Ed25519 signature)` over the cosigned bytes of
    /// adaptor profile §11.1.
    pub cosignature: String,
    /// When this witness cosigned, as RFC 3339.
    pub cosigned_at: String,
}

/// Why a witness refused to cosign. See the module docs, "Refusal reason taxonomy", for what
/// each variant means and how a verifier independently rechecks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalReason {
    /// `retained` and `offered` share a `tree_size` with a different `root_hash`.
    Equivocation,
    /// `offered.tree_size` is smaller than an already-cosigned size, with no history entry at
    /// the offered size itself.
    SizeRegression,
    /// `offered.tree_size > retained.tree_size` and the consistency proof between them,
    /// carried in the refusal, was generated but did not verify.
    ExtensionFailed,
}

/// Signed refusal evidence (adaptor profile §11.2): self-authenticating, not an AHL
/// statement, not anchored, carries no envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalEvidence {
    /// Always `"witness-refusal"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// This witness's identifier.
    pub witness_id: String,
    /// The log the conflicting checkpoints claim to belong to.
    pub log_id: String,
    /// Why cosigning was refused.
    pub reason: RefusalReason,
    /// The checkpoint this witness had already cosigned (or, for `reason: Equivocation`
    /// citing a standing floor, the original conflicting pair's first member).
    pub retained: Checkpoint,
    /// The checkpoint this witness refused (or, for `reason: Equivocation` citing a standing
    /// floor, the original conflicting pair's second member — not necessarily the candidate
    /// that triggered *this* refusal; see `detail`).
    pub offered: Checkpoint,
    /// The consistency proof that was generated and failed to verify — present if and only
    /// if `reason == ExtensionFailed`, so a verifier can rerun the same check (see
    /// [`crate::consistency::verify_extension_failure`]).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub consistency_proof: Option<ConsistencyProofEvidence>,
    /// Informative text; never normative.
    pub detail: String,
    /// When this witness refused, as RFC 3339.
    pub refused_at: String,
    /// This witness's signing key id.
    pub key_id: String,
    /// `"base64:" || base64(raw 64-byte Ed25519 signature)` over `JCS(this object with
    /// `signature` removed)`.
    pub signature: String,
}

/// The outcome of running the state machine on one candidate checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessOutcome {
    /// The candidate was consistent with the retained checkpoint (or is the first ever
    /// witnessed for this log) and has been cosigned and retained.
    Cosigned(Box<CosignedCheckpoint>),
    /// The candidate conflicted with the retained checkpoint; it was not cosigned, and
    /// signed refusal evidence was published instead.
    Refused(Box<RefusalEvidence>),
}

/// Render a unix-nanosecond instant as a plain RFC 3339 timestamp (adaptor profile §11.1's
/// `cosigned_at` / §11.2's `refused_at` — unlike [`crate::checkpoint::render_checkpoint_time`],
/// these carry no fixed fractional-digit requirement).
fn render_rfc3339(now_nanos: u64) -> WitnessResult<String> {
    let dt = OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_nanos))
        .map_err(|_| WitnessError::BadCheckpointTime { value: now_nanos.to_string() })?;
    dt.format(&Rfc3339)
        .map_err(|_| WitnessError::BadCheckpointTime { value: now_nanos.to_string() })
}

/// Which refusal reason to build, and the reason-specific evidence it carries. Bundled so
/// [`refuse_conn`] stays at (and not over) `clippy::too_many_arguments`'s threshold.
enum RefusalKind {
    Equivocation,
    SizeRegression,
    ExtensionFailed(ConsistencyProofEvidence),
}

fn cosign_conn(
    conn: &Connection,
    signer: &dyn WitnessSigner,
    governance: &GovernanceState,
    candidate: &Checkpoint,
    now_rfc3339: &str,
) -> WitnessResult<WitnessOutcome> {
    let checkpoint_value = serde_json::to_value(candidate)?;
    let bytes = ahl_core::cosignature_bytes(&checkpoint_value, signer.witness_id());
    let cosigned = CosignedCheckpoint {
        checkpoint: candidate.clone(),
        witness_id: signer.witness_id().to_owned(),
        key_id: signer.key_id(),
        cosignature: signer.sign(&bytes),
        cosigned_at: now_rfc3339.to_owned(),
    };
    store::insert_cosigned(
        conn,
        &cosigned,
        governance.cadence_nanos(),
        governance.witness_grace_period_nanos(),
    )?;
    Ok(WitnessOutcome::Cosigned(Box::new(cosigned)))
}

fn build_refusal_evidence(
    signer: &dyn WitnessSigner,
    retained: &Checkpoint,
    offered: &Checkpoint,
    kind: &RefusalKind,
    detail: &str,
    now_rfc3339: &str,
) -> WitnessResult<RefusalEvidence> {
    let (reason, consistency_proof) = match kind {
        RefusalKind::Equivocation => (RefusalReason::Equivocation, None),
        RefusalKind::SizeRegression => (RefusalReason::SizeRegression, None),
        RefusalKind::ExtensionFailed(proof) => {
            (RefusalReason::ExtensionFailed, Some(proof.clone()))
        }
    };
    let mut evidence = RefusalEvidence {
        kind: "witness-refusal".to_owned(),
        witness_id: signer.witness_id().to_owned(),
        log_id: offered.log_id.clone(),
        reason,
        retained: retained.clone(),
        offered: offered.clone(),
        consistency_proof,
        detail: detail.to_owned(),
        refused_at: now_rfc3339.to_owned(),
        key_id: signer.key_id(),
        signature: String::new(),
    };
    let bytes = refusal_signing_bytes(&evidence)?;
    evidence.signature = signer.sign(&bytes);
    Ok(evidence)
}

/// Sign and persist refusal evidence that does **not** itself establish a new equivocation
/// floor (`size-regression`, `extension-failed`, or an `equivocation` citing an
/// already-recorded floor). For a *fresh* equivocation discovery, see
/// [`record_equivocation_and_refuse_conn`], which persists the floor and the refusal
/// together, atomically.
fn refuse_conn(
    conn: &Connection,
    signer: &dyn WitnessSigner,
    retained: &Checkpoint,
    offered: &Checkpoint,
    kind: &RefusalKind,
    detail: &str,
    now_rfc3339: &str,
) -> WitnessResult<WitnessOutcome> {
    let evidence = build_refusal_evidence(signer, retained, offered, kind, detail, now_rfc3339)?;
    store::insert_refusal(conn, &evidence)?;
    Ok(WitnessOutcome::Refused(Box::new(evidence)))
}

/// Sign and persist a *fresh* equivocation discovery: the floor row and the refusal evidence
/// that justifies it are written in one `SQLite` transaction (core spec §3.3: "an equivocation
/// record MUST be persisted in the same atomic step as the refusal it justifies").
///
/// `tree_size` is the shared size at which `checkpoint_a` and `checkpoint_b` conflict; the
/// log id is taken from `checkpoint_b.log_id` (both checkpoints' log ids are already
/// established as equal to the configured anchor by this point, so naming it separately
/// would be redundant — and is what would tip this function over
/// `clippy::too_many_arguments`).
fn record_equivocation_and_refuse_conn(
    conn: &Connection,
    signer: &dyn WitnessSigner,
    tree_size: u64,
    checkpoint_a: &Checkpoint,
    checkpoint_b: &Checkpoint,
    now_rfc3339: &str,
) -> WitnessResult<WitnessOutcome> {
    let detail = format!(
        "equivocation: two authenticated checkpoints share tree_size {tree_size} with \
         different root_hash values"
    );
    let evidence = build_refusal_evidence(
        signer,
        checkpoint_a,
        checkpoint_b,
        &RefusalKind::Equivocation,
        &detail,
        now_rfc3339,
    )?;
    store::insert_equivocation_and_refusal(
        conn,
        &evidence.log_id,
        tree_size,
        now_rfc3339,
        &evidence,
    )?;
    Ok(WitnessOutcome::Refused(Box::new(evidence)))
}

/// `JCS(evidence with "signature" removed)` — what a witness signs over refusal evidence
/// (adaptor profile §11.2).
///
/// # Errors
///
/// Propagates a serialization failure (unreachable for a well-formed [`RefusalEvidence`]).
pub fn refusal_signing_bytes(evidence: &RefusalEvidence) -> WitnessResult<Vec<u8>> {
    let mut value = serde_json::to_value(evidence)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
    }
    Ok(ahl_core::jcs(&value))
}

/// Verify a witness cosignature (adaptor profile §11.1) against a specific, already-resolved
/// witness key.
///
/// # Errors
///
/// Propagates a serialization failure (unreachable for a well-formed [`CosignedCheckpoint`])
/// or a malformed `cosignature` string.
pub fn verify_cosignature(
    cosigned: &CosignedCheckpoint,
    witness_key: &ed25519_dalek::VerifyingKey,
) -> WitnessResult<bool> {
    let checkpoint_value = serde_json::to_value(&cosigned.checkpoint)?;
    let bytes = ahl_core::cosignature_bytes(&checkpoint_value, &cosigned.witness_id);
    Ok(ahl_core::verify_signature(witness_key, &bytes, &cosigned.cosignature)?)
}

/// Verify the witness signature on refusal evidence (adaptor profile §11.2 check 1) against a
/// specific, already-resolved witness key.
///
/// This checks only the witness's own signature — it does not re-derive the refusal's
/// *claim* (see [`verify_refusal_claim`] for that) or re-verify the log signatures on
/// `retained`/`offered` (§11.2 check 2), which require the governing manifest's log key set
/// and are the caller's responsibility (see [`crate::governance`]).
///
/// # Errors
///
/// Propagates a serialization failure (unreachable for well-formed evidence) or a malformed
/// `signature` string.
pub fn verify_refusal_signature(
    evidence: &RefusalEvidence,
    witness_key: &ed25519_dalek::VerifyingKey,
) -> WitnessResult<bool> {
    let bytes = refusal_signing_bytes(evidence)?;
    Ok(ahl_core::verify_signature(witness_key, &bytes, &evidence.signature)?)
}

/// Independently recheck a [`RefusalEvidence`]'s **claim**, purely from the evidence it
/// carries, without trusting this witness's classification.
///
/// Core spec §3.3: "every refusal reason MUST be independently checkable from the evidence
/// it carries." This is separate from [`verify_refusal_signature`], which only checks that
/// this witness signed the evidence; a complete check runs both, plus §11.2's own check 2
/// (the log signatures on `retained`/`offered`), which needs the governing manifest and is
/// therefore the caller's responsibility.
///
/// # Errors
///
/// Propagates a parsing error from a malformed carried hash (`reason: ExtensionFailed`).
pub fn verify_refusal_claim(evidence: &RefusalEvidence) -> WitnessResult<bool> {
    match evidence.reason {
        RefusalReason::Equivocation => Ok(evidence.retained.tree_size
            == evidence.offered.tree_size
            && evidence.retained.root_hash != evidence.offered.root_hash),
        RefusalReason::SizeRegression => {
            Ok(evidence.offered.tree_size < evidence.retained.tree_size)
        }
        RefusalReason::ExtensionFailed => {
            let Some(proof) = &evidence.consistency_proof else { return Ok(false) };
            if evidence.offered.tree_size <= evidence.retained.tree_size {
                return Ok(false);
            }
            consistency::verify_extension_failure(
                proof,
                &evidence.retained.root_hash,
                &evidence.offered.root_hash,
            )
        }
    }
}

/// Run the core spec §3.3 state machine on one candidate checkpoint.
///
/// `entries_prefix` MUST cover `[0, candidate.tree_size)` exactly — adaptor profile §10.6:
/// under this profile, enumerated governance requires the full range, since no typed-subset
/// proof exists to prove a shorter set is complete. Governance is resolved from it against
/// `anchor` ([`crate::governance`]), and the candidate's signature is verified against the
/// resolved, activation-bound signing key
/// ([`crate::checkpoint::verify_checkpoint_signature`]) — both pure, store-independent
/// computations, performed before the store is ever touched. Everything from there on —
/// every read this decision depends on, and the write it produces — runs inside one
/// `Store::with_lock` critical section (see the crate-private `transition` function and the
/// module docs, "serialize and make atomic").
///
/// # Errors
///
/// [`WitnessError::IncompleteEntries`], [`WitnessError::GovernanceChainUnresolvable`], a
/// checkpoint-authentication error from [`crate::checkpoint::verify_checkpoint_signature`],
/// [`WitnessError::CheckpointRootMismatch`] for a bad bootstrap checkpoint (see the module
/// docs, "Bootstrap refusal carries no evidence"), or a propagated error from
/// [`crate::consistency::check`] if a consistency proof cannot be generated at all (should not
/// arise given `entries_prefix`'s completeness invariant; see [`crate::consistency`]).
pub fn witness_checkpoint(
    store: &Store,
    signer: &dyn WitnessSigner,
    anchor: &LogAnchor,
    candidate: &Checkpoint,
    raw: Option<&[u8]>,
    entries_prefix: &[Vec<u8>],
    now_nanos: u64,
) -> WitnessResult<WitnessOutcome> {
    let have = u64::try_from(entries_prefix.len())
        .map_err(|_| WitnessError::IndexOverflow { what: "entries_prefix.len()" })?;
    if have != candidate.tree_size {
        return Err(WitnessError::IncompleteEntries { have, need: candidate.tree_size });
    }

    // Authentication touches only `entries_prefix` and `anchor` — pure, store-independent —
    // so it is safe and correct to perform before acquiring the store's lock.
    let governance = governance::resolve(entries_prefix, anchor)?;
    let key = governance.resolve_log_key(&candidate.key_id, candidate.tree_size)?;
    verify_checkpoint_signature(candidate, raw, &anchor.log_id, key)?;

    let leaf_hashes: Vec<Hash> = entries_prefix.iter().map(|b| log_leaf_hash(b)).collect();
    let now_rfc3339 = render_rfc3339(now_nanos)?;

    store.with_lock(|conn| {
        transition(conn, signer, &governance, candidate, &leaf_hashes, &now_rfc3339)
    })
}

/// The atomic body of [`witness_checkpoint`]: every read this decision depends on, and the
/// resulting write, run against the same `conn` inside the caller's single lock acquisition.
fn transition(
    conn: &Connection,
    signer: &dyn WitnessSigner,
    governance: &GovernanceState,
    candidate: &Checkpoint,
    leaf_hashes: &[Hash],
    now_rfc3339: &str,
) -> WitnessResult<WitnessOutcome> {
    let log_id = &candidate.log_id;

    // Core spec §3.3: equivocation is permanent. Re-read the floor inside this same critical
    // section — never trust a value read before the lock was (re)acquired.
    if let Some(floor) = store::equivocation_floor(conn, log_id)? {
        let (original_retained, original_offered) =
            store::original_equivocation_pair(conn, log_id)?.ok_or_else(|| {
                WitnessError::StoreInit(
                    "equivocation floor recorded with no evidence pair".to_owned(),
                )
            })?;
        let detail = format!(
            "log equivocated at tree_size {floor}; candidate at tree_size {} refused without \
             further evaluation",
            candidate.tree_size
        );
        return refuse_conn(
            conn,
            signer,
            &original_retained,
            &original_offered,
            &RefusalKind::Equivocation,
            &detail,
            now_rfc3339,
        );
    }

    // Core spec §3.3: "compare against the whole retained history, not the newest member."
    if let Some(existing) = store::find_cosigned_at_size(conn, log_id, candidate.tree_size)? {
        let existing_checkpoint = existing.cosigned.checkpoint;
        if existing_checkpoint.root_hash == candidate.root_hash {
            // The exact checkpoint this witness already cosigned, resubmitted: idempotent.
            return cosign_conn(conn, signer, governance, candidate, now_rfc3339);
        }
        return record_equivocation_and_refuse_conn(
            conn,
            signer,
            candidate.tree_size,
            &existing_checkpoint,
            candidate,
            now_rfc3339,
        );
    }

    match store::get_retained(conn, log_id)? {
        None => {
            let root = compute_root(leaf_hashes);
            let candidate_root = ahl_core::parse_hash_hex(&candidate.root_hash)?;
            if root != candidate_root {
                return Err(WitnessError::CheckpointRootMismatch {
                    tree_size: candidate.tree_size,
                });
            }
            cosign_conn(conn, signer, governance, candidate, now_rfc3339)
        }
        Some(retained) => {
            let retained_checkpoint = retained.cosigned.checkpoint;
            match consistency::check(&retained_checkpoint, candidate, leaf_hashes)? {
                ConsistencyOutcome::Consistent => {
                    cosign_conn(conn, signer, governance, candidate, now_rfc3339)
                }
                // Unreachable via this call site in practice: `find_cosigned_at_size` above
                // already inspects the very row `retained` would be if the sizes matched, so
                // an equal-size mismatch can never survive to here. Handled identically
                // anyway, defensively, rather than assumed impossible.
                ConsistencyOutcome::Equivocation => record_equivocation_and_refuse_conn(
                    conn,
                    signer,
                    candidate.tree_size,
                    &retained_checkpoint,
                    candidate,
                    now_rfc3339,
                ),
                ConsistencyOutcome::SizeRegression => refuse_conn(
                    conn,
                    signer,
                    &retained_checkpoint,
                    candidate,
                    &RefusalKind::SizeRegression,
                    "offered checkpoint's tree_size is smaller than an already-cosigned one, \
                     and no prior cosigned checkpoint exists at the offered size itself",
                    now_rfc3339,
                ),
                ConsistencyOutcome::ExtensionFailed(proof) => refuse_conn(
                    conn,
                    signer,
                    &retained_checkpoint,
                    candidate,
                    &RefusalKind::ExtensionFailed(proof),
                    "a consistency proof from the retained checkpoint to the offered one was \
                     generated but did not verify",
                    now_rfc3339,
                ),
            }
        }
    }
}

/// The published view of a log's cosigned checkpoint state (core spec §7.3, "Equivocation
/// ends the series"; §3.3's verifier algorithm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishedCheckpoint {
    /// The latest cosigned checkpoint, safe to present as canonical.
    Checkpoint(Box<CosignedCheckpoint>),
    /// This log has equivocated from `floor_tree_size` onward; no checkpoint at or beyond it
    /// may be presented as canonical, however validly any one of them was itself cosigned
    /// before the divergence was found.
    Equivocated {
        /// The lowest `tree_size` at which conflicting roots were observed.
        floor_tree_size: u64,
    },
    /// No checkpoint has ever been cosigned for this log.
    None,
}

/// Compute the read-side [`PublishedCheckpoint`] view for `log_id`.
///
/// A read interface (see [`crate::http`]) MUST use this instead of unconditionally returning
/// the latest retained row, so that a log which has equivocated is reported as such rather
/// than having one of its conflicting branches served as if still canonical.
///
/// # Errors
///
/// Returns [`WitnessError::Store`] on a database failure.
pub fn published_checkpoint(store: &Store, log_id: &str) -> WitnessResult<PublishedCheckpoint> {
    if let Some(floor_tree_size) = store.equivocation_floor(log_id)? {
        return Ok(PublishedCheckpoint::Equivocated { floor_tree_size });
    }
    Ok(match store.get_retained(log_id)? {
        Some(retained) => PublishedCheckpoint::Checkpoint(Box::new(retained.cosigned)),
        None => PublishedCheckpoint::None,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::config::{Ed25519WitnessSigner, KeyObjectSpec, LogAnchorSpec};
    use crate::store::Store;

    struct Fixture {
        store: Store,
        signer: Ed25519WitnessSigner,
        anchor: LogAnchor,
        log_key: ahl_core::TestKey,
        genesis_bytes: Vec<u8>,
        genesis_leaf: Hash,
    }

    fn genesis_manifest_bytes(
        log_id: &str,
        producer: &ahl_core::TestKey,
        log_key: &ahl_core::TestKey,
        cadence: &str,
        grace: &str,
        epoch: &str,
    ) -> Vec<u8> {
        let payload = serde_json::json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": [
                { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
            ],
            "log": {
                "log_id": log_id,
                "operator": "op-1",
                "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                "checkpoint_cadence": cadence,
                "cadence_epoch": epoch,
                "witness_grace_period": grace,
                "keys": [
                    { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 }
                ],
            },
        });
        ahl_core::jcs(&ahl_core::envelope(payload, producer))
    }

    /// Builds a fixture with its own genesis manifest, keyed by two distinct 2-hex-digit
    /// seeds so the producer and log-signing keys never collide.
    fn fixture(producer_seed: &str, log_seed: &str) -> Fixture {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &producer_seed.repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &log_seed.repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", format!("{producer_seed}{log_seed}").repeat(16));
        let genesis_bytes = genesis_manifest_bytes(
            &log_id,
            &producer,
            &log_key,
            "PT5M",
            "PT1M",
            "2026-01-01T00:00:00Z",
        );
        let genesis_id =
            ahl_core::entry_id(&serde_json::from_slice(&genesis_bytes).expect("well-formed json"));
        let genesis_leaf = log_leaf_hash(&genesis_bytes);

        let anchor = LogAnchor::resolve(&LogAnchorSpec {
            log_id,
            genesis_manifest_entry_id: genesis_id,
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: producer.key_id(),
                pubkey: producer.pubkey(),
                valid_from_index: 0,
            }],
        })
        .expect("valid anchor");

        let store = Store::open_in_memory().expect("in-memory store");
        let signer = Ed25519WitnessSigner::from_seed("witness-1", &[9u8; 32]).expect("32 bytes");

        Fixture { store, signer, anchor, log_key, genesis_bytes, genesis_leaf }
    }

    fn genesis_entries(fx: &Fixture) -> Vec<Vec<u8>> {
        vec![fx.genesis_bytes.clone()]
    }

    fn signed_checkpoint(fx: &Fixture, tree_size: u64, root: Hash, time: &str) -> Checkpoint {
        let mut cp = Checkpoint {
            log_id: fx.anchor.log_id.clone(),
            tree_size,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: time.to_owned(),
            key_id: fx.log_key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        cp.signature = fx.log_key.sign(&blob);
        cp
    }

    fn base_nanos() -> u64 {
        crate::checkpoint::parse_checkpoint_time("2026-01-01T00:00:00.000000000Z")
            .expect("well-formed")
    }

    #[test]
    fn the_first_checkpoint_for_a_log_is_cosigned_on_a_matching_root() {
        let fx = fixture("11", "aa");
        let entries = genesis_entries(&fx);
        let root = compute_root(&[fx.genesis_leaf]);
        let cp = signed_checkpoint(&fx, 1, root, "2026-01-01T00:00:00.000000000Z");

        let outcome = witness_checkpoint(
            &fx.store,
            &fx.signer,
            &fx.anchor,
            &cp,
            None,
            &entries,
            base_nanos(),
        )
        .expect("genesis-only checkpoint cosigns");
        match outcome {
            WitnessOutcome::Cosigned(cosigned) => {
                assert_eq!(cosigned.witness_id, "witness-1");
                let key = fx.signer.verifying_key();
                assert!(verify_cosignature(&cosigned, &key).expect("well-formed"));
            }
            WitnessOutcome::Refused(_) => panic!("expected a cosign on the first checkpoint"),
        }
    }

    #[test]
    fn a_root_mismatch_on_the_first_checkpoint_is_an_error_not_refusal_evidence() {
        let fx = fixture("22", "bb");
        let entries = genesis_entries(&fx);
        let bogus_root = [0x77u8; 32];
        let cp = signed_checkpoint(&fx, 1, bogus_root, "2026-01-01T00:00:00.000000000Z");

        assert!(matches!(
            witness_checkpoint(
                &fx.store,
                &fx.signer,
                &fx.anchor,
                &cp,
                None,
                &entries,
                base_nanos()
            ),
            Err(WitnessError::CheckpointRootMismatch { tree_size: 1 })
        ));
    }

    #[test]
    fn a_consistent_second_checkpoint_is_cosigned_and_becomes_retained() {
        let fx = fixture("33", "cc");
        let mut entries = genesis_entries(&fx);
        let root1 = compute_root(&[fx.genesis_leaf]);
        let cp1 = signed_checkpoint(&fx, 1, root1, "2026-01-01T00:00:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp1, None, &entries, base_nanos())
            .expect("first cosigns");

        let second_entry = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": 1 },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        let second_leaf = log_leaf_hash(&second_entry);
        entries.push(second_entry);
        let root2 = compute_root(&[fx.genesis_leaf, second_leaf]);
        let cp2 = signed_checkpoint(&fx, 2, root2, "2026-01-01T00:01:00.000000000Z");

        let outcome = witness_checkpoint(
            &fx.store,
            &fx.signer,
            &fx.anchor,
            &cp2,
            None,
            &entries,
            base_nanos(),
        )
        .expect("consistent extension cosigns");
        assert!(matches!(outcome, WitnessOutcome::Cosigned(_)));
        let retained = fx.store.get_retained(&fx.anchor.log_id).expect("query").expect("present");
        assert_eq!(retained.checkpoint().tree_size, 2);
    }

    #[test]
    fn an_extension_that_fails_consistency_is_refused_with_a_replayable_proof() {
        let fx = fixture("44", "dd");
        let entries = genesis_entries(&fx);
        let root1 = compute_root(&[fx.genesis_leaf]);
        let cp1 = signed_checkpoint(&fx, 1, root1, "2026-01-01T00:00:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp1, None, &entries, base_nanos())
            .expect("first cosigns");

        // A second checkpoint at a larger tree_size, genuinely computed over a real second
        // entry — but its root is then overwritten with an unrelated value before signing,
        // so it authenticates (a valid log signature over *some* blob) yet cannot possibly
        // reconcile with the retained checkpoint's real root.
        let second_entry = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": 1 },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        let mut entries = entries;
        entries.push(second_entry);
        let mut cp2 = signed_checkpoint(&fx, 2, [0xaau8; 32], "2026-01-01T00:01:00.000000000Z");
        cp2.root_hash = format!("sha256:{}", "cd".repeat(32));
        let blob = crate::checkpoint::checkpoint_blob(&cp2).expect("well-formed");
        cp2.signature = fx.log_key.sign(&blob);

        let outcome = witness_checkpoint(
            &fx.store,
            &fx.signer,
            &fx.anchor,
            &cp2,
            None,
            &entries,
            base_nanos(),
        )
        .expect("authenticates, then refuses on a failed extension");
        match outcome {
            WitnessOutcome::Refused(evidence) => {
                assert_eq!(evidence.reason, RefusalReason::ExtensionFailed);
                assert_eq!(evidence.retained.tree_size, 1);
                assert_eq!(evidence.offered.tree_size, 2);
                let proof = evidence.consistency_proof.as_ref().expect("carried for this reason");
                assert_eq!(proof.from_size, 1);
                assert_eq!(proof.to_size, 2);
                // Independently checkable, per core spec §3.3.
                assert!(verify_refusal_claim(&evidence).expect("well-formed"));
                let key = fx.signer.verifying_key();
                assert!(verify_refusal_signature(&evidence, &key).expect("well-formed"));
            }
            WitnessOutcome::Cosigned(_) => panic!("expected a refusal"),
        }
        // The retained checkpoint is unchanged.
        let retained = fx.store.get_retained(&fx.anchor.log_id).expect("query").expect("present");
        assert_eq!(retained.checkpoint().tree_size, 1);
    }

    #[test]
    fn equal_tree_size_different_root_is_refused_as_equivocation() {
        let fx = fixture("55", "ee");
        let entries = genesis_entries(&fx);
        let root1 = compute_root(&[fx.genesis_leaf]);
        let cp1 = signed_checkpoint(&fx, 1, root1, "2026-01-01T00:00:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp1, None, &entries, base_nanos())
            .expect("first cosigns");

        let mut cp2 = signed_checkpoint(&fx, 1, [0x99u8; 32], "2026-01-01T00:05:00.000000000Z");
        let blob = crate::checkpoint::checkpoint_blob(&cp2).expect("well-formed");
        cp2.signature = fx.log_key.sign(&blob);

        let outcome = witness_checkpoint(
            &fx.store,
            &fx.signer,
            &fx.anchor,
            &cp2,
            None,
            &entries,
            base_nanos(),
        )
        .expect("authenticates, then refuses on equivocation");
        match outcome {
            WitnessOutcome::Refused(evidence) => {
                assert_eq!(evidence.reason, RefusalReason::Equivocation);
                assert!(evidence.consistency_proof.is_none());
                assert!(verify_refusal_claim(&evidence).expect("well-formed"));
            }
            WitnessOutcome::Cosigned(_) => panic!("expected a refusal"),
        }

        // Core spec §3.3: once equivocation is recorded, the floor is permanent for this log.
        assert_eq!(fx.store.equivocation_floor(&fx.anchor.log_id).expect("query"), Some(1));

        // A verifier reading the published view MUST see the equivocation, not a chosen
        // branch — even though `cp1` was itself validly cosigned before `cp2` arrived.
        match published_checkpoint(&fx.store, &fx.anchor.log_id).expect("well-formed") {
            PublishedCheckpoint::Equivocated { floor_tree_size } => assert_eq!(floor_tree_size, 1),
            other => panic!("expected an equivocated view, got {other:?}"),
        }
    }

    #[test]
    fn equivocation_is_detected_against_full_history_not_only_the_newest_member() {
        // Core spec §3.3: "An offered checkpoint whose (log_id, tree_size) matches one
        // already cosigned with a different root_hash is equivocation, whatever its size
        // relative to the newest retained member." Cosign sizes 1, 2, 3 genuinely, then offer
        // a CONFLICTING size-2 checkpoint while the retained latest is size 3. A witness that
        // only compared against the newest member would misclassify this as a harmless size
        // regression (2 < 3) and never notice the equivocation.
        let fx = fixture("bb", "cc");
        let mut entries = genesis_entries(&fx);
        let root1 = compute_root(&[fx.genesis_leaf]);
        let cp1 = signed_checkpoint(&fx, 1, root1, "2026-01-01T00:00:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp1, None, &entries, base_nanos())
            .expect("size 1 cosigns");

        let entry_2 = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": 2 },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        let leaf_2 = log_leaf_hash(&entry_2);
        entries.push(entry_2);
        let genuine_root_2 = compute_root(&[fx.genesis_leaf, leaf_2]);
        let cp2 = signed_checkpoint(&fx, 2, genuine_root_2, "2026-01-01T00:02:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp2, None, &entries, base_nanos())
            .expect("size 2 cosigns");

        let entry_3 = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": 3 },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        let leaf_3 = log_leaf_hash(&entry_3);
        let mut entries_3 = entries.clone();
        entries_3.push(entry_3);
        let root_3 = compute_root(&[fx.genesis_leaf, leaf_2, leaf_3]);
        let cp3 = signed_checkpoint(&fx, 3, root_3, "2026-01-01T00:03:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp3, None, &entries_3, base_nanos())
            .expect("size 3 cosigns");

        // Now offer a conflicting size-2 checkpoint: same tree_size as an already-cosigned
        // member, but a different root — and smaller than the CURRENT retained (size 3).
        let mut conflicting_cp2 =
            signed_checkpoint(&fx, 2, [0x42u8; 32], "2026-01-01T00:02:30.000000000Z");
        let blob = crate::checkpoint::checkpoint_blob(&conflicting_cp2).expect("well-formed");
        conflicting_cp2.signature = fx.log_key.sign(&blob);

        let outcome = witness_checkpoint(
            &fx.store,
            &fx.signer,
            &fx.anchor,
            &conflicting_cp2,
            None,
            &entries, // covers [0, 2), matching conflicting_cp2.tree_size == 2
            base_nanos(),
        )
        .expect("authenticates, then refuses on equivocation");
        match outcome {
            WitnessOutcome::Refused(evidence) => {
                assert_eq!(
                    evidence.reason,
                    RefusalReason::Equivocation,
                    "a witness comparing only against the newest member would wrongly report \
                     size-regression here"
                );
                assert_eq!(evidence.retained.tree_size, 2);
                assert_eq!(evidence.offered.tree_size, 2);
            }
            WitnessOutcome::Cosigned(_) => panic!("expected a refusal"),
        }
        assert_eq!(fx.store.equivocation_floor(&fx.anchor.log_id).expect("query"), Some(2));
        // The size-3 checkpoint, cosigned before the conflict was found, remains on record,
        // but is no longer presented as canonical (see `published_checkpoint`).
        assert_eq!(fx.store.list_cosigned(&fx.anchor.log_id).expect("query").len(), 3);
        match published_checkpoint(&fx.store, &fx.anchor.log_id).expect("well-formed") {
            PublishedCheckpoint::Equivocated { floor_tree_size } => assert_eq!(floor_tree_size, 2),
            other => panic!("expected an equivocated view, got {other:?}"),
        }
    }

    #[test]
    fn resubmitting_an_already_cosigned_non_latest_checkpoint_is_idempotent() {
        let fx = fixture("dd", "ee");
        let mut entries = genesis_entries(&fx);
        let root1 = compute_root(&[fx.genesis_leaf]);
        let cp1 = signed_checkpoint(&fx, 1, root1, "2026-01-01T00:00:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp1, None, &entries, base_nanos())
            .expect("size 1 cosigns");

        let entry_2 = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": 2 },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        entries.push(entry_2);
        let root2 = compute_root(&[fx.genesis_leaf, log_leaf_hash(&entries[1])]);
        let cp2 = signed_checkpoint(&fx, 2, root2, "2026-01-01T00:01:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp2, None, &entries, base_nanos())
            .expect("size 2 cosigns");

        // Resubmit the ORIGINAL size-1 checkpoint (not the latest) with its genuine root.
        let genesis_only = genesis_entries(&fx);
        let outcome = witness_checkpoint(
            &fx.store,
            &fx.signer,
            &fx.anchor,
            &cp1,
            None,
            &genesis_only,
            base_nanos(),
        )
        .expect("idempotent resubmission cosigns again rather than erroring");
        assert!(matches!(outcome, WitnessOutcome::Cosigned(_)));
        assert!(fx.store.equivocation_floor(&fx.anchor.log_id).expect("query").is_none());
        // The latest retained checkpoint is unaffected.
        let retained = fx.store.get_retained(&fx.anchor.log_id).expect("query").expect("present");
        assert_eq!(retained.checkpoint().tree_size, 2);
    }

    #[test]
    fn a_log_that_has_equivocated_refuses_every_further_candidate() {
        let fx = fixture("aa", "bb");
        let entries = genesis_entries(&fx);
        let root1 = compute_root(&[fx.genesis_leaf]);
        let cp1 = signed_checkpoint(&fx, 1, root1, "2026-01-01T00:00:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp1, None, &entries, base_nanos())
            .expect("first cosigns");

        let mut cp2 = signed_checkpoint(&fx, 1, [0x99u8; 32], "2026-01-01T00:05:00.000000000Z");
        let blob = crate::checkpoint::checkpoint_blob(&cp2).expect("well-formed");
        cp2.signature = fx.log_key.sign(&blob);
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp2, None, &entries, base_nanos())
            .expect("refuses on equivocation");

        // A later, otherwise entirely legitimate extension is still refused: the log is
        // equivocated, and no further checkpoint may be cosigned for it.
        let second_entry = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": 1 },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        let mut later_entries = entries;
        later_entries.push(second_entry.clone());
        let root2 = compute_root(&[fx.genesis_leaf, log_leaf_hash(&second_entry)]);
        let cp3 = signed_checkpoint(&fx, 2, root2, "2026-01-01T00:10:00.000000000Z");

        let outcome = witness_checkpoint(
            &fx.store,
            &fx.signer,
            &fx.anchor,
            &cp3,
            None,
            &later_entries,
            base_nanos(),
        )
        .expect("authenticates, then refuses because the log is equivocated");
        match outcome {
            WitnessOutcome::Refused(evidence) => {
                // Cites the ORIGINAL conflicting pair (both at tree_size 1) — independently
                // checkable exactly like a fresh equivocation report — not `cp3`.
                assert_eq!(evidence.reason, RefusalReason::Equivocation);
                assert_eq!(evidence.retained.tree_size, 1);
                assert_eq!(evidence.offered.tree_size, 1);
                assert!(verify_refusal_claim(&evidence).expect("well-formed"));
                assert!(evidence.detail.contains("tree_size 2"));
            }
            WitnessOutcome::Cosigned(_) => panic!("expected a refusal"),
        }
        // Still not cosigned or retained.
        let retained = fx.store.get_retained(&fx.anchor.log_id).expect("query").expect("present");
        assert_eq!(retained.checkpoint().tree_size, 1);
    }

    #[test]
    fn a_checkpoint_signed_outside_its_key_validity_range_is_refused() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"66".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"67".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "66".repeat(32));
        let payload = serde_json::json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": [
                { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
            ],
            "log": {
                "log_id": log_id,
                "operator": "op-1",
                "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                "checkpoint_cadence": "PT5M",
                "cadence_epoch": "2026-01-01T00:00:00Z",
                "witness_grace_period": "PT1M",
                "keys": [
                    { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 5 }
                ],
            },
        });
        let genesis_bytes = ahl_core::jcs(&ahl_core::envelope(payload, &producer));
        let genesis_id =
            ahl_core::entry_id(&serde_json::from_slice(&genesis_bytes).expect("well-formed json"));
        let anchor = LogAnchor::resolve(&LogAnchorSpec {
            log_id: log_id.clone(),
            genesis_manifest_entry_id: genesis_id,
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: producer.key_id(),
                pubkey: producer.pubkey(),
                valid_from_index: 0,
            }],
        })
        .expect("valid anchor");

        let genesis_leaf = log_leaf_hash(&genesis_bytes);
        let root = compute_root(&[genesis_leaf]);
        let mut cp = Checkpoint {
            log_id,
            tree_size: 1,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: log_key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        cp.signature = log_key.sign(&blob);

        let store = Store::open_in_memory().expect("in-memory store");
        let signer = Ed25519WitnessSigner::from_seed("witness-1", &[9u8; 32]).expect("32 bytes");
        assert!(matches!(
            witness_checkpoint(&store, &signer, &anchor, &cp, None, &[genesis_bytes], base_nanos()),
            Err(WitnessError::KeyNotYetActive { .. })
        ));
    }

    #[test]
    fn unresolvable_governance_is_refused_not_defaulted() {
        let fx = fixture("77", "ff");
        // Entries claimed to cover the checkpoint, but none of them is the configured
        // genesis manifest — governance can never be established.
        let junk = vec![ahl_core::jcs(&serde_json::json!({
            "payload": { "n": 1 },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }))];
        let root = compute_root(&[log_leaf_hash(&junk[0])]);
        let cp = signed_checkpoint(&fx, 1, root, "2026-01-01T00:00:00.000000000Z");

        assert!(matches!(
            witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp, None, &junk, base_nanos()),
            Err(WitnessError::GovernanceChainUnresolvable { .. })
        ));
    }

    #[test]
    fn incomplete_entries_are_rejected_before_authentication_is_attempted() {
        let fx = fixture("88", "10");
        let cp = signed_checkpoint(&fx, 5, [0u8; 32], "2026-01-01T00:00:00.000000000Z");
        assert!(matches!(
            witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp, None, &[], base_nanos()),
            Err(WitnessError::IncompleteEntries { have: 0, need: 5 })
        ));
    }

    #[test]
    fn a_bad_raw_blob_is_rejected() {
        let fx = fixture("99", "20");
        let entries = genesis_entries(&fx);
        let root = compute_root(&[fx.genesis_leaf]);
        let cp = signed_checkpoint(&fx, 1, root, "2026-01-01T00:00:00.000000000Z");
        let bad_raw = [0u8; 98];
        assert!(matches!(
            witness_checkpoint(
                &fx.store,
                &fx.signer,
                &fx.anchor,
                &cp,
                Some(&bad_raw),
                &entries,
                base_nanos()
            ),
            Err(WitnessError::RawBlobMismatch)
        ));
    }

    #[test]
    fn concurrent_conflicting_extensions_at_the_same_size_equivocate_exactly_once() {
        // Core spec §3.3, "serialize and make atomic": two concurrent submissions extending
        // the same retained checkpoint to different roots at the same new size MUST NOT both
        // be cosigned. Runs the state machine from two real OS threads against one shared
        // `Store`, synchronized with a barrier so both reach `witness_checkpoint` as close to
        // simultaneously as possible, and checks the outcome shape rather than which thread
        // happened to win the race (which is legitimately non-deterministic).
        let fx = fixture("cc", "dd");
        let entries0 = genesis_entries(&fx);
        let root1 = compute_root(&[fx.genesis_leaf]);
        let cp1 = signed_checkpoint(&fx, 1, root1, "2026-01-01T00:00:00.000000000Z");
        witness_checkpoint(&fx.store, &fx.signer, &fx.anchor, &cp1, None, &entries0, base_nanos())
            .expect("bootstrap cosigns");

        let entry_a = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": "a" },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        let entry_b = ahl_core::jcs(&serde_json::json!({
            "payload": { "n": "b" },
            "signatures": [ { "key_id": "sha256:aa", "sig": "base64:bb" } ],
        }));
        let root_a = compute_root(&[fx.genesis_leaf, log_leaf_hash(&entry_a)]);
        let root_b = compute_root(&[fx.genesis_leaf, log_leaf_hash(&entry_b)]);
        let cp_a = signed_checkpoint(&fx, 2, root_a, "2026-01-01T00:01:00.000000000Z");
        let cp_b = signed_checkpoint(&fx, 2, root_b, "2026-01-01T00:01:00.000000000Z");
        let root_hash_a = cp_a.root_hash.clone();
        let root_hash_b = cp_b.root_hash.clone();

        let mut entries_a = entries0.clone();
        entries_a.push(entry_a);
        let mut entries_b = entries0;
        entries_b.push(entry_b);

        let Fixture { store, signer, anchor, .. } = fx;
        let store = Arc::new(store);
        let signer = Arc::new(signer);
        let anchor = Arc::new(anchor);
        let barrier = Arc::new(Barrier::new(2));
        let now = base_nanos();

        let handle_a = {
            let (store, signer, anchor, barrier) = (
                Arc::clone(&store),
                Arc::clone(&signer),
                Arc::clone(&anchor),
                Arc::clone(&barrier),
            );
            thread::spawn(move || {
                barrier.wait();
                witness_checkpoint(
                    store.as_ref(),
                    signer.as_ref(),
                    anchor.as_ref(),
                    &cp_a,
                    None,
                    &entries_a,
                    now,
                )
            })
        };
        let handle_b = {
            let (store, signer, anchor, barrier) = (
                Arc::clone(&store),
                Arc::clone(&signer),
                Arc::clone(&anchor),
                Arc::clone(&barrier),
            );
            thread::spawn(move || {
                barrier.wait();
                witness_checkpoint(
                    store.as_ref(),
                    signer.as_ref(),
                    anchor.as_ref(),
                    &cp_b,
                    None,
                    &entries_b,
                    now,
                )
            })
        };

        let outcome_a = handle_a.join().expect("thread a panicked").expect("thread a errored");
        let outcome_b = handle_b.join().expect("thread b panicked").expect("thread b errored");

        let outcomes = [&outcome_a, &outcome_b];
        let cosigned_count =
            outcomes.iter().filter(|o| matches!(o, WitnessOutcome::Cosigned(_))).count();
        let refused_count =
            outcomes.iter().filter(|o| matches!(o, WitnessOutcome::Refused(_))).count();
        assert_eq!(cosigned_count, 1, "exactly one concurrent submission must be cosigned");
        assert_eq!(refused_count, 1, "the other must be refused, never both cosigned");

        let refused = outcomes
            .into_iter()
            .find_map(|o| match o {
                WitnessOutcome::Refused(evidence) => Some(evidence),
                WitnessOutcome::Cosigned(_) => None,
            })
            .expect("exactly one refusal");
        assert_eq!(refused.reason, RefusalReason::Equivocation);
        assert_eq!(refused.retained.tree_size, 2);
        assert_eq!(refused.offered.tree_size, 2);
        assert!(verify_refusal_claim(refused).expect("well-formed"));

        assert_eq!(store.equivocation_floor(&anchor.log_id).expect("query"), Some(2));
        let retained = store.get_retained(&anchor.log_id).expect("query").expect("present");
        assert_eq!(retained.checkpoint().tree_size, 2);
        assert!(
            retained.checkpoint().root_hash == root_hash_a
                || retained.checkpoint().root_hash == root_hash_b,
            "the winning cosign must be exactly one of the two genuine candidate roots"
        );
    }
}
