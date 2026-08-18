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
//! # Authentication failures are not refusal evidence
//!
//! Adaptor profile §11.2 rule 2 requires refusal evidence to carry **two validly signed**
//! checkpoints ("an unsigned or badly signed checkpoint proves nothing about the log").
//! A candidate that never authenticates at all — unresolvable governance, a signature that
//! does not verify, a key used outside its validity window — is therefore not a "checkpoint
//! the log offered" in the protocol's sense; there is nothing to pair it with in refusal
//! evidence, and [`witness_checkpoint`] reports it as an ordinary [`WitnessError`] instead.
//! [`ConsistencyOutcome`] failures, by contrast, only ever arise between two checkpoints that
//! have both already authenticated, and always produce [`WitnessOutcome::Refused`].
//!
//! # Equivocation ends the series (core spec §7.3)
//!
//! Two authenticated checkpoints sharing a `tree_size` with differing `root_hash` values are
//! **equivocation, not a tie**: "From the lowest `tree_size` at which it occurs, the series
//! is no longer canonical: no incorporation bound, enumeration response or completeness
//! claim may be grounded at or beyond that point, and a party serving series-dependent
//! material MUST report the divergence rather than choosing a branch. … Detecting
//! equivocation and then continuing to serve one branch is a conformance violation." This is
//! a stronger requirement than "refuse this one candidate": once [`consistency::check`]
//! reports [`ConsistencyOutcome::Equivocation`] for a log, [`witness_checkpoint`] records an
//! **equivocation floor** for it ([`Store::record_equivocation`]) and every subsequent call
//! for that log — regardless of the new candidate's own validity — is refused without
//! attempting ordinary consistency checking, so no later checkpoint can be cosigned in a way
//! that would make either conflicting branch look canonical again. [`published_checkpoint`]
//! is the read-side counterpart: once a log has an equivocation floor, it reports
//! [`PublishedCheckpoint::Equivocated`] instead of any specific "latest" checkpoint, however
//! validly that checkpoint was itself cosigned before the divergence was found.

use atl_core::core::merkle::{compute_root, Hash};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::checkpoint::{verify_checkpoint_signature, Checkpoint};
use crate::config::{LogAnchor, WitnessSigner};
use crate::consistency::{self, ConsistencyOutcome};
use crate::error::{WitnessError, WitnessResult};
use crate::governance::{self, GovernanceState};
use crate::metadata::log_leaf_hash;
use crate::store::{RetainedCheckpoint, Store};

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

/// Why a witness refused to cosign (adaptor profile §11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalReason {
    /// Two checkpoints of the same log with an incompatible history — including the
    /// equal-`tree_size`, different-`root_hash` case adaptor profile §11.2 names explicitly.
    Inconsistent,
    /// An offered checkpoint of greater `tree_size` for which no consistency proof from the
    /// retained one could be established.
    MissingConsistencyProof,
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
    /// The checkpoint this witness had already cosigned.
    pub retained: Checkpoint,
    /// The checkpoint this witness refused.
    pub offered: Checkpoint,
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

fn cosign(
    store: &Store,
    signer: &dyn WitnessSigner,
    governance: &GovernanceState,
    candidate: &Checkpoint,
    now_nanos: u64,
) -> WitnessResult<WitnessOutcome> {
    let checkpoint_value = serde_json::to_value(candidate)?;
    let bytes = ahl_core::cosignature_bytes(&checkpoint_value, signer.witness_id());
    let cosigned = CosignedCheckpoint {
        checkpoint: candidate.clone(),
        witness_id: signer.witness_id().to_owned(),
        key_id: signer.key_id(),
        cosignature: signer.sign(&bytes),
        cosigned_at: render_rfc3339(now_nanos)?,
    };
    store.retain(&cosigned, governance.cadence_nanos(), governance.witness_grace_period_nanos())?;
    Ok(WitnessOutcome::Cosigned(Box::new(cosigned)))
}

/// Build, sign, record and return refusal evidence. `log_id` is taken from `offered` — by the
/// time this is called, `offered.log_id` has already been checked against the configured
/// anchor by [`verify_checkpoint_signature`], so it is the authoritative value, and threading
/// a separate `log_id` parameter through as well would be redundant (and is what tipped this
/// function over `clippy::too_many_arguments`).
fn refuse(
    store: &Store,
    signer: &dyn WitnessSigner,
    retained: &Checkpoint,
    offered: &Checkpoint,
    reason: RefusalReason,
    detail: &str,
    now_nanos: u64,
) -> WitnessResult<WitnessOutcome> {
    let mut evidence = RefusalEvidence {
        kind: "witness-refusal".to_owned(),
        witness_id: signer.witness_id().to_owned(),
        log_id: offered.log_id.clone(),
        reason,
        retained: retained.clone(),
        offered: offered.clone(),
        detail: detail.to_owned(),
        refused_at: render_rfc3339(now_nanos)?,
        key_id: signer.key_id(),
        signature: String::new(),
    };
    let bytes = refusal_signing_bytes(&evidence)?;
    evidence.signature = signer.sign(&bytes);
    store.record_refusal(&evidence)?;
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
/// This checks only the witness's own signature — it does not re-verify the log signatures
/// on `retained`/`offered` (§11.2 check 2) or re-derive the conflict category (§11.2 check
/// 3), which require the governing manifest's log key set and are the caller's
/// responsibility (see [`crate::governance`] and [`crate::consistency`]).
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

/// Run the core spec §3.3 state machine on one candidate checkpoint.
///
/// Pipeline:
///
/// 1. `entries_prefix` MUST cover `[0, candidate.tree_size)` exactly — adaptor profile §10.6:
///    under this profile, enumerated governance requires the full range, since no
///    typed-subset proof exists to prove a shorter set is complete.
/// 2. Governance is resolved from `entries_prefix` against `anchor` ([`crate::governance`]),
///    and the candidate's signature is verified against the resolved, activation-bound
///    signing key ([`crate::checkpoint::verify_checkpoint_signature`]). A candidate failing
///    either step is refused outright as a [`WitnessError`] — see the module docs for why
///    this is not refusal evidence.
/// 3. If `anchor.log_id` already has a recorded equivocation floor
///    ([`Store::equivocation_floor`]), every further candidate is refused unconditionally —
///    see the module docs, "Equivocation ends the series" — without running ordinary
///    consistency checking.
/// 4. If this is the first checkpoint ever witnessed for the log, its root MUST recompute
///    from `entries_prefix` (there is no retained checkpoint for a consistency proof to run
///    from); a mismatch is a [`WitnessError::CheckpointRootMismatch`], again not refusal
///    evidence — adaptor profile §11.2's schema has no way to name an absent `retained`
///    checkpoint, so nothing can be published as a two-checkpoint refusal for this case.
/// 5. Otherwise the candidate is classified against the retained checkpoint
///    ([`crate::consistency::check`]): consistent candidates are cosigned, retained, and the
///    outcome published; an [`ConsistencyOutcome::Equivocation`] additionally records the
///    equivocation floor before publishing refusal evidence; any other inconsistency produces
///    refusal evidence without recording a floor, and the retained checkpoint is left
///    unchanged either way.
///
/// # Errors
///
/// [`WitnessError::IncompleteEntries`], [`WitnessError::GovernanceChainUnresolvable`], a
/// checkpoint-authentication error from [`crate::checkpoint::verify_checkpoint_signature`],
/// or [`WitnessError::CheckpointRootMismatch`] for the bootstrap case above.
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

    let governance = governance::resolve(entries_prefix, anchor)?;
    let key = governance.resolve_log_key(&candidate.key_id, candidate.tree_size)?;
    verify_checkpoint_signature(candidate, raw, &anchor.log_id, key)?;

    let leaf_hashes: Vec<Hash> = entries_prefix.iter().map(|b| log_leaf_hash(b)).collect();

    let retained = store.get_retained(&candidate.log_id)?;

    if let Some(floor) = store.equivocation_floor(&candidate.log_id)? {
        // Core spec §7.3: once a log has equivocated, nothing at or beyond the floor may
        // ground a witness assertion. Refuse every further candidate outright — never resume
        // ordinary consistency checking, which could make one branch look canonical again.
        let retained_for_evidence =
            retained.as_ref().map_or_else(|| candidate.clone(), |r| r.cosigned.checkpoint.clone());
        return refuse(
            store,
            signer,
            &retained_for_evidence,
            candidate,
            RefusalReason::Inconsistent,
            &format!(
                "log equivocated at tree_size {floor}; refusing to extend trust to any \
                 further checkpoint"
            ),
            now_nanos,
        );
    }

    match retained {
        None => {
            let root = compute_root(&leaf_hashes);
            let candidate_root = ahl_core::parse_hash_hex(&candidate.root_hash)?;
            if root != candidate_root {
                return Err(WitnessError::CheckpointRootMismatch {
                    tree_size: candidate.tree_size,
                });
            }
            cosign(store, signer, &governance, candidate, now_nanos)
        }
        Some(RetainedCheckpoint { cosigned, .. }) => {
            let retained_checkpoint = cosigned.checkpoint;
            match consistency::check(&retained_checkpoint, candidate, &leaf_hashes)? {
                ConsistencyOutcome::Consistent => {
                    cosign(store, signer, &governance, candidate, now_nanos)
                }
                ConsistencyOutcome::Equivocation => {
                    let detected_at = render_rfc3339(now_nanos)?;
                    store.record_equivocation(&anchor.log_id, candidate.tree_size, &detected_at)?;
                    refuse(
                        store,
                        signer,
                        &retained_checkpoint,
                        candidate,
                        RefusalReason::Inconsistent,
                        "equivocation: retained and offered share a tree_size with \
                         different root_hash values",
                        now_nanos,
                    )
                }
                ConsistencyOutcome::Inconsistent => refuse(
                    store,
                    signer,
                    &retained_checkpoint,
                    candidate,
                    RefusalReason::Inconsistent,
                    "offered checkpoint conflicts with the retained one",
                    now_nanos,
                ),
                ConsistencyOutcome::ProofUnavailable => refuse(
                    store,
                    signer,
                    &retained_checkpoint,
                    candidate,
                    RefusalReason::MissingConsistencyProof,
                    "no consistency proof could be built from the supplied entries",
                    now_nanos,
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
    fn an_inconsistent_checkpoint_is_refused_with_evidence_and_not_cosigned() {
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
        .expect("authenticates, then refuses on inconsistency");
        match outcome {
            WitnessOutcome::Refused(evidence) => {
                assert_eq!(evidence.reason, RefusalReason::Inconsistent);
                assert_eq!(evidence.retained.tree_size, 1);
                assert_eq!(evidence.offered.tree_size, 2);
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
                assert_eq!(evidence.reason, RefusalReason::Inconsistent);
            }
            WitnessOutcome::Cosigned(_) => panic!("expected a refusal"),
        }

        // Core spec §7.3: once equivocation is recorded, the floor is permanent for this log.
        assert_eq!(fx.store.equivocation_floor(&fx.anchor.log_id).expect("query"), Some(1));

        // A verifier reading the published view MUST see the equivocation, not a chosen
        // branch — even though `cp1` was itself validly cosigned before `cp2` arrived.
        match published_checkpoint(&fx.store, &fx.anchor.log_id).expect("well-formed") {
            PublishedCheckpoint::Equivocated { floor_tree_size } => assert_eq!(floor_tree_size, 1),
            other => panic!("expected an equivocated view, got {other:?}"),
        }
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
        assert!(matches!(outcome, WitnessOutcome::Refused(_)));
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
}
