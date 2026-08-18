//! Consistency classification of an offered checkpoint against the retained one.
//!
//! Core spec §3.3 step 2; §7.3 "Equivocation ends the series"; §3.3 "Obligations that make
//! the machine sound"; adaptor profile §11.2.
//!
//! This module classifies **one pair** — `retained` (conventionally the latest retained
//! member) against `offered`. It does **not**, on its own, implement core spec §3.3's
//! "compare against the whole retained history, not the newest member" obligation: doing
//! that correctly requires scanning every previously cosigned checkpoint at `offered`'s exact
//! `tree_size`, which needs the store, not just two [`Checkpoint`] values. That scan lives in
//! [`crate::witness::witness_checkpoint`], which calls into this module only once it has
//! already established (via the store) that no such history entry exists — see that
//! function's doc comment for the full pipeline and why it, not this module, owns
//! equivocation detection end to end.
//!
//! Every reason this module can produce carries evidence a verifier can independently
//! recheck (core spec §3.3: "every refusal reason MUST be independently checkable from the
//! evidence it carries; a reason whose verification procedure is undefined MUST NOT be
//! emitted"): [`ConsistencyOutcome::Equivocation`] is checkable from the two checkpoints'
//! `tree_size`/`root_hash` fields alone; [`ConsistencyOutcome::SizeRegression`] likewise;
//! [`ConsistencyOutcome::ExtensionFailed`] carries the consistency proof that was generated
//! and failed to verify, so a verifier can rerun exactly the same RFC 9162 check (see
//! [`verify_extension_failure`]). A proof that cannot even be *generated* — which, given this
//! crate's invariant that callers always supply the complete `[0, offered.tree_size)` entry
//! range (adaptor profile §10.6), should not arise in practice — is propagated as a
//! [`crate::error::WitnessError`] rather than produced as a fourth, unverifiable outcome:
//! there is no checkable claim to make about a proof that does not exist.

use atl_core::core::merkle::{
    generate_consistency_proof, verify_consistency, ConsistencyProof, Hash,
};
use serde::{Deserialize, Serialize};

use crate::checkpoint::Checkpoint;
use crate::error::{WitnessError, WitnessResult};

/// A consistency proof, carried as refusal evidence for
/// [`ConsistencyOutcome::ExtensionFailed`] so a verifier can rerun the same RFC 9162 check
/// this witness ran (adaptor profile §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProofEvidence {
    /// Size of the older tree (`retained.tree_size`).
    pub from_size: u64,
    /// Size of the newer tree (`offered.tree_size`).
    pub to_size: u64,
    /// Proof hashes connecting the old root to the new root, as `sha256:<hex>` strings, in
    /// the order RFC 9162 §2.1.4 produces them.
    pub path: Vec<String>,
}

impl ConsistencyProofEvidence {
    fn from_atl(proof: &ConsistencyProof) -> Self {
        Self {
            from_size: proof.from_size,
            to_size: proof.to_size,
            path: proof.path.iter().map(|h| format!("sha256:{}", hex::encode(h))).collect(),
        }
    }

    fn to_atl(&self) -> WitnessResult<ConsistencyProof> {
        let path = self
            .path
            .iter()
            .map(|h| ahl_core::parse_hash_hex(h).map_err(WitnessError::from))
            .collect::<WitnessResult<Vec<_>>>()?;
        Ok(ConsistencyProof { from_size: self.from_size, to_size: self.to_size, path })
    }
}

/// The outcome of comparing `offered` against `retained`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyOutcome {
    /// `offered` is a valid append-only extension of `retained`, or an idempotent republish
    /// of it (same `tree_size`, same `root_hash`).
    Consistent,
    /// `retained` and `offered` share a `tree_size` but carry different `root_hash` values —
    /// core spec §7.3: "no append-only tree can produce" two roots at one size.
    Equivocation,
    /// `offered.tree_size < retained.tree_size`: no append-only tree ever shrinks, so a
    /// smaller offered `tree_size` is never consistent with a larger retained one.
    SizeRegression,
    /// `offered.tree_size > retained.tree_size`, a consistency proof was generated between
    /// them, and it did not verify against the two claimed roots. Carries that proof so the
    /// failure is independently checkable.
    ExtensionFailed(ConsistencyProofEvidence),
}

/// Classify `offered` against `retained`, given leaf hashes covering `[0, offered.tree_size)`.
///
/// `leaf_hashes` MUST be the AHL log-tree leaf hashes (see [`crate::metadata::log_leaf_hash`])
/// for entries `[0, offered.tree_size)`, in entry-index order.
///
/// # Errors
///
/// Propagates a parsing error if either checkpoint's `root_hash` is not a well-formed
/// `sha256:<hex>` family string, or a [`crate::error::WitnessError`] if a consistency proof
/// cannot be *generated* from `leaf_hashes` for the `offered.tree_size > retained.tree_size`
/// case — see the module docs for why that is a hard error, not a fourth outcome.
pub fn check(
    retained: &Checkpoint,
    offered: &Checkpoint,
    leaf_hashes: &[Hash],
) -> WitnessResult<ConsistencyOutcome> {
    if offered.tree_size < retained.tree_size {
        return Ok(ConsistencyOutcome::SizeRegression);
    }
    if offered.tree_size == retained.tree_size {
        return Ok(if offered.root_hash == retained.root_hash {
            ConsistencyOutcome::Consistent
        } else {
            ConsistencyOutcome::Equivocation
        });
    }

    let retained_root: Hash = ahl_core::parse_hash_hex(&retained.root_hash)?;
    let offered_root: Hash = ahl_core::parse_hash_hex(&offered.root_hash)?;
    let proof =
        generate_consistency_proof(retained.tree_size, offered.tree_size, |level, index| {
            if level == 0 {
                leaf_hashes.get(usize::try_from(index).ok()?).copied()
            } else {
                None
            }
        })?;
    Ok(if verify_consistency(&proof, &retained_root, &offered_root).unwrap_or(false) {
        ConsistencyOutcome::Consistent
    } else {
        ConsistencyOutcome::ExtensionFailed(ConsistencyProofEvidence::from_atl(&proof))
    })
}

/// Independently rerun an [`ConsistencyOutcome::ExtensionFailed`] claim: reconstruct the
/// carried proof and confirm it does **not** establish consistency between `retained_root`
/// and `offered_root`.
///
/// This is exactly what a verifier holding only the refusal evidence (not this crate's
/// internal state) can and should do to check an `extension-failed` reason for themselves —
/// core spec §3.3's requirement that every refusal reason be independently checkable.
///
/// # Errors
///
/// Propagates a parsing error from a malformed carried hash, or an error if the proof
/// structure itself is invalid (e.g. a path length inconsistent with `from_size`/`to_size`).
pub fn verify_extension_failure(
    evidence: &ConsistencyProofEvidence,
    retained_root_hash: &str,
    offered_root_hash: &str,
) -> WitnessResult<bool> {
    let retained_root: Hash = ahl_core::parse_hash_hex(retained_root_hash)?;
    let offered_root: Hash = ahl_core::parse_hash_hex(offered_root_hash)?;
    let proof = evidence.to_atl()?;
    Ok(!verify_consistency(&proof, &retained_root, &offered_root)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WitnessError;

    fn cp(tree_size: u64, root: Hash) -> Checkpoint {
        Checkpoint {
            log_id: "sha256:aa".to_owned(),
            tree_size,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:bb".to_owned(),
            signature: "base64:AAAA".to_owned(),
        }
    }

    fn leaf(n: u8) -> Hash {
        ahl_core::leaf_hash(&[n])
    }

    #[test]
    fn a_genuine_extension_is_consistent() {
        let leaves: Vec<Hash> = (0u8..8).map(leaf).collect();
        let root_of = |n: usize| atl_core::core::merkle::compute_root(&leaves[..n]);
        let retained = cp(4, root_of(4));
        let offered = cp(8, root_of(8));
        assert_eq!(
            check(&retained, &offered, &leaves).expect("well-formed"),
            ConsistencyOutcome::Consistent
        );
    }

    #[test]
    fn an_unrelated_larger_tree_is_extension_failed_and_carries_a_replayable_proof() {
        let leaves: Vec<Hash> = (0u8..8).map(leaf).collect();
        let retained = cp(4, atl_core::core::merkle::compute_root(&leaves[..4]));
        let mut offered = cp(8, atl_core::core::merkle::compute_root(&leaves[..8]));
        offered.root_hash = format!("sha256:{}", "00".repeat(32));
        let outcome = check(&retained, &offered, &leaves).expect("well-formed");
        let ConsistencyOutcome::ExtensionFailed(evidence) = outcome else {
            panic!("expected ExtensionFailed");
        };
        assert_eq!(evidence.from_size, 4);
        assert_eq!(evidence.to_size, 8);
        // A verifier holding only this evidence and the two root hashes can rerun the check.
        assert!(verify_extension_failure(&evidence, &retained.root_hash, &offered.root_hash)
            .expect("well-formed proof"));
        // And confirm it does NOT also "fail" a genuine, unrelated consistent pair — i.e.
        // the replay is a real check, not a rubber stamp.
        let genuine_offered = cp(8, atl_core::core::merkle::compute_root(&leaves[..8]));
        assert!(!verify_extension_failure(
            &evidence,
            &retained.root_hash,
            &genuine_offered.root_hash
        )
        .expect("well-formed proof"));
    }

    #[test]
    fn equal_tree_size_same_root_is_an_idempotent_republish() {
        let leaves: Vec<Hash> = (0u8..4).map(leaf).collect();
        let root = atl_core::core::merkle::compute_root(&leaves);
        let retained = cp(4, root);
        let offered = cp(4, root);
        assert_eq!(
            check(&retained, &offered, &leaves).expect("well-formed"),
            ConsistencyOutcome::Consistent
        );
    }

    #[test]
    fn equal_tree_size_different_root_is_equivocation() {
        // Core spec §7.3: "Two authenticated members sharing a tree_size with differing
        // root_hash values are equivocation, not a tie."
        let leaves: Vec<Hash> = (0u8..4).map(leaf).collect();
        let retained = cp(4, atl_core::core::merkle::compute_root(&leaves));
        let offered = cp(4, [0xffu8; 32]);
        assert_eq!(
            check(&retained, &offered, &leaves).expect("well-formed"),
            ConsistencyOutcome::Equivocation
        );
    }

    #[test]
    fn a_shrinking_tree_size_is_a_size_regression() {
        let leaves: Vec<Hash> = (0u8..8).map(leaf).collect();
        let retained = cp(8, atl_core::core::merkle::compute_root(&leaves));
        let offered = cp(4, atl_core::core::merkle::compute_root(&leaves[..4]));
        assert_eq!(
            check(&retained, &offered, &leaves).expect("well-formed"),
            ConsistencyOutcome::SizeRegression
        );
    }

    #[test]
    fn insufficient_leaves_are_a_hard_error_not_a_refusable_outcome() {
        // `retained` claims a tree_size the supplied `leaf_hashes` slice does not cover.
        // Core spec §3.3: a reason whose verification procedure is undefined MUST NOT be
        // emitted — there is no proof to carry, so this is not `ExtensionFailed` either.
        let leaves: Vec<Hash> = (0u8..2).map(leaf).collect();
        let retained = cp(4, [0x11u8; 32]);
        let offered = cp(8, [0x22u8; 32]);
        assert!(matches!(check(&retained, &offered, &leaves), Err(WitnessError::Atl(_))));
    }

    #[test]
    fn consistency_proof_evidence_round_trips_through_json() {
        let evidence = ConsistencyProofEvidence {
            from_size: 2,
            to_size: 5,
            path: vec![format!("sha256:{}", "ab".repeat(32))],
        };
        let json = serde_json::to_string(&evidence).expect("serialize");
        let round_tripped: ConsistencyProofEvidence =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_tripped, evidence);
    }

    #[test]
    fn a_malformed_carried_hash_is_rejected_on_replay() {
        let evidence = ConsistencyProofEvidence {
            from_size: 1,
            to_size: 2,
            path: vec!["not-a-hash".to_owned()],
        };
        assert!(verify_extension_failure(&evidence, "sha256:aa", "sha256:bb").is_err());
    }
}
