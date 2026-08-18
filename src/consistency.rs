//! Consistency classification between a retained and an offered checkpoint (core spec §3.3
//! step 2; §7.3 "Equivocation ends the series"; adaptor profile §11.2).

use atl_core::core::merkle::{generate_consistency_proof, verify_consistency, Hash};

use crate::checkpoint::Checkpoint;
use crate::error::WitnessResult;

/// The outcome of comparing an offered checkpoint against the retained one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsistencyOutcome {
    /// `offered` is a valid append-only extension of `retained`, or an idempotent republish
    /// of it (same `tree_size`, same `root_hash`).
    Consistent,
    /// **Equivocation**: `retained` and `offered` share a `tree_size` but carry different
    /// `root_hash` values. Core spec §7.3: "Two authenticated members sharing a `tree_size`
    /// with differing `root_hash` values are equivocation, not a tie … Detecting equivocation
    /// and then continuing to serve one branch is a conformance violation." This is a
    /// distinct, terminal outcome from [`Self::Inconsistent`] precisely because it must be
    /// handled differently by the caller: see [`crate::witness`]'s equivocation-floor
    /// tracking.
    Equivocation,
    /// `offered` conflicts with `retained` in some other way: a `tree_size` regression (no
    /// append-only tree ever shrinks, so a smaller offered `tree_size` is never consistent
    /// with a larger retained one), or a consistency proof that was generated but did not
    /// verify against the two claimed roots.
    Inconsistent,
    /// A consistency proof could not even be generated from the supplied entries — adaptor
    /// profile §11.2's `missing-consistency-proof` reason.
    ProofUnavailable,
}

/// Classify `offered` against `retained`, given leaf hashes covering `[0, offered.tree_size)`.
///
/// `leaf_hashes` MUST be the AHL log-tree leaf hashes (see [`crate::metadata::log_leaf_hash`])
/// for entries `[0, offered.tree_size)`, in entry-index order.
///
/// # Errors
///
/// Propagates a parsing error if either checkpoint's `root_hash` is not a well-formed
/// `sha256:<hex>` family string.
pub fn check(
    retained: &Checkpoint,
    offered: &Checkpoint,
    leaf_hashes: &[Hash],
) -> WitnessResult<ConsistencyOutcome> {
    if offered.tree_size < retained.tree_size {
        return Ok(ConsistencyOutcome::Inconsistent);
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
    let Ok(proof) =
        generate_consistency_proof(retained.tree_size, offered.tree_size, |level, index| {
            if level == 0 {
                leaf_hashes.get(usize::try_from(index).ok()?).copied()
            } else {
                None
            }
        })
    else {
        return Ok(ConsistencyOutcome::ProofUnavailable);
    };
    Ok(if verify_consistency(&proof, &retained_root, &offered_root).unwrap_or(false) {
        ConsistencyOutcome::Consistent
    } else {
        ConsistencyOutcome::Inconsistent
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn an_unrelated_larger_tree_is_inconsistent_not_equivocation() {
        // Different tree_size: a failed extension proof, not the equal-size equivocation
        // case core spec §7.3 names specifically.
        let leaves: Vec<Hash> = (0u8..8).map(leaf).collect();
        let retained = cp(4, atl_core::core::merkle::compute_root(&leaves[..4]));
        let mut offered = cp(8, atl_core::core::merkle::compute_root(&leaves[..8]));
        offered.root_hash = format!("sha256:{}", "00".repeat(32));
        assert_eq!(
            check(&retained, &offered, &leaves).expect("well-formed"),
            ConsistencyOutcome::Inconsistent
        );
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
    fn a_shrinking_tree_size_is_inconsistent() {
        let leaves: Vec<Hash> = (0u8..8).map(leaf).collect();
        let retained = cp(8, atl_core::core::merkle::compute_root(&leaves));
        let offered = cp(4, atl_core::core::merkle::compute_root(&leaves[..4]));
        assert_eq!(
            check(&retained, &offered, &leaves).expect("well-formed"),
            ConsistencyOutcome::Inconsistent
        );
    }

    #[test]
    fn insufficient_leaves_report_proof_unavailable_rather_than_erroring() {
        // `retained` claims a tree_size the supplied `leaf_hashes` slice does not cover.
        let leaves: Vec<Hash> = (0u8..2).map(leaf).collect();
        let retained = cp(4, [0x11u8; 32]);
        let offered = cp(8, [0x22u8; 32]);
        assert_eq!(
            check(&retained, &offered, &leaves).expect("well-formed"),
            ConsistencyOutcome::ProofUnavailable
        );
    }
}
