//! `ahl-witness` — an independent AHL witness implementing the core spec §3.3 state machine
//! for the `ahl-adaptor-atl-v1` profile.
//!
//! # What this crate is
//!
//! Inclusion and consistency proofs establish consistency only within the view a verifier is
//! shown; a log operator can present different histories to different parties. Core spec
//! §3.3 requires, at conformance level L3, at least one **independent witness** per log — a
//! party outside the producer's and operator's control that verifies each new checkpoint
//! against the one it already holds, countersigns it on success, publishes the result, and
//! refuses (with signed evidence) when the log presents something inconsistent. The
//! underlying ATL log has no witness role at all (adaptor profile §11), so this component is
//! what makes L3 reachable.
//!
//! # Architecture
//!
//! A library plus a thin binary (`src/bin/ahl-witness.rs`), the same shape as the sibling
//! `ahl-mirror`:
//!
//! | module | responsibility |
//! | --- | --- |
//! | [`metadata`] | the fixed ATL adaptor metadata object (§4.2) and the log-tree leaf hash |
//! | [`duration`] | ISO 8601 duration parsing for `checkpoint_cadence`/`witness_grace_period` |
//! | [`checkpoint`] | the signed checkpoint object, its 98-byte ATL blob, and signature verification (§6) |
//! | [`config`] | genesis governance anchors (one per watched log) and the witness's own signing identity |
//! | [`governance`] | the verified governance chain walk: producer-signature and `predecessor` checks, checkpoint-signing key, cadence and grace-period resolution |
//! | [`consistency`] | classifying an offered checkpoint against the retained one: consistent, inconsistent, or proof-unavailable |
//! | [`witness`] | the core spec §3.3 state machine: cosigning, refusal evidence, their signatures and verification |
//! | [`freshness`] | staleness of the latest cosigned checkpoint against cadence + grace period (§3.3 item 4) |
//! | [`store`] | durable storage for retained/cosigned checkpoints and published refusal evidence |
//! | [`http`] | the publication interface: submit a checkpoint to be witnessed, read cosigned checkpoints, refusal evidence, and freshness |
//!
//! # What this crate is not
//!
//! It does not walk the statement graph (inputs, outputs, triggers, closure) and does not
//! interpret dataset, pipeline, or retention semantics — those are a verifier's job (core
//! spec §6). It does not serve entries or range proofs — that is `ahl-mirror`'s and any
//! independent mirror's job (core spec §3.5). A witness's scope is narrowly the §3.3 state
//! machine: verify, cosign or refuse, publish, and report its own freshness.
//!
//! # Reuse, not reimplementation
//!
//! Canonicalization, family-string parsing, envelope/checkpoint identifiers, cosignature
//! byte construction and Merkle tree primitives are reused from [`ahl_core`] rather than
//! reimplemented. See the crate README ("Why this duplicates `ahl-mirror`'s `manifest`
//! module") for the one deliberate exception: this crate re-derives governance-chain
//! verification independently of `ahl-mirror`, because a witness's independence from log
//! operator infrastructure (core spec §3.3) would otherwise be conditional on trusting a
//! mirror's computation of it.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(missing_docs, rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
// `ahl-core`'s pinned `atl-core` revision brings `thiserror` 1.x (and the `syn` 2.x it needs)
// while this crate's own `thiserror` is 2.x (needing `syn` 3.x): see ahl-core's Cargo.toml
// for the fuller rationale. Not actionable from library code.
#![allow(clippy::multiple_crate_versions)]
// Test code favours `.expect()` messages that document the fixture and, occasionally,
// `panic!` inside a match arm the test proves unreachable. Production code paths are held to
// the deny above without exception.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)
)]

pub mod checkpoint;
pub mod config;
pub mod consistency;
pub mod duration;
pub mod error;
pub mod freshness;
pub mod governance;
pub mod http;
pub mod metadata;
pub mod store;
pub mod witness;

pub use config::{Deployment, DeploymentSpec, LogAnchor, LogAnchorSpec};
pub use error::{WitnessError, WitnessResult};
pub use store::Store;

/// The current instant as unix nanoseconds.
///
/// # Errors
///
/// Returns [`WitnessError::IndexOverflow`] if the system clock is set before the unix epoch
/// (never true for any real deployment).
pub fn now_nanos() -> WitnessResult<u64> {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    u64::try_from(nanos).map_err(|_| WitnessError::IndexOverflow { what: "system clock" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_nanos_is_after_the_epoch_and_monotone_enough_for_a_test() {
        let a = now_nanos().expect("clock available");
        let b = now_nanos().expect("clock available");
        assert!(a > 0);
        assert!(b >= a);
    }
}
