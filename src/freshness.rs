//! Freshness: staleness of the latest cosigned checkpoint against cadence + grace period
//! (core spec §3.3 item 4; adaptor profile §11.3).
//!
//! "A witness whose latest cosigned checkpoint is older than the declared cadence by more
//! than the declared grace period is stale; verifiers treat staleness as a finding" (core
//! spec §3.3). This is a **reporting** obligation, not a refusal condition: a stale witness
//! still runs the ordinary state machine on a new checkpoint (core spec §3.3 does not name
//! staleness as a reason to withhold cosigning), but MUST expose its own staleness through
//! the publication interface rather than silently looking current.

use crate::checkpoint::parse_checkpoint_time;
use crate::error::WitnessResult;

/// The result of a freshness check for one log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Freshness {
    /// Whether the latest cosigned checkpoint is stale.
    pub stale: bool,
    /// How old the latest cosigned checkpoint's `checkpoint_time` is, in nanoseconds, as of
    /// the moment evaluated.
    pub age_nanos: u64,
    /// The staleness threshold: cadence + grace period, both taken from the manifest version
    /// that governed the retained checkpoint — core spec §3.3: staleness is "judged against
    /// the cadence of the manifest version governing the range in question, not against the
    /// current version's value", and adaptor profile §11.3 states the same rule for grace
    /// period.
    pub threshold_nanos: u64,
}

/// Evaluate freshness for a retained checkpoint's `checkpoint_time`, cadence and grace period.
///
/// # Errors
///
/// Propagates a parse failure if `checkpoint_time` is not the exact adaptor profile §6.3
/// rendering.
pub fn evaluate(
    checkpoint_time: &str,
    cadence_nanos: u64,
    grace_nanos: u64,
    now_nanos: u64,
) -> WitnessResult<Freshness> {
    let checkpoint_nanos = parse_checkpoint_time(checkpoint_time)?;
    let age_nanos = now_nanos.saturating_sub(checkpoint_nanos);
    let threshold_nanos = cadence_nanos.saturating_add(grace_nanos);
    Ok(Freshness { stale: age_nanos > threshold_nanos, age_nanos, threshold_nanos })
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-01-01T00:00:00.000000000Z";

    #[test]
    fn within_cadence_plus_grace_is_fresh() {
        let cadence = 300_000_000_000; // PT5M
        let grace = 60_000_000_000; // PT1M
        let now = crate::checkpoint::parse_checkpoint_time(T0).expect("well-formed") + cadence;
        let fresh = evaluate(T0, cadence, grace, now).expect("well-formed");
        assert!(!fresh.stale);
    }

    #[test]
    fn beyond_cadence_plus_grace_is_stale() {
        let cadence = 300_000_000_000;
        let grace = 60_000_000_000;
        let now = crate::checkpoint::parse_checkpoint_time(T0).expect("well-formed")
            + cadence
            + grace
            + 1;
        let stale = evaluate(T0, cadence, grace, now).expect("well-formed");
        assert!(stale.stale);
        assert_eq!(stale.threshold_nanos, cadence + grace);
    }

    #[test]
    fn exactly_at_the_threshold_is_not_yet_stale() {
        let cadence = 300_000_000_000;
        let grace = 60_000_000_000;
        let now =
            crate::checkpoint::parse_checkpoint_time(T0).expect("well-formed") + cadence + grace;
        let fresh = evaluate(T0, cadence, grace, now).expect("well-formed");
        assert!(!fresh.stale);
    }

    #[test]
    fn a_malformed_checkpoint_time_is_rejected() {
        assert!(evaluate("not-a-time", 1, 1, 1).is_err());
    }
}
