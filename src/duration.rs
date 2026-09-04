//! An ISO 8601 duration parser for `checkpoint_cadence`/`witness_grace_period` (core spec
//! §7.3).
//!
//! Core spec §7.3 restricts these fields to the time-only subset of ISO 8601:
//! `P[n]DT[n]H[n]M[n]S` — days, hours, minutes, seconds. Years and calendar months are
//! **PROHIBITED**, normatively, because their length is context-dependent: admitting them
//! would make cadence, frontier, completeness and freshness computations
//! implementation-dependent, since two conformant parsers could map the same manifest to
//! different nanosecond totals. A value carrying `Y`, or `M` in the date part (a calendar
//! month, as opposed to `M` after `T`, which is minutes), is malformed and MUST be rejected
//! rather than approximated.
//!
//! A witness needs `witness_grace_period` for its own purpose — the [`crate::freshness`]
//! computation of core spec §3.3 item 4 — where `ahl-mirror`'s sibling parser only checks it
//! parses and discards the value (a mirror has no freshness obligation of its own). The
//! grammar and error taxonomy are otherwise identical by design: the two components MUST NOT
//! disagree about what a duration means.
//!
//! Fractional seconds MAY carry at most nine digits (core spec §7.3, "Fractional seconds");
//! a value with more is malformed and MUST be rejected outright, never truncated or rounded
//! — truncation would make the value implementation-dependent in exactly the way the
//! time-only-component restriction exists to prevent. `checkpoint_cadence` itself MUST be
//! greater than zero (same clause); that check is applied where cadence is resolved (see
//! [`crate::governance`]), since this module parses both `checkpoint_cadence` and
//! `witness_grace_period` through the same grammar and only the former carries the
//! positivity requirement.

use crate::error::{WitnessError, WitnessResult};

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_DAY: u64 = 86_400;

/// Parse an ISO 8601 duration of the core spec §7.3 time-only subset to a total nanosecond
/// count.
///
/// # Errors
///
/// Returns [`WitnessError::ProhibitedDurationComponent`] if `value` carries `Y`, or `M` in
/// the date part. Returns [`WitnessError::BadDuration`] if `value` is otherwise not a
/// well-formed duration of the `P[n]DT[n]H[n]M[n]S` grammar, or if the total overflows `u64`
/// nanoseconds.
pub fn parse_iso8601_duration_nanos(value: &str) -> WitnessResult<u64> {
    let bad = || WitnessError::BadDuration { value: value.to_owned() };
    let rest = value.strip_prefix('P').ok_or_else(bad)?;
    if rest.is_empty() {
        return Err(bad());
    }

    if rest.contains('Y') {
        return Err(WitnessError::ProhibitedDurationComponent {
            value: value.to_owned(),
            component: 'Y',
        });
    }

    let (date_part, time_part) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };

    // A literal `M` in the date part is a calendar month (prohibited); a literal `M` in the
    // time part, after `T`, is minutes (allowed) — checked only on `date_part` here.
    if date_part.contains('M') {
        return Err(WitnessError::ProhibitedDurationComponent {
            value: value.to_owned(),
            component: 'M',
        });
    }

    let mut total_seconds: u64 = 0;
    let mut cursor = date_part;
    if let Some((n, remainder)) = take_component(cursor, 'D')? {
        total_seconds = n.checked_mul(SECONDS_PER_DAY).ok_or_else(bad)?;
        cursor = remainder;
    }
    if !cursor.is_empty() {
        return Err(bad());
    }

    let mut extra_nanos: u64 = 0;
    if let Some(time_part) = time_part {
        if time_part.is_empty() {
            return Err(bad());
        }
        let mut cursor = time_part;
        for (unit, seconds_per_unit) in [('H', SECONDS_PER_HOUR), ('M', SECONDS_PER_MINUTE)] {
            if let Some((n, remainder)) = take_component(cursor, unit)? {
                total_seconds = total_seconds
                    .checked_add(n.checked_mul(seconds_per_unit).ok_or_else(bad)?)
                    .ok_or_else(bad)?;
                cursor = remainder;
            }
        }
        if let Some(seconds_str) = cursor.strip_suffix('S') {
            if seconds_str.is_empty() {
                return Err(bad());
            }
            let (whole, frac_nanos) = match seconds_str.split_once('.') {
                Some((w, f)) => {
                    if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(bad());
                    }
                    // Core spec §7.3 "Fractional seconds": at most nine digits; more is
                    // malformed and MUST be rejected, never truncated or rounded — truncation
                    // would make the value implementation-dependent in exactly the way the
                    // component restriction exists to prevent.
                    if f.len() > 9 {
                        return Err(bad());
                    }
                    let mut digits = f.to_owned();
                    while digits.len() < 9 {
                        digits.push('0');
                    }
                    (w, digits.parse::<u64>().map_err(|_| bad())?)
                }
                None => (seconds_str, 0),
            };
            let whole: u64 = whole.parse().map_err(|_| bad())?;
            total_seconds = total_seconds.checked_add(whole).ok_or_else(bad)?;
            extra_nanos = frac_nanos;
            cursor = "";
        }
        if !cursor.is_empty() {
            return Err(bad());
        }
    }

    total_seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|n| n.checked_add(extra_nanos))
        .ok_or_else(bad)
}

/// Consume a leading `"<digits><unit>"` component from `input`, if the next unit character
/// present in `input` (before any other recognised unit letter) is `unit`. Returns the parsed
/// value and the remainder, or `None` if `input` does not start with a component of this unit.
fn take_component(input: &str, unit: char) -> WitnessResult<Option<(u64, &str)>> {
    // `split_once` yields the same two halves a `find` plus range slicing would, and yields
    // them without an index arithmetic step and without assuming `unit` is one byte wide.
    let Some((digits, remainder)) = input.split_once(unit) else { return Ok(None) };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WitnessError::BadDuration { value: input.to_owned() });
    }
    let n: u64 =
        digits.parse().map_err(|_| WitnessError::BadDuration { value: input.to_owned() })?;
    Ok(Some((n, remainder)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_cadence_values_parse() {
        assert_eq!(parse_iso8601_duration_nanos("PT1S").expect("valid"), 1_000_000_000);
        assert_eq!(parse_iso8601_duration_nanos("PT5M").expect("valid"), 300_000_000_000);
        assert_eq!(parse_iso8601_duration_nanos("PT1H").expect("valid"), 3_600_000_000_000);
        assert_eq!(parse_iso8601_duration_nanos("P1D").expect("valid"), 86_400_000_000_000);
        assert_eq!(
            parse_iso8601_duration_nanos("P1DT12H").expect("valid"),
            (86_400 + 43_200) * 1_000_000_000
        );
    }

    #[test]
    fn fractional_seconds_are_honoured() {
        assert_eq!(parse_iso8601_duration_nanos("PT0.5S").expect("valid"), 500_000_000);
        assert_eq!(parse_iso8601_duration_nanos("PT1.000000001S").expect("valid"), 1_000_000_001);
    }

    #[test]
    fn malformed_durations_are_rejected() {
        assert!(parse_iso8601_duration_nanos("5M").is_err());
        assert!(parse_iso8601_duration_nanos("P").is_err());
        assert!(parse_iso8601_duration_nanos("PT").is_err());
        assert!(parse_iso8601_duration_nanos("PTM").is_err());
        assert!(parse_iso8601_duration_nanos("PT5X").is_err());
        assert!(parse_iso8601_duration_nanos("P1H").is_err());
        assert!(parse_iso8601_duration_nanos("PT1.S").is_err());
    }

    #[test]
    fn weeks_are_outside_the_core_spec_grammar_and_rejected() {
        assert!(matches!(
            parse_iso8601_duration_nanos("P1W"),
            Err(WitnessError::BadDuration { .. })
        ));
    }

    #[test]
    fn years_are_rejected_as_a_prohibited_component_not_approximated() {
        let err = parse_iso8601_duration_nanos("P1Y").expect_err("years are prohibited");
        assert!(matches!(err, WitnessError::ProhibitedDurationComponent { component: 'Y', .. }));
    }

    #[test]
    fn calendar_months_are_rejected_as_a_prohibited_component_not_approximated() {
        let err = parse_iso8601_duration_nanos("P1M").expect_err("calendar months are prohibited");
        assert!(matches!(err, WitnessError::ProhibitedDurationComponent { component: 'M', .. }));
        let err =
            parse_iso8601_duration_nanos("P1M2D").expect_err("calendar months are prohibited");
        assert!(matches!(err, WitnessError::ProhibitedDurationComponent { component: 'M', .. }));
    }

    #[test]
    fn minutes_after_t_are_not_confused_with_calendar_months() {
        assert_eq!(parse_iso8601_duration_nanos("PT10M").expect("valid"), 600_000_000_000);
    }

    #[test]
    fn a_year_component_is_rejected_even_alongside_other_prohibited_or_valid_parts() {
        assert!(matches!(
            parse_iso8601_duration_nanos("P1Y2D"),
            Err(WitnessError::ProhibitedDurationComponent { component: 'Y', .. })
        ));
    }

    #[test]
    fn overflow_is_rejected_rather_than_wrapping() {
        assert!(parse_iso8601_duration_nanos(&format!("P{}D", u64::MAX)).is_err());
    }

    #[test]
    fn nine_fractional_digits_are_the_maximum_and_are_honoured_exactly() {
        assert_eq!(parse_iso8601_duration_nanos("PT0.123456789S").expect("valid"), 123_456_789);
    }

    #[test]
    fn ten_fractional_digits_are_rejected_rather_than_truncated() {
        // Core spec §7.3: more than nine fractional digits is malformed and MUST be
        // rejected, never truncated or rounded away.
        assert!(matches!(
            parse_iso8601_duration_nanos("PT0.1234567891S"),
            Err(WitnessError::BadDuration { .. })
        ));
        // In particular this must NOT silently become zero.
        assert!(parse_iso8601_duration_nanos("PT0.0000000009S").is_err());
    }
}
