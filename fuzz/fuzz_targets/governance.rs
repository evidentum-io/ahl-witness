//! Arbitrary bytes as an anchored entry, through the governance chain walk.
//!
//! `resolve` reads every entry the client submitted, picks out `manifest` and `key`
//! statements, verifies their envelopes against the out-of-band anchor, and derives the
//! checkpoint-signing key set, the cadence and the grace period. Each input is offered twice
//! — as entry 0, where it must be a genesis manifest matching the anchor, and as entry 1
//! after the real genesis, where the key-statement branch and manifest resnapshot branch
//! live. The §7.3 duration grammar a manifest carries is driven directly from the same
//! bytes, since it is where the parser's only arithmetic sits.

#![no_main]

use ahl_witness::duration::parse_iso8601_duration_nanos;
use ahl_witness::governance;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(fx) = ahl_witness_fuzz::fixture() else { return };

    let _ = governance::resolve(&[data.to_vec()], &fx.anchor);
    let _ = governance::resolve(&[fx.genesis_bytes.clone(), data.to_vec()], &fx.anchor);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_iso8601_duration_nanos(text);
    }
});
