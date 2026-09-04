//! Arbitrary bytes through the signed checkpoint object: the adaptor profile §6.3 time
//! grammar, the 98-byte blob assembly of §6.1, and the §6.5 signature check.
//!
//! `parse_checkpoint_time` must reject anything that is not the exact nine-fractional-digit
//! rendering, including values that parse but do not round-trip; `checkpoint_blob` reads two
//! family strings and a `u64` straight out of the object; `verify_checkpoint_signature`
//! compares an optional caller-supplied raw blob byte for byte and then verifies. None of
//! the three may panic, whatever the object carries.

#![no_main]

use ahl_witness::checkpoint::{
    checkpoint_blob, parse_checkpoint_time, render_checkpoint_time, verify_checkpoint_signature,
    Checkpoint,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(fx) = ahl_witness_fuzz::fixture() else { return };
    let Ok(cp) = serde_json::from_slice::<Checkpoint>(data) else { return };

    let _ = parse_checkpoint_time(&cp.checkpoint_time);
    // `tree_size` is an unconstrained `u64` from the body, and the renderer is the one place
    // it reaches a calendar computation.
    let _ = render_checkpoint_time(cp.tree_size);
    let _ = checkpoint_blob(&cp);

    let _ = verify_checkpoint_signature(&cp, None, &fx.anchor.log_id, &fx.log_verifying_key);
    // The same object again with a raw blob attached, so the §6.4 byte comparison runs.
    let _ = verify_checkpoint_signature(&cp, Some(data), &fx.anchor.log_id, &fx.log_verifying_key);
});
