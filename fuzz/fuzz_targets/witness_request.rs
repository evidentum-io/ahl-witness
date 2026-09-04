//! Arbitrary bytes as the body of `POST /v1/logs/{log_id}/witness` — the crate's only
//! request body, and its widest entry point.
//!
//! The target reproduces exactly what the handler does with a decoded body: pull
//! `checkpoint`, `raw` and `entries[]`, decode the two base64 fields, and hand the result to
//! the state machine. Behind that call sit the governance chain walk over attacker-supplied
//! entries, checkpoint blob assembly and signature verification, the consistency
//! classification against the retained checkpoint, and the store transition. None of it may
//! panic on any body, however malformed.

#![no_main]

use ahl_witness::checkpoint::Checkpoint;
use ahl_witness::witness::witness_checkpoint;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Some(fx) = ahl_witness_fuzz::fixture() else { return };
    let Ok(body) = serde_json::from_slice::<Value>(data) else { return };

    let Some(checkpoint) = body.get("checkpoint") else { return };
    let Ok(checkpoint) = serde_json::from_value::<Checkpoint>(checkpoint.clone()) else { return };

    // `raw` is optional; a present-but-undecodable value is a request rejection in the
    // handler, so the target stops there too rather than passing `None` and testing a body
    // the server would never have accepted.
    let raw = match body.get("raw") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => match ahl_witness_fuzz::decode_base64_field(text) {
            Some(bytes) => Some(bytes),
            None => return,
        },
        Some(_) => return,
    };

    let Some(entries) = body.get("entries").and_then(Value::as_array) else { return };
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(text) = entry.as_str() else { return };
        let Some(bytes) = ahl_witness_fuzz::decode_base64_field(text) else { return };
        decoded.push(bytes);
    }

    // Primed, so the equivocation, size-regression and extension-failed branches are
    // reachable; fresh per input, so the run is deterministic.
    let Some(store) = ahl_witness_fuzz::primed_store() else { return };
    let _ = witness_checkpoint(
        &store,
        &fx.signer,
        &fx.anchor,
        &checkpoint,
        raw.as_deref(),
        &decoded,
        ahl_witness_fuzz::NOW_NANOS,
    );
});
