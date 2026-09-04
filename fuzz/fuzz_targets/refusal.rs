//! Arbitrary bytes as published witness evidence, through the two independent rechecks a
//! verifier runs on it.
//!
//! Refusal evidence and cosigned checkpoints are the crate's published output, so anything
//! reading them back is reading bytes it did not produce. `verify_refusal_claim` replays a
//! carried consistency proof whose `from_size`, `to_size` and path come straight out of the
//! document; `verify_cosignature` and `verify_refusal_signature` recanonicalize the object
//! and verify over it. None of them may panic on evidence that is well-typed but absurd.

#![no_main]

use ahl_witness::witness::{
    refusal_signing_bytes, verify_cosignature, verify_refusal_claim, verify_refusal_signature,
    CosignedCheckpoint, RefusalEvidence,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(key) = ahl_witness_fuzz::witness_verifying_key() else { return };

    if let Ok(evidence) = serde_json::from_slice::<RefusalEvidence>(data) {
        let _ = verify_refusal_claim(&evidence);
        let _ = refusal_signing_bytes(&evidence);
        let _ = verify_refusal_signature(&evidence, &key);
    }

    if let Ok(cosigned) = serde_json::from_slice::<CosignedCheckpoint>(data) {
        let _ = verify_cosignature(&cosigned, &key);
    }
});
