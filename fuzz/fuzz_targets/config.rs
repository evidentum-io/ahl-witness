//! Arbitrary bytes as the deployment configuration file the binary reads at startup, and as
//! a single log anchor within it.
//!
//! The file is JSON read from disk, so it is not attacker input in the way a request body
//! is; it is fuzzed because resolution decodes a hex seed and a public key per configured
//! log, recomputes each `key_id` from its `pubkey`, and must report a malformed file as an
//! error the operator can read rather than as an abort at startup.

#![no_main]

use ahl_witness::config::{Deployment, DeploymentSpec, LogAnchor, LogAnchorSpec};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(spec) = serde_json::from_slice::<DeploymentSpec>(data) {
        let _ = Deployment::resolve(&spec);
    }
    if let Ok(spec) = serde_json::from_slice::<LogAnchorSpec>(data) {
        let _ = LogAnchor::resolve(&spec);
    }
});
