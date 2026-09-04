//! Regenerate `fuzz/seeds/`.
//!
//! The crate under test has no committed test data — its fixtures are built in code inside
//! `#[cfg(test)]` modules — so the seeds are built here from the same deterministic keys and
//! written out, rather than transcribed. Run from `fuzz/`:
//!
//! ```sh
//! cargo +nightly run --example gen_seeds
//! ```
//!
//! This is not a fuzz target: `cargo fuzz build` builds the crate's `[[bin]]` targets only.

use std::fs;
use std::path::Path;

use ahl_witness::checkpoint::{checkpoint_blob, Checkpoint};
use ahl_witness::store::Store;
use ahl_witness::witness::{witness_checkpoint, Submission, WitnessOutcome};
use ahl_witness_fuzz::{
    fixture, key_statement_bytes, rotating_manifest_bytes, signed_checkpoint,
    witness_request_value, GENESIS_CHECKPOINT_TIME, NOW_NANOS,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

fn main() {
    if run().is_none() {
        eprintln!("could not build the fixtures the seeds are derived from");
        std::process::exit(1);
    }
}

fn write(target: &str, name: &str, bytes: &[u8]) -> Option<()> {
    let dir = Path::new("seeds").join(target);
    fs::create_dir_all(&dir).ok()?;
    fs::write(dir.join(name), bytes).ok()?;
    Some(())
}

fn write_json(target: &str, name: &str, value: &Value) -> Option<()> {
    write(target, name, serde_json::to_string_pretty(value).ok()?.as_bytes())
}

/// A checkpoint over `entries` but claiming `root_hash`, signed by the log key: the shape of
/// every checkpoint the witness authenticates and then refuses.
fn checkpoint_claiming(tree_size: u64, root_hash: &str, time: &str) -> Option<Checkpoint> {
    let fx = fixture()?;
    let mut cp = Checkpoint {
        log_id: fx.anchor.log_id.clone(),
        tree_size,
        root_hash: root_hash.to_owned(),
        checkpoint_time: time.to_owned(),
        key_id: fx.log_key.key_id(),
        signature: String::new(),
    };
    cp.signature = fx.log_key.sign(&checkpoint_blob(&cp).ok()?);
    Some(cp)
}

fn request_of(cp: &Checkpoint, entries: &[Vec<u8>]) -> Option<Value> {
    Some(json!({
        "checkpoint": serde_json::to_value(cp).ok()?,
        "raw": format!("base64:{}", B64.encode(checkpoint_blob(cp).ok()?)),
        "entries": entries
            .iter()
            .map(|bytes| Value::String(format!("base64:{}", B64.encode(bytes))))
            .collect::<Vec<_>>(),
    }))
}

fn run() -> Option<()> {
    let fx = fixture()?;
    let genesis = vec![fx.genesis_bytes.clone()];
    let two = vec![fx.genesis_bytes.clone(), key_statement_bytes()?];
    let other_root = format!("sha256:{}", "cd".repeat(32));

    // --- witness_request -------------------------------------------------------------
    let cosigning = witness_request_value(&genesis, GENESIS_CHECKPOINT_TIME)?;
    write_json("witness_request", "00-cosign-genesis.json", &cosigning)?;
    write_json(
        "witness_request",
        "01-cosign-two-entries.json",
        &witness_request_value(&two, "2026-01-01T00:05:00.000000000Z")?,
    )?;
    let equivocating = checkpoint_claiming(1, &other_root, "2026-01-01T00:05:00.000000000Z")?;
    write_json(
        "witness_request",
        "02-equivocation-at-the-same-size.json",
        &request_of(&equivocating, &genesis)?,
    )?;
    let extension_failed = checkpoint_claiming(2, &other_root, "2026-01-01T00:05:00.000000000Z")?;
    write_json(
        "witness_request",
        "03-extension-failure.json",
        &request_of(&extension_failed, &two)?,
    )?;
    let unsigned = json!({
        "checkpoint": serde_json::to_value(signed_checkpoint(&genesis, GENESIS_CHECKPOINT_TIME)?)
            .ok()?,
        "entries": [format!("base64:{}", B64.encode(&fx.genesis_bytes))],
    });
    write_json("witness_request", "04-no-raw-blob.json", &unsigned)?;
    // The transition exception (I-D §7.1): entry 1 rotates the log key set, and the offered
    // checkpoint of tree_size 2 is signed by the OUTGOING key, so it fails under the state
    // active for its own size and is retried under the predecessor's.
    let rotated = vec![fx.genesis_bytes.clone(), rotating_manifest_bytes()?];
    let rotation_root = format!(
        "sha256:{}",
        hex::encode(atl_core::core::merkle::compute_root(
            &rotated.iter().map(|b| ahl_witness::metadata::log_leaf_hash(b)).collect::<Vec<_>>()
        ))
    );
    let rotation_cp = checkpoint_claiming(2, &rotation_root, "2026-01-01T00:05:00.000000000Z")?;
    write_json(
        "witness_request",
        "05-rotation-anchoring.json",
        &request_of(&rotation_cp, &rotated)?,
    )?;
    // The same submission, NAMING the rotation it is offered for, which is the other way into
    // the transition exception and the only way to reach its named-mismatch refusals.
    let mut named = request_of(&rotation_cp, &rotated)?;
    if let Some(object) = named.as_object_mut() {
        object.insert("rotation_for".to_owned(), json!(1));
    }
    write_json("witness_request", "06-rotation-named.json", &named)?;
    let mut mismatched = named.clone();
    if let Some(object) = mismatched.as_object_mut() {
        object.insert("rotation_for".to_owned(), json!(0));
    }
    write_json("witness_request", "07-rotation-named-mismatch.json", &mismatched)?;

    // --- checkpoint ------------------------------------------------------------------
    let genesis_cp = signed_checkpoint(&genesis, GENESIS_CHECKPOINT_TIME)?;
    write_json("checkpoint", "00-signed.json", &serde_json::to_value(&genesis_cp).ok()?)?;
    let mut wrong_time = genesis_cp.clone();
    wrong_time.checkpoint_time = "2026-01-01T00:00:00Z".to_owned();
    write_json(
        "checkpoint",
        "01-time-not-round-tripping.json",
        &serde_json::to_value(&wrong_time).ok()?,
    )?;
    let mut wrong_sig = genesis_cp.clone();
    wrong_sig.signature = format!("base64:{}", B64.encode([0u8; 64]));
    write_json("checkpoint", "02-signature-invalid.json", &serde_json::to_value(&wrong_sig).ok()?)?;
    let mut huge = genesis_cp.clone();
    huge.tree_size = u64::MAX;
    write_json(
        "checkpoint",
        "03-tree-size-at-the-maximum.json",
        &serde_json::to_value(&huge).ok()?,
    )?;

    // --- governance ------------------------------------------------------------------
    write("governance", "00-genesis-manifest.json", &fx.genesis_bytes)?;
    write("governance", "01-key-add.json", &key_statement_bytes()?)?;
    write("governance", "02-duration-cadence.txt", b"PT5M")?;
    write("governance", "03-duration-full.txt", b"P1DT2H3M4.123456789S")?;
    write("governance", "04-duration-prohibited-month.txt", b"P1M")?;

    // --- refusal ---------------------------------------------------------------------
    let store = Store::open_in_memory().ok()?;
    witness_checkpoint(
        &store,
        &fx.signer,
        &fx.anchor,
        &Submission { checkpoint: &signed_checkpoint(&genesis, GENESIS_CHECKPOINT_TIME)?, raw: None, entries_prefix: &genesis, rotation_for: None },
        NOW_NANOS,
    )
    .ok()?;
    let refused = witness_checkpoint(
        &store,
        &fx.signer,
        &fx.anchor,
        &Submission { checkpoint: &extension_failed, raw: None, entries_prefix: &two, rotation_for: None },
        NOW_NANOS,
    )
    .ok()?;
    match refused {
        WitnessOutcome::Refused(evidence) => {
            write_json(
                "refusal",
                "00-extension-failed.json",
                &serde_json::to_value(&*evidence).ok()?,
            )?;
        }
        _ => return None,
    }

    let equivocation_store = Store::open_in_memory().ok()?;
    witness_checkpoint(
        &equivocation_store,
        &fx.signer,
        &fx.anchor,
        &Submission { checkpoint: &signed_checkpoint(&genesis, GENESIS_CHECKPOINT_TIME)?, raw: None, entries_prefix: &genesis, rotation_for: None },
        NOW_NANOS,
    )
    .ok()?;
    let refused = witness_checkpoint(
        &equivocation_store,
        &fx.signer,
        &fx.anchor,
        &Submission { checkpoint: &equivocating, raw: None, entries_prefix: &genesis, rotation_for: None },
        NOW_NANOS,
    )
    .ok()?;
    match refused {
        WitnessOutcome::Refused(evidence) => {
            write_json("refusal", "01-equivocation.json", &serde_json::to_value(&*evidence).ok()?)?;
        }
        _ => return None,
    }

    let cosigned_store = Store::open_in_memory().ok()?;
    let cosigned = witness_checkpoint(
        &cosigned_store,
        &fx.signer,
        &fx.anchor,
        &Submission { checkpoint: &signed_checkpoint(&genesis, GENESIS_CHECKPOINT_TIME)?, raw: None, entries_prefix: &genesis, rotation_for: None },
        NOW_NANOS,
    )
    .ok()?;
    match cosigned {
        WitnessOutcome::Cosigned { cosigned: checkpoint, .. } => {
            write_json(
                "refusal",
                "02-cosigned-checkpoint.json",
                &serde_json::to_value(&*checkpoint).ok()?,
            )?;
        }
        _ => return None,
    }

    // --- config ----------------------------------------------------------------------
    write_json("config", "00-deployment.json", &ahl_witness_fuzz::deployment_config_value()?)?;
    write_json(
        "config",
        "01-anchor.json",
        &json!({
            "log_id": fx.anchor.log_id,
            "genesis_manifest_entry_id": fx.anchor.genesis_manifest_entry_id,
            "genesis_producer_keys": [{
                "key_id": fx.producer.key_id(),
                "pubkey": fx.producer.pubkey(),
                "valid_from_index": 0,
            }],
        }),
    )?;

    println!("seeds written");
    Some(())
}
