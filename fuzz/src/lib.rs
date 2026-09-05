//! Shared fixtures for the `ahl-witness` fuzz targets.
//!
//! The crate under test ships no committed corpus, so the fixture is built here from
//! deterministic seeds — the same construction the library's own unit tests use — and cached
//! for the process, so a target does no key generation and no I/O per input. Every accessor
//! returns an `Option` rather than asserting: a fixture that failed to build must not be
//! reported as a crash in the library under test.

use std::sync::OnceLock;

use ahl_core::TestKey;
use ahl_witness::checkpoint::{checkpoint_blob, Checkpoint};
use ahl_witness::config::{
    Ed25519WitnessSigner, KeyObjectSpec, LogAnchor, LogAnchorSpec, WitnessSigner as _,
};
use ahl_witness::store::Store;
use ahl_witness::witness::{witness_checkpoint, Submission};
use atl_core::core::merkle::compute_root;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};

/// A fixed instant, so a target's outcome depends on its input and nothing else. This is
/// `2026-06-01T00:00:00Z` in unix nanoseconds.
pub const NOW_NANOS: u64 = 1_780_272_000_000_000_000;

/// The `checkpoint_time` of the fixture's genesis checkpoint, in the exact
/// nine-fractional-digit form the adaptor profile requires.
pub const GENESIS_CHECKPOINT_TIME: &str = "2026-01-01T00:00:00.000000000Z";

/// Everything a target needs to reach past the crate's authentication boundary: a resolved
/// genesis anchor, the two keys it is built from, this witness's signing identity, and the
/// genesis manifest entry itself.
pub struct Fixture {
    /// The resolved out-of-band genesis anchor for the watched log.
    pub anchor: LogAnchor,
    /// The producer key that signed the genesis manifest.
    pub producer: TestKey,
    /// The log's checkpoint-signing key, as the genesis manifest declares it.
    pub log_key: TestKey,
    /// The decoded form of [`Fixture::log_key`].
    pub log_verifying_key: VerifyingKey,
    /// This witness's own signing identity.
    pub signer: Ed25519WitnessSigner,
    /// `JCS(envelope)` of the genesis manifest — entry 0 of the log.
    pub genesis_bytes: Vec<u8>,
}

fn build_fixture() -> Option<Fixture> {
    let producer = TestKey::from_seed_hex("producer", &"11".repeat(32)).ok()?;
    let log_key = TestKey::from_seed_hex("log", &"aa".repeat(32)).ok()?;
    let log_verifying_key = ahl_core::decode_pubkey(&log_key.pubkey()).ok()?;
    let log_id = format!("sha256:{}", "11aa".repeat(16));

    let payload = json!({
        "type": "manifest",
        "ahl_version": ahl_core::AHL_VERSION,
        "producer": "producer-1",
        "keys": [
            { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
        ],
        "log": {
            "log_id": log_id,
            "operator": "op-1",
            "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
            "checkpoint_cadence": "PT5M",
            "cadence_epoch": "2026-01-01T00:00:00Z",
            "witness_grace_period": "PT1M",
            "keys": [
                { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 }
            ],
        },
    });
    let genesis_bytes = ahl_core::jcs(&ahl_core::envelope(payload, &producer));
    let genesis_value: Value = serde_json::from_slice(&genesis_bytes).ok()?;

    let anchor = LogAnchor::resolve(&LogAnchorSpec {
        log_id,
        genesis_manifest_entry_id: ahl_core::entry_id(&genesis_value),
        genesis_producer_keys: vec![KeyObjectSpec {
            key_id: producer.key_id(),
            pubkey: producer.pubkey(),
            valid_from_index: 0,
        }],
    })
    .ok()?;

    let signer = Ed25519WitnessSigner::from_seed("witness-1", &[9u8; 32]).ok()?;

    Some(Fixture { anchor, producer, log_key, log_verifying_key, signer, genesis_bytes })
}

/// The process-wide fixture, or `None` if it could not be built.
pub fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE.get_or_init(build_fixture).as_ref()
}

/// A manifest version that ROTATES the log key set, chained to the fixture's genesis manifest.
///
/// Anchored at entry index 1, it declares a log checkpoint-signing key the genesis manifest
/// does not, which is what makes it a governance-key rotation under I-D §7.1 — and therefore
/// what lets a seed drive the transition exception: a checkpoint of `tree_size` 2 signed by the
/// genesis (OUTGOING) log key does not verify under this version and is retried under it.
#[must_use]
pub fn rotating_manifest_bytes() -> Option<Vec<u8>> {
    let fx = fixture()?;
    let rotated = TestKey::from_seed_hex("log-2", &"bb".repeat(32)).ok()?;
    let payload = json!({
        "type": "manifest",
        "ahl_version": ahl_core::AHL_VERSION,
        "producer": "producer-1",
        "predecessor": fx.anchor.genesis_manifest_entry_id,
        "keys": [
            { "key_id": fx.producer.key_id(), "pubkey": fx.producer.pubkey(), "valid_from_index": 0 }
        ],
        "log": {
            "log_id": fx.anchor.log_id,
            "operator": "op-1",
            "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
            "checkpoint_cadence": "PT5M",
            "cadence_epoch": "2026-01-01T00:00:00Z",
            "witness_grace_period": "PT1M",
            "keys": [
                { "key_id": rotated.key_id(), "pubkey": rotated.pubkey(), "valid_from_index": 0 }
            ],
        },
    });
    Some(ahl_core::jcs(&ahl_core::envelope(payload, &fx.producer)))
}

/// Decode a `"base64:"`-prefixed field the same way the HTTP layer does.
#[must_use]
pub fn decode_base64_field(value: &str) -> Option<Vec<u8>> {
    B64.decode(value.strip_prefix("base64:")?).ok()
}

/// A checkpoint over the first `entries` of the fixture log, signed by the log key the
/// genesis manifest declares.
#[must_use]
pub fn signed_checkpoint(entries: &[Vec<u8>], time: &str) -> Option<Checkpoint> {
    let fx = fixture()?;
    let leaves: Vec<_> =
        entries.iter().map(|bytes| ahl_witness::metadata::log_leaf_hash(bytes)).collect();
    let mut cp = Checkpoint {
        log_id: fx.anchor.log_id.clone(),
        tree_size: u64::try_from(entries.len()).ok()?,
        root_hash: format!("sha256:{}", hex::encode(compute_root(&leaves))),
        checkpoint_time: time.to_owned(),
        key_id: fx.log_key.key_id(),
        signature: String::new(),
    };
    cp.signature = fx.log_key.sign(&checkpoint_blob(&cp).ok()?);
    Some(cp)
}

/// A fresh in-memory store that already holds one cosigned checkpoint for the fixture log.
///
/// Priming matters for coverage: against an empty store every candidate takes the bootstrap
/// branch, and the consistency, equivocation and refusal branches are unreachable. The
/// priming call is fixed, so a target's behaviour still depends on its input alone.
#[must_use]
pub fn primed_store() -> Option<Store> {
    let fx = fixture()?;
    let store = Store::open_in_memory().ok()?;
    let entries = vec![fx.genesis_bytes.clone()];
    let cp = signed_checkpoint(&entries, GENESIS_CHECKPOINT_TIME)?;
    witness_checkpoint(
        &store,
        &fx.signer,
        &fx.anchor,
        &Submission {
            checkpoint: &cp,
            raw: None,
            entries_prefix: &entries,
            rotation_for: None,
        },
        NOW_NANOS,
    )
    .ok()?;
    Some(store)
}

/// This witness's own verifying key, for the cosignature and refusal-signature checks.
#[must_use]
pub fn witness_verifying_key() -> Option<VerifyingKey> {
    Some(fixture()?.signer.verifying_key())
}

/// The witness request body a well-formed client sends for the genesis-only checkpoint: the
/// shape the `witness_request` target's seeds are built around.
#[must_use]
pub fn witness_request_value(entries: &[Vec<u8>], time: &str) -> Option<Value> {
    let cp = signed_checkpoint(entries, time)?;
    Some(json!({
        "checkpoint": serde_json::to_value(&cp).ok()?,
        "raw": format!("base64:{}", B64.encode(checkpoint_blob(&cp).ok()?)),
        "entries": entries
            .iter()
            .map(|bytes| Value::String(format!("base64:{}", B64.encode(bytes))))
            .collect::<Vec<_>>(),
    }))
}

/// A second entry for the fixture log: a `key` statement adding a further producer key.
#[must_use]
pub fn key_statement_bytes() -> Option<Vec<u8>> {
    let fx = fixture()?;
    let added = TestKey::from_seed_hex("producer-2", &"22".repeat(32)).ok()?;
    let payload = json!({
        "type": "key",
        "ahl_version": ahl_core::AHL_VERSION,
        "producer": "producer-1",
        "operation": "add",
        "key": { "key_id": added.key_id(), "pubkey": added.pubkey(), "valid_from_index": 1 },
    });
    Some(ahl_core::jcs(&ahl_core::envelope(payload, &fx.producer)))
}

/// The deployment configuration the binary reads, for the fixture log.
#[must_use]
pub fn deployment_config_value() -> Option<Value> {
    let fx = fixture()?;
    Some(json!({
        "witness_id": fx.signer.witness_id(),
        "signing_key_seed_hex": hex::encode([9u8; 32]),
        "store_path": "witness.sqlite3",
        "logs": [{
            "log_id": fx.anchor.log_id,
            "genesis_manifest_entry_id": fx.anchor.genesis_manifest_entry_id,
            "genesis_producer_keys": [{
                "key_id": fx.producer.key_id(),
                "pubkey": fx.producer.pubkey(),
                "valid_from_index": 0,
            }],
        }],
    }))
}
