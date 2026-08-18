//! Governance: a verified chain of `manifest`/`key` statements, rooted at a configured
//! genesis anchor, giving checkpoint-signing keys, cadence and witness grace period (core
//! spec §7.3; §2.3.5).
//!
//! # Governance statements are not self-authorizing
//!
//! Anchoring proves bytes existed at a position; it does not make a governance statement
//! effective (core spec §7.3, adaptor profile §7.4.1). A candidate counts only if:
//!
//! - it is the **genesis** manifest — its entry id equals
//!   [`crate::config::LogAnchor::genesis_manifest_entry_id`] and its producer signature
//!   verifies under [`crate::config::LogAnchor::genesis_producer_keys`] (the out-of-band
//!   trust anchor, core spec §2.3.5) — or
//! - it is a **non-genesis** manifest whose `predecessor` field names the entry id of the
//!   currently active version and whose producer signature verifies under *that* version's
//!   current producer key set, and whose `log.cadence_epoch` is unchanged from genesis;
//!
//! and a `key` statement counts only if its producer signature verifies under the producer
//! key set currently in force. A candidate failing its check is not governance: it is simply
//! skipped, and the walk continues from whatever the last genuinely verified state was.
//!
//! # Why this duplicates `ahl-mirror`'s `manifest` module
//!
//! Core spec §3.3 requires a witness to be independent of the log operator; `ahl-mirror` is
//! itself commonly operated as (or alongside) that operator's infrastructure. Deriving a
//! witness's trust decisions from a mirror's already-computed [`GovernanceState`] would make
//! the witness's independence conditional on trusting the mirror's computation of it, which
//! defeats the purpose of witnessing (adaptor profile §10.1.1, §10.3: every entry is
//! content-addressed and MUST verify against its own entry id, regardless of who served it).
//! This module therefore re-derives governance from raw entry bytes, exactly as `ahl-mirror`
//! does, so the two components cannot disagree about which key was valid when without that
//! disagreement being independently checkable. The one behavioural difference from the
//! mirror's version: this module also retains `witness_grace_period`, which a witness needs
//! for its own freshness obligation (core spec §3.3 item 4) and a mirror does not.
//!
//! See the crate README for a recommendation that this logic be extracted into a shared
//! library the two components both depend on, to remove the duplication this module
//! currently accepts.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{KeyObjectSpec, LogAnchor, ResolvedKeyObject};
use crate::duration::parse_iso8601_duration_nanos;
use crate::error::{WitnessError, WitnessResult};

#[derive(Debug, Deserialize)]
struct AdaptorBlock {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    hash: String,
}

#[derive(Debug, Deserialize)]
struct LogBlock {
    log_id: String,
    #[allow(dead_code)]
    operator: String,
    #[allow(dead_code)]
    adaptor: AdaptorBlock,
    checkpoint_cadence: String,
    cadence_epoch: String,
    witness_grace_period: String,
    keys: Vec<KeyObjectSpec>,
}

/// A verified governance snapshot: the producer and checkpoint-signing key sets, cadence and
/// witness grace period, in force at the point a chain walk reached.
#[derive(Debug, Clone)]
pub struct GovernanceState {
    producer_keys: HashMap<String, ResolvedKeyObject>,
    log_keys: Vec<ResolvedKeyObject>,
    cadence_nanos: u64,
    cadence_epoch_nanos: u64,
    witness_grace_period_nanos: u64,
    governing_manifest_entry_index: u64,
    governing_manifest_entry_id: String,
    genesis_entry_index: u64,
}

impl GovernanceState {
    /// Resolve the checkpoint-signing key for `key_id`, honouring its activation bound
    /// (adaptor profile §7.3).
    ///
    /// # Errors
    ///
    /// [`WitnessError::UnknownSigningKey`] or [`WitnessError::KeyNotYetActive`].
    pub fn resolve_log_key(&self, key_id: &str, tree_size: u64) -> WitnessResult<&VerifyingKey> {
        let key = self
            .log_keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| WitnessError::UnknownSigningKey { key_id: key_id.to_owned() })?;
        if tree_size < key.valid_from_index {
            return Err(WitnessError::KeyNotYetActive {
                key_id: key_id.to_owned(),
                valid_from_index: key.valid_from_index,
                tree_size,
            });
        }
        Ok(&key.verifying_key)
    }

    /// The `checkpoint_cadence` in force, as a nanosecond duration (core spec §7.3).
    #[must_use]
    pub const fn cadence_nanos(&self) -> u64 {
        self.cadence_nanos
    }

    /// The `witness_grace_period` in force, as a nanosecond duration (core spec §7.3, §3.3
    /// item 4).
    #[must_use]
    pub const fn witness_grace_period_nanos(&self) -> u64 {
        self.witness_grace_period_nanos
    }

    /// `cadence_epoch`, as unix nanoseconds — fixed for the whole corpus by the genesis
    /// manifest (core spec §7.3).
    #[must_use]
    pub const fn cadence_epoch_nanos(&self) -> u64 {
        self.cadence_epoch_nanos
    }

    /// The entry index of the manifest version currently governing.
    #[must_use]
    pub const fn governing_manifest_entry_index(&self) -> u64 {
        self.governing_manifest_entry_index
    }

    /// The entry index of the verified genesis manifest — fixed for the whole corpus.
    #[must_use]
    pub const fn genesis_entry_index(&self) -> u64 {
        self.genesis_entry_index
    }
}

fn resolver_from_map(
    keys: &HashMap<String, ResolvedKeyObject>,
    at_index: u64,
) -> impl Fn(&str) -> Option<String> + '_ {
    move |key_id| {
        let key = keys.get(key_id)?;
        (key.valid_from_index <= at_index).then(|| key.pubkey.clone())
    }
}

fn resolver_from_slice(
    keys: &[ResolvedKeyObject],
    at_index: u64,
) -> impl Fn(&str) -> Option<String> + '_ {
    move |key_id| {
        let key = keys.iter().find(|k| k.key_id == key_id)?;
        (key.valid_from_index <= at_index).then(|| key.pubkey.clone())
    }
}

/// Parse an RFC 3339 timestamp to unix nanoseconds.
fn parse_rfc3339_nanos(value: &str) -> WitnessResult<u64> {
    let bad = || WitnessError::BadCadenceEpoch { value: value.to_owned() };
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| bad())?;
    u64::try_from(parsed.unix_timestamp_nanos()).map_err(|_| bad())
}

/// Try to build a [`GovernanceState`] from a candidate manifest payload's `log` block and
/// top-level producer `keys` array. Returns `None` (not an error) for any schema or content
/// defect — a malformed manifest is simply not valid governance, core spec §7.3.
fn parse_governance(
    payload: &Value,
    entry_index: u64,
    entry_id: String,
    log_id: &str,
    genesis_entry_index: u64,
    required_epoch_nanos: Option<u64>,
) -> Option<GovernanceState> {
    let producer_keys_value = payload.get("keys")?.clone();
    let producer_key_specs: Vec<KeyObjectSpec> =
        serde_json::from_value(producer_keys_value).ok()?;
    let mut producer_keys = HashMap::new();
    for spec in &producer_key_specs {
        let resolved = ResolvedKeyObject::resolve(spec).ok()?;
        producer_keys.insert(resolved.key_id.clone(), resolved);
    }

    let log_value = payload.get("log")?.clone();
    let log_block: LogBlock = serde_json::from_value(log_value).ok()?;
    if log_block.log_id != log_id {
        return None;
    }
    let cadence_nanos = parse_iso8601_duration_nanos(&log_block.checkpoint_cadence).ok()?;
    // Core spec §7.3 "Fractional seconds": "checkpoint_cadence MUST be greater than zero" —
    // a zero cadence would make every gap, however large, satisfy a maximum-gap obligation
    // of zero, which is not a cadence at all.
    if cadence_nanos == 0 {
        return None;
    }
    let witness_grace_period_nanos =
        parse_iso8601_duration_nanos(&log_block.witness_grace_period).ok()?;
    let cadence_epoch_nanos = parse_rfc3339_nanos(&log_block.cadence_epoch).ok()?;
    if let Some(required) = required_epoch_nanos {
        if cadence_epoch_nanos != required {
            return None; // "a later version declaring a different epoch is malformed"
        }
    }

    let mut log_keys = Vec::with_capacity(log_block.keys.len());
    for spec in &log_block.keys {
        log_keys.push(ResolvedKeyObject::resolve(spec).ok()?);
    }

    Some(GovernanceState {
        producer_keys,
        log_keys,
        cadence_nanos,
        cadence_epoch_nanos,
        witness_grace_period_nanos,
        governing_manifest_entry_index: entry_index,
        governing_manifest_entry_id: entry_id,
        genesis_entry_index,
    })
}

fn try_apply_manifest(
    state: &mut Option<GovernanceState>,
    envelope: &Value,
    payload: &Value,
    entry_index: u64,
    anchor: &LogAnchor,
) -> WitnessResult<()> {
    let entry_id = ahl_core::entry_id(envelope);
    match state {
        None => {
            if entry_id != anchor.genesis_manifest_entry_id {
                return Ok(());
            }
            if payload.get("predecessor").is_some() {
                return Ok(()); // predecessor is forbidden for genesis
            }
            let resolve = resolver_from_slice(&anchor.genesis_producer_keys, entry_index);
            if !ahl_core::verify_envelope(envelope, resolve)? {
                return Ok(());
            }
            *state =
                parse_governance(payload, entry_index, entry_id, &anchor.log_id, entry_index, None);
        }
        Some(current) => {
            let Some(predecessor) = payload.get("predecessor").and_then(Value::as_str) else {
                return Ok(());
            };
            if predecessor != current.governing_manifest_entry_id {
                return Ok(());
            }
            let resolve = resolver_from_map(&current.producer_keys, entry_index);
            if !ahl_core::verify_envelope(envelope, resolve)? {
                return Ok(());
            }
            let next = parse_governance(
                payload,
                entry_index,
                entry_id,
                &anchor.log_id,
                current.genesis_entry_index,
                Some(current.cadence_epoch_nanos),
            );
            if let Some(next) = next {
                *state = Some(next);
            }
        }
    }
    Ok(())
}

fn try_apply_key(
    state: &mut GovernanceState,
    envelope: &Value,
    payload: &Value,
    entry_index: u64,
) -> WitnessResult<()> {
    let Some(action) = payload.get("action").and_then(Value::as_str) else { return Ok(()) };
    let Some(key_value) = payload.get("key") else { return Ok(()) };
    let Ok(key_spec) = serde_json::from_value::<KeyObjectSpec>(key_value.clone()) else {
        return Ok(());
    };

    let resolve = resolver_from_map(&state.producer_keys, entry_index);
    if !ahl_core::verify_envelope(envelope, resolve)? {
        return Ok(());
    }

    match action {
        "add" => {
            if let Ok(resolved) = ResolvedKeyObject::resolve(&key_spec) {
                state.producer_keys.insert(resolved.key_id.clone(), resolved);
            }
        }
        "retire" => {
            state.producer_keys.remove(&key_spec.key_id);
        }
        _ => {}
    }
    Ok(())
}

/// Walk `entries_prefix` and return the governance state active at the end of it.
///
/// `entries_prefix` MUST be the complete, contiguous entry sequence
/// `[0, entries_prefix.len())`; every `manifest`/`key` statement it contains is verified
/// along the way.
///
/// # Errors
///
/// Returns [`WitnessError::GovernanceChainUnresolvable`] if no verified genesis manifest is
/// reached within `entries_prefix`.
pub fn resolve(entries_prefix: &[Vec<u8>], anchor: &LogAnchor) -> WitnessResult<GovernanceState> {
    let mut state: Option<GovernanceState> = None;
    for (i, bytes) in entries_prefix.iter().enumerate() {
        let index =
            u64::try_from(i).map_err(|_| WitnessError::IndexOverflow { what: "entry index" })?;
        let Ok(envelope) = serde_json::from_slice::<Value>(bytes) else { continue };
        let Some(payload) = envelope.get("payload") else { continue };
        let Some(kind) = payload.get("type").and_then(Value::as_str) else { continue };
        match kind {
            "manifest" => try_apply_manifest(&mut state, &envelope, payload, index, anchor)?,
            "key" => {
                if let Some(current) = state.as_mut() {
                    try_apply_key(current, &envelope, payload, index)?;
                }
            }
            _ => {}
        }
    }
    let tree_size = u64::try_from(entries_prefix.len())
        .map_err(|_| WitnessError::IndexOverflow { what: "entries_prefix.len()" })?;
    state.ok_or(WitnessError::GovernanceChainUnresolvable { tree_size })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::config::LogAnchorSpec;

    fn anchor_with(genesis: &ahl_core::TestKey, genesis_entry_id: &str) -> LogAnchor {
        LogAnchor::resolve(&LogAnchorSpec {
            log_id: "sha256:aa".to_owned(),
            genesis_manifest_entry_id: genesis_entry_id.to_owned(),
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: genesis.key_id(),
                pubkey: genesis.pubkey(),
                valid_from_index: 0,
            }],
        })
        .expect("valid anchor")
    }

    fn log_block(log_id: &str, cadence: &str, epoch: &str, grace: &str, keys: &Value) -> Value {
        json!({
            "log_id": log_id,
            "operator": "op-1",
            "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
            "checkpoint_cadence": cadence,
            "cadence_epoch": epoch,
            "witness_grace_period": grace,
            "keys": keys,
        })
    }

    fn genesis_manifest(
        producer: &ahl_core::TestKey,
        log_id: &str,
        producer_keys: &Value,
        log_keys: &Value,
        epoch: &str,
    ) -> Value {
        let payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": producer_keys,
            "log": log_block(log_id, "PT5M", epoch, "PT10M", log_keys),
        });
        ahl_core::envelope(payload, producer)
    }

    fn entry_id_of(envelope: &Value) -> String {
        ahl_core::entry_id(envelope)
    }

    fn producer_key_array(k: &ahl_core::TestKey) -> Value {
        json!([{ "key_id": k.key_id(), "pubkey": k.pubkey(), "valid_from_index": 0 }])
    }

    #[test]
    fn a_verified_genesis_manifest_establishes_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"02".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);
        let bytes = ahl_core::jcs(&genesis_env);

        let state = resolve(&[bytes], &anchor).expect("genesis verifies");
        assert_eq!(state.genesis_entry_index(), 0);
        assert_eq!(state.governing_manifest_entry_index(), 0);
        assert!(state.resolve_log_key(&log_key.key_id(), 0).is_ok());
        assert_eq!(state.cadence_nanos(), 300_000_000_000);
        assert_eq!(state.witness_grace_period_nanos(), 600_000_000_000);
    }

    #[test]
    fn a_manifest_with_an_invalid_producer_signature_is_not_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"03".repeat(32)).expect("seed");
        let impostor =
            ahl_core::TestKey::from_seed_hex("impostor", &"04".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"05".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &impostor,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);
        let bytes = ahl_core::jcs(&genesis_env);

        assert!(matches!(
            resolve(&[bytes], &anchor),
            Err(WitnessError::GovernanceChainUnresolvable { .. })
        ));
    }

    #[test]
    fn a_manifest_with_a_bad_predecessor_link_is_not_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"06".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"07".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);

        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"08".repeat(32)).expect("seed");
        let bad_next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": "sha256:not-the-genesis-entry-id",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", "PT10M",
                &producer_key_array(&rotated_log_key)
            ),
        });
        let bad_next_env = ahl_core::envelope(bad_next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&bad_next_env)];
        let state = resolve(&entries, &anchor).expect("genesis alone still resolves");
        assert!(state.resolve_log_key(&log_key.key_id(), 1).is_ok());
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 1).is_err());
    }

    #[test]
    fn a_later_manifest_changing_the_epoch_is_malformed_and_ignored() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"09".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"0a".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);

        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"0b".repeat(32)).expect("seed");
        let next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-06-01T00:00:00Z", "PT10M",
                &producer_key_array(&rotated_log_key)
            ),
        });
        let next_env = ahl_core::envelope(next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&next_env)];
        let state = resolve(&entries, &anchor).expect("genesis still resolves");
        assert!(state.resolve_log_key(&log_key.key_id(), 1).is_ok());
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 1).is_err());
    }

    #[test]
    fn a_valid_rotation_replaces_the_log_key_set_and_keeps_the_epoch() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"0c".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"0d".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);

        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"0e".repeat(32)).expect("seed");
        let next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT1M", "2026-01-01T00:00:00Z", "PT2M",
                &producer_key_array(&rotated_log_key)
            ),
        });
        let next_env = ahl_core::envelope(next_payload, &producer);

        let entries = vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&next_env)];
        let state = resolve(&entries, &anchor).expect("valid rotation resolves");
        assert_eq!(state.governing_manifest_entry_index(), 1);
        assert_eq!(state.genesis_entry_index(), 0);
        assert_eq!(state.cadence_nanos(), 60_000_000_000);
        assert_eq!(state.witness_grace_period_nanos(), 120_000_000_000);
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 1).is_ok());
        assert!(state.resolve_log_key(&log_key.key_id(), 1).is_err());
    }

    #[test]
    fn an_empty_prefix_is_unresolvable() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"0f".repeat(32)).expect("seed");
        let anchor = anchor_with(&producer, "sha256:never-seen");
        assert!(matches!(
            resolve(&[], &anchor),
            Err(WitnessError::GovernanceChainUnresolvable { tree_size: 0 })
        ));
    }

    #[test]
    fn a_key_statement_rotates_producer_keys_and_gates_later_manifests() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"10".repeat(32)).expect("seed");
        let producer_2 =
            ahl_core::TestKey::from_seed_hex("producer-2", &"11".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"12".repeat(32)).expect("seed");
        let genesis_env = genesis_manifest(
            &producer,
            "sha256:aa",
            &producer_key_array(&producer),
            &producer_key_array(&log_key),
            "2026-01-01T00:00:00Z",
        );
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);

        let key_payload = json!({
            "type": "key",
            "action": "add",
            "key": {
                "key_id": producer_2.key_id(), "pubkey": producer_2.pubkey(), "valid_from_index": 1
            },
        });
        let key_env = ahl_core::envelope(key_payload, &producer);

        let rotated_log_key =
            ahl_core::TestKey::from_seed_hex("log-2", &"13".repeat(32)).expect("seed");
        let next_payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "predecessor": genesis_id,
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", "PT10M",
                &producer_key_array(&rotated_log_key)
            ),
        });
        let next_env = ahl_core::envelope(next_payload, &producer_2);

        let entries =
            vec![ahl_core::jcs(&genesis_env), ahl_core::jcs(&key_env), ahl_core::jcs(&next_env)];
        let state = resolve(&entries, &anchor).expect("chain resolves");
        assert_eq!(state.governing_manifest_entry_index(), 2);
        assert!(state.resolve_log_key(&rotated_log_key.key_id(), 2).is_ok());
    }

    #[test]
    fn a_zero_checkpoint_cadence_makes_the_manifest_invalid_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"16".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"17".repeat(32)).expect("seed");
        let payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT0S", "2026-01-01T00:00:00Z", "PT10M",
                &producer_key_array(&log_key)
            ),
        });
        let genesis_env = ahl_core::envelope(payload, &producer);
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);
        let bytes = ahl_core::jcs(&genesis_env);
        assert!(matches!(
            resolve(&[bytes], &anchor),
            Err(WitnessError::GovernanceChainUnresolvable { .. })
        ));
    }

    #[test]
    fn a_malformed_grace_period_makes_the_manifest_invalid_governance() {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"14".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"15".repeat(32)).expect("seed");
        let payload = json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": producer_key_array(&producer),
            "log": log_block(
                "sha256:aa", "PT5M", "2026-01-01T00:00:00Z", "P1Y",
                &producer_key_array(&log_key)
            ),
        });
        let genesis_env = ahl_core::envelope(payload, &producer);
        let genesis_id = entry_id_of(&genesis_env);
        let anchor = anchor_with(&producer, &genesis_id);
        let bytes = ahl_core::jcs(&genesis_env);
        assert!(matches!(
            resolve(&[bytes], &anchor),
            Err(WitnessError::GovernanceChainUnresolvable { .. })
        ));
    }
}
