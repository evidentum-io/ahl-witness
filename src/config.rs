//! Deployment configuration: the witness's own signing identity, and the genesis governance
//! anchor for every log it watches (core spec §2.3.5, §7.3).
//!
//! A witness verifies checkpoints for potentially more than one log — core spec §3.3 puts
//! the state machine "per log" — so, unlike `ahl-mirror` (bound to exactly one Data Tree,
//! adaptor profile §3), this crate's configuration is keyed by `log_id` and carries one
//! [`LogAnchor`] per watched log.

use std::collections::HashMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;

use crate::error::{WitnessError, WitnessResult};

/// A key object in the shape the specification uses throughout:
/// `{key_id, pubkey, valid_from_index}` (core spec §2.3.6, §7.2; adaptor profile §7.2-§7.3).
#[derive(Debug, Clone, Deserialize)]
pub struct KeyObjectSpec {
    /// `sha256:<hex of SHA-256 over the raw 32-byte public key>`.
    pub key_id: String,
    /// `base64:<raw 32-byte Ed25519 public key>`.
    pub pubkey: String,
    /// The entry index from which this key is valid.
    #[serde(default)]
    pub valid_from_index: u64,
}

/// A key object, resolved and self-checked once: its carried `key_id` recomputes from its
/// `pubkey`.
#[derive(Debug, Clone)]
pub struct ResolvedKeyObject {
    /// The key's id, equal to the id recomputed from `verifying_key`.
    pub key_id: String,
    /// The decoded Ed25519 public key.
    pub verifying_key: VerifyingKey,
    /// The original `base64:...` public key string, kept for [`ahl_core::verify_envelope`]'s
    /// resolver interface, which takes the encoded form rather than a decoded key.
    pub pubkey: String,
    /// See [`KeyObjectSpec::valid_from_index`].
    pub valid_from_index: u64,
}

impl ResolvedKeyObject {
    /// Resolve and self-check a configured or manifest-declared key object.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Ahl`] if `pubkey` is malformed, or
    /// [`WitnessError::ConfigKeyIdMismatch`] if the carried `key_id` disagrees with the id
    /// recomputed from `pubkey` (adaptor profile §7.2: recompute, never trust the carried
    /// value).
    pub fn resolve(spec: &KeyObjectSpec) -> WitnessResult<Self> {
        let verifying_key = ahl_core::decode_pubkey(&spec.pubkey)?;
        let computed =
            format!("sha256:{}", hex::encode(atl_core::compute_key_id(verifying_key.as_bytes())));
        if computed != spec.key_id {
            return Err(WitnessError::ConfigKeyIdMismatch {
                configured: spec.key_id.clone(),
                computed,
            });
        }
        Ok(Self {
            key_id: spec.key_id.clone(),
            verifying_key,
            pubkey: spec.pubkey.clone(),
            valid_from_index: spec.valid_from_index,
        })
    }
}

/// The out-of-band trust anchor for one log's governance chain (core spec §2.3.5).
///
/// The genesis manifest's identity and initial producer key fingerprints are "distributed
/// out-of-band" per the core spec — an offline party cannot self-authenticate a self-supplied
/// genesis anchor. This is that configuration, one per watched log.
#[derive(Debug, Clone, Deserialize)]
pub struct LogAnchorSpec {
    /// `sha256:<hex of the Origin ID>` — the single Data Tree this anchor covers (adaptor
    /// profile §3, §7.1).
    pub log_id: String,
    /// The entry id of the trusted genesis manifest.
    pub genesis_manifest_entry_id: String,
    /// The producer key(s) trusted, out-of-band, to have signed the genesis manifest itself.
    /// MUST be non-empty.
    pub genesis_producer_keys: Vec<KeyObjectSpec>,
}

/// A [`LogAnchorSpec`], resolved: every configured key checked once, up front.
#[derive(Debug, Clone)]
pub struct LogAnchor {
    /// The single Data Tree this anchor covers.
    pub log_id: String,
    /// The genesis manifest's required entry id.
    pub genesis_manifest_entry_id: String,
    /// The resolved genesis producer key set.
    pub genesis_producer_keys: Vec<ResolvedKeyObject>,
}

impl LogAnchor {
    /// Resolve a [`LogAnchorSpec`], checking every key's `key_id` against its `pubkey`.
    ///
    /// # Errors
    ///
    /// As [`ResolvedKeyObject::resolve`], for the first key that fails, or
    /// [`WitnessError::NoGenesisProducerKeys`] if `genesis_producer_keys` is empty.
    pub fn resolve(spec: &LogAnchorSpec) -> WitnessResult<Self> {
        if spec.genesis_producer_keys.is_empty() {
            return Err(WitnessError::NoGenesisProducerKeys { log_id: spec.log_id.clone() });
        }
        let genesis_producer_keys = spec
            .genesis_producer_keys
            .iter()
            .map(ResolvedKeyObject::resolve)
            .collect::<WitnessResult<Vec<_>>>()?;
        Ok(Self {
            log_id: spec.log_id.clone(),
            genesis_manifest_entry_id: spec.genesis_manifest_entry_id.clone(),
            genesis_producer_keys,
        })
    }
}

/// The witness's own signing identity (adaptor profile §11.1, §7.2).
///
/// # Production key handling
///
/// This crate accepts the witness's Ed25519 seed as configuration for simplicity; nothing
/// here is suitable for production key handling. A real deployment SHOULD source the signing
/// key from a secrets manager or HSM and implement its own [`WitnessSigner`] rather than
/// constructing an [`Ed25519WitnessSigner`] from a seed on disk.
pub trait WitnessSigner: Send + Sync {
    /// The witness's own identifier, carried in cosignatures and refusal evidence.
    fn witness_id(&self) -> &str;
    /// `sha256:<hex of SHA-256 over the raw 32-byte public key>` — adaptor profile §7.2's key
    /// id rule, adopted identically for witness keys.
    fn key_id(&self) -> String;
    /// Sign `msg`, returning `"base64:" || base64(raw 64-byte Ed25519 signature)`.
    fn sign(&self, msg: &[u8]) -> String;
}

/// An Ed25519 [`WitnessSigner`] built from a raw 32-byte seed.
#[derive(Debug, Clone)]
pub struct Ed25519WitnessSigner {
    witness_id: String,
    signing: SigningKey,
}

impl Ed25519WitnessSigner {
    /// Build a signer from a witness id and a raw 32-byte Ed25519 seed.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::BadSigningKeySeed`] if `seed` is not exactly 32 bytes.
    pub fn from_seed(witness_id: impl Into<String>, seed: &[u8]) -> WitnessResult<Self> {
        let seed: [u8; 32] =
            seed.try_into().map_err(|_| WitnessError::BadSigningKeySeed { got: seed.len() })?;
        Ok(Self { witness_id: witness_id.into(), signing: SigningKey::from_bytes(&seed) })
    }

    /// The Ed25519 public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// The public key as `base64:<raw 32 bytes>` (adaptor profile §7.2).
    #[must_use]
    pub fn pubkey(&self) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        format!("base64:{}", STANDARD.encode(self.signing.verifying_key().as_bytes()))
    }
}

impl WitnessSigner for Ed25519WitnessSigner {
    fn witness_id(&self) -> &str {
        &self.witness_id
    }

    fn key_id(&self) -> String {
        format!(
            "sha256:{}",
            hex::encode(atl_core::compute_key_id(self.signing.verifying_key().as_bytes()))
        )
    }

    fn sign(&self, msg: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        format!("base64:{}", STANDARD.encode(self.signing.sign(msg).to_bytes()))
    }
}

/// The on-disk deployment configuration for the `ahl-witness` binary: this witness's own
/// identity and one [`LogAnchorSpec`] per log it watches.
///
/// # Production key handling
///
/// See [`WitnessSigner`]'s docs: `signing_key_seed_hex` is accepted here for simplicity and
/// is not suitable for production key handling.
#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentSpec {
    /// This witness's identifier, carried in cosignatures and refusal evidence.
    pub witness_id: String,
    /// A 64-character hex encoding of the witness's raw 32-byte Ed25519 seed.
    pub signing_key_seed_hex: String,
    /// Filesystem path to the `SQLite` store.
    pub store_path: String,
    /// One anchor per log this witness watches.
    pub logs: Vec<LogAnchorSpec>,
}

/// A [`DeploymentSpec`], resolved: the signing key decoded, every log anchor resolved and
/// keyed by `log_id`.
pub struct Deployment {
    /// This witness's signing identity.
    pub signer: Ed25519WitnessSigner,
    /// Resolved anchors, keyed by `log_id`.
    pub anchors: HashMap<String, LogAnchor>,
    /// Filesystem path to the `SQLite` store.
    pub store_path: String,
}

impl Deployment {
    /// Resolve a [`DeploymentSpec`].
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::BadSigningKeySeed`] if `signing_key_seed_hex` does not decode
    /// to exactly 32 bytes, or propagates the first [`LogAnchor::resolve`] failure.
    pub fn resolve(spec: &DeploymentSpec) -> WitnessResult<Self> {
        let seed = hex::decode(spec.signing_key_seed_hex.trim())
            .map_err(|_| WitnessError::BadSigningKeySeed { got: 0 })?;
        let signer = Ed25519WitnessSigner::from_seed(spec.witness_id.clone(), &seed)?;
        let mut anchors = HashMap::with_capacity(spec.logs.len());
        for log_spec in &spec.logs {
            let anchor = LogAnchor::resolve(log_spec)?;
            anchors.insert(anchor.log_id.clone(), anchor);
        }
        Ok(Self { signer, anchors, store_path: spec.store_path.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_key(seed: &str) -> ahl_core::TestKey {
        ahl_core::TestKey::from_seed_hex("producer", seed).expect("32-byte test seed")
    }

    fn spec_with(genesis_producer_keys: Vec<KeyObjectSpec>) -> LogAnchorSpec {
        LogAnchorSpec {
            log_id: "sha256:aa".to_owned(),
            genesis_manifest_entry_id: "sha256:genesis".to_owned(),
            genesis_producer_keys,
        }
    }

    #[test]
    fn a_correctly_derived_key_resolves() {
        let k = seed_key(&"11".repeat(32));
        let spec = KeyObjectSpec { key_id: k.key_id(), pubkey: k.pubkey(), valid_from_index: 0 };
        let resolved = ResolvedKeyObject::resolve(&spec).expect("matching key_id");
        assert_eq!(resolved.key_id, k.key_id());
    }

    #[test]
    fn a_mismatched_key_id_is_rejected() {
        let k = seed_key(&"22".repeat(32));
        let spec = KeyObjectSpec {
            key_id: "sha256:00".to_owned(),
            pubkey: k.pubkey(),
            valid_from_index: 0,
        };
        assert!(matches!(
            ResolvedKeyObject::resolve(&spec),
            Err(WitnessError::ConfigKeyIdMismatch { .. })
        ));
    }

    #[test]
    fn log_anchor_resolves_its_genesis_producer_keys() {
        let k = seed_key(&"33".repeat(32));
        let spec = spec_with(vec![KeyObjectSpec {
            key_id: k.key_id(),
            pubkey: k.pubkey(),
            valid_from_index: 0,
        }]);
        let anchor = LogAnchor::resolve(&spec).expect("valid spec");
        assert_eq!(anchor.genesis_producer_keys.len(), 1);
        assert_eq!(anchor.genesis_producer_keys[0].key_id, k.key_id());
        assert_eq!(anchor.genesis_manifest_entry_id, "sha256:genesis");
    }

    #[test]
    fn an_empty_genesis_producer_key_set_is_rejected() {
        let spec = spec_with(vec![]);
        assert!(matches!(
            LogAnchor::resolve(&spec),
            Err(WitnessError::NoGenesisProducerKeys { .. })
        ));
    }

    #[test]
    fn a_signer_produces_a_verifiable_signature_and_matching_key_id() {
        let signer = Ed25519WitnessSigner::from_seed("witness-1", &[7u8; 32]).expect("32 bytes");
        assert_eq!(signer.witness_id(), "witness-1");
        let sig = signer.sign(b"hello");
        let key = ahl_core::decode_pubkey(&signer.pubkey()).expect("valid pubkey encoding");
        assert!(ahl_core::verify_signature(&key, b"hello", &sig).expect("well-formed signature"));
        assert_eq!(
            signer.key_id(),
            format!(
                "sha256:{}",
                hex::encode(atl_core::compute_key_id(signer.verifying_key().as_bytes()))
            )
        );
    }

    #[test]
    fn a_wrong_length_seed_is_rejected() {
        assert!(matches!(
            Ed25519WitnessSigner::from_seed("w", &[0u8; 5]),
            Err(WitnessError::BadSigningKeySeed { got: 5 })
        ));
    }

    #[test]
    fn a_deployment_resolves_its_signer_and_every_log_anchor() {
        let k = seed_key(&"44".repeat(32));
        let spec = DeploymentSpec {
            witness_id: "witness-1".to_owned(),
            signing_key_seed_hex: "ab".repeat(32),
            store_path: ":memory:".to_owned(),
            logs: vec![spec_with(vec![KeyObjectSpec {
                key_id: k.key_id(),
                pubkey: k.pubkey(),
                valid_from_index: 0,
            }])],
        };
        let deployment = Deployment::resolve(&spec).expect("valid deployment");
        assert_eq!(deployment.signer.witness_id(), "witness-1");
        assert!(deployment.anchors.contains_key("sha256:aa"));
    }

    #[test]
    fn a_non_hex_signing_seed_is_rejected() {
        let spec = DeploymentSpec {
            witness_id: "witness-1".to_owned(),
            signing_key_seed_hex: "not-hex".to_owned(),
            store_path: ":memory:".to_owned(),
            logs: vec![],
        };
        assert!(Deployment::resolve(&spec).is_err());
    }

    #[test]
    fn a_wrong_length_signing_seed_is_rejected() {
        let spec = DeploymentSpec {
            witness_id: "witness-1".to_owned(),
            signing_key_seed_hex: "ab".repeat(10),
            store_path: ":memory:".to_owned(),
            logs: vec![],
        };
        assert!(matches!(Deployment::resolve(&spec), Err(WitnessError::BadSigningKeySeed { .. })));
    }
}
