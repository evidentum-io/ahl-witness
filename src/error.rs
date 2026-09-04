//! Error type for `ahl-witness`.

use thiserror::Error;

/// Convenience alias for results carrying [`WitnessError`].
pub type WitnessResult<T> = core::result::Result<T, WitnessError>;

/// Errors produced by `ahl-witness`.
///
/// Every variant names the specific check that failed rather than collapsing into a generic
/// "invalid checkpoint" — the state machine's callers need to be able to tell an
/// **authentication** failure (the candidate never qualified as a checkpoint this log signed
/// at all, so there is nothing to publish refusal evidence about — core spec §3.3, adaptor
/// profile §11.2 rule 2) apart from a **consistency** failure (a validly signed checkpoint
/// that conflicts with the retained one, which does get refusal evidence).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WitnessError {
    // ---- entry material (core spec §2.1, §2.4; adaptor profile §4.2) ----
    /// The submitted bytes parse as JSON but are not envelope-shaped (core spec §2.1: an
    /// object with a `payload` object and a non-empty `signatures` array).
    #[error("not an AHL envelope: {reason}")]
    MalformedEnvelope {
        /// Which structural requirement was missing.
        reason: &'static str,
    },

    /// The submitted bytes parse as a well-formed envelope but do not re-serialize to
    /// themselves under JCS — they are not canonical (core spec §2.4, RFC 8785).
    #[error("submitted bytes are not JCS-canonical")]
    NotCanonical,

    /// A submitted checkpoint carried a member the cosigned object does not contain (adaptor
    /// profile §11.1).
    ///
    /// Refused rather than dropped: a member deserialized past would leave the submitter
    /// believing the witness cosigned what it sent, when the preimage the witness signs is the
    /// six members and nothing else. `raw` is the member this catches in practice, and it has
    /// a place of its own in the request.
    #[error(
        "checkpoint carries `{member}`: the cosigned checkpoint object contains exactly \
         {{log_id, tree_size, root_hash, checkpoint_time, key_id, signature}} and nothing else \
         (adaptor profile §11.1), so no other member can be accepted; the §6.4 `raw` framing is \
         submitted as the request's own top-level `raw`, outside the checkpoint"
    )]
    UnknownCheckpointMember {
        /// The member as submitted.
        member: String,
    },

    /// A submission carried a member the witness request shape does not define.
    #[error(
        "the witness request carries `{member}`, which is not `checkpoint`, `raw` or `entries`"
    )]
    UnknownRequestMember {
        /// The member as submitted.
        member: String,
    },

    /// Fewer entries were supplied than the candidate checkpoint's `tree_size` requires to
    /// resolve governance and consistency (adaptor profile §10.6: enumerated governance
    /// requires the full range, since no typed-subset proof exists under this profile).
    #[error("checkpoint commits {need} entries but only {have} were supplied")]
    IncompleteEntries {
        /// Entries actually supplied, contiguously from index 0.
        have: u64,
        /// Entries the checkpoint's `tree_size` commits.
        need: u64,
    },

    // ---- governance (core spec §7.3; adaptor profile §7.4.1) ----
    /// No verified governance snapshot (genesis manifest plus every subsequent verified
    /// `manifest`/`key` statement) can be established up to this `tree_size` — either
    /// because the supplied entries do not reach that far, or because no valid genesis
    /// manifest (signature-verified against the configured out-of-band anchor) is among
    /// them. Refused rather than resolved from a partial or cached snapshot (core spec §7.3,
    /// "governance statements are not self-authorizing").
    #[error("governance chain is not resolvable up to tree_size {tree_size}")]
    GovernanceChainUnresolvable {
        /// The `tree_size` governance resolution was attempted for.
        tree_size: u64,
    },

    /// A governance statement that is otherwise authentic declares an `ahl_version` this
    /// revision does not verify — or declares none at all.
    ///
    /// I-D §2.2 and §7.1: revision 0.4 verifies no material issued under an earlier revision,
    /// and §7.5 step 1 orders the read "version first, then parse". A `manifest` or `key`
    /// statement whose producer signature has already verified under the key set in force is
    /// therefore read for its declared revision before its content is allowed to establish
    /// anything, and a statement declaring anything other than [`ahl_core::AHL_VERSION`] is
    /// refused here rather than skipped: skipping would silently leave the previous governance
    /// version in force, which is a decision about material this revision has no rules for.
    /// The check runs only after the signature verifies, so an unsigned or forged entry of type
    /// `manifest` cannot abort a walk by declaring an old revision.
    #[error(
        "governance statement at entry index {entry_index} declares ahl_version `{}`, but this \
         revision verifies only `{expected}` (I-D §2.2, §7.1)",
        declared.as_deref().unwrap_or("(absent)")
    )]
    UnsupportedStatementVersion {
        /// The entry index the statement was read at.
        entry_index: u64,
        /// The `ahl_version` the statement declared, or `None` if it declared none.
        declared: Option<String>,
        /// The revision this build verifies: [`ahl_core::AHL_VERSION`].
        expected: &'static str,
    },

    /// A configuration's genesis producer key set is empty; no governance chain can ever
    /// start without at least one out-of-band trusted producer key (core spec §2.3.5).
    #[error("configuration declares no genesis producer keys for log `{log_id}`")]
    NoGenesisProducerKeys {
        /// The log the empty configuration was for.
        log_id: String,
    },

    /// A configured trusted key's `key_id` does not match the id recomputed from its
    /// `pubkey` (adaptor profile §7.2: a verifier MUST recompute, never trust the carried
    /// value).
    #[error("configured key_id `{configured}` does not match the id recomputed from pubkey: `{computed}`")]
    ConfigKeyIdMismatch {
        /// The `key_id` given in configuration.
        configured: String,
        /// The `key_id` recomputed from the configured public key.
        computed: String,
    },

    /// No configured log anchor for this `log_id`; a witness only cosigns logs it has been
    /// explicitly told to watch, never one it happens to receive a checkpoint for.
    #[error("no configured genesis anchor for log `{log_id}`")]
    UnknownLog {
        /// The unconfigured `log_id`.
        log_id: String,
    },

    // ---- checkpoints (adaptor profile §5.2.2, §6) ----
    /// A `checkpoint_time` value is not the exact nine-fractional-digit RFC 3339 rendering
    /// adaptor profile §6.3 requires.
    #[error("`{value}` is not a valid adaptor-profile §6.3 checkpoint_time")]
    BadCheckpointTime {
        /// The value as submitted.
        value: String,
    },

    /// A checkpoint's `log_id` does not match the log this witness was asked to verify it
    /// against.
    #[error("checkpoint log_id `{got}` does not match the configured log_id `{expected}`")]
    WrongLogId {
        /// The configured `log_id`.
        expected: String,
        /// The `log_id` carried by the checkpoint.
        got: String,
    },

    /// A checkpoint is signed by a key this witness does not trust — not present in the
    /// active governance snapshot (adaptor profile §7.3, §7.4).
    #[error("checkpoint signed by untrusted key `{key_id}`")]
    UnknownSigningKey {
        /// The untrusted `key_id`.
        key_id: String,
    },

    /// The resolved key exists but is not yet active at this checkpoint's `tree_size`
    /// (adaptor profile §7.3 activation bound: `valid_from_index`).
    #[error("key `{key_id}` is not valid until index {valid_from_index}, checkpoint tree_size is {tree_size}")]
    KeyNotYetActive {
        /// The key in question.
        key_id: String,
        /// The index the key becomes valid at.
        valid_from_index: u64,
        /// The checkpoint's `tree_size`.
        tree_size: u64,
    },

    /// A checkpoint's signature does not verify against its resolved key.
    #[error("checkpoint signature does not verify against key `{key_id}`")]
    SignatureInvalid {
        /// The key the signature was checked against.
        key_id: String,
    },

    /// `checkpoint.raw` does not match the blob assembled from the parsed checkpoint object
    /// (adaptor profile §6.4).
    #[error("checkpoint.raw does not match the assembled 98-byte blob")]
    RawBlobMismatch,

    /// The very first checkpoint ever offered for a log does not recompute to the entries
    /// claimed to be its own tree. There is no previously retained checkpoint to pair this
    /// with in refusal evidence (adaptor profile §11.2 requires both `retained` and
    /// `offered`), so this is reported as an authentication failure rather than published
    /// refusal evidence — a specification gap; see the crate README.
    #[error("checkpoint at tree_size {tree_size} does not recompute from its own entries")]
    CheckpointRootMismatch {
        /// The tree size whose root failed to recompute.
        tree_size: u64,
    },

    // ---- durations (core spec §7.3) ----
    /// A duration string is not a well-formed ISO 8601 duration of the time-only subset core
    /// spec §7.3 requires (`P[n]DT[n]H[n]M[n]S`).
    #[error("`{value}` is not a valid ISO 8601 duration")]
    BadDuration {
        /// The value as submitted.
        value: String,
    },

    /// A duration string carries a calendar component (`Y`, or `M` in the date part) core
    /// spec §7.3 PROHIBITS in `checkpoint_cadence`/`witness_grace_period`, because years and
    /// calendar months have no fixed length. Rejected outright, never approximated.
    #[error("`{value}` carries a prohibited calendar component (`{component}`); core spec §7.3 restricts durations to days/hours/minutes/seconds")]
    ProhibitedDurationComponent {
        /// The value as submitted.
        value: String,
        /// Which prohibited component was found (`'Y'` or `'M'`).
        component: char,
    },

    /// A `cadence_epoch` value is not a valid RFC 3339 timestamp (core spec §7.3 schema).
    #[error("`{value}` is not a valid RFC 3339 cadence_epoch")]
    BadCadenceEpoch {
        /// The value as submitted.
        value: String,
    },

    // ---- signing identity ----
    /// The configured witness signing key seed is not exactly 32 bytes.
    #[error("witness signing key seed must be 32 bytes, got {got}")]
    BadSigningKeySeed {
        /// The length actually supplied.
        got: usize,
    },

    // ---- infrastructure ----
    /// A value that must fit a narrower integer type does not.
    #[error("{what} does not fit the required integer type")]
    IndexOverflow {
        /// What was being converted.
        what: &'static str,
    },

    /// JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A primitive from `ahl-core` (family-string parsing, signature verification, JCS)
    /// failed.
    #[error("ahl-core error: {0}")]
    Ahl(#[from] ahl_core::AhlError),

    /// A Merkle operation delegated to `atl-core` failed.
    #[error("atl-core error: {0}")]
    Atl(#[from] atl_core::AtlError),

    /// The local store failed.
    #[error("store error: {0}")]
    Store(#[from] rusqlite::Error),

    /// The store could not be opened or migrated.
    #[error("store initialization failed: {0}")]
    StoreInit(String),
}
