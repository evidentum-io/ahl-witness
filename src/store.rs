//! Durable local storage: the latest retained (cosigned) checkpoint per log, the full
//! cosigned-checkpoint history, and published refusal evidence (core spec §3.3; adaptor
//! profile §11).
//!
//! # Rotation cosignatures are stored apart
//!
//! `rotation_cosignatures` is a second, separate table, and separateness is the point. A
//! rotation-anchoring checkpoint verifies under the OUTGOING governance state rather than the
//! state active for its own `tree_size` (I-D §7.1's transition exception), so it is not a
//! member of the series this witness tracks: it never becomes the retained checkpoint, never
//! enters the cosigned history a later candidate is checked for consistency against, and never
//! grounds a freshness answer. Holding it in `cosigned_checkpoints` and filtering on read would
//! make every one of those call sites responsible for remembering the distinction; holding it
//! apart means none of them can forget. What the two DO share is equivocation detection: a
//! rotation-anchoring checkpoint offered at a `tree_size` this witness has already cosigned
//! with a different root is equivocation like any other, and is refused with evidence.
//!
//! Unlike `ahl-mirror`'s store, this one holds no entry bytes and no candidate material —
//! a witness's job is narrower (verify and cosign or refuse, core spec §3.3), not to serve
//! entries or range proofs (that is `ahl-mirror`'s and any independent mirror's job, core
//! spec §3.5). Everything written here is already a *verdict*: a cosignature this witness
//! itself produced, or refusal evidence this witness itself signed.
//!
//! # Serialization and atomicity (core spec §3.3, "Obligations that make the machine sound")
//!
//! "The retain–verify–classify–cosign transition MUST be serialized per log and atomic. Two
//! concurrent submissions extending the same retained state to different roots at the same
//! size MUST NOT both be cosigned; state MUST be re-read inside the critical section, and an
//! equivocation record MUST be persisted in the same atomic step as the refusal it
//! justifies."
//!
//! [`Store`] holds its connection behind one [`Mutex`], and every public method here acquires
//! it for the duration of one call — that alone is enough to make any *single* read or write
//! atomic, but it is **not** enough to make a multi-step decision (read the retained state,
//! classify a candidate against it, then write the result) atomic as a whole: two threads can
//! each acquire and release the lock once per step, interleaving between them. The fix is
//! `Store::with_lock` (crate-private): it exposes the same mutex for the *entire* decision, so
//! [`crate::witness::witness_checkpoint`] performs every read and the resulting write inside
//! one critical section, re-reading state itself rather than trusting a value read before the
//! lock was (re)acquired. The two writes an equivocation discovery requires — the
//! `equivocations` floor row and its accompanying refusal evidence — are additionally wrapped
//! in a real `SQLite` transaction (the crate-private `insert_equivocation_and_refusal`) so
//! they persist together or not at all, independent of the in-process lock (which protects
//! against concurrent *readers/writers*, not against a crash mid-write).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension as _};

use crate::checkpoint::Checkpoint;
use crate::consistency::ConsistencyProofEvidence;
use crate::error::{WitnessError, WitnessResult};
use crate::witness::{CosignedCheckpoint, RefusalEvidence, RefusalReason};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS cosigned_checkpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id          TEXT NOT NULL,
    tree_size       INTEGER NOT NULL,
    root_hash       TEXT NOT NULL,
    checkpoint_time TEXT NOT NULL,
    log_key_id      TEXT NOT NULL,
    log_signature   TEXT NOT NULL,
    witness_id      TEXT NOT NULL,
    witness_key_id  TEXT NOT NULL,
    cosignature     TEXT NOT NULL,
    cosigned_at     TEXT NOT NULL,
    cadence_nanos   INTEGER NOT NULL,
    grace_nanos     INTEGER NOT NULL,
    UNIQUE(log_id, tree_size, checkpoint_time)
);
CREATE TABLE IF NOT EXISTS rotation_cosignatures (
    log_id               TEXT NOT NULL,
    manifest_entry_index INTEGER NOT NULL,
    tree_size            INTEGER NOT NULL,
    root_hash            TEXT NOT NULL,
    checkpoint_time      TEXT NOT NULL,
    log_key_id           TEXT NOT NULL,
    log_signature        TEXT NOT NULL,
    witness_id           TEXT NOT NULL,
    witness_key_id       TEXT NOT NULL,
    cosignature          TEXT NOT NULL,
    cosigned_at          TEXT NOT NULL,
    PRIMARY KEY (log_id, manifest_entry_index, tree_size, checkpoint_time)
);
CREATE TABLE IF NOT EXISTS refusals (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id            TEXT NOT NULL,
    witness_id        TEXT NOT NULL,
    reason            TEXT NOT NULL,
    retained          TEXT NOT NULL,
    offered           TEXT NOT NULL,
    consistency_proof TEXT,
    detail            TEXT NOT NULL,
    refused_at        TEXT NOT NULL,
    key_id            TEXT NOT NULL,
    signature         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS equivocations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id       TEXT NOT NULL,
    tree_size    INTEGER NOT NULL,
    detected_at  TEXT NOT NULL,
    UNIQUE(log_id, tree_size)
);
";

/// A retained cosigned checkpoint, plus the cadence and grace period that governed it.
///
/// Core spec §3.3 item 4: freshness is judged against the governing manifest version, not
/// the current one, so the cadence and grace period in force *at cosigning time* are stored
/// alongside the checkpoint rather than re-resolved later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedCheckpoint {
    /// The cosigned checkpoint.
    pub cosigned: CosignedCheckpoint,
    /// `checkpoint_cadence` in force when this checkpoint was cosigned, in nanoseconds.
    pub cadence_nanos: u64,
    /// `witness_grace_period` in force when this checkpoint was cosigned, in nanoseconds.
    pub grace_nanos: u64,
}

impl RetainedCheckpoint {
    /// Convenience accessor for the underlying [`Checkpoint`].
    #[must_use]
    pub const fn checkpoint(&self) -> &Checkpoint {
        &self.cosigned.checkpoint
    }
}

/// The outcome of a store write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The row was newly stored.
    Inserted,
    /// An identical row already existed.
    AlreadyPresent,
}

/// The witness's durable store.
pub struct Store {
    conn: Mutex<Connection>,
}

fn to_i64(what: &'static str, value: u64) -> WitnessResult<i64> {
    i64::try_from(value).map_err(|_| WitnessError::IndexOverflow { what })
}

fn to_u64(what: &'static str, value: i64) -> WitnessResult<u64> {
    u64::try_from(value).map_err(|_| WitnessError::IndexOverflow { what })
}

impl Store {
    /// Open (creating if absent) a store backed by the `SQLite` file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::StoreInit`] if the file cannot be opened or migrated.
    pub fn open(path: &Path) -> WitnessResult<Self> {
        let conn = Connection::open(path).map_err(|e| WitnessError::StoreInit(e.to_string()))?;
        Self::from_connection(conn)
    }

    /// Open a private in-memory store. Intended for tests.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::StoreInit`] if the in-memory database cannot be created.
    pub fn open_in_memory() -> WitnessResult<Self> {
        let conn =
            Connection::open_in_memory().map_err(|e| WitnessError::StoreInit(e.to_string()))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> WitnessResult<Self> {
        conn.execute_batch(SCHEMA).map_err(|e| WitnessError::StoreInit(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> WitnessResult<T>) -> WitnessResult<T> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| WitnessError::StoreInit("store mutex poisoned".to_owned()))?;
        let result = f(&conn);
        drop(conn);
        result
    }

    /// Hold this store's lock for an entire multi-step decision, so every read inside `f`
    /// observes state no concurrent caller can change until `f` returns, and the write(s) `f`
    /// performs are indivisible from the caller's perspective (core spec §3.3, "serialize and
    /// make atomic"). See the module docs for why per-call locking (what every other method
    /// here does) is not sufficient on its own for a read-classify-write sequence, and see
    /// [`crate::witness::witness_checkpoint`] for the one caller that needs this.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::StoreInit`] if the lock is poisoned, or propagates whatever
    /// `f` returns.
    pub(crate) fn with_lock<T>(
        &self,
        f: impl FnOnce(&Connection) -> WitnessResult<T>,
    ) -> WitnessResult<T> {
        self.with_conn(f)
    }

    /// Retain a newly cosigned checkpoint, together with the cadence and grace period that
    /// governed it.
    ///
    /// Idempotent for a repeated, identical `(log_id, tree_size, checkpoint_time)`.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn retain(
        &self,
        cosigned: &CosignedCheckpoint,
        cadence_nanos: u64,
        grace_nanos: u64,
    ) -> WitnessResult<InsertOutcome> {
        self.with_conn(|conn| insert_cosigned(conn, cosigned, cadence_nanos, grace_nanos))
    }

    /// Fetch the latest retained checkpoint for `log_id` — the greatest `(tree_size,
    /// checkpoint_time)`, matching core spec §7.3's series ordering.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn get_retained(&self, log_id: &str) -> WitnessResult<Option<RetainedCheckpoint>> {
        self.with_conn(|conn| get_retained(conn, log_id))
    }

    /// Fetch a previously cosigned checkpoint at exactly `tree_size` for `log_id`, if any —
    /// regardless of whether it is the latest retained member (core spec §3.3, "compare
    /// against the whole retained history, not the newest member").
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn find_cosigned_at_size(
        &self,
        log_id: &str,
        tree_size: u64,
    ) -> WitnessResult<Option<RetainedCheckpoint>> {
        self.with_conn(|conn| find_cosigned_at_size(conn, log_id, tree_size))
    }

    /// The complete cosigned history for `log_id`, ascending by `(tree_size,
    /// checkpoint_time)`.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn list_cosigned(&self, log_id: &str) -> WitnessResult<Vec<RetainedCheckpoint>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT log_id, tree_size, root_hash, checkpoint_time, log_key_id, \
                 log_signature, witness_id, witness_key_id, cosignature, cosigned_at, \
                 cadence_nanos, grace_nanos \
                 FROM cosigned_checkpoints WHERE log_id = ?1 \
                 ORDER BY tree_size ASC, checkpoint_time ASC",
            )?;
            let rows = stmt.query_map([log_id], retained_row)?;
            rows.collect::<Result<Vec<_>, _>>()?.into_iter().collect()
        })
    }

    /// Append refusal evidence to the published log.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn record_refusal(&self, evidence: &RefusalEvidence) -> WitnessResult<()> {
        self.with_conn(|conn| insert_refusal(conn, evidence))
    }

    /// Every rotation cosignature this witness holds for the rotation anchored at
    /// `manifest_entry_index`, oldest checkpoint first.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn list_rotation_cosignatures(
        &self,
        log_id: &str,
        manifest_entry_index: u64,
    ) -> WitnessResult<Vec<CosignedCheckpoint>> {
        self.with_conn(|conn| list_rotation_cosigned(conn, log_id, manifest_entry_index))
    }

    /// Every refusal published for `log_id`, in the order recorded.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn list_refusals(&self, log_id: &str) -> WitnessResult<Vec<RefusalEvidence>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT witness_id, reason, retained, offered, consistency_proof, detail, \
                 refused_at, key_id, signature \
                 FROM refusals WHERE log_id = ?1 ORDER BY id ASC",
            )?;
            let log_id_owned = log_id.to_owned();
            let rows =
                stmt.query_map([log_id], move |row| Ok(refusal_row(row, log_id_owned.clone())))?;
            rows.collect::<Result<Vec<_>, _>>()?.into_iter().collect()
        })
    }

    /// The lowest `tree_size` at which `log_id` has been recorded as equivocated, if any.
    /// Core spec §7.3: "From the lowest `tree_size` at which it occurs, the series is no
    /// longer canonical" — nothing at or beyond this floor may ground a witness assertion.
    /// Core spec §3.3 confirms the floor is **permanent**: no later checkpoint clears it.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn equivocation_floor(&self, log_id: &str) -> WitnessResult<Option<u64>> {
        self.with_conn(|conn| equivocation_floor(conn, log_id))
    }

    /// The original conflicting pair that established `log_id`'s equivocation floor, if any
    /// — the earliest-recorded refusal with `reason: Equivocation` (later refusals citing a
    /// standing floor reuse this same pair; see
    /// [`crate::witness::witness_checkpoint`]).
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn original_equivocation_pair(
        &self,
        log_id: &str,
    ) -> WitnessResult<Option<(Checkpoint, Checkpoint)>> {
        self.with_conn(|conn| original_equivocation_pair(conn, log_id))
    }
}

// ---------------------------------------------------------------------------
// Connection-level operations.
//
// Free functions, not methods: each is called both from a `Store` method above (which wraps
// exactly one of them in its own `with_conn` lock acquisition) and directly from
// `crate::witness::witness_checkpoint`, composed together inside a *single*
// `Store::with_lock` critical section. Keeping the SQL here and the decision logic in
// `witness.rs` keeps the atomicity fix mechanical: nothing here decides what to do, it only
// reads and writes what it is told to.
// ---------------------------------------------------------------------------

pub(crate) fn insert_cosigned(
    conn: &Connection,
    cosigned: &CosignedCheckpoint,
    cadence_nanos: u64,
    grace_nanos: u64,
) -> WitnessResult<InsertOutcome> {
    let cp = &cosigned.checkpoint;
    let tree_size_i64 = to_i64("tree_size", cp.tree_size)?;
    let cadence_i64 = to_i64("cadence_nanos", cadence_nanos)?;
    let grace_i64 = to_i64("grace_nanos", grace_nanos)?;
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM cosigned_checkpoints \
             WHERE log_id = ?1 AND tree_size = ?2 AND checkpoint_time = ?3 \
             AND root_hash = ?4 AND cosignature = ?5",
            params![
                cp.log_id,
                tree_size_i64,
                cp.checkpoint_time,
                cp.root_hash,
                cosigned.cosignature
            ],
            |row| row.get(0),
        )
        .optional()?;
    if existing.is_some() {
        return Ok(InsertOutcome::AlreadyPresent);
    }
    conn.execute(
        "INSERT INTO cosigned_checkpoints \
         (log_id, tree_size, root_hash, checkpoint_time, log_key_id, log_signature, \
          witness_id, witness_key_id, cosignature, cosigned_at, cadence_nanos, grace_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            cp.log_id,
            tree_size_i64,
            cp.root_hash,
            cp.checkpoint_time,
            cp.key_id,
            cp.signature,
            cosigned.witness_id,
            cosigned.key_id,
            cosigned.cosignature,
            cosigned.cosigned_at,
            cadence_i64,
            grace_i64,
        ],
    )?;
    Ok(InsertOutcome::Inserted)
}

/// Record a cosignature over ROTATION-ANCHORING material, apart from the series (see the
/// module docs). Idempotent for an identical resubmission.
pub(crate) fn insert_rotation_cosigned(
    conn: &Connection,
    manifest_entry_index: u64,
    cosigned: &CosignedCheckpoint,
) -> WitnessResult<InsertOutcome> {
    let cp = &cosigned.checkpoint;
    let index_i64 = to_i64("manifest_entry_index", manifest_entry_index)?;
    let tree_size_i64 = to_i64("tree_size", cp.tree_size)?;

    // The primary key is `(log_id, manifest_entry_index, tree_size, checkpoint_time)`, and two
    // DIFFERENT checkpoints can share it: a log may sign one tree state at one instant under two
    // valid keys, and the key id and signature are not part of the key. So the row at that key is
    // read and compared in full before anything is written — an identical one is idempotent, a
    // different one is a conflict, and neither is an overwrite. `INSERT OR REPLACE` here would
    // discard a cosignature this witness had already published over the other checkpoint.
    let existing = conn
        .query_row(
            "SELECT log_id, tree_size, root_hash, checkpoint_time, log_key_id, log_signature, \
             witness_id, witness_key_id, cosignature, cosigned_at \
             FROM rotation_cosignatures WHERE log_id = ?1 AND manifest_entry_index = ?2 \
             AND tree_size = ?3 AND checkpoint_time = ?4",
            params![cp.log_id, index_i64, tree_size_i64, cp.checkpoint_time],
            cosigned_row,
        )
        .optional()?
        .transpose()?;
    if let Some(existing) = existing {
        if &existing == cosigned {
            return Ok(InsertOutcome::AlreadyPresent);
        }
        return Err(WitnessError::RotationCosignatureConflict {
            manifest_entry_index,
            tree_size: cp.tree_size,
            checkpoint_time: cp.checkpoint_time.clone(),
        });
    }

    // Keep only anchors that could be served. After a rotation that left the LOG key set alone —
    // I-D §7.1 makes a change to the witness key objects a rotation on its own — every later
    // checkpoint of the series qualifies as that rotation's anchor, so recording each one would
    // grow this table with the series to no purpose: the rotation route serves the smallest
    // `(tree_size, checkpoint_time)` and nothing else. A candidate no earlier than one already
    // held is therefore superseded rather than stored. What IS stored stays: an earlier candidate
    // arriving later is recorded beside the one it supersedes, never over it, so what is served
    // is the minimum over everything ever cosigned and does not depend on arrival order.
    let held: Option<(i64, String)> = conn
        .query_row(
            "SELECT tree_size, checkpoint_time FROM rotation_cosignatures \
             WHERE log_id = ?1 AND manifest_entry_index = ?2 \
             ORDER BY tree_size ASC, checkpoint_time ASC LIMIT 1",
            params![cp.log_id, index_i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((held_size, held_time)) = held {
        if (held_size, held_time.as_str()) <= (tree_size_i64, cp.checkpoint_time.as_str()) {
            return Ok(InsertOutcome::AlreadyPresent);
        }
    }

    conn.execute(
        "INSERT INTO rotation_cosignatures \
         (log_id, manifest_entry_index, tree_size, root_hash, checkpoint_time, log_key_id, \
          log_signature, witness_id, witness_key_id, cosignature, cosigned_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            cp.log_id,
            index_i64,
            tree_size_i64,
            cp.root_hash,
            cp.checkpoint_time,
            cp.key_id,
            cp.signature,
            cosigned.witness_id,
            cosigned.key_id,
            cosigned.cosignature,
            cosigned.cosigned_at,
        ],
    )?;
    Ok(InsertOutcome::Inserted)
}

/// Every rotation cosignature this witness holds for one rotation, oldest checkpoint first.
pub(crate) fn list_rotation_cosigned(
    conn: &Connection,
    log_id: &str,
    manifest_entry_index: u64,
) -> WitnessResult<Vec<CosignedCheckpoint>> {
    let index_i64 = to_i64("manifest_entry_index", manifest_entry_index)?;
    let mut stmt = conn.prepare(
        "SELECT log_id, tree_size, root_hash, checkpoint_time, log_key_id, log_signature, \
         witness_id, witness_key_id, cosignature, cosigned_at \
         FROM rotation_cosignatures WHERE log_id = ?1 AND manifest_entry_index = ?2 \
         ORDER BY tree_size ASC, checkpoint_time ASC",
    )?;
    let rows = stmt.query_map(params![log_id, index_i64], cosigned_row)?;
    rows.collect::<Result<Vec<_>, _>>()?.into_iter().collect()
}

/// Read a [`CosignedCheckpoint`] from the ten columns the rotation table selects.
fn cosigned_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WitnessResult<CosignedCheckpoint>> {
    let tree_size: i64 = row.get(1)?;
    let checkpoint = Checkpoint {
        log_id: row.get(0)?,
        tree_size: match u64::try_from(tree_size) {
            Ok(value) => value,
            Err(_) => return Ok(Err(WitnessError::IndexOverflow { what: "tree_size" })),
        },
        root_hash: row.get(2)?,
        checkpoint_time: row.get(3)?,
        key_id: row.get(4)?,
        signature: row.get(5)?,
    };
    Ok(Ok(CosignedCheckpoint {
        checkpoint,
        witness_id: row.get(6)?,
        key_id: row.get(7)?,
        cosignature: row.get(8)?,
        cosigned_at: row.get(9)?,
    }))
}

pub(crate) fn get_retained(
    conn: &Connection,
    log_id: &str,
) -> WitnessResult<Option<RetainedCheckpoint>> {
    conn.query_row(
        "SELECT log_id, tree_size, root_hash, checkpoint_time, log_key_id, \
         log_signature, witness_id, witness_key_id, cosignature, cosigned_at, \
         cadence_nanos, grace_nanos \
         FROM cosigned_checkpoints WHERE log_id = ?1 \
         ORDER BY tree_size DESC, checkpoint_time DESC LIMIT 1",
        [log_id],
        retained_row,
    )
    .optional()?
    .transpose()
}

pub(crate) fn find_cosigned_at_size(
    conn: &Connection,
    log_id: &str,
    tree_size: u64,
) -> WitnessResult<Option<RetainedCheckpoint>> {
    let tree_size_i64 = to_i64("tree_size", tree_size)?;
    conn.query_row(
        "SELECT log_id, tree_size, root_hash, checkpoint_time, log_key_id, \
         log_signature, witness_id, witness_key_id, cosignature, cosigned_at, \
         cadence_nanos, grace_nanos \
         FROM cosigned_checkpoints WHERE log_id = ?1 AND tree_size = ?2 \
         ORDER BY id ASC LIMIT 1",
        params![log_id, tree_size_i64],
        retained_row,
    )
    .optional()?
    .transpose()
}

/// A checkpoint this witness has already cosigned at `tree_size` whose root DIFFERS from
/// `root_hash`, drawn from the rotation table.
///
/// The series table has its own lookup ([`find_cosigned_at_size`]); this is the other half, so
/// that "compare against the whole retained history" (core spec §3.3) means the whole of it and
/// not the series alone. Material held apart from the series is still material this witness
/// vouched for at that size.
pub(crate) fn find_rotation_conflict(
    conn: &Connection,
    log_id: &str,
    tree_size: u64,
    root_hash: &str,
) -> WitnessResult<Option<Checkpoint>> {
    let tree_size_i64 = to_i64("tree_size", tree_size)?;
    let found = conn
        .query_row(
            "SELECT log_id, tree_size, root_hash, checkpoint_time, log_key_id, log_signature, \
             witness_id, witness_key_id, cosignature, cosigned_at \
             FROM rotation_cosignatures WHERE log_id = ?1 AND tree_size = ?2 AND root_hash <> ?3 \
             ORDER BY checkpoint_time ASC LIMIT 1",
            params![log_id, tree_size_i64, root_hash],
            cosigned_row,
        )
        .optional()?;
    found.transpose().map(|found| found.map(|cosigned| cosigned.checkpoint))
}

pub(crate) fn insert_refusal(conn: &Connection, evidence: &RefusalEvidence) -> WitnessResult<()> {
    let retained_json = serde_json::to_string(&evidence.retained)?;
    let offered_json = serde_json::to_string(&evidence.offered)?;
    let proof_json = evidence.consistency_proof.as_ref().map(serde_json::to_string).transpose()?;
    conn.execute(
        "INSERT INTO refusals \
         (log_id, witness_id, reason, retained, offered, consistency_proof, detail, \
          refused_at, key_id, signature) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            evidence.log_id,
            evidence.witness_id,
            reason_str(evidence.reason),
            retained_json,
            offered_json,
            proof_json,
            evidence.detail,
            evidence.refused_at,
            evidence.key_id,
            evidence.signature,
        ],
    )?;
    Ok(())
}

pub(crate) fn equivocation_floor(conn: &Connection, log_id: &str) -> WitnessResult<Option<u64>> {
    let floor: Option<i64> = conn
        .query_row("SELECT MIN(tree_size) FROM equivocations WHERE log_id = ?1", [log_id], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional()?
        .flatten();
    floor.map(|f| to_u64("tree_size", f)).transpose()
}

pub(crate) fn original_equivocation_pair(
    conn: &Connection,
    log_id: &str,
) -> WitnessResult<Option<(Checkpoint, Checkpoint)>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT retained, offered FROM refusals \
             WHERE log_id = ?1 AND reason = ?2 ORDER BY id ASC LIMIT 1",
            params![log_id, reason_str(RefusalReason::Equivocation)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(retained_json, offered_json)| {
        Ok((serde_json::from_str(&retained_json)?, serde_json::from_str(&offered_json)?))
    })
    .transpose()
}

/// Record that `log_id` equivocated at `tree_size`, and persist the refusal evidence that
/// justifies it, in one `SQLite` transaction — core spec §3.3: "an equivocation record MUST
/// be persisted in the same atomic step as the refusal it justifies." Idempotent for a
/// repeated report of the same `(log_id, tree_size)` floor (the refusal is still inserted:
/// each refusal is its own signed statement about one candidate).
///
/// # Errors
///
/// Returns [`WitnessError::Store`] on a database failure.
pub(crate) fn insert_equivocation_and_refusal(
    conn: &Connection,
    log_id: &str,
    tree_size: u64,
    detected_at: &str,
    evidence: &RefusalEvidence,
) -> WitnessResult<InsertOutcome> {
    let tree_size_i64 = to_i64("tree_size", tree_size)?;
    let tx = conn.unchecked_transaction()?;
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM equivocations WHERE log_id = ?1 AND tree_size = ?2",
            params![log_id, tree_size_i64],
            |row| row.get(0),
        )
        .optional()?;
    let outcome = if existing.is_some() {
        InsertOutcome::AlreadyPresent
    } else {
        tx.execute(
            "INSERT INTO equivocations (log_id, tree_size, detected_at) VALUES (?1, ?2, ?3)",
            params![log_id, tree_size_i64, detected_at],
        )?;
        InsertOutcome::Inserted
    };
    insert_refusal(&tx, evidence)?;
    tx.commit()?;
    Ok(outcome)
}

const fn reason_str(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::Equivocation => "equivocation",
        RefusalReason::SizeRegression => "size-regression",
        RefusalReason::ExtensionFailed => "extension-failed",
    }
}

fn reason_from_str(value: &str) -> WitnessResult<RefusalReason> {
    match value {
        "equivocation" => Ok(RefusalReason::Equivocation),
        "size-regression" => Ok(RefusalReason::SizeRegression),
        "extension-failed" => Ok(RefusalReason::ExtensionFailed),
        other => Err(WitnessError::StoreInit(format!("unknown stored refusal reason `{other}`"))),
    }
}

fn refusal_row(row: &rusqlite::Row<'_>, log_id: String) -> WitnessResult<RefusalEvidence> {
    let witness_id: String = row.get(0)?;
    let reason_text: String = row.get(1)?;
    let retained_json: String = row.get(2)?;
    let offered_json: String = row.get(3)?;
    let proof_json: Option<String> = row.get(4)?;
    let detail: String = row.get(5)?;
    let refused_at: String = row.get(6)?;
    let key_id: String = row.get(7)?;
    let signature: String = row.get(8)?;

    let reason = reason_from_str(&reason_text)?;
    let retained: Checkpoint = serde_json::from_str(&retained_json)?;
    let offered: Checkpoint = serde_json::from_str(&offered_json)?;
    let consistency_proof: Option<ConsistencyProofEvidence> =
        proof_json.map(|j| serde_json::from_str(&j)).transpose()?;
    Ok(RefusalEvidence {
        kind: "witness-refusal".to_owned(),
        witness_id,
        log_id,
        reason,
        retained,
        offered,
        consistency_proof,
        detail,
        refused_at,
        key_id,
        signature,
    })
}

fn retained_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WitnessResult<RetainedCheckpoint>> {
    let tree_size: i64 = row.get(1)?;
    let cadence: i64 = row.get(10)?;
    let grace: i64 = row.get(11)?;
    let built = (|| -> WitnessResult<RetainedCheckpoint> {
        let checkpoint = Checkpoint {
            log_id: row.get(0)?,
            tree_size: to_u64("tree_size", tree_size)?,
            root_hash: row.get(2)?,
            checkpoint_time: row.get(3)?,
            key_id: row.get(4)?,
            signature: row.get(5)?,
        };
        let cosigned = CosignedCheckpoint {
            checkpoint,
            witness_id: row.get(6)?,
            key_id: row.get(7)?,
            cosignature: row.get(8)?,
            cosigned_at: row.get(9)?,
        };
        Ok(RetainedCheckpoint {
            cosigned,
            cadence_nanos: to_u64("cadence_nanos", cadence)?,
            grace_nanos: to_u64("grace_nanos", grace)?,
        })
    })();
    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(log_id: &str, tree_size: u64, time: &str) -> Checkpoint {
        Checkpoint {
            log_id: log_id.to_owned(),
            tree_size,
            root_hash: format!("sha256:{tree_size:064x}"),
            checkpoint_time: time.to_owned(),
            key_id: "sha256:aa".to_owned(),
            signature: "base64:AAAA".to_owned(),
        }
    }

    fn cosigned(log_id: &str, tree_size: u64, time: &str) -> CosignedCheckpoint {
        CosignedCheckpoint {
            checkpoint: checkpoint(log_id, tree_size, time),
            witness_id: "witness-1".to_owned(),
            key_id: "sha256:bb".to_owned(),
            cosignature: format!("base64:{tree_size}"),
            cosigned_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    fn refusal(log_id: &str, reason: RefusalReason) -> RefusalEvidence {
        RefusalEvidence {
            kind: "witness-refusal".to_owned(),
            witness_id: "witness-1".to_owned(),
            log_id: log_id.to_owned(),
            reason,
            retained: checkpoint(log_id, 1, "2026-01-01T00:00:00.000000000Z"),
            offered: checkpoint(log_id, 1, "2026-01-01T00:05:00.000000000Z"),
            consistency_proof: None,
            detail: "test".to_owned(),
            refused_at: "2026-01-01T00:06:00Z".to_owned(),
            key_id: "sha256:cc".to_owned(),
            signature: "base64:DEAD".to_owned(),
        }
    }

    #[test]
    fn a_fresh_store_has_no_retained_checkpoint() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert!(store.get_retained("sha256:aa").expect("query").is_none());
    }

    #[test]
    fn retaining_stores_cadence_and_grace_alongside_the_checkpoint() {
        let store = Store::open_in_memory().expect("in-memory store");
        let cp = cosigned("sha256:aa", 1, "2026-01-01T00:00:00.000000000Z");
        store.retain(&cp, 300_000_000_000, 60_000_000_000).expect("retain");
        let retained = store.get_retained("sha256:aa").expect("query").expect("present");
        assert_eq!(retained.cadence_nanos, 300_000_000_000);
        assert_eq!(retained.grace_nanos, 60_000_000_000);
        assert_eq!(retained.checkpoint().tree_size, 1);
    }

    #[test]
    fn the_latest_by_tree_size_and_time_is_retained() {
        let store = Store::open_in_memory().expect("in-memory store");
        store
            .retain(
                &cosigned("sha256:aa", 5, "2026-01-01T00:05:00.000000000Z"),
                60_000_000_000,
                10_000_000_000,
            )
            .expect("retain");
        store
            .retain(
                &cosigned("sha256:aa", 2, "2026-01-01T00:02:00.000000000Z"),
                60_000_000_000,
                10_000_000_000,
            )
            .expect("retain");
        let retained = store.get_retained("sha256:aa").expect("query").expect("present");
        assert_eq!(retained.checkpoint().tree_size, 5);
    }

    #[test]
    fn repeated_identical_retention_is_idempotent() {
        let store = Store::open_in_memory().expect("in-memory store");
        let cp = cosigned("sha256:aa", 1, "2026-01-01T00:00:00.000000000Z");
        assert_eq!(store.retain(&cp, 1, 1).expect("first"), InsertOutcome::Inserted);
        assert_eq!(store.retain(&cp, 1, 1).expect("repeat"), InsertOutcome::AlreadyPresent);
    }

    #[test]
    fn different_logs_are_tracked_independently() {
        let store = Store::open_in_memory().expect("in-memory store");
        store
            .retain(&cosigned("sha256:aa", 3, "2026-01-01T00:00:00.000000000Z"), 1, 1)
            .expect("retain a");
        store
            .retain(&cosigned("sha256:bb", 9, "2026-01-01T00:00:00.000000000Z"), 1, 1)
            .expect("retain b");
        assert_eq!(
            store
                .get_retained("sha256:aa")
                .expect("query")
                .expect("present")
                .checkpoint()
                .tree_size,
            3
        );
        assert_eq!(
            store
                .get_retained("sha256:bb")
                .expect("query")
                .expect("present")
                .checkpoint()
                .tree_size,
            9
        );
    }

    #[test]
    fn cosigned_history_is_listed_in_ascending_order() {
        let store = Store::open_in_memory().expect("in-memory store");
        store
            .retain(&cosigned("sha256:aa", 5, "2026-01-01T00:05:00.000000000Z"), 1, 1)
            .expect("retain");
        store
            .retain(&cosigned("sha256:aa", 2, "2026-01-01T00:02:00.000000000Z"), 1, 1)
            .expect("retain");
        let history = store.list_cosigned("sha256:aa").expect("query");
        assert_eq!(
            history.iter().map(|r| r.checkpoint().tree_size).collect::<Vec<_>>(),
            vec![2, 5]
        );
    }

    #[test]
    fn find_cosigned_at_size_finds_a_non_latest_member() {
        let store = Store::open_in_memory().expect("in-memory store");
        store
            .retain(&cosigned("sha256:aa", 1, "2026-01-01T00:00:00.000000000Z"), 1, 1)
            .expect("retain");
        store
            .retain(&cosigned("sha256:aa", 3, "2026-01-01T00:03:00.000000000Z"), 1, 1)
            .expect("retain");
        let found = store.find_cosigned_at_size("sha256:aa", 1).expect("query").expect("present");
        assert_eq!(found.checkpoint().tree_size, 1);
        assert!(store.find_cosigned_at_size("sha256:aa", 2).expect("query").is_none());
    }

    #[test]
    fn refusal_evidence_round_trips() {
        let store = Store::open_in_memory().expect("in-memory store");
        let evidence = refusal("sha256:aa", RefusalReason::Equivocation);
        store.record_refusal(&evidence).expect("record");
        let listed = store.list_refusals("sha256:aa").expect("query");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].witness_id, "witness-1");
        assert_eq!(listed[0].reason, RefusalReason::Equivocation);
        assert_eq!(listed[0].retained.tree_size, 1);
        assert_eq!(listed[0].offered.checkpoint_time, "2026-01-01T00:05:00.000000000Z");
        assert_eq!(listed[0].signature, "base64:DEAD");
        assert!(listed[0].consistency_proof.is_none());
    }

    #[test]
    fn a_consistency_proof_round_trips_with_the_refusal_that_carries_it() {
        let store = Store::open_in_memory().expect("in-memory store");
        let mut evidence = refusal("sha256:aa", RefusalReason::ExtensionFailed);
        evidence.consistency_proof = Some(ConsistencyProofEvidence {
            from_size: 1,
            to_size: 4,
            path: vec![format!("sha256:{}", "aa".repeat(32))],
        });
        store.record_refusal(&evidence).expect("record");
        let listed = store.list_refusals("sha256:aa").expect("query");
        let proof = listed[0].consistency_proof.as_ref().expect("carried");
        assert_eq!(proof.from_size, 1);
        assert_eq!(proof.to_size, 4);
        assert_eq!(proof.path.len(), 1);
    }

    #[test]
    fn refusals_for_an_unknown_log_are_empty_not_an_error() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert!(store.list_refusals("sha256:missing").expect("query").is_empty());
    }

    #[test]
    fn a_file_backed_store_persists_across_reopen() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("witness.sqlite3");
        {
            let store = Store::open(&path).expect("open file-backed store");
            store
                .retain(&cosigned("sha256:aa", 1, "2026-01-01T00:00:00.000000000Z"), 1, 1)
                .expect("retain");
        }
        let reopened = Store::open(&path).expect("reopen file-backed store");
        assert!(reopened.get_retained("sha256:aa").expect("query").is_some());
    }

    #[test]
    fn a_fresh_store_has_no_equivocation_floor() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert!(store.equivocation_floor("sha256:aa").expect("query").is_none());
        assert!(store.original_equivocation_pair("sha256:aa").expect("query").is_none());
    }

    #[test]
    fn recording_an_equivocation_persists_the_floor_and_the_refusal_together() {
        let store = Store::open_in_memory().expect("in-memory store");
        let evidence = refusal("sha256:aa", RefusalReason::Equivocation);
        store
            .with_lock(|conn| {
                insert_equivocation_and_refusal(
                    conn,
                    "sha256:aa",
                    5,
                    "2026-01-01T00:00:00Z",
                    &evidence,
                )
            })
            .expect("record");
        assert_eq!(store.equivocation_floor("sha256:aa").expect("query"), Some(5));
        let (a, b) =
            store.original_equivocation_pair("sha256:aa").expect("query").expect("present");
        assert_eq!(a.tree_size, 1);
        assert_eq!(b.tree_size, 1);
        assert_eq!(store.list_refusals("sha256:aa").expect("query").len(), 1);
    }

    #[test]
    fn the_floor_is_the_lowest_reported_tree_size() {
        let store = Store::open_in_memory().expect("in-memory store");
        let evidence = refusal("sha256:aa", RefusalReason::Equivocation);
        store
            .with_lock(|conn| {
                insert_equivocation_and_refusal(
                    conn,
                    "sha256:aa",
                    9,
                    "2026-01-01T00:00:00Z",
                    &evidence,
                )
            })
            .expect("record");
        store
            .with_lock(|conn| {
                insert_equivocation_and_refusal(
                    conn,
                    "sha256:aa",
                    3,
                    "2026-01-01T00:01:00Z",
                    &evidence,
                )
            })
            .expect("record");
        assert_eq!(store.equivocation_floor("sha256:aa").expect("query"), Some(3));
    }

    #[test]
    fn repeated_equivocation_reports_at_the_same_size_are_idempotent_for_the_floor() {
        let store = Store::open_in_memory().expect("in-memory store");
        let evidence = refusal("sha256:aa", RefusalReason::Equivocation);
        assert_eq!(
            store
                .with_lock(|conn| insert_equivocation_and_refusal(
                    conn,
                    "sha256:aa",
                    5,
                    "2026-01-01T00:00:00Z",
                    &evidence
                ))
                .expect("first"),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store
                .with_lock(|conn| insert_equivocation_and_refusal(
                    conn,
                    "sha256:aa",
                    5,
                    "2026-01-01T00:00:01Z",
                    &evidence
                ))
                .expect("repeat"),
            InsertOutcome::AlreadyPresent
        );
        // The floor row is deduplicated, but each call still signs and persists its own
        // refusal — every refusal call is a fresh, independently verifiable statement.
        assert_eq!(store.list_refusals("sha256:aa").expect("query").len(), 2);
    }

    #[test]
    fn equivocation_floors_are_tracked_independently_per_log() {
        let store = Store::open_in_memory().expect("in-memory store");
        let evidence = refusal("sha256:aa", RefusalReason::Equivocation);
        store
            .with_lock(|conn| {
                insert_equivocation_and_refusal(
                    conn,
                    "sha256:aa",
                    5,
                    "2026-01-01T00:00:00Z",
                    &evidence,
                )
            })
            .expect("record");
        assert!(store.equivocation_floor("sha256:bb").expect("query").is_none());
    }

    #[test]
    fn with_lock_composes_multiple_reads_and_a_write_atomically() {
        // Exercises the exact composition `witness_checkpoint` relies on: several reads and
        // a write inside one critical section, using the free `pub(crate)` functions
        // directly rather than the per-call `Store` methods.
        let store = Store::open_in_memory().expect("in-memory store");
        let outcome = store
            .with_lock(|conn| {
                let _retained = get_retained(conn, "sha256:aa")?;
                let _at_size = find_cosigned_at_size(conn, "sha256:aa", 1)?;
                let _floor = equivocation_floor(conn, "sha256:aa")?;
                insert_cosigned(
                    conn,
                    &cosigned("sha256:aa", 1, "2026-01-01T00:00:00.000000000Z"),
                    1,
                    1,
                )
            })
            .expect("composed transition");
        assert_eq!(outcome, InsertOutcome::Inserted);
        assert!(store.get_retained("sha256:aa").expect("query").is_some());
    }
}
