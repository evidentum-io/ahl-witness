//! Durable local storage: the latest retained (cosigned) checkpoint per log, the full
//! cosigned-checkpoint history, and published refusal evidence (core spec §3.3; adaptor
//! profile §11).
//!
//! Unlike `ahl-mirror`'s store, this one holds no entry bytes and no candidate material —
//! a witness's job is narrower (verify and cosign or refuse, core spec §3.3), not to serve
//! entries or range proofs (that is `ahl-mirror`'s and any independent mirror's job, core
//! spec §3.5). Everything written here is already a *verdict*: a cosignature this witness
//! itself produced, or refusal evidence this witness itself signed.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension as _};

use crate::checkpoint::Checkpoint;
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
CREATE TABLE IF NOT EXISTS refusals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id      TEXT NOT NULL,
    witness_id  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    retained    TEXT NOT NULL,
    offered     TEXT NOT NULL,
    detail      TEXT NOT NULL,
    refused_at  TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    signature   TEXT NOT NULL
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

    /// Retain a newly cosigned checkpoint, together with the cadence and grace period that
    /// governed it.
    ///
    /// Idempotent for a repeated, identical `(log_id, tree_size, checkpoint_time)` — the
    /// state machine may re-cosign an idempotent republish of an already-retained checkpoint
    /// (see [`crate::consistency::ConsistencyOutcome::Consistent`] for the equal-size,
    /// equal-root case).
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
        let cp = &cosigned.checkpoint;
        let tree_size_i64 = to_i64("tree_size", cp.tree_size)?;
        let cadence_i64 = to_i64("cadence_nanos", cadence_nanos)?;
        let grace_i64 = to_i64("grace_nanos", grace_nanos)?;
        self.with_conn(|conn| {
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
                  witness_id, witness_key_id, cosignature, cosigned_at, cadence_nanos, \
                  grace_nanos) \
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
        })
    }

    /// Fetch the latest retained checkpoint for `log_id` — the greatest `(tree_size,
    /// checkpoint_time)`, matching core spec §7.3's series ordering.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn get_retained(&self, log_id: &str) -> WitnessResult<Option<RetainedCheckpoint>> {
        self.with_conn(|conn| {
            let row = conn
                .query_row(
                    "SELECT log_id, tree_size, root_hash, checkpoint_time, log_key_id, \
                     log_signature, witness_id, witness_key_id, cosignature, cosigned_at, \
                     cadence_nanos, grace_nanos \
                     FROM cosigned_checkpoints WHERE log_id = ?1 \
                     ORDER BY tree_size DESC, checkpoint_time DESC LIMIT 1",
                    [log_id],
                    retained_row,
                )
                .optional()?;
            row.transpose()
        })
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
        let retained_json = serde_json::to_string(&evidence.retained)?;
        let offered_json = serde_json::to_string(&evidence.offered)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO refusals \
                 (log_id, witness_id, reason, retained, offered, detail, refused_at, key_id, \
                  signature) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    evidence.log_id,
                    evidence.witness_id,
                    reason_str(evidence.reason),
                    retained_json,
                    offered_json,
                    evidence.detail,
                    evidence.refused_at,
                    evidence.key_id,
                    evidence.signature,
                ],
            )?;
            Ok(())
        })
    }

    /// Every refusal published for `log_id`, in the order recorded.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn list_refusals(&self, log_id: &str) -> WitnessResult<Vec<RefusalEvidence>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT witness_id, reason, retained, offered, detail, refused_at, key_id, \
                 signature \
                 FROM refusals WHERE log_id = ?1 ORDER BY id ASC",
            )?;
            let log_id_owned = log_id.to_owned();
            let rows = stmt.query_map([log_id], move |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    log_id_owned.clone(),
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (
                    witness_id,
                    reason_text,
                    retained_json,
                    offered_json,
                    detail,
                    refused_at,
                    key_id,
                    sig,
                    lid,
                ) = row?;
                let reason = reason_from_str(&reason_text)?;
                let retained: Checkpoint = serde_json::from_str(&retained_json)?;
                let offered: Checkpoint = serde_json::from_str(&offered_json)?;
                out.push(RefusalEvidence {
                    kind: "witness-refusal".to_owned(),
                    witness_id,
                    log_id: lid,
                    reason,
                    retained,
                    offered,
                    detail,
                    refused_at,
                    key_id,
                    signature: sig,
                });
            }
            Ok(out)
        })
    }

    /// Record that `log_id` equivocated at `tree_size` (core spec §7.3, "Equivocation ends
    /// the series"): two authenticated checkpoints shared this `tree_size` with differing
    /// `root_hash` values. Idempotent for a repeated report of the same `(log_id, tree_size)`.
    ///
    /// The conflicting checkpoints themselves are not duplicated here — they are already
    /// preserved and published as the accompanying refusal evidence (see
    /// [`Self::record_refusal`]); this table exists solely to answer "has this log
    /// equivocated, and from what `tree_size`", which every subsequent witnessing decision
    /// for the log must consult (see [`crate::witness::witness_checkpoint`]).
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn record_equivocation(
        &self,
        log_id: &str,
        tree_size: u64,
        detected_at: &str,
    ) -> WitnessResult<InsertOutcome> {
        let tree_size_i64 = to_i64("tree_size", tree_size)?;
        self.with_conn(|conn| {
            let existing: Option<i64> = conn
                .query_row(
                    "SELECT id FROM equivocations WHERE log_id = ?1 AND tree_size = ?2",
                    params![log_id, tree_size_i64],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.is_some() {
                return Ok(InsertOutcome::AlreadyPresent);
            }
            conn.execute(
                "INSERT INTO equivocations (log_id, tree_size, detected_at) VALUES (?1, ?2, ?3)",
                params![log_id, tree_size_i64, detected_at],
            )?;
            Ok(InsertOutcome::Inserted)
        })
    }

    /// The lowest `tree_size` at which `log_id` has been recorded as equivocated, if any.
    /// Core spec §7.3: "From the lowest `tree_size` at which it occurs, the series is no
    /// longer canonical" — nothing at or beyond this floor may ground a witness assertion.
    ///
    /// # Errors
    ///
    /// Returns [`WitnessError::Store`] on a database failure.
    pub fn equivocation_floor(&self, log_id: &str) -> WitnessResult<Option<u64>> {
        self.with_conn(|conn| {
            let floor: Option<i64> = conn
                .query_row(
                    "SELECT MIN(tree_size) FROM equivocations WHERE log_id = ?1",
                    [log_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            floor.map(|f| to_u64("tree_size", f)).transpose()
        })
    }
}

const fn reason_str(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::Inconsistent => "inconsistent",
        RefusalReason::MissingConsistencyProof => "missing-consistency-proof",
    }
}

fn reason_from_str(value: &str) -> WitnessResult<RefusalReason> {
    match value {
        "inconsistent" => Ok(RefusalReason::Inconsistent),
        "missing-consistency-proof" => Ok(RefusalReason::MissingConsistencyProof),
        other => Err(WitnessError::StoreInit(format!("unknown stored refusal reason `{other}`"))),
    }
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
    fn refusal_evidence_round_trips() {
        let store = Store::open_in_memory().expect("in-memory store");
        let evidence = RefusalEvidence {
            kind: "witness-refusal".to_owned(),
            witness_id: "witness-1".to_owned(),
            log_id: "sha256:aa".to_owned(),
            reason: RefusalReason::Inconsistent,
            retained: checkpoint("sha256:aa", 1, "2026-01-01T00:00:00.000000000Z"),
            offered: checkpoint("sha256:aa", 1, "2026-01-01T00:05:00.000000000Z"),
            detail: "equivocation".to_owned(),
            refused_at: "2026-01-01T00:06:00Z".to_owned(),
            key_id: "sha256:cc".to_owned(),
            signature: "base64:DEAD".to_owned(),
        };
        store.record_refusal(&evidence).expect("record");
        let listed = store.list_refusals("sha256:aa").expect("query");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].witness_id, "witness-1");
        assert_eq!(listed[0].reason, RefusalReason::Inconsistent);
        assert_eq!(listed[0].retained.tree_size, 1);
        assert_eq!(listed[0].offered.checkpoint_time, "2026-01-01T00:05:00.000000000Z");
        assert_eq!(listed[0].signature, "base64:DEAD");
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
    }

    #[test]
    fn recording_an_equivocation_sets_the_floor() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.record_equivocation("sha256:aa", 5, "2026-01-01T00:00:00Z").expect("record");
        assert_eq!(store.equivocation_floor("sha256:aa").expect("query"), Some(5));
    }

    #[test]
    fn the_floor_is_the_lowest_reported_tree_size() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.record_equivocation("sha256:aa", 9, "2026-01-01T00:00:00Z").expect("record");
        store.record_equivocation("sha256:aa", 3, "2026-01-01T00:01:00Z").expect("record");
        assert_eq!(store.equivocation_floor("sha256:aa").expect("query"), Some(3));
    }

    #[test]
    fn repeated_equivocation_reports_are_idempotent() {
        let store = Store::open_in_memory().expect("in-memory store");
        assert_eq!(
            store.record_equivocation("sha256:aa", 5, "2026-01-01T00:00:00Z").expect("first"),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.record_equivocation("sha256:aa", 5, "2026-01-01T00:00:00Z").expect("repeat"),
            InsertOutcome::AlreadyPresent
        );
    }

    #[test]
    fn equivocation_floors_are_tracked_independently_per_log() {
        let store = Store::open_in_memory().expect("in-memory store");
        store.record_equivocation("sha256:aa", 5, "2026-01-01T00:00:00Z").expect("record");
        assert!(store.equivocation_floor("sha256:bb").expect("query").is_none());
    }
}
