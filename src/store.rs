//! The audit store: everything Rachna *observes*.
//!
//! `08-POLICY-AND-STORE.md` §3's line is the whole design: **everything
//! Rachna observes lives here; everything Rachna is told lives in
//! `rachna.nix`.** The DDL is `src/store/schema.sql`, which carries the
//! per-table reasoning.
//!
//! # It is a cache, not truth
//!
//! Deleting the file loses audit history and nothing else (§3.1). That
//! property is load-bearing — it is what makes migrations need not be
//! bulletproof early, and a corrupt database recoverable by deletion. The
//! moment something unrecoverable lives here it is lost, so
//! [`Store::open`] is deliberately free of any "repair" path.
//!
//! # The pragmas are not tuning
//!
//! Each one is a decision from §3.2 rather than a performance knob, so they
//! are applied in code with a reason attached rather than buried in the SQL.

use rusqlite::Connection;
use std::path::Path;

pub mod write;

/// The schema, compiled in.
///
/// Embedded rather than read from disk: a store that could not find its own
/// schema would be a runtime failure for a file we control, and the binary is
/// the only thing a user installs (`06` §5).
const SCHEMA: &str = include_str!("store/schema.sql");

/// Why the store could not be opened.
#[derive(Debug)]
pub enum StoreError {
    /// SQLite refused.
    Sqlite(rusqlite::Error),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "the audit store could not be opened: {error}"),
        }
    }
}

impl core::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// An open audit store.
pub struct Store {
    pub(crate) connection: Connection,
}

/// Written by hand because `rusqlite::Connection` is not `Debug`, and because
/// a database handle has nothing useful to print. Naming the type is what a
/// `Debug` on an enclosing struct actually needs.
impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Store")
    }
}

impl Store {
    /// Opens the store at `path`, creating and migrating the schema.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the file cannot be opened or the schema
    /// cannot be applied.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        Self::prepare(connection)
    }

    /// Opens an in-memory store, for tests.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the schema cannot be applied.
    pub fn in_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        Self::prepare(connection)
    }

    fn prepare(connection: Connection) -> Result<Self, StoreError> {
        // WAL mode: §3.2's single-writer design. Readers (`audit`, `explain`,
        // `status`) must never block the broker, which is the only writer.
        //
        // Set with `query_row` rather than `execute`, because `journal_mode`
        // returns the resulting mode as a row and `execute` treats that as an
        // error. An in-memory database cannot use WAL and reports `memory`,
        // which is correct rather than a failure — so the result is read and
        // discarded rather than asserted.
        let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;

        // Foreign keys are OFF by default in SQLite, per connection. A
        // decision whose run was deleted is meaningless, and the ON DELETE
        // CASCADE in the schema does nothing without this.
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        // NORMAL is safe under WAL and avoids an fsync per flush. FULL would
        // make the batched write in §3.2 pay for durability the store does
        // not need: it is a cache (§3.1).
        connection.execute_batch("PRAGMA synchronous = NORMAL;")?;

        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection })
    }

    /// The underlying connection.
    ///
    /// Exposed because the query layer is built next, and hiding it behind a
    /// method per query before those queries exist would be speculative.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The tables this store holds, sorted.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the catalogue cannot be read.
    pub fn tables(&self) -> Result<Vec<String>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )?;
        let names = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store with one revision, one run and one grant, so decision tests
    /// have valid foreign keys to point at.
    fn seeded() -> Store {
        let store = Store::in_memory().expect("in-memory store opens");
        store
            .connection()
            .execute_batch(
                "INSERT INTO config_revisions (id, ts, approved)
                   VALUES ('rev1', 1000, 1);
                 INSERT INTO runs (id, argv, cwd, started, config_revision)
                   VALUES ('run1', '[\"rachna\",\"start\"]', '/p', 1000, 'rev1');
                 INSERT INTO grants
                   (id, fingerprint, category, first_seen,
                    first_revision, last_revision)
                   VALUES ('g1', 'network github.com:443', 'network',
                           1000, 'rev1', 'rev1');",
            )
            .expect("seed");
        store
    }

    fn insert_decision(store: &Store, sql: &str) -> rusqlite::Result<usize> {
        store.connection().execute(sql, [])
    }

    // ---- the schema applies ----------------------------------------------

    #[test]
    fn every_table_in_the_spec_exists() {
        // 08 §3.3 names six tables. A missing one is a feature that silently
        // cannot work, so this is asserted against the catalogue rather than
        // trusted from the DDL.
        let store = Store::in_memory().expect("opens");
        let mut expected = vec![
            "config_revisions",
            "decisions",
            "grants",
            "observed_scopes",
            "runs",
            "usage",
        ];
        expected.sort_unstable();
        assert_eq!(store.tables().expect("tables"), expected);
    }

    #[test]
    fn the_schema_is_idempotent() {
        // Applied on every open, so a second open must not fail. This is what
        // `IF NOT EXISTS` buys, and it is the cheapest possible migration
        // story — which §3.1 permits precisely because the store is a cache.
        let store = Store::in_memory().expect("first");
        store.connection().execute_batch(SCHEMA).expect("second");
        store.connection().execute_batch(SCHEMA).expect("third");
    }

    #[test]
    fn foreign_keys_are_enforced() {
        // SQLite defaults this OFF, per connection, and the schema's
        // ON DELETE CASCADE is inert without it.
        //
        // Tested by OBSERVING a refusal rather than by reading the pragma: an
        // `enforces_foreign_keys()` accessor existed here and mutation
        // testing replaced its body with `Ok(true)` — the test passed, which
        // means it was asserting the accessor rather than the behaviour.
        // Inserting a row with a dangling reference is the behaviour.
        let store = Store::in_memory().expect("opens");
        let dangling = store.connection().execute(
            "INSERT INTO runs (id, argv, cwd, started, config_revision)
               VALUES ('r', '[]', '/p', 1, 'no-such-revision')",
            [],
        );
        assert!(
            dangling.is_err(),
            "a run referencing a missing revision was accepted, so foreign \
             keys are off and every ON DELETE CASCADE is inert"
        );
    }

    // ---- the CHECK constraints protect the audit trail -------------------

    #[test]
    fn an_allow_without_a_scope_is_refused() {
        // §1.3: treat a missing scope on an allow as a bug. Enforced in the
        // schema so a writer bug cannot silently degrade the audit trail —
        // a grant with no recorded scopes looks narrowable to nothing.
        let store = seeded();
        let result = insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, grant_id, scope)
               VALUES ('run1', 1, 'network', 'github.com:443', 'allow',
                       'g1', NULL)",
        );
        assert!(result.is_err(), "an allow with no scope was accepted");
    }

    #[test]
    fn a_deny_without_a_reason_is_refused() {
        // A denial with no reason makes `explain` useless, which is the one
        // thing the full-fidelity event log exists for.
        let store = seeded();
        let result = insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, deny_reason)
               VALUES ('run1', 1, 'network', 'evil.test:443', 'deny', NULL)",
        );
        assert!(result.is_err(), "a denial with no reason was accepted");
    }

    #[test]
    fn a_deny_carrying_a_scope_is_refused() {
        // The converse, and it matters: a denial with a scope would be
        // counted as usage by the rollup, making a blocked exfiltration
        // attempt look like a live grant that survives `revoke --unused`.
        let store = seeded();
        let result = insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, scope, deny_reason)
               VALUES ('run1', 1, 'network', 'x:1', 'deny', 'x:1',
                       'NoMatchingGrant')",
        );
        assert!(result.is_err(), "a denial with a scope was accepted");
    }

    #[test]
    fn an_allow_carrying_a_deny_reason_is_refused() {
        let store = seeded();
        let result = insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, grant_id, scope,
                deny_reason)
               VALUES ('run1', 1, 'network', 'x:1', 'allow', 'g1', 'x:1',
                       'NoMatchingGrant')",
        );
        assert!(result.is_err());
    }

    #[test]
    fn an_unrecognised_verdict_is_refused() {
        // `verdict` is an enum in Rust (`Decision`), and the schema holds the
        // same closed set so a typo in a query cannot invent a third state.
        let store = seeded();
        let result = insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, scope)
               VALUES ('run1', 1, 'network', 'x:1', 'maybe', 'x:1')",
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_well_formed_allow_and_deny_are_both_accepted() {
        // The constraints must not be so strict that real rows fail — the
        // failure mode where a security check blocks legitimate use.
        let store = seeded();
        insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, grant_id, scope)
               VALUES ('run1', 1, 'network', 'github.com:443', 'allow',
                       'g1', 'github.com:443')",
        )
        .expect("a well-formed allow");
        insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, deny_reason)
               VALUES ('run1', 2, 'network', 'evil.test:443', 'deny',
                       'NoMatchingGrant')",
        )
        .expect("a well-formed deny");
    }

    // ---- referential integrity -------------------------------------------

    #[test]
    fn a_decision_for_an_unknown_run_is_refused() {
        // A decision whose run does not exist cannot be explained, so it is
        // not a record of anything.
        let store = seeded();
        let result = insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, deny_reason)
               VALUES ('nope', 1, 'network', 'x:1', 'deny', 'r')",
        );
        assert!(result.is_err());
    }

    #[test]
    fn deleting_a_run_takes_its_decisions_with_it() {
        // Retention prunes runs; orphaned decisions would be unexplainable
        // rows that still count toward usage.
        let store = seeded();
        insert_decision(
            &store,
            "INSERT INTO decisions
               (run_id, ts, category, target, verdict, deny_reason)
               VALUES ('run1', 1, 'network', 'x:1', 'deny', 'r')",
        )
        .expect("insert");

        store
            .connection()
            .execute("DELETE FROM runs WHERE id = 'run1'", [])
            .expect("delete");

        let remaining: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM decisions", [], |row| row.get(0))
            .expect("count");
        assert_eq!(remaining, 0, "decisions outlived their run");
    }

    #[test]
    fn deleting_a_grant_takes_its_rollups_with_it() {
        let store = seeded();
        store
            .connection()
            .execute_batch(
                "INSERT INTO usage
                   (grant_id, count, runs, first_used, last_used)
                   VALUES ('g1', 5, 2, 1000, 2000);
                 INSERT INTO observed_scopes
                   (grant_id, scope, count, first_seen, last_seen)
                   VALUES ('g1', 'github.com:443', 5, 1000, 2000);",
            )
            .expect("seed rollups");

        store
            .connection()
            .execute("DELETE FROM grants WHERE id = 'g1'", [])
            .expect("delete");

        for table in ["usage", "observed_scopes"] {
            let remaining: i64 = store
                .connection()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("count");
            assert_eq!(remaining, 0, "{table} outlived its grant");
        }
    }

    // ---- the rollup invariants -------------------------------------------

    #[test]
    fn a_rollup_with_negative_counts_is_refused() {
        // A negative count would make a grant look unused and get it
        // revoked, or overflow a comparison in the audit report.
        let store = seeded();
        let result = store.connection().execute(
            "INSERT INTO usage (grant_id, count, runs, first_used, last_used)
               VALUES ('g1', -1, 0, 1, 1)",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_rollup_with_last_used_before_first_used_is_refused() {
        // Inverted timestamps would make the evidence threshold compute a
        // negative span, and `synthesize` would refuse or accept on nonsense.
        let store = seeded();
        let result = store.connection().execute(
            "INSERT INTO usage (grant_id, count, runs, first_used, last_used)
               VALUES ('g1', 1, 1, 2000, 1000)",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn one_scope_per_grant_is_recorded_once() {
        // The primary key is (grant_id, scope): the same host touched twice
        // increments a count, it does not add a row. Without this,
        // `observed_scopes` grows per decision and narrowing becomes the
        // table scan §3.3 separated it to avoid.
        let store = seeded();
        store
            .connection()
            .execute(
                "INSERT INTO observed_scopes
                   (grant_id, scope, count, first_seen, last_seen)
                   VALUES ('g1', 'github.com:443', 1, 1, 1)",
                [],
            )
            .expect("first");
        let duplicate = store.connection().execute(
            "INSERT INTO observed_scopes
               (grant_id, scope, count, first_seen, last_seen)
               VALUES ('g1', 'github.com:443', 1, 2, 2)",
            [],
        );
        assert!(duplicate.is_err(), "a duplicate scope row was accepted");
    }

    #[test]
    fn an_unapproved_revision_is_representable_and_a_third_state_is_not() {
        // `approved` is the first-run acknowledgement (`00` §3.10c), and it
        // is a boolean: a config is acknowledged or it is not.
        let store = Store::in_memory().expect("opens");
        for approved in [0, 1] {
            store
                .connection()
                .execute(
                    "INSERT INTO config_revisions (id, ts, approved)
                       VALUES (?1, 1, ?2)",
                    rusqlite::params![format!("rev{approved}"), approved],
                )
                .expect("valid");
        }
        let invalid = store.connection().execute(
            "INSERT INTO config_revisions (id, ts, approved)
               VALUES ('rev2', 1, 2)",
            [],
        );
        assert!(invalid.is_err());
    }

    #[test]
    fn a_store_error_explains_itself_and_keeps_its_cause() {
        // This string reaches a user when their store cannot be opened, and
        // the source chain is what makes the underlying SQLite message
        // reachable. Mutation testing showed both could be no-ops.
        let error = StoreError::from(rusqlite::Error::QueryReturnedNoRows);
        let message = error.to_string();
        assert!(message.contains("audit store"), "{message:?}");
        assert!(
            core::error::Error::source(&error).is_some(),
            "the SQLite cause was dropped"
        );
    }

    #[test]
    fn a_store_names_itself_when_printed() {
        // `Connection` is not Debug, so this impl is written by hand; an
        // empty one would make any enclosing struct's Debug useless.
        let store = Store::in_memory().expect("opens");
        assert_eq!(format!("{store:?}"), "Store");
    }

    // ---- the cache property ----------------------------------------------

    #[test]
    fn a_store_can_be_recreated_from_nothing() {
        // §3.1: deleting the file loses audit history and nothing else, so
        // opening a fresh store must always succeed without a repair path.
        for _ in 0..3 {
            let store = Store::in_memory().expect("opens");
            assert_eq!(store.tables().expect("tables").len(), 6);
        }
    }

    #[test]
    fn strict_tables_reject_a_wrong_typed_value() {
        // STRICT is on every table: without it SQLite would accept a string
        // in an INTEGER column, so a timestamp could be stored as text and
        // every comparison against it would silently misorder.
        let store = seeded();
        let result = store.connection().execute(
            "INSERT INTO usage (grant_id, count, runs, first_used, last_used)
               VALUES ('g1', 'lots', 1, 1, 1)",
            [],
        );
        assert!(result.is_err(), "STRICT did not reject a text count");
    }
}

#[cfg(test)]
mod on_disk {
    use super::*;

    /// WAL mode on a real file, which an in-memory database cannot show.
    ///
    /// §3.2 makes WAL a design decision rather than tuning: readers
    /// (`audit`, `explain`, `status`) must never block the broker, which is
    /// the sole writer. An in-memory store reports `memory` for
    /// `journal_mode`, so the claim is only testable on disk — and `17`
    /// verified it for `rusqlite` in the abstract, which is not the same as
    /// verifying our own open path sets it.
    #[test]
    fn a_file_backed_store_uses_wal() {
        let dir = std::env::temp_dir().join("rachna-store-wal-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("rachna.db");

        let store = Store::open(&path).expect("opens on disk");
        let mode: String = store
            .connection()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("pragma");
        assert_eq!(mode, "wal", "readers would block the broker");

        // And the sidecar files WAL implies exist, which is what makes the
        // mode observable to another process.
        store
            .connection()
            .execute_batch(
                "INSERT INTO config_revisions (id, ts, approved)
                   VALUES ('rev1', 1, 1);",
            )
            .expect("write");
        assert!(
            dir.join("rachna.db-wal").exists(),
            "no write-ahead log was created"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopening_an_existing_store_keeps_its_rows() {
        // The schema is applied on every open, so a second open must not
        // wipe anything — `IF NOT EXISTS` carries that, and losing audit
        // history on restart would be a silent data loss bug.
        let dir = std::env::temp_dir().join("rachna-store-reopen-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("rachna.db");

        let store = Store::open(&path).expect("first open");
        store
            .connection()
            .execute_batch(
                "INSERT INTO config_revisions (id, ts, approved)
                   VALUES ('rev1', 1, 1);",
            )
            .expect("write");
        drop(store);

        let reopened = Store::open(&path).expect("second open");
        let count: i64 = reopened
            .connection()
            .query_row("SELECT count(*) FROM config_revisions", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(count, 1, "reopening lost rows");

        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
