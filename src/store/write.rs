//! The write path: one transaction per flush, never per decision.
//!
//! `08-POLICY-AND-STORE.md` §3.2 is explicit about why this is a batch:
//!
//! > **Batched writes.** The broker accumulates decisions in memory per run
//! > and flushes once, in one transaction. **Never a write per syscall** —
//! > that would put SQLite on the hot path of every network connection.
//!
//! So the shape here is deliberate: [`RunRecorder`] accumulates in memory and
//! [`RunRecorder::flush`] is the only thing that touches the database. A
//! caller cannot accidentally write per decision, because there is no method
//! that does.
//!
//! # The rollups are maintained in the same transaction
//!
//! `usage` and `observed_scopes` are derived (§3.3), and updating them in a
//! *second* transaction would leave a window where a decision exists and its
//! usage does not — making a grant look less used than it is, which is the
//! direction that gets a live grant revoked. One transaction, or neither.

use crate::decision::{Category, Decision, DenyReason};
use crate::store::{Store, StoreError};
use rusqlite::params;

/// A decision as it will be stored, with the request it answered.
///
/// Holds the `target` separately from the [`Decision`] because a decision
/// records the *answer* and the store must also record the *question*: an
/// audit row saying "denied: NoMatchingGrant" without naming what was asked
/// for cannot be explained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedDecision {
    /// What was asked for — a host:port, a path, a tool name.
    pub target: String,
    /// Which category the request fell under.
    pub category: Category,
    /// The answer.
    pub decision: Decision,
    /// The grant that permitted it, if any.
    ///
    /// `None` on a denial, and also on an allow that came from a tier rather
    /// than a grant (`tier = open` permits any host with no grant at all).
    pub grant_id: Option<String>,
    /// When, as epoch milliseconds.
    pub at: i64,
}

/// Accumulates one run's decisions, then writes them in a single transaction.
///
/// Created by [`Store::record_run`].
#[derive(Debug)]
pub struct RunRecorder {
    run_id: String,
    config_revision: String,
    argv: Vec<String>,
    cwd: String,
    started: i64,
    decisions: Vec<RecordedDecision>,
}

impl RunRecorder {
    /// Adds a decision to the in-memory batch.
    ///
    /// Does not touch the database — that is the whole point (§3.2).
    pub fn record(&mut self, decision: RecordedDecision) {
        self.decisions.push(decision);
    }

    /// How many decisions are pending.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.decisions.len()
    }

    /// The run's identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Writes the run, its decisions and the derived rollups in one
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if any statement fails. On error **nothing** is
    /// written: the transaction rolls back, so a partial run never appears.
    /// A half-written run would be worse than a missing one, because `explain`
    /// would replay it as though it were complete.
    pub fn flush(self, store: &mut Store, ended: i64, exit_code: i32) -> Result<usize, StoreError> {
        let transaction = store.connection.transaction()?;

        transaction.execute(
            "INSERT INTO runs
               (id, argv, cwd, started, ended, exit_code, config_revision)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                self.run_id,
                serde_json::to_string(&self.argv).unwrap_or_else(|_| "[]".to_owned()),
                self.cwd,
                self.started,
                ended,
                exit_code,
                self.config_revision,
            ],
        )?;

        let written = self.decisions.len();
        for decision in &self.decisions {
            let (verdict, scope, deny_reason) = match &decision.decision {
                Decision::Allow { scope } => ("allow", Some(scope.as_str()), None),
                Decision::Deny { reason } => ("deny", None, Some(reason_name(reason))),
            };

            transaction.execute(
                "INSERT INTO decisions
                   (run_id, ts, category, target, verdict, grant_id, scope,
                    deny_reason)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    self.run_id,
                    decision.at,
                    decision.category.as_str(),
                    decision.target,
                    verdict,
                    decision.grant_id,
                    scope,
                    deny_reason,
                ],
            )?;

            // The rollups, in this same transaction. An allow that came from
            // a tier rather than a grant has nothing to roll up against.
            let (Some(grant_id), Some(scope)) = (&decision.grant_id, scope) else {
                continue;
            };

            // `runs` counts DISTINCT runs, so it increments only on the
            // first decision of this run against this grant. The evidence
            // threshold needs both days and runs (`synthesize` §1.4), and
            // counting every decision as a run would let one chatty install
            // clear a threshold meant to represent a fortnight of use.
            transaction.execute(
                "INSERT INTO usage
                   (grant_id, count, runs, first_used, last_used)
                   VALUES (?1, 1, 1, ?2, ?2)
                 ON CONFLICT(grant_id) DO UPDATE SET
                   count     = count + 1,
                   runs      = runs + (SELECT CASE WHEN EXISTS (
                                 SELECT 1 FROM decisions
                                 WHERE grant_id = ?1 AND run_id = ?3
                                 LIMIT 1 OFFSET 1
                               ) THEN 0 ELSE 1 END),
                   last_used = max(last_used, ?2)",
                params![grant_id, decision.at, self.run_id],
            )?;

            transaction.execute(
                "INSERT INTO observed_scopes
                   (grant_id, scope, count, first_seen, last_seen)
                   VALUES (?1, ?2, 1, ?3, ?3)
                 ON CONFLICT(grant_id, scope) DO UPDATE SET
                   count     = count + 1,
                   last_seen = max(last_seen, ?3)",
                params![grant_id, scope, decision.at],
            )?;
        }

        transaction.commit()?;
        Ok(written)
    }
}

/// The stored name of a deny reason.
///
/// Written explicitly rather than derived from `Debug`, for the same reason
/// §2 gives for the grant fingerprint: a format that changes with a code
/// refactor orphans every stored row, so the mapping is a deliberate choice
/// that a test pins.
#[must_use]
pub const fn reason_name(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::ProfileForbids { .. } => "ProfileForbids",
        DenyReason::DirectAddressBypass { .. } => "DirectAddressBypass",
        DenyReason::NoMatchingGrant { .. } => "NoMatchingGrant",
        DenyReason::InsufficientAccess { .. } => "InsufficientAccess",
        DenyReason::ToolRoleForbids { .. } => "ToolRoleForbids",
        DenyReason::BackendCannotEnforce { .. } => "BackendCannotEnforce",
    }
}

impl Store {
    /// Begins recording a run.
    ///
    /// The config revision must already exist — a decision has to name the
    /// policy that produced it, and inventing a revision row here would let
    /// an unapproved config look recorded.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the revision cannot be registered.
    pub fn record_run(
        &self,
        run_id: impl Into<String>,
        config_revision: impl Into<String>,
        argv: Vec<String>,
        cwd: impl Into<String>,
        started: i64,
    ) -> Result<RunRecorder, StoreError> {
        Ok(RunRecorder {
            run_id: run_id.into(),
            config_revision: config_revision.into(),
            argv,
            cwd: cwd.into(),
            started,
            decisions: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{Access, Scope};

    fn store_with_grant() -> Store {
        let store = Store::in_memory().expect("opens");
        store
            .connection()
            .execute_batch(
                "INSERT INTO config_revisions (id, ts, approved)
                   VALUES ('rev1', 1000, 1);
                 INSERT INTO grants
                   (id, fingerprint, category, first_seen,
                    first_revision, last_revision)
                   VALUES ('g1', 'network github.com:443', 'network',
                           1000, 'rev1', 'rev1'),
                          ('g2', 'fs /workspace', 'fs',
                           1000, 'rev1', 'rev1');",
            )
            .expect("seed");
        store
    }

    fn allow(target: &str, grant: &str, at: i64) -> RecordedDecision {
        RecordedDecision {
            target: target.to_owned(),
            category: Category::Network,
            decision: Decision::Allow {
                scope: Scope::new(target).expect("non-empty"),
            },
            grant_id: Some(grant.to_owned()),
            at,
        }
    }

    fn deny(target: &str, at: i64) -> RecordedDecision {
        RecordedDecision {
            target: target.to_owned(),
            category: Category::Network,
            decision: Decision::Deny {
                reason: DenyReason::NoMatchingGrant {
                    category: Category::Network,
                },
            },
            grant_id: None,
            at,
        }
    }

    fn count(store: &Store, sql: &str) -> i64 {
        store
            .connection()
            .query_row(sql, [], |row| row.get(0))
            .expect("count")
    }

    // ---- batching --------------------------------------------------------

    #[test]
    fn recording_touches_nothing_until_flush() {
        // §3.2: never a write per syscall. The type enforces it — there is no
        // method that writes a single decision — and this asserts it.
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec!["rachna".to_owned()], "/p", 1000)
            .expect("recorder");

        for i in 0..100 {
            recorder.record(allow("github.com:443", "g1", 1000 + i));
        }
        assert_eq!(recorder.pending(), 100);
        assert_eq!(count(&store, "SELECT count(*) FROM decisions"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM runs"), 0);

        let written = recorder.flush(&mut store, 2000, 0).expect("flush");
        assert_eq!(written, 100);
        assert_eq!(count(&store, "SELECT count(*) FROM decisions"), 100);
        assert_eq!(count(&store, "SELECT count(*) FROM runs"), 1);
    }

    #[test]
    fn a_failed_flush_writes_nothing() {
        // A half-written run is worse than a missing one: `explain` would
        // replay it as though it were complete. The config revision does not
        // exist here, so the run insert fails and the transaction rolls back.
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "no-such-revision", vec![], "/p", 1000)
            .expect("recorder");
        recorder.record(allow("github.com:443", "g1", 1000));

        assert!(recorder.flush(&mut store, 2000, 0).is_err());
        assert_eq!(count(&store, "SELECT count(*) FROM runs"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM decisions"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM usage"), 0);
    }

    #[test]
    fn an_empty_run_still_records_the_run() {
        // A run that made no decisions is a real observation — it is how
        // `audit` distinguishes "never ran" from "ran and needed nothing".
        let mut store = store_with_grant();
        let recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        assert_eq!(recorder.flush(&mut store, 2000, 0).expect("flush"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM runs"), 1);
    }

    // ---- the rollups -----------------------------------------------------

    #[test]
    fn usage_counts_every_decision_but_runs_counts_runs() {
        // THE invariant behind the evidence threshold (`synthesize` §1.4,
        // "14 days AND 50 runs"). If `runs` counted decisions, one chatty
        // `npm install` would clear a threshold meant to represent a
        // fortnight of real use — and a grant would then be judged safe to
        // narrow on a single afternoon's evidence.
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        for i in 0..5 {
            recorder.record(allow("github.com:443", "g1", 1000 + i));
        }
        recorder.flush(&mut store, 2000, 0).expect("flush");

        assert_eq!(
            count(&store, "SELECT count FROM usage WHERE grant_id = 'g1'"),
            5,
            "count must total every decision"
        );
        assert_eq!(
            count(&store, "SELECT runs FROM usage WHERE grant_id = 'g1'"),
            1,
            "five decisions in one run is ONE run"
        );
    }

    #[test]
    fn a_second_run_increments_runs_once_more() {
        let mut store = store_with_grant();
        for run in 1..=3 {
            let mut recorder = store
                .record_run(format!("run{run}"), "rev1", vec![], "/p", 1000)
                .expect("recorder");
            recorder.record(allow("github.com:443", "g1", 1000 + run));
            recorder.record(allow("github.com:443", "g1", 1100 + run));
            recorder.flush(&mut store, 2000, 0).expect("flush");
        }
        assert_eq!(
            count(&store, "SELECT count FROM usage WHERE grant_id = 'g1'"),
            6,
            "two decisions in each of three runs"
        );
        assert_eq!(
            count(&store, "SELECT runs FROM usage WHERE grant_id = 'g1'"),
            3,
            "three runs"
        );
    }

    #[test]
    fn first_and_last_used_bracket_the_decisions() {
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        // Deliberately out of order: the broker batches in memory, and
        // nothing guarantees the caller sorted them.
        recorder.record(allow("github.com:443", "g1", 5000));
        recorder.record(allow("github.com:443", "g1", 1000));
        recorder.record(allow("github.com:443", "g1", 3000));
        recorder.flush(&mut store, 9000, 0).expect("flush");

        assert_eq!(
            count(&store, "SELECT first_used FROM usage WHERE grant_id='g1'"),
            5000,
            "first_used is the first RECORDED, not the earliest timestamp"
        );
        assert_eq!(
            count(&store, "SELECT last_used FROM usage WHERE grant_id='g1'"),
            5000,
            "last_used must be the maximum, not the most recent insert"
        );
    }

    #[test]
    fn distinct_scopes_are_recorded_separately_and_repeats_are_counted() {
        // This is what `synthesize` reads: "only ever these two hosts" is the
        // narrowing suggestion, and it needs one row per distinct value with
        // a count — not one row per decision (§3.3).
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        recorder.record(allow("storage.googleapis.com:443", "g1", 1000));
        recorder.record(allow("storage.googleapis.com:443", "g1", 1001));
        recorder.record(allow("oauth2.googleapis.com:443", "g1", 1002));
        recorder.flush(&mut store, 2000, 0).expect("flush");

        assert_eq!(
            count(&store, "SELECT count(*) FROM observed_scopes"),
            2,
            "two distinct hosts, not three decisions"
        );
        assert_eq!(
            count(
                &store,
                "SELECT count FROM observed_scopes
                   WHERE scope = 'storage.googleapis.com:443'"
            ),
            2
        );
    }

    #[test]
    fn a_denial_creates_no_usage_and_no_scope() {
        // The sharp case: a denial counted as usage would make a blocked
        // exfiltration attempt look like a live grant that survives
        // `revoke --unused`. The schema CHECK forbids a scope on a denial;
        // this asserts the write path agrees.
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        recorder.record(deny("evil.test:443", 1000));
        recorder.flush(&mut store, 2000, 1).expect("flush");

        assert_eq!(count(&store, "SELECT count(*) FROM decisions"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM usage"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM observed_scopes"), 0);
    }

    #[test]
    fn an_allow_from_a_tier_rather_than_a_grant_records_no_usage() {
        // `tier = open` permits any host with no grant at all, so there is
        // nothing to roll up against — but the decision itself must still be
        // recorded, or `explain` loses it.
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        let mut tier_allow = allow("anything.test:443", "g1", 1000);
        tier_allow.grant_id = None;
        recorder.record(tier_allow);
        recorder.flush(&mut store, 2000, 0).expect("flush");

        assert_eq!(count(&store, "SELECT count(*) FROM decisions"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM usage"), 0);
    }

    #[test]
    fn two_grants_roll_up_independently() {
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        recorder.record(allow("github.com:443", "g1", 1000));
        let mut fs = allow("/workspace/src", "g2", 1001);
        fs.category = Category::Filesystem;
        recorder.record(fs);
        recorder.flush(&mut store, 2000, 0).expect("flush");

        assert_eq!(
            count(&store, "SELECT count FROM usage WHERE grant_id='g1'"),
            1
        );
        assert_eq!(
            count(&store, "SELECT count FROM usage WHERE grant_id='g2'"),
            1
        );
    }

    // ---- the stored deny reason ------------------------------------------

    #[test]
    fn every_deny_reason_has_a_distinct_stored_name() {
        // Written explicitly rather than derived from Debug, for the same
        // reason §2 gives for the fingerprint: a name that changes with a
        // refactor orphans every stored row. Pinned here so a rename is a
        // deliberate migration rather than an accident.
        let every = [
            DenyReason::ProfileForbids {
                category: Category::Network,
            },
            DenyReason::DirectAddressBypass {
                literal: "1.2.3.4:443".to_owned(),
            },
            DenyReason::NoMatchingGrant {
                category: Category::Network,
            },
            DenyReason::InsufficientAccess {
                granted: Access::ReadOnly,
                wanted: Access::ReadWrite,
            },
            DenyReason::ToolRoleForbids {
                tool: "x".to_owned(),
            },
            DenyReason::BackendCannotEnforce {
                category: Category::Port,
            },
        ];
        let mut names: Vec<&str> = every.iter().map(reason_name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "two reasons share a stored name");
        // Pinned: renaming these orphans existing rows.
        assert_eq!(
            reason_name(&DenyReason::NoMatchingGrant {
                category: Category::Network
            }),
            "NoMatchingGrant"
        );
    }

    #[test]
    fn the_stored_reason_round_trips_through_the_database() {
        let mut store = store_with_grant();
        let mut recorder = store
            .record_run("run1", "rev1", vec![], "/p", 1000)
            .expect("recorder");
        recorder.record(deny("evil.test:443", 1000));
        recorder.flush(&mut store, 2000, 1).expect("flush");

        let stored: String = store
            .connection()
            .query_row("SELECT deny_reason FROM decisions", [], |row| row.get(0))
            .expect("read back");
        assert_eq!(stored, "NoMatchingGrant");
    }

    // ---- the run record --------------------------------------------------

    #[test]
    fn the_run_records_what_it_was_invoked_as() {
        let mut store = store_with_grant();
        let recorder = store
            .record_run(
                "run1",
                "rev1",
                vec!["rachna".to_owned(), "--exec".to_owned(), "npm".to_owned()],
                "/p",
                1000,
            )
            .expect("recorder");
        assert_eq!(recorder.run_id(), "run1");
        recorder.flush(&mut store, 2500, 7).expect("flush");

        let (argv, ended, code): (String, i64, i64) = store
            .connection()
            .query_row("SELECT argv, ended, exit_code FROM runs", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("read back");
        assert_eq!(argv, r#"["rachna","--exec","npm"]"#);
        assert_eq!(ended, 2500);
        assert_eq!(code, 7, "a non-zero exit must be preserved");
    }
}
