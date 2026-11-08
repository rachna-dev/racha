//! The audit queries: what `rachna audit` reports.
//!
//! `01-ARCHITECTURE.md` §7 step 6 names three findings — **unused,
//! over-broad, stale** — and `08-POLICY-AND-STORE.md` §3.3 requires each to
//! be a single statement, because `audit` and `status` must be instant.
//!
//! # Every finding carries its evidence
//!
//! `08` §1.4's second honesty rule is a *security* rule, not an ergonomic
//! one: §3.4 names the attack where malware forges silence so real grants
//! look unused and audit advises revoking them. So a finding never says bare
//! "unused" — it carries the observation behind it and the threshold that
//! observation was judged against, and a grant below the threshold produces
//! **no finding at all** rather than a weak one.
//!
//! That is why these return [`Finding`] values rather than printing: the
//! threshold has to travel with the claim to wherever it is displayed.

use crate::store::{Store, StoreError};
use crate::synthesize::{Evidence, Threshold};
use rusqlite::params;

/// Something `audit` found, with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A grant with no recorded use, where enough was observed to say so.
    ///
    /// Never emitted below the threshold: absence of evidence is not evidence
    /// of absence (§3.4).
    Unused {
        grant_id: String,
        fingerprint: String,
        /// How much observation supports the claim.
        evidence: Evidence,
        /// What it was judged against, so the finding can print it.
        threshold: Threshold,
    },
    /// A grant used only at values narrower than it permits.
    ///
    /// The headline narrowing case (§1.4): `*.googleapis.com:443` observed at
    /// two hosts becomes two exact rules.
    OverBroad {
        grant_id: String,
        fingerprint: String,
        /// The concrete values actually touched, which is what makes a
        /// suggestion possible at all (§1.3).
        observed: Vec<String>,
        evidence: Evidence,
        threshold: Threshold,
    },
}

impl Finding {
    /// The grant this concerns.
    #[must_use]
    pub fn grant_id(&self) -> &str {
        match self {
            Self::Unused { grant_id, .. } | Self::OverBroad { grant_id, .. } => grant_id,
        }
    }

    /// The evidence behind the claim.
    #[must_use]
    pub const fn evidence(&self) -> Evidence {
        match self {
            Self::Unused { evidence, .. } | Self::OverBroad { evidence, .. } => *evidence,
        }
    }
}

impl core::fmt::Display for Finding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unused {
                fingerprint,
                evidence,
                threshold,
                ..
            } => write!(
                f,
                "{fingerprint} — never used in {} days across {} runs \
                 (threshold: {} days and {} runs)",
                evidence.days, evidence.runs, threshold.days, threshold.runs
            ),
            Self::OverBroad {
                fingerprint,
                observed,
                evidence,
                threshold,
                ..
            } => write!(
                f,
                "{fingerprint} — only ever {} (in {} days across {} runs; \
                 threshold: {} days and {} runs)",
                observed.join(", "),
                evidence.days,
                evidence.runs,
                threshold.days,
                threshold.runs
            ),
        }
    }
}

impl Store {
    /// Grants with no recorded use, where enough was observed to say so.
    ///
    /// A left join rather than a `NOT IN`: the grant is the thing being
    /// reported, so it has to be the driving table, and `NOT IN` against a
    /// nullable column is the classic way to silently return nothing.
    ///
    /// `now` is passed in rather than read from a clock, keeping this
    /// testable and matching the engine's purity rule (§1.1).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the query fails.
    pub fn unused_grants(
        &self,
        now: i64,
        threshold: Threshold,
    ) -> Result<Vec<Finding>, StoreError> {
        // The evidence for an UNUSED grant is how long and how widely we have
        // been watching — which is the whole project's observation window,
        // not the grant's own history (it has none). Measuring it per grant
        // would make every newly-added grant instantly "unused".
        let evidence = self.observation_window(now)?;
        if !threshold.is_met_by(evidence) {
            return Ok(Vec::new());
        }

        let mut statement = self.connection.prepare(
            "SELECT g.id, g.fingerprint
               FROM grants g
               LEFT JOIN usage u ON u.grant_id = g.id
              WHERE u.grant_id IS NULL
              ORDER BY g.id",
        )?;
        let findings = statement
            .query_map([], |row| {
                Ok(Finding::Unused {
                    grant_id: row.get(0)?,
                    fingerprint: row.get(1)?,
                    evidence,
                    threshold,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(findings)
    }

    /// Grants whose observed values are narrower than what they permit.
    ///
    /// "Narrower" is decided by the caller, not here: this reports what was
    /// *observed*, and `synthesize` decides whether a tighter rule set
    /// covers it. Keeping the judgement there means there is one definition
    /// of "narrowest covering rule" rather than two that can disagree.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the query fails.
    pub fn over_broad_grants(
        &self,
        threshold: Threshold,
        max_scopes: usize,
    ) -> Result<Vec<Finding>, StoreError> {
        // One statement, per §3.3. The per-grant evidence is in `usage`, and
        // the scopes come from `observed_scopes` — which is exactly why §3.3
        // keeps them in separate tables: folding them together would make
        // this a table scan.
        let mut statement = self.connection.prepare(
            "SELECT g.id,
                    g.fingerprint,
                    u.runs,
                    u.first_used,
                    u.last_used,
                    group_concat(s.scope, char(10))
               FROM grants g
               JOIN usage u           ON u.grant_id = g.id
               JOIN observed_scopes s ON s.grant_id = g.id
              GROUP BY g.id
             HAVING count(s.scope) <= ?1
              ORDER BY g.id",
        )?;

        let rows = statement
            .query_map(params![max_scopes as i64], |row| {
                let runs: i64 = row.get(2)?;
                let first: i64 = row.get(3)?;
                let last: i64 = row.get(4)?;
                let scopes: String = row.get(5)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    runs,
                    first,
                    last,
                    scopes,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let findings = rows
            .into_iter()
            .filter_map(|(id, fingerprint, runs, first, last, scopes)| {
                let evidence = Evidence {
                    days: days_between(first, last),
                    runs: u32::try_from(runs).unwrap_or(u32::MAX),
                };
                // Below the threshold there is no finding, not a weak one.
                // A grant used twice this afternoon says nothing about what
                // it needs next week.
                threshold.is_met_by(evidence).then(|| Finding::OverBroad {
                    grant_id: id,
                    fingerprint,
                    observed: scopes.lines().map(str::to_owned).collect(),
                    evidence,
                    threshold,
                })
            })
            .collect();
        Ok(findings)
    }

    /// How long and how widely this project has been observed.
    ///
    /// The denominator for an unused-grant claim.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the query fails.
    pub fn observation_window(&self, now: i64) -> Result<Evidence, StoreError> {
        let (earliest, runs): (Option<i64>, i64) =
            self.connection
                .query_row("SELECT min(started), count(*) FROM runs", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
        Ok(Evidence {
            days: earliest.map_or(0, |earliest| days_between(earliest, now)),
            runs: u32::try_from(runs).unwrap_or(u32::MAX),
        })
    }
}

/// Whole days between two epoch-millisecond timestamps.
///
/// Saturating rather than wrapping: a clock that went backwards must yield
/// zero days — which fails the threshold and suppresses the finding — rather
/// than a huge span that would make every grant look safely revocable.
#[must_use]
pub const fn days_between(from: i64, to: i64) -> u32 {
    const DAY: i64 = 24 * 60 * 60 * 1000;
    if to <= from {
        return 0;
    }
    // `saturating_sub`, because `to - from` overflows across i64::MIN..MAX
    // and a panic here would take the broker down on a bad clock.
    let days = to.saturating_sub(from) / DAY;
    // Clamped before the cast rather than converted with `TryFrom`, which is
    // not const-stable yet. The comparison is what makes the truncation
    // provably impossible, so the `as` is safe rather than merely lint-quiet.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the branch above proves 0 <= days <= u32::MAX"
    )]
    if days > u32::MAX as i64 {
        u32::MAX
    } else {
        days as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{Category, Decision, Scope};
    use crate::store::write::RecordedDecision;

    const DAY: i64 = 24 * 60 * 60 * 1000;

    /// A store with two grants: one used, one never used.
    fn store_with_history(days: i64, runs: i64) -> Store {
        let mut store = Store::in_memory().expect("opens");
        store
            .connection()
            .execute_batch(
                "INSERT INTO config_revisions (id, ts, approved)
                   VALUES ('rev1', 0, 1);
                 INSERT INTO grants
                   (id, fingerprint, category, first_seen,
                    first_revision, last_revision)
                   VALUES ('used', 'network *.googleapis.com:443', 'network',
                           0, 'rev1', 'rev1'),
                          ('never', 'network legacy.example:443', 'network',
                           0, 'rev1', 'rev1');",
            )
            .expect("seed");

        for run in 0..runs {
            // Spread the runs across the window so `days` is real.
            let at = run * (days * DAY).max(1) / runs.max(1);
            let mut recorder = store
                .record_run(format!("run{run}"), "rev1", vec![], "/p", at)
                .expect("recorder");
            for host in ["storage.googleapis.com:443", "oauth2.googleapis.com:443"] {
                recorder.record(RecordedDecision {
                    target: host.to_owned(),
                    category: Category::Network,
                    decision: Decision::Allow {
                        scope: Scope::new(host).expect("non-empty"),
                    },
                    grant_id: Some("used".to_owned()),
                    at,
                });
            }
            recorder.flush(&mut store, at + 1, 0).expect("flush");
        }
        store
    }

    // ---- unused ----------------------------------------------------------

    #[test]
    fn an_unused_grant_is_reported_once_there_is_enough_evidence() {
        let store = store_with_history(30, 100);
        let findings = store
            .unused_grants(30 * DAY, Threshold::DEFAULT)
            .expect("query");
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].grant_id(), "never");
    }

    #[test]
    fn a_used_grant_is_never_reported_as_unused() {
        let store = store_with_history(30, 100);
        let findings = store
            .unused_grants(30 * DAY, Threshold::DEFAULT)
            .expect("query");
        assert!(
            findings.iter().all(|f| f.grant_id() != "used"),
            "a grant with recorded usage was called unused"
        );
    }

    #[test]
    fn thin_evidence_reports_nothing_rather_than_a_weak_finding() {
        // THE §3.4 defence. Malware can forge silence so real grants look
        // unused and audit advises revoking them. Three days and seven runs
        // says nothing about a weekly job, so there is NO finding — not a
        // hedged one.
        let store = store_with_history(3, 7);
        let findings = store
            .unused_grants(3 * DAY, Threshold::DEFAULT)
            .expect("query");
        assert!(
            findings.is_empty(),
            "advised revoking on 3 days of evidence: {findings:#?}"
        );
    }

    #[test]
    fn both_halves_of_the_threshold_gate_an_unused_finding() {
        // Either alone is defeatable: 100 runs in one day says nothing about
        // a weekly job, and 30 days with 2 runs says nothing at all.
        let runs_only = store_with_history(1, 100);
        assert!(runs_only
            .unused_grants(DAY, Threshold::DEFAULT)
            .expect("query")
            .is_empty());

        let days_only = store_with_history(30, 2);
        assert!(days_only
            .unused_grants(30 * DAY, Threshold::DEFAULT)
            .expect("query")
            .is_empty());
    }

    #[test]
    fn an_unused_finding_carries_the_threshold_it_was_judged_against() {
        // §1.4: "unused in 31 days across 1,284 runs" is defensible; bare
        // "unused" is not. The threshold has to travel with the claim.
        let store = store_with_history(30, 100);
        let findings = store
            .unused_grants(30 * DAY, Threshold::DEFAULT)
            .expect("query");
        let rendered = findings[0].to_string();
        assert!(rendered.contains("30 days"), "{rendered}");
        assert!(rendered.contains("100 runs"), "{rendered}");
        assert!(
            rendered.contains("threshold: 14 days and 50 runs"),
            "{rendered}"
        );
    }

    #[test]
    fn the_observation_window_is_the_project_not_the_grant() {
        // A newly added grant has no history of its own. Measuring evidence
        // per grant would make every new grant instantly "unused" — the
        // wrong answer, and the one that revokes a grant the day it lands.
        let store = store_with_history(30, 100);
        let window = store.observation_window(30 * DAY).expect("window");
        assert_eq!(window.days, 30);
        assert_eq!(window.runs, 100);
    }

    #[test]
    fn an_empty_store_reports_nothing() {
        let store = Store::in_memory().expect("opens");
        assert!(store
            .unused_grants(90 * DAY, Threshold::DEFAULT)
            .expect("query")
            .is_empty());
        assert_eq!(
            store.observation_window(0).expect("window"),
            Evidence { days: 0, runs: 0 }
        );
    }

    // ---- over-broad ------------------------------------------------------

    #[test]
    fn a_wildcard_used_at_two_hosts_is_reported_with_those_hosts() {
        // The headline narrowing case (§1.4), and it needs the concrete
        // values: "used 412 times" suggests nothing, "only ever these two"
        // suggests two exact rules.
        let store = store_with_history(30, 100);
        let findings = store
            .over_broad_grants(Threshold::DEFAULT, 10)
            .expect("query");
        assert_eq!(findings.len(), 1, "{findings:#?}");
        match &findings[0] {
            Finding::OverBroad { observed, .. } => {
                let mut observed = observed.clone();
                observed.sort();
                assert_eq!(
                    observed,
                    ["oauth2.googleapis.com:443", "storage.googleapis.com:443"]
                );
            }
            other => panic!("expected OverBroad, got {other:?}"),
        }
    }

    #[test]
    fn a_grant_with_too_many_scopes_is_not_reported() {
        // A grant observed at hundreds of hosts is being used as intended;
        // listing them all would be noise, not a suggestion. The cap is the
        // caller's, because what counts as "narrow enough to suggest" is a
        // presentation decision.
        let store = store_with_history(30, 100);
        let findings = store
            .over_broad_grants(Threshold::DEFAULT, 1)
            .expect("query");
        assert!(findings.is_empty(), "two scopes exceeded a cap of one");
    }

    #[test]
    fn an_over_broad_finding_also_respects_the_threshold() {
        // Narrowing on thin evidence is the same mistake as revoking on it:
        // a grant used twice this afternoon says nothing about next week.
        let store = store_with_history(1, 3);
        assert!(store
            .over_broad_grants(Threshold::DEFAULT, 10)
            .expect("query")
            .is_empty());
    }

    #[test]
    fn an_over_broad_finding_renders_the_observed_values() {
        let store = store_with_history(30, 100);
        let findings = store
            .over_broad_grants(Threshold::DEFAULT, 10)
            .expect("query");
        let rendered = findings[0].to_string();
        assert!(rendered.contains("googleapis.com:443"), "{rendered}");
        assert!(rendered.contains("threshold:"), "{rendered}");
    }

    #[test]
    fn a_never_used_grant_is_not_also_reported_as_over_broad() {
        // It has no observed scopes, so there is nothing to narrow TO. The
        // join must exclude it, or audit would suggest narrowing a grant to
        // the empty set — which is a revocation wearing a disguise.
        let store = store_with_history(30, 100);
        let findings = store
            .over_broad_grants(Threshold::DEFAULT, 10)
            .expect("query");
        assert!(findings.iter().all(|f| f.grant_id() != "never"));
    }

    // ---- the day arithmetic ----------------------------------------------

    #[test]
    fn days_between_is_evaluable_at_compile_time() {
        // `const` is not decoration here: it is the compiler proving the
        // function has no hidden allocation, panic path or I/O, which is the
        // same purity the policy engine relies on (§1.1).
        //
        // A first draft dropped `const` because `TryFrom` is not const-stable.
        // That was the wrong fix — only the conversion needed replacing, with
        // an explicit clamp. This `const` binding fails to COMPILE if anyone
        // drops it again.
        const THIRTY_DAYS: u32 = days_between(0, 30 * DAY);
        assert_eq!(THIRTY_DAYS, 30);
    }

    #[test]
    fn days_between_counts_whole_days() {
        assert_eq!(days_between(0, 0), 0);
        assert_eq!(days_between(0, DAY - 1), 0, "not yet a day");
        assert_eq!(days_between(0, DAY), 1);
        assert_eq!(days_between(0, 30 * DAY), 30);
    }

    #[test]
    fn a_backwards_clock_yields_zero_days_not_a_huge_span() {
        // Saturating on purpose: a huge span would clear the threshold and
        // make every grant look safely revocable. Zero fails the threshold
        // and suppresses the finding, which is the safe direction.
        assert_eq!(days_between(30 * DAY, 0), 0);
        assert_eq!(days_between(i64::MAX, i64::MIN), 0);
    }

    #[test]
    fn an_absurd_span_saturates_rather_than_wrapping() {
        assert_eq!(days_between(i64::MIN, i64::MAX), u32::MAX);
    }
}
