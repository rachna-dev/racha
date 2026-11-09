//! Which grant sets a human has approved (`00` §3.10c, §3.11a).
//!
//! This is the durable half of the reload gate. `reload.rs` decides whether a
//! change *needs* approval; this records whether it *has* one, so the answer
//! survives a restart — and so `rachna status` can say "waiting on you"
//! rather than silently doing nothing.
//!
//! # Keyed on the grant set, not the file
//!
//! The id is [`AccessSummary::fingerprint`], and this is the point of the
//! table rather than an implementation detail. `00` §3.10c:
//!
//! > Keyed on the **effective grant set**, not the file's hash. Reformatting,
//! > a comment, or a reordered list must not re-prompt, or the
//! > acknowledgement becomes noise people learn to bypass.
//!
//! `schema.sql` previously documented this column as *"content hash of
//! rachna.nix"*, which would have re-prompted on a comment — exactly the
//! noise that teaches people to alias `start --accept`.
//!
//! # Why a store and not a file
//!
//! `08` §4.1 lists an `approved` file in the project directory, and `08` §3.1
//! calls the database *"a cache, not truth"* — so putting an approval record
//! in it looks wrong. It is not, for one reason: **an approval is an
//! observation about what a human did, not a permission.** Deleting
//! `rachna.db` loses the record and the next widening change re-prompts,
//! which is the safe direction and exactly `08` §3.1's "rebuildable" test. A
//! permission that vanished on cache loss would be the dangerous direction,
//! and permissions remain only in `rachna.nix`.

use crate::store::{Store, StoreError};
use crate::summary::AccessSummary;

/// Whether a grant set may be applied without asking.
///
/// Three states, not two. `Unseen` and `Pending` are both "do not apply", but
/// they are different things to tell a user: one has never been shown, the
/// other was shown and not approved. `00` §3.3's rules apply — a report that
/// cannot distinguish them cannot say what to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// This grant set has never been recorded. The first-run gate applies.
    Unseen,
    /// Recorded, and not approved. Shown once already.
    Pending,
    /// Approved by a human. May be applied.
    Approved,
}

impl Approval {
    /// Whether a change to this grant set may be applied.
    ///
    /// Written as an explicit match rather than `== Approved`, so adding a
    /// state is a compile error here instead of silently counting as
    /// permitted.
    #[must_use]
    pub const fn permits_apply(self) -> bool {
        match self {
            Self::Approved => true,
            Self::Unseen | Self::Pending => false,
        }
    }
}

impl Store {
    /// The approval state of a grant set.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the table cannot be read.
    pub fn approval_of(&self, summary: &AccessSummary) -> Result<Approval, StoreError> {
        let fingerprint = summary.fingerprint();
        let mut statement = self
            .connection()
            .prepare("SELECT approved FROM config_revisions WHERE id = ?1")?;
        let mut rows = statement.query([&fingerprint])?;
        match rows.next()? {
            None => Ok(Approval::Unseen),
            Some(row) => {
                let approved: i64 = row.get(0)?;
                if approved == 1 {
                    Ok(Approval::Approved)
                } else {
                    Ok(Approval::Pending)
                }
            }
        }
    }

    /// Records that a grant set was shown and not approved.
    ///
    /// Idempotent, and deliberately **never downgrades an approval**: calling
    /// this on an already-approved set leaves it approved. Otherwise a second
    /// `start` would revoke an approval the user already gave, and the gate
    /// would ask again on every run — the noise `00` §3.10c warns about.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the row cannot be written.
    pub fn record_pending(
        &self,
        summary: &AccessSummary,
        now_millis: i64,
    ) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT INTO config_revisions (id, ts, approved) VALUES (?1, ?2, 0)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![summary.fingerprint(), now_millis],
        )?;
        Ok(())
    }

    /// Records a human's approval of a grant set.
    ///
    /// What `rachna start --accept` and the reload gate's approve step call.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the row cannot be written.
    /// Whether any grant set has ever been approved for this project.
    ///
    /// Distinct from [`Self::approval_of`], which asks about **one** grant
    /// set. The gate needs both: *is this set approved* decides whether to
    /// ask, and *has anything been approved here* decides what to SAY —
    /// "first run" is a lie to a user whose config has run here for months
    /// and just gained a host.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlite`] if the table cannot be read.
    pub fn has_approved_anything(&self) -> Result<bool, StoreError> {
        let mut statement = self
            .connection()
            .prepare("SELECT 1 FROM config_revisions WHERE approved = 1 LIMIT 1")?;
        let mut rows = statement.query([])?;
        Ok(rows.next()?.is_some())
    }

    pub fn approve(&self, summary: &AccessSummary, now_millis: i64) -> Result<(), StoreError> {
        self.connection().execute(
            "INSERT INTO config_revisions (id, ts, approved) VALUES (?1, ?2, 1)
             ON CONFLICT(id) DO UPDATE SET approved = 1, ts = ?2",
            rusqlite::params![summary.fingerprint(), now_millis],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Access;
    use crate::grant::{Endpoint, Grant};
    use crate::policy::{Profile, Tier};
    use std::path::PathBuf;

    fn summary(grants: &[Grant]) -> AccessSummary {
        AccessSummary::new(Tier::Allowlist, Profile::Development, grants)
    }

    fn network(host: &str) -> Grant {
        Grant::Network {
            endpoint: Endpoint::new(host, 443).expect("valid host"),
        }
    }

    #[test]
    fn only_an_approved_set_permits_applying() {
        // The whole decision, stated once against the type rather than
        // inferred from store round-trips. Written as a table over every
        // variant so adding one without deciding its answer is a visible
        // omission here rather than a silent `false`.
        assert!(Approval::Approved.permits_apply());
        assert!(!Approval::Pending.permits_apply());
        assert!(!Approval::Unseen.permits_apply());
    }

    #[test]
    fn an_unseen_grant_set_is_not_approved() {
        // The default must be "ask", not "allow". A store that answered
        // `Approved` for a set it had never seen would make the whole gate
        // vacuous on a fresh machine — which is every first run.
        let store = Store::in_memory().expect("store");
        let set = summary(&[network("github.com")]);
        assert_eq!(store.approval_of(&set).expect("read"), Approval::Unseen);
        assert!(!store.approval_of(&set).expect("read").permits_apply());
    }

    #[test]
    fn approving_a_set_permits_it_and_nothing_else() {
        let store = Store::in_memory().expect("store");
        let approved = summary(&[network("github.com")]);
        let other = summary(&[network("evil.test")]);

        store.approve(&approved, 1).expect("approve");

        assert_eq!(
            store.approval_of(&approved).expect("read"),
            Approval::Approved
        );
        // And it PERMITS. A mutation survivor found this missing: every
        // `permits_apply` assertion in this module was negative, so
        // `permits_apply -> false` was indistinguishable from the real
        // thing. A gate that always refuses looks safe and blocks every
        // approved start — the failure mode a user reports as "rachna will
        // not start", with nothing in the output to explain it.
        assert!(
            store.approval_of(&approved).expect("read").permits_apply(),
            "an approved grant set did not permit a start"
        );
        // The other set is NOT approved by association — the thing a
        // fingerprint keyed on the file's bytes would have got wrong if two
        // configs happened to share one.
        assert_eq!(store.approval_of(&other).expect("read"), Approval::Unseen);
        assert!(!store.approval_of(&other).expect("read").permits_apply());
    }

    #[test]
    fn project_history_is_separate_from_this_sets_approval() {
        // What the gate's WORDING rests on. `approval_of` answers about one
        // grant set, so it returns `Unseen` both for a genuine first run
        // and for a config that has run here for months and gained a host.
        // Telling the second user "this config has not run here before" is
        // a lie they can detect, and a gate they do not believe gets
        // bypassed.
        let store = Store::in_memory().expect("store");
        let first = summary(&[network("github.com")]);
        let widened = summary(&[network("github.com"), network("crates.io")]);

        assert!(
            !store.has_approved_anything().expect("read"),
            "a fresh store claimed a prior approval"
        );

        store.approve(&first, 1).expect("approve");

        // The widened set is unapproved — so the gate still ASKS …
        assert_eq!(store.approval_of(&widened).expect("read"), Approval::Unseen);
        // … and the project has history, so it must not say "first run".
        assert!(
            store.has_approved_anything().expect("read"),
            "a project with an approved set was reported as fresh"
        );
    }

    #[test]
    fn a_pending_record_alone_is_not_history() {
        // `Pending` means shown-and-not-approved. A user who saw a summary
        // and pressed `q` has approved nothing, so the next start is still
        // that config's first run here — saying otherwise would imply they
        // had once allowed it.
        let store = Store::in_memory().expect("store");
        let set = summary(&[network("github.com")]);
        store.record_pending(&set, 1).expect("record");
        assert_eq!(store.approval_of(&set).expect("read"), Approval::Pending);
        assert!(
            !store.has_approved_anything().expect("read"),
            "declining a summary was counted as having run here"
        );
    }

    #[test]
    fn a_shown_but_unapproved_set_is_distinguishable_from_an_unseen_one() {
        // Both block, but they are different things to tell a user: one has
        // never been shown, the other was shown and declined. `00` §3.3
        // requires a report to say what to do next, which needs the
        // distinction.
        let store = Store::in_memory().expect("store");
        let set = summary(&[network("github.com")]);

        assert_eq!(store.approval_of(&set).expect("read"), Approval::Unseen);
        store.record_pending(&set, 1).expect("record");
        assert_eq!(store.approval_of(&set).expect("read"), Approval::Pending);
        assert!(!store.approval_of(&set).expect("read").permits_apply());
    }

    #[test]
    fn recording_pending_never_revokes_an_approval() {
        // Otherwise a second `start` would revoke the approval the user just
        // gave, and the gate would ask on every run — `00` §3.10c's noise,
        // which is what teaches people to alias `--accept`.
        let store = Store::in_memory().expect("store");
        let set = summary(&[network("github.com")]);

        store.approve(&set, 1).expect("approve");
        store.record_pending(&set, 2).expect("record");
        assert_eq!(
            store.approval_of(&set).expect("read"),
            Approval::Approved,
            "a pending record downgraded an approval"
        );
    }

    #[test]
    fn approval_is_idempotent() {
        let store = Store::in_memory().expect("store");
        let set = summary(&[network("github.com")]);
        store.approve(&set, 1).expect("first");
        store.approve(&set, 2).expect("second");
        assert_eq!(store.approval_of(&set).expect("read"), Approval::Approved);
    }

    // ---- the property `00` §3.10c actually specifies ---------------------

    #[test]
    fn a_reformat_does_not_re_prompt_but_a_new_grant_does() {
        // THE requirement, and the one the schema's comment had wrong. It
        // said "content hash of rachna.nix", which would re-prompt on a
        // comment change — the exact noise `00` §3.10c forbids.
        //
        // A reorder stands in for a reformat here: both are file changes that
        // grant nothing new, and this layer never sees the file's bytes at
        // all, which is what makes the property hold.
        let store = Store::in_memory().expect("store");
        let one = summary(&[network("a.test"), network("b.test")]);
        let reordered = summary(&[network("b.test"), network("a.test")]);

        store.approve(&one, 1).expect("approve");
        assert_eq!(
            store.approval_of(&reordered).expect("read"),
            Approval::Approved,
            "a reordered list re-prompted"
        );

        // And adding one DOES re-trigger, which is `00` §3.11's
        // supply-chain case arriving for free.
        let widened = summary(&[network("a.test"), network("b.test"), network("c.test")]);
        assert_eq!(
            store.approval_of(&widened).expect("read"),
            Approval::Unseen,
            "a new grant was approved by association"
        );
    }

    #[test]
    fn narrowing_produces_an_unseen_set_rather_than_a_silent_pass() {
        // Worth pinning because it is the one case where "unseen" is the
        // right answer and "needs approval" is not. Removing a grant yields
        // a fingerprint nobody has approved — but `reload.rs` applies it
        // anyway, because `may_apply_now` keys on `diff.widens()`, not on
        // this. The two layers answer different questions and must not be
        // conflated: this one records history, that one decides policy.
        let store = Store::in_memory().expect("store");
        let wide = summary(&[network("a.test"), network("b.test")]);
        let narrow = summary(&[network("a.test")]);

        store.approve(&wide, 1).expect("approve");
        assert_eq!(
            store.approval_of(&narrow).expect("read"),
            Approval::Unseen,
            "narrowing must not inherit the wider set's approval"
        );
    }

    #[test]
    fn a_filesystem_access_change_is_a_different_grant_set() {
        // `read-only` to `read-write` is a widening that does not add a
        // grant, so a test using only network hosts would miss it. The
        // fingerprint has to notice.
        let store = Store::in_memory().expect("store");
        let read_only = summary(&[Grant::Filesystem {
            path: PathBuf::from("/workspace"),
            access: Access::ReadOnly,
        }]);
        let read_write = summary(&[Grant::Filesystem {
            path: PathBuf::from("/workspace"),
            access: Access::ReadWrite,
        }]);

        store.approve(&read_only, 1).expect("approve");
        assert_eq!(
            store.approval_of(&read_write).expect("read"),
            Approval::Unseen,
            "granting write inherited read-only's approval"
        );
    }

    #[test]
    fn an_axis_change_alone_is_a_different_grant_set() {
        // `tier = allowlist` to `open` adds no grant and permits every host.
        // `summary.rs`'s fingerprint includes the axes for this reason; the
        // assertion is here because this layer is what stores the answer.
        let store = Store::in_memory().expect("store");
        let grants = [network("a.test")];
        let allowlisted = AccessSummary::new(Tier::Allowlist, Profile::Development, &grants);
        let opened = AccessSummary::new(Tier::Open, Profile::Development, &grants);

        store.approve(&allowlisted, 1).expect("approve");
        assert_eq!(
            store.approval_of(&opened).expect("read"),
            Approval::Unseen,
            "opening the network inherited the allowlist's approval"
        );
    }
}
