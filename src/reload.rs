//! Classifying a config change: what can be applied live, and what cannot.
//!
//! `00-PRODUCT.md` §3.5 is the specification, and the point is that **Rachna
//! must say which it did**:
//!
//! | Change | Action |
//! |---|---|
//! | network, ports, mounts, resource limits | **live** — recompile and swap |
//! | service config | **restart that unit** |
//! | packages, guest version, kernel params | **rebuild + VM restart** |
//!
//! # The acceptance test is a negative
//!
//! `01-ARCHITECTURE.md` §7 step 9: *a broken config provably cannot disturb a
//! running env.* So the central type here is not the diff — it is
//! [`Reload::Rejected`], and the invariant is that a rejected reload yields
//! **no** change of any kind. `18` §2 states it: an evaluation error must
//! keep the last-good spec and surface the Nix error verbatim.
//!
//! # Why classification is pure
//!
//! It takes two policies and returns what to do. No watcher, no VM, no clock.
//! §5b.4 forbids concurrent policy evaluation and application — "the file
//! watcher may fire twice; applying two evaluations concurrently could leave
//! the live policy neither old nor new" — and a pure classifier makes the
//! actor's job a single `latest wins` decision rather than a merge.

use crate::config::ConfigErrors;
use crate::decide::Policy;
use crate::decision::Category;
use crate::grant::Grant;
use crate::summary::{AccessSummary, GrantDiff};

/// What a config change requires.
///
/// Ordered least to most disruptive, and that order is meaningful: a change
/// touching several categories takes the **most** disruptive action, which
/// [`Ord`] gives for free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disruption {
    /// Nothing to do: the effective config is unchanged.
    ///
    /// Distinct from `Live` with an empty diff, because a reformat should
    /// produce no output at all rather than "applied 0 changes".
    None,
    /// Recompile the policy and swap it. Sub-100ms, no guest involvement.
    Live,
    /// Restart one service inside the guest.
    RestartService,
    /// Rebuild the closure and restart the VM.
    Rebuild,
}

impl Disruption {
    /// Every level, least disruptive first.
    pub const ALL: [Self; 4] = [Self::None, Self::Live, Self::RestartService, Self::Rebuild];

    /// The word shown to a user.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no change",
            Self::Live => "live",
            Self::RestartService => "restart service",
            Self::Rebuild => "rebuild + restart",
        }
    }

    /// Whether applying this interrupts work in the guest.
    ///
    /// The question a user actually has. `Live` does not; the other two do,
    /// and saying so before acting is the difference between a tool that
    /// reloads and one that surprises you.
    #[must_use]
    pub const fn interrupts_work(self) -> bool {
        matches!(self, Self::RestartService | Self::Rebuild)
    }
}

/// The outcome of a config change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    /// The new config is valid; here is what to do.
    Accepted {
        /// How disruptive the change is.
        disruption: Disruption,
        /// What changed, for the report.
        diff: GrantDiff,
        /// Whether the grant set widened, so the user must re-acknowledge
        /// (`00` §3.10c).
        needs_acknowledgement: bool,
    },
    /// The new config is broken. **Nothing changed.**
    ///
    /// Carries the errors so they can be rendered against the file
    /// (`render.rs`), and deliberately carries nothing else: there is no
    /// partial policy to apply, no "mostly valid" state. `18` §2 requires the
    /// last-good spec to survive untouched.
    Rejected { errors: ConfigErrors },
}

impl Reload {
    /// Whether the running environment should change at all.
    ///
    /// The invariant step 9 exists to prove: `false` for every rejection, and
    /// for an accepted change that turns out to be a no-op.
    #[must_use]
    pub const fn changes_anything(&self) -> bool {
        match self {
            Self::Accepted { disruption, .. } => !matches!(disruption, Disruption::None),
            // A broken config provably cannot disturb a running env.
            Self::Rejected { .. } => false,
        }
    }

    /// How disruptive this is, or `None` for a rejection.
    #[must_use]
    pub const fn disruption(&self) -> Option<Disruption> {
        match self {
            Self::Accepted { disruption, .. } => Some(*disruption),
            Self::Rejected { .. } => None,
        }
    }
}

/// Classifies a change from `current` to `proposed`.
///
/// Both are already-evaluated policies: evaluation and parsing happen before
/// this, and their failure is what produces [`Reload::Rejected`] via
/// [`reject`].
#[must_use]
pub fn classify(current: &Policy, proposed: &Policy) -> Reload {
    let before = AccessSummary::new(current.tier, current.profile, &current.grants);
    let after = AccessSummary::new(proposed.tier, proposed.profile, &proposed.grants);
    let diff = GrantDiff::between(&before, &after);

    // Change is detected by FINGERPRINT, not by the diff being non-empty.
    //
    // Found by a test: tightening `profile` from `online` to `sealed` with no
    // grants declared produces an EMPTY diff — the diff lists granted entries,
    // and a forbidden category renders as a `none (…)` marker that
    // `AccessSummary::entries` deliberately excludes (it is an absence, not a
    // grant). So there is nothing on either side to differ, while the
    // fingerprint correctly changes because it includes the axes.
    //
    // Using the diff here would have classified "seal this environment" as
    // no change at all — the most dangerous direction, since the user would
    // believe they had tightened something and nothing would have happened.
    let changed = before.fingerprint() != after.fingerprint();

    // The most disruptive category wins, which `Ord` gives directly. A change
    // touching both network and packages is a rebuild: doing the live half
    // first would apply a policy to a guest about to be replaced.
    let disruption = if changed {
        changed_categories(current, proposed)
            .into_iter()
            .map(disruption_for)
            .max()
            .unwrap_or(Disruption::Live)
    } else {
        Disruption::None
    };

    Reload::Accepted {
        disruption,
        // `widens()` rather than any change: a narrowing edit changes the
        // fingerprint but gives the user nothing new to review (`00` §3.10c).
        needs_acknowledgement: diff.widens(),
        diff,
    }
}

/// A rejection, for when evaluation or parsing failed.
///
/// A separate constructor rather than a branch inside [`classify`], because
/// at that point there is no proposed policy to compare — the config never
/// became one. Pretending otherwise would mean inventing a `Policy` to
/// classify against.
#[must_use]
pub const fn reject(errors: ConfigErrors) -> Reload {
    Reload::Rejected { errors }
}

/// Which categories differ between two policies.
fn changed_categories(current: &Policy, proposed: &Policy) -> Vec<Category> {
    let mut changed = Vec::new();

    // The axes are policy-level and always live: tier governs network, and
    // profile gates categories. Neither touches the closure.
    if current.tier != proposed.tier || current.profile != proposed.profile {
        changed.push(Category::Network);
    }

    for category in Category::ALL {
        let mine = grants_in(current, category);
        let theirs = grants_in(proposed, category);
        if mine != theirs {
            changed.push(category);
        }
    }
    changed
}

fn grants_in(policy: &Policy, category: Category) -> Vec<&Grant> {
    let mut grants: Vec<&Grant> = policy
        .grants
        .iter()
        .filter(|grant| grant.category() == category)
        .collect();
    // Sorted so a reordered config is not a change (`00` §3.10c's rule,
    // applied to reload rather than to the summary).
    grants.sort_by_key(|grant| format!("{grant:?}"));
    grants
}

/// What a change in one category requires.
///
/// Mapped from `00` §3.5's table. The notable entry is [`Category::Tool`]:
/// exposing a tool means putting it on the guest's PATH, which `20` §4.2b
/// derives from declared packages — so a tool change implies a package change
/// and therefore a rebuild.
const fn disruption_for(category: Category) -> Disruption {
    match category {
        // Policy-only: recompile and swap.
        Category::Network | Category::Filesystem | Category::Port | Category::Secret => {
            Disruption::Live
        }
        // A tool comes from a package, so exposing one changes the closure.
        Category::Tool => Disruption::Rebuild,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, ConfigError};
    use crate::decide::Capabilities;
    use crate::decision::Access;
    use crate::grant::{endpoint, ToolKind};
    use crate::policy::{Profile, Tier};
    use std::path::PathBuf;

    fn policy(grants: Vec<Grant>) -> Policy {
        Policy {
            tier: Tier::Allowlist,
            profile: Profile::Online,
            grants,
            capabilities: Capabilities::all(),
        }
    }

    fn network(host: &str) -> Grant {
        Grant::Network {
            endpoint: endpoint(host, 443),
        }
    }

    // ---- step 9's acceptance test: the negative --------------------------

    #[test]
    fn a_broken_config_changes_nothing() {
        // 01 §7 step 9: "a broken config provably cannot disturb a running
        // env". The rejection carries errors and NOTHING else — there is no
        // partial policy, no "mostly valid" state. 18 §2 requires the
        // last-good spec to survive untouched.
        let errors =
            config::parse(r#"{ "tier": "nope" }"#, Capabilities::all()).expect_err("invalid");
        let reload = reject(errors);

        assert!(!reload.changes_anything());
        assert_eq!(reload.disruption(), None);
        match reload {
            Reload::Rejected { errors } => assert!(!errors.all().is_empty()),
            Reload::Accepted { .. } => panic!("a broken config was accepted"),
        }
    }

    #[test]
    fn every_kind_of_config_error_still_changes_nothing() {
        // Asserted over error kinds rather than one example: the invariant is
        // about rejection itself, not about which mistake caused it.
        let broken = [
            r#"[1,2,3]"#,
            r#"{ "tier": "nope", "profile": "development" }"#,
            r#"{ "profile": "development" }"#,
            r#"{ "tier": "none", "profile": "development", "netwrk": {} }"#,
            r#"{ "tier": "none", "profile": "development",
                 "network": { "allow": [ "no-port" ] } }"#,
        ];
        for json in broken {
            let errors = config::parse(json, Capabilities::all()).expect_err(json);
            assert!(
                !reject(errors).changes_anything(),
                "a broken config proposed a change: {json}"
            );
        }
    }

    #[test]
    fn a_rejection_keeps_the_errors_for_rendering() {
        // The errors have to survive, or the user gets "config invalid" with
        // no caret and no line — which 22 §4.2 exists to prevent.
        let errors = config::parse(
            r#"{ "tier": "none", "profile": "development", "netwrk": {} }"#,
            Capabilities::all(),
        )
        .expect_err("invalid");
        match reject(errors) {
            Reload::Rejected { errors } => {
                assert!(errors.all().contains(&ConfigError::UnknownKey {
                    at: "netwrk".to_owned()
                }));
            }
            Reload::Accepted { .. } => panic!("accepted"),
        }
    }

    // ---- the three disruption classes ------------------------------------

    #[test]
    fn adding_a_host_is_live() {
        // 00 §3.5: network allowlist changes recompile the policy and swap.
        // No guest involvement, so work in flight is not interrupted.
        let before = policy(vec![network("a.test")]);
        let after = policy(vec![network("a.test"), network("b.test")]);
        let reload = classify(&before, &after);
        assert_eq!(reload.disruption(), Some(Disruption::Live));
        assert!(reload.changes_anything());
        assert!(!Disruption::Live.interrupts_work());
    }

    #[test]
    fn changing_a_mount_or_port_or_secret_is_also_live() {
        for (before, after) in [
            (
                vec![Grant::Filesystem {
                    path: PathBuf::from("/w"),
                    access: Access::ReadOnly,
                }],
                vec![Grant::Filesystem {
                    path: PathBuf::from("/w"),
                    access: Access::ReadWrite,
                }],
            ),
            (
                vec![],
                vec![Grant::Port {
                    guest: 3000,
                    host: 3000,
                }],
            ),
            (
                vec![],
                vec![Grant::Secret {
                    name: "aws".to_owned(),
                }],
            ),
        ] {
            assert_eq!(
                classify(&policy(before), &policy(after)).disruption(),
                Some(Disruption::Live)
            );
        }
    }

    #[test]
    fn exposing_a_tool_requires_a_rebuild() {
        // A tool comes from a declared package (20 §4.2b), so exposing one
        // changes the Nix closure — which 00 §3.5 classifies as rebuild +
        // restart, not live.
        let after = policy(vec![Grant::Tool {
            name: "rust-analyzer".to_owned(),
            kind: ToolKind::Lsp,
            network: false,
        }]);
        let reload = classify(&policy(vec![]), &after);
        assert_eq!(reload.disruption(), Some(Disruption::Rebuild));
        assert!(Disruption::Rebuild.interrupts_work());
    }

    #[test]
    fn the_most_disruptive_category_wins() {
        // A change touching both network and tools is a REBUILD. Applying
        // the live half first would push a policy into a guest that is about
        // to be replaced — work done twice, and a window where the running
        // guest has permissions the new one will not.
        let after = policy(vec![
            network("new.test"),
            Grant::Tool {
                name: "gopls".to_owned(),
                kind: ToolKind::Lsp,
                network: false,
            },
        ]);
        assert_eq!(
            classify(&policy(vec![network("a.test")]), &after).disruption(),
            Some(Disruption::Rebuild)
        );
    }

    #[test]
    fn the_disruption_order_is_least_to_most() {
        // `max()` picks the winner above, so the declaration order IS the
        // severity order. Pinned, because a reorder would silently make a
        // rebuild classify as live.
        assert!(Disruption::None < Disruption::Live);
        assert!(Disruption::Live < Disruption::RestartService);
        assert!(Disruption::RestartService < Disruption::Rebuild);
        let mut sorted = Disruption::ALL;
        sorted.sort_unstable();
        assert_eq!(sorted, Disruption::ALL);
    }

    // ---- no-ops ----------------------------------------------------------

    #[test]
    fn an_identical_config_is_no_change_rather_than_an_empty_live_reload() {
        // A reformat should produce no output at all, not "applied 0
        // changes" — which is the difference between a watcher that is quiet
        // and one that is noise people learn to ignore.
        let same = policy(vec![network("a.test")]);
        let reload = classify(&same, &same);
        assert_eq!(reload.disruption(), Some(Disruption::None));
        assert!(!reload.changes_anything());
    }

    #[test]
    fn a_reordered_config_is_no_change() {
        let before = policy(vec![network("a.test"), network("b.test")]);
        let after = policy(vec![network("b.test"), network("a.test")]);
        assert_eq!(
            classify(&before, &after).disruption(),
            Some(Disruption::None),
            "a reorder was treated as a change"
        );
    }

    // ---- acknowledgement -------------------------------------------------

    #[test]
    fn a_widening_change_needs_acknowledgement() {
        // 00 §3.10c: a git pull that adds a grant must re-gate.
        let after = policy(vec![network("a.test"), network("evil.test")]);
        match classify(&policy(vec![network("a.test")]), &after) {
            Reload::Accepted {
                needs_acknowledgement,
                ..
            } => assert!(needs_acknowledgement),
            Reload::Rejected { .. } => panic!("rejected"),
        }
    }

    #[test]
    fn a_narrowing_change_does_not_need_acknowledgement() {
        // It changes the fingerprint but gives the user nothing NEW to
        // review — and re-gating on every narrowing would train people to
        // pass --accept reflexively.
        let before = policy(vec![network("a.test"), network("b.test")]);
        let after = policy(vec![network("a.test")]);
        match classify(&before, &after) {
            Reload::Accepted {
                needs_acknowledgement,
                disruption,
                ..
            } => {
                assert!(!needs_acknowledgement);
                assert_eq!(disruption, Disruption::Live, "it is still a change");
            }
            Reload::Rejected { .. } => panic!("rejected"),
        }
    }

    #[test]
    fn a_no_op_needs_no_acknowledgement() {
        let same = policy(vec![network("a.test")]);
        match classify(&same, &same) {
            Reload::Accepted {
                needs_acknowledgement,
                ..
            } => assert!(!needs_acknowledgement),
            Reload::Rejected { .. } => panic!("rejected"),
        }
    }

    // ---- the axes --------------------------------------------------------

    #[test]
    fn changing_a_tier_or_profile_is_live() {
        // Both are policy-level: tier governs network, profile gates
        // categories, and neither touches the closure.
        let before = policy(vec![]);
        let mut wider_tier = policy(vec![]);
        wider_tier.tier = Tier::Open;
        assert_eq!(
            classify(&before, &wider_tier).disruption(),
            Some(Disruption::Live)
        );

        let mut sealed = policy(vec![]);
        sealed.profile = Profile::Sealed;
        assert_eq!(
            classify(&before, &sealed).disruption(),
            Some(Disruption::Live)
        );
    }

    #[test]
    fn an_axis_change_alongside_a_tool_change_is_still_a_rebuild() {
        // Mutation testing found the axis comparison untested: every other
        // axis test changes an axis with NO grants, so `changed_categories`
        // returns an empty list either way and `unwrap_or(Live)` masks what
        // the comparison concluded.
        //
        // Here the axis change must contribute Network (live) while the tool
        // change contributes Rebuild. If the axis comparison were inverted,
        // Network would be missing — which happens not to change this
        // verdict, so the next test is the one that distinguishes it.
        let mut proposed = policy(vec![Grant::Tool {
            name: "gopls".to_owned(),
            kind: ToolKind::Lsp,
            network: false,
        }]);
        proposed.tier = Tier::Open;
        assert_eq!(
            classify(&policy(vec![]), &proposed).disruption(),
            Some(Disruption::Rebuild)
        );
    }

    #[test]
    fn an_axis_change_alone_with_grants_present_is_live_via_the_axis_check() {
        // THE test that pins the axis comparison. The grants are IDENTICAL on
        // both sides, so `changed_categories` finds nothing from the grant
        // loop — the only way to a non-empty list is the axis check itself.
        //
        // With the comparison inverted the list is empty, `unwrap_or(Live)`
        // still yields Live, and the verdict is unchanged... so the
        // assertion has to be on the CATEGORIES, not the disruption.
        let grants = vec![network("a.test")];
        let before = policy(grants.clone());
        let mut after = policy(grants);
        after.tier = Tier::Open;

        let changed = changed_categories(&before, &after);
        assert_eq!(
            changed,
            vec![Category::Network],
            "the axis check must report Network and the grant loop nothing"
        );

        // And with the axes equal, the same grants produce no categories at
        // all — which is what makes the assertion above meaningful.
        assert!(changed_categories(&before, &before).is_empty());
    }

    #[test]
    fn a_profile_change_alone_also_reports_network_from_the_axis_check() {
        // The `||` half of the comparison: tier equal, profile differing.
        let grants = vec![network("a.test")];
        let before = policy(grants.clone());
        let mut after = policy(grants);
        after.profile = Profile::Development;
        assert_eq!(changed_categories(&before, &after), vec![Category::Network]);
    }

    #[test]
    fn sealing_an_environment_with_no_grants_is_still_a_change() {
        // The bug this module's change detection was first written with.
        // Tightening `profile` to `sealed` with no grants declared produces
        // an EMPTY diff — a forbidden category renders as a `none (…)` marker
        // that AccessSummary::entries excludes, being an absence rather than
        // a grant — so there is nothing on either side to differ.
        //
        // Classifying that as "no change" is the most dangerous direction:
        // the user believes they tightened something and nothing happened.
        // Detection is by fingerprint, which includes the axes.
        let mut sealed = policy(vec![]);
        sealed.profile = Profile::Sealed;
        let reload = classify(&policy(vec![]), &sealed);
        assert!(
            reload.changes_anything(),
            "sealing an environment was treated as a no-op"
        );
        assert_eq!(reload.disruption(), Some(Disruption::Live));
    }

    #[test]
    fn opening_the_tier_needs_acknowledgement() {
        // `tier = open` permits any host, which is the largest widening
        // available and must not slip through unreviewed.
        let mut wider = policy(vec![]);
        wider.tier = Tier::Open;
        match classify(&policy(vec![]), &wider) {
            Reload::Accepted {
                needs_acknowledgement,
                ..
            } => assert!(needs_acknowledgement, "opening the network went unreviewed"),
            Reload::Rejected { .. } => panic!("rejected"),
        }
    }

    // ---- naming ----------------------------------------------------------

    #[test]
    fn every_disruption_has_a_distinct_name() {
        // Distinct, because the name is what a reload report prints and what
        // the audit stores — two levels sharing one word would make a record
        // ambiguous after the fact.
        //
        // The "and renders" half of this test used to assert
        // `to_string() == as_str()`, which tested only that a `Display` impl
        // forwarded to the accessor beside it. That impl had no production
        // caller and is deleted (AGENTS.md, "Unfalsifiable code").
        let mut names: Vec<&str> = Disruption::ALL.iter().map(|d| d.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
        // And every name says something, so the uniqueness above is not
        // satisfied by a set of empty strings.
        for disruption in Disruption::ALL {
            assert!(
                !disruption.as_str().is_empty(),
                "{disruption:?} has no name"
            );
        }
    }

    #[test]
    fn only_the_guest_touching_levels_interrupt_work() {
        assert!(!Disruption::None.interrupts_work());
        assert!(!Disruption::Live.interrupts_work());
        assert!(Disruption::RestartService.interrupts_work());
        assert!(Disruption::Rebuild.interrupts_work());
    }
}
