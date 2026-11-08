//! The denial report: every denial in a run, with the fix.
//!
//! `00-PRODUCT.md` §3.3 specifies this, and it is the product's distinctive
//! surface — deny-by-default is only survivable if the permission tax gets
//! refunded (§3.4). The build order calls step 10 *the milestone that
//! matters* because by here the whole loop works with no hypervisor.
//!
//! Five rules from §3.3, each enforced somewhere specific:
//!
//! 1. **Every denial in a run, not the first.** A command touching six
//!    blocked things must not take six edit-rerun cycles.
//! 2. **Always show the hand-edit snippet.** Non-negotiable: it teaches the
//!    schema, works when the CST editor refuses, and keeps the file the
//!    source of truth rather than a thing the CLI mutates.
//! 3. **Suggest the narrowest grant that would have worked** — exactly
//!    `registry.npmjs.org:443`, never `*.npmjs.org`, never "allow all".
//! 4. **Attribution is honest** — the process *chain*, because a parent does
//!    not prove intent but `node → node-gyp` tells a developer it was a build
//!    script.
//! 5. **Grade by severity** — a credential-store read gets a different
//!    suggestion than a registry fetch.

use crate::decision::{Category, DenyReason};
use crate::policy::{Profile, Tier};
use core::fmt;
use std::collections::BTreeMap;

/// One denial, with how often it happened and who caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Which category.
    pub category: Category,
    /// What was asked for.
    pub target: String,
    /// Why it was refused.
    pub reason: DenyReason,
    /// How many times, so a hot loop is visible as `× 47`.
    pub count: u32,
    /// The process chain, outermost first.
    ///
    /// A `Vec` rather than a single name because rule 4 requires the chain:
    /// `node → node-gyp` is what distinguishes a build script from `npm`
    /// itself, and a parent alone does not prove intent.
    pub chain: Vec<String>,
}

impl Denial {
    /// The chain rendered as `node → node-gyp`.
    #[must_use]
    pub fn chain_display(&self) -> String {
        self.chain.join(" → ")
    }

    /// Whether this target looks like a credential store.
    ///
    /// Rule 5. Pattern-matched on the path rather than configured, because
    /// the point is to catch the case a user did not think to declare — and
    /// a missed match degrades to the ordinary suggestion rather than to a
    /// wrong one.
    #[must_use]
    pub fn touches_credentials(&self) -> bool {
        if self.category != Category::Filesystem {
            return false;
        }
        const MARKERS: &[&str] = &[
            ".aws/credentials",
            ".ssh/",
            ".netrc",
            ".npmrc",
            ".docker/config.json",
            ".kube/config",
            ".gnupg/",
            "id_rsa",
            "id_ed25519",
        ];
        let target = self.target.to_lowercase();
        MARKERS.iter().any(|marker| target.contains(marker))
    }
}

/// The narrowest grant that would have permitted a denial.
///
/// Rule 3, as a type: the only constructors produce an exact grant, so there
/// is no path by which a report suggests a wildcard. A suggestion broader
/// than the denial would quietly widen a policy the user is trying to
/// tighten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suggestion {
    /// A `rachna` command that makes the edit.
    Command(String),
    /// A credential grant instead of a filesystem mount (rule 5).
    ///
    /// Separate from `Command` so the report can lead with the warning: a
    /// mount over `~/.aws/credentials` gives the guest the whole file for as
    /// long as it is mounted, where a scoped secret does not.
    PreferSecret { name: String, command: String },
    /// Nothing a grant can fix.
    ///
    /// `BackendCannotEnforce` and `ProfileForbids` are not grant-fixable
    /// (`decision.rs`'s `is_fixable_by_grant`), and offering a command that
    /// would change nothing is worse than offering none.
    NotFixableByGrant { explanation: String },
}

/// A whole run's denials, with suggestions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What was run.
    pub command: String,
    /// Its exit code.
    pub exit_code: i32,
    /// How long it took, in milliseconds.
    pub duration_ms: u64,
    /// The run identifier, for `rachna explain`.
    pub run_id: String,
    /// Every denial, grouped.
    denials: Vec<Denial>,
    /// The axes in force, for the near-miss hint (rule: teach the profile
    /// model).
    tier: Tier,
    profile: Profile,
}

impl Report {
    /// Builds a report from a run's denials.
    ///
    /// Denials are **grouped by (category, target)** and counted, because
    /// rule 1 is "every denial" and a hot loop produces the same denial
    /// hundreds of times — listing each would bury the other five.
    #[must_use]
    pub fn new(
        command: impl Into<String>,
        exit_code: i32,
        duration_ms: u64,
        run_id: impl Into<String>,
        tier: Tier,
        profile: Profile,
        denials: Vec<Denial>,
    ) -> Self {
        let mut grouped: BTreeMap<(Category, String), Denial> = BTreeMap::new();
        for denial in denials {
            let key = (denial.category, denial.target.clone());
            grouped
                .entry(key)
                .and_modify(|existing| existing.count += denial.count)
                .or_insert(denial);
        }
        Self {
            command: command.into(),
            exit_code,
            duration_ms,
            run_id: run_id.into(),
            denials: grouped.into_values().collect(),
            tier,
            profile,
        }
    }

    /// Every distinct denial.
    #[must_use]
    pub fn denials(&self) -> &[Denial] {
        &self.denials
    }

    /// Whether anything was blocked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.denials.is_empty()
    }

    /// The suggestion for one denial.
    #[must_use]
    pub fn suggestion(&self, denial: &Denial) -> Suggestion {
        if !denial.reason.is_fixable_by_grant() {
            return Suggestion::NotFixableByGrant {
                explanation: self.explain_unfixable(denial),
            };
        }

        // Rule 5: a credential store gets a different suggestion. Checked
        // before the ordinary path, or the report would lead with the mount
        // that is the thing being discouraged.
        if denial.touches_credentials() {
            let name = credential_name(&denial.target);
            return Suggestion::PreferSecret {
                command: format!("rachna secret add {name} --ttl 1h"),
                name,
            };
        }

        // Rule 3: the target verbatim. No widening, by construction.
        Suggestion::Command(match denial.category {
            Category::Network => format!("rachna allow network {}", denial.target),
            Category::Filesystem => {
                let access = match &denial.reason {
                    // A read-only grant exists and a write was wanted, so the
                    // fix is widening that grant rather than adding one.
                    DenyReason::InsufficientAccess { .. } => "--read-write",
                    _ => "--read-only",
                };
                format!("rachna allow fs {} {access}", denial.target)
            }
            Category::Port => format!("rachna port {}", denial.target),
            Category::Secret => format!("rachna secret add {}", denial.target),
            Category::Tool => format!("rachna expose {}", denial.target),
        })
    }

    /// Why a denial cannot be fixed with a grant, in terms a user can act on.
    fn explain_unfixable(&self, denial: &Denial) -> String {
        match &denial.reason {
            DenyReason::ProfileForbids { category } => {
                // Teach the profile model: name the profile that would allow
                // it, so people learn profiles instead of accumulating
                // ad-hoc grants.
                match permitting_profile(*category) {
                    Some(profile) => format!(
                        "the `{}` profile forbids {category}; `profile = \"{profile}\"` \
                         would allow it",
                        self.profile
                    ),
                    None => format!("the `{}` profile forbids {category}", self.profile),
                }
            }
            DenyReason::BackendCannotEnforce { category } => format!(
                "this host cannot enforce {category} limits, so granting it \
                 would be a rule that does not hold"
            ),
            DenyReason::ToolRoleForbids { tool } => {
                format!("the `{tool}` tool's own role forbids this")
            }
            other => format!("{other:?}"),
        }
    }

    /// The hand-edit snippet (rule 2 — non-negotiable).
    ///
    /// Always produced when there is anything grantable, because it teaches
    /// the schema and keeps `rachna.nix` the source of truth rather than a
    /// thing the CLI mutates.
    #[must_use]
    pub fn hand_edit_snippet(&self) -> Option<String> {
        let hosts: Vec<&str> = self
            .grantable()
            .filter(|d| d.category == Category::Network)
            .map(|d| d.target.as_str())
            .collect();
        // Credential stores are excluded from the mount snippet on purpose:
        // the report has just advised a scoped secret INSTEAD of a mount, and
        // printing the mount anyway would hand the user the thing being
        // discouraged. Rule 5 beats rule 2 for this one case — the snippet is
        // still shown, it just does not contradict the warning above it.
        let paths: Vec<&Denial> = self
            .grantable()
            .filter(|d| d.category == Category::Filesystem)
            .filter(|d| !d.touches_credentials())
            .collect();

        if hosts.is_empty() && paths.is_empty() {
            return None;
        }

        let mut snippet = String::new();
        if !hosts.is_empty() {
            let quoted: Vec<String> = hosts.iter().map(|h| format!("\"{h}\"")).collect();
            snippet.push_str(&format!("    network.allow = [ {} ];\n", quoted.join(" ")));
        }
        if !paths.is_empty() {
            snippet.push_str("    filesystem.mounts = [\n");
            for denial in paths {
                let access = match &denial.reason {
                    DenyReason::InsufficientAccess { .. } => "read-write",
                    _ => "read-only",
                };
                snippet.push_str(&format!(
                    "      {{ source = \"{}\"; access = \"{access}\"; }}\n",
                    denial.target
                ));
            }
            snippet.push_str("    ];\n");
        }
        Some(snippet)
    }

    fn grantable(&self) -> impl Iterator<Item = &Denial> {
        self.denials
            .iter()
            .filter(|denial| denial.reason.is_fixable_by_grant())
    }

    /// The near-miss hint: a tier that would have allowed a network denial.
    ///
    /// Teaches the tier model the same way the profile hint does. `None` when
    /// the current tier is already the most permissive, because "open would
    /// allow this, you are on open" is noise.
    #[must_use]
    pub fn tier_hint(&self) -> Option<String> {
        let has_network_denial = self
            .denials
            .iter()
            .any(|denial| denial.category == Category::Network);
        if !has_network_denial || self.tier == Tier::Open {
            return None;
        }
        // `internet` is the next step up from `allowlist` and `none`, and is
        // the one worth naming: it needs no per-host grant while still
        // excluding the host's private networks.
        (self.tier != Tier::Internet).then(|| {
            format!(
                "`tier = \"internet\"` would allow these without per-host grants; \
                 you are on `{}`",
                self.tier
            )
        })
    }
}

/// The least permissive profile that allows `category`.
fn permitting_profile(category: Category) -> Option<Profile> {
    Profile::ALL
        .into_iter()
        .find(|profile| !profile.forbids(category))
}

/// A credential name guessed from a path, for `rachna secret add`.
fn credential_name(target: &str) -> String {
    let lower = target.to_lowercase();
    for (marker, name) in [
        (".aws/", "aws"),
        (".ssh/", "ssh"),
        (".npmrc", "npm"),
        (".docker/", "docker"),
        (".kube/", "kube"),
        (".gnupg/", "gpg"),
        (".netrc", "netrc"),
    ] {
        if lower.contains(marker) {
            return name.to_owned();
        }
    }
    "credential".to_owned()
}

impl fmt::Display for Report {
    /// The report as §3.3 specifies it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.duration_ms as f64 / 1000.0;
        writeln!(
            f,
            "✗ {} exited {} · {seconds:.1}s · {} blocked",
            self.command,
            self.exit_code,
            self.denials.len()
        )?;
        writeln!(f)?;

        for denial in &self.denials {
            let label = match (denial.category, &denial.reason) {
                (Category::Filesystem, DenyReason::InsufficientAccess { .. }) => "fs write",
                (Category::Filesystem, _) => "fs read",
                (category, _) => category.as_str(),
            };
            writeln!(
                f,
                "  {label:<9} {:<28} × {:<4} {}",
                denial.target,
                denial.count,
                denial.chain_display()
            )?;

            // Rule 5: the warning goes directly under the line it concerns,
            // not in a footnote.
            if let Suggestion::PreferSecret { command, .. } = self.suggestion(denial) {
                writeln!(
                    f,
                    "  {:<9} ⚠ credential store — prefer a scoped secret over a mount:",
                    ""
                )?;
                writeln!(f, "  {:<9}   {command}", "")?;
            }
            if let Suggestion::NotFixableByGrant { explanation } = self.suggestion(denial) {
                writeln!(f, "  {:<9} ⚠ {explanation}", "")?;
            }
        }

        let commands: Vec<String> = self
            .grantable()
            .filter(|d| !d.touches_credentials())
            .filter_map(|denial| match self.suggestion(denial) {
                Suggestion::Command(command) => Some(command),
                _ => None,
            })
            .collect();
        if !commands.is_empty() {
            writeln!(f)?;
            for command in commands {
                writeln!(f, "  {command}")?;
            }
        }

        if let Some(snippet) = self.hand_edit_snippet() {
            writeln!(f)?;
            writeln!(f, "  or add to rachna.nix:")?;
            write!(f, "{snippet}")?;
        }

        if let Some(hint) = self.tier_hint() {
            writeln!(f)?;
            writeln!(f, "  {hint}")?;
        }

        writeln!(f)?;
        writeln!(
            f,
            "  rachna explain {}    for the full decision trace",
            self.run_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Access;

    fn denial(category: Category, target: &str, count: u32) -> Denial {
        Denial {
            category,
            target: target.to_owned(),
            reason: DenyReason::NoMatchingGrant { category },
            count,
            chain: vec!["node".to_owned()],
        }
    }

    fn report(denials: Vec<Denial>) -> Report {
        Report::new(
            "npm install",
            1,
            4200,
            "run/a3f2",
            Tier::Allowlist,
            Profile::Development,
            denials,
        )
    }

    // ---- rule 1: every denial, not the first ----------------------------

    #[test]
    fn every_denial_in_a_run_is_reported() {
        // A command touching six blocked things must not take six
        // edit-rerun cycles (§3.3).
        let denials: Vec<Denial> = (0..6)
            .map(|i| denial(Category::Network, &format!("host{i}.test:443"), 1))
            .collect();
        let report = report(denials);
        assert_eq!(report.denials().len(), 6);
        let rendered = report.to_string();
        for i in 0..6 {
            assert!(
                rendered.contains(&format!("host{i}.test:443")),
                "{rendered}"
            );
        }
    }

    #[test]
    fn repeated_denials_are_grouped_and_counted() {
        // A hot loop produces the same denial hundreds of times; listing
        // each would bury the other five.
        let denials = vec![
            denial(Category::Network, "a.test:443", 40),
            denial(Category::Network, "a.test:443", 7),
            denial(Category::Network, "b.test:443", 2),
        ];
        let report = report(denials);
        assert_eq!(report.denials().len(), 2, "not grouped");
        let counted = report
            .denials()
            .iter()
            .find(|d| d.target == "a.test:443")
            .expect("present");
        assert_eq!(counted.count, 47, "counts must sum");
    }

    #[test]
    fn the_same_target_in_two_categories_stays_separate() {
        // Grouping is by (category, target): a port 3000 and a secret named
        // "3000" are different denials.
        let report = report(vec![
            denial(Category::Port, "3000", 1),
            denial(Category::Secret, "3000", 1),
        ]);
        assert_eq!(report.denials().len(), 2);
    }

    #[test]
    fn an_empty_report_is_detectable() {
        assert!(report(vec![]).is_empty());
        assert!(!report(vec![denial(Category::Network, "a:1", 1)]).is_empty());
    }

    // ---- rule 2: always show the hand-edit snippet ----------------------

    #[test]
    fn the_hand_edit_snippet_is_always_shown_for_grantable_denials() {
        // Non-negotiable (§3.3): it teaches the schema, works when the CST
        // editor refuses, and keeps the file the source of truth.
        let report = report(vec![denial(Category::Network, "a.test:443", 1)]);
        let snippet = report.hand_edit_snippet().expect("a snippet");
        assert!(snippet.contains("network.allow"), "{snippet}");
        assert!(snippet.contains("\"a.test:443\""), "{snippet}");
        assert!(report.to_string().contains("or add to rachna.nix:"));
    }

    #[test]
    fn a_write_denial_suggests_read_write_in_both_the_command_and_the_snippet() {
        // InsufficientAccess means a read-only grant exists and a write was
        // wanted, so the fix is WIDENING that grant rather than adding one.
        let mut write = denial(Category::Filesystem, "/w/src", 1);
        write.reason = DenyReason::InsufficientAccess {
            granted: Access::ReadOnly,
            wanted: Access::ReadWrite,
        };
        let report = report(vec![write.clone()]);
        assert_eq!(
            report.suggestion(&write),
            Suggestion::Command("rachna allow fs /w/src --read-write".to_owned())
        );
        let snippet = report.hand_edit_snippet().expect("a snippet");
        assert!(snippet.contains("read-write"), "{snippet}");
    }

    #[test]
    fn nothing_grantable_means_no_snippet_rather_than_an_empty_one() {
        let mut unfixable = denial(Category::Port, "3000", 1);
        unfixable.reason = DenyReason::BackendCannotEnforce {
            category: Category::Port,
        };
        assert_eq!(report(vec![unfixable]).hand_edit_snippet(), None);
    }

    // ---- rule 3: the narrowest grant ------------------------------------

    #[test]
    fn a_suggestion_is_never_broader_than_the_denial() {
        // §3.3: exactly `registry.npmjs.org:443`, never `*.npmjs.org`, never
        // "allow all network". Enforced by construction — the only
        // constructors take the target verbatim — and asserted here because
        // it is the rule most tempting to relax for convenience.
        for target in [
            "registry.npmjs.org:443",
            "storage.googleapis.com:443",
            "deep.sub.domain.example:8443",
        ] {
            let one = denial(Category::Network, target, 1);
            let suggestion = report(vec![one.clone()]).suggestion(&one);
            match suggestion {
                Suggestion::Command(command) => {
                    assert!(command.contains(target), "{command}");
                    assert!(!command.contains('*'), "widened: {command}");
                }
                other => panic!("expected a command, got {other:?}"),
            }
        }
    }

    #[test]
    fn no_rendering_of_any_report_contains_a_wildcard() {
        // The property, over every category: a wildcard anywhere in this
        // output would be Rachna suggesting the user widen beyond what was
        // observed — the inverse of what synthesize's rule 1 protects.
        let denials: Vec<Denial> = Category::ALL
            .iter()
            .map(|c| denial(*c, "exact.target:443", 1))
            .collect();
        let rendered = report(denials).to_string();
        assert!(!rendered.contains('*'), "{rendered}");
    }

    // ---- rule 4: honest attribution -------------------------------------

    #[test]
    fn the_process_chain_is_shown_not_just_the_parent() {
        // §3.3: a parent does not prove intent, but `node → node-gyp` tells
        // a developer it was a build script rather than npm itself.
        let mut chained = denial(Category::Network, "github.com:443", 2);
        chained.chain = vec!["node".to_owned(), "node-gyp".to_owned()];
        assert_eq!(chained.chain_display(), "node → node-gyp");
        assert!(report(vec![chained])
            .to_string()
            .contains("node → node-gyp"));
    }

    #[test]
    fn a_single_process_chain_renders_without_an_arrow() {
        let one = denial(Category::Network, "a:1", 1);
        assert_eq!(one.chain_display(), "node");
    }

    // ---- rule 5: grade by severity --------------------------------------

    #[test]
    fn a_credential_store_prefers_a_scoped_secret_over_a_mount() {
        for (path, expected) in [
            ("/Users/you/.aws/credentials", "aws"),
            ("/Users/you/.ssh/id_rsa", "ssh"),
            ("/Users/you/.npmrc", "npm"),
            ("/Users/you/.docker/config.json", "docker"),
            ("/Users/you/.kube/config", "kube"),
        ] {
            let credential = denial(Category::Filesystem, path, 1);
            assert!(credential.touches_credentials(), "{path} not recognised");
            match report(vec![credential.clone()]).suggestion(&credential) {
                Suggestion::PreferSecret { name, command } => {
                    assert_eq!(name, expected, "{path}");
                    assert!(command.starts_with("rachna secret add"), "{command}");
                }
                other => panic!("{path} got {other:?}"),
            }
        }
    }

    #[test]
    fn a_credential_denial_is_not_also_offered_as_a_mount() {
        // The contradiction this caught: the report advises a scoped secret
        // INSTEAD of a mount, and printing the mount anyway would hand the
        // user the thing being discouraged. Rule 5 beats rule 2 here — the
        // snippet is still shown, it just does not contradict the warning.
        let credential = denial(Category::Filesystem, "/Users/you/.aws/credentials", 1);
        let report = report(vec![credential]);
        let rendered = report.to_string();
        assert!(rendered.contains("prefer a scoped secret"), "{rendered}");
        assert!(
            !rendered.contains("filesystem.mounts"),
            "the snippet contradicted its own warning:\n{rendered}"
        );
    }

    #[test]
    fn an_ordinary_path_is_not_treated_as_a_credential() {
        // A false positive here would push a user toward `rachna secret add`
        // for a source directory, which cannot work.
        for path in ["/w/src/main.rs", "/w/node_modules", "/w/Cargo.toml"] {
            assert!(
                !denial(Category::Filesystem, path, 1).touches_credentials(),
                "{path} misread as a credential"
            );
        }
    }

    #[test]
    fn a_credential_marker_in_a_network_target_is_not_a_credential() {
        // Only filesystem denials can be credential stores; a host happening
        // to contain ".ssh" is not one.
        assert!(!denial(Category::Network, "ssh.example:22", 1).touches_credentials());
    }

    // ---- not fixable by a grant -----------------------------------------

    #[test]
    fn an_unenforceable_category_is_not_offered_a_grant() {
        // Offering a command that would change nothing is worse than
        // offering none (`decision.rs`'s is_fixable_by_grant).
        let mut unfixable = denial(Category::Port, "3000", 1);
        unfixable.reason = DenyReason::BackendCannotEnforce {
            category: Category::Port,
        };
        match report(vec![unfixable.clone()]).suggestion(&unfixable) {
            Suggestion::NotFixableByGrant { explanation } => {
                assert!(explanation.contains("cannot enforce"), "{explanation}");
                assert!(explanation.contains("does not hold"), "{explanation}");
            }
            other => panic!("offered a grant for an unenforceable limit: {other:?}"),
        }
    }

    #[test]
    fn a_profile_refusal_names_the_profile_that_would_allow_it() {
        // Teach the profile model (§3.3), so people learn profiles instead
        // of accumulating ad-hoc grants.
        let mut forbidden = denial(Category::Secret, "aws", 1);
        forbidden.reason = DenyReason::ProfileForbids {
            category: Category::Secret,
        };
        match report(vec![forbidden.clone()]).suggestion(&forbidden) {
            Suggestion::NotFixableByGrant { explanation } => {
                assert!(explanation.contains("development"), "{explanation}");
                assert!(explanation.contains("online"), "{explanation}");
            }
            other => panic!("{other:?}"),
        }
    }

    // ---- the tier hint ---------------------------------------------------

    #[test]
    fn a_network_denial_on_an_allowlist_suggests_the_tier_model() {
        let hint = report(vec![denial(Category::Network, "a:1", 1)])
            .tier_hint()
            .expect("a hint");
        assert!(hint.contains("internet"), "{hint}");
        assert!(hint.contains("allowlist"), "{hint}");
    }

    #[test]
    fn no_tier_hint_when_it_would_be_noise() {
        // "open would allow this, you are on open" is noise; so is a tier
        // hint for a run with no network denial at all.
        let open = Report::new(
            "x",
            1,
            1,
            "r",
            Tier::Open,
            Profile::Development,
            vec![denial(Category::Network, "a:1", 1)],
        );
        assert_eq!(open.tier_hint(), None);

        let no_network = report(vec![denial(Category::Filesystem, "/w/f", 1)]);
        assert_eq!(no_network.tier_hint(), None);

        let already_internet = Report::new(
            "x",
            1,
            1,
            "r",
            Tier::Internet,
            Profile::Development,
            vec![denial(Category::Network, "a:1", 1)],
        );
        assert_eq!(already_internet.tier_hint(), None);
    }

    // ---- the header and the trace pointer -------------------------------

    #[test]
    fn the_header_reports_the_command_exit_code_duration_and_count() {
        let rendered = report(vec![denial(Category::Network, "a:1", 1)]).to_string();
        assert!(rendered.contains("npm install"), "{rendered}");
        assert!(rendered.contains("exited 1"), "{rendered}");
        assert!(rendered.contains("4.2s"), "{rendered}");
        assert!(rendered.contains("1 blocked"), "{rendered}");
    }

    #[test]
    fn the_runnable_commands_appear_in_the_output() {
        // Mutation testing found this untested: three mutants in the Display
        // impl survived — deleting the command block entirely, and inverting
        // both guards around it — because the tests asserted the SNIPPET and
        // the header but never that the copy-pasteable commands render.
        //
        // Those commands are the thing a user actually runs. A report that
        // explained the problem and omitted them would be the permission tax
        // without the refund (§3.4).
        let rendered = report(vec![
            denial(Category::Network, "registry.npmjs.org:443", 47),
            denial(Category::Filesystem, "/w/vendor", 1),
        ])
        .to_string();
        assert!(
            rendered.contains("rachna allow network registry.npmjs.org:443"),
            "{rendered}"
        );
        assert!(
            rendered.contains("rachna allow fs /w/vendor --read-only"),
            "{rendered}"
        );
    }

    #[test]
    fn a_report_with_nothing_grantable_prints_no_command_block() {
        // The other half of the guard: an empty command block would leave a
        // stray blank section implying there is something to run.
        let mut unfixable = denial(Category::Port, "3000", 1);
        unfixable.reason = DenyReason::BackendCannotEnforce {
            category: Category::Port,
        };
        let rendered = report(vec![unfixable]).to_string();
        assert!(!rendered.contains("rachna allow"), "{rendered}");
        assert!(!rendered.contains("rachna port"), "{rendered}");
    }

    #[test]
    fn a_credential_denial_contributes_no_allow_command() {
        // It gets `rachna secret add` under its own line instead, and an
        // `allow fs` alongside would contradict that advice — the same
        // contradiction the snippet test covers, on the command path.
        let credential = denial(Category::Filesystem, "/Users/you/.aws/credentials", 1);
        let rendered = report(vec![credential]).to_string();
        assert!(!rendered.contains("rachna allow fs"), "{rendered}");
        assert!(rendered.contains("rachna secret add aws"), "{rendered}");
    }

    #[test]
    fn the_report_points_at_the_full_trace() {
        // `rachna explain run/a3f2` is how a user gets from the summary to
        // every decision, which is what the full-fidelity event log is for.
        let rendered = report(vec![denial(Category::Network, "a:1", 1)]).to_string();
        assert!(rendered.contains("rachna explain run/a3f2"), "{rendered}");
    }
}
