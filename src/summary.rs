//! The first-run access summary (`00-PRODUCT.md` §3.10c).
//!
//! On the first `start` of a grant set this machine has not run, Rachna prints
//! what the config grants and stops. This is **not** the permission prompt
//! §3.2 rules out: answering cannot create a grant that is absent from the
//! file, refusing cannot remove one, and `rachna.nix` is unchanged either way.
//! It is a read gate, not a write path.
//!
//! # Two properties carry the whole feature
//!
//! 1. **Completeness.** A category omitted from the output is a grant the user
//!    believes they do not have. Every [`Category`] appears, including empty
//!    ones — `secrets  none` is information, and its absence would read as
//!    "this config does not touch credentials".
//!
//! 2. **Keyed on the effective grant set, not the file.** Reformatting, a
//!    comment or a reordered list must not re-gate, or the acknowledgement
//!    becomes noise people learn to alias away. A grant *added* must.

use crate::decision::{Access, Category};
use crate::grant::Grant;
use crate::policy::{Profile, Tier};
use core::fmt;
use std::collections::BTreeSet;

/// What a config grants, grouped for display.
///
/// # Example
///
/// ```text
///   rachna.nix grants, first run:
///
///   network   github.com:443
///             registry.npmjs.org:443
///   fs        /Users/you/.npmrc  read-only
///             /workspace  read-write
///   tool      rust-analyzer  lsp, no network
///   port      3000 -> 3000
///   secret    aws  <- credential access
///
///   this config has not run here before.
///   review it, then:  rachna start --accept
/// ```
///
/// Built from an evaluated policy. Holds the axes as well as the grants
/// because `tier = open` grants network access that no [`Grant`] records —
/// omitting it would be a completeness hole of exactly the kind property 1
/// exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessSummary {
    tier: Tier,
    profile: Profile,
    lines: Vec<(Category, Vec<String>)>,
}

impl AccessSummary {
    /// Summarises what `grants` and the two axes permit.
    #[must_use]
    pub fn new(tier: Tier, profile: Profile, grants: &[Grant]) -> Self {
        let lines = Category::ALL
            .iter()
            .map(|&category| (category, Self::detail(category, tier, profile, grants)))
            .collect();
        Self {
            tier,
            profile,
            lines,
        }
    }

    /// The human-readable entries for one category, sorted for stability.
    ///
    /// Sorted rather than source-ordered so the rendering — and therefore the
    /// fingerprint built from it — does not change when a list is reordered
    /// in `rachna.nix` (property 2).
    fn detail(category: Category, tier: Tier, profile: Profile, grants: &[Grant]) -> Vec<String> {
        // A category the profile forbids is reported as forbidden, NOT as the
        // grants that happen to be written down.
        //
        // Found by the fingerprint/diff agreement test: with `profile =
        // sealed`, this listed `secret aws` for a config where `decide` denies
        // every secret at step 1 (`08` §1.2). Overstating access is the same
        // class of bug as omitting a category — the user reads a permission
        // they do not have — and it is the more dangerous direction here,
        // because it invites accepting a config on a false basis.
        if profile.forbids(category) {
            return vec![format!("none ({profile} profile forbids it)")];
        }

        // `open` and `internet` permit any host without an allowlist entry, so
        // the grants list would understate the access. This is the completeness
        // hole that made holding the axes necessary.
        if category == Category::Network && matches!(tier, Tier::Open | Tier::Internet) {
            return vec![format!("any host (tier = {tier})")];
        }

        let mut entries: BTreeSet<String> = BTreeSet::new();
        for grant in grants.iter().filter(|g| g.category() == category) {
            entries.insert(match grant {
                Grant::Network { endpoint } => endpoint.to_string(),
                Grant::Filesystem { path, access } => {
                    let access = match access {
                        Access::ReadOnly => "read-only",
                        Access::ReadWrite => "read-write",
                    };
                    format!("{}  {access}", path.display())
                }
                Grant::Tool {
                    name,
                    kind,
                    network,
                } => {
                    let net = if *network { "network" } else { "no network" };
                    format!("{name}  {kind}, {net}")
                }
                Grant::Port { guest, host } => format!("{guest} -> {host}"),
                // Marked, because credential access is the grant a user most
                // needs to notice in a repo they just cloned. Everything else
                // here is scoped; a credential is the thing that leaves.
                Grant::Secret { name } => format!("{name}  <- credential access"),
            });
        }
        entries.into_iter().collect()
    }

    /// Every granted entry as a flat set, for comparison.
    ///
    /// Built from the same `lines` the rendering and the fingerprint use, so
    /// a diff can never disagree with what was displayed.
    fn entries(&self) -> BTreeSet<(Category, String)> {
        let mut out = BTreeSet::new();
        for (category, entries) in &self.lines {
            for entry in entries {
                // A "forbidden" marker describes an absence, so it is not an
                // entry: counting it would make a sealed config look as though
                // it granted something, and would put it in the diff.
                if entry.starts_with("none (") {
                    continue;
                }
                out.insert((*category, entry.clone()));
            }
        }
        out
    }

    /// A stable identifier for *what this grants*, not for the file's bytes.
    ///
    /// Property 2. Two configs that permit exactly the same things share a
    /// fingerprint, so a reformat does not re-gate; adding or widening a grant
    /// changes it, so a `git pull` that adds one does.
    ///
    /// Written explicitly rather than derived from `Debug` or a serializer,
    /// because `08-POLICY-AND-STORE.md` §2 records that a format change
    /// orphans stored records and must therefore be a deliberate migration.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut out = format!("tier={}\nprofile={}\n", self.tier, self.profile);
        for (category, entries) in &self.lines {
            for entry in entries {
                out.push_str(category.as_str());
                out.push(' ');
                out.push_str(entry);
                out.push('\n');
            }
        }
        out
    }

    /// Whether this grants anything at all beyond the defaults.
    ///
    /// A `none (… forbids it)` line is not a grant, so a config whose profile
    /// forbids everything still reports as empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }

    /// The categories that grant nothing.
    ///
    /// Rendered as `none` rather than skipped: a missing line reads as "this
    /// config does not touch credentials", which is a different claim.
    #[must_use]
    pub fn empty_categories(&self) -> Vec<Category> {
        let granted = self.entries();
        self.lines
            .iter()
            .filter(|(category, _)| !granted.iter().any(|(c, _)| c == category))
            .map(|(category, _)| *category)
            .collect()
    }
}

/// How a grant set changed since the last accepted one.
///
/// The edit loop in `00-PRODUCT.md` §3.10c is *review, edit, start again*, so
/// the second showing must answer "what changed" rather than reprinting the
/// whole list. Reprinting is what trains people to stop reading it.
///
/// Both directions are reported. A **removed** grant is as important as an
/// added one: it is the evidence that the edit you made actually took effect,
/// and silently showing only additions would leave a failed edit looking
/// identical to a successful one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantDiff {
    added: Vec<(Category, String)>,
    removed: Vec<(Category, String)>,
}

impl GrantDiff {
    /// What changed going from `previous` to `current`.
    #[must_use]
    pub fn between(previous: &AccessSummary, current: &AccessSummary) -> Self {
        let before = previous.entries();
        let after = current.entries();
        Self {
            added: after.difference(&before).cloned().collect(),
            removed: before.difference(&after).cloned().collect(),
        }
    }

    /// Whether anything changed at all.
    ///
    /// `true` means the fingerprint is unchanged, so no re-acknowledgement is
    /// needed — the two must never disagree, which a test asserts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Whether this change grants anything that was not granted before.
    ///
    /// The question the gate actually turns on. A purely *narrowing* edit —
    /// removing grants and adding none — still changes the fingerprint, but a
    /// user who has already seen the wider set has nothing new to review.
    #[must_use]
    pub fn widens(&self) -> bool {
        !self.added.is_empty()
    }
}

impl fmt::Display for GrantDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (category, entry) in &self.removed {
            writeln!(f, "  - {:<7} {entry}", category.as_str())?;
        }
        for (category, entry) in &self.added {
            writeln!(f, "  + {:<7} {entry}", category.as_str())?;
        }
        Ok(())
    }
}

impl fmt::Display for AccessSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  rachna.nix grants, first run:")?;
        writeln!(f)?;
        for (category, entries) in &self.lines {
            let label = category.as_str();
            match entries.split_first() {
                None => writeln!(f, "  {label:<9} none")?,
                Some((first, rest)) => {
                    writeln!(f, "  {label:<9} {first}")?;
                    for entry in rest {
                        writeln!(f, "  {:<9} {entry}", "")?;
                    }
                }
            }
        }
        // Trailing blank line, so a caller appending the acknowledgement
        // prompt does not have to remember one.
        writeln!(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{Endpoint, ToolKind};
    use std::path::PathBuf;

    fn endpoint(host: &str, port: u16) -> Endpoint {
        Endpoint::new(host, port).expect("test endpoints are non-empty")
    }

    fn realistic_grants() -> Vec<Grant> {
        vec![
            Grant::Network {
                endpoint: endpoint("registry.npmjs.org", 443),
            },
            Grant::Network {
                endpoint: endpoint("github.com", 443),
            },
            Grant::Filesystem {
                path: PathBuf::from("/workspace"),
                access: Access::ReadWrite,
            },
            Grant::Port {
                guest: 3000,
                host: 3000,
            },
            Grant::Secret {
                name: "aws".to_owned(),
            },
            Grant::Tool {
                name: "rust-analyzer".to_owned(),
                kind: ToolKind::Lsp,
                network: false,
            },
        ]
    }

    // ---- property 1: completeness ----------------------------------------

    #[test]
    fn every_category_appears_even_when_it_grants_nothing() {
        // A category omitted from the output is a grant the user believes they
        // do not have. This is the property the whole feature rests on, so it
        // is asserted over Category::ALL rather than spot-checked.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Sealed, &[]);
        let rendered = summary.to_string();
        for category in Category::ALL {
            assert!(
                rendered.contains(category.as_str()),
                "{category} is missing from an empty summary:\n{rendered}"
            );
        }
        assert_eq!(summary.empty_categories(), Category::ALL.to_vec());
        assert!(summary.is_empty());
    }

    #[test]
    fn an_empty_category_renders_as_none_rather_than_being_skipped() {
        // "secrets none" is information; a missing line reads as "this config
        // does not touch credentials", which is a different claim.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Sealed, &[]);
        let rendered = summary.to_string();
        assert!(rendered.contains("secret    none"), "{rendered}");
    }

    #[test]
    fn empty_categories_names_exactly_the_ones_with_no_grants() {
        // Mutation testing found this: existing tests only checked the
        // all-empty and all-granted extremes, so a comparison flipped to `!=`
        // — reporting the categories that DO have grants — survived. A mixed
        // config is the case that distinguishes them.
        let summary = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[
                Grant::Secret {
                    name: "aws".to_owned(),
                },
                Grant::Port {
                    guest: 3000,
                    host: 3000,
                },
            ],
        );
        let empty = summary.empty_categories();
        for category in Category::ALL {
            let granted = matches!(category, Category::Secret | Category::Port);
            assert_eq!(
                empty.contains(&category),
                !granted,
                "{category}: granted={granted} but empty_categories disagrees"
            );
        }
    }

    #[test]
    fn a_realistic_config_renders_every_grant() {
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let rendered = summary.to_string();
        for expected in [
            "registry.npmjs.org:443",
            "github.com:443",
            "/workspace  read-write",
            "3000 -> 3000",
            "aws",
            "rust-analyzer  lsp, no network",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}:\n{rendered}"
            );
        }
        assert!(!summary.is_empty());
        assert!(summary.empty_categories().is_empty());
    }

    #[test]
    fn an_open_tier_is_reported_even_though_no_grant_records_it() {
        // The completeness hole that made holding the axes necessary: `open`
        // and `internet` permit any host WITHOUT an allowlist entry, so a
        // summary built from grants alone would show "network none" for a
        // config with unrestricted network access.
        for tier in [Tier::Open, Tier::Internet] {
            let summary = AccessSummary::new(tier, Profile::Development, &[]);
            let rendered = summary.to_string();
            assert!(
                rendered.contains("any host"),
                "tier {tier} understated network access:\n{rendered}"
            );
            assert!(
                !summary.is_empty(),
                "tier {tier} reported as granting nothing"
            );
        }
    }

    #[test]
    fn an_allowlist_tier_with_no_grants_reports_no_network() {
        // The converse: `allowlist` with nothing allowed really is no network,
        // so it must NOT claim "any host".
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Development, &[]);
        assert!(!summary.to_string().contains("any host"));
    }

    // ---- property 2: keyed on the grant set, not the file ----------------

    #[test]
    fn reordering_grants_does_not_change_the_fingerprint() {
        // Property 2. If a reordered list re-gated, the acknowledgement would
        // become noise and people would alias it away.
        let mut reversed = realistic_grants();
        reversed.reverse();
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &reversed);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a, b, "the summary itself must be order-independent");
    }

    #[test]
    fn a_duplicated_grant_does_not_change_the_fingerprint() {
        // Declaring the same host twice grants no more than once.
        let mut doubled = realistic_grants();
        doubled.push(Grant::Network {
            endpoint: endpoint("github.com", 443),
        });
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &doubled);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn adding_a_grant_changes_the_fingerprint() {
        // The other half: a `git pull` that adds a grant must re-gate. This is
        // §3.11's supply-chain case arriving for free.
        let mut widened = realistic_grants();
        widened.push(Grant::Network {
            endpoint: endpoint("evil.example", 443),
        });
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &widened);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn widening_an_existing_grant_changes_the_fingerprint() {
        // The subtle case: the same path at a higher access level is a
        // different permission, and keying on a path alone would miss it.
        let read_only = vec![Grant::Filesystem {
            path: PathBuf::from("/workspace"),
            access: Access::ReadOnly,
        }];
        let read_write = vec![Grant::Filesystem {
            path: PathBuf::from("/workspace"),
            access: Access::ReadWrite,
        }];
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &read_only);
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &read_write);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn changing_an_axis_changes_the_fingerprint() {
        // Both axes are part of what a config grants, so a tier or profile
        // change must re-gate even with identical grants.
        let grants = realistic_grants();
        let base = AccessSummary::new(Tier::Allowlist, Profile::Development, &grants);
        assert_ne!(
            base.fingerprint(),
            AccessSummary::new(Tier::Open, Profile::Development, &grants).fingerprint(),
            "tier must participate"
        );
        assert_ne!(
            base.fingerprint(),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &grants).fingerprint(),
            "profile must participate"
        );
    }

    #[test]
    fn a_tool_gaining_network_access_changes_the_fingerprint() {
        // A tool is a distinct principal (00 §11.2), so the same tool with
        // network access is a different grant.
        let offline = vec![Grant::Tool {
            name: "rust-analyzer".to_owned(),
            kind: ToolKind::Lsp,
            network: false,
        }];
        let online = vec![Grant::Tool {
            name: "rust-analyzer".to_owned(),
            kind: ToolKind::Lsp,
            network: true,
        }];
        assert_ne!(
            AccessSummary::new(Tier::Allowlist, Profile::Online, &offline).fingerprint(),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &online).fingerprint()
        );
    }

    #[test]
    fn the_fingerprint_is_stable_across_calls() {
        // It is written to disk to decide whether to re-gate, so instability
        // would re-prompt on every start.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        assert_eq!(summary.fingerprint(), summary.fingerprint());
    }

    /// Parses the rendering back into (category, entries), so tests can assert
    /// an entry appears under the RIGHT label rather than merely somewhere.
    ///
    /// Added because mutation testing killed nothing on the two category
    /// comparisons in `detail`: every existing test asserted only that a
    /// string was present, so mutants that filed grants under the wrong
    /// category survived. "Present somewhere" is not the property — the
    /// summary's whole job is saying *which* access you are granting.
    fn parse(summary: &AccessSummary) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for line in summary.to_string().lines() {
            let Some(rest) = line.strip_prefix("  ") else {
                continue;
            };
            if rest.is_empty() || rest.starts_with("rachna.nix") {
                continue;
            }
            let (label, entry) = rest.split_at(9);
            let (label, entry) = (label.trim(), entry.trim());
            if label.is_empty() {
                // A continuation line belongs to the preceding category.
                if let Some((_, entries)) = out.last_mut() {
                    entries.push(entry.to_owned());
                }
            } else {
                out.push((label.to_owned(), vec![entry.to_owned()]));
            }
        }
        out
    }

    #[test]
    fn each_grant_is_listed_under_its_own_category() {
        // Kills the `g.category() == category` mutant: with `!=`, every grant
        // would be filed under the wrong categories, which is a worse
        // completeness failure than omitting it — the user reads an access
        // they do not have and misses one they do.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let parsed = parse(&summary);
        let find = |label: &str| -> Vec<String> {
            parsed
                .iter()
                .find(|(l, _)| l == label)
                .map(|(_, e)| e.clone())
                .unwrap_or_default()
        };
        assert_eq!(
            find("network"),
            vec!["github.com:443", "registry.npmjs.org:443"]
        );
        assert_eq!(find("fs"), vec!["/workspace  read-write"]);
        assert_eq!(find("port"), vec!["3000 -> 3000"]);
        assert_eq!(find("secret"), vec!["aws  <- credential access"]);
        assert_eq!(find("tool"), vec!["rust-analyzer  lsp, no network"]);
    }

    #[test]
    fn an_open_tier_reports_any_host_under_network_and_nowhere_else() {
        // Kills the `category == Category::Network` mutant: with `!=`, every
        // category except network would claim "any host" — telling the user
        // their filesystem and credentials are unrestricted.
        let summary = AccessSummary::new(Tier::Open, Profile::Development, &[]);
        for (label, entries) in parse(&summary) {
            let claims_any_host = entries.iter().any(|e| e.contains("any host"));
            if label == "network" {
                assert!(claims_any_host, "network must report the open tier");
            } else {
                assert!(
                    !claims_any_host,
                    "{label} claimed 'any host', which is network's axis alone"
                );
            }
        }
    }

    #[test]
    fn a_credential_grant_is_visible_in_the_rendering() {
        // The grant a user most needs to notice in a cloned repo.
        let summary = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Secret {
                name: "aws".to_owned(),
            }],
        );
        let rendered = summary.to_string();
        assert!(rendered.contains("secret"), "{rendered}");
        assert!(rendered.contains("aws"), "{rendered}");
        // Flagged explicitly: everything else in this summary is scoped, and
        // a credential is the thing that leaves the machine.
        assert!(rendered.contains("<- credential access"), "{rendered}");
    }

    // ---- the edit loop: selective acceptance by editing the file --------

    #[test]
    fn removing_the_credential_shows_as_a_removal() {
        // The §3.10c flow: you do not want the credential, so you delete it
        // and start again. The second summary must show that the edit took
        // effect, which is why removals are reported and not only additions.
        let before = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let narrowed: Vec<Grant> = realistic_grants()
            .into_iter()
            .filter(|g| g.category() != Category::Secret)
            .collect();
        let after = AccessSummary::new(Tier::Allowlist, Profile::Online, &narrowed);

        let diff = GrantDiff::between(&before, &after);
        assert_eq!(diff.to_string(), "  - secret  aws  <- credential access\n");
        assert!(!diff.is_empty());
        // The key property: narrowing does not need a fresh review.
        assert!(!diff.widens(), "removing a grant must not re-gate");
    }

    #[test]
    fn an_added_grant_widens_and_a_removed_one_does_not() {
        let base = AccessSummary::new(Tier::Allowlist, Profile::Online, &[]);
        let wider = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Secret {
                name: "aws".to_owned(),
            }],
        );
        assert!(GrantDiff::between(&base, &wider).widens());
        assert!(!GrantDiff::between(&wider, &base).widens());
    }

    #[test]
    fn a_diff_reports_both_directions_at_once() {
        // An edit that swaps one host for another is both, and showing only
        // the addition would hide that the old grant is gone.
        let before = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Network {
                endpoint: endpoint("old.example", 443),
            }],
        );
        let after = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Network {
                endpoint: endpoint("new.example", 443),
            }],
        );
        let rendered = GrantDiff::between(&before, &after).to_string();
        assert!(rendered.contains("- network old.example:443"), "{rendered}");
        assert!(rendered.contains("+ network new.example:443"), "{rendered}");
    }

    #[test]
    fn an_unchanged_grant_set_produces_an_empty_diff() {
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let mut reordered = realistic_grants();
        reordered.reverse();
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &reordered);
        let diff = GrantDiff::between(&a, &b);
        assert!(diff.is_empty(), "a reorder is not a change");
        assert!(!diff.widens());
        assert_eq!(diff.to_string(), "");
    }

    #[test]
    fn an_empty_diff_and_an_equal_fingerprint_always_agree() {
        // These two answer the same question by different routes — "must this
        // re-gate?" — so disagreement would mean either a silent re-prompt or
        // a silently-skipped review. Checked across a realistic set of edits.
        let base = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let mut widened = realistic_grants();
        widened.push(Grant::Port {
            guest: 9999,
            host: 9999,
        });
        let variants = [
            AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants()),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &widened),
            AccessSummary::new(Tier::Open, Profile::Online, &realistic_grants()),
            AccessSummary::new(Tier::Allowlist, Profile::Sealed, &realistic_grants()),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &[]),
        ];
        for variant in &variants {
            let same_fingerprint = base.fingerprint() == variant.fingerprint();
            let empty_diff = GrantDiff::between(&base, variant).is_empty();
            assert_eq!(
                same_fingerprint, empty_diff,
                "fingerprint and diff disagree for {variant:?}"
            );
        }
    }

    #[test]
    fn a_forbidden_category_is_reported_as_forbidden_not_as_its_grants() {
        // The bug the fingerprint/diff agreement test found. A sealed profile
        // denies every secret at step 1 of the matching order (08 §1.2), so
        // listing `secret aws` would tell the user they have a credential
        // grant that `decide` will refuse.
        //
        // Overstating access is the same class of bug as omitting a category,
        // and the more dangerous direction: it invites accepting a config on
        // a false basis.
        let summary = AccessSummary::new(
            Tier::Allowlist,
            Profile::Sealed,
            &[Grant::Secret {
                name: "aws".to_owned(),
            }],
        );
        let rendered = summary.to_string();
        assert!(
            rendered.contains("none (sealed profile forbids it)"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("aws"),
            "a forbidden grant must not be listed as granted:\n{rendered}"
        );
        // And it is not counted as a grant.
        assert!(summary.is_empty());
        assert!(summary.empty_categories().contains(&Category::Secret));
    }

    #[test]
    fn changing_a_profile_shows_up_in_the_diff() {
        // Profiles gate whole categories, so tightening one is a real change
        // to what is granted and must be visible in the diff rather than only
        // in the fingerprint.
        let grants = vec![Grant::Secret {
            name: "aws".to_owned(),
        }];
        let online = AccessSummary::new(Tier::Allowlist, Profile::Online, &grants);
        let sealed = AccessSummary::new(Tier::Allowlist, Profile::Sealed, &grants);
        let diff = GrantDiff::between(&online, &sealed);
        assert!(!diff.is_empty(), "sealing a profile is a change");
        assert!(!diff.widens(), "sealing only removes access");
        assert!(diff.to_string().contains("- secret"), "{diff}");
    }

    #[test]
    fn changing_a_tier_shows_up_in_the_diff() {
        // The axes are part of what is granted, so a tier change must appear
        // in the diff and not only in the fingerprint.
        let before = AccessSummary::new(Tier::Allowlist, Profile::Online, &[]);
        let after = AccessSummary::new(Tier::Open, Profile::Online, &[]);
        let diff = GrantDiff::between(&before, &after);
        assert!(diff.widens(), "opening the network is a widening");
        assert!(diff.to_string().contains("any host"), "{diff}");
    }

    #[test]
    fn multiple_entries_in_one_category_are_all_shown() {
        // A summary that truncated would be a completeness hole.
        let grants: Vec<Grant> = (0..5)
            .map(|i| Grant::Port {
                guest: 3000 + i,
                host: 3000 + i,
            })
            .collect();
        // Online, not Sealed: the sealed profile forbids ports, so a sealed
        // config would correctly report them as forbidden rather than listing
        // them — which is what this test's first draft got wrong.
        let rendered = AccessSummary::new(Tier::None, Profile::Online, &grants).to_string();
        for i in 0..5 {
            assert!(
                rendered.contains(&format!("{} -> {}", 3000 + i, 3000 + i)),
                "{rendered}"
            );
        }
    }
}
