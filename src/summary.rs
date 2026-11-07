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
            .map(|&category| (category, Self::detail(category, tier, grants)))
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
    fn detail(category: Category, tier: Tier, grants: &[Grant]) -> Vec<String> {
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
                Grant::Secret { name } => name.clone(),
            });
        }
        entries.into_iter().collect()
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
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.iter().all(|(_, entries)| entries.is_empty())
    }

    /// The categories that grant nothing.
    ///
    /// Rendered as `none` rather than skipped: a missing line reads as "this
    /// config does not touch credentials", which is a different claim.
    #[must_use]
    pub fn empty_categories(&self) -> Vec<Category> {
        self.lines
            .iter()
            .filter(|(_, entries)| entries.is_empty())
            .map(|(category, _)| *category)
            .collect()
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
        Ok(())
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
        assert_eq!(find("secret"), vec!["aws"]);
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
        let rendered = AccessSummary::new(Tier::None, Profile::Sealed, &grants).to_string();
        for i in 0..5 {
            assert!(
                rendered.contains(&format!("{} -> {}", 3000 + i, 3000 + i)),
                "{rendered}"
            );
        }
    }
}
