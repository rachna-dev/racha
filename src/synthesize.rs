//! `synthesize(observations) -> Vec<Grant>` — the narrowing path.
//!
//! The inverse of [`decide`](crate::decide::decide): given what a project
//! *actually did*, produce the smallest rule set that would have permitted
//! exactly that and nothing more (`08-POLICY-AND-STORE.md` §1.1). Most policy
//! engines only answer `decide`; having both in one pure module is what makes
//! the audit story possible at all.
//!
//! # The two honesty rules, and why they are not optional
//!
//! `08-POLICY-AND-STORE.md` §1.4 states both. They are implemented as types
//! rather than conventions because each guards against a different failure:
//!
//! 1. **Never suggest something broader than what was observed.** The output
//!    is a floor, not a guess at intent. A suggestion broader than the
//!    evidence would quietly *widen* a policy while claiming to narrow it —
//!    the worst possible bug in a narrowing tool.
//!
//! 2. **Refuse to suggest below an evidence threshold.** This one is a
//!    *security* rule, not an ergonomic one. §3.4 names the attack: malware
//!    forges silence so real grants look unused and audit advises revoking
//!    them. A threshold means absence of evidence is not evidence of absence,
//!    and the threshold is always reported with the finding so a user can
//!    judge it.

use crate::decision::Access;
use crate::grant::{Endpoint, Grant, Request};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// How much evidence is required before a narrowing is suggested.
///
/// Defaults are `08-POLICY-AND-STORE.md` §1.4's: **14 days and 50 runs**, both
/// required. The doc is explicit that these are a guess to be revisited with
/// real data, so they live in one named place rather than scattered as
/// literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    /// Days of observation required.
    pub days: u32,
    /// Distinct runs required.
    pub runs: u32,
}

impl Threshold {
    /// The default: 14 days **and** 50 runs.
    pub const DEFAULT: Self = Self { days: 14, runs: 50 };

    /// Whether `evidence` clears this threshold.
    ///
    /// Both conditions are required. Either alone is defeatable: 50 runs in an
    /// afternoon says nothing about a weekly job, and 14 days with 3 runs says
    /// nothing at all.
    #[must_use]
    pub const fn is_met_by(self, evidence: Evidence) -> bool {
        evidence.days >= self.days && evidence.runs >= self.runs
    }
}

impl Default for Threshold {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How much observation actually accumulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Evidence {
    /// Days spanned by the observations.
    pub days: u32,
    /// Distinct runs that contributed.
    pub runs: u32,
}

/// What was actually observed, and how much of it there was.
///
/// Holds [`Request`]s rather than scope strings because a request is already
/// the concrete-act type (`grant.rs`): reusing it means narrowing cannot be
/// fed a pattern by mistake, which is rule 1 enforced structurally.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observations {
    observed: Vec<Request>,
    evidence: Evidence,
}

impl Observations {
    /// Records what was observed across `evidence` worth of running.
    #[must_use]
    pub fn new(observed: impl IntoIterator<Item = Request>, evidence: Evidence) -> Self {
        Self {
            observed: observed.into_iter().collect(),
            evidence,
        }
    }

    /// How much observation accumulated.
    #[must_use]
    pub const fn evidence(&self) -> Evidence {
        self.evidence
    }

    /// Whether anything was observed at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observed.is_empty()
    }
}

/// Why `synthesize` declined to suggest anything.
///
/// A refusal is a result, not an error: "I will not guess from this" is the
/// correct answer often enough that it needs its own representation, and it
/// carries the threshold so the finding can print it (§1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not enough observation to draw a conclusion.
    ///
    /// Carries both sides so the report can say *"unused in 3 days across 7
    /// runs; threshold is 14 days and 50 runs"* rather than bare "unused".
    InsufficientEvidence { have: Evidence, need: Threshold },
}

/// The narrowest rule set covering `observations`, or a [`Refusal`].
///
/// # Errors
///
/// Returns [`Refusal::InsufficientEvidence`] when the observations do not clear
/// `threshold`. This is the §3.4 defence: malware can forge silence, so
/// absence of evidence must not become advice to revoke.
pub fn synthesize(
    observations: &Observations,
    threshold: Threshold,
) -> Result<Vec<Grant>, Refusal> {
    if !threshold.is_met_by(observations.evidence) {
        return Err(Refusal::InsufficientEvidence {
            have: observations.evidence,
            need: threshold,
        });
    }

    // Deliberately NOT short-circuited on `is_empty`: with the threshold met,
    // "nothing was observed" is a real finding — the honest narrowest rule set
    // covering no observations is the empty one, which is what `revoke
    // --unused` acts on. Returning a refusal here would hide it.
    let mut grants: Vec<Grant> = Vec::new();
    grants.extend(network_grants(&observations.observed));
    grants.extend(filesystem_grants(&observations.observed));
    grants.extend(other_grants(&observations.observed));
    Ok(grants)
}

/// One exact grant per distinct endpoint touched.
///
/// **This is wildcard collapse** (§1.4): a grant for `*.googleapis.com:443`
/// observed at only two hosts becomes two exact rules. The collapse is not a
/// special case in the algorithm — emitting exactly what was seen *is* the
/// collapse, which is rule 1 falling out of the design rather than being
/// checked for.
fn network_grants(observed: &[Request]) -> Vec<Grant> {
    let endpoints: BTreeSet<&Endpoint> = observed
        .iter()
        .filter_map(|request| match request {
            Request::Network { endpoint, .. } => Some(endpoint),
            _ => None,
        })
        .collect();
    endpoints
        .into_iter()
        .cloned()
        .map(|endpoint| Grant::Network { endpoint })
        .collect()
}

/// Path narrowing: the minimal set of ancestors covering what was touched.
///
/// A read-write mount where every write landed under `./src`, `./target` and
/// `./node_modules` should suggest those three rather than the whole tree
/// (§1.4). Paths are grouped by the access actually used, so a tree that was
/// only ever read yields a read-only grant — the narrowing that matters most,
/// since a read-write mount is the broadest filesystem permission there is.
fn filesystem_grants(observed: &[Request]) -> Vec<Grant> {
    let mut grants = Vec::new();
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let paths: BTreeSet<&Path> = observed
            .iter()
            .filter_map(|request| match request {
                Request::Filesystem { path, access: used } if *used == access => {
                    Some(path.as_path())
                }
                _ => None,
            })
            .collect();
        grants.extend(
            minimal_covering_paths(&paths)
                .into_iter()
                .map(|path| Grant::Filesystem { path, access }),
        );
    }
    grants
}

/// Drops any path that an ancestor in the same set already covers.
///
/// Suggesting both `/workspace` and `/workspace/src` is redundant, and the
/// redundant entry reads as a second permission. Never *introduces* an
/// ancestor that was not observed — that would be rule 1 violated, widening
/// the policy while claiming to narrow it.
fn minimal_covering_paths(paths: &BTreeSet<&Path>) -> Vec<PathBuf> {
    paths
        .iter()
        .filter(|candidate| {
            !paths
                .iter()
                .any(|other| other != *candidate && candidate.starts_with(other))
        })
        .map(|path| path.to_path_buf())
        .collect()
}

/// Tools, ports and secrets: exact, because they have no breadth to narrow.
///
/// A tool name, a port number and a credential name are each already the
/// narrowest possible expression of themselves. They are still emitted, so a
/// synthesized rule set is complete enough to replace a policy wholesale
/// rather than needing the old one merged in.
fn other_grants(observed: &[Request]) -> Vec<Grant> {
    let mut tools: BTreeSet<&str> = BTreeSet::new();
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    let mut secrets: BTreeSet<&str> = BTreeSet::new();

    for request in observed {
        match request {
            Request::Tool { name } => {
                tools.insert(name);
            }
            Request::Port { guest } => {
                ports.insert(*guest);
            }
            Request::Secret { name } => {
                secrets.insert(name);
            }
            Request::Network { .. } | Request::Filesystem { .. } => {}
        }
    }

    let mut grants = Vec::new();
    // A synthesized tool grant is network-less and typed as an LSP only
    // because observation cannot reveal either: a `Request::Tool` carries a
    // name alone. The conservative reading is the correct one here — assuming
    // network access from a bare invocation would widen the policy.
    grants.extend(tools.into_iter().map(|name| Grant::Tool {
        name: name.to_owned(),
        kind: crate::grant::ToolKind::Lsp,
        network: false,
    }));
    // A port observation names the guest port; the host side is a forwarding
    // choice, not an observation, so it mirrors the guest rather than being
    // invented.
    grants.extend(
        ports
            .into_iter()
            .map(|guest| Grant::Port { guest, host: guest }),
    );
    grants.extend(secrets.into_iter().map(|name| Grant::Secret {
        name: name.to_owned(),
    }));
    grants
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::{decide, Capabilities, Policy};
    use crate::decision::Category;
    use crate::grant::ToolKind;
    use crate::policy::{Profile, Tier};

    fn endpoint(host: &str, port: u16) -> Endpoint {
        Endpoint::new(host, port).expect("test endpoints are non-empty")
    }

    /// Evidence that clears the default threshold.
    const AMPLE: Evidence = Evidence {
        days: 30,
        runs: 100,
    };

    fn net(host: &str, port: u16) -> Request {
        Request::Network {
            endpoint: endpoint(host, port),
            literal_address: false,
        }
    }

    fn file(path: &str, access: Access) -> Request {
        Request::Filesystem {
            path: PathBuf::from(path),
            access,
        }
    }

    fn synthesized(observed: Vec<Request>) -> Vec<Grant> {
        synthesize(&Observations::new(observed, AMPLE), Threshold::DEFAULT)
            .expect("ample evidence clears the threshold")
    }

    // ---- rule 2: the evidence threshold ----------------------------------

    #[test]
    fn thin_evidence_is_refused_rather_than_guessed_at() {
        // The §3.4 attack: malware forges silence so real grants look unused
        // and audit advises revoking them. A refusal is the defence.
        let thin = Observations::new(vec![], Evidence { days: 3, runs: 7 });
        let result = synthesize(&thin, Threshold::DEFAULT);
        assert_eq!(
            result,
            Err(Refusal::InsufficientEvidence {
                have: Evidence { days: 3, runs: 7 },
                need: Threshold::DEFAULT,
            })
        );
    }

    #[test]
    fn a_refusal_carries_both_sides_so_the_finding_can_print_them() {
        // "unused in 3 days across 7 runs; threshold is 14 and 50" is
        // defensible; bare "unused" is not (§1.4).
        let thin = Observations::new(vec![], Evidence { days: 1, runs: 2 });
        match synthesize(&thin, Threshold::DEFAULT) {
            Err(Refusal::InsufficientEvidence { have, need }) => {
                assert_eq!(have.days, 1);
                assert_eq!(have.runs, 2);
                assert_eq!(need, Threshold::DEFAULT);
            }
            Ok(grants) => panic!("suggested {} grants from 1 day", grants.len()),
        }
    }

    #[test]
    fn both_halves_of_the_threshold_are_required() {
        // Either alone is defeatable: 50 runs in an afternoon says nothing
        // about a weekly job, and 14 days with 3 runs says nothing at all.
        let days_only = Evidence { days: 30, runs: 1 };
        let runs_only = Evidence { days: 1, runs: 500 };
        assert!(!Threshold::DEFAULT.is_met_by(days_only));
        assert!(!Threshold::DEFAULT.is_met_by(runs_only));
        assert!(Threshold::DEFAULT.is_met_by(AMPLE));
    }

    #[test]
    fn the_threshold_boundary_is_inclusive() {
        // Exactly at the threshold must pass, or the documented "14 days and
        // 50 runs" would really mean 15 and 51.
        let exact = Evidence { days: 14, runs: 50 };
        assert!(Threshold::DEFAULT.is_met_by(exact));
        assert!(!Threshold::DEFAULT.is_met_by(Evidence { days: 13, runs: 50 }));
        assert!(!Threshold::DEFAULT.is_met_by(Evidence { days: 14, runs: 49 }));
    }

    #[test]
    fn the_documented_defaults_are_the_actual_defaults() {
        assert_eq!(Threshold::default(), Threshold::DEFAULT);
        assert_eq!(Threshold::DEFAULT.days, 14);
        assert_eq!(Threshold::DEFAULT.runs, 50);
    }

    #[test]
    fn silence_with_ample_evidence_is_a_finding_not_a_refusal() {
        // With the threshold met, "nothing was observed" is real information —
        // it is what `revoke --unused` acts on. Refusing here would hide it.
        let silent = Observations::new(vec![], AMPLE);
        assert!(silent.is_empty());
        assert_eq!(synthesize(&silent, Threshold::DEFAULT), Ok(vec![]));
    }

    // ---- rule 1: never broader than observed -----------------------------

    #[test]
    fn a_wildcard_collapses_to_exactly_the_hosts_observed() {
        // The headline narrowing case (§1.4). A grant for *.googleapis.com
        // observed at two hosts becomes those two hosts, never the wildcard.
        let grants = synthesized(vec![
            net("storage.googleapis.com", 443),
            net("oauth2.googleapis.com", 443),
            net("storage.googleapis.com", 443),
        ]);
        assert_eq!(
            grants,
            vec![
                Grant::Network {
                    endpoint: endpoint("oauth2.googleapis.com", 443)
                },
                Grant::Network {
                    endpoint: endpoint("storage.googleapis.com", 443)
                },
            ],
            "duplicates collapse; no wildcard is invented"
        );
    }

    #[test]
    fn no_synthesized_network_grant_is_ever_a_wildcard() {
        // Rule 1, asserted as a property: a wildcard is broader than any
        // finite set of observations, so synthesize must never emit one.
        let grants = synthesized(vec![
            net("a.example.com", 443),
            net("b.example.com", 443),
            net("c.example.com", 80),
        ]);
        for grant in &grants {
            if let Grant::Network { endpoint } = grant {
                assert!(
                    !endpoint.is_wildcard(),
                    "{endpoint} widens the policy while claiming to narrow it"
                );
            }
        }
        assert_eq!(grants.len(), 3, "ports distinguish endpoints");
    }

    #[test]
    fn paths_narrow_to_the_observed_subtrees_not_the_whole_mount() {
        let grants = synthesized(vec![
            file("/workspace/src", Access::ReadWrite),
            file("/workspace/target", Access::ReadWrite),
            file("/workspace/src", Access::ReadWrite),
        ]);
        assert_eq!(
            grants,
            vec![
                Grant::Filesystem {
                    path: PathBuf::from("/workspace/src"),
                    access: Access::ReadWrite,
                },
                Grant::Filesystem {
                    path: PathBuf::from("/workspace/target"),
                    access: Access::ReadWrite,
                },
            ],
            "must not suggest /workspace, which was never touched directly"
        );
    }

    #[test]
    fn a_redundant_descendant_is_dropped_but_never_replaced_by_a_new_ancestor() {
        // Suggesting both /workspace and /workspace/src reads as two
        // permissions. Dropping the descendant is right; INVENTING a common
        // ancestor would violate rule 1.
        let grants = synthesized(vec![
            file("/workspace", Access::ReadWrite),
            file("/workspace/src/main.rs", Access::ReadWrite),
        ]);
        assert_eq!(
            grants,
            vec![Grant::Filesystem {
                path: PathBuf::from("/workspace"),
                access: Access::ReadWrite,
            }]
        );
    }

    #[test]
    fn sibling_paths_do_not_acquire_a_common_parent() {
        // The sharpest rule-1 case: /a/x and /a/y must NOT become /a.
        let grants = synthesized(vec![
            file("/a/x", Access::ReadOnly),
            file("/a/y", Access::ReadOnly),
        ]);
        let paths: Vec<&Path> = grants
            .iter()
            .filter_map(|g| match g {
                Grant::Filesystem { path, .. } => Some(path.as_path()),
                _ => None,
            })
            .collect();
        assert_eq!(paths, vec![Path::new("/a/x"), Path::new("/a/y")]);
        assert!(
            !paths.contains(&Path::new("/a")),
            "invented a parent nobody touched"
        );
    }

    #[test]
    fn a_tree_only_ever_read_yields_a_read_only_grant() {
        // The narrowing that matters most: read-write is the broadest
        // filesystem permission, so downgrading it on evidence is the point.
        let grants = synthesized(vec![
            file("/workspace/vendor", Access::ReadOnly),
            file("/workspace/vendor", Access::ReadOnly),
        ]);
        assert_eq!(
            grants,
            vec![Grant::Filesystem {
                path: PathBuf::from("/workspace/vendor"),
                access: Access::ReadOnly,
            }]
        );
    }

    #[test]
    fn reads_and_writes_on_one_tree_yield_separate_grants() {
        // A path read AND written needs the write grant; the read grant is
        // retained because the levels are tracked independently and collapsing
        // them is a decision for the caller, not a silent one here.
        let grants = synthesized(vec![
            file("/workspace/src", Access::ReadOnly),
            file("/workspace/src", Access::ReadWrite),
        ]);
        assert_eq!(grants.len(), 2, "both access levels were observed");
        assert!(grants.contains(&Grant::Filesystem {
            path: PathBuf::from("/workspace/src"),
            access: Access::ReadWrite,
        }));
    }

    // ---- the round trip: the property that makes this trustworthy --------

    #[test]
    fn everything_observed_is_still_permitted_by_what_was_synthesized() {
        // THE load-bearing property. A narrowing that breaks a working project
        // is worse than no narrowing, so a synthesized rule set must permit
        // every observation it was derived from. Checked by feeding the output
        // back through decide().
        let observed = vec![
            net("storage.googleapis.com", 443),
            net("registry.npmjs.org", 443),
            file("/workspace/src", Access::ReadWrite),
            file("/workspace/vendor", Access::ReadOnly),
            Request::Tool {
                name: "rust-analyzer".to_owned(),
            },
            Request::Port { guest: 3000 },
            Request::Secret {
                name: "aws".to_owned(),
            },
        ];
        let policy = Policy {
            tier: Tier::Allowlist,
            profile: Profile::Online,
            capabilities: Capabilities::all(),
            grants: synthesized(observed.clone()),
        };
        for request in &observed {
            let decision = decide(&policy, request);
            assert!(
                decision.is_allowed(),
                "synthesized policy refused an observation it came from: {request:?}"
            );
        }
        // And every category is exercised, so the property is not vacuous for
        // some variant.
        let mut covered: Vec<Category> = observed.iter().map(Request::category).collect();
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(covered, Category::ALL.to_vec());
    }

    #[test]
    fn what_was_synthesized_does_not_permit_a_neighbour_that_was_not_observed() {
        // The other half of trustworthiness: narrowing must actually narrow.
        let policy = Policy {
            tier: Tier::Allowlist,
            profile: Profile::Online,
            capabilities: Capabilities::all(),
            grants: synthesized(vec![net("storage.googleapis.com", 443)]),
        };
        for unobserved in [
            net("oauth2.googleapis.com", 443),
            net("storage.googleapis.com", 80),
            file("/etc/passwd", Access::ReadOnly),
        ] {
            assert!(
                !decide(&policy, &unobserved).is_allowed(),
                "{unobserved:?} was never observed and must not be permitted"
            );
        }
    }

    // ---- the categories with no breadth ----------------------------------

    #[test]
    fn tools_ports_and_secrets_are_emitted_exactly_and_deduplicated() {
        let grants = synthesized(vec![
            Request::Tool {
                name: "rust-analyzer".to_owned(),
            },
            Request::Tool {
                name: "rust-analyzer".to_owned(),
            },
            Request::Port { guest: 3000 },
            Request::Secret {
                name: "aws".to_owned(),
            },
        ]);
        assert_eq!(
            grants,
            vec![
                Grant::Tool {
                    name: "rust-analyzer".to_owned(),
                    kind: ToolKind::Lsp,
                    network: false,
                },
                Grant::Port {
                    guest: 3000,
                    host: 3000,
                },
                Grant::Secret {
                    name: "aws".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn a_synthesized_tool_grant_withholds_network_access() {
        // Observation cannot reveal whether a tool used the network: a
        // Request::Tool carries a name alone. Assuming it did would widen the
        // policy, so the conservative reading is the correct one.
        let grants = synthesized(vec![Request::Tool {
            name: "gopls".to_owned(),
        }]);
        assert_eq!(
            grants,
            vec![Grant::Tool {
                name: "gopls".to_owned(),
                kind: ToolKind::Lsp,
                network: false,
            }]
        );
    }

    #[test]
    fn observations_report_their_own_evidence() {
        let observations = Observations::new(vec![net("a.com", 443)], AMPLE);
        assert_eq!(observations.evidence(), AMPLE);
        assert!(!observations.is_empty());
    }
}
