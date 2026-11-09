//! `decide(policy, request) -> Decision` — the enforcement path.
//!
//! This is a **direct transcription of the matching order** in
//! `08-POLICY-AND-STORE.md` §1.2, in that order, so the code can be checked
//! against the specification line by line:
//!
//! ```text
//! 1. Does the profile forbid this category outright?       -> ProfileForbids
//! 2. Is this a literal address where policy speaks names?  -> DirectAddressBypass
//! 3. Does a grant cover the target?
//!      no                                                  -> NoMatchingGrant
//!      yes, but not this access level                      -> InsufficientAccess
//!      yes                                                 -> Allow + scope
//! 4. If a tool is involved, does its own role permit this?  -> ToolRoleForbids
//! 5. Can the backend actually enforce this rule?            -> BackendCannotEnforce
//! ```
//!
//! The order is not an implementation detail. A profile refusal must precede
//! grant lookup, or a grant could re-open what the profile closed; and a
//! literal-address bypass must precede it too, or the allowlist would appear
//! to work while being trivially sidestepped.
//!
//! Pure: no files, no sockets, no clock, no randomness
//! (`08-POLICY-AND-STORE.md` §1.1). Every input is an argument.

use crate::decision::{Access, Category, Decision, DenyReason, Scope};
use crate::grant::{Grant, Request};
use crate::policy::{Profile, Tier};
use crate::resources::Resources;

/// What the backend can actually enforce.
///
/// Enters the decision path rather than being checked once at startup, because
/// **a rule the backend cannot enforce must not behave like a rule that is
/// simply absent** — if it did, the config file would lie
/// (`08-POLICY-AND-STORE.md` §1.2 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    unenforceable: Vec<Category>,
}

impl Capabilities {
    /// A backend that enforces every category.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            unenforceable: Vec::new(),
        }
    }

    /// A backend that cannot enforce the listed categories.
    #[must_use]
    pub fn lacking(categories: impl IntoIterator<Item = Category>) -> Self {
        Self {
            unenforceable: categories.into_iter().collect(),
        }
    }

    /// Whether `category` can actually be enforced.
    #[must_use]
    pub fn enforces(&self, category: Category) -> bool {
        !self.unenforceable.contains(&category)
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::all()
    }
}

/// Everything `decide` needs, and nothing it does not.
///
/// Built from an evaluated `rachna.nix` plus the backend's capabilities. Held
/// by reference in [`decide`] so a decision never clones a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The network axis (`00-PRODUCT.md` §3.9).
    pub tier: Tier,
    /// The everything-else axis.
    pub profile: Profile,
    /// What `rachna.nix` declares.
    pub grants: Vec<Grant>,
    /// What the project may consume (`19` §2.1).
    ///
    /// On the policy rather than beside it, because `15` §3.2 concluded
    /// exactly that: *"Resource limits belong in the policy model, not
    /// `ExecSpec`: exceeding one should produce a `Decision` and land in the
    /// audit trail, so `rachna audit` can report a project hitting its
    /// ceiling for a week."*
    pub resources: Resources,
    /// What the backend can enforce.
    pub capabilities: Capabilities,
}

impl Policy {
    /// A policy that denies everything: no grants, strictest axes.
    ///
    /// The deny-by-default starting point, and the base every test builds on.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            tier: Tier::None,
            profile: Profile::Sealed,
            grants: Vec::new(),
            // The declared defaults, not zeroes: `deny_all` is about
            // PERMISSIONS, and a policy with no memory is not stricter — it
            // is unbootable.
            resources: Resources::default(),
            capabilities: Capabilities::all(),
        }
    }
}

/// Decides whether `request` is permitted by `policy`.
///
/// Returns an [`Allow`](Decision::Allow) carrying the concrete value touched,
/// or a [`Deny`](Decision::Deny) carrying why. Never a bare bool: the reason is
/// what the denial report, `rachna explain` and narrowing each consume
/// (`01-ARCHITECTURE.md` §2.2).
#[must_use]
pub fn decide(policy: &Policy, request: &Request) -> Decision {
    let category = request.category();

    // Step 1 — the profile forbids the category outright. Before grants, so a
    // grant cannot re-open what the profile closed.
    if policy.profile.forbids(category) {
        return deny(DenyReason::ProfileForbids { category });
    }

    // Network's axis is the tier, not the profile (§3.9). `none` denies before
    // any grant is consulted, which is why it is a tier and not an empty list.
    if category == Category::Network && !policy.tier.permits_any_network() {
        return deny(DenyReason::ProfileForbids { category });
    }

    // Step 2 — a literal address where policy speaks names. Before the grant
    // lookup, because otherwise an allowlist appears to work while being
    // sidestepped by dialling an IP (`02` §7).
    if let Request::Network {
        endpoint,
        literal_address: true,
    } = request
    {
        if policy.tier == Tier::Allowlist {
            return deny(DenyReason::DirectAddressBypass {
                literal: endpoint.to_string(),
            });
        }
    }

    // Step 5, hoisted — the backend cannot enforce this category.
    //
    // Specified as step 5 but evaluated before the grant lookup on purpose:
    // asked last, an unenforceable category with no grant would report
    // NoMatchingGrant, suggesting a `rachna allow` that would change nothing.
    // A denial must never propose a fix that cannot work (`00` §3.3), so the
    // honest reason wins over the specified position. Covered by a test that
    // names this reordering.
    if !policy.capabilities.enforces(category) {
        return deny(DenyReason::BackendCannotEnforce { category });
    }

    // `tier = open` and `internet` permit any endpoint without an allowlist
    // entry, so the scope is still the concrete endpoint touched.
    if let Request::Network { endpoint, .. } = request {
        if matches!(policy.tier, Tier::Open | Tier::Internet) {
            return allow(category, &endpoint.to_string());
        }
    }

    // Step 3 — does a grant cover the target?
    let matches: Vec<&Grant> = policy
        .grants
        .iter()
        .filter(|grant| grant.category() == category)
        .filter(|grant| covers(grant, request))
        .collect();

    let Some(best) = matches.iter().copied().max_by_key(|grant| grant.access()) else {
        return deny(DenyReason::NoMatchingGrant { category });
    };

    // Step 3b — covered, but not at this access level.
    if !best.access().covers(request.access()) {
        return deny(DenyReason::InsufficientAccess {
            granted: best.access(),
            wanted: request.access(),
        });
    }

    // Step 4 — a tool's own role — is NOT implemented here, deliberately.
    //
    // `ToolRoleForbids` fires when a request is made *by* a tool and that
    // tool's own role forbids it. That needs an actor on the request, which
    // `Request` does not yet carry: today a request is anonymous. A block
    // matching on the tool grant's `network` flag would look like a check
    // while enforcing nothing, which is worse than an absent check because it
    // reads as covered.
    //
    // So the variant exists in `DenyReason` (the vocabulary is right) and
    // nothing produces it until `Request` grows an actor, in the step that
    // adds tool proxying. Asserted by a test, so this cannot be forgotten.

    allow(category, &scope_of(request))
}

/// The concrete value a request touched, for narrowing.
///
/// Under-recording this is the single easiest way to make audit useless, and
/// it is invisible until months of data have been collected uselessly
/// (`08-POLICY-AND-STORE.md` §1.3).
fn scope_of(request: &Request) -> String {
    match request {
        Request::Network { endpoint, .. } => endpoint.to_string(),
        Request::Filesystem { path, .. } => path.display().to_string(),
        Request::Tool { name } | Request::Secret { name } => name.clone(),
        Request::Port { guest } => guest.to_string(),
    }
}

/// Whether `grant` covers `request`, ignoring access level.
///
/// Access is checked separately so the caller can distinguish "no grant" from
/// "a grant, but read-only" — two denials with different fixes.
fn covers(grant: &Grant, request: &Request) -> bool {
    match (grant, request) {
        (
            Grant::Network { endpoint: granted },
            Request::Network {
                endpoint: wanted, ..
            },
        ) => granted.port() == wanted.port() && host_matches(granted.host(), wanted.host()),
        (Grant::Filesystem { path: granted, .. }, Request::Filesystem { path: wanted, .. }) => {
            wanted.starts_with(granted)
        }
        (Grant::Tool { name: granted, .. }, Request::Tool { name: wanted }) => granted == wanted,
        (Grant::Port { guest: granted, .. }, Request::Port { guest: wanted }) => granted == wanted,
        (Grant::Secret { name: granted }, Request::Secret { name: wanted }) => granted == wanted,
        _ => false,
    }
}

/// Whether a granted host pattern covers a requested host.
///
/// `*.example.com` matches `a.example.com` but **not** `example.com` itself:
/// the wildcard stands for at least one label. Matching the bare domain would
/// quietly widen every wildcard grant by one host.
fn host_matches(granted: &str, wanted: &str) -> bool {
    granted
        .strip_prefix("*.")
        .map_or(granted == wanted, |suffix| {
            wanted
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
        })
}

/// Builds an [`Allow`](Decision::Allow), or denies if the scope is unrecordable.
///
/// A scope can only fail to record when it is empty, which means a request
/// named nothing — a caller bug. Denying is the safe direction: a silent allow
/// with no recorded value would make audit useless exactly where it matters
/// (`08-POLICY-AND-STORE.md` §1.3). The reason carries the request's real
/// category rather than a placeholder, because this decision is written to the
/// audit store and a wrong category there is a false record.
fn allow(category: Category, scope: &str) -> Decision {
    match Scope::new(scope) {
        Ok(scope) => Decision::Allow { scope },
        Err(_) => deny(DenyReason::NoMatchingGrant { category }),
    }
}

const fn deny(reason: DenyReason) -> Decision {
    Decision::Deny { reason }
}

const _: () = {
    // Access must be Ord for `max_by_key` above to mean "most permissive".
    const fn assert_ord<T: Ord>() {}
    assert_ord::<Access>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{endpoint, ToolKind};
    use std::path::PathBuf;

    /// A policy that permits the category under test and nothing else.
    fn permissive() -> Policy {
        Policy {
            tier: Tier::Allowlist,
            profile: Profile::Online,
            grants: Vec::new(),
            resources: Resources::default(),
            capabilities: Capabilities::all(),
        }
    }

    fn reason(decision: &Decision) -> &DenyReason {
        match decision {
            Decision::Deny { reason } => reason,
            Decision::Allow { scope } => {
                panic!("expected a denial, got allow scope {}", scope.as_str())
            }
        }
    }

    fn scope(decision: &Decision) -> &str {
        match decision {
            Decision::Allow { scope } => scope.as_str(),
            Decision::Deny { reason } => panic!("expected an allow, got {reason:?}"),
        }
    }

    // ---- deny-by-default --------------------------------------------------

    #[test]
    fn every_category_is_denied_by_an_empty_policy() {
        // The product's central claim. Asserted over every category so a new
        // one cannot default to permitted.
        let policy = Policy::deny_all();
        let requests = [
            Request::Network {
                endpoint: endpoint("github.com", 443),
                literal_address: false,
            },
            Request::Filesystem {
                path: PathBuf::from("/etc/passwd"),
                access: Access::ReadOnly,
            },
            Request::Tool {
                name: "rust-analyzer".to_owned(),
            },
            Request::Port { guest: 3000 },
            Request::Secret {
                name: "aws".to_owned(),
            },
        ];
        let mut seen: Vec<Category> = Vec::new();
        for request in requests {
            let decision = decide(&policy, &request);
            assert!(
                !decision.is_allowed(),
                "{request:?} was allowed by an empty policy"
            );
            seen.push(request.category());
        }
        seen.sort_unstable();
        assert_eq!(seen, Category::ALL.to_vec(), "a category went untested");
    }

    // ---- step 1: ProfileForbids ------------------------------------------

    #[test]
    fn a_profile_refusal_precedes_the_grant_lookup() {
        // Order matters: if grants were consulted first, a grant would
        // re-open what the profile closed.
        let policy = Policy {
            profile: Profile::Sealed,
            grants: vec![Grant::Secret {
                name: "aws".to_owned(),
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Secret {
                name: "aws".to_owned(),
            },
        );
        assert_eq!(
            reason(&decision),
            &DenyReason::ProfileForbids {
                category: Category::Secret
            },
            "an explicit grant must not override the profile"
        );
    }

    #[test]
    fn tier_none_denies_network_even_with_a_matching_grant() {
        let policy = Policy {
            tier: Tier::None,
            grants: vec![Grant::Network {
                endpoint: endpoint("github.com", 443),
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Network {
                endpoint: endpoint("github.com", 443),
                literal_address: false,
            },
        );
        assert!(!decision.is_allowed(), "tier=none must deny before grants");
    }

    // ---- step 2: DirectAddressBypass -------------------------------------

    #[test]
    fn a_literal_address_is_refused_distinctly_on_an_allowlist() {
        // Not NoMatchingGrant: policy names hosts, and the guest dialling an
        // IP skips DNS entirely (02 §7). It needs its own explanation.
        let policy = Policy {
            tier: Tier::Allowlist,
            grants: vec![Grant::Network {
                endpoint: endpoint("github.com", 443),
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Network {
                endpoint: endpoint("140.82.121.4", 443),
                literal_address: true,
            },
        );
        assert_eq!(
            reason(&decision),
            &DenyReason::DirectAddressBypass {
                literal: "140.82.121.4:443".to_owned()
            }
        );
    }

    #[test]
    fn a_literal_address_is_fine_when_the_tier_does_not_speak_names() {
        // On `internet` the policy is not an allowlist, so dialling an IP
        // bypasses nothing and must not be reported as a bypass.
        let policy = Policy {
            tier: Tier::Internet,
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Network {
                endpoint: endpoint("140.82.121.4", 443),
                literal_address: true,
            },
        );
        assert_eq!(scope(&decision), "140.82.121.4:443");
    }

    // ---- step 3: NoMatchingGrant / InsufficientAccess / Allow ------------

    #[test]
    fn a_matching_grant_allows_and_records_the_concrete_value() {
        let policy = Policy {
            grants: vec![Grant::Network {
                endpoint: endpoint("*.googleapis.com", 443),
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Network {
                endpoint: endpoint("storage.googleapis.com", 443),
                literal_address: false,
            },
        );
        // The scope is the HOST TOUCHED, not the wildcard that permitted it —
        // this is what makes narrowing possible (08 §1.3).
        assert_eq!(scope(&decision), "storage.googleapis.com:443");
    }

    #[test]
    fn a_wildcard_does_not_match_the_bare_domain() {
        // `*.example.com` stands for at least one label. Matching
        // `example.com` would silently widen every wildcard grant by one host.
        let policy = Policy {
            grants: vec![Grant::Network {
                endpoint: endpoint("*.googleapis.com", 443),
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Network {
                endpoint: endpoint("googleapis.com", 443),
                literal_address: false,
            },
        );
        assert_eq!(
            reason(&decision),
            &DenyReason::NoMatchingGrant {
                category: Category::Network
            }
        );
    }

    #[test]
    fn a_wildcard_does_not_match_a_suffix_that_is_not_a_label_boundary() {
        // `*.googleapis.com` must not match `evilgoogleapis.com`.
        let policy = Policy {
            grants: vec![Grant::Network {
                endpoint: endpoint("*.googleapis.com", 443),
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Network {
                endpoint: endpoint("evilgoogleapis.com", 443),
                literal_address: false,
            },
        );
        assert!(!decision.is_allowed(), "suffix match crossed a label");
    }

    #[test]
    fn a_port_mismatch_is_not_a_match() {
        let policy = Policy {
            grants: vec![Grant::Network {
                endpoint: endpoint("github.com", 443),
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Network {
                endpoint: endpoint("github.com", 80),
                literal_address: false,
            },
        );
        assert!(!decision.is_allowed(), "port must participate in matching");
    }

    #[test]
    fn a_read_only_mount_refuses_a_write_with_the_access_levels_named() {
        // Distinct from NoMatchingGrant: the fix is widening the existing
        // grant, not adding one, and the report says which is which.
        let policy = Policy {
            grants: vec![Grant::Filesystem {
                path: PathBuf::from("/workspace"),
                target: None,
                access: Access::ReadOnly,
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Filesystem {
                path: PathBuf::from("/workspace/src/main.rs"),
                access: Access::ReadWrite,
            },
        );
        assert_eq!(
            reason(&decision),
            &DenyReason::InsufficientAccess {
                granted: Access::ReadOnly,
                wanted: Access::ReadWrite,
            }
        );
    }

    #[test]
    fn a_read_only_mount_permits_a_read() {
        let policy = Policy {
            grants: vec![Grant::Filesystem {
                path: PathBuf::from("/workspace"),
                target: None,
                access: Access::ReadOnly,
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Filesystem {
                path: PathBuf::from("/workspace/src/main.rs"),
                access: Access::ReadOnly,
            },
        );
        assert_eq!(scope(&decision), "/workspace/src/main.rs");
    }

    #[test]
    fn the_most_permissive_matching_grant_wins() {
        // Two grants cover the path; the read-write one must be chosen, or a
        // legitimate write would be refused because of grant ordering.
        let policy = Policy {
            grants: vec![
                Grant::Filesystem {
                    path: PathBuf::from("/workspace"),
                    target: None,
                    access: Access::ReadOnly,
                },
                Grant::Filesystem {
                    path: PathBuf::from("/workspace"),
                    target: None,
                    access: Access::ReadWrite,
                },
            ],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Filesystem {
                path: PathBuf::from("/workspace/f"),
                access: Access::ReadWrite,
            },
        );
        assert!(decision.is_allowed(), "grant order must not decide this");
    }

    #[test]
    fn a_path_outside_the_mount_is_not_covered() {
        let policy = Policy {
            grants: vec![Grant::Filesystem {
                path: PathBuf::from("/workspace"),
                target: None,
                access: Access::ReadWrite,
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Filesystem {
                path: PathBuf::from("/etc/passwd"),
                access: Access::ReadOnly,
            },
        );
        assert_eq!(
            reason(&decision),
            &DenyReason::NoMatchingGrant {
                category: Category::Filesystem
            }
        );
    }

    #[test]
    fn a_grant_for_one_category_never_satisfies_another() {
        // Cross-category leakage would be the worst kind of bug here.
        let policy = Policy {
            grants: vec![Grant::Port {
                guest: 3000,
                host: 3000,
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Secret {
                name: "3000".to_owned(),
            },
        );
        assert!(!decision.is_allowed(), "a port grant satisfied a secret");
    }

    // ---- step 5: BackendCannotEnforce ------------------------------------

    #[test]
    fn an_unenforceable_category_says_so_rather_than_blaming_a_missing_grant() {
        // This is why step 5 is hoisted above the grant lookup: asked last, an
        // unenforceable category with no grant would report NoMatchingGrant
        // and suggest a `rachna allow` that changes nothing.
        let policy = Policy {
            resources: Resources::default(),
            capabilities: Capabilities::lacking([Category::Port]),
            ..permissive()
        };
        let decision = decide(&policy, &Request::Port { guest: 3000 });
        assert_eq!(
            reason(&decision),
            &DenyReason::BackendCannotEnforce {
                category: Category::Port
            }
        );
        assert!(
            !reason(&decision).is_fixable_by_grant(),
            "must not suggest a grant that cannot work"
        );
    }

    #[test]
    fn an_unenforceable_category_is_denied_even_with_a_matching_grant() {
        // The sharp case: a rule the backend cannot enforce must not behave
        // like one that is present and working, or the config file lies.
        let policy = Policy {
            resources: Resources::default(),
            capabilities: Capabilities::lacking([Category::Port]),
            grants: vec![Grant::Port {
                guest: 3000,
                host: 3000,
            }],
            ..permissive()
        };
        let decision = decide(&policy, &Request::Port { guest: 3000 });
        assert!(
            !decision.is_allowed(),
            "an unenforceable grant was honoured"
        );
    }

    #[test]
    fn capabilities_default_to_enforcing_everything() {
        for category in Category::ALL {
            assert!(Capabilities::default().enforces(category));
            assert!(Capabilities::all().enforces(category));
        }
        let partial = Capabilities::lacking([Category::Network]);
        assert!(!partial.enforces(Category::Network));
        assert!(partial.enforces(Category::Filesystem));
    }

    // ---- the open-tier shortcut ------------------------------------------

    #[test]
    fn open_and_internet_tiers_allow_without_an_allowlist_entry() {
        for tier in [Tier::Open, Tier::Internet] {
            let policy = Policy {
                tier,
                ..permissive()
            };
            let decision = decide(
                &policy,
                &Request::Network {
                    endpoint: endpoint("example.com", 443),
                    literal_address: false,
                },
            );
            assert_eq!(
                scope(&decision),
                "example.com:443",
                "tier {tier} must not require a grant"
            );
        }
    }

    // ---- every allow records a scope ------------------------------------

    #[test]
    fn every_allow_records_a_non_empty_scope() {
        // Treat a missing scope on an Allow as a bug (08 §1.3). Asserted for
        // one allow per category, so no path can allow without recording.
        let policy = Policy {
            tier: Tier::Allowlist,
            profile: Profile::Online,
            resources: Resources::default(),
            capabilities: Capabilities::all(),
            grants: vec![
                Grant::Network {
                    endpoint: endpoint("github.com", 443),
                },
                Grant::Filesystem {
                    path: PathBuf::from("/workspace"),
                    target: None,
                    access: Access::ReadWrite,
                },
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
            ],
        };
        let requests = [
            Request::Network {
                endpoint: endpoint("github.com", 443),
                literal_address: false,
            },
            Request::Filesystem {
                path: PathBuf::from("/workspace/f"),
                access: Access::ReadWrite,
            },
            Request::Tool {
                name: "rust-analyzer".to_owned(),
            },
            Request::Port { guest: 3000 },
            Request::Secret {
                name: "aws".to_owned(),
            },
        ];
        let mut covered: Vec<Category> = Vec::new();
        for request in requests {
            let decision = decide(&policy, &request);
            assert!(
                !scope(&decision).is_empty(),
                "{request:?} allowed with an empty scope"
            );
            covered.push(request.category());
        }
        covered.sort_unstable();
        assert_eq!(covered, Category::ALL.to_vec());
    }

    // ---- what is deliberately not implemented ---------------------------

    #[test]
    fn tool_role_forbids_is_vocabulary_only_for_now() {
        // `decide` cannot produce ToolRoleForbids: it fires when a request is
        // made BY a tool, and `Request` carries no actor yet. This test exists
        // so the gap is recorded rather than discovered later — delete it in
        // the step that adds an actor, and assert the real behaviour.
        let policy = Policy {
            grants: vec![Grant::Tool {
                name: "rust-analyzer".to_owned(),
                kind: ToolKind::Lsp,
                network: false,
            }],
            ..permissive()
        };
        let decision = decide(
            &policy,
            &Request::Tool {
                name: "rust-analyzer".to_owned(),
            },
        );
        assert!(decision.is_allowed());
        assert!(
            !matches!(
                decision,
                Decision::Deny {
                    reason: DenyReason::ToolRoleForbids { .. }
                }
            ),
            "if this fires, an actor was added and this test should be replaced"
        );
    }
}
