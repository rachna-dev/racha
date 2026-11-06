//! A permission answer is an event, not a boolean.
//!
//! The broker's API cannot be `fn allow(req) -> bool`. It must return a
//! [`Decision`] carrying the matched rule, what was touched within that rule's
//! scope, why a denial happened, and the narrowest grant that would have
//! allowed it. Getting this wrong means retrofitting attribution through every
//! call site later (design-docs/00-PRODUCT.md §9.1).
//!
//! Two fields earn their keep specifically:
//!
//! - [`Decision::scope`] is what makes *narrowing* possible rather than just
//!   revoking. Knowing a `*.googleapis.com` grant was only ever used for two
//!   concrete hosts is what lets audit propose the tighter rule.
//! - [`Decision::suggestion`] is why denial reports need no separate reporting
//!   pass: the engine already computed the narrowest matching rule, so it
//!   should say so.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::GrantId;
use crate::spec::{Grant, Profile};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
}

impl Verdict {
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

/// The engine's answer to one [`crate::Request`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    /// Which grant permitted this, for usage attribution. `None` on denial.
    pub matched: Option<GrantId>,
    /// What specifically was touched within the matched grant's scope. This is
    /// the raw material for narrowing suggestions.
    pub scope: Option<Scope>,
    pub reason: DenyReason,
    /// The narrowest grant that would have allowed this request.
    ///
    /// Always the tightest rule that works — exactly `registry.npmjs.org:443`,
    /// never `*.npmjs.org`, never "allow all network"
    /// (design-docs/00-PRODUCT.md §3.3).
    pub suggestion: Option<Grant>,
}

impl Decision {
    /// An allow, attributed to the grant that permitted it.
    #[must_use]
    pub fn allow(matched: GrantId, scope: Scope) -> Self {
        Self {
            verdict: Verdict::Allow,
            matched: Some(matched),
            scope: Some(scope),
            reason: DenyReason::NotDenied,
            suggestion: None,
        }
    }

    /// A denial, carrying why and what would fix it.
    #[must_use]
    pub fn deny(reason: DenyReason, suggestion: Option<Grant>) -> Self {
        Self {
            verdict: Verdict::Deny,
            matched: None,
            scope: None,
            reason,
            suggestion,
        }
    }

    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.verdict.is_allowed()
    }
}

/// What was actually touched within a grant's scope.
///
/// A grant can be broader than any single use of it. Recording the concrete
/// value per decision is what later lets audit say "this wildcard was only ever
/// two hosts" or "all writes were under ./src".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// The concrete host contacted under a possibly-wildcard grant.
    Host(String),
    /// The concrete path touched under a directory mount.
    Path(String),
    /// Nothing narrower than the grant itself — a port forward or a device is
    /// already as specific as it gets.
    Exact,
}

/// Why a request was denied. Drives both `rachna explain` and the phrasing of
/// the suggestion in a denial report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    /// Placeholder on allows, so [`Decision`] needs no `Option<DenyReason>`.
    NotDenied,
    /// Nothing in the policy speaks to this request. The default outcome:
    /// deny unless explicitly granted.
    NoMatchingGrant,
    /// A grant covers the target but not this level of access — e.g. a write
    /// to a read-only mount.
    InsufficientAccess { grant: GrantId },
    /// The current profile forbids this category outright. Worth distinguishing
    /// so the report can teach the profile model instead of just suggesting
    /// another ad-hoc grant: "`development` would allow this; you're on
    /// `sealed`" (design-docs/00-PRODUCT.md §3.3).
    ProfileForbids { profile: Profile },
    /// The guest connected to a literal address where policy is expressed as
    /// hostnames. Denied rather than resolved, because a hostname allowlist
    /// that trusts guest-side DNS is not an enforcement boundary
    /// (idea.md §10.3).
    DirectAddressBypass { address: String },
    /// A declared tool was invoked, but its own scoped role forbids this —
    /// e.g. a language server with `network = false` trying to dial out.
    ToolRoleForbids { tool: String },
    /// The backend cannot enforce what the policy asks for. Rachna refuses
    /// rather than silently downgrading security (idea.md §16.2).
    BackendCannotEnforce { capability: String },
}

impl fmt::Display for DenyReason {
    /// Human phrasing used directly in denial reports and `rachna explain`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDenied => f.write_str("allowed"),
            Self::NoMatchingGrant => f.write_str("no matching grant in rachna.nix"),
            Self::InsufficientAccess { grant } => {
                write!(f, "grant {grant} does not permit this access level")
            }
            Self::ProfileForbids { profile } => {
                write!(f, "profile \"{profile}\" forbids this category")
            }
            Self::DirectAddressBypass { address } => write!(
                f,
                "connected directly to {address}; policy is expressed as hostnames"
            ),
            Self::ToolRoleForbids { tool } => {
                write!(f, "tool \"{tool}\" is not permitted to do this")
            }
            Self::BackendCannotEnforce { capability } => {
                write!(f, "backend cannot enforce {capability}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Proto;

    #[test]
    fn allow_is_attributed_to_a_grant() {
        let grant = Grant::Network {
            host: "*.googleapis.com".to_owned(),
            port: 443,
            proto: Proto::Tcp,
        };
        let decision =
            Decision::allow(grant.id(), Scope::Host("storage.googleapis.com".to_owned()));

        assert!(decision.is_allowed());
        assert_eq!(decision.matched, Some(grant.id()));
        // The concrete host, not the wildcard — this is what narrowing needs.
        assert_eq!(
            decision.scope,
            Some(Scope::Host("storage.googleapis.com".to_owned()))
        );
    }

    #[test]
    fn denial_carries_the_narrowest_fix() {
        let suggestion = Grant::Network {
            host: "registry.npmjs.org".to_owned(),
            port: 443,
            proto: Proto::Tcp,
        };
        let decision = Decision::deny(DenyReason::NoMatchingGrant, Some(suggestion.clone()));

        assert!(!decision.is_allowed());
        assert!(decision.matched.is_none());
        assert_eq!(decision.suggestion, Some(suggestion));
    }

    #[test]
    fn deny_reasons_read_as_report_lines() {
        assert_eq!(
            DenyReason::NoMatchingGrant.to_string(),
            "no matching grant in rachna.nix"
        );
        assert_eq!(
            DenyReason::ProfileForbids {
                profile: Profile::Sealed
            }
            .to_string(),
            "profile \"sealed\" forbids this category"
        );
        assert_eq!(
            DenyReason::DirectAddressBypass {
                address: "140.82.112.3:443".to_owned()
            }
            .to_string(),
            "connected directly to 140.82.112.3:443; policy is expressed as hostnames"
        );
    }
}
