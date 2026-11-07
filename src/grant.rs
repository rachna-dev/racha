//! What a `rachna.nix` permits, and what a running project asks for.
//!
//! # Why these are enums over categories rather than one struct
//!
//! The grant syntax in `19-RACHNA-NIX-SURFACE.md` §2 is genuinely different
//! per category — a host-and-port string, a mount record with an access level,
//! a port triple, a tool name with a role. One struct covering all of them
//! would carry a field per category with most unset, and "a network grant with
//! a mount target" would be representable. A sum type makes those states
//! impossible instead (`AGENTS.md`, "make illegal states unrepresentable").
//!
//! # Matching is a separate concern
//!
//! These types model *what was declared* and *what was asked*. Deciding
//! whether one covers the other is `decide()`'s job, which keeps this module
//! pure data and lets the decision logic be tested against a table.

use crate::decision::{Access, Category};
use core::fmt;
use std::path::PathBuf;

/// A network endpoint: a host pattern and a port.
///
/// Parsed from `"registry.npmjs.org:443"`. The host is kept as written,
/// including a leading `*.`, because a grant's breadth is exactly what audit
/// narrows (`08-POLICY-AND-STORE.md` §1.4) and rewriting it here would lose
/// the thing being narrowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    /// Builds an endpoint from a host pattern and port.
    ///
    /// # Errors
    ///
    /// [`EndpointError::EmptyHost`] if `host` is empty. An empty host would
    /// match either everything or nothing depending on the matcher, and both
    /// readings are dangerous in a policy file.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, EndpointError> {
        let host = host.into();
        if host.is_empty() {
            return Err(EndpointError::EmptyHost);
        }
        Ok(Self { host, port })
    }

    /// The host pattern, exactly as declared.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the host is a wildcard pattern such as `*.googleapis.com`.
    ///
    /// Wildcard collapse is the headline narrowing case
    /// (`08-POLICY-AND-STORE.md` §1.4), so audit needs to recognise one
    /// without re-parsing the string at each call site.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.host.starts_with("*.")
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why an [`Endpoint`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    /// The host was empty, which no matcher can read unambiguously.
    EmptyHost,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyHost => f.write_str("a network endpoint must name a host"),
        }
    }
}

impl core::error::Error for EndpointError {}

/// What kind of protocol a declared tool speaks.
///
/// A closed set, because derivation from declared packages (`20` §4.2b) only
/// suggests exposures for kinds Rachna understands how to proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ToolKind {
    /// Language Server Protocol.
    Lsp,
    /// A formatter: stdin to stdout.
    Formatter,
    /// Debug Adapter Protocol.
    Debugger,
}

impl ToolKind {
    /// Every tool kind.
    pub const ALL: [Self; 3] = [Self::Lsp, Self::Formatter, Self::Debugger];

    /// The word used in `rachna.nix`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lsp => "lsp",
            Self::Formatter => "formatter",
            Self::Debugger => "debugger",
        }
    }
}

impl fmt::Display for ToolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One permission, as declared in `rachna.nix`.
///
/// Every variant's category is recoverable via [`Self::category`], so the
/// matching order in `08-POLICY-AND-STORE.md` §1.2 can filter by category
/// without a parallel mapping that could drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// `network.allow = [ "registry.npmjs.org:443" ]`.
    Network { endpoint: Endpoint },
    /// `filesystem.mounts = [ { source = ./.; access = "read-write"; } ]`.
    Filesystem { path: PathBuf, access: Access },
    /// `tools.expose = [ { name = "rust-analyzer"; kind = "lsp"; } ]`.
    Tool {
        name: String,
        kind: ToolKind,
        /// Whether the tool itself may reach the network. Separate from the
        /// project's own tier: a tool is a distinct principal
        /// (`00-PRODUCT.md` §11.2).
        network: bool,
    },
    /// `ports = [ { guest = 3000; host = 3000; } ]`.
    Port { guest: u16, host: u16 },
    /// A named credential, supplied to the guest as a placeholder.
    ///
    /// Holds no secret value: the host substitutes the real token, and the
    /// guest never sees it (`00-PRODUCT.md` §3.6). A `Grant` is written to the
    /// audit store, so a secret in this type would be a secret on disk.
    Secret { name: String },
}

impl Grant {
    /// Which category this grant speaks to.
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
            Self::Network { .. } => Category::Network,
            Self::Filesystem { .. } => Category::Filesystem,
            Self::Tool { .. } => Category::Tool,
            Self::Port { .. } => Category::Port,
            Self::Secret { .. } => Category::Secret,
        }
    }

    /// The access level this grant confers.
    ///
    /// Only filesystem grants distinguish read from write; the rest are
    /// all-or-nothing and report [`Access::ReadWrite`] because being granted
    /// at all is full use of that capability.
    #[must_use]
    pub const fn access(&self) -> Access {
        match self {
            Self::Filesystem { access, .. } => *access,
            Self::Network { .. } | Self::Tool { .. } | Self::Port { .. } | Self::Secret { .. } => {
                Access::ReadWrite
            }
        }
    }
}

/// What a running project is asking to do.
///
/// Deliberately **not** `Grant`: a request is a concrete act, where a grant may
/// be a pattern. `*.googleapis.com:443` is a legitimate grant and never a
/// legitimate request, and keeping them distinct means a pattern cannot be
/// mistaken for something that happened — which is what audit's scope
/// recording depends on (`08` §1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Reaching a network address.
    Network {
        endpoint: Endpoint,
        /// Set when the guest dialled a literal address rather than a name.
        ///
        /// Carried on the request because a hostname allowlist that resolves
        /// on the guest's behalf is not a boundary — the guest can dial an IP
        /// and skip DNS (`02` §7). This is what
        /// [`crate::decision::DenyReason::DirectAddressBypass`] reports.
        literal_address: bool,
    },
    /// Touching a host path at a given access level.
    Filesystem { path: PathBuf, access: Access },
    /// Invoking a declared tool.
    Tool { name: String },
    /// Binding a port in the guest.
    Port { guest: u16 },
    /// Reading a credential placeholder.
    Secret { name: String },
}

impl Request {
    /// Which category this request falls under.
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
            Self::Network { .. } => Category::Network,
            Self::Filesystem { .. } => Category::Filesystem,
            Self::Tool { .. } => Category::Tool,
            Self::Port { .. } => Category::Port,
            Self::Secret { .. } => Category::Secret,
        }
    }

    /// The access level this request needs.
    #[must_use]
    pub const fn access(&self) -> Access {
        match self {
            Self::Filesystem { access, .. } => *access,
            Self::Network { .. } | Self::Tool { .. } | Self::Port { .. } | Self::Secret { .. } => {
                Access::ReadWrite
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(host: &str, port: u16) -> Endpoint {
        Endpoint::new(host, port).expect("test endpoints are non-empty")
    }

    /// One grant of every variant, so adding a variant fails to compile here.
    fn every_grant() -> Vec<Grant> {
        let all = vec![
            Grant::Network {
                endpoint: endpoint("registry.npmjs.org", 443),
            },
            Grant::Filesystem {
                path: PathBuf::from("/workspace"),
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
        ];
        for grant in &all {
            match grant {
                Grant::Network { .. }
                | Grant::Filesystem { .. }
                | Grant::Tool { .. }
                | Grant::Port { .. }
                | Grant::Secret { .. } => {}
            }
        }
        all
    }

    /// One request of every variant.
    fn every_request() -> Vec<Request> {
        let all = vec![
            Request::Network {
                endpoint: endpoint("registry.npmjs.org", 443),
                literal_address: false,
            },
            Request::Filesystem {
                path: PathBuf::from("/workspace/src/main.rs"),
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
        for request in &all {
            match request {
                Request::Network { .. }
                | Request::Filesystem { .. }
                | Request::Tool { .. }
                | Request::Port { .. }
                | Request::Secret { .. } => {}
            }
        }
        all
    }

    #[test]
    fn grants_and_requests_cover_every_category_exactly_once() {
        // decide() filters candidate grants by category, so a category with no
        // grant variant would be permanently un-grantable and one with two
        // would be ambiguous. This is the invariant that makes the §1.2
        // matching order total.
        let mut from_grants: Vec<Category> = every_grant().iter().map(Grant::category).collect();
        from_grants.sort_unstable();
        assert_eq!(from_grants, Category::ALL.to_vec());

        let mut from_requests: Vec<Category> =
            every_request().iter().map(Request::category).collect();
        from_requests.sort_unstable();
        assert_eq!(from_requests, Category::ALL.to_vec());
    }

    #[test]
    fn only_filesystem_distinguishes_read_from_write() {
        // Every other category is all-or-nothing, so reporting anything but
        // ReadWrite would make Access::covers reject a legitimate request.
        for grant in every_grant() {
            if grant.category() == Category::Filesystem {
                continue;
            }
            assert_eq!(
                grant.access(),
                Access::ReadWrite,
                "{grant:?} is all-or-nothing and must report ReadWrite"
            );
        }
        for request in every_request() {
            if request.category() == Category::Filesystem {
                continue;
            }
            assert_eq!(request.access(), Access::ReadWrite, "{request:?}");
        }
    }

    #[test]
    fn a_filesystem_grant_reports_the_access_it_was_given() {
        // Guards against access() returning a constant, which would silently
        // turn every read-only mount into read-write.
        for access in [Access::ReadOnly, Access::ReadWrite] {
            let grant = Grant::Filesystem {
                path: PathBuf::from("/workspace"),
                access,
            };
            assert_eq!(grant.access(), access);
            let request = Request::Filesystem {
                path: PathBuf::from("/workspace/f"),
                access,
            };
            assert_eq!(request.access(), access);
        }
    }

    #[test]
    fn an_endpoint_must_name_a_host() {
        // An empty host matches everything or nothing depending on the
        // matcher, and both readings are dangerous in a policy file.
        assert_eq!(Endpoint::new("", 443), Err(EndpointError::EmptyHost));
    }

    #[test]
    fn the_empty_host_error_explains_itself() {
        let message = EndpointError::EmptyHost.to_string();
        assert!(message.contains("host"), "{message:?}");
    }

    #[test]
    fn an_endpoint_preserves_the_host_as_written() {
        // Audit narrows a grant's breadth, so rewriting or normalising the
        // pattern here would destroy the thing being narrowed (08 §1.4).
        let wildcard = endpoint("*.googleapis.com", 443);
        assert_eq!(wildcard.host(), "*.googleapis.com");
        assert_eq!(wildcard.port(), 443);
        assert_eq!(wildcard.to_string(), "*.googleapis.com:443");
    }

    #[test]
    fn wildcards_are_recognised_only_by_a_leading_star_dot() {
        assert!(endpoint("*.googleapis.com", 443).is_wildcard());
        assert!(!endpoint("storage.googleapis.com", 443).is_wildcard());
        // Not a wildcard: a star elsewhere is a literal character in a
        // hostname, not the pattern we support collapsing.
        assert!(!endpoint("api.*.com", 443).is_wildcard());
        assert!(!endpoint("*", 443).is_wildcard());
    }

    #[test]
    fn endpoints_differing_only_by_port_are_distinct() {
        // A grant for :443 must not satisfy a request for :80, so the port
        // has to participate in equality.
        assert_ne!(endpoint("github.com", 443), endpoint("github.com", 80));
    }

    #[test]
    fn a_literal_address_request_is_distinguishable() {
        // The DirectAddressBypass denial depends on this flag surviving from
        // the request into decide(): policy names hosts, but the guest can
        // dial an IP and skip DNS entirely (02 §7).
        let dialled_name = Request::Network {
            endpoint: endpoint("github.com", 443),
            literal_address: false,
        };
        let dialled_ip = Request::Network {
            endpoint: endpoint("140.82.121.4", 443),
            literal_address: true,
        };
        assert_ne!(dialled_name, dialled_ip);
        match dialled_ip {
            Request::Network {
                literal_address, ..
            } => assert!(literal_address),
            _ => panic!("constructed a network request"),
        }
    }

    #[test]
    fn tool_kinds_are_distinct_and_pinned() {
        let mut names: Vec<&str> = ToolKind::ALL.iter().map(|k| k.as_str()).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "two tool kinds share a name");
        // Pinned: these appear in rachna.nix.
        assert_eq!(ToolKind::Lsp.as_str(), "lsp");
        for kind in ToolKind::ALL {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    #[test]
    fn a_tools_network_access_is_independent_of_its_kind() {
        // A tool is a distinct principal (00 §11.2): two grants for the same
        // tool differing only in network access are different permissions.
        let offline = Grant::Tool {
            name: "rust-analyzer".to_owned(),
            kind: ToolKind::Lsp,
            network: false,
        };
        let online = Grant::Tool {
            name: "rust-analyzer".to_owned(),
            kind: ToolKind::Lsp,
            network: true,
        };
        assert_ne!(offline, online);
    }

    #[test]
    fn a_secret_grant_carries_no_secret_value() {
        // Structural: Grant::Secret holds only a name. A Grant is written to
        // the audit store, so a value here would be a credential on disk
        // (00 §3.6).
        let grant = Grant::Secret {
            name: "aws".to_owned(),
        };
        match grant {
            Grant::Secret { name } => assert_eq!(name, "aws"),
            _ => panic!("constructed a secret grant"),
        }
    }
}
