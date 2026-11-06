//! What the guest is trying to do.
//!
//! A [`Request`] is the input to the policy engine. It carries the process
//! *chain* rather than a single process name, because a parent's identity does
//! not prove the intent of the code that actually opened the connection
//! (idea.md §10.4) — but the chain is what tells a developer "that's a build
//! script, not npm itself" (design-docs/00-PRODUCT.md §3.3).

use std::fmt;

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::RunId;

/// One attempted operation, as observed by the broker.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    /// The run this attempt belongs to. Denials are accumulated per run so a
    /// command that touches six blocked things reports all six at once.
    pub run: RunId,
    pub kind: RequestKind,
    pub process: ProcessChain,
    pub at: OffsetDateTime,
}

/// The permission taxonomy, as a request.
///
/// Mirrors the policy categories in [`crate::spec::PolicySpec`]: every category
/// a config can speak about must be expressible as a request, or it cannot be
/// enforced or audited.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestKind {
    Network {
        host: String,
        port: u16,
        proto: Proto,
        /// Set when the guest connected to a literal address rather than
        /// resolving a name. Policy must treat this differently: a hostname
        /// allowlist that trusts DNS is not an enforcement boundary
        /// (idea.md §10.3).
        resolved_from_dns: bool,
    },
    FileSystem {
        path: Utf8PathBuf,
        access: FsAccess,
    },
    /// A host port being opened on the guest's behalf.
    PortForward {
        guest: u16,
        host: u16,
        bind: String,
    },
    /// Invoking a tool exposed to the host, e.g. an editor spawning an LSP.
    /// Denials here join the same report as everything else
    /// (design-docs/00-PRODUCT.md §6.4).
    Tool {
        name: String,
    },
    /// Reading a host environment variable.
    EnvVar {
        name: String,
    },
    /// A brokered secret, by logical name rather than value.
    Secret {
        name: String,
    },
    /// A host IPC endpoint: docker socket, D-Bus, a unix socket.
    HostIpc {
        endpoint: String,
    },
    Device {
        name: String,
    },
}

impl RequestKind {
    /// A short, stable category label used in reports and in the store's
    /// `decisions.kind` column.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::Network { .. } => "network",
            Self::FileSystem { .. } => "fs",
            Self::PortForward { .. } => "port",
            Self::Tool { .. } => "tool",
            Self::EnvVar { .. } => "env",
            Self::Secret { .. } => "secret",
            Self::HostIpc { .. } => "ipc",
            Self::Device { .. } => "device",
        }
    }
}

impl fmt::Display for RequestKind {
    /// The one-line form used in denial reports.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network { host, port, .. } => write!(f, "network  {host}:{port}"),
            Self::FileSystem { path, access } => write!(f, "fs {access}  {path}"),
            Self::PortForward { guest, host, .. } => write!(f, "port     {guest} → {host}"),
            Self::Tool { name } => write!(f, "tool     {name}"),
            Self::EnvVar { name } => write!(f, "env      {name}"),
            Self::Secret { name } => write!(f, "secret   {name}"),
            Self::HostIpc { endpoint } => write!(f, "ipc      {endpoint}"),
            Self::Device { name } => write!(f, "device   {name}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsAccess {
    Read,
    Write,
}

impl fmt::Display for FsAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
        }
    }
}

/// The process that made the attempt, plus its ancestry inside the guest.
///
/// Ordered outermost-first, so `[npm, node, node-gyp]` reads the way the
/// report prints it: `npm → node → node-gyp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessChain(Vec<ProcessInfo>);

impl ProcessChain {
    /// # Panics
    ///
    /// Never panics; an empty chain is accepted and renders as `?`. The broker
    /// should still prefer reporting a partial chain over none, since
    /// attribution quality is what makes a denial report actionable.
    #[must_use]
    pub fn new(chain: Vec<ProcessInfo>) -> Self {
        Self(chain)
    }

    /// The process that actually made the attempt.
    #[must_use]
    pub fn leaf(&self) -> Option<&ProcessInfo> {
        self.0.last()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ProcessInfo] {
        &self.0
    }
}

impl fmt::Display for ProcessChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("?");
        }
        let names: Vec<&str> = self.0.iter().map(|p| p.name.as_str()).collect();
        f.write_str(&names.join(" → "))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(name: &str, pid: u32) -> ProcessInfo {
        ProcessInfo {
            name: name.to_owned(),
            pid,
        }
    }

    #[test]
    fn chain_renders_as_report_shows_it() {
        let chain = ProcessChain::new(vec![
            proc("npm", 400),
            proc("node", 412),
            proc("node-gyp", 480),
        ]);
        assert_eq!(chain.to_string(), "npm → node → node-gyp");
        assert_eq!(chain.leaf().map(|p| p.pid), Some(480));
    }

    #[test]
    fn empty_chain_is_honest_rather_than_panicking() {
        let chain = ProcessChain::new(vec![]);
        assert_eq!(chain.to_string(), "?");
        assert!(chain.leaf().is_none());
    }

    #[test]
    fn network_request_renders_for_denial_report() {
        let kind = RequestKind::Network {
            host: "registry.npmjs.org".to_owned(),
            port: 443,
            proto: Proto::Tcp,
            resolved_from_dns: true,
        };
        assert_eq!(kind.to_string(), "network  registry.npmjs.org:443");
        assert_eq!(kind.category(), "network");
    }
}
