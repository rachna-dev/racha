//! The two artifacts `rachna.nix` evaluates into.
//!
//! [`ExecSpec`] is *what to build and run*; [`PolicySpec`] is *what is
//! permitted*. Nothing downstream re-reads the Nix file, and the hot-reload
//! classifier is a diff over these two structs: `PolicySpec` deltas are
//! usually live, `ExecSpec` deltas usually need a rebuild. That split is the
//! whole reload decision, and it falls out of the types rather than needing
//! special cases (design-docs/01-ARCHITECTURE.md §2).

use std::collections::BTreeMap;
use std::fmt;

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

use crate::ids::GrantId;
use crate::request::{FsAccess, Proto};

/// What to build and run. Changing any of this generally means a new Nix
/// closure, which means a rebuild and a VM restart.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecSpec {
    pub name: String,
    pub system: System,
    /// Store paths or package attribute names, resolved by the evaluator.
    pub packages: Vec<String>,
    pub services: BTreeMap<String, Service>,
    /// Named project commands, e.g. `dev` → `npm run dev`.
    pub entrypoints: BTreeMap<String, String>,
    pub resources: Resources,
    /// Persistent volumes, keyed by mount point in the guest. Database data
    /// lives here so it survives restarts and participates in snapshots
    /// (idea.md §12.5).
    pub volumes: BTreeMap<Utf8PathBuf, Volume>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct System {
    /// Base image identity, e.g. a nixpkgs revision. Pinned, never floating.
    pub pin: String,
    pub arch: Arch,
}

impl Default for System {
    fn default() -> Self {
        Self {
            pin: String::new(),
            arch: Arch::host(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The architecture Rachna is running on.
    ///
    /// A guest of a different architecture than the host needs emulation
    /// rather than hardware virtualization, which the backend must report as a
    /// capability rather than silently accept.
    #[must_use]
    pub fn host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self::Aarch64
        } else {
            Self::X86_64
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub enable: bool,
    pub port: Option<u16>,
    /// Extra NixOS service settings, passed through opaquely.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    pub cpus: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub max_processes: u32,
}

impl Default for Resources {
    /// Deliberately modest. A project must not be able to exhaust the host
    /// (idea.md §8.9), and a default that is too generous makes the limit
    /// invisible until something goes wrong.
    fn default() -> Self {
        Self {
            cpus: 4,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            max_processes: 512,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    pub size_bytes: u64,
    /// Whether this volume is included in snapshots. Database volumes are;
    /// scratch and build caches need not be.
    pub snapshot: bool,
}

/// What is permitted. This is the *complete* statement of the environment's
/// authority: there is no second place a permission can live — no session
/// grants, no `--once`, no runtime state that outlives a decision
/// (design-docs/00-PRODUCT.md §3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySpec {
    pub profile: Profile,
    /// Every effective permission, flattened. The evaluator is responsible for
    /// expanding profile defaults into explicit grants, so that
    /// `rachna config inspect` can show the real authority and audit can track
    /// each grant individually.
    pub grants: Vec<Grant>,
}

impl PolicySpec {
    #[must_use]
    pub fn find(&self, id: &GrantId) -> Option<&Grant> {
        self.grants.iter().find(|g| &g.id() == id)
    }
}

/// Named bundles of defaults. A profile is a *starting point the evaluator
/// expands*, not a runtime indirection — by the time a `PolicySpec` exists,
/// every permission it implies is an explicit [`Grant`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// No network interface, no host mounts, no host credentials. Closest to a
    /// true air gap (idea.md §13.1).
    Sealed,
    /// The practical default: the project workspace is the one deliberate
    /// exception to otherwise restrictive host access (idea.md §13.2).
    #[default]
    Development,
    /// Network permitted through a policy gateway with an allowlist
    /// (idea.md §13.3).
    Online,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sealed => f.write_str("sealed"),
            Self::Development => f.write_str("development"),
            Self::Online => f.write_str("online"),
        }
    }
}

/// One effective permission.
///
/// Its [`GrantId`] is derived from [`Grant::fingerprint`], so the same
/// permission keeps its identity — and therefore its usage history — across
/// reformatting, reordering, and comment changes in `rachna.nix`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grant {
    Network {
        /// A host pattern. `*.example.com` is accepted but is exactly the kind
        /// of over-broad grant `rachna audit` offers to collapse into the
        /// hosts actually contacted (design-docs/00-PRODUCT.md §3.4).
        host: String,
        port: u16,
        proto: Proto,
    },
    FileSystem {
        /// Host path made available to the guest.
        source: Utf8PathBuf,
        /// Where it appears inside the guest.
        target: Utf8PathBuf,
        access: Access,
    },
    PortForward {
        guest: u16,
        host: u16,
        /// Defaults to `127.0.0.1`; binding wider needs saying so explicitly
        /// (idea.md §12.4).
        bind: String,
    },
    /// Exposes a guest tool to the host as a protocol endpoint — never as a
    /// file the host executes (design-docs/00-PRODUCT.md §6.5).
    Tool {
        name: String,
        kind: ToolKind,
        /// A tool is a scoped role, not an inheritor of the environment's
        /// authority: a language server needs the workspace, not the network.
        workspace: Access,
        network: bool,
    },
    EnvVar {
        name: String,
    },
    Secret {
        name: String,
        ttl_seconds: u64,
    },
    HostIpc {
        endpoint: String,
    },
    Device {
        name: String,
    },
}

impl Grant {
    /// The normalized content this grant's identity is derived from.
    ///
    /// Must be stable across cosmetic config changes and must distinguish
    /// anything semantically different. Changing this format orphans existing
    /// usage records, so it is deliberately explicit rather than derived from
    /// `Debug` or serialization.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        match self {
            Self::Network { host, port, proto } => {
                let proto = match proto {
                    Proto::Tcp => "tcp",
                    Proto::Udp => "udp",
                };
                format!("network:{}:{port}:{proto}", host.to_lowercase())
            }
            Self::FileSystem {
                source,
                target,
                access,
            } => format!("fs:{source}:{target}:{access}"),
            Self::PortForward { guest, host, bind } => format!("port:{guest}:{host}:{bind}"),
            Self::Tool {
                name,
                kind,
                workspace,
                network,
            } => format!("tool:{name}:{kind}:{workspace}:{network}"),
            Self::EnvVar { name } => format!("env:{name}"),
            Self::Secret { name, ttl_seconds } => format!("secret:{name}:{ttl_seconds}"),
            Self::HostIpc { endpoint } => format!("ipc:{endpoint}"),
            Self::Device { name } => format!("device:{name}"),
        }
    }

    #[must_use]
    pub fn id(&self) -> GrantId {
        GrantId::from_content(&self.fingerprint())
    }

    /// The category label, matching [`crate::request::RequestKind::category`].
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

impl fmt::Display for Grant {
    /// The form shown in `rachna audit` and in suggested fixes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network { host, port, .. } => write!(f, "network  {host}:{port}"),
            Self::FileSystem { source, access, .. } => write!(f, "fs {access}  {source}"),
            Self::PortForward { guest, host, .. } => write!(f, "port     {guest} → {host}"),
            Self::Tool { name, kind, .. } => write!(f, "tool     {name} ({kind})"),
            Self::EnvVar { name } => write!(f, "env      {name}"),
            Self::Secret { name, .. } => write!(f, "secret   {name}"),
            Self::HostIpc { endpoint } => write!(f, "ipc      {endpoint}"),
            Self::Device { name } => write!(f, "device   {name}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    ReadOnly,
    ReadWrite,
    None,
}

impl Access {
    /// Whether this access level permits the requested operation.
    #[must_use]
    pub fn permits(self, requested: FsAccess) -> bool {
        match (self, requested) {
            (Self::None, _) => false,
            (Self::ReadOnly, FsAccess::Read) => true,
            (Self::ReadOnly, FsAccess::Write) => false,
            (Self::ReadWrite, _) => true,
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => f.write_str("ro"),
            Self::ReadWrite => f.write_str("rw"),
            Self::None => f.write_str("none"),
        }
    }
}

/// How the host reaches an exposed tool. Each kind is a protocol, which is why
/// a tool can be proxied at all: stdin → stdout/stderr plus an exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolKind {
    /// Language Server Protocol over stdio.
    Lsp,
    /// Debug Adapter Protocol over stdio.
    Debugger,
    /// Reads source on stdin, writes formatted source on stdout.
    Formatter,
    /// Any other command: argv in, stdio through, exit code out.
    Command,
}

impl fmt::Display for ToolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lsp => f.write_str("lsp"),
            Self::Debugger => f.write_str("debugger"),
            Self::Formatter => f.write_str("formatter"),
            Self::Command => f.write_str("command"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npm_registry() -> Grant {
        Grant::Network {
            host: "registry.npmjs.org".to_owned(),
            port: 443,
            proto: Proto::Tcp,
        }
    }

    #[test]
    fn grant_identity_ignores_host_case() {
        // Hostnames are case-insensitive, so these are the same permission and
        // must share usage history.
        let lower = npm_registry();
        let mixed = Grant::Network {
            host: "Registry.NPMJS.org".to_owned(),
            port: 443,
            proto: Proto::Tcp,
        };
        assert_eq!(lower.id(), mixed.id());
    }

    #[test]
    fn grant_identity_distinguishes_semantics() {
        let tcp = npm_registry();
        let udp = Grant::Network {
            host: "registry.npmjs.org".to_owned(),
            port: 443,
            proto: Proto::Udp,
        };
        let other_port = Grant::Network {
            host: "registry.npmjs.org".to_owned(),
            port: 80,
            proto: Proto::Tcp,
        };

        assert_ne!(tcp.id(), udp.id());
        assert_ne!(tcp.id(), other_port.id());
    }

    #[test]
    fn read_only_does_not_permit_writes() {
        assert!(Access::ReadOnly.permits(FsAccess::Read));
        assert!(!Access::ReadOnly.permits(FsAccess::Write));
        assert!(Access::ReadWrite.permits(FsAccess::Write));
        assert!(!Access::None.permits(FsAccess::Read));
    }

    #[test]
    fn policy_lookup_by_id_round_trips() {
        let grant = npm_registry();
        let spec = PolicySpec {
            profile: Profile::Development,
            grants: vec![grant.clone()],
        };
        assert_eq!(spec.find(&grant.id()), Some(&grant));
    }

    #[test]
    fn default_profile_is_development() {
        assert_eq!(Profile::default(), Profile::Development);
        assert_eq!(Profile::default().to_string(), "development");
    }
}
