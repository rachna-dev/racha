//! The command surface.
//!
//! Subcommands exist only for things that have no tool equivalent. **If a
//! declared tool can be invoked directly, Rachna does not wrap it** — there is
//! no `rachna fmt`, no `rachna lsp`, no `rachna test`, because the tool already
//! knows which files and which config and a wrapper would only guess worse
//! (design-docs/00-PRODUCT.md §5.1).
//!
//! `--exec` is the one general escape hatch, and it is also what the shims are
//! internally.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "rachna",
    about = "A declarative, isolated development environment you can pause, resume, and throw away.",
    version,
    // Subcommands are optional because `rachna --exec "..."` is a complete
    // invocation on its own.
    args_conflicts_with_subcommands = true
)]
pub(crate) struct Cli {
    /// Run a command inside the environment.
    ///
    /// Given a string, it runs through the guest's shell, so pipes and `&&`
    /// work. For argv with no shell involved, use `rachna exec -- cmd args`.
    #[arg(long = "exec", value_name = "COMMAND", global = false)]
    pub(crate) exec: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create a rachna.nix in the current directory.
    Init,

    /// Check that the environment and host tooling are in working order.
    Doctor {
        /// Also check editor configuration for drift.
        #[arg(long)]
        ide: bool,
    },

    /// Show the environment, its services, its policy, and its resources.
    Status,

    /// Tail logs from the guest.
    Logs {
        #[arg(long, short)]
        follow: bool,
    },

    // ── Lifecycle ────────────────────────────────────────────────────────
    /// Start the environment.
    Start,
    /// Shut the environment down.
    Stop,
    /// Freeze execution, keeping RAM allocated. Fast, reclaims nothing.
    Pause,
    /// Save state to disk and release host RAM. The steady state between
    /// sessions.
    Suspend,
    /// Restore a suspended or paused environment.
    Resume,
    /// Rebuild the Nix closure after a package change, then restart.
    Rebuild {
        /// Restart immediately rather than waiting for the next start.
        #[arg(long)]
        now: bool,
    },

    /// Run a command inside the environment, passing argv through untouched.
    Exec {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },

    // ── Editing rachna.nix ───────────────────────────────────────────────
    //
    // Every one of these *writes the file*. There is no `--persist` flag,
    // because there is no non-persistent alternative: the file is the only
    // authority (design-docs/00-PRODUCT.md §3.2).
    /// Grant a permission by writing it to rachna.nix.
    Allow {
        #[command(subcommand)]
        what: AllowWhat,
    },
    /// Remove a permission from rachna.nix.
    Revoke {
        /// Remove every grant the audit reports as unused.
        #[arg(long)]
        unused: bool,
        /// Only consider grants unused for at least this long, e.g. `30d`.
        #[arg(long, value_name = "DURATION")]
        older_than: Option<String>,
    },
    /// Expose a guest tool to the host as a protocol endpoint.
    Expose { kind: String, name: String },
    /// Stop exposing a tool.
    Unexpose { name: String },
    /// Add a package to the environment. Requires a rebuild.
    Add {
        #[command(subcommand)]
        what: AddWhat,
    },
    /// Forward a guest port to the host, bound to 127.0.0.1 by default.
    Port {
        guest: u16,
        #[arg(long)]
        host: Option<u16>,
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },
    /// Set a scalar config value, e.g. `rachna set resources.memory 8GB`.
    Set { key: String, value: String },
    /// Manage brokered secrets: scoped and short-lived, never a mounted
    /// credential store.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Inspect the effective configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    // ── Observation ──────────────────────────────────────────────────────
    /// Report grants that are unused, over-broad, or stale — and how to narrow
    /// them.
    Audit {
        /// Walk each finding interactively and apply the narrowing.
        #[arg(long)]
        narrow: bool,
        /// Show what would change without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Exit non-zero if any grant is unused. For CI.
        #[arg(long)]
        ci: bool,
        /// Explain every recorded use of one permission.
        #[arg(long, value_name = "GRANT")]
        why: Option<String>,
    },
    /// Show the full decision trace for a run, e.g. `rachna explain run/a3f2`.
    Explain { run: String },

    // ── Saved state ──────────────────────────────────────────────────────
    /// Create and restore restorable points, including live process memory.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// Create and restore disk-only recovery points, without process memory.
    Checkpoint {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Point an editor at the environment.
    Ide {
        editor: String,
        /// Report configuration drift instead of writing anything.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AllowWhat {
    /// Allow outbound network to one or more hosts.
    Network {
        /// Host, optionally with `:port`. Defaults to port 443.
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Make a host path available inside the guest.
    Fs {
        path: camino::Utf8PathBuf,
        #[arg(long)]
        read_only: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AddWhat {
    /// Add a package by nixpkgs attribute name.
    Package { name: String },
    /// Enable a service, e.g. postgres.
    Service { name: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum SecretAction {
    Add {
        name: String,
        #[arg(long)]
        ttl: Option<String>,
    },
    List,
    Remove {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigAction {
    /// Show the fully-evaluated effective config, with defaults visible.
    Inspect,
    /// Show how the live environment differs from the file.
    Diff,
    /// Evaluate without applying.
    Validate,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SnapshotAction {
    Create { name: String },
    List,
    Restore { name: String },
    Delete { name: String },
}

/// Parse and dispatch.
pub(crate) fn run() -> ExitCode {
    let cli = Cli::parse();

    // `--exec` and `exec` are the same operation in two spellings: a string
    // goes through the guest shell, argv does not.
    if let Some(command) = cli.exec {
        return dispatch_exec(ExecForm::Shell(command));
    }

    match cli.command {
        Some(Command::Exec { argv }) => dispatch_exec(ExecForm::Argv(argv)),
        Some(_other) => {
            todo!("step 8: init, status, config inspect/diff, allow, audit, explain")
        }
        None => {
            // No arguments at all: show help rather than doing something.
            let mut cmd = <Cli as clap::CommandFactory>::command();
            let _ = cmd.print_help();
            println!();
            ExitCode::SUCCESS
        }
    }
}

/// How a command was spelled.
// Payloads are carried but not yet read: `dispatch_exec` is unimplemented until
// step 10, when the guest transport exists.
#[allow(dead_code)]
#[derive(Debug)]
enum ExecForm {
    /// A string, run through the guest's shell so pipes and `&&` work.
    Shell(String),
    /// Argv passed through with no shell involved.
    Argv(Vec<String>),
}

fn dispatch_exec(_form: ExecForm) -> ExitCode {
    todo!("step 10: cwd mapping, stdio fidelity, run record, denial report")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // Catches conflicting flags, duplicate names, and bad arg combinations
        // at test time rather than at a user's first invocation.
        Cli::command().debug_assert();
    }

    #[test]
    fn exec_accepts_the_string_form() {
        let cli = Cli::try_parse_from(["rachna", "--exec", "npm install"]).expect("parses");
        assert_eq!(cli.exec.as_deref(), Some("npm install"));
    }

    #[test]
    fn exec_subcommand_preserves_argv_including_double_dash() {
        // `cargo test -- --nocapture` must arrive intact; clap must not eat the
        // inner flags.
        let cli =
            Cli::try_parse_from(["rachna", "exec", "--", "cargo", "test", "--", "--nocapture"])
                .expect("parses");
        let Some(Command::Exec { argv }) = cli.command else {
            panic!("expected exec");
        };
        assert_eq!(argv, ["cargo", "test", "--", "--nocapture"]);
    }

    #[test]
    fn allow_network_takes_several_hosts() {
        // The denial report suggests one command for all blocked hosts, so this
        // has to be variadic.
        let cli = Cli::try_parse_from([
            "rachna",
            "allow",
            "network",
            "registry.npmjs.org",
            "github.com",
        ])
        .expect("parses");
        let Some(Command::Allow {
            what: AllowWhat::Network { hosts },
        }) = cli.command
        else {
            panic!("expected allow network");
        };
        assert_eq!(hosts, ["registry.npmjs.org", "github.com"]);
    }

    #[test]
    fn there_is_no_persist_flag() {
        // `allow` always writes the file; a `--persist` flag would imply a
        // non-persistent alternative exists. It must not parse.
        assert!(
            Cli::try_parse_from(["rachna", "allow", "network", "example.com", "--persist"])
                .is_err()
        );
    }

    #[test]
    fn no_tool_wrapping_subcommands_exist() {
        // The rule: if a declared tool can be invoked directly, Rachna does not
        // wrap it. These must stay unparseable.
        for wrapper in ["fmt", "lsp", "test"] {
            assert!(
                Cli::try_parse_from(["rachna", wrapper]).is_err(),
                "`rachna {wrapper}` should not be a subcommand"
            );
        }
    }
}
