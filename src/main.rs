//! The `rachna` binary.
//!
//! Thin on purpose: it turns `argv` into a [`Command`](rachna::cli::Command)
//! and dispatches. Everything it calls is library code that was already
//! tested without a process, which is what `01-ARCHITECTURE.md` §7's "no step
//! needs a hypervisor until step 7" bought.
//!
//! # Exit codes are an API
//!
//! `21-SPEC-AUDIT.md` §3.3 flagged this: scripts and CI branch on them, so
//! they are defined here as named constants rather than scattered integers.

#![allow(clippy::print_stdout, clippy::print_stderr, reason = "this is the CLI")]

use rachna::cli::{Command, ConfigAction, Invocation};
use std::ffi::OsString;
use std::process::ExitCode;

/// Everything worked.
const OK: u8 = 0;
/// The invocation could not be understood.
const USAGE: u8 = 64;
/// Something this build cannot do yet.
///
/// A real exit code rather than a panic: a user on a half-built tool should
/// get a sentence, and `todo!()` would give them a backtrace.
const UNIMPLEMENTED: u8 = 70;

// Reserved, deliberately not defined yet: a `DENIED` code for "the command
// ran and the policy refused something" (`00` §3.3), distinct from USAGE so a
// script can tell "you asked wrongly" from "the policy refused". It arrives
// with the step that can produce a denial — defining it now would be a
// constant nothing sets, which is the mistake `jiff`/`ulid` already taught
// (added ahead of a need, removed by cargo-machete).

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();

    match Invocation::from_argv(&argv) {
        Err(error) => {
            eprintln!("rachna: {error}");
            eprintln!("run `rachna --help` for the available commands");
            ExitCode::from(USAGE)
        }
        Ok(Invocation::Shim { tool, args }) => {
            // The shim path. Arguments are handed on untouched — `17` §1's
            // whole reason for choosing lexopt over clap.
            eprintln!(
                "rachna: the `{tool}` shim needs a running environment \
                 (step 13); {} argument(s) would be forwarded verbatim",
                args.len()
            );
            ExitCode::from(UNIMPLEMENTED)
        }
        Ok(Invocation::Rachna(command)) => run(command),
    }
}

fn run(command: Command) -> ExitCode {
    match command {
        Command::Version => {
            println!("rachna {}", rachna::version());
            ExitCode::from(OK)
        }
        Command::Help => {
            print!("{}", help());
            ExitCode::from(OK)
        }
        // Everything below needs a VM, a store on disk, or a config file, and
        // those arrive with steps 11-13. Naming them individually rather than
        // with a catch-all so adding a backend is a compile error here, not a
        // silently-missing verb.
        Command::Init { .. }
        | Command::Start { .. }
        | Command::Stop
        | Command::Status
        | Command::Doctor
        | Command::Config { .. }
        | Command::Audit { .. }
        | Command::Explain { .. }
        | Command::Allow { .. } => {
            eprintln!(
                "rachna: `{}` needs a backend, which lands with build-order \
                 step 11 (design-docs/01-ARCHITECTURE.md §7)",
                name_of(&command)
            );
            ExitCode::from(UNIMPLEMENTED)
        }
    }
}

/// The verb a command came from, for messages.
const fn name_of(command: &Command) -> &'static str {
    match command {
        Command::Init { .. } => "init",
        Command::Start { .. } => "start",
        Command::Stop => "stop",
        Command::Status => "status",
        Command::Doctor => "doctor",
        Command::Config { action } => match action {
            ConfigAction::Inspect => "config inspect",
            ConfigAction::Diff => "config diff",
            ConfigAction::Validate => "config validate",
        },
        Command::Audit { .. } => "audit",
        Command::Explain { .. } => "explain",
        Command::Allow { .. } => "allow",
        Command::Version => "--version",
        Command::Help => "--help",
    }
}

/// Hand-written help.
///
/// `17` §1 accepted "no generated help" as the cost of `lexopt`, and `21`
/// §2.4 recorded the gap. This is it: written once, and cheap to keep correct
/// because a test asserts every parsed verb appears here.
fn help() -> String {
    format!(
        "\
rachna {version} — a declarative, isolated development environment

USAGE
  rachna <command> [options]

ENVIRONMENT
  init [--template <url>]   write a starting rachna.nix
  start [--accept]          start or resume; --accept acknowledges the
                            first-run access summary
  stop                      stop the environment
  status                    what is running, and what it is allowed
  doctor                    check this host, and verify enforcement

CONFIG
  config inspect            the effective config, with defaults visible
  config diff               live runtime versus the file
  config validate           check without applying
  allow <category> <target>...
                            add a grant. category is one of:
                            network, fs, port, secret, tool
                            fs takes --read-only or --read-write

AUDIT
  audit [--narrow] [--ci]   find unused and over-broad grants
  explain <run-id>          every decision in one run

  --version                 print the version
  --help                    this text

rachna.nix is the only authority. Every command above that changes
permissions edits that file; nothing grants anything that is not written
down.
",
        version = rachna::version()
    )
}
