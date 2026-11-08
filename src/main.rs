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

use rachna::cli::{Command, Invocation};
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
            print!("{}", rachna::cli::help());
            ExitCode::from(OK)
        }
        // The `rachna.nix`-editing verbs. Distinguished from the rest
        // because they need NO backend — `00` §5.3's whole point is that they
        // are a surgical edit to one file — so reporting "needs a backend"
        // would name the wrong missing piece. What they wait on is the CST
        // editor, which `00` §5.3 itself calls "a convenience, not
        // load-bearing": the fallback is to print the snippet to paste, and
        // that is what this message is a placeholder for.
        Command::Edit(edit) => {
            eprintln!(
                "rachna: `{}` would edit rachna.nix, and the comment-preserving \
                 editor is not built yet (00 §5.3). Until it is, add it to \
                 rachna.nix by hand — `rachna config validate` will check it",
                edit.verb()
            );
            ExitCode::from(UNIMPLEMENTED)
        }
        // Everything below needs a VM or a store on disk, and those arrive
        // with steps 11-13. Naming them individually rather than with a
        // catch-all so adding a backend is a compile error here, not a
        // silently-missing verb.
        Command::Init { .. }
        | Command::Start { .. }
        | Command::Stop
        | Command::Status
        | Command::Doctor
        | Command::Config { .. }
        | Command::Audit { .. }
        | Command::Explain { .. } => {
            eprintln!(
                "rachna: `{}` needs a backend, which lands with build-order \
                 step 11 (design-docs/01-ARCHITECTURE.md §7)",
                command.verb()
            );
            ExitCode::from(UNIMPLEMENTED)
        }
    }
}
