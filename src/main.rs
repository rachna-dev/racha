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
    // Captured before the match, because the arms below move `command`.
    let verb = command.verb();
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
        Command::Init { .. } => commands::init(),
        Command::Start { accept } => commands::start(accept),
        Command::Stop => commands::stop(),
        Command::Status => commands::status(),
        // Everything below still needs work that has not landed. Naming them
        // individually rather than with a catch-all so adding one is a
        // compile error here, not a silently-missing verb.
        Command::Doctor
        | Command::Config { .. }
        | Command::Audit { .. }
        | Command::Explain { .. } => {
            eprintln!(
                "rachna: `{}` is not built yet \
                 (design-docs/01-ARCHITECTURE.md §7)",
                verb
            );
            ExitCode::from(UNIMPLEMENTED)
        }
    }
}

/// The verbs that do something, kept out of `main`'s dispatch.
///
/// `main.rs` is untested by design (`01` §7: the library is tested without a
/// process), and AGENTS.md records the consequence — *anything with
/// observable behaviour does not belong in it*. So these are thin: each
/// gathers what the host knows, calls `rachna::run`, and prints. The
/// decisions live in `run.rs`, where tests reach them.
mod commands {
    use rachna::layout::{default_root, ProjectId};
    use rachna::run::{self, Context, StartError};
    use rachna::summary::Answer;
    use rachna::supervise;
    use rachna::tap;
    use std::io::IsTerminal;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    /// Everything worked.
    const OK: u8 = 0;
    /// Something this build cannot do yet.
    const UNIMPLEMENTED: u8 = 70;
    /// The policy could not be enforced, or the config is wrong.
    ///
    /// Distinct from a usage error: `21` §3.3 makes exit codes an API, and a
    /// script needs to tell "you asked wrongly" from "the policy refused".
    const REFUSED: u8 = 77;
    /// Something failed while trying.
    const FAILED: u8 = 74;

    /// Builds the context from this host and this directory.
    ///
    /// # Errors
    ///
    /// A message, when the project directory or the guest cannot be found.
    fn context() -> Result<Context, String> {
        let project_dir = std::env::current_dir().map_err(|error| error.to_string())?;
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is not set, so ~/.rachna cannot be located".to_owned())?;

        // `08` §4.3: the id is derived from the project's canonical path, so
        // two checkouts of one repo are different projects — which `08`
        // §4.3's worktree note says is correct rather than incidental.
        let canonical = project_dir
            .canonicalize()
            .unwrap_or_else(|_| project_dir.clone());
        let project = ProjectId::new(project_slug(&canonical)).map_err(|e| e.to_string())?;

        Ok(Context {
            project_dir,
            rachna_root: default_root(&home),
            project,
            // The pinned guest. Not yet fetched — `21` §2.1a is the
            // supply-chain story — so this is the local checkout.
            nixpkgs: PathBuf::from("<nixpkgs>"),
            // `decide::Capabilities` — which policy categories this
            // backend cannot enforce. Everything is enforceable until a
            // measured gap says otherwise, and `tap` below carries the one
            // gap this host actually has.
            capabilities: rachna::decide::Capabilities::all(),
            tap: detect_tap(),
            interactive: std::io::stdin().is_terminal(),
        })
    }

    /// A readable, path-derived project id.
    ///
    /// `08` §4.3 shows these as `<name>-<hash>`: the name so a user can find
    /// their own directory under `~/.rachna`, and the hash because two
    /// checkouts must not share state. The hash is of the *canonical* path,
    /// so a symlinked route to the same project is the same project.
    fn project_slug(canonical: &Path) -> String {
        let name = canonical
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "project".to_owned());
        // Only characters that are safe in a path component; `ProjectId`
        // refuses the rest, and sanitising here beats refusing a directory
        // the user did not choose the name of.
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        format!("{safe}-{:x}", path_hash(canonical))
    }

    /// A short, stable hash of a path.
    ///
    /// `DefaultHasher` is not stable across Rust releases, which would
    /// orphan a project's state on a toolchain bump — so this is a plain
    /// FNV-1a, written out because `17`'s rule is to avoid a dependency for
    /// something this small.
    fn path_hash(path: &Path) -> u32 {
        let mut hash: u32 = 0x811c_9dc5;
        for byte in path.to_string_lossy().as_bytes() {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        hash
    }

    /// What the hypervisor on this host supports.
    ///
    /// **Note the name collision**, which cost a compile error here:
    /// `backend::Capabilities` is what the *hypervisor* can do (snapshots,
    /// quotas), while `decide::Capabilities` is which *policy categories*
    /// this backend cannot enforce. Both are legitimate and the shared name
    /// is a trap — `Context` needs both, so each is named by its module.
    fn backend_capabilities() -> rachna::backend::Capabilities {
        if cfg!(target_os = "macos") {
            rachna::backend::Capabilities::measured_macos()
        } else {
            rachna::backend::Capabilities::measured_linux()
        }
    }

    /// Whether the network helper is present and capable.
    ///
    /// Reports [`tap::Capability::Unknown`] rather than guessing, which
    /// `tap.rs` treats as a refusal — the same direction as
    /// `enforcement::Outcome::Inconclusive`.
    fn detect_tap() -> tap::Capability {
        if cfg!(target_os = "macos") {
            // `02` §7 measured VZ networking needing no privileges at all.
            return tap::Capability::Present;
        }
        tap::Capability::Unknown {
            why: "rachna-netd is not built yet (15 §7 item 8)".to_owned(),
        }
    }

    /// `rachna init` — write a starting `rachna.nix`.
    pub(crate) fn init() -> ExitCode {
        let Ok(context) = context() else {
            eprintln!("rachna: cannot determine this project");
            return ExitCode::from(FAILED);
        };
        let file = context.config_file();
        if file.exists() {
            eprintln!("rachna: {} already exists", file.display());
            return ExitCode::from(REFUSED);
        }
        // The secure configuration is the one you get by writing nothing
        // (`19` §4.5), so the template is deliberately minimal: an empty
        // allowlist denies all network, and the profile grants only the
        // workspace.
        // FLAT, not nested under `isolation`, and the difference is a real
        // gap rather than a style choice.
        //
        // `19` §2.2 writes the user-facing shape as `isolation = { tier =
        // …; }`, and `config.rs` parses the EVALUATED JSON, which is flat —
        // because a NixOS-style module emits `config.isolation`'s contents,
        // not the wrapper (`00` §5.3 rule 3: "this works because rachna.nix
        // is a NixOS-style module").
        //
        // **That module does not exist yet.** So `start` evaluates
        // `rachna.nix` raw, with nothing to flatten it — and a template
        // using `19` §2.2's nesting fails with `isolation: no such option`,
        // which is exactly what the first run of this command did.
        //
        // Writing the flat shape makes `init` → `start` work today and is
        // honest about which half is missing. When the module lands, this
        // template moves to the nested form and the module does the
        // flattening.
        let template = concat!(
            "# What this environment may do. Nothing here is implied:\n",
            "# an empty allowlist denies all network, and deleting a line\n",
            "# makes the environment stricter rather than looser.\n",
            "#\n",
            "# NOTE: flat for now. `19` §2.2's `isolation = { … }` nesting\n",
            "# needs the NixOS-style module that does the flattening, which\n",
            "# is not built yet.\n",
            "{\n",
            "  tier = \"allowlist\";\n",
            "  profile = \"development\";\n",
            "  network.allow = [ ];\n",
            "}\n",
        );
        match std::fs::write(&file, template) {
            Ok(()) => {
                println!("wrote {}", file.display());
                println!("edit it, then: rachna start");
                ExitCode::from(OK)
            }
            Err(error) => {
                eprintln!("rachna: cannot write {}: {error}", file.display());
                ExitCode::from(FAILED)
            }
        }
    }

    /// `rachna start`.
    pub(crate) fn start(accept: bool) -> ExitCode {
        let context = match context() {
            Ok(context) => context,
            Err(why) => {
                eprintln!("rachna: {why}");
                return ExitCode::from(FAILED);
            }
        };

        // Idempotent: `00` §5.2 makes this the command people type on `cd`.
        match run::already_running(&context) {
            Ok(running) if !running.is_empty() => {
                println!("already running ({} process(es))", running.processes.len());
                return ExitCode::from(OK);
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("rachna: {error}");
                return ExitCode::from(FAILED);
            }
        }

        let policy = match run::evaluate(&context) {
            Ok(policy) => policy,
            Err(error) => return report(&error),
        };

        // `--accept` is the NON-TTY path and nothing else. `00` §3.10c:
        // "at a terminal it is a keypress, not a command to retype" — a flag
        // that worked interactively would let a user accept a cloned
        // config's permissions in the same breath as asking to start it,
        // which is the one thing this gate exists to prevent. So at a TTY
        // the flag is ignored and `a` is the only way through.
        if accept && !context.interactive {
            let now = now_millis();
            if let Err(error) = run::accept(&context, &policy, now) {
                return report(&error);
            }
        }

        let approval = match run::approval_of(&context, &policy) {
            Ok(approval) => approval,
            Err(error) => return report(&error),
        };

        // Resume shares this gate. There is no separate `resume` verb —
        // `start` is both (`cli.rs` help: "start or resume") — so passing
        // the snapshot's verdict here is what gives resume the summary the
        // user asked for, rather than a second code path that could drift.
        let resuming = match run::resume_verdict(&context, &policy) {
            Ok(verdict) => verdict,
            Err(error) => return report(&error),
        };

        // Whether this project ever approved anything here — it decides
        // what the gate SAYS, not whether it asks. Without it a config that
        // merely widened is told it has never run here.
        let history = match run::history_of(&context) {
            Ok(history) => history,
            Err(error) => return report(&error),
        };

        let gate = match run::check(
            &policy,
            &context.tap,
            approval,
            history,
            resuming.as_ref(),
            context.interactive,
        ) {
            Ok(gate) => gate,
            Err(error) => return report(&error),
        };

        // THE SUMMARY IS UNCONDITIONAL. `00` §3.10c, corrected: a user about
        // to hand a directory to a VM should be told what that VM may do,
        // every time — not once in the project's history.
        print!("{}", gate.shown);
        if let Some(why) = &gate.divergence {
            print!("{why}");
        }

        if let Some(prompt) = &gate.prompt {
            print!("{prompt}");
            if !context.interactive {
                // A pipeline cannot press a key. `00` §3.10c: CI needs the
                // flag, and blocking forever on input nobody can send is
                // worse than refusing.
                //
                // It SAYS which refusal this is. A mutant flipping this
                // condition survived because a piped `start` then read
                // stdin, hit EOF, aborted, and exited 77 — the same code by
                // a different route, indistinguishable from the outside.
                // The two cases also need different advice: a pipeline
                // cannot press `a`, so telling it to is useless.
                eprintln!(
                    "rachna: not a terminal, so the summary cannot be \
                     acknowledged here. Pass --accept in CI."
                );
                return ExitCode::from(REFUSED);
            }
            match read_answer() {
                Answer::AcceptAll => {
                    if let Err(error) = run::accept(&context, &policy, now_millis()) {
                        return report(&error);
                    }
                }
                Answer::ShowAll => {
                    // The long form rolled up per category; print every
                    // entry, then ask again rather than proceeding — a `l`
                    // that started would mean reading the list accepted it.
                    // Right-aligned numbers, width from the largest. With
                    // `[{}]` the columns step out of line at `[10]`, which
                    // is exactly the size of list this branch exists for.
                    let items = gate.summary.reviewable();
                    let width = items.len().to_string().len();
                    for item in &items {
                        println!(
                            "  [{:>width$}] {:<8} {}",
                            item.number,
                            item.category.as_str(),
                            item.entry
                        );
                    }
                    // The prompt's own leading text follows a blank line
                    // everywhere else; without one here the list runs
                    // straight into "this config has not run here before".
                    println!();
                    print!("{prompt}");
                    if !matches!(read_answer(), Answer::AcceptAll) {
                        println!("not started");
                        return ExitCode::from(REFUSED);
                    }
                    if let Err(error) = run::accept(&context, &policy, now_millis()) {
                        return report(&error);
                    }
                }
                Answer::Abort => {
                    println!("not started");
                    return ExitCode::from(REFUSED);
                }
            }
        }

        // The policy is enforceable and the user has just seen and accepted
        // it. The launch itself needs the boot bundle, which `21` §2.1a's
        // supply chain has to deliver — so this is where the work remains.
        //
        // No second summary print: `gate.shown` above is the one place it
        // appears, so the two cannot disagree.
        eprintln!(
            "rachna: policy approved and enforceable, but the guest image \
             is not fetched yet (21 §2.1a). Everything up to the launch now \
             runs."
        );
        ExitCode::from(UNIMPLEMENTED)
    }

    /// `rachna stop`.
    pub(crate) fn stop() -> ExitCode {
        let context = match context() {
            Ok(context) => context,
            Err(why) => {
                eprintln!("rachna: {why}");
                return ExitCode::from(FAILED);
            }
        };
        match run::stop(&context) {
            Ok(report) if report.is_clean() => {
                println!("{report}");
                ExitCode::from(OK)
            }
            Ok(report) => {
                eprintln!("{report}");
                ExitCode::from(FAILED)
            }
            Err(error) => {
                eprintln!("rachna: {error}");
                ExitCode::from(FAILED)
            }
        }
    }

    /// `rachna status`.
    pub(crate) fn status() -> ExitCode {
        let context = match context() {
            Ok(context) => context,
            Err(why) => {
                eprintln!("rachna: {why}");
                return ExitCode::from(FAILED);
            }
        };

        let running = match run::already_running(&context) {
            Ok(running) => running,
            Err(error) => {
                eprintln!("rachna: {error}");
                return ExitCode::from(FAILED);
            }
        };
        if running.is_empty() {
            println!("stopped");
        } else {
            println!("running:");
            for process in &running.processes {
                println!("  {} (pid {})", process.role, process.pid);
            }
        }
        println!("project:  {}", context.project.as_str());
        println!("state:    {}", context.paths().root().display());

        // What this host can enforce, which `01` §2.6 says must be reported
        // rather than assumed — and `resources.rs` says must be stated when
        // a declared limit is advisory.
        if let Ok(policy) = run::evaluate(&context) {
            print!(
                "{}",
                rachna::summary::AccessSummary::new(policy.tier, policy.profile, &policy.grants)
            );
            for advisory in rachna::resources::Resources::advisory_on(backend_capabilities()) {
                println!("  ⚠ {advisory}");
            }
        }
        if !context.tap.can_create_tap() {
            println!("  ⚠ host-mediated networking is unavailable on this host");
        }
        ExitCode::from(OK)
    }

    /// One keypress, with no Enter.
    ///
    /// **Anything unrecognised aborts** — `summary::Answer::from_key`
    /// decides, and a stray byte must never accept a cloned config's
    /// permissions.
    ///
    /// # Why raw mode rather than `read_line`
    ///
    /// `00` §3.10c promises **a keypress**: *"pressing `a` is the same
    /// decision"* as running the command again, and that is only true if
    /// `a` alone decides. With `read_line` the user types `a` and then
    /// waits — found by driving the real binary under a pty, where a lone
    /// `a` produced no response at all. A gate that appears to hang is a
    /// gate people kill and work around.
    ///
    /// The terminal settings are restored on **every** path, including the
    /// error ones. A process that exits leaving a terminal in raw mode
    /// leaves the user's shell with no echo and no line editing, which
    /// looks like it broke their terminal rather than refused a start.
    ///
    /// Not a TTY, or the attributes cannot be read? Fall back to a line.
    /// `start` already refuses before prompting when stdin is not
    /// interactive, so this covers the odd case of a TTY that will not go
    /// raw rather than the pipeline.
    fn read_answer() -> Answer {
        use std::io::{Read, Write};
        // Flush, or the prompt sits in a buffer while we wait for input the
        // user does not know we want.
        let _ = std::io::stdout().flush();

        let stdin = std::io::stdin();
        let Ok(saved) = rustix::termios::tcgetattr(&stdin) else {
            return read_answer_line();
        };
        let mut raw = saved.clone();
        raw.make_raw();
        if rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &raw).is_err()
        {
            return read_answer_line();
        }

        let mut byte = [0_u8; 1];
        let read = std::io::stdin().read(&mut byte);
        // BEFORE interpreting the key: the restore must not depend on what
        // was typed, or an unexpected byte leaves the terminal raw.
        let _ = rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &saved);
        // Raw mode suppresses the echo of the newline the user's keypress
        // would normally produce, so the next line we print would start in
        // the prompt's column.
        println!();

        // The DECISION is `summary::answer_from_read`, which is pure and
        // tested. It used to be this `match`, and a mutant deleting its
        // `Ok(1)` arm — making every keypress abort — survived the whole
        // suite: a gate that always refuses looks safe while blocking every
        // start, with nothing in the output to explain it.
        rachna::summary::answer_from_read(read.ok(), byte[0])
    }

    /// A whole line, for a terminal that will not go raw.
    fn read_answer_line() -> Answer {
        use std::io::BufRead;
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            return Answer::Abort;
        }
        line.trim()
            .chars()
            .next()
            .map_or(Answer::Abort, Answer::from_key)
    }

    /// Prints a start failure and picks its exit code.
    fn report(error: &StartError) -> ExitCode {
        eprintln!("rachna: {error}");
        match error {
            // The config says something this host cannot do, or says
            // something wrong. Both are refusals rather than crashes.
            StartError::Unenforceable(_) | StartError::Config { .. } => ExitCode::from(REFUSED),
            StartError::NoConfig { .. }
            | StartError::Evaluation { .. }
            | StartError::Store { .. }
            | StartError::Supervise(_) => ExitCode::from(FAILED),
        }
    }

    /// Now, in epoch milliseconds.
    fn now_millis() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    /// Re-exported so `start` can name the type in its own error path.
    #[allow(unused_imports, reason = "used by the match above")]
    use supervise as _;
}
