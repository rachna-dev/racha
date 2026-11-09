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
        Command::Start { accept, supervise } => commands::start(accept, supervise),
        Command::Stop => commands::stop(),
        Command::Suspend => commands::suspend(),
        Command::Resume => commands::resume(),
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
    /// Not built yet.
    ///
    /// `cfg`-gated because on macOS NOTHING in this module returns it any
    /// more — `start` boots a guest rather than refusing — and an unused
    /// constant is how a dead exit code outlives the thing that used it.
    #[cfg(not(target_os = "macos"))]
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
    pub(crate) fn start(accept: bool, supervise: bool) -> ExitCode {
        let context = match context() {
            Ok(context) => context,
            Err(why) => {
                eprintln!("rachna: {why}");
                return ExitCode::from(FAILED);
            }
        };

        // A record left by a crashed supervisor is cleared BEFORE the
        // check below, so a crash does not make `start` refuse forever.
        // Separate from the check because `already_running` is a query:
        // deleting inside it made `stop`'s polling loop destroy the record
        // it was about to signal.
        //
        // NOT under `--supervise`. The supervisor is spawned by a `start`
        // that records it and is *about* to — at this instant the record
        // may name a pid that is still starting, so a supervisor clearing
        // "stale" records deletes its own. Measured: `rachna stop` then
        // reported "0 process(es)" against a demonstrably running guest,
        // because there was no record left to read.
        if !supervise {
            run::clear_stale_record(&context);
        }

        // Idempotent: `00` §5.2 makes this the command people type on `cd`.
        //
        // SKIPPED under `--supervise`. The supervisor is spawned BY a
        // `start` that has already recorded it, so it would find its own
        // state file, print "already running" and exit 0 — which is exactly
        // what happened: `start` reported "the supervisor exited with 0"
        // and no guest ran. The parent's record is not evidence about the
        // child.
        match run::already_running(&context) {
            Ok(running) if !running.is_empty() && !supervise => {
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
            // `--accept` in CI covers the SNAPSHOT divergence too, not just
            // an unapproved grant set. Without this a pipeline could never
            // resume at all: `run::accept` records approval of the grant
            // set, the resume gate also asks when a snapshot was taken
            // under different grants, and no flag reached that — so
            // `rachna resume --accept` refused with "not a terminal" on a
            // policy it had just been told to accept.
            if accept && !context.interactive {
                print!("{}", gate.shown);
                if let Some(why) = &gate.divergence {
                    print!("{why}");
                }
                println!("  accepted by --accept");
                return launch_or_supervise(&context, &policy, supervise, true);
            }
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

        // Approved, enforceable, and the user has just read what it
        // permits. Boot it.
        //
        // No second summary print: `gate.shown` above is the one place it
        // appears, so the two cannot disagree.
        // `--supervise` means "I am the held-open process"; a plain
        // `start` spawns one and returns. The gate above runs either way,
        // so a supervisor cannot be a way around it.
        // `true`: the gate is behind us, by keypress or by flag.
        launch_or_supervise(&context, &policy, supervise, true)
    }

    /// Either holds the guest or spawns something that does.
    ///
    /// One function rather than the same three lines at each exit from the
    /// gate: `start` leaves the gate by two paths now (a keypress and
    /// `--accept` in CI), and duplicating the routing is how one of them
    /// comes to skip the supervisor.
    fn launch_or_supervise(
        context: &run::Context,
        policy: &rachna::decide::Policy,
        supervise: bool,
        accepted: bool,
    ) -> ExitCode {
        // On Linux there is nothing to detach from — `supervise.rs` spawns
        // `cloud-hypervisor` as its own process, which already outlives the
        // CLI — so the flag only matters on macOS.
        #[cfg(target_os = "macos")]
        if !supervise {
            return spawn_supervisor(context, accepted);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = supervise;
        launch_approved(context, policy)
    }

    /// Boots the guest for an approved policy.
    ///
    /// Separate from [`start`] because that function's job is the **gate** —
    /// and a gate whose function also owns the launch is one where a future
    /// edit can reach the launch without passing the gate.
    #[cfg(target_os = "macos")]
    fn launch_approved(context: &run::Context, policy: &rachna::decide::Policy) -> ExitCode {
        use rachna::backend::macos_vm::Guest;
        use rachna::boot::{launch_for, provision_root, provision_state, Image};

        let image = match Image::find(&context.rachna_root) {
            Ok(image) => image,
            Err(error) => {
                eprintln!("rachna: {error}");
                return ExitCode::from(FAILED);
            }
        };

        let paths = context.paths();
        let root = match provision_root(&image, &paths) {
            Ok(root) => root,
            Err(error) => {
                eprintln!("rachna: {error}");
                return ExitCode::from(FAILED);
            }
        };
        // The persistent volume, separate from the root. Without it the
        // guest falls back to a tmpfs `/data` and every start is a fresh
        // database — which is what happened before this existed.
        let state = match provision_state(policy, &paths) {
            Ok(state) => state,
            Err(error) => {
                eprintln!("rachna: {error}");
                return ExitCode::from(FAILED);
            }
        };

        let plan = launch_for(policy, &image, &paths, root, state);

        // The snapshot decides HOW the configuration is built, so this is
        // read before constructing the guest rather than after. `02` §4:
        // a restore's config must match the snapshot's, and `Guest::new`
        // truncates the console — a different attachment, which restore
        // rejects with "invalid argument".
        let snapshot = paths.snapshot_dir().join(SNAPSHOT_FILE);
        let restoring = snapshot.exists();

        let built = if restoring {
            Guest::for_restore(&plan)
        } else {
            Guest::new(&plan)
        };
        let guest = match built {
            Ok(guest) => guest,
            Err(error) => {
                eprintln!("rachna: {error}");
                return ExitCode::from(REFUSED);
            }
        };
        // RESTORE if a snapshot is waiting, else cold boot. `02` §4:
        // restore lands `Paused`, so the resume is explicit — which is why
        // this is two calls rather than one.
        let resumed = if restoring {
            match guest.restore(&snapshot).and_then(|()| guest.resume()) {
                Ok(()) => true,
                Err(error) => {
                    // `02` §4: a macOS update can invalidate saved state,
                    // and the requirement is to fall back to a cold boot
                    // LOUDLY rather than fail. A user whose session
                    // silently vanished is a support problem; one told why
                    // is mildly annoyed.
                    eprintln!(
                        "rachna: could not resume from the snapshot ({error}). \
                         Booting fresh instead — the suspended session is lost."
                    );
                    let _ = std::fs::remove_file(&snapshot);
                    false
                }
            }
        } else {
            false
        };

        if !resumed {
            if let Err(error) = guest.start() {
                eprintln!("rachna: {error}");
                return ExitCode::from(FAILED);
            }
        }

        // Waits for the guest to say it is up, rather than printing
        // "started" the moment the hypervisor returns. `02` §6.3 measured a
        // VM reporting Running with a guest that had produced nothing, so
        // the console is the only honest evidence.
        //
        // A RESUMED guest is skipped: its services came back with its
        // memory and it will never print the boot marker again, so waiting
        // for one would time out on a working environment.
        let up = resumed
            || guest.wait_for_console(
                &plan.console_log,
                GUEST_READY_MARKER,
                std::time::Duration::from_secs(GUEST_BOOT_BUDGET_SECS),
            );
        if !up {
            eprintln!(
                "rachna: the guest did not finish starting within {GUEST_BOOT_BUDGET_SECS}s. \
                 Its console is at {}",
                plan.console_log.display()
            );
            let _ = guest.stop();
            return ExitCode::from(FAILED);
        }

        println!("started");
        println!("  console: {}", plan.console_log.display());
        if !guest.can_snapshot() {
            // `00` §3.7: a capability that is absent must be SAID so, not
            // discovered at the first `rachna suspend`.
            println!("  note: this configuration cannot be suspended");
        }

        // Holds the guest until asked to stop. This process IS the VM
        // (`02` §6), so returning would kill it — which is why `start`
        // spawns this rather than doing it inline.
        let request = rachna::supervise::shutdown_request(&paths);
        let suspend = rachna::supervise::suspend_request(&paths);
        loop {
            let state = guest.state();
            if state != rachna::backend::macos_vm::VmState::Running {
                // SAYS WHY. A supervisor that exits silently is
                // indistinguishable from one that crashed, and `stop` then
                // reports "0 process(es)" for a guest that stopped on its
                // own — which is what sent me looking at `stop` when the
                // supervisor was the problem.
                eprintln!("rachna: the guest is {state:?}, so the supervisor is exiting");
                return ExitCode::from(OK);
            }
            // `rachna suspend` asks here. Checked BEFORE the shutdown
            // request: the two are different files precisely so a suspend
            // cannot be mistaken for a stop, and a guest asked to do both
            // should keep its state rather than discard it.
            if suspend.exists() {
                let _ = std::fs::remove_file(&suspend);
                // pause -> save -> stop (`02` §4's compound suspend).
                let outcome = guest
                    .pause()
                    .and_then(|()| guest.save(&snapshot))
                    .and_then(|()| guest.stop());
                if let Err(error) = outcome {
                    eprintln!("rachna: could not suspend: {error}");
                    // The snapshot may be partial, and `24` §6 measured a
                    // two-of-three snapshot restoring with no error at all
                    // — so a failed save must not leave a file `resume`
                    // would trust.
                    let _ = std::fs::remove_file(&snapshot);
                    return ExitCode::from(FAILED);
                }
                return ExitCode::from(OK);
            }

            // `rachna stop` asks here before it signals. Honouring the
            // request means the guest's init unmounts and syncs; being
            // killed instead left the state volume corrupt (`02` §6.10).
            if request.exists() {
                if let Err(error) = guest.shutdown(GRACEFUL_SHUTDOWN) {
                    // Nothing to recover: `shutdown` already fell back to a
                    // destructive stop. Recorded on the console, which is
                    // where a supervisor's output goes.
                    eprintln!("rachna: shutting the guest down: {error}");
                }
                return ExitCode::from(OK);
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    /// How long the supervisor gives its guest to shut itself down.
    ///
    /// Shorter than `run::GRACEFUL_STOP`, deliberately: `stop` waits for
    /// the supervisor, so the inner budget must fit inside the outer one or
    /// `stop` gives up and signals while the guest is still flushing.
    #[cfg(target_os = "macos")]
    const GRACEFUL_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(15);

    /// Spawns a supervisor to hold the guest, and returns.
    ///
    /// # Why `start` cannot just boot the VM itself
    ///
    /// A VZ guest lives **inside** the process that created it (`02` §6), so
    /// a `start` that booted it directly would have to block forever — and
    /// that is not a design choice, it is a broken command: it never
    /// returns, so nothing can script it, and `tests/cli_binary.rs`'s
    /// `no_invocation_panics` hung the entire gate the first time this was
    /// wired that way. **A command that cannot return cannot be tested.**
    ///
    /// So `start` re-executes itself with `--supervise`, records that pid
    /// where `stop` looks, and returns. The hidden flag is the mechanism
    /// `supervise.rs` already assumes: a pid in a state file that `stop`
    /// signals.
    #[cfg(target_os = "macos")]
    fn spawn_supervisor(context: &run::Context, accepted: bool) -> ExitCode {
        use rachna::supervise::{self, Role, Running, Supervised};

        let paths = context.paths();
        let runtime = paths.runtime_dir();
        if let Err(error) = std::fs::create_dir_all(&runtime) {
            eprintln!("rachna: cannot create {}: {error}", runtime.display());
            return ExitCode::from(FAILED);
        }

        let binary = match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("rachna: cannot find my own binary: {error}");
                return ExitCode::from(FAILED);
            }
        };

        // Its output goes to a FILE, not to /dev/null. Discarding it threw
        // away the only diagnostic the supervisor has: a failed restore
        // falls back to a cold boot and says so loudly — and that message
        // went nowhere, so a resume that silently rebooted looked like the
        // restore path never ran at all.
        //
        // Not inherited from this terminal either: a stdout tied to the
        // parent's pipe would keep it open after `start` returns, so the
        // shell would appear to hang.
        let log_path = runtime.join("supervisor.log");
        let supervisor_log = std::fs::File::create(&log_path);
        let (out, err) = match supervisor_log {
            Ok(file) => match file.try_clone() {
                Ok(second) => (
                    std::process::Stdio::from(file),
                    std::process::Stdio::from(second),
                ),
                Err(_) => (std::process::Stdio::null(), std::process::Stdio::null()),
            },
            Err(_) => (std::process::Stdio::null(), std::process::Stdio::null()),
        };

        // `--accept` IS FORWARDED. The supervisor runs the same gate (that
        // is the point — a supervisor must not be a way around it), so
        // without the flag it reached the resume gate with no way through
        // and refused with "not a terminal" after the parent had already
        // accepted. The guest then cold-booted instead of resuming, which
        // looked like the restore path was never taken at all.
        //
        // Safe to forward: at this point the parent has either recorded a
        // human's keypress or been given the flag itself, so the
        // supervisor is re-checking a decision already made rather than
        // making a new one.
        let mut spawn = std::process::Command::new(&binary);
        spawn.arg("start").arg(SUPERVISE_FLAG);
        if accepted {
            spawn.arg("--accept");
        }
        let child = spawn
            .current_dir(&context.project_dir)
            .stdin(std::process::Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                eprintln!("rachna: cannot start the supervisor: {error}");
                return ExitCode::from(FAILED);
            }
        };

        let running = Running {
            processes: vec![Supervised {
                role: Role::Supervisor,
                pid: child.id(),
            }],
            transient: Vec::new(),
        };
        let state = supervise::state_file(&paths);
        if let Err(error) = std::fs::write(&state, running.to_text()) {
            // Nothing could stop it, so stop it now — the same rule
            // `run::launch` applies: a guest nobody can stop is worse than
            // no guest.
            let _ = rustix::process::kill_process(
                rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX))
                    .unwrap_or(rustix::process::Pid::INIT),
                rustix::process::Signal::TERM,
            );
            eprintln!(
                "rachna: started, but could not record it in {}: {error}. \
                 The guest has been stopped.",
                state.display()
            );
            return ExitCode::from(FAILED);
        }

        // Waits for the guest to say it is up before reporting success.
        // `02` §6.3: a VM reports Running with a guest that has produced
        // nothing, so the console is the only honest evidence — and a
        // `start` that returns before the database is ready is a `start`
        // whose next command fails.
        let console = paths.console_log();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(GUEST_BOOT_BUDGET_SECS);
        while std::time::Instant::now() < deadline {
            if std::fs::read_to_string(&console)
                .unwrap_or_default()
                .contains(GUEST_READY_MARKER)
            {
                println!("started");
                println!("  console: {}", console.display());
                println!("  stop it with: rachna stop");
                return ExitCode::from(OK);
            }
            // THE SUPERVISOR'S OWN EXIT, checked every turn. Without this
            // a supervisor that died immediately — no guest image, a
            // refused configuration — still cost the FULL boot budget
            // before `start` said anything, because the loop only watched
            // for success. Found by the test that asserts `start` returns:
            // it took 180s.
            //
            // `try_wait` rather than `wait`: the supervisor normally
            // outlives us, so blocking on it would be the bug this whole
            // function exists to avoid.
            match child.try_wait() {
                Ok(Some(status)) => {
                    let _ = std::fs::remove_file(&state);
                    eprintln!(
                        "rachna: the environment did not start. The \
                         supervisor exited with {}.",
                        status.code().map_or_else(
                            || "no code (signalled)".to_owned(),
                            |code| code.to_string()
                        )
                    );
                    // Its own stderr went nowhere by design (a stderr tied
                    // to this terminal would keep the pipe open), so point
                    // at the console, which is where a guest's own
                    // complaints land (`05` §4.3).
                    if console.exists() {
                        eprintln!("  console: {}", console.display());
                    }
                    if log_path.exists() {
                        eprintln!("  supervisor: {}", log_path.display());
                    }
                    // The supervisor's exit code, so a script sees the
                    // real reason rather than a generic failure.
                    return ExitCode::from(
                        u8::try_from(status.code().unwrap_or(i32::from(FAILED))).unwrap_or(FAILED),
                    );
                }
                // Still running, which is the normal case.
                Ok(None) => {}
                Err(error) => {
                    eprintln!("rachna: cannot check on the supervisor: {error}");
                    return ExitCode::from(FAILED);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        eprintln!(
            "rachna: the guest did not finish starting within \
             {GUEST_BOOT_BUDGET_SECS}s. Its console is at {}, and `rachna \
             stop` will tear it down",
            console.display()
        );
        ExitCode::from(FAILED)
    }

    /// The hidden flag that makes a `rachna start` hold the guest.
    ///
    /// Not in `--help`: it is not for users, it is how `start` re-executes
    /// itself. `cli.rs` rejects unknown flags, so this is parsed there
    /// rather than sniffed from `argv` in two places.
    pub(crate) const SUPERVISE_FLAG: &str = "--supervise";

    /// Boots the guest for an approved policy.
    ///
    /// The Linux path goes through `supervise.rs`, which spawns
    /// `cloud-hypervisor` as a separate process — a different shape from
    /// macOS entirely (`02` §6), which is why these are separate functions
    /// rather than one with a `cfg` inside it.
    #[cfg(not(target_os = "macos"))]
    fn launch_approved(_context: &run::Context, _policy: &rachna::decide::Policy) -> ExitCode {
        eprintln!(
            "rachna: the Linux launch path needs the guest bundle from \
             `guest/flake.nix` (01 §7.0c). On macOS this works today; see \
             ci/build-guest-aarch64.sh for how the image is assembled."
        );
        ExitCode::from(UNIMPLEMENTED)
    }

    /// What the guest prints when its services are up.
    ///
    /// Matched against the console rather than inferred from the VM's
    /// state, per `02` §6.3.
    const GUEST_READY_MARKER: &str = "RACHNA-SERVICES-UP";

    /// How long to wait for that marker.
    ///
    /// Generous because a first boot runs `initdb`: `05` §5 measured 6.97 s
    /// to a bare NixOS userspace, and a database adds to that.
    const GUEST_BOOT_BUDGET_SECS: u64 = 180;

    /// `rachna suspend`.
    ///
    /// Asks the running supervisor to write its guest's memory to disk and
    /// stop. The supervisor does the work because it **holds the VM** — a
    /// VZ guest lives inside its creating process (`02` §6), so no other
    /// process can save it.
    pub(crate) fn suspend() -> ExitCode {
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
            // Not an error: `00` §5.2's spirit is that these commands are
            // safe to type when you are unsure what is going on.
            println!("nothing to suspend");
            return ExitCode::from(OK);
        }

        let paths = context.paths();
        let request = rachna::supervise::suspend_request(&paths);
        if let Err(error) = std::fs::write(&request, b"suspend\n") {
            eprintln!("rachna: cannot ask the supervisor to suspend: {error}");
            return ExitCode::from(FAILED);
        }

        // Waits for the supervisor to go, because a `suspend` that returns
        // while the memory is still being written would let the next
        // command see a half-written snapshot.
        let deadline = std::time::Instant::now() + SUSPEND_BUDGET;
        while std::time::Instant::now() < deadline {
            match run::already_running(&context) {
                Ok(now) if now.is_empty() => {
                    let _ = std::fs::remove_file(&request);
                    run::clear_stale_record(&context);
                    let snapshot = paths.snapshot_dir().join(SNAPSHOT_FILE);
                    if snapshot.exists() {
                        let size = std::fs::metadata(&snapshot).map_or(0, |m| m.len());
                        println!("suspended ({} MiB)", size / 1024 / 1024);
                        // NOT "resume it with: rachna resume" on macOS —
                        // that is an offered command that does not work
                        // (`02` §6.11), and `00` §3.3's rule makes naming
                        // a broken action worse than naming none.
                        if cfg!(target_os = "macos") {
                            println!(
                                "  note: the memory snapshot cannot be restored yet \
                                 (02 §6.11)."
                            );
                            println!(
                                "  `rachna start` boots fresh; your data is on the \
                                 state volume, not in the snapshot."
                            );
                        } else {
                            println!("  resume it with: rachna resume");
                        }
                        return ExitCode::from(OK);
                    }
                    // The supervisor stopped and wrote nothing. Reported as
                    // a failure rather than a suspend, because `resume`
                    // would then find nothing and the user would have lost
                    // the running state believing it was saved.
                    eprintln!(
                        "rachna: the environment stopped but no snapshot was written. \
                         Its console is at {}",
                        paths.console_log().display()
                    );
                    return ExitCode::from(FAILED);
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("rachna: {error}");
                    return ExitCode::from(FAILED);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        let _ = std::fs::remove_file(&request);
        eprintln!(
            "rachna: the environment did not suspend within {}s. It is still \
             running; `rachna stop` will tear it down, losing its state",
            SUSPEND_BUDGET.as_secs()
        );
        ExitCode::from(FAILED)
    }

    /// `rachna resume`.
    ///
    /// Boots from a snapshot rather than cold. **Goes through the policy
    /// gate**, like `start`: `00` §3.10c's correction makes the summary
    /// unconditional on every resume, and a snapshot taken under grants
    /// `rachna.nix` no longer declares needs a keypress.
    pub(crate) fn resume() -> ExitCode {
        let context = match context() {
            Ok(context) => context,
            Err(why) => {
                eprintln!("rachna: {why}");
                return ExitCode::from(FAILED);
            }
        };

        // MEASURED LIMIT, stated before anything runs. `02` §6.11: a
        // rebuilt VZ configuration cannot restore — the same object can,
        // and `resume` is a different process, so it has no way to offer
        // one. Attempting it would cold-boot and discard the suspended
        // session, which is worse than refusing: a user who is told
        // "cannot resume" still has their state on disk, and one who is
        // told "started" has lost it.
        //
        // Not a `todo!`: the mechanism works within a process, and which
        // way to close this is a product decision (`02` §6.11's table).
        if cfg!(target_os = "macos") {
            eprintln!(
                "rachna: `resume` cannot restore a suspended session yet. \
                 Virtualization.framework refuses a rebuilt configuration \
                 (02 §6.11, measured), and `resume` is a separate process \
                 from the one that saved."
            );
            eprintln!(
                "  your data is safe: it lives on the state volume, not in \
                 the snapshot. `rachna start` boots fresh and the database \
                 comes back."
            );
            return ExitCode::from(UNIMPLEMENTED_RESUME);
        }

        let snapshot = context.paths().snapshot_dir().join(SNAPSHOT_FILE);
        if !snapshot.exists() {
            // Names the alternative, per `00` §3.3 — a user with no
            // snapshot wants to know what to type, not that a file is
            // absent.
            eprintln!(
                "rachna: nothing to resume (no snapshot at {}). \
                 `rachna start` boots a fresh environment",
                snapshot.display()
            );
            return ExitCode::from(FAILED);
        }

        // `start` with the snapshot present IS resume: it runs the gate,
        // spawns the supervisor, and the supervisor restores rather than
        // cold-boots when a snapshot is there. One path, so a resume
        // cannot skip a check that `start` makes.
        start(false, false)
    }

    /// `resume` is not available: 70, "not built yet".
    ///
    /// Distinct from a refusal (77): the policy is fine and the host is
    /// fine, the mechanism is missing.
    const UNIMPLEMENTED_RESUME: u8 = 70;

    /// The snapshot's filename, inside the project's `snapshots/`.
    ///
    /// One name rather than a timestamped series: `00` §7's suspend/resume
    /// is "close the laptop and come back", not a history. A named series
    /// is `rachna snapshot`'s job if that verb is ever built.
    pub(crate) const SNAPSHOT_FILE: &str = "memory.vzvmsave";

    /// How long `suspend` waits for the memory to be written.
    ///
    /// `24` §4 measured 152-329 ms to snapshot a real guest and `16` §4
    /// measured 2735 ms with Postgres and Node running, so this is that
    /// with room for a guest that has touched much more memory.
    const SUSPEND_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

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
