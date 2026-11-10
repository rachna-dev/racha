//! The binary, end to end.
//!
//! `21-SPEC-AUDIT.md` §2.4 recorded "no `--help` text" as a gap, and `17` §1
//! accepted hand-written help as the cost of choosing `lexopt`. These tests
//! are what keeps that hand-written text honest: a verb the parser accepts
//! but the help omits is undiscoverable, and a verb the help advertises but
//! the parser rejects is a lie.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

fn rachna(args: &[&str]) -> (String, String, i32) {
    let binary = env!("CARGO_BIN_EXE_rachna");
    let output = Command::new(binary)
        .args(args)
        .output()
        .expect("the binary runs");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

#[test]
fn every_verb_the_parser_accepts_appears_in_the_help() {
    // A verb that parses but is not documented is undiscoverable, which for
    // a tool with no generated help is the failure mode to guard against.
    let (help, _, code) = rachna(&["--help"]);
    assert_eq!(code, 0);
    for verb in [
        "init", "start", "stop", "suspend", "resume", "status", "doctor", "config", "audit",
        "explain", "allow",
    ] {
        assert!(help.contains(verb), "`{verb}` is undocumented:\n{help}");
    }
    for flag in ["--template", "--accept", "--narrow", "--ci", "--read-only"] {
        assert!(help.contains(flag), "`{flag}` is undocumented:\n{help}");
    }
}

#[test]
fn the_help_states_the_product_invariant() {
    // The one thing a user must understand: the file is the only authority.
    let (help, _, _) = rachna(&["--help"]);
    assert!(help.contains("rachna.nix is the only authority"), "{help}");
}

#[test]
fn version_prints_the_version_and_exits_zero() {
    let (stdout, _, code) = rachna(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("rachna "), "{stdout}");
}

#[test]
fn an_unknown_command_exits_with_a_usage_code_and_a_suggestion() {
    // 64 is the conventional EX_USAGE. Exit codes are an API (`21` §3.3):
    // a script must be able to tell a usage error from a policy denial.
    let (_, stderr, code) = rachna(&["statu"]);
    assert_eq!(code, 64, "stderr: {stderr}");
    assert!(stderr.contains("did you mean `status`"), "{stderr}");
}

#[test]
fn an_unimplemented_verb_says_so_rather_than_panicking() {
    // A user on a half-built tool should get a sentence, not a backtrace.
    //
    // `status` used to be the example here and now WORKS, which is what
    // this test caught. `audit` is the current one — it needs the query
    // layer over the store.
    let (_, stderr, code) = rachna(&["audit"]);
    assert_eq!(code, 70, "stderr: {stderr}");
    assert!(stderr.contains("not built yet"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn status_reports_rather_than_refusing() {
    // HERMETIC, via HOME. This test read the developer's real `~/.rachna`
    // and failed on a state file left by an earlier buggy build: a dead pid
    // in a format the parser no longer accepted. The assertion was right
    // and the environment was shared, which is the worse kind of flake —
    // it fails for reasons that have nothing to do with the change under
    // test, and it can also PASS because of leftovers.
    let home = std::env::temp_dir().join(format!("rachna-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("scratch home");

    // The first verb that does real work. It runs in any directory — a
    // project with no `rachna.nix` is "stopped", not an error, because
    // `00` §5.2 makes `status` the thing you type when you are not sure
    // what is going on.
    let binary = env!("CARGO_BIN_EXE_rachna");
    let output = Command::new(binary)
        .arg("status")
        .env("HOME", &home)
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("stopped") || stdout.contains("running"),
        "stdout: {stdout}"
    );
    // And it names where the state lives, so a user can find or delete it.
    assert!(stdout.contains("state:"), "stdout: {stdout}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn no_invocation_panics() {
    // Over every verb and several malformed forms: a panic in argument
    // handling is the one failure a user cannot act on.
    let invocations: &[&[&str]] = &[
        &[],
        &["--help"],
        &["--version"],
        &["init"],
        &["init", "--template"],
        &["start", "--accept"],
        &["stop", "--force"],
        &["config"],
        &["config", "nonsense"],
        &["audit", "--narrow", "--ci"],
        &["explain"],
        &["allow"],
        &["allow", "fs", "/w", "--read-only", "--read-write"],
        &["xyzzy"],
        &["-"],
        &["--"],
    ];
    for args in invocations {
        let (_, stderr, code) = rachna(args);
        assert!(!stderr.contains("panicked"), "{args:?} panicked:\n{stderr}");
        // The defined set, per `21` §3.3's "exit codes are an API". It grew
        // when `start` and `stop` began doing work, and this assertion is
        // what caught that — a verb returning an undefined code is a script
        // that cannot branch on it.
        //
        //   0   worked
        //   64  EX_USAGE — the invocation was not understood
        //   70  not built yet
        //   74  tried and failed
        //   77  refused: the policy is wrong, or cannot be enforced
        assert!(
            matches!(code, 0 | 64 | 70 | 74 | 77),
            "{args:?} exited {code}, which is not a defined code"
        );
    }
}

#[test]
fn a_command_that_cannot_work_exits_non_zero() {
    // THE gap mutation testing found. `every_defined_exit_code_is_one_of_the_set`
    // asserts the code is in `{0, 64, 70, 74, 77}` — and **0 is in that
    // set**, so a mutant replacing any command's body with
    // `Default::default()` (which is `ExitCode::SUCCESS`) satisfies it.
    // Roughly a dozen survivors were exactly that shape.
    //
    // So this asserts the code is NOT zero where it must not be. Each case
    // is a situation a user reaches by accident, and a script branching on
    // success would do the wrong thing for every one of them.
    let dir = std::env::temp_dir().join(format!("rachna-nonzero-{}", std::process::id()));
    let home = dir.join("home");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&home).expect("scratch dirs");

    let binary = env!("CARGO_BIN_EXE_rachna");
    let run = |args: &[&str]| -> (String, i32) {
        let out = Command::new(binary)
            .args(args)
            .current_dir(&dir)
            .env("HOME", &home)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the binary runs");
        (
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            out.status.code().unwrap_or(-1),
        )
    };

    // No `rachna.nix` at all. `start` must refuse — it has nothing to
    // evaluate — and so must `resume`, which is asked to restore something
    // that does not exist.
    //
    // `suspend` is NOT in this list, and that is the contract rather than
    // an oversight: with nothing running it prints "nothing to suspend" and
    // exits 0, because `00` §5.2 makes these commands safe to type when you
    // are unsure what is going on. Asserting non-zero there failed, which
    // is the test learning the contract rather than the contract being
    // wrong.
    for args in [vec!["start"], vec!["resume"], vec!["resume", "a-name"]] {
        let (text, code) = run(&args);
        assert_ne!(
            code, 0,
            "`{args:?}` succeeded with no rachna.nix, which it cannot have \
             done:\n{text}"
        );
    }

    // And `suspend` with nothing running SUCCEEDS, saying so. Asserted
    // rather than merely excluded above, so the distinction is pinned: a
    // future change making it refuse would be a behaviour change, not a
    // silent one.
    let (text, code) = run(&["suspend"]);
    assert_eq!(
        code, 0,
        "`suspend` with nothing running should succeed:\n{text}"
    );
    assert!(
        text.contains("nothing to suspend"),
        "`suspend` succeeded without saying there was nothing to do:\n{text}"
    );

    // An unusable snapshot name is refused specifically, not merely
    // non-zero: 77 is "the policy or the request is wrong".
    let (text, code) = run(&["resume", "../escape"]);
    assert_eq!(
        code, 77,
        "a path-shaped snapshot name was not refused:\n{text}"
    );

    // And the two that DO work without a config still work — otherwise this
    // test would pass against a binary that refuses everything.
    for args in [vec!["--version"], vec!["--help"], vec!["status"]] {
        let (text, code) = run(&args);
        assert_eq!(code, 0, "`{args:?}` should succeed anywhere:\n{text}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Whether `nix` is on PATH, and therefore whether the policy gate is
/// reachable at all.
///
/// The gate EVALUATES `rachna.nix` before showing it, so without `nix` the
/// binary exits 74 ("could not run `nix`") long before any gate behaviour
/// happens. Two tests asserted gate exit codes and both failed that way in
/// the `mutants` job, whose container has no nix — and the second only
/// surfaced after the first was fixed, which is why this is one helper
/// rather than two copies of the same check.
///
/// The property is still covered in CI: the `devenv` job runs the full gate
/// inside a shell that has nix. "Skips in some jobs" and "unchecked in CI"
/// are different claims.
fn nix_is_available() -> bool {
    std::process::Command::new("nix")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn every_start_prints_the_access_summary_even_when_approved() {
    // THE user-reported defect, at the binary. `00` §3.10c once said
    // "thereafter start is silent", the implementation followed it, and a
    // second `start` printed nothing and launched. The correction: the
    // summary prints every time; only the keypress is conditional.
    //
    // Driven through the real binary because the defect was in `main.rs`'s
    // wiring — `run::check` can be right while nothing prints it.
    let dir = std::env::temp_dir().join(format!("rachna-gate-{}", std::process::id()));
    let home = dir.join("home");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&home).expect("scratch dirs");

    let binary = env!("CARGO_BIN_EXE_rachna");
    let run = |args: &[&str]| -> (String, i32) {
        let output = Command::new(binary)
            .args(args)
            .current_dir(&dir)
            .env("HOME", &home)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the binary runs");
        (
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            output.status.code().unwrap_or(-1),
        )
    };

    if !nix_is_available() {
        println!("SKIP: no `nix` on PATH, so the gate is never reached");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let (_, code) = run(&["init"]);
    assert_eq!(code, 0, "init failed");
    let config = dir.join("rachna.nix");
    let text = std::fs::read_to_string(&config).expect("rachna.nix");
    // WIDENED WITH A MOUNT, not a network allowlist. A network grant is
    // refused before the gate on any host that cannot enforce it — Linux
    // reports "this host cannot enforce it: rachna-netd is not built yet"
    // — so the gate never runs and the assertions below describe output
    // that was never produced. This test passed on macOS and failed in the
    // `devenv` job for that reason.
    //
    // The grant only has to be non-empty and enforceable everywhere.
    std::fs::write(
        &config,
        text.replace(
            "network.allow = [ ];",
            "network.allow = [ ];\n  filesystem.mounts = [ { source = \"/tmp\"; } ];",
        ),
    )
    .expect("widen");

    // First start: unapproved, so it refuses and names the commands.
    let (first, code) = run(&["start"]);
    assert_eq!(code, 77, "an unapproved start did not refuse:\n{first}");
    assert!(first.contains("/tmp"), "{first}");
    // And it refuses for the RIGHT reason. Without this, a piped start that
    // wrongly tried to read stdin would hit EOF, abort, and exit 77 by a
    // different route — the same code, so the assertion above cannot tell
    // the two apart. A mutant flipping that condition survived on exactly
    // this ambiguity.
    assert!(
        first.contains("not a terminal"),
        "a piped start did not say why it could not ask:\n{first}"
    );
    assert!(
        !first.contains("not started"),
        "a piped start read stdin instead of refusing outright:\n{first}"
    );

    // Approve (non-TTY, so the flag applies).
    let (_, code) = run(&["start", "--accept"]);
    assert_ne!(code, 77, "--accept did not record the approval");

    // THE ASSERTION. The second start must still say what it permits.
    let (second, _) = run(&["start"]);
    assert!(
        second.contains("/tmp"),
        "an approved start was SILENT about what it permits:\n{second}"
    );
    // And it must not claim this is the first run, which would be a lie the
    // user can detect — and a gate they stop believing.
    assert!(
        !second.contains("has not run here before"),
        "an approved start claimed it had never run here:\n{second}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn start_returns_rather_than_blocking_forever() {
    // THE property, and it is not obvious. A VZ guest lives inside the
    // process that created it (`02` §6), so the first wiring of `start`
    // booted the VM inline and blocked forever to keep it alive. That hung
    // `no_invocation_panics` and with it the whole gate — the suite simply
    // stopped, with no failure to read.
    //
    // A command that cannot return cannot be scripted and cannot be
    // tested, so `start` spawns a supervisor and returns. This asserts the
    // RETURNING, not the booting: it runs with no guest image installed,
    // which is a fast refusal on any host.
    let dir = std::env::temp_dir().join(format!("rachna-returns-{}", std::process::id()));
    let home = dir.join("home");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&home).expect("scratch dirs");

    let binary = env!("CARGO_BIN_EXE_rachna");
    let run = |args: &[&str]| -> i32 {
        Command::new(binary)
            .args(args)
            .current_dir(&dir)
            .env("HOME", &home)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the binary runs")
            .status
            .code()
            .unwrap_or(-1)
    };
    assert_eq!(run(&["init"]), 0, "init failed");

    // `--accept` so the gate does not refuse first: the point is what
    // happens AFTER approval, which is where the block was.
    let started = std::time::Instant::now();
    let code = run(&["start", "--accept"]);
    let took = started.elapsed();

    assert!(
        took < std::time::Duration::from_secs(60),
        "`start` took {took:?} — it is blocking rather than returning"
    );
    // Any defined code is fine; hanging is not. With no image installed
    // this refuses, which is the fast path.
    assert!(
        matches!(code, 0 | 64 | 70 | 74 | 77),
        "`start` exited {code}, which is not a defined code"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn accept_is_ignored_at_a_terminal_and_required_in_a_pipeline() {
    // `00` §3.10c, in bold: **"`--accept` does nothing at a TTY, and that
    // is deliberate. It is the CI path and only the CI path."** A flag that
    // worked interactively would let a user accept a cloned config's
    // permissions in the same breath as asking to start it — never seeing
    // the summary — which is the one outcome that section exists to
    // prevent.
    //
    // **Nothing asserted this**, and I used `rachna start --accept` as my
    // demo command throughout a session, presenting the forbidden shortcut
    // as the normal way to use the tool. The enforcement was right; the
    // habit was not, and an unasserted property is one nobody is told
    // about when it breaks.
    //
    // BOTH halves are tested, and the TTY half needs a real pty: removing
    // the `!context.interactive` guard left a pipe-only version of this
    // test passing, because a pipe exercises the branch where the flag is
    // SUPPOSED to work. A test that cannot fail when the property is
    // removed is not testing it.
    let dir = std::env::temp_dir().join(format!("rachna-accept-{}", std::process::id()));
    let home = dir.join("home");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&home).expect("scratch dirs");
    // A config with a REAL grant: an empty grant set needs no
    // acknowledgement (there is nothing to accept), so testing against one
    // would pass whatever the flag did. That is exactly the weak test that
    // first made me think the gate had been defeated.
    std::fs::write(
        dir.join("rachna.nix"),
        // A FILESYSTEM mount, not a network grant. A network allowlist is
        // refused BEFORE the gate on a host that cannot enforce it — Linux
        // says "this host cannot enforce it: rachna-netd is not built yet"
        // — so the gate never runs and "not a terminal" never prints. The
        // test passed on macOS and failed in the `devenv` job for exactly
        // that reason.
        //
        // The grant only has to be non-empty: `needs_input` requires a
        // non-empty summary, and a mount is enforceable on every platform.
        "{\n  tier = \"allowlist\";\n  profile = \"development\";\n  \
         filesystem.mounts = [ { source = \"/tmp\"; } ];\n}\n",
    )
    .expect("config");

    let binary = env!("CARGO_BIN_EXE_rachna");
    let run = |args: &[&str]| -> (String, i32) {
        let out = Command::new(binary)
            .args(args)
            .current_dir(&dir)
            .env("HOME", &home)
            // The pipe IS the condition under test: no terminal.
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the binary runs");
        (
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            out.status.code().unwrap_or(-1),
        )
    };

    // THE GATE NEEDS `nix`, because the policy is evaluated before it is
    // shown. Without `nix` on PATH `rachna` exits 74 (cannot evaluate)
    // long before reaching the gate, which is correct behaviour and not
    // what this test is about — it failed exactly that way in the
    // `mutants` job, whose container has no nix.
    //
    // Said out loud rather than passing quietly: a green run that silently
    // checked nothing is the failure mode this whole test exists to
    // prevent.
    //
    // The property is still checked in CI — the `devenv` job runs the full
    // gate inside a shell that HAS nix, so this skips only in the jobs
    // that could never reach the gate. Worth stating, because "it skips in
    // CI" and "it is unchecked in CI" are different claims.
    if !nix_is_available() {
        println!("SKIP: no `nix` on PATH, so the gate is never reached");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // WITHOUT the flag, piped: refused, and it says which refusal this is
    // rather than leaving a pipeline to guess.
    let (text, code) = run(&["start"]);
    assert_eq!(code, 77, "a piped start was not refused: {text}");
    assert!(
        text.contains("not a terminal"),
        "the refusal does not say why: {text}"
    );
    assert!(
        text.contains("--accept"),
        "the refusal does not name the action a pipeline can take: {text}"
    );
    // And the summary is shown BEFORE the refusal: `00` §3.10c wants the
    // grants visible every time, not only when they are accepted.
    assert!(text.contains("/tmp"), "the grants were not shown: {text}");

    // WITH the flag, piped: the CI path, so it gets past the gate. It may
    // still fail later for want of a guest image — what matters is that it
    // is no longer the GATE refusing.
    let (accepted, _) = run(&["start", "--accept"]);
    assert!(
        !accepted.contains("not a terminal"),
        "--accept did not satisfy the gate in a pipeline: {accepted}"
    );

    // AT A TERMINAL the flag must do nothing, and this is the half that
    // matters: `interactive` comes from `stdin().is_terminal()`, so only a
    // real pty reaches the branch `00` §3.10c cares about.
    //
    // Driven from RUST, via `rustix::pty`. The first version shelled out to
    // `python3`, which does not exist in the devenv shell where tests run —
    // so it captured nothing and skipped silently, forever. A test that
    // cannot run in the project's own test environment is not a test.
    // A SEPARATE HOME. The piped `--accept` above RECORDED an approval, so
    // by this point the grant set is approved and there is nothing left to
    // gate — the first version of this test asserted against "running
    // under these grants" and failed for its own earlier side effect.
    // Approval is per-project-per-machine state, and a test that shares it
    // between cases is testing the order it happens to run them in.
    let fresh_home = dir.join("home-tty");
    std::fs::create_dir_all(&fresh_home).expect("a fresh home");

    let pty =
        rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)
            .expect("a pty");
    rustix::pty::grantpt(&pty).expect("grantpt");
    rustix::pty::unlockpt(&pty).expect("unlockpt");
    let name = rustix::pty::ptsname(&pty, Vec::new()).expect("ptsname");
    let slave_path =
        std::path::PathBuf::from(String::from_utf8(name.into_bytes()).expect("a utf-8 tty name"));

    // The child's stdin IS the pty slave, which is what makes
    // `is_terminal()` true for it.
    let slave_in = std::fs::File::open(&slave_path).expect("open the slave");
    let slave_out = std::fs::OpenOptions::new()
        .write(true)
        .open(&slave_path)
        .expect("open the slave for writing");
    let mut child = Command::new(binary)
        .args(["start", "--accept"])
        .current_dir(&dir)
        .env("HOME", &fresh_home)
        .stdin(std::process::Stdio::from(slave_in))
        .stdout(std::process::Stdio::from(
            slave_out.try_clone().expect("clone"),
        ))
        .stderr(std::process::Stdio::from(slave_out))
        .spawn()
        .expect("spawn under a pty");

    // Read until the question appears, it starts anyway, or time runs out.
    // No key is ever sent: the point is that it must WAIT.
    let mut seen = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut buffer = [0_u8; 4096];
    while std::time::Instant::now() < deadline {
        match rustix::io::read(&pty, &mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                seen.push_str(&String::from_utf8_lossy(&buffer[..n]));
                if seen.contains("[a] accept") || seen.contains("started") {
                    break;
                }
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !seen.trim().is_empty(),
        "the pty captured nothing, so this asserted on no evidence"
    );
    assert!(
        seen.contains("[a] accept"),
        "`start --accept` at a TTY did not ask for the keypress, so the flag \
         is a shortcut past the gate — `00` §3.10c forbids exactly this. \
         Got:\n{seen}"
    );
    assert!(
        !seen.contains("started"),
        "`start --accept` STARTED at a TTY with no keypress:\n{seen}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn snapshot_names_are_validated_before_anything_is_written() {
    // A snapshot name becomes a FILENAME, so `../escape` is an attempt to
    // write outside the project whether or not anyone meant it that way —
    // the same reasoning `layout::ProjectId` applies to project
    // directories.
    //
    // Checked at the binary because that is where a name arrives: the
    // module's own tests prove the rule, and this proves the rule is
    // reached before any work happens.
    let dir = std::env::temp_dir().join(format!("rachna-snapname-{}", std::process::id()));
    let home = dir.join("home");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&home).expect("scratch dirs");

    let binary = env!("CARGO_BIN_EXE_rachna");
    let run = |args: &[&str]| -> (String, i32) {
        let out = Command::new(binary)
            .args(args)
            .current_dir(&dir)
            .env("HOME", &home)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the binary runs");
        (
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            out.status.code().unwrap_or(-1),
        )
    };
    assert_eq!(run(&["init"]).1, 0, "init failed");

    // First assert a GOOD name gets past validation, or the refusals below
    // would pass against a verb that refuses everything.
    let (good, _) = run(&["resume", "a-fine-name"]);
    assert!(
        !good.contains("not a path") && !good.contains("typeable"),
        "a valid name was refused as invalid: {good}"
    );

    for attempt in ["../escape", "a/b", ".."] {
        let (text, code) = run(&["resume", attempt]);
        assert_eq!(code, 77, "`{attempt}` was not refused: {text}");
        assert!(
            text.contains("not a path"),
            "`{attempt}` was refused without saying why: {text}"
        );
    }

    // `snapshots` runs anywhere and reports rather than failing — the same
    // rule `status` follows (`00` §5.2).
    let (listing, code) = run(&["snapshots"]);
    assert_eq!(code, 0, "snapshots failed: {listing}");
    assert!(
        listing.contains("rachna suspend"),
        "an empty listing should say how to make one: {listing}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "macos")]
#[test]
fn the_binary_carries_the_virtualization_entitlement() {
    // 02 §4, measured: without `com.apple.security.virtualization`,
    // VZVirtualMachine.init THROWS NSInvalidArgumentException — a crash
    // rather than an error return. So an unsigned binary does not degrade,
    // it dies, and `ci/gate.sh` signs as part of the gate.
    //
    // Asserted on the built artefact rather than trusting the script, since
    // `codesign` exits 0 whether or not the entitlement took.
    //
    // THE SIGNATURE IS SIGNED HERE, not assumed. Any `cargo build` or `cargo
    // test` relinks the binary and DISCARDS its signature — found by this
    // test failing against a binary the gate had just signed. So "the gate
    // signs it" is not a property that survives the next build, and a
    // release process must sign after its final link, never before.
    let binary = env!("CARGO_BIN_EXE_rachna");
    let signed = Command::new("./ci/sign-macos.sh")
        .arg(binary)
        .output()
        .expect("the signing script runs");
    assert!(
        signed.status.success(),
        "signing failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let output = Command::new("codesign")
        .args(["-d", "--entitlements", "-", binary])
        .output()
        .expect("codesign runs on macOS");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("com.apple.security.virtualization"),
        "this binary would crash on first VM use. Run ci/sign-macos.sh.\n{combined}"
    );
}
