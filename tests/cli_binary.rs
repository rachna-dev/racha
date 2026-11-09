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

    let (_, code) = run(&["init"]);
    assert_eq!(code, 0, "init failed");
    let config = dir.join("rachna.nix");
    let text = std::fs::read_to_string(&config).expect("rachna.nix");
    std::fs::write(
        &config,
        text.replace(
            "network.allow = [ ];",
            "network.allow = [ \"github.com:443\" ];",
        ),
    )
    .expect("widen");

    // First start: unapproved, so it refuses and names the commands.
    let (first, code) = run(&["start"]);
    assert_eq!(code, 77, "an unapproved start did not refuse:\n{first}");
    assert!(first.contains("github.com"), "{first}");
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
        second.contains("github.com"),
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
