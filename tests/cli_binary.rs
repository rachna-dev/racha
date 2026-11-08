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
        "init", "start", "stop", "status", "doctor", "config", "audit", "explain", "allow",
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
    let (_, stderr, code) = rachna(&["status"]);
    assert_eq!(code, 70, "stderr: {stderr}");
    assert!(stderr.contains("step 11"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
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
        assert!(
            code == 0 || code == 64 || code == 70,
            "{args:?} exited {code}, which is not a defined code"
        );
    }
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
