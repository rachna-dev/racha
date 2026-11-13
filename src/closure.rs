//! Building a project's package closure, host-side.
//!
//! `ExecSpec` parses `environment.packages` and `Image::find_for` picks the
//! image a spec needs. Between the two there was nothing: no code turned a
//! declared package list into an image, so a project could declare
//! `nodejs_22` and boot a guest without it. This module is that step.
//!
//! # Why the host builds, and the guest never does
//!
//! `guest.nix` sets `nix.settings.substituters = lib.mkForce [ ]`, which is
//! a security property rather than a configuration choice: `19` §3's rule is
//! that **a guest able to fetch its own packages escapes both the
//! reproducibility contract and the network policy**. A guest that could
//! resolve `github:cachix/devenv` would be a guest that had routed around
//! the allowlist the user approved.
//!
//! Measured, rather than assumed — `26` §6b ran `devenv shell` inside the
//! real guest:
//!
//! ```text
//! devenv=devenv 2.4.0 (x86_64-linux)      <- present and working
//! nix=nix (Nix) 2.34.8                    <- present and working
//! substituters=[]
//! x Failed to lock inputs: … while fetching 'github:cachix/devenv'
//!   error: failed to resolve address for github.com
//! ```
//!
//! So devenv is installed and cannot complete a `devenv shell`, exactly as
//! designed. `05` §7.6 guessed the resolution and this confirms it: the host
//! evaluates and builds; the guest only *enters* what it is given.
//!
//! # One mechanism for two features
//!
//! `environment.packages` and a project's own `devenv.nix` need the same
//! thing — a closure built on the host and handed over as an image — so this
//! module serves both rather than each getting its own path.
//!
//! # Substitution only
//!
//! Every build here is expected to **fetch** rather than compile. `06` §27
//! records prebuilt closures arriving from a binary cache in seconds, and
//! `02` §161 confirmed an `aarch64-linux` kernel fetched on a Darwin host
//! that cannot compile one. A package that would have to be *built* is
//! therefore a reportable condition rather than a long wait: see
//! [`BuildPlan::substitute_only`].

use crate::exec::ExecSpec;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What to build, and how to invoke `nix` to build it.
///
/// Pure: it constructs an argument list and nothing else, so the
/// security-relevant flags are table-testable without a Nix installation —
/// the same shape as [`crate::eval::Invocation`] and
/// [`crate::backend::linux::virtiofsd_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlan {
    args: Vec<OsString>,
    expression: String,
    closure_key: String,
}

impl BuildPlan {
    /// The plan for a spec's package set, pinned to `nixpkgs`.
    ///
    /// # Errors
    ///
    /// [`PlanError::Bare`] when the spec declares nothing to build — the
    /// caller should use the shared base image instead, and asking for a
    /// build would produce an image identical to it.
    pub fn for_spec(exec: &ExecSpec, nixpkgs: &Path) -> Result<Self, PlanError> {
        if exec.is_bare() {
            return Err(PlanError::Bare);
        }

        let expression = Self::render(exec, nixpkgs);
        let mut pin = OsString::from("nixpkgs=");
        pin.push(nixpkgs);

        let args: Vec<OsString> = vec![
            "build".into(),
            // `--impure --restrict-eval` with an explicit `-I` allowlist,
            // which is `eval.rs`'s pattern and is tighter than purity here
            // rather than looser.
            //
            // MEASURED, because the obvious choice does not work: a plain
            // `nix build --expr` that imports our pinned store path fails
            // with
            //
            //   error: access to absolute path '/nix/store/…-source' is
            //   forbidden in pure evaluation mode (use '--impure')
            //
            // So an expression naming the pin needs `--impure`, and
            // `--restrict-eval` is then what bounds it — closing `23` §1's
            // four attacks (readFile, getEnv, fetchurl, and the
            // exfiltration chain) while allowing exactly one search path.
            // Purity alone would have forbidden the pin and permitted
            // nothing in its place.
            "--impure".into(),
            "--restrict-eval".into(),
            // OUR pin, and nothing else. Note there is no `-I` for the
            // project directory: unlike an evaluation, a build reads no
            // project file, so a config cannot reach its own fragments
            // from here.
            "-I".into(),
            pin,
            // `--expr` rather than a file, because the expression is
            // DERIVED from the already-parsed spec. Writing it to a temp
            // file and building that would add a window between parse and
            // build for the content to differ.
            "--expr".into(),
            expression.clone().into(),
            // No `result` symlink in the user's project. `eval.rs` makes
            // the same choice for the same reason: Rachna reads the store
            // path from stdout and the project directory stays untouched.
            "--no-link".into(),
            "--print-out-paths".into(),
            // `--max-jobs 1`, NOT 0, and this was measured rather than
            // chosen.
            //
            // `06` §27's promise is "a download, never a compile", and the
            // obvious way to enforce it is `--max-jobs 0`. That FAILS on a
            // correct build:
            //
            //   error: Cannot build '…-rachna-project-test.drv'
            //   Reason: local builds are disabled (max-jobs = 0)
            //
            // because the `buildEnv` wrapper itself is a derivation — a
            // symlink tree over the packages — and it is never in a binary
            // cache, being unique to this project's package list. A
            // `--dry-run` confirms the distinction: of everything in the
            // closure, "this derivation will be built" names ONLY the
            // wrapper, and every actual package is already fetched.
            //
            // So 1 job allows the trivial local step while
            // [`BuildPlan::precheck`] is what refuses a real compile —
            // enforcement by asking first, rather than by a flag that
            // cannot tell a symlink tree from a C++ toolchain.
            "--max-jobs".into(),
            "1".into(),
            // No remote builders. A build that cannot be substituted must
            // fail here rather than silently going to a machine the user
            // did not ask about.
            "--builders".into(),
            "".into(),
        ];

        Ok(Self {
            args,
            expression,
            closure_key: exec.closure_key(),
        })
    }

    /// The Nix expression for a spec's packages.
    ///
    /// `buildEnv` rather than a list of paths: it produces ONE store path
    /// with a merged `bin/`, which is what the guest can put on a PATH. A
    /// list would leave the guest resolving several roots, and the
    /// `-man`/`-doc` output problem that `ci/build-guest.sh` hit (where
    /// `nix build postgresql_16` prints the man path first) is avoided
    /// because `buildEnv` selects the default outputs itself.
    fn render(exec: &ExecSpec, nixpkgs: &Path) -> String {
        // Sorted and deduplicated, matching `closure_key`: two configs
        // differing only in declaration order must produce one closure, or
        // the cache key and the built artefact would disagree about
        // identity.
        let mut names: Vec<&str> = exec.packages.iter().map(String::as_str).collect();
        names.sort_unstable();
        names.dedup();

        let paths = names
            .iter()
            .map(|name| format!("pkgs.{name}"))
            .collect::<Vec<_>>()
            .join(" ");

        // `<nixpkgs>`, resolved by the `-I` above — NOT the absolute store
        // path. Measured: naming the path directly fails with
        //
        //   error: access to absolute path '/nix/store/…-source' is
        //   forbidden in pure evaluation mode (use '--impure' to override)
        //
        // and under `--impure --restrict-eval` the search path is the
        // channel that works. `nixpkgs` here cannot be the user's: `-I`
        // supplies exactly one entry and `cleared_env` removes `NIX_PATH`,
        // so the angle brackets resolve to our pin and nothing else.
        //
        // ONE import, bound once. A first version wrote
        // `with import … {}; let pkgs = import … {}; in …`, which imports
        // nixpkgs twice and brings its whole attribute set into scope for
        // no reason.
        let _ = nixpkgs;
        format!(
            "let pkgs = import <nixpkgs> {{}}; in pkgs.buildEnv {{ \
             name = \"rachna-project-{}\"; paths = [ {} ]; }}",
            exec.closure_key(),
            paths
        )
    }

    /// The arguments to pass to `nix`.
    #[must_use]
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// The expression being built, for `rachna config inspect` and errors.
    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }

    /// The identity of the image this closure belongs to.
    #[must_use]
    pub fn closure_key(&self) -> &str {
        &self.closure_key
    }

    /// The same build as a **dry run**, for asking what would be compiled.
    ///
    /// This is how `06` §27's "a download, never a compile" is enforced,
    /// and it has to be a separate question rather than a flag on the
    /// build: `--max-jobs 0` cannot distinguish the `buildEnv` symlink
    /// tree — which is never cached, because it is unique to this package
    /// list — from a package that would really have to be compiled.
    ///
    /// `nix build --dry-run` prints `this derivation will be built:` for
    /// the former and lists every uncached package under the same heading,
    /// so [`would_compile`] reads the answer off that output.
    #[must_use]
    pub fn dry_run_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = self
            .args
            .iter()
            .filter(|a| *a != "--print-out-paths")
            .cloned()
            .collect();
        args.push("--dry-run".into());
        args
    }

    /// The environment variables that must be cleared, as for an evaluation.
    ///
    /// Same reason as [`crate::eval::Invocation::cleared_env`]: `NIX_PATH`
    /// left in place keeps the user's own search-path entries reachable, so
    /// the pin would leak whatever their environment holds. Load-bearing
    /// here too, because the expression resolves `<nixpkgs>` through the
    /// search path.
    #[must_use]
    pub const fn cleared_env(&self) -> &'static [&'static str] {
        &["NIX_PATH"]
    }
}

/// What a dry run says would have to be compiled, excluding the wrapper.
///
/// `nix build --dry-run` prints, on stderr:
///
/// ```text
/// this derivation will be built:
///   /nix/store/…-rachna-project-<key>.drv
/// these 104 paths will be fetched (758.4 MiB download, 2.3 GiB unpacked):
///   /nix/store/…-jq-1.8.2-bin
/// ```
///
/// The `buildEnv` wrapper always appears under "will be built", because it
/// is unique to one package list and so never cached. Anything ELSE under
/// that heading is a package that would be compiled on the user's machine —
/// which `06` §27 says must not happen on `rachna start`.
///
/// Returned as the names, so a caller can say *which* package is the
/// problem. `00` §3.3: an error that names no action is not actionable, and
/// "something would be compiled" leaves a user nowhere to go.
#[must_use]
pub fn would_compile(dry_run_stderr: &str, closure_key: &str) -> Vec<String> {
    let wrapper = format!("rachna-project-{closure_key}");
    let mut names = Vec::new();
    let mut in_build_section = false;

    for line in dry_run_stderr.lines() {
        let trimmed = line.trim();
        // The headings. `will be built` covers both the singular form
        // ("this derivation will be built:") and the plural ("these 3
        // derivations will be built:"), which differ by count — a check
        // for only one spelling silently stops working at two packages.
        if trimmed.contains("will be built") {
            in_build_section = true;
            continue;
        }
        if trimmed.contains("will be fetched") {
            in_build_section = false;
            continue;
        }
        if !in_build_section || !trimmed.starts_with("/nix/store/") {
            continue;
        }
        if trimmed.contains(&wrapper) {
            continue;
        }
        // `…-jq-1.8.2-bin.drv` reads better as `jq-1.8.2-bin`: the hash is
        // noise to a user and the `.drv` suffix is an implementation
        // detail of how the question was asked.
        let name = trimmed
            .rsplit('/')
            .next()
            .unwrap_or(trimmed)
            .split_once('-')
            .map_or(trimmed, |(_hash, name)| name)
            .trim_end_matches(".drv");
        names.push(name.to_owned());
    }
    names
}

/// Why a build plan could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// The spec declares no packages and no services.
    ///
    /// Not a failure: it means the shared base image is the right one, and
    /// `Image::find_for` already returns it. Distinguished so a caller
    /// cannot mistake "nothing to do" for "something went wrong".
    Bare,
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bare => f.write_str(
                "this project declares no packages, so the shared base guest \
                 image is the right one and nothing needs building",
            ),
        }
    }
}

impl core::error::Error for PlanError {}

/// Where a built closure is recorded for a project.
///
/// The store path is written beside the image rather than re-derived,
/// because `nix build --print-out-paths` is the only thing that knows it and
/// re-running the build to ask again would defeat the caching this exists
/// for.
#[must_use]
pub fn closure_record(image_dir: &Path) -> PathBuf {
    image_dir.join("closure-path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{ExecSpec, Service};

    fn spec(packages: &[&str]) -> ExecSpec {
        ExecSpec {
            packages: packages.iter().map(|p| (*p).to_owned()).collect(),
            ..ExecSpec::default()
        }
    }

    fn pinned() -> &'static Path {
        Path::new("/nix/store/abc-nixpkgs")
    }

    fn rendered(plan: &BuildPlan) -> Vec<String> {
        plan.args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    // ---- the thing this module exists for -------------------------------

    #[test]
    fn a_declared_package_set_produces_a_build_plan() {
        // THE case. Before this module, `environment.packages` parsed,
        // validated, and chose a directory name — and nothing ever built
        // an image for it, so the guest booted without the packages.
        let plan = BuildPlan::for_spec(&spec(&["nodejs_22", "postgresql_16"]), pinned())
            .expect("a spec with packages is buildable");
        let args = rendered(&plan);
        assert_eq!(args[0], "build");
        assert!(plan.expression().contains("pkgs.nodejs_22"));
        assert!(plan.expression().contains("pkgs.postgresql_16"));
    }

    #[test]
    fn a_bare_spec_is_not_an_error_and_is_not_built() {
        // The common case: no packages means the shared base image, which
        // `08` §4.1.1 calls the only shared thing — 493 MB per guest
        // version rather than per project. Building here would produce an
        // image identical to it.
        let error = BuildPlan::for_spec(&ExecSpec::default(), pinned())
            .expect_err("a bare spec has nothing to build");
        assert_eq!(error, PlanError::Bare);
        let message = error.to_string();
        assert!(message.contains("base guest"), "{message}");
        assert!(message.contains("nothing needs building"), "{message}");
    }

    // ---- the promise that start is a download ---------------------------

    #[test]
    fn a_build_allows_the_wrapper_and_no_remote_builders() {
        // `--max-jobs 1`, not 0, and this was MEASURED. 0 fails on a
        // correct build:
        //
        //   error: Cannot build '…-rachna-project-test.drv'
        //   Reason: local builds are disabled (max-jobs = 0)
        //
        // because `buildEnv` is itself a derivation — a symlink tree over
        // the packages — and it is never cached, being unique to one
        // package list. A `--dry-run` confirms only the wrapper is built
        // and every package is fetched.
        let plan = BuildPlan::for_spec(&spec(&["jq"]), pinned()).expect("buildable");
        let args = rendered(&plan);
        let at = args
            .iter()
            .position(|a| a == "--max-jobs")
            .expect("a job limit must be set");
        assert_eq!(args[at + 1], "1", "0 cannot build the buildEnv wrapper");

        // And no remote builders: a build that cannot be substituted must
        // fail locally rather than quietly going to a machine the user did
        // not ask about.
        let at = args
            .iter()
            .position(|a| a == "--builders")
            .expect("remote builders must be disabled explicitly");
        assert_eq!(args[at + 1], "");
    }

    #[test]
    fn a_build_is_restricted_rather_than_pure() {
        // `--impure` ALONE would be wrong, and pure alone does not work.
        // Measured: a pure `nix build --expr` importing our pinned store
        // path fails with "access to absolute path … is forbidden in pure
        // evaluation mode". So this uses `eval.rs`'s pattern — impure for
        // the search path, `--restrict-eval` to bound it — which closes
        // `23` §1's four attacks while permitting exactly one `-I`.
        let plan = BuildPlan::for_spec(&spec(&["jq"]), pinned()).expect("buildable");
        let args = rendered(&plan);
        assert!(args.iter().any(|a| a == "--impure"));
        assert!(
            args.iter().any(|a| a == "--restrict-eval"),
            "impure without a restriction is the attack surface `23` closed: {args:?}"
        );

        // EXACTLY ONE search path, and it is ours. A second `-I` would be
        // another nixpkgs a config could reach.
        let includes: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && args[i - 1] == "-I")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(includes.len(), 1, "{args:?}");
        assert_eq!(includes[0], "nixpkgs=/nix/store/abc-nixpkgs");
    }

    #[test]
    fn a_dry_run_asks_without_building() {
        // How "a download, never a compile" is actually enforced: ask
        // first, because no flag can tell a symlink tree from a C++
        // toolchain.
        let plan = BuildPlan::for_spec(&spec(&["jq"]), pinned()).expect("buildable");
        let dry: Vec<String> = plan
            .dry_run_args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(dry.iter().any(|a| a == "--dry-run"));
        // `--print-out-paths` is dropped: a dry run produces no output
        // path, and asking for one makes the invocation inconsistent.
        assert!(!dry.iter().any(|a| a == "--print-out-paths"));
        // Everything security-relevant survives the transformation.
        assert!(dry.iter().any(|a| a == "--restrict-eval"));
        assert!(dry.iter().any(|a| a == "nixpkgs=/nix/store/abc-nixpkgs"));
    }

    // ---- reading the dry run -------------------------------------------

    #[test]
    fn the_wrapper_alone_is_not_a_compile() {
        // REAL `nix build --dry-run` output, captured from the measurement
        // that produced this design. The wrapper is always built, so
        // treating it as a compile would refuse every valid project.
        let out = "this derivation will be built:\n                     /nix/store/z67f-rachna-project-deadbeef12345678.drv\n";
        assert!(would_compile(out, "deadbeef12345678").is_empty());
    }

    #[test]
    fn a_package_that_would_compile_is_named() {
        // `00` §3.3: name the action. "Something would be compiled" leaves
        // a user nowhere to go; naming the package tells them what to
        // change or wait for.
        let out = "these 2 derivations will be built:\n                     /nix/store/aaa-rachna-project-key.drv\n                     /nix/store/bbb-ffmpeg-7.1.drv\n                   these 104 paths will be fetched (758.4 MiB download):\n                     /nix/store/ccc-jq-1.8.2-bin\n";
        let names = would_compile(out, "key");
        assert_eq!(names, vec!["ffmpeg-7.1"]);
    }

    #[test]
    fn fetched_paths_are_never_mistaken_for_compiles() {
        // The two headings are adjacent in real output, and a parser that
        // does not switch sections would report every fetched package as
        // something to be compiled — refusing a build that was entirely
        // cached.
        let out = "this derivation will be built:\n                     /nix/store/aaa-rachna-project-key.drv\n                   these 3 paths will be fetched (1.0 MiB download):\n                     /nix/store/ccc-jq-1.8.2-bin\n                     /nix/store/ddd-ripgrep-15.2.0\n";
        assert!(would_compile(out, "key").is_empty());
    }

    #[test]
    fn both_the_singular_and_plural_headings_are_recognised() {
        // Nix writes "this derivation will be built:" for one and "these 3
        // derivations will be built:" for several. Matching only one
        // spelling works until a project declares a second uncached
        // package, which is the worst time to find out.
        for heading in [
            "this derivation will be built:",
            "these 2 derivations will be built:",
        ] {
            let out = format!("{heading}\n  /nix/store/bbb-ffmpeg-7.1.drv\n");
            assert_eq!(would_compile(&out, "key"), vec!["ffmpeg-7.1"], "{heading}");
        }
    }

    #[test]
    fn empty_output_means_everything_was_already_present() {
        // A fully cached closure prints neither heading, which must read
        // as "nothing to compile" rather than as a parse failure.
        assert!(would_compile("", "key").is_empty());
    }

    #[test]
    fn a_build_leaves_no_symlink_in_the_project() {
        // `eval.rs` makes the same choice: the store path is read from
        // stdout and the user's directory stays untouched. A `result`
        // symlink appearing in a project is both surprising and a path a
        // later build could follow.
        let plan = BuildPlan::for_spec(&spec(&["jq"]), pinned()).expect("buildable");
        let args = rendered(&plan);
        assert!(args.iter().any(|a| a == "--no-link"));
        assert!(args.iter().any(|a| a == "--print-out-paths"));
    }

    #[test]
    fn the_pinned_nixpkgs_is_the_only_one_reachable() {
        // `08` §4.1.1: a project does not pin its own nixpkgs, because the
        // guest version is part of the rachna version. The expression
        // imports OUR store path, so a config cannot substitute another.
        let plan = BuildPlan::for_spec(&spec(&["jq"]), pinned()).expect("buildable");
        let expression = plan.expression();

        // The expression names `<nixpkgs>`, and the PIN comes from `-I`.
        // Measured: an absolute store path in the expression is refused
        // outright — "access to absolute path … is forbidden in pure
        // evaluation mode" — so the search path is the only channel that
        // works here.
        assert!(expression.contains("import <nixpkgs>"), "{expression}");
        assert_eq!(
            expression.matches("import ").count(),
            1,
            "nixpkgs must be imported once: {expression}"
        );

        // `<nixpkgs>` is safe ONLY because of these two together: exactly
        // one `-I`, which is ours, and `NIX_PATH` cleared so the user's
        // own search path cannot supply a different one. Asserted here
        // rather than in two separate tests, because it is the
        // CONJUNCTION that makes the angle brackets safe — either alone
        // would leave a hole.
        let args = rendered(&plan);
        let includes: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && args[i - 1] == "-I")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(includes, vec!["nixpkgs=/nix/store/abc-nixpkgs"], "{args:?}");
        assert!(plan.cleared_env().contains(&"NIX_PATH"));
    }

    #[test]
    fn nix_path_is_cleared_for_a_build_as_well_as_an_evaluation() {
        // `23` §2 found `NIX_PATH` load-bearing for evaluation. A build
        // resolves imports too, so leaving it set would let the user's
        // search path reach a different nixpkgs here even though the
        // evaluation was restricted.
        let plan = BuildPlan::for_spec(&spec(&["jq"]), pinned()).expect("buildable");
        assert!(plan.cleared_env().contains(&"NIX_PATH"));
    }

    // ---- identity ------------------------------------------------------

    #[test]
    fn declaration_order_does_not_change_what_is_built() {
        // The same property `closure_key` has, and the two must AGREE: if
        // the key says "one image" and the expression says "two different
        // closures", the cache would hand a project the wrong artefact.
        let one = BuildPlan::for_spec(&spec(&["nodejs_22", "postgresql_16"]), pinned())
            .expect("buildable");
        let other = BuildPlan::for_spec(&spec(&["postgresql_16", "nodejs_22"]), pinned())
            .expect("buildable");
        assert_eq!(one.expression(), other.expression());
        assert_eq!(one.closure_key(), other.closure_key());
    }

    #[test]
    fn a_different_package_set_builds_something_else() {
        let one = BuildPlan::for_spec(&spec(&["nodejs_22"]), pinned()).expect("buildable");
        let other = BuildPlan::for_spec(&spec(&["nodejs_20"]), pinned()).expect("buildable");
        assert_ne!(one.expression(), other.expression());
        assert_ne!(one.closure_key(), other.closure_key());
    }

    #[test]
    fn the_plan_carries_the_key_the_image_directory_is_named_after() {
        // `Image::find_for` looks in `project_guest_dir(…, closure_key)`.
        // If the plan built under a different key the build would succeed
        // and the lookup would still miss, which is the silent-failure
        // shape this assertion exists to prevent.
        let exec = spec(&["jq", "ripgrep"]);
        let plan = BuildPlan::for_spec(&exec, pinned()).expect("buildable");
        assert_eq!(plan.closure_key(), exec.closure_key());
    }

    #[test]
    fn a_service_alone_is_buildable_without_any_packages() {
        // `services.postgres.enable` with no `environment.packages` still
        // changes the closure, so a spec that `is_bare()` rejects must be
        // buildable here — otherwise a service-only project would fall
        // back to the base image forever.
        let exec = ExecSpec {
            services: vec![Service {
                name: "postgres".to_owned(),
                enable: true,
                port: Some(5432),
            }],
            ..ExecSpec::default()
        };
        assert!(!exec.is_bare());
        let plan = BuildPlan::for_spec(&exec, pinned()).expect("a service needs a build");
        // No packages, so `paths` is empty — a valid `buildEnv` that
        // produces a closure the service generation can be layered onto.
        assert!(
            plan.expression().contains("paths = [  ]"),
            "{}",
            plan.expression()
        );
    }

    // ---- the expression itself -----------------------------------------

    #[test]
    fn packages_are_merged_into_one_environment() {
        // `buildEnv` rather than a list of store paths: ONE path with a
        // merged `bin/`, which is what a guest can put on a PATH. It also
        // sidesteps the multi-output problem `ci/build-guest.sh` hit, where
        // `nix build postgresql_16` prints the `-man` path first.
        let plan = BuildPlan::for_spec(&spec(&["jq", "ripgrep"]), pinned()).expect("buildable");
        let expression = plan.expression();
        assert!(expression.contains("buildEnv"), "{expression}");
        assert!(
            expression.contains("paths = [ pkgs.jq pkgs.ripgrep ]"),
            "{expression}"
        );
    }

    #[test]
    fn the_environment_is_named_after_the_closure_key() {
        // So a store path is traceable back to the config that produced it
        // — otherwise `/nix/store/…-rachna-project-…` is anonymous and
        // nobody can tell which project a leftover belongs to.
        let exec = spec(&["jq"]);
        let plan = BuildPlan::for_spec(&exec, pinned()).expect("buildable");
        assert!(
            plan.expression()
                .contains(&format!("rachna-project-{}", exec.closure_key())),
            "{}",
            plan.expression()
        );
    }

    #[test]
    fn a_duplicate_package_is_built_once() {
        // `config.rs` rejects a duplicate before this point, so this is
        // belt rather than braces — but the expression must not contain the
        // same path twice regardless, because `buildEnv` would fail on a
        // collision rather than dedupe.
        let exec = ExecSpec {
            packages: vec!["jq".to_owned(), "jq".to_owned()],
            ..ExecSpec::default()
        };
        let plan = BuildPlan::for_spec(&exec, pinned()).expect("buildable");
        assert_eq!(plan.expression().matches("pkgs.jq").count(), 1);
    }

    #[test]
    fn the_closure_record_sits_beside_the_image() {
        // Written rather than re-derived: `nix build --print-out-paths` is
        // the only thing that knows the store path, and re-running the
        // build to ask again would defeat the caching this exists for.
        let dir = Path::new("/r/guests/26.11-aarch64-deadbeef");
        let record = closure_record(dir);
        assert_eq!(record, dir.join("closure-path"));
        assert!(record.starts_with(dir));
    }
}
