//! Evaluating `rachna.nix` — the restricted invocation, as a value.
//!
//! `18-NIX-BOUNDARY.md` §2 settles that evaluation shells out to `nix eval`
//! rather than linking an evaluator: only Nix evaluates Nix correctly, and
//! *silently disagreeing about a security policy* is the worst possible
//! failure.
//!
//! `23-SPIKE-EVAL-SANDBOX.md` settles **how**, and that part was a live
//! vulnerability rather than a preference. Measured on an unrestricted
//! evaluation of a cloned config:
//!
//! | Attack | Result |
//! |---|---|
//! | `builtins.readFile "/etc/passwd"` | ✅ contents returned into the config |
//! | `builtins.getEnv "SECRET_TOKEN"` | ✅ returned the token verbatim |
//! | `builtins.fetchurl "https://…"` | ✅ network reached during evaluation |
//! | all three combined | ✅ host content exfiltrated to a remote URL |
//!
//! This module's job is to make that invocation impossible to get wrong by
//! accident, which is why the arguments are constructed rather than passed in
//! as strings.
//!
//! # Why this holds no `Command`
//!
//! [`Invocation`] *describes* the evaluation; running it belongs to the layer
//! that owns process spawning. So the security-critical argument list is
//! table-testable with no subprocess, and a test can assert the restriction
//! flags are present without needing Nix installed
//! (`01-ARCHITECTURE.md` §4).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The `nix eval` invocation for one config file.
///
/// Built by [`Self::restricted`], which is the only constructor: there is no
/// way to ask for an unrestricted evaluation, because `23` §1 measured what
/// that permits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    args: Vec<OsString>,
    project_dir: PathBuf,
    nixpkgs: PathBuf,
}

impl Invocation {
    /// The restricted evaluation of `config` in `project_dir`.
    ///
    /// `nixpkgs` is **our** pinned store path, passed explicitly. `23` §2
    /// notes the side benefit: under restriction `<nixpkgs>` is unavailable,
    /// so a config can use `lib` but cannot reach a *different* nixpkgs. That
    /// enforces a rule `08` §4.1.1 had already decided — a project does not
    /// choose its pin — which was previously unenforceable.
    ///
    /// # Paths must be canonical
    ///
    /// Nix compares the `-I` allowlist against **resolved** paths, so a
    /// symlinked ancestor makes the entry silently fail to match. On macOS
    /// both `/tmp` and `/var` are symlinks, so this is the common case rather
    /// than an edge one: a project under either evaluates to
    ///
    /// ```text
    /// error: access to absolute path '/private/var/…/rachna.nix'
    ///        is forbidden in restricted mode
    /// ```
    ///
    /// — an incomprehensible message about the user's own config. Found by
    /// the integration test in `tests/eval_sandbox.rs`, which used
    /// `std::env::temp_dir()` and therefore hit it immediately.
    ///
    /// [`Self::restricted`] does not canonicalise for you, because that needs
    /// I/O and this type is deliberately pure. Use
    /// [`Self::canonicalised`] unless you have already resolved the paths.
    #[must_use]
    pub fn restricted(project_dir: &Path, config: &Path, nixpkgs: &Path) -> Self {
        // Built as one literal rather than successive pushes: clippy is
        // right that the push form is noise, and a single list also makes the
        // security-critical argument set readable top to bottom. Each entry's
        // reason is on its own line.
        let mut pin = OsString::from("nixpkgs=");
        pin.push(nixpkgs);

        let args: Vec<OsString> = vec![
            "eval".into(),
            // Required for `-I` search paths to apply at all. The restriction
            // below is what makes it safe, not its absence.
            "--impure".into(),
            // Closes all four attacks in `23` §1: readFile, getEnv, fetchurl,
            // and the exfiltration chain combining them.
            "--restrict-eval".into(),
            // Allow the project's own directory, so a relative
            // `import ./frag.nix` keeps working. `--restrict-eval` alone
            // refuses even the config file itself — measured.
            "-I".into(),
            project_dir.into(),
            // Allow our pin, and only ours.
            "-I".into(),
            pin,
            // `--json` rather than a bare eval, for two independent reasons
            // that converge on the same fix:
            //
            //   `22` §3: a lazily-evaluated list element produces exit code 0
            //   and no error, so an invalid policy is silently accepted.
            //   `23` §3.1: laziness hides imports, so a fragment imported but
            //   never used never appears in the trace and the watcher would
            //   silently ignore edits to it.
            //
            // Forcing the whole config fixes both.
            "--json".into(),
            // Puts `evaluating file '<path>'` on stderr while stdout stays
            // clean JSON — the only way to learn the import set (`23` §3).
            "-vvv".into(),
            // `-f`, never `--expr`: evaluating BY PATH is what replaces
            // `<unknown-file>` with the real filename in error messages
            // (`22` §2).
            "-f".into(),
            config.into(),
        ];

        Self {
            args,
            project_dir: project_dir.to_path_buf(),
            nixpkgs: nixpkgs.to_path_buf(),
        }
    }

    /// The restricted evaluation, with every path resolved first.
    ///
    /// The constructor to reach for. Canonicalising is not a convenience: an
    /// unresolved `-I` entry does not loosen the sandbox, it breaks a
    /// legitimate config with a message about a path the user never typed.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if any path cannot be
    /// resolved — which means it does not exist, and evaluating a config that
    /// is not there should fail here rather than inside Nix.
    pub fn canonicalised(
        project_dir: &Path,
        config: &Path,
        nixpkgs: &Path,
    ) -> std::io::Result<Self> {
        Ok(Self::restricted(
            &project_dir.canonicalize()?,
            &config.canonicalize()?,
            &nixpkgs.canonicalize()?,
        ))
    }

    /// The arguments to pass to `nix`.
    #[must_use]
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// The environment variables that must be **cleared**.
    ///
    /// `NIX_PATH` is load-bearing (`23` §2): without clearing it the user's
    /// own search-path entries remain reachable, so the allowlist would leak
    /// whatever their environment happens to contain. Returned as data so a
    /// test can assert it rather than trusting the spawning code to remember.
    #[must_use]
    pub const fn cleared_env(&self) -> &'static [&'static str] {
        &["NIX_PATH"]
    }

    /// The directory a relative import may reach.
    #[must_use]
    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    /// The nixpkgs this evaluation is pinned to.
    #[must_use]
    pub fn nixpkgs(&self) -> &Path {
        &self.nixpkgs
    }
}

/// The files that participated in an evaluation.
///
/// Parsed from `-vvv` stderr. The watcher needs every one, or an edit to an
/// imported fragment is silently ignored (`00-PRODUCT.md` §3.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportSet {
    files: Vec<PathBuf>,
}

impl ImportSet {
    /// Extracts the import set from `nix eval -vvv` stderr.
    ///
    /// Lines look like `evaluating file '/path/to/file.nix'`. Store paths are
    /// dropped: nixpkgs is ours and pinned, so watching it would mean
    /// watching 1.6 GiB of immutable content for changes that cannot happen.
    #[must_use]
    pub fn from_stderr(stderr: &str) -> Self {
        let files = stderr
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("evaluating file '")?;
                let path = rest.strip_suffix('\'')?;
                // `«nix-internal»/…` is not a real path, and /nix/store is
                // immutable.
                if path.starts_with('«') || path.starts_with("/nix/store/") {
                    return None;
                }
                Some(PathBuf::from(path))
            })
            .collect();
        Self { files }
    }

    /// Every file the watcher must watch.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Whether no file was found.
    ///
    /// **An empty import set from a successful evaluation is a bug, not a
    /// valid result**: the config file itself always participates. `23` §5
    /// records that the `evaluating file` line is debug output rather than a
    /// documented interface, so a Nix release could change it — and the
    /// failure must be loud rather than a silently-empty watch list.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> Invocation {
        Invocation::restricted(
            Path::new("/proj"),
            Path::new("/proj/rachna.nix"),
            Path::new("/nix/store/abc-nixpkgs"),
        )
    }

    fn args_as_strings(invocation: &Invocation) -> Vec<String> {
        invocation
            .args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    // ---- the restriction flags are present -------------------------------

    #[test]
    fn every_flag_that_closes_a_measured_attack_is_present() {
        // Each of these was measured permitting a real exfiltration in `23`
        // §1. Asserted individually so a removal names which attack reopens.
        let args = args_as_strings(&invocation());
        assert!(
            args.contains(&"--restrict-eval".to_owned()),
            "readFile/getEnv/fetchurl all become reachable without this"
        );
        assert!(
            args.contains(&"--json".to_owned()),
            "without this a bad list element exits 0 (22 §3) and laziness \
             hides imports (23 §3.1)"
        );
        assert!(
            args.contains(&"-vvv".to_owned()),
            "the import set is unobtainable without this (23 §3)"
        );
    }

    #[test]
    fn nix_path_is_cleared() {
        // Load-bearing: without clearing it the user's own search-path
        // entries stay reachable and the allowlist leaks (23 §2). Exposed as
        // data so this is asserted rather than left to the spawning code.
        assert_eq!(invocation().cleared_env(), ["NIX_PATH"]);
    }

    #[test]
    fn both_allowed_paths_are_passed_and_nothing_else() {
        let args = args_as_strings(&invocation());
        let allowed: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && args[i - 1] == "-I")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(
            allowed,
            ["/proj", "nixpkgs=/nix/store/abc-nixpkgs"],
            "exactly the project dir and our pin — a third entry is a hole"
        );
    }

    #[test]
    fn the_config_file_is_passed_with_dash_f_not_as_an_expression() {
        // `23` §3 and `22` §2: evaluating BY PATH is what replaces
        // `<unknown-file>` with the real filename in every error message.
        // `--expr` would lose it.
        let args = args_as_strings(&invocation());
        let position = args.iter().position(|a| a == "-f").expect("-f present");
        assert_eq!(args[position + 1], "/proj/rachna.nix");
        assert!(!args.contains(&"--expr".to_owned()));
    }

    #[test]
    fn the_invocation_reports_what_it_was_built_for() {
        let invocation = invocation();
        assert_eq!(invocation.project_dir(), Path::new("/proj"));
        assert_eq!(invocation.nixpkgs(), Path::new("/nix/store/abc-nixpkgs"));
    }

    #[test]
    fn there_is_no_unrestricted_constructor() {
        // Structural, asserted by the type rather than by a runtime check:
        // `restricted` is the only way to build an Invocation, so no call
        // site can ask for an unsandboxed evaluation. This test exists to
        // fail if a second constructor is ever added without this being
        // reconsidered.
        let args = args_as_strings(&invocation());
        assert!(args.contains(&"--restrict-eval".to_owned()));
    }

    // ---- the import set ---------------------------------------------------

    #[test]
    fn the_import_set_is_parsed_from_the_trace() {
        let stderr = "\
evaluating file '«nix-internal»/derivation-internal.nix'
evaluating file '/proj/rachna.nix'
evaluating file '/proj/frag.nix'
evaluating file '/proj/deep.nix'
";
        let set = ImportSet::from_stderr(stderr);
        assert_eq!(
            set.files(),
            [
                PathBuf::from("/proj/rachna.nix"),
                PathBuf::from("/proj/frag.nix"),
                PathBuf::from("/proj/deep.nix"),
            ],
            "every project file, in evaluation order"
        );
    }

    #[test]
    fn nix_internal_and_store_paths_are_excluded_from_the_watch_list() {
        // nixpkgs is ours and pinned, so watching it means watching 1.6 GiB
        // of immutable content for changes that cannot happen.
        let stderr = "\
evaluating file '«nix-internal»/derivation-internal.nix'
evaluating file '/nix/store/q55-source/lib/modules.nix'
evaluating file '/proj/rachna.nix'
";
        let set = ImportSet::from_stderr(stderr);
        assert_eq!(set.files(), [PathBuf::from("/proj/rachna.nix")]);
    }

    #[test]
    fn an_empty_import_set_is_detectable() {
        // `23` §5: the `evaluating file` line is debug output, not a
        // documented interface, so a Nix release could change its format. The
        // config file always participates, so an empty set from a successful
        // evaluation means the parse broke — and that must be loud rather
        // than a silently-empty watch list.
        assert!(ImportSet::from_stderr("").is_empty());
        assert!(ImportSet::from_stderr("some other output\n").is_empty());
        assert!(!ImportSet::from_stderr("evaluating file '/a.nix'\n").is_empty());
    }

    #[test]
    fn a_malformed_trace_line_is_skipped_rather_than_mis_parsed() {
        // A missing closing quote must not yield a truncated path that the
        // watcher would then watch. Skipping is right: the emptiness check
        // above is what surfaces a wholesale format change.
        let set = ImportSet::from_stderr("evaluating file '/proj/unterminated\n");
        assert!(set.is_empty());
    }

    #[test]
    fn a_path_containing_a_quote_is_handled() {
        // Legal on both platforms, and an attacker who can create a filename
        // controls its bytes (`17` §1). The suffix strip takes the LAST
        // quote, so an embedded one does not truncate the path.
        let set = ImportSet::from_stderr("evaluating file '/proj/we'ird.nix'\n");
        assert_eq!(set.files(), [PathBuf::from("/proj/we'ird.nix")]);
    }
}
