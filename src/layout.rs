//! Where everything lives on the host (`08` §4.1).
//!
//! One module owns the `~/.rachna` tree, because the alternative is what this
//! project had: `rachna.db` as a literal in `store.rs`, socket paths invented
//! by each caller, and a test using `/p/vfs.sock`. Nothing derived a path from
//! a project, so nothing could *re-derive* one.
//!
//! # The measured reason this exists
//!
//! `16` §5.2 is the sharp case. A restore failed with:
//!
//! ```text
//! vhost-user: can't connect to peer: Connection refused (os error 111)
//! ```
//!
//! because the virtiofsd daemons had exited with the original VM, and the
//! snapshot's `config.json` records their **absolute socket paths**.
//! Restarting them on those exact paths made the same restore succeed in
//! 2163 ms.
//!
//! Two consequences, and the second is why this is a module rather than a
//! helper:
//!
//! - **The failure is not self-describing.** `Connection refused` reads as a
//!   networking fault, so a user hitting it will misdiagnose it. `15` §7
//!   lists this as tier 2 for that reason: the defect is in what we tell the
//!   user, not only in what fails.
//! - **Temporary socket paths make restore impossible.** A path under
//!   `mktemp` cannot be recreated on the next boot, so the snapshot's
//!   recorded path names a socket that can never exist again. Restore is
//!   therefore not merely harder — it is *unrecoverable* — which means
//!   deterministic paths are a correctness requirement rather than tidiness.
//!
//! # Why not `XDG_DATA_HOME`
//!
//! `08` §4.1 chose `~/.rachna` deliberately, over both XDG and macOS's
//! `~/Library/Application Support`: one obvious top-level directory means a
//! user can find it, back it up, delete it, and answer "how much disk is this
//! costing me" with `du -sh ~/.rachna`. Splitting across two platform
//! conventions makes every one of those harder for no correctness gain.

use std::path::{Path, PathBuf};

/// A project's stable identity, as it appears in a path.
///
/// `08` §4.1 shows these as `orders-api-a3f2` — a readable name plus a hash
/// of the project's real location, because two checkouts of the same repo are
/// different environments and must not share a state disk.
///
/// A newtype rather than a `String` so a project directory and a project id
/// cannot be swapped at a call site: they are both strings and the mistake
/// would be silent, producing a tree one level deeper than intended.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectId(String);

/// Why a project id could not be formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectIdError {
    /// Empty, which would collapse `projects/<id>/` to `projects/`.
    Empty,
    /// Contains a path separator or a `..` component.
    ///
    /// Its own variant because this is the dangerous one: an id of
    /// `../../etc` would put a state disk outside the Rachna tree entirely.
    /// `20` §4 has project names coming from directory names, which users and
    /// cloned repositories control.
    NotASingleComponent,
}

impl core::fmt::Display for ProjectIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("a project id cannot be empty"),
            Self::NotASingleComponent => {
                f.write_str("a project id must be one path component: no `/`, no `\\`, and no `..`")
            }
        }
    }
}

impl core::error::Error for ProjectIdError {}

impl ProjectId {
    /// Builds an id, refusing anything that is not a single path component.
    ///
    /// # Errors
    ///
    /// [`ProjectIdError`] for an empty id or one containing a separator or
    /// `..`. Refused rather than sanitised: silently rewriting `../../etc`
    /// into `etc` would put a project's state somewhere the user did not ask
    /// for and could not predict, and `exclusion.rs` already establishes that
    /// name-based rewriting is the wrong tool for a path question.
    pub fn new(id: impl Into<String>) -> Result<Self, ProjectIdError> {
        let id = id.into();
        if id.is_empty() {
            return Err(ProjectIdError::Empty);
        }
        // Both separators, because a Windows-style path in a config file
        // read on Linux is still an attempt to escape, and `Path` would not
        // treat `\` as a separator here.
        if id.contains('/') || id.contains('\\') || id == ".." || id == "." {
            return Err(ProjectIdError::NotASingleComponent);
        }
        Ok(Self(id))
    }

    /// The id as it appears in a path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The host-side tree for one project (`08` §4.1).
///
/// Every path is derived, never stored, so there is exactly one answer to
/// "where is this project's state disk". `16` §5.2 needs that property for
/// restore; everything else gets it for free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPaths {
    root: PathBuf,
}

impl ProjectPaths {
    /// The tree under an explicit Rachna root.
    ///
    /// Takes the root rather than reading `$HOME`, for the reason
    /// `guest_release_of` and `binary_has_entitlement` both ended up this
    /// way (`AGENTS.md`, "Unfalsifiable code"): a function whose only input
    /// is ambient state has one observable answer, so no test can tell it
    /// from a constant. A caller wanting the real tree passes
    /// [`default_root`]'s result.
    #[must_use]
    pub fn new(rachna_root: &Path, project: &ProjectId) -> Self {
        Self {
            root: rachna_root.join("projects").join(project.as_str()),
        }
    }

    /// This project's directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The audit store (`00` §8).
    ///
    /// Host-side and guest-unreachable: a guest that can forge usage data can
    /// defeat the audit mechanism (`08` §3.4).
    #[must_use]
    pub fn database(&self) -> PathBuf {
        self.root.join("rachna.db")
    }

    /// The shim directory — host-executed, and never writable by the guest.
    ///
    /// `00` §6.3: a guest that can replace `.rachna/bin/rustfmt` gets **code
    /// execution on the host**, because the editor is configured to run it.
    /// So the real shims live here, outside any mount, and the in-project
    /// `.rachna/bin` is a symlink to it.
    #[must_use]
    pub fn shim_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// This project's read-only package closure.
    #[must_use]
    pub fn closure_image(&self) -> PathBuf {
        self.root.join("disks").join("closure.img")
    }

    /// The durable service-data block device (`08` §4.1.3).
    ///
    /// A block device rather than a virtiofs share, because `16` §5.1
    /// measured that Postgres cannot use a virtiofs data directory at all —
    /// `226/NAMESPACE` on every boot — and `24` §7 verified a row surviving a
    /// cold boot on this.
    #[must_use]
    pub fn state_image(&self) -> PathBuf {
        self.root.join("disks").join("state.img")
    }

    /// What must not be reachable from inside this project's guest.
    ///
    /// Derived here rather than assembled by a caller, so there is one answer
    /// to "what is excluded" — `00` §3.11's third bullet: *"the exclusion
    /// list is part of the mount's definition, not a special case for one
    /// filename."*
    ///
    /// Takes the project directory because `rachna.nix` lives there, in the
    /// user's repo, while the shims live in this tree. That split is the
    /// point: `08` §4 keeps Rachna's integrity-critical files **out** of the
    /// mounted project folder precisely so the guest cannot reach them.
    #[must_use]
    pub fn exclusions(&self, project_dir: &Path) -> crate::exclusion::ExclusionSet {
        crate::exclusion::ExclusionSet::for_project(
            &project_dir.join("rachna.nix"),
            &self.shim_dir(),
        )
    }

    /// Where snapshots go.
    #[must_use]
    pub fn snapshot_dir(&self) -> PathBuf {
        self.root.join("snapshots")
    }

    /// The runtime directory: sockets and anything else that dies with the VM.
    ///
    /// Separate from the rest so `rachna stop` has one place to clear, and so
    /// a stale socket is obviously stale. `24` §6 lost 477 seconds to a
    /// leftover virtiofsd socket, which is the cost of not having this.
    #[must_use]
    pub fn runtime_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    /// The vhost-user socket for a virtiofs share, by tag.
    ///
    /// **This is the method `16` §5.2 requires.** The snapshot records this
    /// absolute path, so `rachna resume` must be able to recreate the exact
    /// same string on a later boot, in a different process, after a reboot.
    /// A `mktemp` path cannot do that, which makes restore unrecoverable
    /// rather than merely awkward.
    ///
    /// Derived from the tag so the mapping is total: every share the guest
    /// mounts has exactly one socket, and two shares cannot collide unless
    /// they share a tag — which the guest could not distinguish either.
    #[must_use]
    pub fn share_socket(&self, tag: &str) -> PathBuf {
        self.runtime_dir().join(format!("vfs-{tag}.sock"))
    }

    /// The Cloud Hypervisor API socket, for `ch-remote`.
    #[must_use]
    pub fn api_socket(&self) -> PathBuf {
        self.runtime_dir().join("api.sock")
    }

    /// The serial console log.
    ///
    /// A file rather than a pty: `05` §4.3 measured that `console=ttyS0` with
    /// `--serial file=` is the combination that produces output at all, and
    /// `04` §4.3 notes CH does not print a pty path.
    #[must_use]
    pub fn console_log(&self) -> PathBuf {
        self.runtime_dir().join("console.log")
    }
}

/// The guest system this build is paired with.
///
/// `08` §4.1.1: the guest version is **ours**, bumped deliberately, and it
/// is part of the `rachna` version — `0.4.0+26.11` reads as "Rachna 0.4.0,
/// built against NixOS 26.11". The short nixpkgs rev is included because
/// the release alone is not an identity: two builds against `26.11` at
/// different revs are different guests, and a snapshot taken under one
/// cannot be restored into the other.
///
/// Must match `guest/flake.nix`'s pinned `nixpkgs` input. A mismatch means
/// the directory name claims a guest the image is not, which `08` §4.1.1's
/// whole versioning scheme exists to prevent.
pub const GUEST_VERSION: &str = "26.11-3181085";

/// The shared guest directory for one guest version and architecture.
///
/// `08` §4.1.1 calls this **the only shared thing**, and `24` §3 measured why
/// it matters: 493 MB per guest version. Ten projects cost 493 MB plus what
/// each guest dirties, rather than 4.9 GB of near-identical data — which is
/// also the argument `00` §7 makes for an overlay root over a writable image.
#[must_use]
pub fn guest_dir(rachna_root: &Path, guest_version: &str, arch: &str) -> PathBuf {
    rachna_root
        .join("guests")
        .join(format!("{guest_version}-{arch}"))
}

/// The default Rachna root for a given home directory.
///
/// Takes `home` rather than reading `$HOME` — same reason as
/// [`ProjectPaths::new`].
#[must_use]
pub fn default_root(home: &Path) -> PathBuf {
    home.join(".rachna")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> ProjectPaths {
        let project = ProjectId::new("orders-api-a3f2").expect("a valid id");
        ProjectPaths::new(Path::new("/home/dev/.rachna"), &project)
    }

    #[test]
    fn the_tree_matches_what_08_section_4_1_specifies() {
        // Pinned against the document rather than against itself: `08` §4.1
        // draws this tree, and a path that drifts from it silently splits a
        // project's state across two locations.
        let p = paths();
        assert_eq!(
            p.root(),
            Path::new("/home/dev/.rachna/projects/orders-api-a3f2")
        );
        assert_eq!(
            p.database(),
            Path::new("/home/dev/.rachna/projects/orders-api-a3f2/rachna.db")
        );
        assert_eq!(
            p.shim_dir(),
            Path::new("/home/dev/.rachna/projects/orders-api-a3f2/bin")
        );
        assert_eq!(
            p.closure_image(),
            Path::new("/home/dev/.rachna/projects/orders-api-a3f2/disks/closure.img")
        );
        assert_eq!(
            p.state_image(),
            Path::new("/home/dev/.rachna/projects/orders-api-a3f2/disks/state.img")
        );
        assert_eq!(
            p.snapshot_dir(),
            Path::new("/home/dev/.rachna/projects/orders-api-a3f2/snapshots")
        );
    }

    #[test]
    fn the_exclusion_set_names_the_policy_file_and_this_tree_s_shims() {
        // One answer to "what is excluded", per `00` §3.11's third bullet.
        // The split matters: rachna.nix is in the USER's repo, the shims are
        // in Rachna's tree — `08` §4 puts them there precisely so a guest
        // that can write the project folder cannot reach them.
        let paths = paths();
        let set = paths.exclusions(Path::new("/Users/you/Projects/app"));
        assert_eq!(
            set.paths(),
            [
                PathBuf::from("/Users/you/Projects/app/rachna.nix"),
                PathBuf::from("/home/dev/.rachna/projects/orders-api-a3f2/bin"),
            ]
        );
        // The shim path is NOT under the project directory, which is the
        // property that makes it unreachable from the mount.
        assert!(
            !set.paths()[1].starts_with("/Users/you/Projects/app"),
            "the shims are inside the mounted project folder"
        );
    }

    #[test]
    fn a_share_socket_is_the_same_path_every_time_it_is_derived() {
        // THE property `16` §5.2 needs. A snapshot records the absolute
        // socket path, so restore must be able to recreate that exact string
        // in a later process, after a reboot — otherwise the recorded path
        // names a socket that can never exist again and restore is
        // unrecoverable rather than merely awkward.
        //
        // Derived twice through independently-constructed values, so this
        // cannot pass by returning a cached field.
        let first = paths().share_socket("workspace");
        let project = ProjectId::new("orders-api-a3f2").expect("valid");
        let second =
            ProjectPaths::new(Path::new("/home/dev/.rachna"), &project).share_socket("workspace");
        assert_eq!(first, second);

        // And it is NOT a temporary path, which is the thing that made
        // restore impossible. Asserted explicitly because "it happens to be
        // under .rachna today" is how that regresses.
        let text = first.to_string_lossy();
        assert!(
            text.starts_with("/home/dev/.rachna/"),
            "a share socket must live in the project tree: {text}"
        );
        for temporary in ["/tmp/", "/var/folders/", "XXXX"] {
            assert!(
                !text.contains(temporary),
                "a socket under {temporary} cannot be recreated after a reboot: {text}"
            );
        }
    }

    #[test]
    fn two_shares_get_two_sockets() {
        // A collision would hand the guest the wrong share, and `16` §5.2
        // applies "four times" for a four-share guest — so the mapping from
        // tag to socket has to be injective.
        let p = paths();
        let tags = ["workspace", "state", "cache", "secrets"];
        let mut sockets: Vec<PathBuf> = tags.iter().map(|tag| p.share_socket(tag)).collect();
        let total = sockets.len();
        sockets.sort();
        sockets.dedup();
        assert_eq!(sockets.len(), total, "two tags share a socket path");
        // And each names its tag, so a stale socket on disk says which share
        // it belonged to — `24` §6 lost 477 seconds to an unidentified one.
        for tag in tags {
            assert!(
                p.share_socket(tag).to_string_lossy().contains(tag),
                "{tag}'s socket does not name it"
            );
        }
    }

    #[test]
    fn runtime_state_is_separate_from_durable_state() {
        // So `rachna stop` has one directory to clear, and so nothing that
        // must survive a stop is sitting next to something that must not.
        let p = paths();
        let runtime = p.runtime_dir();
        for ephemeral in [p.share_socket("workspace"), p.api_socket(), p.console_log()] {
            assert!(
                ephemeral.starts_with(&runtime),
                "{} is not under the runtime dir",
                ephemeral.display()
            );
        }
        for durable in [p.database(), p.state_image(), p.snapshot_dir()] {
            assert!(
                !durable.starts_with(&runtime),
                "{} would be deleted by a stop",
                durable.display()
            );
        }
    }

    #[test]
    fn a_project_id_cannot_escape_the_tree() {
        // `20` §4 has project names coming from DIRECTORY names, which users
        // and cloned repositories control. An id of `../../etc` would put a
        // state disk outside the Rachna tree entirely.
        //
        // First assert the thing under attack exists: a normal id works.
        assert!(ProjectId::new("orders-api-a3f2").is_ok());

        for hostile in [
            "..",
            ".",
            "../etc",
            "../../etc/cron.d",
            "a/b",
            "/absolute",
            "trailing/",
            "back\\slash",
            "..\\..\\windows",
        ] {
            assert_eq!(
                ProjectId::new(hostile).err(),
                Some(ProjectIdError::NotASingleComponent),
                "`{hostile}` was accepted as a project id"
            );
        }
        assert_eq!(ProjectId::new("").err(), Some(ProjectIdError::Empty));
    }

    #[test]
    fn a_refused_id_is_not_quietly_rewritten() {
        // Refused rather than sanitised: turning `../../etc` into `etc` would
        // put a project's state somewhere the user did not ask for and could
        // not predict. `exclusion.rs` already establishes that name-based
        // rewriting is the wrong tool for a path question.
        let error = ProjectId::new("../../etc").expect_err("must be refused");
        let text = error.to_string();
        assert!(text.contains("one path component"), "{text}");
        assert!(text.contains(".."), "{text}");
    }

    #[test]
    fn every_copy_of_the_guest_version_agrees() {
        // THE VERSION IS WRITTEN IN THREE PLACES, and all three must say
        // the same thing or the product silently breaks:
        //
        //   src/layout.rs      where the binary LOOKS for an image
        //   ci/build-guest.sh  where a local build WRITES one
        //   ci/install.sh      where the installer UNPACKS one
        //
        // A bump to one alone is not a build error. The installer would
        // fetch the image into a directory the binary never reads, and
        // `rachna start` would report "no guest image" on a machine that
        // had just downloaded one — a failure that looks like a bad
        // download and is a version mismatch.
        //
        // Read from the FILES rather than restated here: a constant
        // compared against another constant tests nothing.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for script in ["ci/build-guest.sh", "ci/install.sh"] {
            let text = std::fs::read_to_string(root.join(script))
                .unwrap_or_else(|_| panic!("{script} is part of the repo"));
            assert!(
                text.contains(GUEST_VERSION),
                "{script} does not mention GUEST_VERSION ({GUEST_VERSION}), so \
                 it writes or reads a directory the binary will not look in"
            );
        }
    }

    #[test]
    fn the_guest_version_matches_the_flake_it_claims() {
        // `GUEST_VERSION` names the directory the image lands in, and the
        // image is built from `guest/flake.nix`'s pinned nixpkgs. If the
        // two drift, the directory claims a guest the image is not — and
        // `08` §4.1.1's versioning exists precisely so a snapshot cannot
        // be restored into a different guest. A silent mismatch defeats it.
        //
        // Read from the FLAKE rather than restated here: a constant
        // compared against another constant tests nothing.
        let flake = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("guest/flake.nix"),
        )
        .expect("guest/flake.nix is part of the repo");

        let rev = GUEST_VERSION
            .split('-')
            .next_back()
            .expect("the version carries a rev");
        assert!(
            flake.contains(rev),
            "GUEST_VERSION names rev `{rev}`, which guest/flake.nix does not \
             pin. One of the two was bumped without the other."
        );
    }

    #[test]
    fn the_guest_directory_is_shared_and_names_both_versions() {
        // `08` §4.1.1: the only shared thing. `24` §3 measured 493 MB per
        // guest version, so ten projects cost 493 MB rather than 4.9 GB —
        // but only if the path does not include the project.
        let root = Path::new("/home/dev/.rachna");
        let dir = guest_dir(root, "26.11-3181085", "aarch64");
        assert_eq!(
            dir,
            Path::new("/home/dev/.rachna/guests/26.11-3181085-aarch64")
        );
        assert!(
            !dir.to_string_lossy().contains("projects"),
            "a guest directory under projects/ would defeat sharing: {}",
            dir.display()
        );
        // Different architectures must not collide: an aarch64 guest handed
        // an x86_64 kernel does not boot, and `02` §4 makes a mismatched
        // configuration a restore failure rather than an error.
        assert_ne!(dir, guest_dir(root, "26.11-3181085", "x86_64"));
        assert_ne!(dir, guest_dir(root, "26.05-aaaaaaa", "aarch64"));
    }

    #[test]
    fn two_checkouts_of_one_repo_do_not_share_state() {
        // `08` §4.1 shows ids as `<name>-<hash>` precisely because two
        // checkouts are two environments. The hash is the caller's job, but
        // the path must keep them apart.
        let root = Path::new("/home/dev/.rachna");
        let one = ProjectId::new("orders-api-a3f2").expect("valid");
        let two = ProjectId::new("orders-api-b7e1").expect("valid");
        let first = ProjectPaths::new(root, &one);
        let second = ProjectPaths::new(root, &two);
        assert_ne!(first.state_image(), second.state_image());
        assert_ne!(first.database(), second.database());
        assert_ne!(
            first.share_socket("workspace"),
            second.share_socket("workspace")
        );
    }

    #[test]
    fn the_root_is_dot_rachna_rather_than_an_xdg_path() {
        // `08` §4.1 chose this deliberately over XDG and macOS's
        // Application Support, so `du -sh ~/.rachna` answers "how much disk
        // is this costing me". Pinned because it is a product decision.
        assert_eq!(
            default_root(Path::new("/home/dev")),
            Path::new("/home/dev/.rachna")
        );
        let text = default_root(Path::new("/Users/dev"))
            .to_string_lossy()
            .into_owned();
        assert!(!text.contains("Library"), "{text}");
        assert!(!text.contains(".local"), "{text}");
    }
}
