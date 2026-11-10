//! Turning a policy into something a backend can launch.
//!
//! The seam `01` §7.0c named as the last gap: `run::launch` was complete and
//! nothing called it, because nothing produced a [`Launch`]. This is that
//! producer — it finds the guest image on disk and applies the policy's
//! resource limits to it.
//!
//! # Why the image is found rather than built
//!
//! `02` §6.9 measured that `guest/flake.nix`'s bundle needs **240
//! derivations built** for `aarch64-linux`, which an `aarch64-darwin` host
//! cannot do. So `rachna start` must not try: it looks for an image, and
//! says exactly how to produce one when there is none. A command that
//! silently shells out to a 20-minute build is worse than one that tells
//! you what to run.

use crate::backend::linux::{Disk, Launch, Share};
use crate::decide::Policy;
use crate::layout::ProjectPaths;
use std::path::{Path, PathBuf};

/// The three files a guest needs.
///
/// Named individually rather than as a directory, so a *partial* image is a
/// specific complaint rather than "something is wrong". `24` §6 measured a
/// two-of-three snapshot restoring with **no error at all**, which is the
/// precedent this guards against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// The kernel. On aarch64 an uncompressed `Image`; `02` §6.5 recorded
    /// that no `vmlinux` extraction is needed there.
    pub kernel: PathBuf,
    /// The initramfs that finds and switches to the root.
    pub initramfs: PathBuf,
    /// The root filesystem.
    pub root: PathBuf,
}

/// Why a guest could not be prepared.
#[derive(Debug)]
pub enum BootError {
    /// No guest image is installed.
    NoImage {
        /// Where one was looked for.
        looked_in: PathBuf,
    },
    /// An image directory exists but is missing a file.
    Incomplete {
        /// Which file.
        missing: PathBuf,
    },
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Names the script, because `00` §3.3 requires a message to name
            // an action — and because the alternative, running a 240-
            // derivation build behind the user's back, is worse.
            Self::NoImage { looked_in } => write!(
                f,
                "no guest image in {}. Build one:\n    \
                 ./ci/build-guest.sh",
                looked_in.display()
            ),
            // Specific, per `24` §6: a partial image must not be treated as
            // either present or absent.
            Self::Incomplete { missing } => write!(
                f,
                "the guest image is incomplete: {} is missing. Rebuild it:\n    \
                 ./ci/build-guest.sh",
                missing.display()
            ),
        }
    }
}

impl std::error::Error for BootError {}

/// The architecture this host runs guests for.
///
/// A guest built for the wrong architecture does not degrade — it fails at
/// boot with nothing useful on the console — so the path carries the arch
/// and this is the single place that names it.
#[must_use]
pub const fn host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

impl Image {
    /// Finds the installed guest image.
    ///
    /// # Errors
    ///
    /// [`BootError::NoImage`] when the directory is absent, or
    /// [`BootError::Incomplete`] naming the first missing file.
    pub fn find(rachna_root: &Path) -> Result<Self, BootError> {
        // THROUGH `layout::guest_dir`, which names the guest VERSION as
        // well as the arch. This used to be `guests/<arch>` with no
        // version — and `08` §4.1.1 is explicit that the versioning is
        // what stops a guest upgrade from overwriting an image existing
        // snapshots still reference. An unversioned path makes that
        // overwrite silent.
        let dir = crate::layout::guest_dir(rachna_root, crate::layout::GUEST_VERSION, host_arch());
        if !dir.is_dir() {
            return Err(BootError::NoImage { looked_in: dir });
        }
        let image = Self {
            kernel: dir.join("Image"),
            initramfs: dir.join("initramfs.gz"),
            root: dir.join("root.img"),
        };
        // Every file, not just the first — and reported one at a time so
        // the message names a specific thing to fix.
        for required in [&image.kernel, &image.initramfs, &image.root] {
            if !required.is_file() {
                return Err(BootError::Incomplete {
                    missing: required.clone(),
                });
            }
        }
        Ok(image)
    }
}

/// Builds the launch for this policy and image.
///
/// The root disk is **writable** and per-project: `00` §7's layers make the
/// workspace the thing that persists, and a guest that cannot write cannot
/// run `initdb`. The shared image is copied per project by
/// [`provision_root`] rather than attached directly, so two projects cannot
/// corrupt each other.
#[must_use]
pub fn launch_for(
    policy: &Policy,
    image: &Image,
    paths: &ProjectPaths,
    project_dir: &Path,
    home: &Path,
    root: PathBuf,
    state: PathBuf,
) -> Launch {
    let shares = shares_for(policy, project_dir, home);
    Launch {
        kernel: image.kernel.clone(),
        initrd: image.initramfs.clone(),
        // `root=/dev/vda rw` matches what the initramfs looks for. Not
        // configurable: a mismatch between this and the initramfs is a boot
        // failure with no diagnostic, so the two are written together.
        // The mount map rides on the command line: see
        // `mount_parameters` for why that is the only channel available
        // before the guest has mounted anything.
        cmdline: format!("console=hvc0 root=/dev/vda rw{}", mount_parameters(&shares)),
        memory_mib: policy.resources.memory_mib,
        cpus: policy.resources.cpus,
        // ORDER IS THE INTERFACE: the guest sees these as /dev/vda and
        // /dev/vdb, and `snapshot.rs` records the order because restoring
        // into a swapped configuration would hand the guest its state disk
        // as its root. The initramfs mounts vda; the guest's init mounts
        // vdb at /data.
        disks: vec![
            Disk {
                path: root,
                read_only: false,
            },
            Disk {
                path: state,
                read_only: false,
            },
        ],
        // THE WORKSPACE. Without this the environment is isolated from
        // the thing it exists to work on — `00` §1's whole premise is a
        // project directory you can edit on the host and build in the
        // guest.
        //
        // The socket is empty because VZ has no virtiofsd; `Share`'s
        // comment records why both fields exist.
        shares,
        console_log: paths.console_log(),
        api_socket: paths.api_socket(),
    }
}

/// The tag the guest mounts the workspace by.
///
/// One constant rather than a string at each end: the host names the share
/// and the guest's init mounts it, and a mismatch is a guest with no
/// workspace and nothing on the console to say why.
pub const WORKSPACE_TAG: &str = "workspace";

/// The tag-to-destination map, as kernel command-line parameters.
///
/// # Why the command line and not a file
///
/// VZ identifies a share by a **tag** and gives the host no way to say
/// where the guest should mount it — the guest decides. A tag is also
/// length-limited and cannot contain `/`, so the destination cannot be
/// encoded in the tag itself.
///
/// A file beside the console was the first idea and does not work: the
/// guest cannot read the host's runtime directory, which is the whole
/// point of the isolation. The kernel command line is the one channel that
/// reaches a guest before anything is mounted, which is exactly when the
/// init needs this.
///
/// Rendered as `rachna.mount=tag:/path`, repeated. Paths with spaces are
/// refused earlier rather than quoted here: the kernel command line has no
/// quoting, so a space would silently split one mount into two.
#[must_use]
fn mount_parameters(shares: &[Share]) -> String {
    shares
        .iter()
        .filter_map(|share| {
            // Only shares with a declared destination. The workspace's is
            // fixed and the guest's init already knows it.
            let guest_path = share.guest_path.as_ref()?;
            let path = guest_path.to_string_lossy();
            // A space would split the parameter, so such a mount is
            // dropped WITH the summary still showing it — which would be a
            // permission silently not applied. Refused at parse time
            // instead; this is the belt.
            if path.contains(char::is_whitespace) {
                return None;
            }
            Some(format!(" rachna.mount={}:{path}", share.tag))
        })
        .collect()
}

/// Every directory the guest can see./// Every directory the guest can see.
///
/// The workspace, plus whatever `filesystem.mounts` declares. **The
/// declared mounts were being gated and audited and never mounted** — the
/// policy carried them, the summary showed them, and this function built a
/// one-element list containing only the workspace. A permission the user
/// approved and the guest never received.
///
/// `~` is expanded at both ends, with the two meanings `expand_home`
/// describes: the host's home in `source`, the guest's in `target`.
fn shares_for(policy: &Policy, project_dir: &Path, home: &Path) -> Vec<Share> {
    let mut shares = vec![Share {
        tag: WORKSPACE_TAG.to_owned(),
        host_path: project_dir.to_path_buf(),
        socket: PathBuf::new(),
        // WRITABLE. A guest that cannot write to the workspace cannot
        // compile, install dependencies, or run a formatter — the
        // isolation that matters is the HOST boundary (`00` §3), not the
        // project directory the user is working in.
        read_only: false,
        // The workspace has a fixed destination the guest's init knows.
        guest_path: None,
    }];

    for (index, grant) in policy.grants.iter().enumerate() {
        let crate::grant::Grant::Filesystem {
            path,
            target,
            access,
        } = grant
        else {
            continue;
        };
        let host_path = crate::grant::expand_home(path, home);
        // The project directory is already shared as the workspace. A
        // config that also mounts `.` would otherwise get two shares of
        // one directory, which VZ accepts and the guest then sees twice.
        if host_path == project_dir {
            continue;
        }
        shares.push(Share {
            // Tags must be unique and are what the guest mounts by, so
            // they are generated rather than taken from the path — a path
            // contains `/`, which is not a legal tag.
            tag: format!("mount{index}"),
            host_path,
            socket: PathBuf::new(),
            read_only: *access == crate::decision::Access::ReadOnly,
            // Where the guest puts it. `None` means the guest's default.
            guest_path: target
                .as_ref()
                .map(|t| crate::grant::expand_home(t, Path::new(crate::grant::GUEST_HOME))),
        });
    }
    shares
}

/// Where this project's writable root copy lives.
///
/// Beside the closure and state images, in the project's `disks/`.
#[must_use]
pub fn root_image(paths: &ProjectPaths) -> PathBuf {
    paths.closure_image().with_file_name("root.img")
}

/// Creates the project's state volume if it does not exist.
///
/// **This is what makes the environment persistent**, and it is a separate
/// disk from the root on purpose: `00` §7's layers put the durable data
/// here, so a root image that is rebuilt or replaced does not take the
/// database with it.
///
/// An empty ext4 is not created here — the guest formats it on first use,
/// because `mke2fs` is a guest-side tool and shelling out to one on the
/// host would make the host's toolchain part of the boot path.
///
/// # Errors
///
/// The underlying IO error. A failure is usually a full disk.
pub fn provision_state(policy: &Policy, paths: &ProjectPaths) -> Result<PathBuf, std::io::Error> {
    let target = paths.state_image();
    if target.exists() {
        return Ok(target);
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Sparse: `19` §2.1's default is 20 GiB, and allocating that eagerly
    // would cost a user 20 GiB per project for a database holding
    // kilobytes.
    let file = std::fs::File::create(&target)?;
    file.set_len(policy.resources.disk_mib * 1024 * 1024)?;
    Ok(target)
}

/// Gives this project its own writable copy of the root image.
///
/// Copied rather than shared because the guest writes to it — Postgres's
/// data directory lives there — and two projects sharing one root would
/// corrupt each other's databases. Copy-on-write would be better and is a
/// step-14 concern; correctness first (`01` §3b).
///
/// Returns the project's root path, copying only if it is not already there.
///
/// # Errors
///
/// The underlying IO error, with the paths named: a failure here is usually
/// a full disk, and a user needs to know which file.
pub fn provision_root(image: &Image, paths: &ProjectPaths) -> Result<PathBuf, std::io::Error> {
    // `root_image`, NOT `state_image`. Using the latter here conflated the
    // two volumes: the root copy occupied the state path, no second disk
    // was attached, and the guest's init fell back to a tmpfs `/data` — so
    // Postgres ran `initdb` on EVERY boot and the todos were silently
    // recreated rather than persisted. Measured by counting `initdb` runs
    // in the console across a stop/start cycle: two boots, two initdbs.
    let target = root_image(paths);
    if target.exists() {
        return Ok(target);
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(&image.root, &target).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "cannot copy {} to {}: {error}",
                image.root.display(),
                target.display()
            ),
        )
    })?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::Capabilities;
    use crate::policy::{Profile, Tier};
    use crate::resources::Resources;

    fn policy() -> Policy {
        Policy {
            tier: Tier::Allowlist,
            profile: Profile::Development,
            grants: Vec::new(),
            resources: Resources {
                cpus: 2,
                memory_mib: 1024,
                disk_mib: 2048,
                processes: 64,
            },
            capabilities: Capabilities::all(),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rachna-boot-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    #[test]
    fn a_missing_image_names_the_script_that_builds_one() {
        // `00` §3.3: a message that names no action is not actionable, and
        // this is the first wall a new user hits.
        let root = scratch("missing");
        let error = Image::find(&root).expect_err("no image is installed");
        let text = error.to_string();
        assert!(text.contains("build-guest.sh"), "{text}");
        assert!(text.contains("guests/"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_partial_image_names_the_missing_file_rather_than_failing_vaguely() {
        // `24` §6 measured a TWO-of-three snapshot restoring with no error
        // at all. A partial guest image is the same trap one layer up, so
        // each file is checked and named.
        let root = scratch("partial");
        let dir = crate::layout::guest_dir(&root, crate::layout::GUEST_VERSION, host_arch());
        std::fs::create_dir_all(&dir).expect("dirs");
        std::fs::write(dir.join("Image"), b"kernel").expect("kernel");
        std::fs::write(dir.join("initramfs.gz"), b"initrd").expect("initrd");
        // root.img deliberately absent.

        let error = Image::find(&root).expect_err("an incomplete image must be refused");
        let text = error.to_string();
        assert!(
            text.contains("root.img"),
            "the error did not name the missing file: {text}"
        );
        assert!(text.contains("incomplete"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_complete_image_is_found() {
        // The positive case, so the two refusals above are not vacuous.
        let root = scratch("complete");
        let dir = crate::layout::guest_dir(&root, crate::layout::GUEST_VERSION, host_arch());
        std::fs::create_dir_all(&dir).expect("dirs");
        for name in ["Image", "initramfs.gz", "root.img"] {
            std::fs::write(dir.join(name), b"x").expect("file");
        }
        let image = Image::find(&root).expect("a complete image is found");
        assert!(image.kernel.ends_with("Image"));
        assert!(image.root.ends_with("root.img"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_launch_carries_the_policys_resource_limits() {
        // The point of this module: `19` §2.1's declared limits must reach
        // the hypervisor, or they are documentation.
        let root = scratch("launch");
        let dir = crate::layout::guest_dir(&root, crate::layout::GUEST_VERSION, host_arch());
        std::fs::create_dir_all(&dir).expect("dirs");
        for name in ["Image", "initramfs.gz", "root.img"] {
            std::fs::write(dir.join(name), b"x").expect("file");
        }
        let image = Image::find(&root).expect("found");
        let project = crate::layout::ProjectId::new("demo-abcd").expect("valid id");
        let paths = ProjectPaths::new(&root, &project);

        let launch = launch_for(
            &policy(),
            &image,
            &paths,
            Path::new("/some/project"),
            Path::new("/Users/someone"),
            PathBuf::from("/tmp/root.img"),
            PathBuf::from("/tmp/state.img"),
        );
        // THE WORKSPACE IS SHARED. Without it the environment cannot see
        // the project it exists to work on, which is `00` §1's premise.
        assert_eq!(launch.shares.len(), 1, "the workspace was not shared");
        assert_eq!(launch.shares[0].tag, WORKSPACE_TAG);
        assert_eq!(launch.shares[0].host_path, Path::new("/some/project"));
        assert!(
            !launch.shares[0].read_only,
            "a read-only workspace cannot be built in"
        );
        // TWO disks, in order: the guest sees /dev/vda (root) and /dev/vdb
        // (state), and its init mounts vdb at /data. One disk meant a
        // tmpfs /data and a database recreated on every boot.
        assert_eq!(launch.disks.len(), 2, "the state volume was not attached");
        assert!(
            launch.disks[0].path.ends_with("root.img"),
            "{:?}",
            launch.disks
        );
        assert!(
            launch.disks[1].path.ends_with("state.img"),
            "{:?}",
            launch.disks
        );
        assert!(
            launch.disks.iter().all(|disk| !disk.read_only),
            "a read-only volume cannot hold a database: {:?}",
            launch.disks
        );
        assert_eq!(
            launch.cpus, 2,
            "the policy's cpu count did not reach the launch"
        );
        assert_eq!(
            launch.memory_mib, 1024,
            "the policy's memory did not reach the launch"
        );
        // And the command line matches what the initramfs looks for — a
        // mismatch here is a boot failure with nothing on the console.
        assert!(
            launch.cmdline.contains("root=/dev/vda"),
            "{}",
            launch.cmdline
        );
        assert!(
            launch.cmdline.contains("console=hvc0"),
            "{}",
            launch.cmdline
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_state_volume_is_separate_from_the_root_and_survives_a_restart() {
        // THE persistence property, and the bug it closes.
        // `provision_root` wrote the root copy to `state_image()`, so no
        // second disk was attached, the guest's init fell back to a tmpfs
        // `/data`, and Postgres ran `initdb` on every boot. Measured in
        // the console across a stop/start cycle: two boots, two initdbs,
        // "persistent" todos that were actually recreated each time.
        let root_dir = scratch("state");
        let dir = crate::layout::guest_dir(&root_dir, crate::layout::GUEST_VERSION, host_arch());
        std::fs::create_dir_all(&dir).expect("dirs");
        for name in ["Image", "initramfs.gz", "root.img"] {
            std::fs::write(dir.join(name), b"x").expect("file");
        }
        let image = Image::find(&root_dir).expect("found");
        let project = crate::layout::ProjectId::new("stateful-01").expect("id");
        let paths = ProjectPaths::new(&root_dir, &project);

        let root = provision_root(&image, &paths).expect("root");
        let state = provision_state(&policy(), &paths).expect("state");
        assert_ne!(
            root, state,
            "the root copy and the state volume are the same file"
        );

        // The declared size, sparse: 20 GiB eagerly allocated per project
        // would be unusable.
        let declared = policy().resources.disk_mib * 1024 * 1024;
        assert_eq!(
            std::fs::metadata(&state).expect("metadata").len(),
            declared,
            "the state volume is not the size the policy declares"
        );

        // AND IT SURVIVES. A second start must not replace it, or every
        // start would discard the database.
        std::fs::write(&state, b"the guest has written here").expect("write");
        let again = provision_state(&policy(), &paths).expect("again");
        assert_eq!(
            std::fs::read(&again).expect("readable"),
            b"the guest has written here",
            "starting again replaced the state volume"
        );
        let _ = std::fs::remove_dir_all(&root_dir);
    }

    #[test]
    fn a_declared_mount_reaches_the_guest_and_not_only_the_summary() {
        // THE gap. The policy carried `filesystem.mounts`, the permission
        // summary showed them, and `launch_for` built a share list
        // containing only the workspace — so a mount the user read and
        // approved was never given to the guest. A permission that is
        // audited and not applied is worse than one that is absent: the
        // user believes they have it.
        let root_dir = scratch("mounts");
        let dir = crate::layout::guest_dir(&root_dir, crate::layout::GUEST_VERSION, host_arch());
        std::fs::create_dir_all(&dir).expect("dirs");
        for name in ["Image", "initramfs.gz", "root.img"] {
            std::fs::write(dir.join(name), b"x").expect("file");
        }
        let image = Image::find(&root_dir).expect("found");
        let project = crate::layout::ProjectId::new("mounted-01").expect("id");
        let paths = ProjectPaths::new(&root_dir, &project);

        let mut policy = policy();
        policy.grants = vec![crate::grant::Grant::Filesystem {
            path: PathBuf::from("~/.zshrc"),
            target: Some(PathBuf::from("~/.zshrc")),
            access: crate::decision::Access::ReadOnly,
        }];

        let launch = launch_for(
            &policy,
            &image,
            &paths,
            Path::new("/some/project"),
            Path::new("/Users/someone"),
            PathBuf::from("/tmp/root.img"),
            PathBuf::from("/tmp/state.img"),
        );

        // The workspace, plus the declared mount.
        assert_eq!(launch.shares.len(), 2, "{:?}", launch.shares);
        let declared = launch
            .shares
            .iter()
            .find(|s| s.tag != WORKSPACE_TAG)
            .expect("the declared mount is missing from the shares");

        // BOTH ends resolved, against different homes.
        assert_eq!(
            declared.host_path,
            PathBuf::from("/Users/someone/.zshrc"),
            "the source's `~` was not expanded against the host's home"
        );
        assert_eq!(
            declared.guest_path.as_deref(),
            Some(Path::new("/home/dev/.zshrc")),
            "the target's `~` was not expanded against the guest's home"
        );
        // Read-only carried through: a dotfile the guest can rewrite is one
        // it can use to change what runs on the HOST next time.
        assert!(declared.read_only, "a read-only mount became writable");

        // And the guest is TOLD where to put it, on the kernel command
        // line — VZ has no field for a destination, so without this the
        // share arrives anonymous and the guest mounts it anywhere.
        assert!(
            launch
                .cmdline
                .contains(&format!("rachna.mount={}:/home/dev/.zshrc", declared.tag)),
            "the destination never reached the guest: {}",
            launch.cmdline
        );
        let _ = std::fs::remove_dir_all(&root_dir);
    }

    #[test]
    fn mounting_the_project_directory_does_not_share_it_twice() {
        // `{ source = "."; }` is a reasonable thing to write, and the
        // workspace is already that directory — two shares of one path is
        // something VZ accepts and the guest then sees twice.
        let root_dir = scratch("dupe");
        let dir = crate::layout::guest_dir(&root_dir, crate::layout::GUEST_VERSION, host_arch());
        std::fs::create_dir_all(&dir).expect("dirs");
        for name in ["Image", "initramfs.gz", "root.img"] {
            std::fs::write(dir.join(name), b"x").expect("file");
        }
        let image = Image::find(&root_dir).expect("found");
        let project = crate::layout::ProjectId::new("dupe-0001").expect("id");
        let paths = ProjectPaths::new(&root_dir, &project);

        let mut policy = policy();
        policy.grants = vec![crate::grant::Grant::Filesystem {
            path: PathBuf::from("/some/project"),
            target: None,
            access: crate::decision::Access::ReadWrite,
        }];

        let launch = launch_for(
            &policy,
            &image,
            &paths,
            Path::new("/some/project"),
            Path::new("/Users/someone"),
            PathBuf::from("/tmp/root.img"),
            PathBuf::from("/tmp/state.img"),
        );
        assert_eq!(
            launch.shares.len(),
            1,
            "the project directory was shared twice: {:?}",
            launch.shares
        );
        let _ = std::fs::remove_dir_all(&root_dir);
    }

    #[test]
    fn each_project_gets_its_own_writable_root() {
        // Two projects sharing one root image would corrupt each other's
        // Postgres data directory. Copying is the correctness-first choice
        // (`01` §3b); copy-on-write is a step-14 concern.
        let root = scratch("provision");
        let dir = crate::layout::guest_dir(&root, crate::layout::GUEST_VERSION, host_arch());
        std::fs::create_dir_all(&dir).expect("dirs");
        std::fs::write(dir.join("Image"), b"k").expect("k");
        std::fs::write(dir.join("initramfs.gz"), b"i").expect("i");
        std::fs::write(dir.join("root.img"), b"shared-root").expect("r");
        let image = Image::find(&root).expect("found");

        let first = crate::layout::ProjectId::new("first-0001").expect("id");
        let second = crate::layout::ProjectId::new("second-0002").expect("id");
        let first_root = provision_root(&image, &ProjectPaths::new(&root, &first)).expect("first");
        let second_root =
            provision_root(&image, &ProjectPaths::new(&root, &second)).expect("second");

        assert_ne!(
            first_root, second_root,
            "two projects shared one root image"
        );
        assert_eq!(
            std::fs::read(&first_root).expect("readable"),
            b"shared-root",
            "the copy does not match the source"
        );

        // And a second call does NOT re-copy: that would discard the
        // project's state on every start, which is the opposite of `00`
        // §7's persistence.
        std::fs::write(&first_root, b"project-has-written-here").expect("write");
        let again = provision_root(&image, &ProjectPaths::new(&root, &first)).expect("again");
        assert_eq!(
            std::fs::read(&again).expect("readable"),
            b"project-has-written-here",
            "starting again overwrote the project's own state"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
