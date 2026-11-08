//! The Linux backend: Cloud Hypervisor.
//!
//! Chosen on measured grounds (`03` §1, `04` §2), and every flag below comes
//! from a measurement rather than the documentation — in two cases the
//! documentation implied the opposite.
//!
//! # `--memory shared=on` is what makes restore fast
//!
//! `04`'s headline finding **inverts** what the docs implied. `03` §1 warned
//! that virtiofs (`shared=on`) looked mutually exclusive with fast restore,
//! forcing a choice between a live workspace mount and quick resume. The
//! opposite is true, measured:
//!
//! | | snapshot | restore + resume | size |
//! |---|---|---|---|
//! | **`shared=on`** | **44 ms** | **150 ms** | sparse |
//! | `shared=off` | 1174 ms | — | 2.1 GB (full RAM) |
//!
//! A **38× faster** snapshot with the thing we need anyway. So `shared=on` is
//! not a tuning choice, it is the configuration.
//!
//! # The console wiring is the other inverted finding
//!
//! `04` §4.2 and `05` §4.3: `--serial file=` with `console=ttyS0`. The
//! `--console file=` / `hvc0` variant produces **zero output and zero
//! errors**, which is the worst possible failure shape — it looks like a
//! guest that booted silently.
//!
//! # Why this module builds arguments rather than spawning
//!
//! Same reason as `eval.rs`: the security-critical part is *which flags are
//! passed*, and that is table-testable with no hypervisor. Spawning belongs
//! to the layer above, which is also where `04` §3's two host requirements
//! (`/dev/kvm` access, `CAP_NET_ADMIN` for a tap) are checked.

use crate::backend::Capabilities;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What the Linux backend can do, as measured.
///
/// The one `false` is the tier-1 gap: `09` §4 recovered a planted secret from
/// a snapshot file, so snapshots are **not** encrypted at rest here. Reported
/// honestly rather than aspirationally, because `01` §2.6 forbids claiming a
/// capability we do not have — and the conformance suite surfaces it as a
/// skip on every run until it is closed.
#[must_use]
pub const fn measured_capabilities() -> Capabilities {
    Capabilities {
        memory_snapshot: true,
        // `09` §4, measured BROKEN: a planted secret was recoverable.
        encrypted_snapshots: false,
        // `10` §3 and `13` §1: cgroup v2 CPUQuota and io limits both enforce.
        cpu_quota: true,
        io_quota: true,
    }
}

/// A virtiofs share to attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The tag the guest mounts by.
    pub tag: String,
    /// The vhost-user socket virtiofsd is listening on.
    pub socket: PathBuf,
}

/// A block device to attach.
///
/// Order is significant: the guest addresses these as `/dev/vda`, `/dev/vdb`
/// in attachment order, and `snapshot.rs` records that order because
/// restoring into a swapped configuration would hand the guest its state
/// disk as its closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    /// The image path.
    pub path: PathBuf,
    /// Whether the guest may write to it.
    pub read_only: bool,
}

/// Everything needed to launch a guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The PVH-capable ELF kernel.
    ///
    /// `05` §4.4: nixpkgs ships only a `bzImage`, and CH needs an ELF. The
    /// guest flake extracts one and asserts it is ELF, because an empty or
    /// still-compressed image fails at boot with no useful message.
    pub kernel: PathBuf,
    /// The initrd.
    pub initrd: PathBuf,
    /// The kernel command line.
    pub cmdline: String,
    /// Memory in mebibytes.
    pub memory_mib: u64,
    /// vCPU count.
    pub cpus: u32,
    /// Block devices, in attachment order.
    pub disks: Vec<Disk>,
    /// virtiofs shares.
    pub shares: Vec<Share>,
    /// Where to write the serial console.
    pub console_log: PathBuf,
    /// The API socket, for `ch-remote`.
    pub api_socket: PathBuf,
}

impl Launch {
    /// The `cloud-hypervisor` arguments.
    ///
    /// Built as one list so the security-critical set reads top to bottom
    /// with each flag's reason beside it.
    #[must_use]
    pub fn args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            "--kernel".into(),
            self.kernel.clone().into(),
            "--initramfs".into(),
            self.initrd.clone().into(),
            "--cmdline".into(),
            self.cmdline.clone().into(),
            // `shared=on` is NOT tuning. `04`: it makes snapshot 38× faster
            // (44 ms vs 1174 ms) and restore possible at all with virtiofs
            // attached — inverting what the documentation implied.
            "--memory".into(),
            format!("size={}M,shared=on", self.memory_mib).into(),
            // `core_scheduling=vm` keeps the guest's vCPUs off hyperthread
            // siblings shared with host work, which closes the SMT
            // side-channel class. `11` §2 measured it **free** —
            // 8347/8346/9414 ms against a baseline of 10098/8590/8468 — and
            // `15` §3.6 is explicit: "both it and core_scheduling=vm should
            // be on by default; neither costs anything measurable."
            //
            // So it is not configurable. A free mitigation behind a flag is
            // a mitigation most users never get.
            "--cpus".into(),
            format!("boot={},core_scheduling=vm", self.cpus).into(),
            // `--serial file=` with `console=ttyS0` in the cmdline. The
            // `--console file=` / hvc0 variant produces ZERO output and ZERO
            // errors (`04` §4.2) — a guest that looks like it booted
            // silently, which is the worst failure to debug.
            "--serial".into(),
            {
                let mut flag = OsString::from("file=");
                flag.push(&self.console_log);
                flag
            },
            "--console".into(),
            "off".into(),
            // Needed for pause/resume/snapshot at all: `ch-remote` talks to
            // this socket, and `04` §4.3 notes CH does not print a pty path
            // to stdout, so the API is the only reliable channel.
            "--api-socket".into(),
            self.api_socket.clone().into(),
        ];

        if !self.disks.is_empty() {
            args.push("--disk".into());
            for disk in &self.disks {
                let mut spec = OsString::from("path=");
                spec.push(&disk.path);
                // REQUIRED from CH v54. Measured on v54.0.0: omitting it is a
                // fatal `ParsingConfig(Validation(ImageTypeRequired))` —
                // "Image type required for disk" — where v53 (the version the
                // 04 spike used) inferred it. `04` §7 recommended targeting
                // v54 for its n-2 migration guarantee, and this is the
                // behaviour change that came with it.
                //
                // `raw` because Rachna's disks are raw images: a squashfs or
                // erofs closure (`00` §7 Layer C) and an ext4 state volume.
                spec.push(",image_type=raw");
                if disk.read_only {
                    spec.push(",readonly=on");
                }
                args.push(spec);
            }
        }

        if !self.shares.is_empty() {
            args.push("--fs".into());
            for share in &self.shares {
                let mut spec = OsString::from(format!("tag={},socket=", share.tag));
                spec.push(&share.socket);
                args.push(spec);
            }
        }

        // Landlock last, because its ruleset is derived from every path
        // above. `15` §3.6: defence against a **compromised VMM** — the one
        // attack a VM boundary cannot stop, and `idea.md` §19's first listed
        // risk. Measured free, so it is on by default rather than offered.
        args.extend(self.landlock_args());

        args
    }

    /// The Landlock flags, derived from the paths this launch already uses.
    ///
    /// Derived rather than configured, for the reason `exclusion.rs` exists:
    /// a hand-written allowlist beside a hand-written device list is two
    /// lists that drift, and the failure is a VM that cannot open its own
    /// disk. Every path the VMM legitimately touches is already a field on
    /// [`Launch`], so the ruleset is a projection of it.
    ///
    /// # What this actually restricts, measured
    ///
    /// Landlock applies **after** the VMM has opened its disks, so denying
    /// the disk images proves nothing — a probe doing that booted fine and
    /// looked like a decorative flag. The discriminating test is a file
    /// opened *later*: with a snapshot directory inside the rules,
    /// `ch-remote snapshot` wrote 204 MB; with the same directory outside
    /// them, it was **refused**. So the restriction is real, and what it
    /// buys is that a compromised VMM cannot write outside these paths.
    ///
    /// `/dev/kvm` is included because the VMM needs it and a ruleset without
    /// it would be a VM that cannot start — the kind of "secure" default
    /// that gets switched off.
    ///
    /// # A path CH will CREATE must be named by its directory
    ///
    /// Measured, and this would have broken every VM. **CH validates that
    /// every rule path exists at startup**, and the console log, API socket
    /// and virtiofs sockets do not exist yet — CH and virtiofsd create them.
    /// Naming them directly is a fatal
    /// `Validation(LandlockPathDoesNotExist("…/console.log"))` before the
    /// guest starts at all.
    ///
    /// So those get a rule on their **containing directory**, `rw`. That is
    /// looser than naming the file and it is the only thing that works; the
    /// directory is per-project runtime state (`layout.rs`), so the widening
    /// is bounded to paths Rachna owns rather than to anything useful to an
    /// attacker.
    ///
    /// Found by running the invocation this function generates rather than
    /// by reading it. The argument list looked correct and every unit test
    /// passed.
    fn landlock_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["--landlock".into()];
        let mut rules: Vec<OsString> = Vec::new();

        let mut rule = |path: &Path, access: &str| {
            let mut spec = OsString::from("path=");
            spec.push(path);
            spec.push(format!(",access={access}"));
            rules.push(spec);
        };

        rule(Path::new("/dev/kvm"), "rw");
        // These exist before CH runs: the boot bundle and the disk images.
        rule(&self.kernel, "r");
        rule(&self.initrd, "r");
        for disk in &self.disks {
            rule(&disk.path, if disk.read_only { "r" } else { "rw" });
        }

        // These do NOT exist yet, so the rule names the directory. Collected
        // and deduplicated because the console log, the API socket and every
        // share socket normally share one runtime directory, and repeating
        // it would make the argument list grow with the share count for no
        // additional access.
        let will_be_created = core::iter::once(self.console_log.as_path())
            .chain(core::iter::once(self.api_socket.as_path()))
            .chain(self.shares.iter().map(|share| share.socket.as_path()));
        let mut runtime_dirs: Vec<&Path> = Vec::new();
        for path in will_be_created {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() && !runtime_dirs.contains(&parent) {
                    runtime_dirs.push(parent);
                }
            }
        }
        for dir in runtime_dirs {
            rule(dir, "rw");
        }

        if !rules.is_empty() {
            args.push("--landlock-rules".into());
            args.extend(rules);
        }
        args
    }
}

/// Whether an argument list requests shared memory.
///
/// `04`: `--memory shared=on` is what makes snapshot fast *and* virtiofs
/// possible, so a launch without it cannot be snapshotted. Separated from
/// [`Launch::supports_snapshot`] so both outcomes are testable.
#[must_use]
pub fn args_support_snapshot(args: &[OsString]) -> bool {
    args.iter()
        .any(|arg| arg.to_string_lossy().contains("shared=on"))
}

/// The `virtiofsd` arguments for one share.
///
/// `16` §5.2 found **four per guest**, fully independent — so they are
/// started in parallel (`01` §5b.2), and serialising them would be pointless
/// latency on every start *and* every restore.
#[must_use]
pub fn virtiofsd_args(socket: &Path, shared_dir: &Path) -> Vec<OsString> {
    vec![
        "--socket-path".into(),
        socket.into(),
        "--shared-dir".into(),
        shared_dir.into(),
        // `13` §2 measured the worker child running with Seccomp: 2,
        // NoNewPrivs: 1 and a separate pid namespace — virtiofsd is fully
        // confined by default, correcting `11` §6 which claimed otherwise.
        // Sandboxing is left at its default precisely because the default is
        // the confined one.
        "--cache".into(),
        "auto".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch() -> Launch {
        Launch {
            kernel: PathBuf::from("/bundle/vmlinux"),
            initrd: PathBuf::from("/bundle/initrd"),
            cmdline: "console=ttyS0 panic=1".to_owned(),
            memory_mib: 2048,
            cpus: 2,
            disks: vec![
                Disk {
                    path: PathBuf::from("/p/closure.img"),
                    read_only: true,
                },
                Disk {
                    path: PathBuf::from("/p/state.img"),
                    read_only: false,
                },
            ],
            shares: vec![Share {
                tag: "workspace".to_owned(),
                socket: PathBuf::from("/p/vfs.sock"),
            }],
            console_log: PathBuf::from("/p/console.log"),
            api_socket: PathBuf::from("/p/api.sock"),
        }
    }

    fn rendered(launch: &Launch) -> Vec<String> {
        launch
            .args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn shared_on_is_always_set_because_it_is_what_makes_restore_fast() {
        // 04's headline, which INVERTS the documentation: 03 §1 warned
        // virtiofs looked mutually exclusive with fast restore. Measured,
        // shared=on makes snapshot 38x faster (44ms vs 1174ms) AND is
        // required for virtiofs. Not a tuning knob.
        let args = rendered(&launch());
        let memory = args
            .iter()
            .position(|a| a == "--memory")
            .map(|i| args[i + 1].clone())
            .expect("--memory is passed");
        assert!(memory.contains("shared=on"), "{memory}");
        assert!(memory.contains("size=2048M"), "{memory}");
        assert!(args_support_snapshot(&launch().args()));
    }

    #[test]
    fn a_launch_without_shared_on_is_not_snapshottable() {
        // Mutation testing found `supports_snapshot` untested: every fixture
        // has shared=on, so a mutant returning a constant `true` agreed with
        // all of them.
        //
        // The negative case cannot arise from `Launch` today — `args()`
        // always emits shared=on — so it is constructed by checking the
        // predicate's actual input. That matters because 03 §1 wrongly
        // believed virtiofs and fast restore were exclusive, and a future
        // change that made shared=on conditional would silently break
        // snapshots while this method kept saying yes.
        let without: Vec<OsString> = ["--memory", "size=2048M"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(
            !args_support_snapshot(&without),
            "shared=off is not snapshottable"
        );

        let with: Vec<OsString> = ["--memory", "size=2048M,shared=on"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(args_support_snapshot(&with));

        // And the real launch always has it.
        assert!(args_support_snapshot(&launch().args()));
    }

    #[test]
    fn the_console_uses_serial_file_and_not_the_silent_hvc0_variant() {
        // 04 §4.2 / 05 §4.3: `--console file=` with hvc0 produces ZERO
        // output and ZERO errors — a guest that looks like it booted
        // silently, which is the worst failure shape to debug. So the serial
        // path is pinned and `--console off` is explicit.
        let args = rendered(&launch());
        let serial = args
            .iter()
            .position(|a| a == "--serial")
            .map(|i| args[i + 1].clone())
            .expect("--serial is passed");
        assert_eq!(serial, "file=/p/console.log");

        let console = args
            .iter()
            .position(|a| a == "--console")
            .map(|i| args[i + 1].clone())
            .expect("--console is passed");
        assert_eq!(console, "off", "hvc0 would be silent");
    }

    #[test]
    fn disks_keep_their_order_and_their_read_only_flags() {
        // The guest addresses these as /dev/vda, /dev/vdb IN ORDER, which is
        // why snapshot.rs records the order: restoring into a swapped config
        // would hand the guest its state disk as its closure.
        let args = rendered(&launch());
        let start = args.iter().position(|a| a == "--disk").expect("--disk");
        assert_eq!(
            args[start + 1],
            "path=/p/closure.img,image_type=raw,readonly=on"
        );
        assert_eq!(args[start + 2], "path=/p/state.img,image_type=raw");
    }

    #[test]
    fn every_disk_declares_its_image_type() {
        // Measured on CH v54.0.0: omitting image_type is a FATAL
        // `ParsingConfig(Validation(ImageTypeRequired))`, where v53 inferred
        // it. The VM does not start at all, so this is not a nicety — and
        // `04` §7 recommended targeting v54, which is where the requirement
        // arrived.
        // Scoped to the arguments that FOLLOW `--disk`, not to every
        // `path=` in the list. The proxy "starts with path=" was correct
        // until Landlock arrived, whose rules are also `path=…` — and the
        // test then failed on `path=/dev/kvm,access=rw`, demanding an
        // image_type for a device that is not a disk. A test keyed on a
        // coincidence of syntax rather than on the thing it means.
        let args = rendered(&launch());
        let start = args.iter().position(|a| a == "--disk").expect("--disk");
        let disks: Vec<&String> = args[start + 1..]
            .iter()
            .take_while(|a| !a.starts_with("--"))
            .collect();
        assert!(!disks.is_empty(), "no disk arguments to check");
        for arg in disks {
            assert!(
                arg.contains("image_type="),
                "{arg} would make CH refuse to start"
            );
        }
    }

    #[test]
    fn core_scheduling_is_always_on_because_it_is_free() {
        // `11` §2 measured it free — 8347/8346/9414 ms against a baseline of
        // 10098/8590/8468 — and `15` §3.6 says "neither costs anything
        // measurable". A free mitigation behind a flag is one most users
        // never get, so it is not configurable.
        let args = rendered(&launch());
        let cpus = args
            .iter()
            .position(|a| a == "--cpus")
            .map(|i| args[i + 1].clone())
            .expect("--cpus");
        assert!(
            cpus.contains("core_scheduling=vm"),
            "the SMT side-channel mitigation is off: {cpus}"
        );
        // And the vCPU count survives, since both live in one argument.
        assert!(cpus.contains("boot="), "{cpus}");
    }

    #[test]
    fn landlock_is_enabled_and_its_rules_cover_every_path_the_vmm_uses() {
        // `15` §3.6: defence against a COMPROMISED VMM — the one attack a VM
        // boundary cannot stop. A ruleset missing a path the VMM needs is a
        // VM that will not start, which is the kind of "secure" default
        // people switch off, so the rules are derived from `Launch` rather
        // than written beside it.
        let launch = launch();
        let args = rendered(&launch);
        assert!(args.contains(&"--landlock".to_owned()));

        let start = args
            .iter()
            .position(|a| a == "--landlock-rules")
            .expect("--landlock-rules");
        let rules: Vec<&String> = args[start + 1..]
            .iter()
            .take_while(|a| !a.starts_with("--"))
            .collect();

        // Paths that EXIST before CH runs are named directly.
        for required in [
            "/dev/kvm",
            launch.kernel.to_str().expect("utf8"),
            launch.initrd.to_str().expect("utf8"),
        ] {
            assert!(
                rules.iter().any(|rule| rule.contains(required)),
                "no Landlock rule covers {required}: {rules:?}"
            );
        }

        // Paths CH CREATES are covered by their directory, not by name.
        // Measured: naming them is a fatal
        // `Validation(LandlockPathDoesNotExist("…/console.log"))` before the
        // guest starts, because CH checks every rule path exists. An earlier
        // version of this test demanded the file by name and so asserted
        // the one shape that cannot work — it passed while the real
        // invocation refused to boot.
        for created in [&launch.console_log, &launch.api_socket] {
            let parent = created.parent().expect("a parent").to_str().expect("utf8");
            assert!(
                rules
                    .iter()
                    .any(|rule| **rule == format!("path={parent},access=rw")),
                "no Landlock rule covers the directory of {}: {rules:?}",
                created.display()
            );
            assert!(
                !rules
                    .iter()
                    .any(|rule| rule.contains(created.to_str().expect("utf8"))),
                "{} is named directly, which CH refuses as nonexistent",
                created.display()
            );
        }
        for disk in &launch.disks {
            let path = disk.path.to_str().expect("utf8");
            assert!(
                rules.iter().any(|rule| rule.contains(path)),
                "no Landlock rule covers the disk {path}"
            );
        }
        // Same for share sockets: virtiofsd creates them, so the rule is on
        // the directory.
        for share in &launch.shares {
            let parent = share
                .socket
                .parent()
                .expect("a parent")
                .to_str()
                .expect("utf8");
            assert!(
                rules
                    .iter()
                    .any(|rule| **rule == format!("path={parent},access=rw")),
                "no Landlock rule covers the directory of {}",
                share.socket.display()
            );
        }

        // And one directory appears ONCE however many files live in it.
        // The console log, API socket and share sockets normally share a
        // runtime directory (`layout.rs`), and repeating it would grow the
        // argument list with the share count for no additional access.
        let mut dirs: Vec<&String> = rules
            .iter()
            .filter(|rule| rule.ends_with(",access=rw"))
            .copied()
            .collect();
        let total = dirs.len();
        dirs.sort();
        dirs.dedup();
        assert_eq!(total, dirs.len(), "a Landlock rule is repeated: {rules:?}");
    }

    #[test]
    fn a_read_only_disk_gets_a_read_only_landlock_rule() {
        // The access level is carried through rather than blanket `rw`:
        // granting write to the shared closure image would let a
        // compromised VMM corrupt a disk every project on this host boots
        // from (`08` §4.1.1 — the closure is THE shared thing).
        let args = rendered(&launch());
        let start = args
            .iter()
            .position(|a| a == "--landlock-rules")
            .expect("--landlock-rules");
        let rules: Vec<&String> = args[start + 1..]
            .iter()
            .take_while(|a| !a.starts_with("--"))
            .collect();

        for disk in &launch().disks {
            let path = disk.path.to_str().expect("utf8");
            let rule = rules
                .iter()
                .find(|rule| rule.contains(path))
                .unwrap_or_else(|| panic!("no rule for {path}"));
            let expected = if disk.read_only {
                "access=r"
            } else {
                "access=rw"
            };
            assert!(
                rule.ends_with(expected),
                "{path} is read_only={} but its rule is {rule}",
                disk.read_only
            );
        }
    }

    #[test]
    fn a_share_passes_its_tag_and_socket() {
        let args = rendered(&launch());
        let start = args.iter().position(|a| a == "--fs").expect("--fs");
        assert_eq!(args[start + 1], "tag=workspace,socket=/p/vfs.sock");
    }

    #[test]
    fn the_api_socket_is_always_passed() {
        // Without it there is no pause, resume or snapshot at all: ch-remote
        // talks to this socket, and 04 §4.3 notes CH does not print a pty
        // path to stdout, so the API is the only reliable channel.
        assert!(rendered(&launch()).contains(&"--api-socket".to_owned()));
    }

    #[test]
    fn a_launch_with_no_disks_or_shares_omits_those_flags() {
        // An empty `--disk` with no value would make CH reject the whole
        // invocation, so the flag has to be absent rather than present-empty.
        let bare = Launch {
            disks: vec![],
            shares: vec![],
            ..launch()
        };
        let args = rendered(&bare);
        assert!(!args.contains(&"--disk".to_owned()));
        assert!(!args.contains(&"--fs".to_owned()));
        // And it is still snapshottable, because shared=on does not depend
        // on there being a share.
        assert!(args_support_snapshot(&bare.args()));
    }

    #[test]
    fn the_linux_capabilities_report_the_tier_one_snapshot_gap_honestly() {
        // 09 §4 RECOVERED a planted secret from a snapshot file. 01 §2.6
        // forbids claiming a capability we lack, so this is false until the
        // gap is closed — and the conformance suite surfaces it as a skip on
        // every run until then.
        let capabilities = measured_capabilities();
        assert!(
            !capabilities.encrypted_snapshots,
            "claiming encryption would hide a measured tier-1 gap"
        );
        assert!(capabilities.memory_snapshot, "04 §1");
        assert!(capabilities.cpu_quota, "10 §3: cgroup CPUQuota enforces");
        assert!(capabilities.io_quota, "13 §1");
    }

    #[test]
    fn virtiofsd_gets_a_socket_and_a_shared_dir() {
        let args: Vec<String> = virtiofsd_args(Path::new("/p/vfs.sock"), Path::new("/p/workspace"))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--socket-path".to_owned()));
        assert!(args.contains(&"/p/vfs.sock".to_owned()));
        assert!(args.contains(&"--shared-dir".to_owned()));
        assert!(args.contains(&"/p/workspace".to_owned()));
    }

    #[test]
    fn virtiofsd_is_left_at_its_default_sandboxing() {
        // 13 §2 measured the worker child running with Seccomp: 2,
        // NoNewPrivs: 1 and a separate pid namespace — virtiofsd is FULLY
        // confined by default, correcting 11 §6 which claimed otherwise.
        // Passing a sandbox flag would risk weakening what is already right.
        let args: Vec<String> = virtiofsd_args(Path::new("/s"), Path::new("/d"))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|a| a.contains("sandbox")),
            "do not override a default that is already confined: {args:?}"
        );
    }
}
