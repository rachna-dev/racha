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
            "--cpus".into(),
            format!("boot={}", self.cpus).into(),
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

        args
    }

    /// Whether this launch can be snapshotted.
    ///
    /// `shared=on` is always set, so this is always true — asserted as a
    /// method rather than assumed, because `03` §1's warning that virtiofs
    /// and fast restore were exclusive was wrong, and a future reader may
    /// reasonably doubt it.
    #[must_use]
    pub fn supports_snapshot(&self) -> bool {
        self.args()
            .iter()
            .any(|arg| arg.to_string_lossy().contains("shared=on"))
    }
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
