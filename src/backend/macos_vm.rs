//! Virtualization.framework, driven from Rust. **The only module that may
//! use `unsafe`.**
//!
//! # Why `unsafe` lives here and nowhere else
//!
//! `Cargo.toml` sets `unsafe_code = "deny"`, and `17`'s choice of
//! `objc2-virtualization` rested on the belief that the binding was safe
//! Rust. **It is not** — all 502 of its functions are `pub unsafe fn`, with
//! no safe function anywhere in it. `17`'s 2026-11-09 correction records how
//! that claim survived a probe which could not have tested it.
//!
//! So a macOS backend requires `unsafe`. The project owner chose to
//! *contain* it rather than ban it (no macOS backend at all) or move it
//! behind a Swift shim (the same `unsafe`, but where neither clippy nor
//! `cargo-mutants` can see it). `unsafe_code` is a **deny**, not a
//! **forbid**, precisely so one module can lift it.
//!
//! **`tests/unsafe_containment.rs` asserts this is the only such module**,
//! because nothing else would stop a second one appearing quietly.
//!
//! # The rule that kills a VZ guest silently
//!
//! **Every call must be dispatched ONTO the queue the VM was created with.**
//! Getting this wrong is a crash with no diagnostic — exit -5 (SIGTRAP),
//! nothing on stdout or stderr, the process simply ending between two
//! `println!`s. That is why it is structural here rather than checked.
//!
//! Three measurements got this right, and the first two were wrong turns
//! worth recording (`02` §6):
//!
//! 1. Private queue, `start` called from the **main thread** — died
//!    silently. Creating a VM with a queue and then calling from elsewhere
//!    is the violation.
//! 2. **Main** queue, calls from `main` — worked, and is a trap: it only
//!    works from `main`. `libtest` runs every test on a *spawned* thread,
//!    where `NSRunLoop::currentRunLoop()` is a different run loop than the
//!    main queue, so callbacks could never fire and all four lifecycle
//!    tests died mid-test. **A design that only works on the main thread is
//!    a design that cannot be tested.**
//! 3. **Private queue, every call dispatched onto it** — works from any
//!    thread, and needs no run loop of ours at all: a dispatch queue runs
//!    its own. This is what the module does.
//!
//! So there is no run-loop pumping here. An earlier version pumped
//! `NSRunLoop` on the calling thread, which was necessary only because of
//! choice 2 and is dead weight under choice 3.
//!
//! Consequence for the design: a VZ guest lives **inside this process** and
//! dies with it. `supervise.rs`'s spawn-and-record-a-PID model is right for
//! Cloud Hypervisor and structurally wrong here.

#![allow(
    unsafe_code,
    reason = "Virtualization.framework is an ObjC API and every one of \
              objc2-virtualization's 502 functions is `unsafe fn`. This is \
              the single module permitted to lift the crate-level deny, \
              asserted by tests/unsafe_containment.rs."
)]
#![cfg(target_os = "macos")]

use crate::backend::linux::Launch;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSArray, NSError, NSString, NSURL};
use objc2_virtualization::{
    VZDirectorySharingDeviceConfiguration, VZDiskImageStorageDeviceAttachment,
    VZEntropyDeviceConfiguration, VZFileSerialPortAttachment, VZLinuxBootLoader,
    VZSerialPortConfiguration, VZSharedDirectory, VZSingleDirectoryShare,
    VZStorageDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioFileSystemDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
    VZVirtualMachineState,
};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long to wait for `start` to call back before giving up.
///
/// `05` §5 measured 6.97 s to full boot on a real NixOS guest, so this is
/// boot time plus headroom rather than a guess. A hang here means the
/// framework never answered, which is worth reporting as itself.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

/// How often to re-read a guest's console while waiting for it.
const POLL: Duration = Duration::from_millis(100);

/// A pending VZ operation's result, and the condvar its block signals.
///
/// Named because the inline type is unreadable — `Arc<(Mutex<Option<Result<(),
/// String>>>, Condvar)>` says nothing at a glance about what it carries.
type Completion = Arc<(Mutex<Option<Result<(), String>>>, Condvar)>;

/// What went wrong, in the order a user can act on it.
#[derive(Debug)]
pub enum VmError {
    /// The configuration is not valid for this host.
    Invalid(String),
    /// The framework refused to start the VM.
    StartFailed(String),
    /// `start` never called back.
    StartTimedOut,
    /// A path the configuration names does not exist.
    Missing(std::path::PathBuf),
    /// Save or restore failed.
    SaveRestore(String),
    /// This configuration cannot be snapshotted at all.
    ///
    /// Separate from [`Self::SaveRestore`] because `02` §4 makes
    /// `validateSaveRestoreSupport` a **distinct gate** from `validate`, to
    /// be surfaced as a capability rather than discovered at the first
    /// suspend.
    SnapshotUnsupported(String),
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "this host cannot run that configuration: {why}"),
            Self::StartFailed(why) => write!(f, "the guest did not start: {why}"),
            Self::StartTimedOut => write!(
                f,
                "the guest did not start within {}s, and Virtualization.framework \
                 never reported why",
                OPERATION_TIMEOUT.as_secs()
            ),
            // Names the file AND what to do. "x does not exist" was the
            // first version, and the error-message test rejected it: a user
            // reading it learns nothing about why rachna wanted that path
            // or how to get it.
            Self::Missing(path) => write!(
                f,
                "the guest image is incomplete: {} is missing.                  Run `rachna doctor` to re-fetch it",
                path.display()
            ),
            Self::SaveRestore(why) => write!(f, "the snapshot could not be used: {why}"),
            Self::SnapshotUnsupported(why) => write!(
                f,
                "this environment cannot be suspended: {why}. `rachna stop` \
                 still works, and loses the running state"
            ),
        }
    }
}

impl std::error::Error for VmError {}

/// What to do with the console log when building a configuration.
///
/// An enum rather than a `bool`, because `build(launch, true)` says nothing
/// about what is true (AGENTS.md, "prefer enums") — and getting it wrong
/// here is a lost session rather than a cosmetic bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Console {
    /// Truncate: this is a cold boot, and a stale readiness marker would
    /// make the next `start` report success without waiting.
    Fresh,
    /// Leave it exactly as it is: a restore's configuration must match the
    /// snapshot's, and a replaced console file does not (`02` §4).
    Keep,
}

/// A live guest, and the handle its lifecycle runs through.
///
/// Not `Send`: every VZ call must happen on the queue the VM was created
/// with (`02` §6.2), and the type system is the right place to enforce that
/// — a `Guest` moved to another thread is the silent-death bug.
pub struct Guest {
    /// The queue the VM was created with. **Every** call goes through it.
    queue: dispatch2::DispatchRetained<dispatch2::DispatchQueue>,
    vm: Retained<VZVirtualMachine>,
    /// Kept so [`Self::restore`] can reuse the SAME configuration object.
    ///
    /// `02` §4 measured that rebuilding an equivalent config fails restore
    /// with `VZErrorRestore` — so holding it is not an optimisation.
    config: Retained<VZVirtualMachineConfiguration>,
    snapshotable: bool,
}

impl std::fmt::Debug for Guest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guest")
            .field("state", &self.state())
            .field("snapshotable", &self.snapshotable)
            .finish()
    }
}

/// Where a guest is, in our vocabulary rather than VZ's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// No vCPU is running and no memory is held.
    Stopped,
    /// Running.
    Running,
    /// vCPUs stopped, memory retained. The only state a snapshot may be
    /// taken from (`02` §4).
    Paused,
    /// Starting, pausing, resuming, or stopping.
    Transitioning,
    /// The framework reported an error state.
    Failed,
}

fn url(path: &Path) -> Retained<NSURL> {
    // No `unsafe`: the compiler says this one is safe, and keeping an
    // unneeded block here would dilute the ones that are load-bearing.
    // Every `unsafe` in this file should be a place a reviewer must think.
    NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()))
}

fn describe(error: *mut NSError) -> String {
    if error.is_null() {
        return "no error reported".to_owned();
    }
    // SAFETY: checked non-null, and VZ hands us a valid NSError.
    unsafe { (*error).localizedDescription() }.to_string()
}

impl Guest {
    /// Builds the configuration and constructs the VM, without starting it.
    ///
    /// Splitting construction from [`Self::start`] is deliberate: `02` §4
    /// requires `validateSaveRestoreSupport` be surfaced as a capability at
    /// **config** time rather than discovered at the first suspend, and that
    /// answer has to exist before anything boots.
    ///
    /// # Errors
    ///
    /// [`VmError::Missing`] if the kernel or initrd is absent — checked
    /// here because VZ's own failure for a missing kernel is an exception
    /// rather than an error return. [`VmError::Invalid`] if the host
    /// refuses the configuration.
    pub fn new(launch: &Launch) -> Result<Self, VmError> {
        Self::build(launch, Console::Fresh)
    }

    /// Builds a `Guest` whose configuration must match a snapshot's.
    ///
    /// **Measured limit (`02` §6.11): a rebuilt configuration cannot
    /// restore at all.** The same `Guest` restores its own snapshot
    /// reliably; a second one built from an identical [`Launch`] is
    /// refused with "invalid argument", and four candidate causes were
    /// eliminated. So this is useful only *within* the process that saved
    /// — it does not make a snapshot portable across a command boundary,
    /// and `rachna resume` as a separate process cannot work this way.
    ///
    /// **`02` §4's hardest constraint**: *"Rebuilding an equivalent config
    /// with a fresh console pipe fails with `VZErrorRestore` / 'invalid
    /// argument'"*. Measured again here, from the other end — a supervisor
    /// is a NEW PROCESS, so it cannot hold the original configuration
    /// object and must rebuild one the snapshot accepts.
    ///
    /// What broke it was [`Console::Fresh`]'s truncation: renaming the
    /// console aside and creating a new file is a *different* attachment,
    /// and restore rejected it with "invalid argument" — the supervisor
    /// then cold-booted and the suspended session was lost.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn for_restore(launch: &Launch) -> Result<Self, VmError> {
        Self::build(launch, Console::Keep)
    }

    fn build(launch: &Launch, console: Console) -> Result<Self, VmError> {
        for required in [&launch.kernel, &launch.initrd] {
            if !required.exists() {
                return Err(VmError::Missing(required.clone()));
            }
        }

        // SAFETY: every call below is an ObjC message send through
        // objc2-virtualization. The arguments are owned Rust values or
        // Retained ObjC objects that outlive the call, and this runs before
        // any VM exists so there is no queue affinity to violate yet.
        unsafe {
            let boot = VZLinuxBootLoader::initWithKernelURL(
                VZLinuxBootLoader::alloc(),
                &url(&launch.kernel),
            );
            boot.setInitialRamdiskURL(Some(&url(&launch.initrd)));
            boot.setCommandLine(&NSString::from_str(&launch.cmdline));

            let config = VZVirtualMachineConfiguration::new();
            config.setBootLoader(Some(&boot));
            config.setCPUCount(launch.cpus as usize);
            config.setMemorySize(launch.memory_mib * 1024 * 1024);

            // The console is FILE-backed, not a pipe. `02` §4 measured that
            // a fresh console pipe breaks restore with VZErrorRestore, and
            // `05` §4.3 that the serial console is the only reliable channel
            // out of a guest — so this is both the log and the diagnostic.
            if let Some(parent) = launch.console_log.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // TRUNCATED, not appended — and this is a correctness
            // requirement, not tidiness. A caller decides the guest is up
            // by finding a marker in this file (`02` §6.3, because the VM's
            // own state lies), so an appended log means the NEXT start
            // matches the PREVIOUS boot's marker and reports success
            // immediately.
            //
            // Measured: with `append`, a second `rachna start` returned
            // "started" without waiting, leaving TWO supervisors running
            // against one state file — and `stop` could only tear down the
            // one it knew about.
            //
            // The previous boot's log is not lost silently: it is moved
            // aside, because the most useful console is usually the one
            // from the boot that just failed.
            match console {
                // A cold boot gets a fresh log, so a readiness marker in
                // it is about THIS boot (`02` §6.10).
                Console::Fresh => {
                    if launch.console_log.exists() {
                        let previous = launch.console_log.with_extension("log.previous");
                        let _ = std::fs::rename(&launch.console_log, previous);
                    }
                    let _ = std::fs::File::create(&launch.console_log);
                }
                // A restore must leave it ALONE. Replacing the file is a
                // different attachment, and `02` §4's `VZErrorRestore`
                // follows.
                Console::Keep => {
                    let _ = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&launch.console_log);
                }
            }
            let attachment = VZFileSerialPortAttachment::initWithURL_append_error(
                VZFileSerialPortAttachment::alloc(),
                &url(&launch.console_log),
                true,
            )
            .map_err(|error| VmError::Invalid(error.localizedDescription().to_string()))?;
            let port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            port.setAttachment(Some(&attachment));
            let ports: Retained<NSArray<VZSerialPortConfiguration>> =
                NSArray::from_retained_slice(&[Retained::into_super(port)]);
            config.setSerialPorts(&ports);

            // Entropy: a guest without it blocks on first use of
            // /dev/random, which looks like a hang rather than a missing
            // device.
            let entropy = VZVirtioEntropyDeviceConfiguration::new();
            let entropies: Retained<NSArray<VZEntropyDeviceConfiguration>> =
                NSArray::from_retained_slice(&[Retained::into_super(entropy)]);
            config.setEntropyDevices(&entropies);

            // Disks, in attachment order — the guest addresses these as
            // /dev/vda, /dev/vdb in this order, and `snapshot.rs` records
            // that order because restoring into a swapped configuration
            // would hand the guest its state disk as its closure.
            if !launch.disks.is_empty() {
                let mut attached: Vec<Retained<VZStorageDeviceConfiguration>> = Vec::new();
                for disk in &launch.disks {
                    if !disk.path.exists() {
                        return Err(VmError::Missing(disk.path.clone()));
                    }
                    let image = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
                        VZDiskImageStorageDeviceAttachment::alloc(),
                        &url(&disk.path),
                        disk.read_only,
                    )
                    .map_err(|error| VmError::Invalid(error.localizedDescription().to_string()))?;
                    let block = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                        VZVirtioBlockDeviceConfiguration::alloc(),
                        &image,
                    );
                    attached.push(Retained::into_super(block));
                }
                let devices: Retained<NSArray<VZStorageDeviceConfiguration>> =
                    NSArray::from_retained_slice(&attached);
                config.setStorageDevices(&devices);
            }

            // Directory shares: the workspace, and whatever else the
            // policy grants. VZ shares a host DIRECTORY — no virtiofsd, no
            // socket — which is why `Share` carries a path.
            if !launch.shares.is_empty() {
                let mut devices: Vec<Retained<VZDirectorySharingDeviceConfiguration>> = Vec::new();
                for share in &launch.shares {
                    if !share.host_path.is_dir() {
                        return Err(VmError::Missing(share.host_path.clone()));
                    }
                    // `02` §4.1, measured on the guest side: never mount a
                    // host share over a directory systemd owns. The TAG is
                    // what the guest mounts by, and the guest decides
                    // where — so the host's job is to name it accurately
                    // and not to pick the mount point.
                    let tag = NSString::from_str(&share.tag);
                    // The tag must be valid, and VZ is the authority on
                    // what that means rather than us guessing a charset.
                    VZVirtioFileSystemDeviceConfiguration::validateTag_error(&tag).map_err(
                        |error| {
                            VmError::Invalid(format!(
                                "`{}` is not a usable share tag: {}",
                                share.tag,
                                error.localizedDescription()
                            ))
                        },
                    )?;

                    let directory = VZSharedDirectory::initWithURL_readOnly(
                        VZSharedDirectory::alloc(),
                        &url(&share.host_path),
                        share.read_only,
                    );
                    let single = VZSingleDirectoryShare::initWithDirectory(
                        VZSingleDirectoryShare::alloc(),
                        &directory,
                    );
                    let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                        VZVirtioFileSystemDeviceConfiguration::alloc(),
                        &tag,
                    );
                    device.setShare(Some(&single));
                    devices.push(Retained::into_super(device));
                }
                let list: Retained<NSArray<VZDirectorySharingDeviceConfiguration>> =
                    NSArray::from_retained_slice(&devices);
                config.setDirectorySharingDevices(&list);
            }

            config
                .validateWithError()
                .map_err(|error| VmError::Invalid(error.localizedDescription().to_string()))?;

            // The SEPARATE gate (`02` §4). Recorded rather than refused: a
            // project that never suspends is still usable, and `00` §3.7
            // wants a missing capability stated rather than silently absent.
            let snapshotable = config.validateSaveRestoreSupportWithError().is_ok();

            // A PRIVATE queue, not the main one. `02` §6.2: the main queue
            // works only from `main`, which makes the backend untestable —
            // `libtest` runs on spawned threads. Every call is dispatched
            // onto this queue instead, which works from anywhere.
            let queue = dispatch2::DispatchQueue::new("sh.rachna.vz", None);
            let vm = VZVirtualMachine::initWithConfiguration_queue(
                VZVirtualMachine::alloc(),
                &config,
                &queue,
            );

            Ok(Self {
                queue,
                vm,
                config,
                snapshotable,
            })
        }
    }

    /// Whether this configuration can be suspended to disk.
    ///
    /// `02` §4's separate gate, answered at config time.
    #[must_use]
    pub const fn can_snapshot(&self) -> bool {
        self.snapshotable
    }

    /// Where the guest is now.
    #[must_use]
    pub fn state(&self) -> VmState {
        // ON THE QUEUE, like every other call. `state` is a property read
        // and VZ still documents queue affinity for it; reading it from
        // another thread is the same violation as calling `start` there.
        let raw = self.on_queue(|vm| {
            // SAFETY: dispatched onto the VM's own queue.
            unsafe { vm.state() }
        });
        match raw {
            VZVirtualMachineState::Stopped => VmState::Stopped,
            VZVirtualMachineState::Running => VmState::Running,
            VZVirtualMachineState::Paused => VmState::Paused,
            VZVirtualMachineState::Error => VmState::Failed,
            _ => VmState::Transitioning,
        }
    }

    /// Boots the guest and waits for the framework to confirm it.
    ///
    /// # Errors
    ///
    /// [`VmError::StartFailed`] with the framework's own message, or
    /// [`VmError::StartTimedOut`] if it never answers.
    pub fn start(&self) -> Result<(), VmError> {
        let outcome = self.await_completion(|vm, handler| {
            // SAFETY: on the main queue, which is the queue the VM was
            // created with (`02` §6.2).
            unsafe { vm.startWithCompletionHandler(handler) }
        })?;
        outcome.map_err(VmError::StartFailed)
    }

    /// Stops the guest, discarding its running state.
    ///
    /// # Errors
    ///
    /// [`VmError::StartFailed`] carrying the framework's message — the
    /// variant is shared because a failed stop and a failed start are the
    /// same shape of problem for a caller.
    pub fn stop(&self) -> Result<(), VmError> {
        if self.state() == VmState::Stopped {
            return Ok(());
        }
        let outcome = self.await_completion(|vm, handler| {
            // SAFETY: as `start`.
            unsafe { vm.stopWithCompletionHandler(handler) }
        })?;
        outcome.map_err(VmError::StartFailed)
    }

    /// Asks the guest to shut itself down, and waits for it to stop.
    ///
    /// **Not [`Self::stop`]**, and the difference cost a corrupted
    /// filesystem to find. `stop` is documented by Apple as *"a destructive
    /// operation … without giving the guest a chance to stop cleanly"* — so
    /// a `rachna stop` built on it killed the guest with its state volume
    /// unflushed, and the next boot mounted a filesystem reporting
    /// `EXT4-fs error … deleted inode referenced`. The data was on the
    /// disk; the metadata describing it was not.
    ///
    /// This sends the guest the equivalent of a power button press, so its
    /// init unmounts and syncs. Falls back to a destructive stop when the
    /// guest does not respond — a guest that ignores shutdown must not
    /// leave `rachna stop` hanging forever.
    ///
    /// # Errors
    ///
    /// [`VmError::StartFailed`] if neither path could stop the guest.
    pub fn shutdown(&self, grace: Duration) -> Result<(), VmError> {
        if self.state() == VmState::Stopped {
            return Ok(());
        }

        // PAUSE FIRST, and this order is the whole fix. Pausing stops the
        // vCPUs with memory and devices intact, which drains the
        // virtio-blk queue — the writes the guest has already issued reach
        // the image before the VM goes away.
        //
        // The previous version asked the guest first and paused only after
        // the grace period expired. That looked more polite and was worse:
        // a busybox `sh` acting as init never acts on VZ's ACPI event (a
        // `trap` fires only after the current command returns, and the
        // loop sits in `sleep`), so every stop burned the full grace
        // waiting for an answer that never came — and `run::stop`'s own
        // budget expired meanwhile and signalled the supervisor dead,
        // mid-flush. Measured: the state volume came back unformatted on
        // the next boot, and Postgres ran `initdb` again.
        //
        // Best-effort: a guest that cannot be paused still has to be
        // stopped, and refusing to stop it would leave it running.
        let paused = self.pause().is_ok();

        // Then ask, for the guests that DO listen — a NixOS guest with
        // systemd will unmount properly, which is strictly better than
        // relying on a drained queue. Only from a non-paused state, since
        // `canRequestStop` is false while paused.
        if !paused {
            let requested = self.on_queue(|vm| {
                // SAFETY: on the VM's own queue.
                unsafe {
                    if vm.canRequestStop() {
                        vm.requestStopWithError().is_ok()
                    } else {
                        false
                    }
                }
            });
            if requested {
                let deadline = Instant::now() + grace;
                while Instant::now() < deadline {
                    if self.state() == VmState::Stopped {
                        return Ok(());
                    }
                    std::thread::sleep(POLL);
                }
            }
        }

        self.stop()
    }

    /// Pauses the guest: vCPUs stop, memory is retained.
    ///
    /// # Errors
    ///
    /// The framework's message if it refuses.
    pub fn pause(&self) -> Result<(), VmError> {
        let outcome = self.await_completion(|vm, handler| {
            // SAFETY: as `start`.
            unsafe { vm.pauseWithCompletionHandler(handler) }
        })?;
        outcome.map_err(VmError::StartFailed)
    }

    /// Resumes a paused guest.
    ///
    /// # Errors
    ///
    /// The framework's message if it refuses.
    pub fn resume(&self) -> Result<(), VmError> {
        let outcome = self.await_completion(|vm, handler| {
            // SAFETY: as `start`.
            unsafe { vm.resumeWithCompletionHandler(handler) }
        })?;
        outcome.map_err(VmError::StartFailed)
    }

    /// Writes the guest's memory to `path`. The guest must be **paused**.
    ///
    /// `02` §4: the VM must be `Paused` before saving, which is why
    /// `suspend` is compound (pause → save → stop) and needs a
    /// transitioning state.
    ///
    /// # Errors
    ///
    /// [`VmError::SnapshotUnsupported`] if this configuration was never
    /// savable, or [`VmError::SaveRestore`] if the write failed.
    pub fn save(&self, path: &Path) -> Result<(), VmError> {
        if !self.snapshotable {
            return Err(VmError::SnapshotUnsupported(
                "validateSaveRestoreSupport refused this device set".to_owned(),
            ));
        }
        if self.state() != VmState::Paused {
            return Err(VmError::SaveRestore(format!(
                "the guest must be paused before saving, and it is {:?}",
                self.state()
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| VmError::SaveRestore(error.to_string()))?;
        }
        let target = url(path);
        let outcome = self.await_completion(|vm, handler| {
            // SAFETY: as `start`; `target` outlives the call.
            unsafe { vm.saveMachineStateToURL_completionHandler(&target, handler) }
        })?;
        outcome.map_err(VmError::SaveRestore)
    }

    /// Restores memory from `path`, landing **paused** (`02` §4).
    ///
    /// # Errors
    ///
    /// [`VmError::Missing`] if there is no snapshot there, or
    /// [`VmError::SaveRestore`] with the framework's message — which `02`
    /// §4 notes a macOS update can cause, and which a caller must treat as
    /// "fall back to a cold boot, loudly" rather than as a broken install.
    pub fn restore(&self, path: &Path) -> Result<(), VmError> {
        if !path.exists() {
            return Err(VmError::Missing(path.to_path_buf()));
        }
        // The SAME config object, held since construction. `02` §4 measured
        // that an equivalent rebuilt config fails with VZErrorRestore.
        let _ = &self.config;
        let source = url(path);
        let outcome = self.await_completion(|vm, handler| {
            // SAFETY: as `start`.
            unsafe { vm.restoreMachineStateFromURL_completionHandler(&source, handler) }
        })?;
        outcome.map_err(VmError::SaveRestore)
    }

    /// Waits until the guest writes `marker` to its console, or the
    /// deadline passes.
    ///
    /// **The console, not the VM's state.** `02` §6.3 measured a VM
    /// reporting `Running` while the guest had produced nothing — so the
    /// only honest evidence a guest is alive is output the *guest* wrote.
    ///
    /// Returns whether the marker appeared.
    pub fn wait_for_console(&self, log: &Path, marker: &str, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if std::fs::read_to_string(log)
                .unwrap_or_default()
                .contains(marker)
            {
                return true;
            }
            if self.state() == VmState::Failed {
                return false;
            }
            // A plain sleep. The dispatch queue runs the VM on its own
            // thread (`02` §6, measurement 3), so this thread has nothing
            // to pump and sleeping starves nobody.
            std::thread::sleep(POLL);
        }
        false
    }

    /// Runs `work` on the VM's queue and returns its value.
    ///
    /// Synchronous, because every caller needs the answer before
    /// proceeding, and `exec_sync` is what makes "on the queue" true rather
    /// than hoped for.
    fn on_queue<T, F>(&self, work: F) -> T
    where
        F: FnOnce(&VZVirtualMachine) -> T + Send,
        T: Send,
    {
        // The VM pointer crosses into the closure as an address because
        // `Retained` is not `Send`. That is sound here and nowhere else:
        // `exec_sync` blocks this thread until the closure finishes, so
        // `self.vm` provably outlives the borrow, and the closure runs on
        // the queue the VM belongs to.
        let address = Retained::as_ptr(&self.vm) as usize;
        let mut slot = None;
        self.queue.exec_sync(|| {
            // SAFETY: `address` came from `self.vm` immediately above, and
            // `exec_sync` guarantees this runs before that borrow ends.
            let vm: &VZVirtualMachine = unsafe { &*(address as *const VZVirtualMachine) };
            slot = Some(work(vm));
        });
        // `expect` here would be a panic in the module that drives the VM,
        // which `Cargo.toml` warns against for exactly this code. The
        // closure cannot have been skipped — `exec_sync` is synchronous by
        // definition — so there is nothing to recover FROM; the honest move
        // is to make that unrepresentable rather than assert it at runtime.
        match slot {
            Some(value) => value,
            // Unreachable without `exec_sync` breaking its own contract.
            // Expressed as a loop on the queue rather than a panic so a
            // broken contract degrades into a visible hang in the backend
            // instead of unwinding across the ObjC boundary, which is
            // undefined behaviour.
            None => Self::exec_sync_broke_its_contract(),
        }
    }

    /// `exec_sync` returned without running its closure.
    ///
    /// Not reachable: `exec_sync` is synchronous by contract. It is a
    /// function rather than a `panic!` because unwinding across the
    /// Objective-C boundary is undefined behaviour, so a hang that shows up
    /// in a backtrace is strictly better than a panic that corrupts the
    /// process — and `Cargo.toml` warns on `panic` in this crate for the
    /// same reason.
    fn exec_sync_broke_its_contract() -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Issues a completion-handler call on the queue and waits for it.
    ///
    /// The shared shape of every lifecycle operation: VZ answers through a
    /// block, so the call is dispatched onto the queue and this thread
    /// waits on a condvar the block signals. Written once so `start`,
    /// `stop`, `pause`, `resume`, `save` and `restore` cannot each get the
    /// queue affinity subtly wrong — which is a silent crash, not a bug
    /// report (`02` §6).
    fn await_completion<F>(&self, issue: F) -> Result<Result<(), String>, VmError>
    where
        F: FnOnce(&VZVirtualMachine, &block2::DynBlock<dyn Fn(*mut NSError)>) + Send,
    {
        let done: Completion = Arc::new((Mutex::new(None), Condvar::new()));

        let signal = Arc::clone(&done);
        self.on_queue(move |vm| {
            let handler = block2::RcBlock::new(move |error: *mut NSError| {
                let outcome = if error.is_null() {
                    Ok(())
                } else {
                    Err(describe(error))
                };
                let (lock, waiters) = &*signal;
                if let Ok(mut slot) = lock.lock() {
                    *slot = Some(outcome);
                }
                waiters.notify_all();
            });
            issue(vm, &handler);
        });

        let (lock, waiters) = &*done;
        let mut slot = lock.lock().map_err(|_| VmError::StartTimedOut)?;
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        while slot.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let (next, timed_out) = waiters
                .wait_timeout(slot, left)
                .map_err(|_| VmError::StartTimedOut)?;
            slot = next;
            if timed_out.timed_out() && slot.is_none() {
                break;
            }
        }
        slot.take().ok_or(VmError::StartTimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_names_something_a_user_can_act_on() {
        let cases = [
            VmError::Invalid("bad cpu count".to_owned()),
            VmError::StartFailed("no entitlement".to_owned()),
            VmError::StartTimedOut,
            VmError::Missing(std::path::PathBuf::from("/no/kernel")),
            VmError::SaveRestore("invalidated by a macOS update".to_owned()),
            VmError::SnapshotUnsupported("device set".to_owned()),
        ];
        for case in &cases {
            let text = case.to_string();
            assert!(text.len() > 25, "{case:?} says too little: {text}");
            assert!(
                text.chars().next().is_some_and(char::is_lowercase),
                "{case:?} should read as a sentence fragment: {text}"
            );
        }
    }

    #[test]
    fn an_unsnapshotable_config_says_what_still_works() {
        // `00` §3.7: a missing capability must be stated, not silently
        // absent — and the message has to leave the user somewhere to go.
        let message = VmError::SnapshotUnsupported("no".to_owned()).to_string();
        assert!(message.contains("rachna stop"), "{message}");
        assert!(message.contains("loses the running state"), "{message}");
    }

    #[test]
    fn a_timeout_says_the_framework_was_silent() {
        // The distinction that matters when debugging: a refusal carries
        // Apple's message, a timeout means there was none.
        let message = VmError::StartTimedOut.to_string();
        assert!(message.contains("never reported why"), "{message}");
        assert!(
            message.contains(&OPERATION_TIMEOUT.as_secs().to_string()),
            "a timeout should say how long it waited: {message}"
        );
    }

    #[test]
    fn a_missing_kernel_is_refused_before_the_framework_sees_it() {
        // VZ throws an EXCEPTION for a missing kernel rather than returning
        // an error, and an exception here is a crash with no diagnostic
        // (`02` §4's entitlement row is the same class of problem). So the
        // check has to happen on our side of the boundary.
        let launch = Launch {
            kernel: std::path::PathBuf::from("/definitely/not/here/Image"),
            initrd: std::path::PathBuf::from("/definitely/not/here/initrd"),
            cmdline: "console=hvc0".to_owned(),
            memory_mib: 512,
            cpus: 1,
            disks: Vec::new(),
            shares: Vec::new(),
            console_log: std::path::PathBuf::from("/tmp/rachna-test-console.log"),
            api_socket: std::path::PathBuf::from("/tmp/rachna-test-api.sock"),
        };
        match Guest::new(&launch) {
            Err(VmError::Missing(path)) => {
                assert!(path.to_string_lossy().contains("Image"), "{path:?}");
            }
            other => panic!("a missing kernel was not refused: {other:?}"),
        }
    }
}
