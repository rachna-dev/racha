//! Snapshot metadata: what must be recorded to restore a snapshot at all.
//!
//! `02-SPIKE-MACOS-VZ.md` §4 found this the hard way, and it is stricter than
//! it sounds:
//!
//! > The config must be **compatible** with the saved state. Rebuilding an
//! > equivalent config with a *fresh console pipe* fails with `VZErrorRestore`
//! > / "invalid argument". Restore initially failed until the **same** config
//! > object was reused.
//!
//! So a snapshot is useless without enough metadata to reconstruct a
//! byte-compatible configuration. This type is that metadata, and the reason
//! it exists separately from the backend is that *getting it wrong is
//! silent*: the snapshot writes fine and fails months later on restore.
//!
//! # Three further constraints this encodes
//!
//! - **A snapshot is tied to the guest it came from** (`02` §4), so the guest
//!   version is part of the identity rather than a note.
//! - **A macOS update can invalidate saved state**, with a specific error. So
//!   the host OS version is recorded, letting `resume` say *why* it is cold
//!   booting instead of reporting a generic failure.
//! - **Save files are encrypted with a host-tied key** (`02` §4), so a
//!   snapshot is **not portable between machines** — recorded explicitly,
//!   because a user copying `~/.rachna` to a new laptop otherwise gets an
//!   unexplained failure.

use crate::backend::Capabilities;
use core::fmt;

/// Why a snapshot cannot be restored.
///
/// Each variant is a *reason to cold boot*, not an error to propagate: `02`
/// §4 requires a failed restore to fall back loudly rather than fail, because
/// "your saved session was invalidated by a macOS update, booting fresh" is
/// merely annoying where a silent vanishing is a support nightmare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incompatible {
    /// The snapshot was taken from a different guest.
    ///
    /// Normal rather than exceptional: upgrading `rachna` bumps the guest
    /// (`08` §4.1.1), so every upgrade invalidates existing snapshots.
    GuestChanged { taken_with: String, running: String },
    /// The host OS changed, which macOS documents as invalidating saved state.
    HostOsChanged { taken_on: String, running: String },
    /// The snapshot came from another machine.
    ///
    /// Save files are encrypted with a key tied to the host, so this cannot
    /// work — and saying so beats a decryption error.
    DifferentMachine { taken_on: String, running: String },
    /// The device configuration differs.
    ///
    /// The `VZErrorRestore` case: a config that is *equivalent* but not
    /// *identical* fails, so this compares the recorded shape rather than
    /// trusting that rebuilding produced the same thing.
    DeviceConfigChanged { detail: String },
    /// The backend cannot restore at all.
    NoSnapshotSupport,
    /// The snapshot on disk is incomplete.
    ///
    /// **Measured, and the failure mode is silence** (`24` §6): a Cloud
    /// Hypervisor snapshot is three files — `config.json`, `memory-ranges`,
    /// `state.json` — and `ch-remote snapshot` returns *before* `state.json`
    /// is flushed. Restoring from two of three exits with **no error, no log
    /// and no process.**
    ///
    /// So this is checked rather than discovered: `02` §4 requires a failed
    /// restore to fall back *loudly*, and a silent exit is the opposite.
    Incomplete { missing: Vec<String> },
}

impl fmt::Display for Incompatible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuestChanged {
                taken_with,
                running,
            } => write!(
                f,
                "this snapshot was taken with guest {taken_with} and you are \
                 running {running} — booting fresh"
            ),
            Self::HostOsChanged { taken_on, running } => write!(
                f,
                "macOS changed from {taken_on} to {running}, which invalidates \
                 saved VM state — booting fresh"
            ),
            Self::DifferentMachine { taken_on, running } => write!(
                f,
                "this snapshot was taken on {taken_on} and encrypted with that \
                 machine's key; it cannot be restored on {running} — booting fresh"
            ),
            Self::DeviceConfigChanged { detail } => write!(
                f,
                "the environment's devices changed ({detail}), so the saved \
                 state no longer matches — booting fresh"
            ),
            Self::NoSnapshotSupport => {
                f.write_str("this host cannot restore saved VM state — booting fresh")
            }
            Self::Incomplete { missing } => write!(
                f,
                "this snapshot is incomplete ({} missing), so it was never \
                 finished writing — booting fresh",
                missing.join(", ")
            ),
        }
    }
}

impl core::error::Error for Incompatible {}

/// The device shape a snapshot was taken with.
///
/// Compared field by field rather than by a hash, so a mismatch can *name*
/// what changed — `02` §4's whole lesson is that an equivalent-but-different
/// config fails, and a user told "devices changed" with no detail cannot act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceShape {
    /// Memory in bytes. Part of the saved state's layout.
    pub memory_bytes: u64,
    /// vCPU count.
    pub cpu_count: u32,
    /// Block devices, in attachment order.
    ///
    /// Order matters: VZ attaches by index, so reordering two disks is a
    /// different machine even with identical contents.
    pub block_devices: Vec<String>,
    /// virtiofs share tags, in attachment order.
    pub shares: Vec<String>,
    /// Whether a console was attached, and how.
    ///
    /// `02` §4: a **fresh console pipe** is what broke restore, and
    /// file-backed attachments are more robust. Recorded so a restore can
    /// refuse rather than fail opaquely.
    pub console: ConsoleKind,
    /// Whether a balloon device was attached (`12` §2).
    pub balloon: bool,
}

/// How a console was attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleKind {
    /// No console.
    None,
    /// A file, which `02` §4 found more robust across restore.
    File,
    /// A pipe — the attachment that broke restore when recreated.
    Pipe,
    /// A pty, for an interactive session.
    Pty,
}

impl ConsoleKind {
    /// Every kind.
    pub const ALL: [Self; 4] = [Self::None, Self::File, Self::Pipe, Self::Pty];

    /// The name used in metadata and messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::File => "file",
            Self::Pipe => "pipe",
            Self::Pty => "pty",
        }
    }

    /// Whether this attachment survives being recreated for a restore.
    ///
    /// `02` §4, measured: a fresh **pipe** fails with `VZErrorRestore`. A
    /// file-backed attachment is reconstructible because its identity is the
    /// path rather than a live file descriptor.
    #[must_use]
    pub const fn survives_recreation(self) -> bool {
        matches!(self, Self::None | Self::File)
    }
}

impl fmt::Display for ConsoleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DeviceShape {
    /// Names the first difference from `other`, or `None` if identical.
    ///
    /// Returns the *first* rather than all of them because a restore stops at
    /// the first incompatibility anyway, and one clear sentence beats a list
    /// the user cannot act on differently.
    #[must_use]
    pub fn first_difference(&self, other: &Self) -> Option<String> {
        if self.memory_bytes != other.memory_bytes {
            return Some(format!(
                "memory {} → {}",
                self.memory_bytes, other.memory_bytes
            ));
        }
        if self.cpu_count != other.cpu_count {
            return Some(format!("cpus {} → {}", self.cpu_count, other.cpu_count));
        }
        if self.block_devices != other.block_devices {
            return Some(format!(
                "disks {:?} → {:?}",
                self.block_devices, other.block_devices
            ));
        }
        if self.shares != other.shares {
            return Some(format!("shares {:?} → {:?}", self.shares, other.shares));
        }
        if self.console != other.console {
            return Some(format!("console {} → {}", self.console, other.console));
        }
        if self.balloon != other.balloon {
            return Some(format!("balloon {} → {}", self.balloon, other.balloon));
        }
        None
    }
}

/// The files a complete Cloud Hypervisor snapshot contains.
///
/// Measured (`24` §6). Listed rather than inferred, because the consequence
/// of a missing one is a *silent* restore failure.
pub const REQUIRED_FILES: [&str; 3] = ["config.json", "memory-ranges", "state.json"];

/// Which required files are absent from a snapshot.
///
/// `present` is what the caller found on disk. Pure, so the rule is testable
/// without a filesystem — and the caller does the I/O, as everywhere else in
/// this crate.
#[must_use]
pub fn missing_files<'a>(present: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let present: Vec<&str> = present.into_iter().collect();
    REQUIRED_FILES
        .iter()
        .filter(|required| !present.contains(*required))
        .map(|required| (*required).to_owned())
        .collect()
}

/// Everything recorded alongside a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// The guest version the snapshot was taken with.
    pub guest_version: String,
    /// The host OS version, for the macOS-update case.
    pub host_os_version: String,
    /// A stable identifier for the machine.
    ///
    /// Needed because save files are encrypted with a host-tied key, so a
    /// snapshot from another machine cannot be decrypted at all.
    pub machine_id: String,
    /// The device shape, for the `VZErrorRestore` case.
    pub devices: DeviceShape,
    /// The snapshot files found on disk.
    ///
    /// Empty means "not checked" rather than "none found", so a caller that
    /// does not inspect the directory is not told its snapshot is broken.
    /// When populated, [`Metadata::check_restorable`] verifies completeness
    /// first (`24` §6).
    pub present_files: Vec<String>,
    /// The effective grant set the guest was running under when saved.
    ///
    /// [`AccessSummary::fingerprint`](crate::summary::AccessSummary::fingerprint),
    /// so it is comment- and order-insensitive exactly as `00` §3.10c
    /// requires of the approval record it is compared against.
    ///
    /// # Why a snapshot must carry this
    ///
    /// **Resume had no policy gate at all.** `lifecycle.rs` went
    /// `Suspended → Resuming → Running` without consulting a policy, and
    /// nothing recorded what the snapshot had been permitted — so a guest
    /// suspended under one grant set resumed under it unchecked, however
    /// long ago and whatever `rachna.nix` says now.
    ///
    /// That is not an attack, which is what makes it worse: `git pull`,
    /// `rachna resume`, and yesterday's permissions are live again with no
    /// summary, which is precisely the gap `00` §3.10c was written to close
    /// for `start` and never covered for `resume`.
    ///
    /// Empty means "not recorded" — a snapshot from a build before this
    /// field existed. Treated as *needing approval* rather than as matching,
    /// because the safe direction for an unknown grant set is to ask.
    pub grant_fingerprint: String,
}

/// Whether a resume may proceed without asking the user first.
///
/// **Deliberately not an [`Incompatible`] variant**, and the distinction is
/// the whole design: a changed grant set does not make a snapshot
/// *unrestorable*. The memory image is fine, the devices match, the guest
/// would come back perfectly — the question is whether it *should*, under
/// permissions nobody has reviewed. Folding this into `Incompatible` would
/// make "your policy changed" read as "your snapshot is broken" and send the
/// user to delete it.
///
/// # Why resume needs this at all
///
/// `00` §3.10c gates `start` on a first-run summary, and nothing gated
/// `resume`. `lifecycle.rs` went `Suspended → Resuming → Running` without
/// consulting a policy, and [`Metadata`] did not record what the snapshot had
/// been permitted. So: `git pull`, `rachna resume`, and yesterday's
/// permissions are live again with no summary. Not an attack — which is what
/// makes it worse than the forged-approval case `08` §3.4a describes, because
/// it needs nobody to do anything wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeApproval {
    /// The grant set is unchanged and already approved. Resume silently.
    Unchanged,
    /// The grant set differs from the snapshot's, or was never approved.
    ///
    /// Carries both fingerprints so a caller can render the diff rather than
    /// only announce that something changed — `00` §3.3's rule applies here
    /// as everywhere: a user told "permissions changed" cannot act.
    NeedsApproval {
        /// What the snapshot was running under.
        taken_with: String,
        /// What `rachna.nix` says now.
        running: String,
    },
    /// The snapshot predates grant recording, so nothing can be compared.
    ///
    /// Its own variant rather than folded into `NeedsApproval`, because the
    /// honest message differs: there is no diff to show, and the reason is
    /// our own format change rather than anything the user did.
    Unrecorded,
}

impl ResumeApproval {
    /// Whether the resume may proceed without asking.
    ///
    /// An explicit match, so adding a variant is a compile error here rather
    /// than silently counting as permitted.
    #[must_use]
    pub const fn may_resume_silently(&self) -> bool {
        match *self {
            Self::Unchanged => true,
            Self::NeedsApproval { .. } | Self::Unrecorded => false,
        }
    }
}

impl Metadata {
    /// Whether resuming this snapshot needs the user to approve first.
    ///
    /// Separate from [`Self::check_restorable`] because the two answer
    /// different questions and a caller needs both: *can* this restore, and
    /// *may* it. A snapshot can be perfectly restorable and still carry
    /// permissions nobody has reviewed.
    ///
    /// `approved` is the store's answer for the *current* grant set
    /// (`store::approval`), supplied rather than looked up here so this stays
    /// pure and so there is one approval authority.
    #[must_use]
    pub fn check_resume_approval(
        &self,
        running_fingerprint: &str,
        approved: bool,
    ) -> ResumeApproval {
        if self.grant_fingerprint.is_empty() {
            return ResumeApproval::Unrecorded;
        }
        // Both conditions, and both are necessary. An unchanged grant set
        // that was never approved must still ask — otherwise suspending
        // before approving and resuming afterwards would launder an
        // unapproved policy through the snapshot.
        if self.grant_fingerprint == running_fingerprint && approved {
            return ResumeApproval::Unchanged;
        }
        ResumeApproval::NeedsApproval {
            taken_with: self.grant_fingerprint.clone(),
            running: running_fingerprint.to_owned(),
        }
    }

    /// Whether this snapshot can be restored into `running`.
    ///
    /// # Errors
    ///
    /// [`Incompatible`] naming the single reason, in the order a user would
    /// want to hear it: machine identity first, because that one can never be
    /// fixed, then the guest, then the host OS, then devices.
    pub fn check_restorable(
        &self,
        running: &Self,
        capabilities: Capabilities,
    ) -> Result<(), Incompatible> {
        if !capabilities.memory_snapshot {
            return Err(Incompatible::NoSnapshotSupport);
        }
        // Before anything about compatibility: is the snapshot even finished?
        // `24` §6 measured a two-of-three snapshot restoring with no error at
        // all, so an unchecked incomplete snapshot is a silent failure.
        if !self.present_files.is_empty() {
            let missing = missing_files(self.present_files.iter().map(String::as_str));
            if !missing.is_empty() {
                return Err(Incompatible::Incomplete { missing });
            }
        }
        // First, because it is the only one a user cannot resolve by any
        // action short of going back to the original machine.
        if self.machine_id != running.machine_id {
            return Err(Incompatible::DifferentMachine {
                taken_on: self.machine_id.clone(),
                running: running.machine_id.clone(),
            });
        }
        if self.guest_version != running.guest_version {
            return Err(Incompatible::GuestChanged {
                taken_with: self.guest_version.clone(),
                running: running.guest_version.clone(),
            });
        }
        if self.host_os_version != running.host_os_version {
            return Err(Incompatible::HostOsChanged {
                taken_on: self.host_os_version.clone(),
                running: running.host_os_version.clone(),
            });
        }
        if let Some(detail) = self.devices.first_difference(&running.devices) {
            return Err(Incompatible::DeviceConfigChanged { detail });
        }
        Ok(())
    }
}

/// What a user must be told before a snapshot is written.
///
/// `09` §4 is the most serious finding in that document, and it was measured
/// rather than inferred: Cloud Hypervisor writes guest memory to a plain
/// file, and a planted marker was recovered from it verbatim. So **anything
/// in guest RAM at snapshot time is on disk in plaintext** — tokens, SSH
/// material, decrypted database pages, environment secrets — protected only
/// by file mode `0600`.
///
/// Encryption is the fix and is not built yet. This type is §4's *fifth*
/// requirement, which can ship now and is the honest default: *"Until
/// encryption lands, `rachna snapshot create` on Linux should state that the
/// snapshot contains unencrypted guest memory. An unstated weakness is worse
/// than a stated one."*
///
/// # Why a type rather than a log line
///
/// The same reason [`Decision`](crate::decision::Decision) is an event rather
/// than a bool: a warning that lives in a `println!` at one call site is one
/// refactor away from being lost, and nothing would fail. Here the only way
/// to get a [`Confidentiality`] is to ask, the warning text is derived from a
/// measured [`Capabilities`], and a test asserts the Linux answer is not
/// silent. If encryption lands, this starts returning
/// [`Confidentiality::Encrypted`] and the warning disappears on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidentiality {
    /// Guest memory is encrypted at rest by the platform.
    ///
    /// macOS, with a host-tied key (`02` §4, `12` §1) — which is also why
    /// such a snapshot is not portable, handled by
    /// [`Incompatible::DifferentMachine`].
    Encrypted,
    /// Guest memory is written in plaintext.
    ///
    /// Linux today (`09` §4). Carries the path so the message can name the
    /// file a user would have to protect or delete.
    Plaintext,
}

impl Confidentiality {
    /// What the platform actually does, from measured capabilities.
    ///
    /// Takes [`Capabilities`] rather than reading `cfg!(target_os)` so the
    /// answer comes from what a backend *measured* — the same reason
    /// `measured_capabilities` takes `save_restore_supported` instead of
    /// assuming it.
    #[must_use]
    pub const fn of(capabilities: Capabilities) -> Self {
        if capabilities.encrypted_snapshots {
            Self::Encrypted
        } else {
            Self::Plaintext
        }
    }

    /// Whether a user must be warned before this snapshot is written.
    #[must_use]
    pub const fn needs_warning(&self) -> bool {
        matches!(*self, Self::Plaintext)
    }

    /// The warning to print, or `None` when there is nothing to warn about.
    ///
    /// Deliberately specific about all four things `09` §4 says a user needs:
    /// that memory is in the clear, what kinds of secret that includes, that
    /// mode `0600` is the only protection, and that deleting the file does not
    /// erase it. A vague "snapshots may contain sensitive data" would satisfy
    /// a checklist and not a user.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        match *self {
            Self::Encrypted => None,
            Self::Plaintext => Some(
                "this snapshot will contain UNENCRYPTED guest memory: any                  token, key, or decrypted data in RAM is written to disk in                  plaintext (09 §4, measured). The file is mode 0600 and that                  is the only protection. Deleting it later does not erase the                  contents. Credential placeholders keep real secrets out of                  guest memory entirely (00 §3.6)"
                    .to_owned(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- snapshot confidentiality (09 §4, the open tier-1 item) ----------

    // The measured platform shapes come from `Capabilities` itself —
    // `measured_macos()` and `measured_linux()` — rather than being copied
    // here. A local copy would keep passing after someone closed the Linux
    // gap, which is exactly the regression these tests exist to notice.

    #[test]
    fn a_linux_snapshot_is_never_written_silently() {
        // 09 §4's fifth requirement, which is the one that can ship before
        // encryption: "An unstated weakness is worse than a stated one."
        //
        // First, assert the thing under attack EXISTS: that the Linux
        // capability shape really is the unencrypted one. Without this the
        // rest passes just as well against a platform that encrypts, which
        // would make the whole test vacuous.
        assert!(
            !Capabilities::measured_linux().encrypted_snapshots,
            "09 §4 measured Linux snapshots as plaintext; if this is now              false the gap is closed and this test should be rewritten"
        );

        let linux = Confidentiality::of(Capabilities::measured_linux());
        assert_eq!(linux, Confidentiality::Plaintext);
        assert!(linux.needs_warning());
        let warning = linux.warning().expect("a plaintext snapshot warns");

        // The four things 09 §4 says a user needs, each checked, because a
        // vague warning satisfies a checklist rather than a user.
        assert!(
            warning.contains("UNENCRYPTED"),
            "the warning must be unmissable: {warning}"
        );
        assert!(warning.contains("plaintext"), "{warning}");
        assert!(warning.contains("0600"), "{warning}");
        assert!(
            warning.contains("does not erase"),
            "09 §4 requires saying that deletion is not erasure: {warning}"
        );
        // And the mitigation that actually works today, so the warning is
        // actionable rather than only alarming.
        assert!(warning.contains("placeholder"), "{warning}");
    }

    #[test]
    fn an_encrypted_snapshot_does_not_warn_about_nothing() {
        // The other half, and not a formality: a tool that warns on every
        // platform teaches users to ignore the warning, which costs the Linux
        // case its force.
        assert!(
            Capabilities::measured_macos().encrypted_snapshots,
            "02 §4 measured macOS save files as encrypted"
        );
        let macos = Confidentiality::of(Capabilities::measured_macos());
        assert_eq!(macos, Confidentiality::Encrypted);
        assert!(!macos.needs_warning());
        assert_eq!(macos.warning(), None);
    }

    #[test]
    fn confidentiality_follows_the_measurement_not_the_platform() {
        // `of` reads the capability rather than `cfg!(target_os)`, so if a
        // future Linux backend encrypts, the warning disappears by itself
        // instead of needing someone to remember this file. Proven by
        // flipping only that field.
        let encrypting_linux = Capabilities {
            encrypted_snapshots: true,
            ..Capabilities::measured_linux()
        };
        assert_eq!(
            Confidentiality::of(encrypting_linux),
            Confidentiality::Encrypted,
            "the warning must be driven by the measurement, not by the OS"
        );
        // And the converse: a macOS configuration that somehow did not
        // encrypt would warn, rather than being trusted for being macOS.
        let plain_macos = Capabilities {
            encrypted_snapshots: false,
            ..Capabilities::measured_macos()
        };
        assert!(Confidentiality::of(plain_macos).needs_warning());
    }

    fn shape() -> DeviceShape {
        DeviceShape {
            memory_bytes: 2 * 1024 * 1024 * 1024,
            cpu_count: 4,
            block_devices: vec!["closure.img".to_owned(), "state.img".to_owned()],
            shares: vec!["workspace".to_owned()],
            console: ConsoleKind::File,
            balloon: true,
        }
    }

    fn metadata() -> Metadata {
        Metadata {
            guest_version: "26.11-3181085".to_owned(),
            host_os_version: "15.3.2".to_owned(),
            machine_id: "machine-a".to_owned(),
            devices: shape(),
            present_files: REQUIRED_FILES.iter().map(|f| (*f).to_owned()).collect(),
            grant_fingerprint: "tier=allowlist\nprofile=development\n".to_owned(),
        }
    }

    // ---- resume must not restore unreviewed permissions ------------------

    const FINGERPRINT: &str = "tier=allowlist\nprofile=development\n";

    #[test]
    fn an_unchanged_and_approved_grant_set_resumes_silently() {
        // The common case, and it must stay silent: a prompt on every resume
        // is the noise `00` §3.10c warns teaches people to bypass the gate.
        let snapshot = metadata();
        let verdict = snapshot.check_resume_approval(FINGERPRINT, true);
        assert_eq!(verdict, ResumeApproval::Unchanged);
        assert!(verdict.may_resume_silently());
    }

    #[test]
    fn a_changed_grant_set_needs_approval_and_names_both_sides() {
        // THE gap this closes. `lifecycle.rs` went Suspended -> Resuming ->
        // Running with no policy consulted, and `Metadata` recorded no grant
        // set — so `git pull`, `rachna resume`, and yesterday's permissions
        // were live again with no summary.
        let snapshot = metadata();
        let widened = "tier=open\nprofile=development\n";
        let verdict = snapshot.check_resume_approval(widened, true);
        assert!(!verdict.may_resume_silently());
        let ResumeApproval::NeedsApproval {
            taken_with,
            running,
        } = &verdict
        else {
            panic!("a changed grant set resumed unreviewed: {verdict:?}")
        };
        // BOTH sides, so a caller can render the diff rather than only
        // announce that something changed (`00` §3.3).
        assert_eq!(taken_with, FINGERPRINT);
        assert_eq!(running, widened);
    }

    #[test]
    fn an_unapproved_grant_set_cannot_be_laundered_through_a_snapshot() {
        // The subtle one, and the reason the check needs BOTH conditions.
        // Suspend while a grant set is still unapproved, then resume: the
        // fingerprints match, so a comparison alone would say "unchanged"
        // and wave through a policy no human ever reviewed.
        let snapshot = metadata();
        let verdict = snapshot.check_resume_approval(FINGERPRINT, false);
        assert!(
            !verdict.may_resume_silently(),
            "an unapproved policy was laundered through a suspend/resume cycle"
        );
    }

    #[test]
    fn a_snapshot_with_no_recorded_grant_set_asks_rather_than_assumes() {
        // A snapshot from a build before this field existed. "Not recorded"
        // must mean ASK, not match: the safe direction for an unknown grant
        // set is the summary, and the message differs from a changed-policy
        // one because there is no diff to show.
        let mut old = metadata();
        old.grant_fingerprint = String::new();
        let verdict = old.check_resume_approval(FINGERPRINT, true);
        assert_eq!(verdict, ResumeApproval::Unrecorded);
        assert!(!verdict.may_resume_silently());
    }

    #[test]
    fn a_changed_policy_is_not_reported_as_a_broken_snapshot() {
        // The distinction that keeps a user from deleting a perfectly good
        // snapshot. A changed grant set must leave `check_restorable`
        // untouched — the memory image is fine, the devices match, and only
        // the permissions need review.
        let mut snapshot = metadata();
        snapshot.grant_fingerprint = "tier=none\nprofile=sealed\n".to_owned();
        assert_eq!(
            snapshot.check_restorable(&metadata(), Capabilities::all()),
            Ok(()),
            "a policy change was reported as an incompatible snapshot"
        );
        // And the resume check still catches it, so this is a separation of
        // concerns rather than a hole.
        assert!(!snapshot
            .check_resume_approval(FINGERPRINT, true)
            .may_resume_silently());
    }

    #[test]
    fn narrowing_the_policy_also_asks() {
        // Deliberate, and a departure from `reload.rs`, which applies a
        // narrowing change immediately. The difference is what the user is
        // about to get: a *reload* under a tighter policy gives them less
        // than they had, which needs no review — but a *resume* hands back a
        // guest whose live processes were started under the WIDER set. Those
        // processes already hold whatever they opened. So the honest question
        // on resume is "do you want this guest back", not "is the new policy
        // narrower", and the answer is not derivable from the diff direction.
        let snapshot = metadata();
        let narrowed = "tier=none\nprofile=sealed\n";
        assert!(
            !snapshot
                .check_resume_approval(narrowed, true)
                .may_resume_silently(),
            "a resume under a different policy went unreviewed"
        );
    }

    // ---- the happy path --------------------------------------------------

    #[test]
    fn an_identical_environment_restores() {
        assert_eq!(
            metadata().check_restorable(&metadata(), Capabilities::all()),
            Ok(())
        );
    }

    // ---- each reason, and the order they are reported in ----------------

    #[test]
    fn a_different_machine_is_reported_first_because_it_cannot_be_fixed() {
        // Save files are encrypted with a host-tied key (02 §4), so this is
        // the one reason no action resolves. Reported before the others even
        // when several differ, because telling a user their guest changed
        // when the real problem is the machine sends them to do useless work.
        let taken = metadata();
        let running = Metadata {
            machine_id: "machine-b".to_owned(),
            guest_version: "27.05-999".to_owned(),
            host_os_version: "16.0".to_owned(),
            devices: DeviceShape {
                cpu_count: 8,
                ..shape()
            },
            ..metadata()
        };
        assert_eq!(
            taken.check_restorable(&running, Capabilities::all()),
            Err(Incompatible::DifferentMachine {
                taken_on: "machine-a".to_owned(),
                running: "machine-b".to_owned(),
            })
        );
    }

    #[test]
    fn a_guest_change_is_reported_before_a_host_os_change() {
        // Upgrading rachna bumps the guest (08 §4.1.1), so this is the
        // COMMON case and the one a user should hear about.
        let taken = metadata();
        let running = Metadata {
            guest_version: "27.05-999".to_owned(),
            host_os_version: "16.0".to_owned(),
            ..metadata()
        };
        assert!(matches!(
            taken.check_restorable(&running, Capabilities::all()),
            Err(Incompatible::GuestChanged { .. })
        ));
    }

    #[test]
    fn a_macos_update_is_named_as_the_reason() {
        // 02 §4: macOS documents that an update can invalidate saved state.
        // "your saved session was invalidated by a macOS update, booting
        // fresh" is merely annoying; a silent vanishing is a support
        // nightmare.
        let taken = metadata();
        let running = Metadata {
            host_os_version: "15.4".to_owned(),
            ..metadata()
        };
        let error = taken
            .check_restorable(&running, Capabilities::all())
            .expect_err("incompatible");
        assert_eq!(
            error,
            Incompatible::HostOsChanged {
                taken_on: "15.3.2".to_owned(),
                running: "15.4".to_owned(),
            }
        );
        let message = error.to_string();
        assert!(message.contains("macOS changed"), "{message}");
        assert!(message.contains("booting fresh"), "{message}");
    }

    #[test]
    fn no_snapshot_support_is_reported_before_anything_else() {
        // There is nothing to compare if the backend cannot restore at all.
        let taken = metadata();
        let running = Metadata {
            machine_id: "machine-b".to_owned(),
            ..metadata()
        };
        assert_eq!(
            taken.check_restorable(&running, Capabilities::none()),
            Err(Incompatible::NoSnapshotSupport)
        );
    }

    // ---- the incomplete-snapshot case (24 §6) ---------------------------

    #[test]
    fn an_incomplete_snapshot_is_refused_before_any_compatibility_check() {
        // THE measured silent failure: a CH snapshot is three files, and
        // `ch-remote snapshot` returns before state.json is flushed. Two of
        // three restores with NO error, NO log and NO process — which is the
        // opposite of 02 §4's requirement to fall back loudly.
        //
        // Checked FIRST, because telling a user their guest version changed
        // when the snapshot was never finished writing sends them to the
        // wrong fix.
        let taken = Metadata {
            present_files: vec!["config.json".to_owned(), "memory-ranges".to_owned()],
            guest_version: "a-different-guest".to_owned(),
            ..metadata()
        };
        assert_eq!(
            taken.check_restorable(&metadata(), Capabilities::all()),
            Err(Incompatible::Incomplete {
                missing: vec!["state.json".to_owned()]
            })
        );
    }

    #[test]
    fn every_required_file_is_detected_when_missing() {
        for omitted in REQUIRED_FILES {
            let present: Vec<String> = REQUIRED_FILES
                .iter()
                .filter(|f| **f != omitted)
                .map(|f| (*f).to_owned())
                .collect();
            assert_eq!(
                missing_files(present.iter().map(String::as_str)),
                vec![omitted.to_owned()],
                "{omitted} went undetected"
            );
        }
    }

    #[test]
    fn a_complete_snapshot_reports_nothing_missing() {
        assert!(missing_files(REQUIRED_FILES).is_empty());
    }

    #[test]
    fn an_unchecked_snapshot_is_not_reported_as_broken() {
        // Empty means "not inspected", not "nothing found" — a caller that
        // does not read the directory must not be told its snapshot is
        // incomplete.
        let unchecked = Metadata {
            present_files: vec![],
            ..metadata()
        };
        assert_eq!(
            unchecked.check_restorable(&metadata(), Capabilities::all()),
            Ok(())
        );
    }

    #[test]
    fn the_incomplete_message_names_what_is_missing_and_what_happens_next() {
        let message = Incompatible::Incomplete {
            missing: vec!["state.json".to_owned()],
        }
        .to_string();
        assert!(message.contains("state.json"), "{message}");
        assert!(message.contains("never finished writing"), "{message}");
        assert!(message.contains("booting fresh"), "{message}");
    }

    // ---- the VZErrorRestore case ----------------------------------------

    #[test]
    fn every_device_field_change_is_detected_and_named() {
        // 02 §4's hard lesson: an EQUIVALENT config fails where an IDENTICAL
        // one works, and the failure is `VZErrorRestore` / "invalid
        // argument" — which tells a user nothing. So each field is compared
        // and the difference is named.
        let base = shape();
        let variants: Vec<(&str, DeviceShape)> = vec![
            (
                "memory",
                DeviceShape {
                    memory_bytes: 4 << 30,
                    ..base.clone()
                },
            ),
            (
                "cpus",
                DeviceShape {
                    cpu_count: 8,
                    ..base.clone()
                },
            ),
            (
                "disks",
                DeviceShape {
                    block_devices: vec!["closure.img".to_owned()],
                    ..base.clone()
                },
            ),
            (
                "shares",
                DeviceShape {
                    shares: vec!["workspace".to_owned(), "extra".to_owned()],
                    ..base.clone()
                },
            ),
            (
                "console",
                DeviceShape {
                    console: ConsoleKind::Pipe,
                    ..base.clone()
                },
            ),
            (
                "balloon",
                DeviceShape {
                    balloon: false,
                    ..base.clone()
                },
            ),
        ];
        for (field, changed) in variants {
            let detail = base
                .first_difference(&changed)
                .unwrap_or_else(|| panic!("{field} change went undetected"));
            assert!(
                detail.contains(field),
                "the {field} change was detected but reported as {detail:?}"
            );
        }
    }

    #[test]
    fn reordering_two_disks_is_a_different_machine() {
        // VZ attaches by INDEX, so swapping two disks is a different machine
        // even with identical contents — and a restore into it would hand
        // the guest its state disk as its closure.
        let base = shape();
        let swapped = DeviceShape {
            block_devices: vec!["state.img".to_owned(), "closure.img".to_owned()],
            ..base.clone()
        };
        assert!(base.first_difference(&swapped).is_some());
    }

    #[test]
    fn an_identical_shape_reports_no_difference() {
        assert_eq!(shape().first_difference(&shape()), None);
    }

    // ---- the console, which is what actually broke ----------------------

    #[test]
    fn a_pipe_console_does_not_survive_recreation() {
        // THE measured failure (02 §4): restore worked only when the SAME
        // config object was reused, and a fresh pipe broke it. A file-backed
        // attachment is reconstructible because its identity is a path rather
        // than a live descriptor.
        assert!(!ConsoleKind::Pipe.survives_recreation());
        assert!(!ConsoleKind::Pty.survives_recreation());
        assert!(ConsoleKind::File.survives_recreation());
        assert!(ConsoleKind::None.survives_recreation());
    }

    #[test]
    fn every_console_kind_has_a_distinct_name() {
        let mut names: Vec<&str> = ConsoleKind::ALL.iter().map(|k| k.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
        for kind in ConsoleKind::ALL {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    // ---- every message is actionable -------------------------------------

    #[test]
    fn every_reason_says_what_happens_next() {
        // 02 §4 requires a failed restore to fall back LOUDLY. Every message
        // therefore ends with what Rachna is about to do, so the user is not
        // left wondering whether their work is gone.
        let every = [
            Incompatible::GuestChanged {
                taken_with: "a".to_owned(),
                running: "b".to_owned(),
            },
            Incompatible::HostOsChanged {
                taken_on: "15.3".to_owned(),
                running: "15.4".to_owned(),
            },
            Incompatible::DifferentMachine {
                taken_on: "a".to_owned(),
                running: "b".to_owned(),
            },
            Incompatible::DeviceConfigChanged {
                detail: "cpus 4 → 8".to_owned(),
            },
            Incompatible::NoSnapshotSupport,
        ];
        for reason in every {
            let message = reason.to_string();
            assert!(
                message.contains("booting fresh") || message.contains("cannot restore"),
                "{reason:?} does not say what happens next: {message}"
            );
            assert!(message.len() > 30, "{reason:?} is too terse: {message}");
        }
    }

    #[test]
    fn a_machine_mismatch_explains_why_it_can_never_work() {
        // Without the encryption detail a user will try copying the file
        // again, or assume Rachna is broken.
        let message = Incompatible::DifferentMachine {
            taken_on: "laptop".to_owned(),
            running: "desktop".to_owned(),
        }
        .to_string();
        assert!(message.contains("encrypted"), "{message}");
        assert!(message.contains("key"), "{message}");
    }
}
