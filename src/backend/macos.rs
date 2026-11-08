//! The macOS backend: Virtualization.framework.
//!
//! Measured in `02-SPIKE-MACOS-VZ.md`. Every constraint below is from that
//! spike rather than from Apple's prose, because several were found only by
//! probing:
//!
//! | Constraint | Where |
//! |---|---|
//! | the entitlement is mandatory, and its absence **throws** | §4 |
//! | the VM must be `Paused` before saving; restore lands `Paused` | §4 |
//! | `validateSaveRestoreSupport` is a **separate** gate | §4 |
//! | a macOS update can invalidate saved state | §4 |
//! | the config must be *identical*, not equivalent | §4 |
//! | snapshots are encrypted with a host-tied key | §4, `12` §1 |
//! | **no per-VM CPU or I/O throttles exist** | `12` §4 |
//! | ballooning **is** available, as `…TraditionalMemoryBalloon…` | `12` §2 |
//!
//! # What this module is, and is not
//!
//! It is the translation layer: our `Action` to VZ's API, and VZ's state back
//! to ours. It deliberately holds **no policy** — the lifecycle machine
//! decides legality first (`backend.rs`), so this cannot invent a transition
//! the machine forbids.
//!
//! # Why the throttle capabilities are constants
//!
//! `12` §4 measured that macOS has no per-VM CPU or I/O throttle at all. That
//! is a property of the platform rather than of a configuration, so reporting
//! it as anything else would be the silent downgrade `01` §2.6 forbids: *a
//! backend reporting a capability it does not have is worse than one
//! admitting the gap.*

use crate::backend::Capabilities;

/// What the macOS backend can do, as measured.
///
/// `save_restore_supported` is a parameter rather than a constant because
/// `02` §4 makes `validateSaveRestoreSupport` a **separate gate** that not
/// every device configuration passes — so the caller must have asked VZ
/// rather than assumed.
#[must_use]
pub const fn measured_capabilities(save_restore_supported: bool) -> Capabilities {
    Capabilities {
        memory_snapshot: save_restore_supported,
        // §4 and `12` §1: encrypted with a host-tied key, verified three
        // ways. Also why snapshots are not portable between machines.
        encrypted_snapshots: true,
        // `12` §4: the API is absent, not restricted — there is nothing to
        // probe and nothing we could lift.
        cpu_quota: false,
        io_quota: false,
    }
}

/// Why the macOS backend could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacosError {
    /// The binary lacks `com.apple.security.virtualization`.
    ///
    /// Its own variant because the failure mode is a **crash**, not an error
    /// return (`02` §4): `VZVirtualMachine.init` throws
    /// `NSInvalidArgumentException`. So this must be checked *before* a VM is
    /// constructed, and `02` §4b records that a signature does not survive a
    /// rebuild — making it a live runtime check rather than a build-time
    /// guarantee.
    MissingEntitlement,
    /// The configuration cannot be saved and restored.
    SaveRestoreUnsupported { reason: String },
    /// VZ rejected the configuration.
    InvalidConfiguration { reason: String },
}

impl core::fmt::Display for MacosError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingEntitlement => f.write_str(
                "this rachna binary is not signed with \
                 com.apple.security.virtualization, so starting a VM would \
                 crash rather than fail. Run ci/sign-macos.sh — and note that \
                 any rebuild discards the signature (02 §4b)",
            ),
            Self::SaveRestoreUnsupported { reason } => write!(
                f,
                "this configuration cannot be suspended to disk: {reason}. \
                 The environment will still start, stop, pause and resume"
            ),
            Self::InvalidConfiguration { reason } => write!(
                f,
                "Virtualization.framework rejected the configuration: {reason}"
            ),
        }
    }
}

impl core::error::Error for MacosError {}

/// Whether `binary` carries the virtualization entitlement.
///
/// `02` §4 makes this load-bearing: without the entitlement
/// `VZVirtualMachine.init` **throws** `NSInvalidArgumentException`, which in
/// Rust terms is an abort we cannot catch. So it is checked *before* any VM
/// is constructed.
///
/// `02` §4b is why the check is at runtime rather than trusted from the
/// build: `cargo build` relinks and discards the signature, so a developer
/// running a freshly-built binary genuinely has an unsigned one.
///
/// # Why this takes a path
///
/// An earlier `has_entitlement()` read `current_exe()` and had no caller. Its
/// mutants were unkillable — the test binary's signature depends on whether
/// anything rebuilt it since signing, so no assertion could distinguish the
/// real function from a constant. Taking the path makes both outcomes
/// testable against binaries whose signature is *known*, and the caller
/// decides which binary it means. Same conclusion as the `guest_release`
/// wrapper deleted earlier: code no test can distinguish from a constant
/// deserves the question of why it exists.
#[cfg(target_os = "macos")]
#[must_use]
pub fn binary_has_entitlement(binary: &std::path::Path) -> bool {
    let Ok(output) = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(binary)
        .output()
    else {
        return false;
    };
    // `codesign` writes the plist to stdout on some versions and stderr on
    // others, and exits 0 either way — so both are searched rather than one
    // trusted. Same "verify, do not assume" rule as ci/sign-macos.sh.
    let combined = [output.stdout, output.stderr].concat();
    String::from_utf8_lossy(&combined).contains("com.apple.security.virtualization")
}

/// Whether `binary` carries the virtualization entitlement.
///
/// Always `false` off macOS: there is no such entitlement, and claiming one
/// would let a Linux caller believe a VZ precondition was met.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub const fn binary_has_entitlement(_binary: &std::path::Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capability_set_matches_what_the_spikes_measured() {
        // Pinned, because these encode measurements rather than preferences.
        let with_snapshots = measured_capabilities(true);
        assert!(with_snapshots.memory_snapshot, "02 §1");
        assert!(with_snapshots.encrypted_snapshots, "12 §1, three ways");
        assert!(
            !with_snapshots.cpu_quota,
            "12 §4: no per-VM throttles exist"
        );
        assert!(!with_snapshots.io_quota, "12 §4");
    }

    #[test]
    fn save_restore_is_reported_per_configuration_not_per_platform() {
        // 02 §4: validateSaveRestoreSupport is a SEPARATE gate, and not every
        // device configuration passes. A constant `true` would mean
        // discovering the gap at the first `suspend` — the silent-downgrade
        // shape 01 §2.6 forbids.
        assert!(measured_capabilities(true).memory_snapshot);
        assert!(!measured_capabilities(false).memory_snapshot);
        // The rest is unaffected: an unsavable config still encrypts, and
        // still has no throttles.
        assert!(measured_capabilities(false).encrypted_snapshots);
        assert!(!measured_capabilities(false).cpu_quota);
    }

    #[test]
    fn the_entitlement_error_names_the_fix_and_the_trap() {
        // 02 §4b: a signature does not survive a rebuild, so a user who
        // signed once and then ran `cargo build` is unsigned again. The
        // message has to say that, or they report it as a bug.
        let message = MacosError::MissingEntitlement.to_string();
        assert!(message.contains("ci/sign-macos.sh"), "{message}");
        assert!(message.contains("rebuild discards"), "{message}");
        assert!(message.contains("crash"), "{message}");
    }

    #[test]
    fn an_unsavable_configuration_still_says_what_works() {
        // Suspend being unavailable does not make the environment useless,
        // and saying so stops a user assuming the backend is broken.
        let message = MacosError::SaveRestoreUnsupported {
            reason: "a device does not support it".to_owned(),
        }
        .to_string();
        assert!(message.contains("will still start"), "{message}");
    }

    #[test]
    fn every_error_explains_itself_at_length() {
        for error in [
            MacosError::MissingEntitlement,
            MacosError::SaveRestoreUnsupported {
                reason: "x".to_owned(),
            },
            MacosError::InvalidConfiguration {
                reason: "y".to_owned(),
            },
        ] {
            assert!(error.to_string().len() > 40, "{error:?} is too terse");
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn off_macos_nothing_is_ever_entitled() {
        // Runs only on Linux, which is where the stub this asserts actually
        // compiles. Claiming an entitlement off macOS would let a caller
        // believe a VZ precondition was met on a platform with no VZ.
        //
        // `cargo-mutants` on macOS reports this stub as a surviving mutant,
        // because it mutates source that is not compiled for the host — so
        // the mutant is killed by the Linux CI job rather than locally. The
        // platform matrix (01 §4.2) exists for exactly this.
        assert!(!binary_has_entitlement(std::path::Path::new(
            "/usr/bin/true"
        )));
        assert!(!binary_has_entitlement(std::path::Path::new(
            "/nonexistent"
        )));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_check_distinguishes_a_signed_binary_from_an_unsigned_one() {
        // BOTH outcomes, against binaries whose signature is known — because
        // 02 §4 makes a false positive here a crash rather than an error, and
        // a false negative a refusal to start a working environment.
        //
        // Mutation testing forced this shape: an earlier test compared our
        // answer to codesign's, which agreed with a constant-returning mutant
        // whenever the real answer matched that constant.
        let dir = std::env::temp_dir().join("rachna-entitlement-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        // Any Mach-O will do; `true` is tiny and always present.
        let unsigned = dir.join("unsigned");
        std::fs::copy("/usr/bin/true", &unsigned).expect("copy");
        // Ad-hoc sign with NO entitlements, so it is validly signed and
        // still lacks the one that matters — the realistic failure, since a
        // plain `cargo build` produces exactly this.
        std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&unsigned)
            .output()
            .expect("codesign runs");
        assert!(
            !binary_has_entitlement(&unsigned),
            "an unsigned binary was reported as entitled — this would crash"
        );

        let signed = dir.join("signed");
        std::fs::copy("/usr/bin/true", &signed).expect("copy");
        std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg("build/vz.entitlements")
            .arg(&signed)
            .output()
            .expect("codesign runs");
        assert!(
            binary_has_entitlement(&signed),
            "a correctly signed binary was reported as unentitled"
        );

        // A path that is not a binary at all must be false, not a panic.
        assert!(!binary_has_entitlement(&dir.join("does-not-exist")));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
