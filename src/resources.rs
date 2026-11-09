//! What a project declares it may consume (`19` §2.1).
//!
//! ```nix
//! resources = { cpus = 4; memory = "2GB"; disk = "20GB"; processes = 512; };
//! ```
//!
//! # Why this is a policy type and not a tuning struct
//!
//! `15` §3.2 measured all four and found **two of three enforce**, which is
//! the whole reason this needs care:
//!
//! | Limit | Linux | macOS |
//! |---|---|---|
//! | memory | guest kernel OOM-kills at its limit; host cgroup backstops | **total host RAM — no limit at all** |
//! | host CPU quota | enforced: `nr_throttled 119`, 126 % against a 200 % quota | **no API exists** — advisory |
//! | disk I/O quota | throttles: 0 engagements unquoted, 50 and 18 quoted | absent |
//! | processes | **was not enforced**: 512 declared, `ulimit -u` 7754 | not measured |
//!
//! Two consequences this type encodes rather than leaves to a caller:
//!
//! - **vCPU count is not CPU share.** `15` §3.2: *"Four vCPUs on 16 cores
//!   could have taken 400 %; the cgroup held it near 200 %. So declaring
//!   `cpus = 4` must produce **both** a count and a host quota, or the limit
//!   is cosmetic."* So [`Resources::host_cpu_quota_percent`] exists and is
//!   derived, not optional.
//! - **A limit that cannot be enforced must say so.** macOS has no per-VM CPU
//!   or memory ceiling (`12` §4), and `01` §3b forbids a config that lies:
//!   *"a rule the backend cannot enforce must never behave like a rule that
//!   is simply missing."* [`Resources::advisory_on`] is that answer.
//!
//! # The parser rejected this entirely
//!
//! Before this module, `resources` was not in `config.rs`'s known keys — so
//! a `rachna.nix` copied from `19` §2.1 was **rejected** with `resources: no
//! such option`. Exactly the `kind = "command"` defect (`21` §2.5): a
//! documented option the code refuses.

use crate::backend::Capabilities;
use core::fmt;

/// What a project may consume.
///
/// Every field has a default, because `19` §4.5's property is that *"an empty
/// `rachna.nix` is valid"* — the Nix module supplies these before
/// `config.rs` ever sees the JSON, and the defaults here are what that module
/// declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    /// vCPUs the guest sees.
    pub cpus: u32,
    /// Guest memory, in mebibytes.
    ///
    /// Stored as a number rather than the `"2GB"` string a user writes,
    /// because `Launch` needs mebibytes and parsing twice is how two answers
    /// appear. [`parse_size`] does it once.
    pub memory_mib: u64,
    /// The state volume's size, in mebibytes.
    pub disk_mib: u64,
    /// The guest process ceiling (`15` §3.2, now enforced guest-side).
    pub processes: u32,
}

impl Default for Resources {
    /// `19` §2.1's declared defaults.
    ///
    /// Pinned to the document rather than chosen here: a default that drifts
    /// from the one `rachna.nix`'s module declares would make `config
    /// inspect` disagree with what actually runs.
    fn default() -> Self {
        Self {
            cpus: 4,
            memory_mib: 2048,
            disk_mib: 20 * 1024,
            processes: 512,
        }
    }
}

impl Resources {
    /// The host CPU quota, as a percentage, for a cgroup `CPUQuota`.
    ///
    /// **This is the point of the type.** `15` §3.2 measured that four vCPUs
    /// on sixteen cores could consume 400 % without a quota, and that the
    /// cgroup held it near 200 % with one. So a declared `cpus` must produce
    /// *both* numbers — and because one `cpus` value produces both, they
    /// cannot disagree.
    ///
    /// 100 % per vCPU: `cpus = 4` means "may use four cores' worth", which is
    /// what a user writing `4` means and what the vCPU count already
    /// promises. A quota below the vCPU count would make the guest see
    /// processors it cannot use, which is worse than either limit alone.
    #[must_use]
    pub const fn host_cpu_quota_percent(&self) -> u32 {
        self.cpus.saturating_mul(100)
    }

    /// Which declared limits this backend cannot enforce.
    ///
    /// `01` §3b: *"a rule the backend cannot enforce must never behave like a
    /// rule that is simply missing, or the config file lies."* So this is
    /// reported rather than silently dropped, and `status` says it.
    ///
    /// Derived from measured [`Capabilities`] rather than
    /// `cfg!(target_os = "macos")`, for the reason `snapshot::Confidentiality`
    /// is: if a backend gains the capability, the warning disappears by
    /// itself.
    #[must_use]
    pub fn advisory_on(capabilities: Capabilities) -> Vec<Advisory> {
        let mut out = Vec::new();
        if !capabilities.cpu_quota {
            out.push(Advisory::Cpu);
        }
        if !capabilities.io_quota {
            out.push(Advisory::DiskIo);
        }
        out
    }
}

/// A declared limit this host cannot actually enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advisory {
    /// `cpus` produces a vCPU count but no host quota.
    ///
    /// macOS: `12` §4 found **no per-VM CPU throttle in the API at all** —
    /// absent rather than restricted, so there is nothing to probe and
    /// nothing we could lift.
    Cpu,
    /// `disk` is a size, with no I/O throttle behind it.
    DiskIo,
}

impl Advisory {
    /// Every advisory, for exhaustive tests.
    pub const ALL: [Self; 2] = [Self::Cpu, Self::DiskIo];

    /// The option a user wrote.
    #[must_use]
    pub const fn option(self) -> &'static str {
        match self {
            Self::Cpu => "resources.cpus",
            Self::DiskIo => "resources.disk",
        }
    }

    /// What is and is not enforced, in one sentence.
    ///
    /// Names what *does* hold, because `12` §4's finding is a partial gap
    /// rather than a total one: the guest really does see four vCPUs, it just
    /// may use more of the host than that implies.
    #[must_use]
    pub const fn what_holds(self) -> &'static str {
        match self {
            Self::Cpu => {
                "the guest sees this many vCPUs, but this host has no per-VM \
                 CPU quota, so it may use more host CPU than that implies"
            }
            Self::DiskIo => {
                "the volume is this size, but this host cannot throttle disk \
                 I/O, so a busy guest can saturate the device"
            }
        }
    }
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is advisory: {}", self.option(), self.what_holds())
    }
}

/// Why a size could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeError {
    /// No digits at the start.
    NotANumber { given: String },
    /// A suffix we do not know.
    UnknownUnit { given: String, unit: String },
    /// Zero, which is not a size.
    ///
    /// Its own variant because `memory = "0GB"` parses as a number and would
    /// otherwise produce a VM with no memory — a configuration that fails at
    /// boot with a message about neither memory nor Rachna.
    Zero { given: String },
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotANumber { given } => write!(
                f,
                "{given:?} is not a size. Write a number and a unit, as in \"2GB\""
            ),
            Self::UnknownUnit { given, unit } => write!(
                f,
                "{given:?} has an unknown unit {unit:?}. Use MB, MiB, GB or GiB"
            ),
            Self::Zero { given } => write!(
                f,
                "{given:?} is zero. A guest with no memory or no disk cannot \
                 start, and the failure would name neither"
            ),
        }
    }
}

impl core::error::Error for SizeError {}

/// Reads `"2GB"` into mebibytes.
///
/// # Why `GB` means 1024 MiB here
///
/// A developer writing `memory = "2GB"` means two gibibytes — it is what
/// every hypervisor, `free -h` and task manager shows them. Treating it as
/// 2000 MB would give a guest 1.86 GiB and make a 2 GiB snapshot measurement
/// not reproduce. So `GB` and `GiB` are both 1024 MiB, deliberately, and the
/// decimal reading is not offered rather than being offered and wrong.
///
/// # Errors
///
/// [`SizeError`] naming what was wrong and the shape that works.
pub fn parse_size(text: &str) -> Result<u64, SizeError> {
    let trimmed = text.trim();
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (number, unit) = trimmed.split_at(digits_end);
    if number.is_empty() {
        return Err(SizeError::NotANumber {
            given: text.to_owned(),
        });
    }
    let value: u64 = number.parse().map_err(|_| SizeError::NotANumber {
        given: text.to_owned(),
    })?;

    let unit = unit.trim();
    let mib = match unit.to_ascii_uppercase().as_str() {
        // No unit means mebibytes, matching Cloud Hypervisor's own
        // `--memory size=2048M`.
        "" | "M" | "MB" | "MIB" => value,
        "G" | "GB" | "GIB" => value.saturating_mul(1024),
        _ => {
            return Err(SizeError::UnknownUnit {
                given: text.to_owned(),
                unit: unit.to_owned(),
            })
        }
    };
    if mib == 0 {
        return Err(SizeError::Zero {
            given: text.to_owned(),
        });
    }
    Ok(mib)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the defaults 19 §2.1 declares -----------------------------------

    #[test]
    fn the_defaults_match_what_19_section_2_1_documents() {
        // Pinned to the document, not chosen here. A default that drifts
        // from the Nix module's would make `config inspect` disagree with
        // what runs — the shape `21` §2.5 caught in the CLI row.
        //
        // `19` §2.1: resources = { cpus = 4; memory = "2GB";
        //                          disk = "20GB"; processes = 512; };
        let defaults = Resources::default();
        assert_eq!(defaults.cpus, 4);
        assert_eq!(defaults.memory_mib, parse_size("2GB").expect("valid"));
        assert_eq!(defaults.disk_mib, parse_size("20GB").expect("valid"));
        assert_eq!(defaults.processes, 512);
    }

    #[test]
    fn the_default_process_limit_is_the_one_the_guest_enforces() {
        // `24` §7 measured the guest enforcing 512 across the rlimit, the
        // cgroup `pids.max` and the unit `TasksMax`. If this default and
        // that number disagreed, the declared limit would be a lie again —
        // which is the defect `15` §3.2 found in the first place.
        assert_eq!(Resources::default().processes, 512);
    }

    // ---- the point of the type: cpus produces TWO numbers -----------------

    #[test]
    fn a_declared_cpu_count_produces_a_host_quota_too() {
        // `15` §3.2: "Four vCPUs on 16 cores could have taken 400 %; the
        // cgroup held it near 200 %. So declaring cpus = 4 must produce BOTH
        // a count and a host quota, or the limit is cosmetic."
        //
        // One `cpus` value produces both, so they cannot disagree.
        for cpus in [1_u32, 2, 4, 8, 16] {
            let resources = Resources {
                cpus,
                ..Resources::default()
            };
            assert_eq!(
                resources.host_cpu_quota_percent(),
                cpus * 100,
                "the quota does not match the vCPU count"
            );
        }
    }

    #[test]
    fn the_quota_is_never_below_the_vcpu_count() {
        // A quota below the count makes the guest see processors it cannot
        // use, which is worse than either limit alone: the scheduler
        // oversubscribes and everything is slow for no stated reason.
        for cpus in [1_u32, 3, 7, 64] {
            let resources = Resources {
                cpus,
                ..Resources::default()
            };
            assert!(
                resources.host_cpu_quota_percent() >= cpus * 100,
                "{cpus} vCPUs got a quota of {} %",
                resources.host_cpu_quota_percent()
            );
        }
    }

    // ---- a limit that cannot be enforced must say so ----------------------

    #[test]
    fn macos_reports_cpu_and_io_as_advisory() {
        // `12` §4: no per-VM CPU or I/O throttle exists in the API at all —
        // absent rather than restricted. `01` §3b forbids treating that as
        // though the rule were simply missing.
        let advisories = Resources::advisory_on(Capabilities::measured_macos());
        assert_eq!(advisories, [Advisory::Cpu, Advisory::DiskIo]);
    }

    #[test]
    fn linux_reports_nothing_advisory() {
        // `15` §3.2 measured both enforcing on Linux: nr_throttled 119 for
        // CPU, and 50/18 throttle engagements for I/O against 0 unquoted. A
        // warning here would be the false positive that teaches users to
        // ignore the real one.
        assert!(
            Resources::advisory_on(Capabilities::measured_linux()).is_empty(),
            "Linux reported an advisory limit it actually enforces"
        );
    }

    #[test]
    fn the_advisory_follows_the_capability_not_the_platform() {
        // Derived from measured capabilities, so a backend that gains the
        // throttle stops warning by itself — the reason
        // `snapshot::Confidentiality` works the same way. Proven by flipping
        // one field.
        let gains_cpu = Capabilities {
            cpu_quota: true,
            ..Capabilities::measured_macos()
        };
        assert_eq!(Resources::advisory_on(gains_cpu), [Advisory::DiskIo]);
    }

    #[test]
    fn an_advisory_names_the_option_and_what_still_holds() {
        // `12` §4's gap is partial, not total: the guest really does see
        // four vCPUs. A message saying only "not enforced" would overstate
        // it, and one saying nothing would understate it.
        for advisory in Advisory::ALL {
            let text = advisory.to_string();
            assert!(text.contains("resources."), "{text}");
            assert!(text.contains("advisory"), "{text}");
            assert!(text.len() > 60, "too terse to act on: {text}");
        }
        let cpu = Advisory::Cpu.to_string();
        assert!(cpu.contains("sees this many vCPUs"), "{cpu}");
        assert!(cpu.contains("more host CPU"), "{cpu}");
    }

    // ---- sizes -----------------------------------------------------------

    #[test]
    fn a_size_reads_as_the_unit_a_developer_means() {
        // `GB` is 1024 MiB deliberately. A developer writing "2GB" means two
        // gibibytes — it is what every hypervisor and `free -h` shows them.
        // The decimal reading would give 1.86 GiB and make `24` §3's 2 GiB
        // snapshot measurement not reproduce.
        assert_eq!(parse_size("2GB").expect("valid"), 2048);
        assert_eq!(parse_size("2GiB").expect("valid"), 2048);
        assert_eq!(parse_size("20GB").expect("valid"), 20480);
        // Mebibytes, including the bare number CH's own `size=2048M` uses.
        assert_eq!(parse_size("512MB").expect("valid"), 512);
        assert_eq!(parse_size("512MiB").expect("valid"), 512);
        assert_eq!(parse_size("2048").expect("valid"), 2048);
        // Case and spacing are a user's business, not a parse error.
        assert_eq!(parse_size("2gb").expect("valid"), 2048);
        assert_eq!(parse_size(" 2 GB ").expect("valid"), 2048);
    }

    #[test]
    fn zero_is_refused_because_the_real_failure_would_name_neither() {
        // "0GB" parses as a number and would produce a VM with no memory,
        // failing at boot with a message about neither memory nor Rachna.
        for zero in ["0", "0GB", "0MiB"] {
            let error = parse_size(zero).expect_err("zero is not a size");
            assert_eq!(
                error,
                SizeError::Zero {
                    given: zero.to_owned()
                }
            );
            assert!(error.to_string().contains("cannot"), "{error}");
        }
    }

    #[test]
    fn a_bad_size_says_what_shape_works() {
        // `00` §3.3's rule: a message that only rejects sends the user to a
        // search engine.
        let not_a_number = parse_size("lots").expect_err("not a size");
        assert!(
            not_a_number.to_string().contains("\"2GB\""),
            "{not_a_number}"
        );

        let bad_unit = parse_size("2TB").expect_err("unknown unit");
        assert_eq!(
            bad_unit,
            SizeError::UnknownUnit {
                given: "2TB".to_owned(),
                unit: "TB".to_owned()
            }
        );
        // Names the units that work, so the fix is in the message.
        let text = bad_unit.to_string();
        for unit in ["MB", "MiB", "GB", "GiB"] {
            assert!(text.contains(unit), "the error omits {unit}: {text}");
        }
    }

    #[test]
    fn a_huge_size_saturates_rather_than_wrapping() {
        // `u64::MAX` gibibytes would wrap to a small number and silently
        // give a guest less memory than a user asked for — the direction
        // that produces a confusing OOM rather than a refusal.
        let huge = format!("{}GB", u64::MAX);
        assert_eq!(parse_size(&huge).expect("saturates"), u64::MAX);
    }
}
