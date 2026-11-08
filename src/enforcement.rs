//! Verifying enforcement rather than trusting it (`00` §3.7).
//!
//! `01` §2.6 establishes that [`Capabilities`](crate::backend::Capabilities)
//! describe a backend *as configured* rather than a platform. `00` §3.7 says
//! why that is necessary but insufficient:
//!
//! > That records what a backend **claims**. Nothing verified the claim at
//! > runtime. So on `rachna doctor` **and on every `rachna start`**, Rachna
//! > attempts the bypass and requires it to fail.
//!
//! This module is that attempt, and its result is what decides
//! [`State::Running`](crate::lifecycle::State::Running) versus
//! [`State::Unenforced`](crate::lifecycle::State::Unenforced).
//!
//! # Why a verdict type and not a bool
//!
//! The same reason [`Decision`](crate::decision::Decision) is an event: a
//! bool says *whether* enforcement held and nothing about which check failed,
//! so `rachna status` could only say "unenforced" and leave the user to
//! guess. Each check names itself, its result, and what a user can do.
//!
//! # The direction of the check is the whole design
//!
//! Every check here is phrased so that **a working boundary makes it fail**.
//! A check that confirms something *succeeds* passes when the mechanism is
//! missing: that is exactly how `15` §3.2's process limit went unnoticed
//! (512 declared, 7754 actual, nothing complaining) and how the first version
//! of the guest's own pids probe reported success with every limit removed.
//! So the probes attempt the bypass, and an attempt that *works* is the
//! failure.
//!
//! `00` §3.7: *"The check is adversarial by construction, which is the only
//! kind worth running."*

use crate::lifecycle::Action;
use core::fmt;

/// One thing `00` §3.7 requires Rachna to attempt and find blocked.
///
/// An enum rather than free-form strings because `rachna status` must be able
/// to say *which* boundary is unverified, and because adding a boundary
/// should be a compile error in [`Self::ALL`] rather than a silently
/// unchecked claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    /// The guest process is still confined the way Rachna started it.
    ///
    /// `00` §3.7's first bullet. Checked because a sandbox that was applied
    /// at launch and then dropped — a backend restarted by hand, a
    /// `systemd-run` scope that exited, a Landlock ruleset not actually
    /// loaded — leaves a VM that looks identical and is not confined.
    GuestConfinement,
    /// A direct connection from the guest to the internet actually fails.
    ///
    /// `00` §3.7's second bullet, and the one users care about most, since
    /// `00` §3.9 makes network deny-by-default the headline property.
    NetworkEgress,
    /// The declared process limit is the enforced one.
    ///
    /// Added from measurement rather than from `00` §3.7's list: `15` §3.2
    /// found `resources.processes = 512` enforcing nothing, with `ulimit -u`
    /// at 7754. A limit that is declared and not applied is the same class of
    /// defect as a boundary that is claimed and not present, so it belongs in
    /// the same check.
    ProcessLimit,
    /// `rachna.nix` is not reachable from inside the guest.
    ///
    /// `00` §3.11 excludes it from the workspace mount so project code cannot
    /// edit its own policy. `13` §2 and `15` §3.4 measured two ways a
    /// name-based exclusion can be defeated (hardlink, case variant), which
    /// is why this is verified at runtime rather than trusted from the mount
    /// arguments.
    PolicyFileUnreachable,
}

impl Check {
    /// Every check, for exhaustive tests and for `doctor` to run all of them.
    pub const ALL: [Self; 4] = [
        Self::GuestConfinement,
        Self::NetworkEgress,
        Self::ProcessLimit,
        Self::PolicyFileUnreachable,
    ];

    /// A short stable name, for `status` output and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestConfinement => "guest-confinement",
            Self::NetworkEgress => "network-egress",
            Self::ProcessLimit => "process-limit",
            Self::PolicyFileUnreachable => "policy-file-unreachable",
        }
    }

    /// What this check attempts, phrased as the bypass it tries.
    ///
    /// Short enough for one terminal line in a `status` block. A user reading
    /// "tried to reach an address no policy allows" can tell what was
    /// actually tested, where "network check" tells them nothing and cannot
    /// be audited.
    ///
    /// Measured rather than guessed: the first version of these ran to ~115
    /// characters and wrapped in the middle of a sentence, which a test
    /// asserting only `contains("require")` happily passed. Printing the
    /// block is what found it.
    #[must_use]
    pub const fn attempts(self) -> &'static str {
        match self {
            Self::GuestConfinement => "read the hypervisor's own confinement",
            Self::NetworkEgress => "connect to an address no policy allows",
            Self::ProcessLimit => "fork past the declared process limit",
            Self::PolicyFileUnreachable => "open rachna.nix from inside the guest",
        }
    }
}

/// How a [`Check`] is carried out in the guest.
///
/// A command plus the rule for reading its result, kept together because
/// separating them is how a probe ends up inverted. `15` §3.2's process limit
/// and this module's own first pids probe both reported success while the
/// mechanism was absent, and in each case the command was right and the
/// *interpretation* was wrong.
///
/// # Why the expectation is a type and not a comment
///
/// Every probe here expects its command to **fail**. Writing that as
/// [`Expect::NonZeroExit`] rather than as `// should fail` means
/// [`Probe::read`] cannot be written the other way round by accident, and a
/// test can assert the direction for every check at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The check this carries out.
    pub check: Check,
    /// Where this check is carried out, and how to read the answer.
    pub how: How,
}

/// Where a check runs.
///
/// Not every boundary can be probed from the guest, and pretending otherwise
/// is what produced the first draft of this type: `GuestConfinement` had an
/// empty command string and an expectation that meant nothing, which is the
/// "declared and does nothing" shape this project has now found five times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// Run a command in the guest; the boundary held if it exits non-zero.
    ///
    /// A shell line rather than an argv, because that is what
    /// [`Kind::Exec`](crate::protocol::Kind::Exec) carries and because these
    /// need a redirection to be meaningful.
    GuestCommandMustFail { command: &'static str },
    /// Run a command in the guest and compare its output to a number the
    /// host knows.
    ///
    /// Exists for the process limit, because `15` §3.2's lesson is that
    /// "some limit exists" is not the question: the guest-side probe measured
    /// a kernel ceiling of 2325 and reported success with every Rachna limit
    /// removed. So the host holds the declared figure and compares.
    GuestOutputMustEqual {
        command: &'static str,
        /// The declared value, as the guest would print it.
        expected: u32,
    },
    /// Answered by the host about itself, with no guest involvement.
    ///
    /// `GuestConfinement` asks whether the *hypervisor process* is still
    /// confined as Rachna started it. A guest cannot answer that about its
    /// own host, and a guest-side probe that appeared to would be worse than
    /// none — so this names the gap instead of faking a command.
    HostSideOnly,
}

impl Probe {
    /// Every probe, one per [`Check`].
    ///
    /// The commands are deliberately boring: `coreutils` and a shell builtin,
    /// nothing that needs a package in the guest. A probe that cannot run
    /// yields [`Outcome::Inconclusive`], which blocks enforcement — so a
    /// missing tool would make every environment unenforced.
    #[must_use]
    pub fn all(declared_processes: u32) -> Vec<Self> {
        vec![
            Self {
                check: Check::GuestConfinement,
                how: How::HostSideOnly,
            },
            Self {
                check: Check::NetworkEgress,
                how: How::GuestCommandMustFail {
                    // A literal address, so DNS is not in the path: a probe
                    // that failed because resolution failed would report the
                    // network boundary as holding when it was never tested —
                    // the false-negative shape of `11` §7. 1.1.1.1:443 is
                    // reachable from any unfiltered network, which is exactly
                    // the property being denied.
                    //
                    // `timeout` because a DROP rule makes a connect hang
                    // rather than refuse, and a probe that blocks forever is
                    // an inconclusive result dressed as a pending one.
                    //
                    // `bash` explicitly, NOT `sh`: `/dev/tcp` is a bash
                    // feature. Measured that the guest's `/bin/sh` currently
                    // IS bash (`environment.binsh` resolves to
                    // bash-interactive), so `sh` would work today — and that
                    // is precisely the problem. A guest config change would
                    // make the probe error out, which reports `Inconclusive`
                    // and blocks every start, for a reason no message would
                    // name. Depending on the shell by name makes the
                    // requirement visible.
                    command: "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'",
                },
            },
            Self {
                check: Check::ProcessLimit,
                // Reports the limit rather than attempting a fork bomb. The
                // guest-side spike showed why: forking past the limit kills
                // the reporter, and the one run that survived did so at the
                // KERNEL's ceiling of 2325 rather than ours.
                how: How::GuestOutputMustEqual {
                    command: "ulimit -u",
                    expected: declared_processes,
                },
            },
            Self {
                check: Check::PolicyFileUnreachable,
                how: How::GuestCommandMustFail {
                    // `00` §3.11 excludes rachna.nix from the workspace
                    // mount. `13` §2 and `15` §3.4 measured a hardlink and a
                    // case variant defeating a name-based check, so a passing
                    // probe here is necessary and NOT sufficient — the inode
                    // check in `exclusion.rs` is the real defence. Recorded
                    // so this is not mistaken for the whole of it.
                    command: "cat /workspace/rachna.nix",
                },
            },
        ]
    }
}

/// What happened when a [`Check`] was attempted.
///
/// Three outcomes, not two. `Inconclusive` exists because this project has
/// already been burned by treating "found nothing" as "nothing is there":
/// `11` §7 and `13` §2 record three false-negative measurements, and `24`
/// §5's guest-memory search is still marked inconclusive because the marker
/// turned out to live in a virtiofs share rather than in guest RAM.
///
/// Collapsing `Inconclusive` into `Held` would be the dangerous direction —
/// a probe that could not run would report a boundary as verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The bypass was attempted and **failed**. The boundary holds.
    Held,
    /// The bypass was attempted and **succeeded**. The boundary is absent.
    ///
    /// Carries what was observed, because `00` §3.3's rules apply here too:
    /// a user told "network enforcement failed" cannot act, where one told
    /// "reached 1.1.1.1:443 from the guest in 12 ms" can.
    Bypassed { observed: String },
    /// The check could not be run, so nothing was learned.
    ///
    /// Treated as a failure to verify, never as a pass — see the type's own
    /// documentation.
    Inconclusive { why: String },
}

impl Outcome {
    /// Whether this outcome proves the boundary holds.
    ///
    /// Only [`Self::Held`] does. Written as an explicit match rather than
    /// `!matches!(self, Bypassed)` so that adding an outcome is a compile
    /// error here instead of silently counting as verified.
    #[must_use]
    pub const fn verified(&self) -> bool {
        match *self {
            Self::Held => true,
            Self::Bypassed { .. } | Self::Inconclusive { .. } => false,
        }
    }
}

/// One check and what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The check that was run.
    pub check: Check,
    /// What it found.
    pub outcome: Outcome,
}

/// The result of running every check `00` §3.7 requires.
///
/// Deliberately **not** a `bool` plus a log: `rachna status` has to show the
/// per-check detail, and the audit trail has to record which boundary was
/// unverified on a given run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    findings: Vec<Finding>,
}

impl Report {
    /// Builds a report from findings.
    ///
    /// # Errors
    ///
    /// [`Incomplete`] when a check in [`Check::ALL`] has no finding. A
    /// partial report is refused rather than accepted, because the thing a
    /// caller does with a report is decide whether to enter `Running` — and
    /// a missing check would silently not count against that decision. Same
    /// reasoning as [`Scope`](crate::decision::Scope) refusing to be empty.
    pub fn new(findings: Vec<Finding>) -> Result<Self, Incomplete> {
        let mut missing: Vec<Check> = Check::ALL
            .into_iter()
            .filter(|check| !findings.iter().any(|f| f.check == *check))
            .collect();
        if !missing.is_empty() {
            missing.sort_unstable_by_key(|check| check.as_str());
            return Err(Incomplete { missing });
        }
        // A duplicated check is also refused: two findings for one boundary
        // means one of them is stale, and silently keeping either would make
        // the verdict depend on vector order.
        for check in Check::ALL {
            let count = findings.iter().filter(|f| f.check == check).count();
            if count > 1 {
                return Err(Incomplete {
                    missing: vec![check],
                });
            }
        }
        Ok(Self { findings })
    }

    /// Every finding, in [`Check::ALL`] order rather than insertion order.
    ///
    /// Stable output matters: `doctor` is a thing people diff between runs
    /// and paste into bug reports.
    #[must_use]
    pub fn findings(&self) -> Vec<&Finding> {
        Check::ALL
            .into_iter()
            .filter_map(|check| self.findings.iter().find(|f| f.check == check))
            .collect()
    }

    /// Whether every boundary was verified.
    #[must_use]
    pub fn fully_enforced(&self) -> bool {
        self.findings.iter().all(|f| f.outcome.verified())
    }

    /// The checks that did not verify, in a stable order.
    #[must_use]
    pub fn unverified(&self) -> Vec<&Finding> {
        self.findings()
            .into_iter()
            .filter(|f| !f.outcome.verified())
            .collect()
    }

    /// The action a start should apply given this report.
    ///
    /// This is the join between verification and the state machine, and the
    /// reason it lives here rather than in a caller: `00` §3.7 requires a
    /// failing guest to land in `unenforced` **and never to degrade
    /// silently**, so the mapping must be one function that cannot be
    /// forgotten at a call site.
    #[must_use]
    pub fn completing_action(&self) -> Action {
        if self.fully_enforced() {
            Action::Completed
        } else {
            Action::EnforcementFailed
        }
    }
}

impl fmt::Display for Report {
    /// The `rachna status` enforcement block (`00` §3.7).
    ///
    /// Follows `denial.rs`'s shape — `✓`/`✗` markers, one line per item, the
    /// remedy directly under the line it concerns — because a user should not
    /// have to learn two report formats. `00` §3.3 rule 5 is the same rule.
    ///
    /// The enforced case is **one line**, deliberately. A tool that prints
    /// four reassuring ticks every start trains people to skip the block, and
    /// then the one time it says `✗` they skip that too.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fully_enforced() {
            return writeln!(
                f,
                "✓ enforcement verified — {} boundaries checked",
                Check::ALL.len()
            );
        }

        let unverified = self.unverified();
        writeln!(
            f,
            "✗ UNENFORCED — {} of {} boundaries could not be verified",
            unverified.len(),
            Check::ALL.len()
        )?;
        writeln!(f)?;
        for finding in unverified {
            match &finding.outcome {
                // Named differently on purpose. "bypassed" means we proved
                // the boundary is absent; "unverified" means we could not
                // tell. Printing both as "failed" would merge a known hole
                // with an unknown one, and they need different responses.
                Outcome::Bypassed { observed } => {
                    writeln!(f, "  {:<24} ✗ bypassed: {observed}", finding.check.as_str())?;
                }
                Outcome::Inconclusive { why } => {
                    writeln!(f, "  {:<24} ? unverified: {why}", finding.check.as_str())?;
                }
                // Unreachable via `unverified()`, and written out rather than
                // left to a wildcard so adding an Outcome is a compile error
                // here instead of silently printing nothing.
                Outcome::Held => {}
            }
            // The frame carries the REQUIREMENT, so each description can be
            // a plain attempt. Two frames, because one does not fit both
            // outcomes: "tried to X — and it did not fail" is simply FALSE
            // for an inconclusive check, where the attempt could not be made
            // at all. Printing the block is what caught that; the test
            // asserting `contains("did not fail")` had passed it.
            let frame = match finding.outcome {
                Outcome::Inconclusive { .. } => "could not",
                _ => "tried to",
            };
            let outcome = match finding.outcome {
                Outcome::Inconclusive { .. } => "",
                _ => " — and it did not fail",
            };
            writeln!(
                f,
                "  {:<24}   {frame} {}{outcome}",
                "",
                finding.check.attempts()
            )?;
        }
        writeln!(f)?;
        // `00` §3.7 requires the OFFER, not just the warning: "with an offer
        // to restart confined. Never a silent degradation."
        //
        // Both commands are ones the parser ACTUALLY accepts. A first draft
        // offered `rachna start --verify-enforcement`, a flag that appears in
        // neither `00` §5.2 nor `cli.rs` — an offer pointing at a command
        // that does not work is worse than no offer, and a test asserting
        // `contains("rachna start")` passed it. There is now a test that
        // parses every command this block prints.
        writeln!(f, "  rachna stop && rachna start   # restart confined")?;
        writeln!(f, "  rachna doctor                 # why this host cannot")
    }
}

/// A report that did not cover every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incomplete {
    /// The checks with no finding, or a check with more than one.
    pub missing: Vec<Check>,
}

impl fmt::Display for Incomplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "enforcement was not fully verified: no single result for {}. \
             This is a bug in rachna rather than a problem with the \
             environment — a partial report must not be treated as a pass \
             (00 §3.7)",
            self.missing
                .iter()
                .map(|check| check.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl core::error::Error for Incomplete {}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(check: Check) -> Finding {
        Finding {
            check,
            outcome: Outcome::Held,
        }
    }

    fn all_held() -> Vec<Finding> {
        Check::ALL.into_iter().map(held).collect()
    }

    #[test]
    fn all_is_exhaustive() {
        // Adding a check without adding it to ALL would mean a boundary that
        // is never verified and never reported as unverified — the silent
        // shape 00 §3.7 exists to prevent. The match is the compiler's job;
        // this catches the list being short.
        for check in Check::ALL {
            let covered = match check {
                Check::GuestConfinement
                | Check::NetworkEgress
                | Check::ProcessLimit
                | Check::PolicyFileUnreachable => true,
            };
            assert!(covered);
        }
        assert_eq!(Check::ALL.len(), 4);
        // And no two checks share a name, since the name is what `status`
        // prints and the audit stores.
        let mut names: Vec<&str> = Check::ALL.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Check::ALL.len());
    }

    // ---- the probes (how each check is actually carried out) -------------

    #[test]
    fn there_is_exactly_one_probe_per_check() {
        // A check with no probe is a boundary nobody tests, and a report
        // built from an incomplete probe set would be refused by
        // `Report::new` at runtime rather than caught here.
        let probes = Probe::all(512);
        assert_eq!(probes.len(), Check::ALL.len());
        for check in Check::ALL {
            let matching: Vec<&Probe> = probes.iter().filter(|p| p.check == check).collect();
            assert_eq!(
                matching.len(),
                1,
                "{} has {} probes, want exactly 1",
                check.as_str(),
                matching.len()
            );
        }
    }

    #[test]
    fn no_probe_runs_an_empty_command() {
        // The first draft of `Probe` gave `GuestConfinement` an empty command
        // string and an expectation that meant nothing — the "declared and
        // does nothing" shape this project has found five times. The gap is
        // now named by `How::HostSideOnly` instead of faked, and this test
        // is what stops the fake coming back.
        for probe in Probe::all(512) {
            match probe.how {
                How::GuestCommandMustFail { command }
                | How::GuestOutputMustEqual { command, .. } => {
                    assert!(
                        !command.trim().is_empty(),
                        "{} has an empty command",
                        probe.check.as_str()
                    );
                }
                // Allowed, and the point: a boundary the guest cannot answer
                // about says so rather than shipping a command that proves
                // nothing.
                How::HostSideOnly => {}
            }
        }
    }

    #[test]
    fn the_process_limit_probe_carries_the_declared_number() {
        // `15` §3.2's lesson, as a type: "some limit exists" is not the
        // question. The guest probe measured a KERNEL ceiling of 2325 and
        // reported success with every Rachna limit removed, so the declared
        // figure has to reach the comparison.
        for declared in [512_u32, 1, 4096] {
            let probe = Probe::all(declared)
                .into_iter()
                .find(|p| p.check == Check::ProcessLimit)
                .expect("a process-limit probe exists");
            let How::GuestOutputMustEqual { expected, .. } = probe.how else {
                panic!("the process limit must be compared, not merely attempted")
            };
            assert_eq!(
                expected, declared,
                "the probe compares against {expected}, not the declared {declared}"
            );
        }
    }

    #[test]
    fn the_network_probe_uses_a_literal_address_and_a_timeout() {
        let probe = Probe::all(512)
            .into_iter()
            .find(|p| p.check == Check::NetworkEgress)
            .expect("a network probe exists");
        let How::GuestCommandMustFail { command } = probe.how else {
            panic!("egress must be an attempt that fails")
        };
        // No DNS in the path: a probe that failed because resolution failed
        // would report the boundary as holding when it was never tested —
        // the false-negative shape `11` §7 records three times.
        assert!(
            command.contains("1.1.1.1"),
            "the egress probe must not depend on DNS: {command}"
        );
        assert!(
            !command.contains("example.com") && !command.contains("google"),
            "a hostname puts DNS in the path: {command}"
        );
        // And it must not be able to hang: a DROP rule makes connect() block
        // rather than refuse, and a probe that blocks forever is an
        // inconclusive result dressed up as a pending one.
        assert!(
            command.contains("timeout"),
            "the egress probe can hang without a timeout: {command}"
        );
        // `/dev/tcp` is a BASH feature, so the shell is named rather than
        // inherited. Measured: the guest's /bin/sh is currently bash, which
        // means `sh` would work today and break silently on a guest config
        // change — reporting Inconclusive and blocking every start for a
        // reason no message would name.
        assert!(
            command.contains("bash"),
            "/dev/tcp needs bash, not whatever sh happens to be: {command}"
        );
    }

    #[test]
    fn only_the_confinement_check_is_answered_host_side() {
        // The asymmetry is deliberate and worth pinning: if a second check
        // quietly became HostSideOnly, it would stop being probed in the
        // guest with nothing failing.
        let host_side: Vec<Check> = Probe::all(512)
            .into_iter()
            .filter(|p| p.how == How::HostSideOnly)
            .map(|p| p.check)
            .collect();
        assert_eq!(host_side, vec![Check::GuestConfinement]);
    }

    #[test]
    fn only_a_blocked_bypass_counts_as_verified() {
        // The core property. `Inconclusive` counting as verified is the
        // dangerous direction, and it is exactly what three measured
        // false negatives in this project did (`11` §7, `13` §2, `24` §5).
        assert!(Outcome::Held.verified());
        assert!(!Outcome::Bypassed {
            observed: "reached 1.1.1.1:443".to_owned()
        }
        .verified());
        assert!(!Outcome::Inconclusive {
            why: "no guest agent".to_owned()
        }
        .verified());
    }

    #[test]
    fn a_report_missing_a_check_is_refused() {
        // First assert the thing under attack exists: a complete report is
        // accepted. Without this the test would pass against a `new` that
        // rejected everything.
        assert!(Report::new(all_held()).is_ok());

        for omitted in Check::ALL {
            let partial: Vec<Finding> = Check::ALL
                .into_iter()
                .filter(|c| *c != omitted)
                .map(held)
                .collect();
            let error = Report::new(partial)
                .expect_err("a report missing a check must not be constructible");
            assert_eq!(error.missing, vec![omitted]);
            // The message has to say this is our bug, not the user's
            // environment — otherwise they go looking for a sandbox problem.
            let text = error.to_string();
            assert!(text.contains(omitted.as_str()), "{text}");
            assert!(text.contains("bug in rachna"), "{text}");
            assert!(text.contains("must not be treated as a pass"), "{text}");
        }
        // An empty report is the degenerate case and must not be a pass.
        assert!(Report::new(vec![]).is_err());
    }

    #[test]
    fn a_duplicated_check_is_refused() {
        // Two findings for one boundary means one is stale, and keeping
        // either silently would make the verdict depend on vector order.
        let mut findings = all_held();
        findings.push(Finding {
            check: Check::NetworkEgress,
            outcome: Outcome::Bypassed {
                observed: "reached 1.1.1.1:443".to_owned(),
            },
        });
        let error = Report::new(findings).expect_err("a duplicate must be refused");
        assert_eq!(error.missing, vec![Check::NetworkEgress]);
    }

    #[test]
    fn a_single_bypass_makes_the_whole_report_unenforced() {
        // 00 §3.7: never a silent degradation. Three of four boundaries
        // holding is not "mostly enforced", it is unenforced with a specific
        // cause — so the report must not average.
        for failing in Check::ALL {
            let findings: Vec<Finding> = Check::ALL
                .into_iter()
                .map(|check| Finding {
                    check,
                    outcome: if check == failing {
                        Outcome::Bypassed {
                            observed: "the bypass worked".to_owned(),
                        }
                    } else {
                        Outcome::Held
                    },
                })
                .collect();
            let report = Report::new(findings).expect("complete");
            assert!(
                !report.fully_enforced(),
                "{} was bypassed and the report still claimed enforcement",
                failing.as_str()
            );
            assert_eq!(report.unverified().len(), 1);
            assert_eq!(report.unverified()[0].check, failing);
            assert_eq!(report.completing_action(), Action::EnforcementFailed);
        }
    }

    #[test]
    fn an_inconclusive_check_also_blocks_enforcement() {
        // Separate from the bypass test on purpose: "we could not tell" and
        // "we could tell, and it failed" must both stop a `Running`, and the
        // temptation is always to let the first one through.
        let findings: Vec<Finding> = Check::ALL
            .into_iter()
            .map(|check| Finding {
                check,
                outcome: if check == Check::NetworkEgress {
                    Outcome::Inconclusive {
                        why: "the guest agent did not answer".to_owned(),
                    }
                } else {
                    Outcome::Held
                },
            })
            .collect();
        let report = Report::new(findings).expect("complete");
        assert!(!report.fully_enforced());
        assert_eq!(report.completing_action(), Action::EnforcementFailed);
    }

    #[test]
    fn every_boundary_holding_is_the_only_path_to_running() {
        let report = Report::new(all_held()).expect("complete");
        assert!(report.fully_enforced());
        assert!(report.unverified().is_empty());
        assert_eq!(report.completing_action(), Action::Completed);
    }

    #[test]
    fn findings_come_back_in_a_stable_order_whatever_the_input_order() {
        // `doctor` output gets diffed between runs and pasted into bug
        // reports, so insertion order must not leak into it.
        let forward = Report::new(all_held()).expect("complete");
        let mut reversed = all_held();
        reversed.reverse();
        let backward = Report::new(reversed).expect("complete");

        let names = |report: &Report| -> Vec<&'static str> {
            report.findings().iter().map(|f| f.check.as_str()).collect()
        };
        assert_eq!(names(&forward), names(&backward));
        // And it really is ALL's order, not merely consistent.
        assert_eq!(
            names(&forward),
            Check::ALL.iter().map(|c| c.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_check_describes_the_bypass_it_attempts() {
        // The direction of the check IS the design (see the module docs), so
        // each description must name an attempt that is expected to fail —
        // not a capability expected to succeed. A check phrased the other way
        // passes when the mechanism is missing, which is how 15 §3.2's
        // process limit went unnoticed for a whole spike.
        for check in Check::ALL {
            let text = check.attempts();
            assert!(
                text.len() > 30,
                "{}'s description is too terse to audit: {text}",
                check.as_str()
            );
            // Each description is a plain ATTEMPT — a verb phrase naming
            // what was tried. The requirement ("and it did not fail") lives
            // in the sentence frame that prints it, asserted separately
            // below, because an earlier version put "require" in every
            // description and printed "tried to require … to fail".
            let first = text.split(' ').next().unwrap_or("");
            assert!(
                !first.is_empty() && first.chars().all(|c| c.is_ascii_lowercase()),
                "{}'s description should start with a verb: {text}",
                check.as_str()
            );
            assert!(
                !text.contains("require"),
                "the requirement belongs in the frame, not the description: {text}"
            );
            // And it must fit a terminal. The first version ran to ~115
            // characters and wrapped mid-sentence; this test passed it,
            // because it only checked for the word "require". Printing the
            // block is what caught it, so the width is now asserted.
            assert!(
                text.len() <= 56,
                "{}'s description is {} chars and will wrap: {text}",
                check.as_str(),
                text.len()
            );
        }
    }

    // ---- the status block (00 §3.7's "surfaced", not just computed) ------

    #[test]
    fn the_enforced_case_is_one_quiet_line() {
        // A tool that prints four reassuring ticks on every start trains
        // people to skip the block — and then the one time it says ✗ they
        // skip that too. So success is terse by design, and that is asserted
        // rather than left to drift.
        let text = Report::new(all_held()).expect("complete").to_string();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.starts_with('✓'), "{text}");
        assert!(text.contains("verified"), "{text}");
        // And it must NOT look like a warning.
        assert!(!text.contains('✗'), "{text}");
    }

    #[test]
    fn an_unenforced_report_names_the_boundary_the_attempt_and_the_offer() {
        // 00 §3.7: surfaced in `rachna status`, "with an offer to restart
        // confined. Never a silent degradation."
        let findings: Vec<Finding> = Check::ALL
            .into_iter()
            .map(|check| Finding {
                check,
                outcome: if check == Check::NetworkEgress {
                    Outcome::Bypassed {
                        observed: "connected to 1.1.1.1:443 in 12 ms".to_owned(),
                    }
                } else {
                    Outcome::Held
                },
            })
            .collect();
        let text = Report::new(findings).expect("complete").to_string();

        assert!(text.contains("UNENFORCED"), "{text}");
        assert!(text.contains("network-egress"), "{text}");
        // What was actually observed, per 00 §3.3: "network enforcement
        // failed" is unactionable where this is not.
        assert!(text.contains("1.1.1.1:443"), "{text}");
        // What was attempted, so the claim is auditable — AND the required
        // outcome, which is what makes the line mean "this is a problem"
        // rather than "here is a thing we did".
        assert!(text.contains("tried to"), "{text}");
        assert!(text.contains("did not fail"), "{text}");
        // The offer.
        assert!(text.contains("rachna start"), "{text}");
        assert!(text.contains("rachna doctor"), "{text}");
        // Only the failing boundary is listed: the three that held must not
        // add noise to the one that did not.
        for held in [
            Check::GuestConfinement,
            Check::ProcessLimit,
            Check::PolicyFileUnreachable,
        ] {
            assert!(
                !text.contains(held.as_str()),
                "a boundary that HELD was listed as a problem: {text}"
            );
        }
    }

    #[test]
    fn every_command_this_block_offers_actually_parses() {
        // The test that was missing. A first draft offered
        // `rachna start --verify-enforcement` — a flag in neither `00` §5.2
        // nor `cli.rs` — and the assertion `contains("rachna start")` passed
        // it happily. An offer pointing at a command that does not work is
        // worse than no offer, because the user now believes they tried.
        //
        // So every `rachna …` command printed here is fed through the real
        // parser, the same way `denial.rs` suggestions are.
        let findings: Vec<Finding> = Check::ALL
            .into_iter()
            .map(|check| Finding {
                check,
                outcome: Outcome::Bypassed {
                    observed: "x".to_owned(),
                },
            })
            .collect();
        let text = Report::new(findings).expect("complete").to_string();

        let mut checked = 0;
        for line in text.lines() {
            // Strip a trailing `# comment`, which is prose rather than args.
            let command = line.split('#').next().unwrap_or("").trim();
            for part in command.split("&&") {
                let part = part.trim();
                if !part.starts_with("rachna ") {
                    continue;
                }
                let argv: Vec<std::ffi::OsString> = part
                    .split_whitespace()
                    .map(std::ffi::OsString::from)
                    .collect();
                let parsed = crate::cli::Invocation::from_argv(&argv);
                assert!(
                    parsed.is_ok(),
                    "the status block offers `{part}`, which the parser rejects: {:?}",
                    parsed.err()
                );
                checked += 1;
            }
        }
        // And the loop must have found something: a block that printed no
        // commands at all would pass every assertion above.
        assert!(
            checked >= 2,
            "only {checked} commands were checked — is the offer still printed?"
        );
    }

    #[test]
    fn a_proven_hole_reads_differently_from_an_unknown_one() {
        // The distinction that matters operationally: "we proved the boundary
        // is absent" and "we could not tell" need different responses, so
        // printing both as "failed" would merge a known hole with an unknown
        // one.
        let one = |check: Check, outcome: Outcome| -> String {
            let findings: Vec<Finding> = Check::ALL
                .into_iter()
                .map(|c| Finding {
                    check: c,
                    outcome: if c == check {
                        outcome.clone()
                    } else {
                        Outcome::Held
                    },
                })
                .collect();
            Report::new(findings).expect("complete").to_string()
        };

        let bypassed = one(
            Check::NetworkEgress,
            Outcome::Bypassed {
                observed: "reached the internet".to_owned(),
            },
        );
        let unknown = one(
            Check::NetworkEgress,
            Outcome::Inconclusive {
                why: "the guest agent did not answer".to_owned(),
            },
        );
        assert!(bypassed.contains("bypassed"), "{bypassed}");
        assert!(unknown.contains("unverified"), "{unknown}");

        // The ATTEMPT line, asserted on the LINE and not on the whole block.
        //
        // This is the second vacuity trap in this one test, and a mutation
        // survivor found it: `contains("could not")` over the whole report
        // is satisfied by the HEADER — "✗ UNENFORCED — n of m boundaries
        // could not be verified" — so deleting the `could not` arm from the
        // frame match changed the finding line and every assertion still
        // passed. 23 tests green with the mutant applied.
        //
        // So each assertion now names the line it is about. `contains` over
        // a multi-line report is almost always too weak: some other line
        // says the word.
        // Selected by INDENTATION, not by content. My first attempt matched
        // on `contains("could not ")` and picked up the header — "boundaries
        // could not be verified" — which is the very trap this helper exists
        // to avoid, one level down. Finding lines are indented; the header
        // is not, and that is a structural property rather than a wording
        // one.
        let attempt_line = |text: &str| -> String {
            text.lines()
                .filter(|line| line.starts_with("  "))
                .find(|line| line.contains("tried to") || line.contains("could not"))
                .unwrap_or("")
                .to_owned()
        };
        let bypassed_line = attempt_line(&bypassed);
        let unknown_line = attempt_line(&unknown);
        assert!(
            bypassed_line.contains("tried to") && bypassed_line.contains("did not fail"),
            "a proven bypass must say what was tried and that it worked: {bypassed_line:?}"
        );
        assert!(
            unknown_line.contains("could not"),
            "an inconclusive check must say the attempt could not be made: {unknown_line:?}"
        );
        assert!(
            !unknown_line.contains("tried to"),
            "an inconclusive check must not claim an attempt was made: {unknown_line:?}"
        );
        assert!(
            !unknown_line.contains("did not fail"),
            "an inconclusive check must not claim the bypass succeeded: {unknown_line:?}"
        );
        assert_ne!(bypassed, unknown);
        // Both are still UNENFORCED: the difference is in the explanation,
        // never in the verdict.
        assert!(bypassed.contains("UNENFORCED"));
        assert!(unknown.contains("UNENFORCED"));
    }

    #[test]
    fn every_failing_boundary_appears_when_several_fail() {
        // A report that showed only the first problem would send a user round
        // the loop once per boundary.
        let findings: Vec<Finding> = Check::ALL
            .into_iter()
            .map(|check| Finding {
                check,
                outcome: Outcome::Bypassed {
                    observed: format!("{} was bypassed", check.as_str()),
                },
            })
            .collect();
        let text = Report::new(findings).expect("complete").to_string();
        for check in Check::ALL {
            assert!(
                text.contains(check.as_str()),
                "{} is missing: {text}",
                check.as_str()
            );
        }
        assert!(text.contains("4 of 4"), "{text}");
    }

    #[test]
    fn a_bypass_finding_carries_what_was_observed() {
        // 00 §3.3's rule applies here too: a user told only "network
        // enforcement failed" cannot act on it.
        let outcome = Outcome::Bypassed {
            observed: "connected to 1.1.1.1:443 from the guest in 12 ms".to_owned(),
        };
        let Outcome::Bypassed { observed } = &outcome else {
            panic!("constructed a Bypassed and matched something else")
        };
        assert!(observed.contains("1.1.1.1"));
    }
}
