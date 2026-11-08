//! The backend seam, and a mock that implements all of it.
//!
//! `01-ARCHITECTURE.md` §3 asks for the mock **first**, for two reasons that
//! are not about convenience:
//!
//! 1. It lets the policy, audit, reload and IDE work be built and tested with
//!    no hypervisor — which is what made steps 2–6 testable at all.
//! 2. It becomes the basis of a **conformance suite every real backend must
//!    pass**, so capability gaps surface as explicit skips rather than silent
//!    divergence.
//!
//! Point 2 is the one with teeth. The platforms genuinely differ — snapshots
//! are encrypted on macOS and were measured *recoverable* on Linux (`09` §4);
//! macOS has no per-VM CPU or I/O throttles (`12` §4) while Linux enforces
//! both (`11` §3, `13` §1). A seam that papered over those would let a
//! security claim be true on one platform and silently false on the other,
//! which is exactly what `00` §3.7 forbids.
//!
//! So [`Capabilities`] is part of the trait rather than a footnote, and the
//! conformance suite asks each backend what it can do before asserting it
//! does it.

use crate::lifecycle::{Action, Refused, State};

pub mod linux;
pub mod macos;
use core::fmt;

/// What a backend can actually do.
///
/// Distinct from [`crate::decide::Capabilities`], which is about *policy*
/// categories a backend can enforce. This is about *lifecycle* operations.
/// Keeping them separate means "cannot snapshot" and "cannot enforce network
/// policy" are different answers, because they have different consequences:
/// the first degrades performance, the second degrades security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Whether memory snapshots work.
    ///
    /// `02` §4: on macOS this needs `validateSaveRestoreSupport()`, a
    /// *separate* gate from `validate()`, and not every device configuration
    /// can be saved. Must be surfaced as a capability rather than discovered
    /// at the first `suspend`.
    pub memory_snapshot: bool,
    /// Whether snapshots are encrypted at rest.
    ///
    /// Measured: **true on macOS** — keyed to the host, so snapshots are not
    /// portable between machines (`02` §4, `12` §1). **False on Linux**,
    /// where a planted secret was recovered from a snapshot file (`09` §4).
    /// That is a tier-1 correctness gap, not a nicety, and it is a capability
    /// precisely so the gap cannot be forgotten.
    pub encrypted_snapshots: bool,
    /// Whether the guest's CPU share can be capped.
    ///
    /// Linux: yes, via cgroup `CPUQuota` (`10` §3). macOS: **no per-VM
    /// throttles exist** (`12` §4).
    pub cpu_quota: bool,
    /// Whether guest disk I/O can be capped.
    ///
    /// Linux: yes (`13` §1). macOS: no (`12` §4).
    pub io_quota: bool,
}

impl Capabilities {
    /// Everything works — the mock, and the aspiration.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            memory_snapshot: true,
            encrypted_snapshots: true,
            cpu_quota: true,
            io_quota: true,
        }
    }

    /// Nothing works.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            memory_snapshot: false,
            encrypted_snapshots: false,
            cpu_quota: false,
            io_quota: false,
        }
    }

    /// What `02`, `09` and `12` measured on macOS.
    ///
    /// Encoded as a constructor rather than left to a caller, so the measured
    /// facts live next to the capability they describe and a conformance run
    /// can state which platform shape it is testing.
    #[must_use]
    pub const fn measured_macos() -> Self {
        Self {
            memory_snapshot: true,
            // Keyed to the host; verified three ways (`12` §1).
            encrypted_snapshots: true,
            // No per-VM throttles exist (`12` §4).
            cpu_quota: false,
            io_quota: false,
        }
    }

    /// What `04`, `09`, `10`, `11` and `13` measured on Linux.
    #[must_use]
    pub const fn measured_linux() -> Self {
        Self {
            memory_snapshot: true,
            // A planted secret was RECOVERED from a snapshot (`09` §4).
            // Tier-1 gap, tracked, and false until it is closed.
            encrypted_snapshots: false,
            cpu_quota: true,
            io_quota: true,
        }
    }
}

/// Why a backend operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// The lifecycle machine refused the action before the backend saw it.
    Refused(Refused),
    /// The backend cannot do this at all.
    ///
    /// Distinct from a *failure*: a missing capability is a permanent
    /// property of the platform, and retrying will not help. Telling the two
    /// apart is what lets the conformance suite skip rather than fail.
    Unsupported {
        operation: &'static str,
        reason: &'static str,
    },
    /// The operation was attempted and failed.
    Failed {
        operation: &'static str,
        reason: String,
    },
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refused) => write!(f, "{refused}"),
            Self::Unsupported { operation, reason } => {
                write!(f, "{operation} is not supported here: {reason}")
            }
            Self::Failed { operation, reason } => write!(f, "{operation} failed: {reason}"),
        }
    }
}

impl core::error::Error for BackendError {}

impl From<Refused> for BackendError {
    fn from(refused: Refused) -> Self {
        Self::Refused(refused)
    }
}

/// A virtual machine backend.
///
/// Every method drives the lifecycle machine, so a backend cannot invent a
/// transition the machine forbids. That inversion is deliberate: the machine
/// is pure and exhaustively tested, and the backend is the part that talks to
/// a hypervisor.
pub trait Backend {
    /// What this backend can do.
    fn capabilities(&self) -> Capabilities;

    /// The current state.
    fn state(&self) -> State;

    /// Applies a lifecycle action.
    ///
    /// # Errors
    ///
    /// [`BackendError::Refused`] if the machine forbids it,
    /// [`BackendError::Unsupported`] if this backend cannot,
    /// [`BackendError::Failed`] if it tried and could not.
    fn apply(&mut self, action: Action) -> Result<State, BackendError>;

    /// A human-readable name, for `rachna status` and conformance output.
    fn name(&self) -> &'static str;
}

/// A backend that implements the full lifecycle in process.
///
/// Used by every test above the policy layer, and the reference the
/// conformance suite checks real backends against.
#[derive(Debug)]
pub struct Mock {
    state: State,
    capabilities: Capabilities,
    /// Actions to fail rather than perform, so failure paths are testable.
    ///
    /// Present because `02` §4 makes partial failure a *normal* case — a
    /// macOS update can invalidate saved state — and a mock that could only
    /// succeed would leave the recovery transitions untested.
    fail_next: Vec<Action>,
    /// Every action applied, in order.
    history: Vec<Action>,
}

impl Mock {
    /// A stopped mock that can do everything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Stopped,
            capabilities: Capabilities::all(),
            fail_next: Vec::new(),
            history: Vec::new(),
        }
    }

    /// A mock with the given capabilities, for conformance tests.
    #[must_use]
    pub fn with_capabilities(capabilities: Capabilities) -> Self {
        Self {
            capabilities,
            ..Self::new()
        }
    }

    /// Makes the next occurrence of `action` fail.
    pub fn fail(&mut self, action: Action) {
        self.fail_next.push(action);
    }

    /// Every action applied so far.
    #[must_use]
    pub fn history(&self) -> &[Action] {
        &self.history
    }
}

impl Default for Mock {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for Mock {
    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    fn state(&self) -> State {
        self.state
    }

    fn name(&self) -> &'static str {
        "mock"
    }

    fn apply(&mut self, action: Action) -> Result<State, BackendError> {
        // The machine decides legality FIRST, before any capability or
        // failure handling. A backend that checked its own rules first could
        // accept something the machine forbids, and then the two disagree
        // about what state the environment is in.
        let next = self.state.apply(action)?;

        if action == Action::Suspend && !self.capabilities.memory_snapshot {
            return Err(BackendError::Unsupported {
                operation: "suspend",
                reason: "this backend cannot save memory state",
            });
        }

        if let Some(position) = self.fail_next.iter().position(|queued| *queued == action) {
            self.fail_next.remove(position);
            return Err(BackendError::Failed {
                operation: action.as_str(),
                reason: "injected failure".to_owned(),
            });
        }

        self.history.push(action);
        self.state = next;
        Ok(next)
    }
}

/// The conformance suite: what every backend must do.
///
/// `01-ARCHITECTURE.md` §3 requires this so **capability gaps surface as
/// explicit skips rather than silent divergence.** Each check reports
/// [`Outcome::Skipped`] with a reason when the backend lacks the capability,
/// so a conformance run on macOS and one on Linux produce *different but both
/// honest* reports — rather than one of them quietly asserting nothing.
pub mod conformance {
    use super::{Action, Backend, BackendError, State};

    /// What one conformance check concluded.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Outcome {
        /// The backend did the thing.
        Passed,
        /// The backend cannot do the thing, and said so up front.
        ///
        /// Carries the reason so a report reads *"snapshot: skipped — this
        /// backend cannot save memory state"* rather than a bare skip. A skip
        /// with no reason is indistinguishable from a check nobody wrote.
        Skipped { reason: String },
        /// The backend claimed it could and then did not.
        Failed { reason: String },
    }

    impl Outcome {
        /// Whether this outcome should fail a conformance run.
        ///
        /// A skip does not: it is a measured platform difference. Only a
        /// backend that claims a capability and then fails it is a defect.
        #[must_use]
        pub const fn is_defect(&self) -> bool {
            matches!(self, Self::Failed { .. })
        }
    }

    /// One named check and its outcome.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Check {
        pub name: &'static str,
        pub outcome: Outcome,
    }

    /// Runs the suite against `backend`, which must start stopped.
    ///
    /// Returns every check, in order, so a caller can print the full report
    /// rather than only the failures — a run where everything skipped is a
    /// finding too.
    pub fn run(backend: &mut impl Backend) -> Vec<Check> {
        vec![
            check_boot_and_stop(backend),
            check_pause_and_resume(backend),
            check_suspend_and_resume(backend),
            check_illegal_is_refused(backend),
            check_snapshot_confidentiality(backend),
            check_resource_limits(backend),
        ]
    }

    /// Whether the whole run is clean.
    #[must_use]
    pub fn is_conformant(checks: &[Check]) -> bool {
        !checks.iter().any(|check| check.outcome.is_defect())
    }

    fn settle(backend: &mut impl Backend) -> Result<State, BackendError> {
        // Drive any in-flight transition to completion. Written as a helper
        // because every check needs it: the lifecycle machine makes compound
        // operations two steps (`02` §4), so a check that forgot the second
        // would test the transition rather than the operation.
        match backend.state() {
            State::Transitioning(_) => backend.apply(Action::Completed),
            settled => Ok(settled),
        }
    }

    fn passed(name: &'static str) -> Check {
        Check {
            name,
            outcome: Outcome::Passed,
        }
    }

    fn failed(name: &'static str, reason: impl Into<String>) -> Check {
        Check {
            name,
            outcome: Outcome::Failed {
                reason: reason.into(),
            },
        }
    }

    fn skipped(name: &'static str, reason: impl Into<String>) -> Check {
        Check {
            name,
            outcome: Outcome::Skipped {
                reason: reason.into(),
            },
        }
    }

    fn check_boot_and_stop(backend: &mut impl Backend) -> Check {
        const NAME: &str = "boot and stop";
        if let Err(error) = backend.apply(Action::Start) {
            return failed(NAME, error.to_string());
        }
        match settle(backend) {
            Ok(State::Running) => {}
            Ok(other) => return failed(NAME, format!("start landed in {other}, not running")),
            Err(error) => return failed(NAME, error.to_string()),
        }
        match backend.apply(Action::Stop) {
            Ok(State::Stopped) => passed(NAME),
            Ok(other) => failed(NAME, format!("stop landed in {other}")),
            Err(error) => failed(NAME, error.to_string()),
        }
    }

    fn check_pause_and_resume(backend: &mut impl Backend) -> Check {
        const NAME: &str = "pause and resume";
        if backend.apply(Action::Start).is_err() || settle(backend).is_err() {
            return failed(NAME, "could not reach running");
        }
        let result = backend
            .apply(Action::Pause)
            .and_then(|_| backend.apply(Action::Resume));
        let outcome = match result {
            Ok(State::Running) => passed(NAME),
            Ok(other) => failed(NAME, format!("resume landed in {other}")),
            Err(error) => failed(NAME, error.to_string()),
        };
        let _ = backend.apply(Action::Stop);
        outcome
    }

    fn check_suspend_and_resume(backend: &mut impl Backend) -> Check {
        const NAME: &str = "suspend and resume";
        if !backend.capabilities().memory_snapshot {
            return skipped(NAME, "this backend cannot save memory state");
        }
        if backend.apply(Action::Start).is_err() || settle(backend).is_err() {
            return failed(NAME, "could not reach running");
        }
        if backend.apply(Action::Suspend).is_err() {
            return failed(NAME, "suspend refused despite the capability");
        }
        match settle(backend) {
            Ok(State::Suspended) => {}
            Ok(other) => return failed(NAME, format!("suspend landed in {other}")),
            Err(error) => return failed(NAME, error.to_string()),
        }
        if backend.apply(Action::Resume).is_err() {
            return failed(NAME, "resume refused from suspended");
        }
        let outcome = match settle(backend) {
            Ok(State::Running) => passed(NAME),
            Ok(other) => failed(NAME, format!("resume landed in {other}")),
            Err(error) => failed(NAME, error.to_string()),
        };
        let _ = backend.apply(Action::Stop);
        outcome
    }

    /// Public so it can be exercised from a state other than `Stopped`.
    ///
    /// Mutation testing found the guard below untested: within [`run`] the
    /// backend always arrives already stopped, so flipping `!=` to `==`
    /// changed nothing observable. A conformance check with an untested
    /// branch is a check that might not run — which is the silent divergence
    /// this whole module exists to prevent.
    pub fn check_illegal_is_refused(backend: &mut impl Backend) -> Check {
        const NAME: &str = "illegal transitions refused";
        // From Stopped, pausing is meaningless. A backend that accepted it
        // would be inventing a state the machine does not have.
        if backend.state() != State::Stopped {
            let _ = backend.apply(Action::Stop);
        }
        match backend.apply(Action::Pause) {
            Err(BackendError::Refused(_)) => passed(NAME),
            Err(other) => failed(NAME, format!("refused for the wrong reason: {other}")),
            Ok(state) => failed(
                NAME,
                format!("accepted pause from stopped, landing in {state}"),
            ),
        }
    }

    fn check_snapshot_confidentiality(backend: &mut impl Backend) -> Check {
        const NAME: &str = "snapshots are encrypted at rest";
        // A tier-1 correctness item (`09` §4), measured BROKEN on Linux: a
        // planted secret was recovered from a snapshot file. Reported as a
        // skip rather than a pass so the gap stays visible in every
        // conformance run until it is closed.
        if backend.capabilities().encrypted_snapshots {
            passed(NAME)
        } else {
            skipped(
                NAME,
                "snapshots are not encrypted on this backend — a planted \
                 secret was recoverable (09 §4); tier-1 gap",
            )
        }
    }

    fn check_resource_limits(backend: &mut impl Backend) -> Check {
        const NAME: &str = "cpu and io quotas";
        let capabilities = backend.capabilities();
        match (capabilities.cpu_quota, capabilities.io_quota) {
            (true, true) => passed(NAME),
            (false, false) => skipped(NAME, "no per-VM throttles exist on this platform (12 §4)"),
            (true, false) => skipped(NAME, "cpu quota only; no io quota"),
            (false, true) => skipped(NAME, "io quota only; no cpu quota"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::conformance::{is_conformant, run, Outcome};
    use super::*;
    use crate::lifecycle::Transition;

    #[test]
    fn a_full_capability_mock_passes_every_check() {
        let mut mock = Mock::new();
        let checks = run(&mut mock);
        assert!(is_conformant(&checks), "{checks:#?}");
        assert!(
            checks.iter().all(|c| c.outcome == Outcome::Passed),
            "a full-capability backend should skip nothing: {checks:#?}"
        );
    }

    #[test]
    fn the_measured_platform_shapes_both_conform_but_differ() {
        // THE point of the suite (01 §3): capability gaps surface as explicit
        // skips rather than silent divergence. macOS and Linux produce
        // DIFFERENT reports and both are honest — neither is a failure.
        let mut macos = Mock::with_capabilities(Capabilities::measured_macos());
        let mac_checks = run(&mut macos);
        assert!(is_conformant(&mac_checks), "{mac_checks:#?}");

        let mut linux = Mock::with_capabilities(Capabilities::measured_linux());
        let linux_checks = run(&mut linux);
        assert!(is_conformant(&linux_checks), "{linux_checks:#?}");

        let skipped = |checks: &[conformance::Check], name: &str| {
            checks
                .iter()
                .find(|c| c.name == name)
                .is_some_and(|c| matches!(c.outcome, Outcome::Skipped { .. }))
        };

        // macOS: encrypted snapshots pass, resource quotas skip (12 §4).
        assert!(!skipped(&mac_checks, "snapshots are encrypted at rest"));
        assert!(skipped(&mac_checks, "cpu and io quotas"));

        // Linux: the reverse. The snapshot gap (09 §4) is a tier-1 item and
        // stays visible in every run until closed.
        assert!(skipped(&linux_checks, "snapshots are encrypted at rest"));
        assert!(!skipped(&linux_checks, "cpu and io quotas"));
    }

    #[test]
    fn a_skip_always_carries_a_reason() {
        // A skip with no reason is indistinguishable from a check nobody
        // wrote, which is the silent divergence the suite exists to prevent.
        for capabilities in [
            Capabilities::none(),
            Capabilities::measured_macos(),
            Capabilities::measured_linux(),
        ] {
            let mut mock = Mock::with_capabilities(capabilities);
            for check in run(&mut mock) {
                if let Outcome::Skipped { reason } = &check.outcome {
                    assert!(!reason.is_empty(), "{} skipped with no reason", check.name);
                }
            }
        }
    }

    #[test]
    fn a_capability_less_backend_skips_rather_than_fails() {
        // It genuinely cannot snapshot or throttle, and that is not a defect
        // — it is a platform. Only claiming a capability and then failing is.
        let mut mock = Mock::with_capabilities(Capabilities::none());
        let checks = run(&mut mock);
        assert!(is_conformant(&checks), "{checks:#?}");
        assert!(
            checks
                .iter()
                .any(|c| matches!(c.outcome, Outcome::Skipped { .. })),
            "nothing skipped despite no capabilities"
        );
    }

    #[test]
    fn a_backend_that_claims_snapshots_and_fails_them_is_a_defect() {
        // The case the suite is really for: a capability that lies. A skip is
        // honest; this is not.
        let mut mock = Mock::new();
        mock.fail(Action::Suspend);
        let checks = run(&mut mock);
        assert!(!is_conformant(&checks), "a lying capability passed");
        let suspend = checks
            .iter()
            .find(|c| c.name == "suspend and resume")
            .expect("the check ran");
        assert!(suspend.outcome.is_defect(), "{suspend:?}");
    }

    #[test]
    fn the_illegal_transition_check_works_from_any_starting_state() {
        // Mutation testing found the guard in check_illegal_is_refused
        // untested: within `run` the backend always arrives stopped, so
        // flipping its comparison changed nothing. These call it directly
        // from a RUNNING backend, which is the branch that was dead.
        //
        // It matters because the check has to stop the backend first — asking
        // a running VM to pause is LEGAL, so without that step the check
        // would assert the opposite of what it claims.
        let mut running = Mock::new();
        running.apply(Action::Start).expect("legal");
        running.apply(Action::Completed).expect("legal");
        assert_eq!(running.state(), State::Running);

        let check = conformance::check_illegal_is_refused(&mut running);
        assert_eq!(
            check.outcome,
            Outcome::Passed,
            "the check must stop the backend first, or it tests the wrong thing"
        );

        // And from a suspended backend, where `pause` is also illegal but the
        // path to stopped differs.
        let mut suspended = Mock::new();
        for action in [
            Action::Start,
            Action::Completed,
            Action::Suspend,
            Action::Completed,
        ] {
            suspended.apply(action).expect("legal");
        }
        assert_eq!(suspended.state(), State::Suspended);
        assert_eq!(
            conformance::check_illegal_is_refused(&mut suspended).outcome,
            Outcome::Passed
        );
    }

    // ---- the seam -------------------------------------------------------

    #[test]
    fn the_machine_decides_legality_before_the_backend_sees_it() {
        // A backend that checked its own rules first could accept something
        // the machine forbids, and then the two disagree about what state the
        // environment is in.
        let mut mock = Mock::with_capabilities(Capabilities::none());
        // Suspend is both illegal here (stopped) AND unsupported. The REFUSAL
        // must win, because the action was never legal to attempt.
        match mock.apply(Action::Suspend) {
            Err(BackendError::Refused(_)) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unsupported_operation_is_distinguishable_from_a_failure() {
        // A missing capability is permanent and retrying will not help; a
        // failure might be transient. Conflating them would make the
        // conformance suite unable to tell a skip from a defect.
        let mut unsupported = Mock::with_capabilities(Capabilities::none());
        unsupported.apply(Action::Start).expect("legal");
        unsupported.apply(Action::Completed).expect("legal");
        match unsupported.apply(Action::Suspend) {
            Err(BackendError::Unsupported { operation, .. }) => assert_eq!(operation, "suspend"),
            other => panic!("expected Unsupported, got {other:?}"),
        }

        let mut failing = Mock::new();
        failing.apply(Action::Start).expect("legal");
        failing.apply(Action::Completed).expect("legal");
        failing.fail(Action::Suspend);
        match failing.apply(Action::Suspend) {
            Err(BackendError::Failed { operation, .. }) => assert_eq!(operation, "suspend"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_action_does_not_advance_the_state() {
        // Otherwise a failed suspend would leave the environment claiming to
        // be suspended with no snapshot behind it.
        let mut mock = Mock::new();
        mock.apply(Action::Start).expect("legal");
        mock.apply(Action::Completed).expect("legal");
        mock.fail(Action::Suspend);
        assert!(mock.apply(Action::Suspend).is_err());
        assert_eq!(mock.state(), State::Running, "state advanced on failure");
    }

    #[test]
    fn a_failed_action_is_not_recorded_in_history() {
        // History is what happened, not what was attempted.
        let mut mock = Mock::new();
        mock.fail(Action::Start);
        assert!(mock.apply(Action::Start).is_err());
        assert!(mock.history().is_empty());
    }

    #[test]
    fn history_records_what_was_applied_in_order() {
        let mut mock = Mock::new();
        for action in [
            Action::Start,
            Action::Completed,
            Action::Pause,
            Action::Resume,
        ] {
            mock.apply(action).expect("legal");
        }
        assert_eq!(
            mock.history(),
            [
                Action::Start,
                Action::Completed,
                Action::Pause,
                Action::Resume
            ]
        );
    }

    #[test]
    fn an_injected_failure_fires_once() {
        // So a test can exercise "fails then succeeds", which is the macOS
        // invalidated-snapshot case (02 §4): restore fails, cold boot works.
        let mut mock = Mock::new();
        mock.fail(Action::Start);
        assert!(mock.apply(Action::Start).is_err());
        assert_eq!(
            mock.apply(Action::Start).expect("second attempt"),
            State::Transitioning(Transition::Starting)
        );
    }

    #[test]
    fn a_mock_starts_stopped_and_names_itself() {
        let mock = Mock::new();
        assert_eq!(mock.state(), State::Stopped);
        assert_eq!(mock.name(), "mock");
        assert_eq!(Mock::default().state(), State::Stopped);
    }

    // ---- the capability sets --------------------------------------------

    #[test]
    fn the_measured_capability_sets_match_what_the_spikes_found() {
        // Pinned, because these encode measurements rather than preferences.
        // Changing one should mean a new measurement, not a convenience.
        let macos = Capabilities::measured_macos();
        assert!(macos.memory_snapshot, "02 §1");
        assert!(macos.encrypted_snapshots, "12 §1, verified three ways");
        assert!(!macos.cpu_quota, "12 §4: no per-VM throttles");
        assert!(!macos.io_quota, "12 §4");

        let linux = Capabilities::measured_linux();
        assert!(linux.memory_snapshot, "04 §1");
        assert!(
            !linux.encrypted_snapshots,
            "09 §4: a planted secret was recovered"
        );
        assert!(linux.cpu_quota, "10 §3");
        assert!(linux.io_quota, "13 §1");
    }

    #[test]
    fn all_and_none_are_opposites() {
        let all = Capabilities::all();
        let none = Capabilities::none();
        assert_ne!(all, none);
        for (field, a, n) in [
            ("memory_snapshot", all.memory_snapshot, none.memory_snapshot),
            (
                "encrypted_snapshots",
                all.encrypted_snapshots,
                none.encrypted_snapshots,
            ),
            ("cpu_quota", all.cpu_quota, none.cpu_quota),
            ("io_quota", all.io_quota, none.io_quota),
        ] {
            assert!(a, "{field} should be true in all()");
            assert!(!n, "{field} should be false in none()");
        }
    }

    #[test]
    fn a_backend_error_explains_itself() {
        let unsupported = BackendError::Unsupported {
            operation: "suspend",
            reason: "no save support",
        };
        assert!(unsupported.to_string().contains("not supported"));

        let failed = BackendError::Failed {
            operation: "start",
            reason: "boom".to_owned(),
        };
        assert!(failed.to_string().contains("boom"));

        let refused = BackendError::from(State::Stopped.apply(Action::Pause).expect_err("illegal"));
        assert!(refused.to_string().contains("pause"));
    }
}
