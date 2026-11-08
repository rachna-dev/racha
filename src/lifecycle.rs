//! The lifecycle state machine: what an environment can do next.
//!
//! `01-ARCHITECTURE.md` §7 step 7's acceptance test is "illegal transitions
//! rejected", and the states come from measured hypervisor behaviour rather
//! than from a tidy diagram:
//!
//! - **The VM must be paused before saving, and restore lands paused**
//!   (`02` §4, from `VZVirtualMachine.h` and confirmed by probing). So
//!   `suspend` is internally pause → save → stop and `resume` is restore →
//!   resume: both are **compound**, both can fail partway, and the machine
//!   needs a transitioning state that leaves the environment recoverable.
//! - **A macOS update can invalidate saved state.** So a failed restore is a
//!   normal transition to handle, not an error path — it falls back to cold
//!   boot, loudly (`02` §4).
//! - **Enforcement is verified on every start** (`00` §3.7). A guest that
//!   fails the check enters [`State::Unenforced`], which is a real state and
//!   not a flag: *never a silent degradation.*
//!
//! # Why this is a pure function
//!
//! [`State::apply`] takes a state and an action and returns the next state or
//! a refusal. No VM, no clock, no I/O — so every transition, legal and
//! illegal, is table-testable, and the backend cannot disagree with the
//! machine about what is allowed.

use core::fmt;

/// What an environment is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// No VM exists. Nothing has been started, or `stop` completed.
    Stopped,
    /// A compound operation is in flight.
    ///
    /// Exists because `suspend` and `resume` are each several hypervisor
    /// calls (`02` §4) and can fail between them. Without this state a crash
    /// mid-suspend would leave a stored state that claims to be `Running`
    /// while no VM exists.
    Transitioning(Transition),
    /// Running, with enforcement verified.
    Running,
    /// Running, but **enforcement could not be verified**.
    ///
    /// A distinct state rather than a boolean on `Running`, because `00` §3.7
    /// requires a security claim to be either true or loudly absent. Making
    /// it a flag invites code that forgets to check it.
    Unenforced,
    /// Paused: vCPUs stopped, memory retained, VM still present.
    ///
    /// The only state from which a snapshot may be taken — enforced by the
    /// hypervisor, so §2 of this module does not try to be clever about it.
    Paused,
    /// Suspended to disk: no VM, but a snapshot exists to resume from.
    Suspended,
}

/// A compound operation in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transition {
    /// Booting.
    Starting,
    /// pause → save → stop.
    Suspending,
    /// restore → resume.
    Resuming,
    /// Rebuilding the guest closure, which requires a restart.
    Rebuilding,
}

impl Transition {
    /// Where this transition lands when it succeeds.
    #[must_use]
    pub const fn completes_as(self) -> State {
        match self {
            // Enforcement is verified as part of starting, so a plain success
            // is `Running`; the failure path is `Action::EnforcementFailed`.
            Self::Starting | Self::Resuming | Self::Rebuilding => State::Running,
            Self::Suspending => State::Suspended,
        }
    }

    /// Where this transition lands when it fails.
    ///
    /// Not simply `Stopped`: a failed *suspend* may have already written a
    /// snapshot, and a failed *resume* must not discard the one it was
    /// reading. `02` §4 requires a failed restore to fall back to cold boot
    /// loudly rather than losing the saved state.
    #[must_use]
    pub const fn recovers_as(self) -> State {
        match self {
            // The snapshot it was reading is still there, so the environment
            // is still suspended and a retry — or a cold boot — is possible.
            Self::Resuming => State::Suspended,
            // A partial suspend cannot be trusted as a snapshot, and the VM
            // may already be gone. Stopped is the honest answer.
            Self::Starting | Self::Suspending | Self::Rebuilding => State::Stopped,
        }
    }

    /// The word used in `rachna status`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Suspending => "suspending",
            Self::Resuming => "resuming",
            Self::Rebuilding => "rebuilding",
        }
    }
}

impl fmt::Display for Transition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Something that happens to an environment.
///
/// Both user commands and outcomes reported by the backend, in one enum: a
/// transition completing is as much an event as a user asking for it, and
/// splitting them would mean two state machines that can disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// `rachna start`.
    Start,
    /// `rachna stop`.
    Stop,
    /// `rachna pause`.
    Pause,
    /// `rachna resume` from paused, or from suspended.
    Resume,
    /// `rachna suspend`.
    Suspend,
    /// `rachna rebuild`.
    Rebuild,
    /// The in-flight transition finished.
    Completed,
    /// The in-flight transition failed.
    Failed,
    /// Enforcement verification failed during start (`00` §3.7).
    EnforcementFailed,
}

impl Action {
    /// Every action, for exhaustive table tests.
    pub const ALL: [Self; 9] = [
        Self::Start,
        Self::Stop,
        Self::Pause,
        Self::Resume,
        Self::Suspend,
        Self::Rebuild,
        Self::Completed,
        Self::Failed,
        Self::EnforcementFailed,
    ];

    /// The word a user types, where there is one.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Suspend => "suspend",
            Self::Rebuild => "rebuild",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::EnforcementFailed => "enforcement-failed",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an action was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// Where the environment was.
    pub state: State,
    /// What was asked for.
    pub action: Action,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot {} while {}",
            self.action,
            match self.state {
                State::Transitioning(transition) =>
                    return write!(
                        f,
                        "cannot {} while {transition} is in progress",
                        self.action
                    ),
                other => other.as_str(),
            }
        )
    }
}

impl core::error::Error for Refused {}

impl State {
    /// Every state, for exhaustive table tests.
    pub const ALL: [Self; 9] = [
        Self::Stopped,
        Self::Running,
        Self::Unenforced,
        Self::Paused,
        Self::Suspended,
        Self::Transitioning(Transition::Starting),
        Self::Transitioning(Transition::Suspending),
        Self::Transitioning(Transition::Resuming),
        Self::Transitioning(Transition::Rebuilding),
    ];

    /// The word used in `rachna status`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Unenforced => "unenforced",
            Self::Paused => "paused",
            Self::Suspended => "suspended",
            Self::Transitioning(transition) => transition.as_str(),
        }
    }

    /// Whether a VM process exists.
    ///
    /// `Suspended` is deliberately false: a snapshot exists but no VM does,
    /// which is what makes resume a restore rather than an unpause.
    #[must_use]
    pub const fn has_vm(self) -> bool {
        matches!(self, Self::Running | Self::Unenforced | Self::Paused)
    }

    /// Whether commands may run in the guest.
    ///
    /// `Unenforced` is **true**: the environment works, and refusing to use
    /// it would be a worse answer than telling the user loudly that its
    /// isolation is unverified (`00` §3.7 offers a confined restart rather
    /// than blocking).
    #[must_use]
    pub const fn accepts_commands(self) -> bool {
        matches!(self, Self::Running | Self::Unenforced)
    }

    /// Applies `action`, returning the next state.
    ///
    /// # Errors
    ///
    /// [`Refused`] if the action is not legal from this state. Refusing is
    /// the whole point: a state machine that quietly allowed `snapshot` on a
    /// running VM would produce a corrupt snapshot the hypervisor never
    /// agreed to.
    pub const fn apply(self, action: Action) -> Result<Self, Refused> {
        let refused = Err(Refused {
            state: self,
            action,
        });

        match (self, action) {
            // Starting, from anywhere there is no VM.
            (Self::Stopped, Action::Start) => Ok(Self::Transitioning(Transition::Starting)),
            (Self::Suspended, Action::Start | Action::Resume) => {
                Ok(Self::Transitioning(Transition::Resuming))
            }

            // Pausing and unpausing an existing VM. These are single
            // hypervisor calls, so there is no transitioning state.
            (Self::Running | Self::Unenforced, Action::Pause) => Ok(Self::Paused),
            (Self::Paused, Action::Resume) => Ok(Self::Running),

            // Suspending: compound (pause -> save -> stop), so it goes
            // through a transition. Permitted from Paused too, because the
            // first step of the compound operation is already done.
            (Self::Running | Self::Unenforced | Self::Paused, Action::Suspend) => {
                Ok(Self::Transitioning(Transition::Suspending))
            }

            // Rebuilding changes the closure, which requires a restart.
            (Self::Running | Self::Unenforced | Self::Paused, Action::Rebuild) => {
                Ok(Self::Transitioning(Transition::Rebuilding))
            }

            // Stopping. Idempotent from Stopped: `rachna stop` on a stopped
            // environment is a no-op rather than an error, because a user
            // should not have to know the state to ask for the state they
            // want.
            (Self::Running | Self::Unenforced | Self::Paused | Self::Stopped, Action::Stop) => {
                Ok(Self::Stopped)
            }
            // Stopping a suspended environment discards its snapshot, which
            // is a real action with a real effect, so it is allowed and
            // lands in Stopped rather than being a no-op.
            (Self::Suspended, Action::Stop) => Ok(Self::Stopped),

            // Outcomes of a transition. Only a transition can complete or
            // fail — a `Completed` arriving in any other state means the
            // backend and the machine have diverged, and refusing surfaces
            // that rather than papering over it.
            (Self::Transitioning(transition), Action::Completed) => Ok(transition.completes_as()),
            (Self::Transitioning(transition), Action::Failed) => Ok(transition.recovers_as()),

            // Enforcement verification failed during start or resume
            // (`00` §3.7). The environment is usable and says so loudly.
            (
                Self::Transitioning(Transition::Starting | Transition::Resuming),
                Action::EnforcementFailed,
            ) => Ok(Self::Unenforced),

            // Everything else. Notably: no action is accepted while
            // transitioning except Completed/Failed/EnforcementFailed, so a
            // user cannot stack `suspend` onto a `resume` already in flight.
            _ => refused,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for State {
    /// [`State::Stopped`] — an environment that has never been started.
    fn default() -> Self {
        Self::Stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every (state, action) pair — 81 of them.
    fn every_pair() -> impl Iterator<Item = (State, Action)> {
        State::ALL
            .into_iter()
            .flat_map(|state| Action::ALL.into_iter().map(move |action| (state, action)))
    }

    #[test]
    fn the_whole_transition_table_is_pinned() {
        // "Illegal transitions rejected" (01 §7 step 7) is only meaningful if
        // every pair has a decided answer, so all 81 are listed here rather
        // than counted.
        //
        // A first draft asserted a COUNT, which was both wrong (27, not 24)
        // and a weak assertion: a count cannot tell a new legal transition
        // from a lost one. Listing them means adding or removing a transition
        // is a visible diff that has to be justified.
        let legal: Vec<(State, Action, State)> = every_pair()
            .filter_map(|(state, action)| {
                state.apply(action).ok().map(|next| (state, action, next))
            })
            .collect();

        let expected: &[(State, Action, State)] = &[
            // Stopped
            (
                State::Stopped,
                Action::Start,
                State::Transitioning(Transition::Starting),
            ),
            (State::Stopped, Action::Stop, State::Stopped),
            // Running
            (State::Running, Action::Stop, State::Stopped),
            (State::Running, Action::Pause, State::Paused),
            (
                State::Running,
                Action::Suspend,
                State::Transitioning(Transition::Suspending),
            ),
            (
                State::Running,
                Action::Rebuild,
                State::Transitioning(Transition::Rebuilding),
            ),
            // Unenforced behaves identically
            (State::Unenforced, Action::Stop, State::Stopped),
            (State::Unenforced, Action::Pause, State::Paused),
            (
                State::Unenforced,
                Action::Suspend,
                State::Transitioning(Transition::Suspending),
            ),
            (
                State::Unenforced,
                Action::Rebuild,
                State::Transitioning(Transition::Rebuilding),
            ),
            // Paused
            (State::Paused, Action::Stop, State::Stopped),
            (State::Paused, Action::Resume, State::Running),
            (
                State::Paused,
                Action::Suspend,
                State::Transitioning(Transition::Suspending),
            ),
            (
                State::Paused,
                Action::Rebuild,
                State::Transitioning(Transition::Rebuilding),
            ),
            // Suspended
            (
                State::Suspended,
                Action::Start,
                State::Transitioning(Transition::Resuming),
            ),
            (State::Suspended, Action::Stop, State::Stopped),
            (
                State::Suspended,
                Action::Resume,
                State::Transitioning(Transition::Resuming),
            ),
            // Transitions: only outcomes
            (
                State::Transitioning(Transition::Starting),
                Action::Completed,
                State::Running,
            ),
            (
                State::Transitioning(Transition::Starting),
                Action::Failed,
                State::Stopped,
            ),
            (
                State::Transitioning(Transition::Starting),
                Action::EnforcementFailed,
                State::Unenforced,
            ),
            (
                State::Transitioning(Transition::Suspending),
                Action::Completed,
                State::Suspended,
            ),
            (
                State::Transitioning(Transition::Suspending),
                Action::Failed,
                State::Stopped,
            ),
            (
                State::Transitioning(Transition::Resuming),
                Action::Completed,
                State::Running,
            ),
            (
                State::Transitioning(Transition::Resuming),
                Action::Failed,
                State::Suspended,
            ),
            (
                State::Transitioning(Transition::Resuming),
                Action::EnforcementFailed,
                State::Unenforced,
            ),
            (
                State::Transitioning(Transition::Rebuilding),
                Action::Completed,
                State::Running,
            ),
            (
                State::Transitioning(Transition::Rebuilding),
                Action::Failed,
                State::Stopped,
            ),
        ];

        for entry in &legal {
            assert!(expected.contains(entry), "undeclared transition: {entry:?}");
        }
        for entry in expected {
            assert!(legal.contains(entry), "declared but refused: {entry:?}");
        }
        assert_eq!(legal.len(), expected.len());
    }

    #[test]
    fn no_transition_ever_lands_in_the_state_it_came_from_by_accident() {
        // A self-loop is legitimate only for the idempotent cases, and those
        // are deliberate: `stop` when stopped. Anything else looping would be
        // an action that silently does nothing.
        for (state, action) in every_pair() {
            if let Ok(next) = state.apply(action) {
                if next == state {
                    assert_eq!(
                        (state, action),
                        (State::Stopped, Action::Stop),
                        "unexpected self-loop"
                    );
                }
            }
        }
    }

    // ---- the compound operations ----------------------------------------

    #[test]
    fn suspend_goes_through_a_transition_rather_than_landing_directly() {
        // `02` §4: suspend is pause -> save -> stop, three hypervisor calls.
        // Landing directly in Suspended would mean a crash between them
        // leaves a stored state claiming a snapshot that was never written.
        let state = State::Running.apply(Action::Suspend).expect("legal");
        assert_eq!(state, State::Transitioning(Transition::Suspending));
        assert_eq!(
            state.apply(Action::Completed).expect("legal"),
            State::Suspended
        );
    }

    #[test]
    fn a_failed_resume_keeps_the_environment_suspended() {
        // `02` §4: a macOS update can invalidate saved state, and a failed
        // restore must fall back to cold boot LOUDLY rather than losing the
        // snapshot. Landing in Stopped would discard what it was reading.
        let resuming = State::Suspended.apply(Action::Resume).expect("legal");
        assert_eq!(resuming, State::Transitioning(Transition::Resuming));
        assert_eq!(
            resuming.apply(Action::Failed).expect("legal"),
            State::Suspended,
            "a failed restore must not discard the snapshot"
        );
    }

    #[test]
    fn a_failed_suspend_lands_stopped_not_suspended() {
        // The converse, and it matters: a partial suspend cannot be trusted
        // as a snapshot. Claiming Suspended would offer the user a resume
        // from a half-written file.
        let suspending = State::Running.apply(Action::Suspend).expect("legal");
        assert_eq!(
            suspending.apply(Action::Failed).expect("legal"),
            State::Stopped
        );
    }

    #[test]
    fn a_failed_start_lands_stopped() {
        let starting = State::Stopped.apply(Action::Start).expect("legal");
        assert_eq!(
            starting.apply(Action::Failed).expect("legal"),
            State::Stopped
        );
    }

    #[test]
    fn nothing_can_be_stacked_onto_an_in_flight_transition() {
        // A user typing `suspend` during a `resume` must be refused, not
        // queued: the backend is mid-way through a compound operation and a
        // second one would interleave hypervisor calls.
        for transition in [
            Transition::Starting,
            Transition::Suspending,
            Transition::Resuming,
            Transition::Rebuilding,
        ] {
            let state = State::Transitioning(transition);
            for action in Action::ALL {
                let allowed = matches!(
                    action,
                    Action::Completed | Action::Failed | Action::EnforcementFailed
                );
                let accepted = state.apply(action).is_ok();
                if !allowed {
                    assert!(!accepted, "{transition} accepted a user action: {action}");
                }
            }
        }
    }

    #[test]
    fn only_a_transition_can_complete_or_fail() {
        // A `Completed` arriving in a settled state means the backend and the
        // machine have diverged. Refusing surfaces that; accepting would
        // paper over it.
        for state in State::ALL {
            if matches!(state, State::Transitioning(_)) {
                continue;
            }
            for action in [Action::Completed, Action::Failed] {
                assert!(
                    state.apply(action).is_err(),
                    "{state} accepted {action} with nothing in flight"
                );
            }
        }
    }

    // ---- the unenforced state -------------------------------------------

    #[test]
    fn a_failed_enforcement_check_produces_a_state_not_a_flag() {
        // `00` §3.7: never a silent degradation. A boolean on Running invites
        // code that forgets to check it; a distinct state makes every match
        // site handle it.
        let starting = State::Stopped.apply(Action::Start).expect("legal");
        assert_eq!(
            starting.apply(Action::EnforcementFailed).expect("legal"),
            State::Unenforced
        );
    }

    #[test]
    fn enforcement_can_also_fail_on_resume() {
        // `00` §3.7 verifies on doctor AND on every start. A resumed VM is a
        // started VM as far as the guest is concerned.
        let resuming = State::Suspended.apply(Action::Resume).expect("legal");
        assert_eq!(
            resuming.apply(Action::EnforcementFailed).expect("legal"),
            State::Unenforced
        );
    }

    #[test]
    fn enforcement_cannot_fail_out_of_nowhere() {
        // It is an outcome of starting, so it is meaningless elsewhere.
        for state in State::ALL {
            let legal = matches!(
                state,
                State::Transitioning(Transition::Starting | Transition::Resuming)
            );
            assert_eq!(
                state.apply(Action::EnforcementFailed).is_ok(),
                legal,
                "{state} disagreed about EnforcementFailed"
            );
        }
    }

    #[test]
    fn an_unenforced_environment_still_accepts_commands() {
        // Refusing to use it would be a worse answer than saying loudly that
        // its isolation is unverified — `00` §3.7 offers a confined restart
        // rather than blocking.
        assert!(State::Unenforced.accepts_commands());
        assert!(State::Running.accepts_commands());
        assert!(!State::Paused.accepts_commands());
        assert!(!State::Suspended.accepts_commands());
        assert!(!State::Stopped.accepts_commands());
    }

    #[test]
    fn unenforced_behaves_like_running_for_every_action() {
        // The one difference is what `status` says. If the two diverged on
        // what is allowed, an unenforced environment would be subtly broken
        // in ways nobody tested.
        for action in Action::ALL {
            assert_eq!(
                State::Running.apply(action).is_ok(),
                State::Unenforced.apply(action).is_ok(),
                "Running and Unenforced disagree about {action}"
            );
        }
    }

    // ---- has_vm, and why Suspended is false -----------------------------

    #[test]
    fn suspended_has_no_vm_which_is_what_makes_resume_a_restore() {
        assert!(!State::Suspended.has_vm());
        assert!(!State::Stopped.has_vm());
        assert!(State::Running.has_vm());
        assert!(State::Unenforced.has_vm());
        assert!(
            State::Paused.has_vm(),
            "paused keeps memory and the process"
        );
    }

    #[test]
    fn a_transitioning_state_claims_no_vm() {
        // Mid-flight the answer is genuinely unknown, and claiming a VM
        // exists would let something try to talk to one that may be gone.
        for transition in [Transition::Starting, Transition::Suspending] {
            assert!(!State::Transitioning(transition).has_vm());
        }
    }

    // ---- idempotence where a user expects it ----------------------------

    #[test]
    fn stopping_an_already_stopped_environment_is_a_no_op() {
        // A user should not have to know the current state to ask for the
        // state they want.
        assert_eq!(
            State::Stopped.apply(Action::Stop).expect("legal"),
            State::Stopped
        );
    }

    #[test]
    fn stopping_a_suspended_environment_discards_its_snapshot() {
        // A real action with a real effect, so it is allowed — and it lands
        // in Stopped, which is the honest description afterwards.
        assert_eq!(
            State::Suspended.apply(Action::Stop).expect("legal"),
            State::Stopped
        );
    }

    #[test]
    fn start_on_a_suspended_environment_resumes_rather_than_cold_booting() {
        // "Lazy wake" (`00` §3.1): the first command after `cd` resumes from
        // a memory snapshot. Cold booting instead would throw away the
        // product's central performance bet.
        assert_eq!(
            State::Suspended.apply(Action::Start).expect("legal"),
            State::Transitioning(Transition::Resuming)
        );
    }

    #[test]
    fn starting_a_running_environment_is_refused_rather_than_restarting_it() {
        // Silently restarting would discard a warm guest and any in-flight
        // work. Refusing makes the user say what they meant.
        assert!(State::Running.apply(Action::Start).is_err());
        assert!(State::Paused.apply(Action::Start).is_err());
    }

    // ---- naming and rendering -------------------------------------------

    #[test]
    fn every_state_and_action_has_a_distinct_name() {
        // These appear in `rachna status` and in stored records, so a
        // collision would make two states indistinguishable.
        let mut states: Vec<&str> = State::ALL.iter().map(|s| s.as_str()).collect();
        let total = states.len();
        states.sort_unstable();
        states.dedup();
        assert_eq!(states.len(), total, "two states share a name");

        let mut actions: Vec<&str> = Action::ALL.iter().map(|a| a.as_str()).collect();
        let total = actions.len();
        actions.sort_unstable();
        actions.dedup();
        assert_eq!(actions.len(), total, "two actions share a name");
    }

    #[test]
    fn display_agrees_with_as_str() {
        for state in State::ALL {
            assert_eq!(state.to_string(), state.as_str());
        }
        for action in Action::ALL {
            assert_eq!(action.to_string(), action.as_str());
        }
    }

    #[test]
    fn a_refusal_says_what_was_asked_and_where_it_was_asked_from() {
        let refusal = State::Suspended.apply(Action::Pause).expect_err("illegal");
        let message = refusal.to_string();
        assert!(message.contains("pause"), "{message}");
        assert!(message.contains("suspended"), "{message}");
    }

    #[test]
    fn a_refusal_during_a_transition_names_the_transition() {
        // "cannot suspend while resuming is in progress" tells the user to
        // wait; "cannot suspend while transitioning" does not say what for.
        let refusal = State::Transitioning(Transition::Resuming)
            .apply(Action::Suspend)
            .expect_err("illegal");
        let message = refusal.to_string();
        assert!(message.contains("resuming"), "{message}");
        assert!(message.contains("in progress"), "{message}");
    }

    #[test]
    fn the_default_state_is_stopped() {
        assert_eq!(State::default(), State::Stopped);
    }

    // ---- reachability ----------------------------------------------------

    #[test]
    fn every_state_is_reachable_from_stopped() {
        // An unreachable state is dead code pretending to be a design. Found
        // by breadth-first search over the transition table rather than by
        // reading it.
        let mut reached = vec![State::Stopped];
        let mut frontier = vec![State::Stopped];
        while let Some(state) = frontier.pop() {
            for action in Action::ALL {
                if let Ok(next) = state.apply(action) {
                    if !reached.contains(&next) {
                        reached.push(next);
                        frontier.push(next);
                    }
                }
            }
        }
        for state in State::ALL {
            assert!(reached.contains(&state), "{state} is unreachable");
        }
    }

    #[test]
    fn stopped_is_reachable_from_every_state() {
        // No state may be a trap: a user must always be able to get back to
        // a clean slate.
        for start in State::ALL {
            let mut reached = vec![start];
            let mut frontier = vec![start];
            let mut found = start == State::Stopped;
            while let Some(state) = frontier.pop() {
                for action in Action::ALL {
                    if let Ok(next) = state.apply(action) {
                        if next == State::Stopped {
                            found = true;
                        }
                        if !reached.contains(&next) {
                            reached.push(next);
                            frontier.push(next);
                        }
                    }
                }
            }
            assert!(found, "{start} cannot reach stopped");
        }
    }
}
