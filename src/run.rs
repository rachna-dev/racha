//! `rachna start` and `rachna stop`, joining everything else.
//!
//! **The third missing piece from `01` §7.0b.** Every decision layer was
//! built and tested; `supervise.rs` can now spawn; `agent.rs` serves. This is
//! the function that calls them in order, and until it existed
//! `rachna start` exited 70 with a sentence.
//!
//! # The order is the security argument
//!
//! Each step gates the next, and the sequence is not arbitrary — reordering
//! any of the first four would weaken something a document measured:
//!
//! 1. **Evaluate `rachna.nix`, restricted.** `23`'s spike measured a cloned
//!    config reading `/etc/passwd`, returning `$SECRET_TOKEN` and
//!    exfiltrating both, *host-side at full privilege, during start*. So the
//!    restricted invocation comes before anything trusts the output.
//! 2. **Parse into a policy.** An unknown key is an error (`00` §5.3 rule 4),
//!    because a config that silently means something else is the same defect
//!    class as a limit declared and never enforced.
//! 3. **Refuse what this host cannot enforce.** `16` §5.3 measured that a
//!    networked guest *does not boot at all* without `CAP_NET_ADMIN`, so the
//!    only question is whether the user gets our sentence or a hypervisor
//!    backtrace.
//! 4. **Gate on the grant set.** `00` §3.10c: a first run shows what it is
//!    about to permit and waits. A changed set re-asks.
//! 5. **Launch**, virtiofsd then Cloud Hypervisor (`supervise.rs`).
//! 6. **Record what is running**, so `stop` can find it.
//!
//! Verification (`enforcement.rs`) belongs after 5 and needs the agent to
//! execute its probes; `Outcome::Inconclusive` is what the report carries
//! until then, and that blocks a `Running` rather than passing silently.
//!
//! # Why this is a module and not `main.rs`
//!
//! `main.rs` is untested by design (`01` §7), and AGENTS.md now records why:
//! *anything with observable behaviour does not belong in it.* The ordering
//! above is the most security-relevant behaviour in the project, so it lives
//! where tests can reach it.

use crate::config;
use crate::decide::{Capabilities, Policy};
use crate::eval::Invocation;
use crate::layout::{ProjectId, ProjectPaths};
use crate::store::approval::Approval;
use crate::store::Store;
use crate::summary::{review_prompt, AccessSummary, Selection};
use crate::supervise::{self, Children, Running, StartPlan};
use crate::tap;
use core::fmt;
use std::path::PathBuf;

/// What `start` needs that is not in `rachna.nix`.
///
/// Grouped so a test can supply all of it, and so the ordering above is
/// exercised without a real home directory.
#[derive(Debug, Clone)]
pub struct Context {
    /// The project directory — where `rachna.nix` lives.
    pub project_dir: PathBuf,
    /// The Rachna root, normally `~/.rachna` (`08` §4.1).
    pub rachna_root: PathBuf,
    /// This project's stable id.
    pub project: ProjectId,
    /// The pinned nixpkgs the guest is built from.
    pub nixpkgs: PathBuf,
    /// What the backend can enforce, as measured.
    pub capabilities: Capabilities,
    /// Whether `CAP_NET_ADMIN` is available (`tap.rs`).
    pub tap: tap::Capability,
    /// Whether stdin is a terminal, so the gate knows to prompt.
    pub interactive: bool,
}

impl Context {
    /// The paths for this project.
    #[must_use]
    pub fn paths(&self) -> ProjectPaths {
        ProjectPaths::new(&self.rachna_root, &self.project)
    }

    /// Where `rachna.nix` is.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.project_dir.join("rachna.nix")
    }
}

/// How far `start` got, and why it stopped.
///
/// A sum type rather than `Result<(), Error>` because **two of the outcomes
/// are not failures**: a first run that needs acknowledgement and an
/// environment already running are both normal, and reporting them as errors
/// would make a script's exit code say the wrong thing.
#[derive(Debug)]
pub enum Started {
    /// The guest is up.
    Running {
        /// What to tear down.
        running: Running,
        /// The handles, so `stop` can reap (`supervise.rs`).
        children: Children,
    },
    /// Already running; nothing was done.
    ///
    /// `00` §5.2 makes `start` the command people type on `cd`, so it must
    /// be idempotent rather than an error on the second run.
    AlreadyRunning { running: Running },
    /// The grant set needs a human (`00` §3.10c).
    ///
    /// Carries the rendered summary and prompt, so the caller prints rather
    /// than re-derives — and a test can assert what a user would see.
    NeedsAcknowledgement {
        /// What the config grants.
        summary: AccessSummary,
        /// The prompt, already shaped for a terminal or a pipe.
        prompt: String,
    },
}

/// Why `start` could not proceed.
#[derive(Debug)]
pub enum StartError {
    /// `rachna.nix` is not there.
    NoConfig { looked_for: PathBuf },
    /// Evaluation failed.
    ///
    /// Carries Nix's own stderr verbatim: `18` §2 requires the last-good
    /// spec to survive and the error to be surfaced unchanged, and `22`'s
    /// whole finding is that Nix's messages are bad enough that paraphrasing
    /// them loses the only usable detail.
    Evaluation { stderr: String },
    /// The evaluated config is invalid.
    Config { errors: config::ConfigErrors },
    /// This host cannot enforce the declared policy.
    Unenforceable(tap::Unenforceable),
    /// The store could not be opened.
    Store { why: String },
    /// A process would not start.
    Supervise(supervise::StartError),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoConfig { looked_for } => write!(
                f,
                "no rachna.nix in {}. `rachna init` writes a starting one",
                looked_for.parent().unwrap_or(looked_for).display()
            ),
            Self::Evaluation { stderr } => write!(f, "rachna.nix did not evaluate:\n{stderr}"),
            Self::Config { errors } => {
                for error in errors.all() {
                    writeln!(f, "{error}")?;
                }
                Ok(())
            }
            Self::Unenforceable(why) => write!(f, "{why}"),
            Self::Store { why } => write!(f, "cannot open the audit store: {why}"),
            Self::Supervise(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for StartError {}

/// Evaluates `rachna.nix` and parses it, with nothing trusted in between.
///
/// Separated from [`start`] so the restricted-evaluation step is testable
/// against a real `nix eval` without launching a VM — which is how `23`'s
/// sandbox tests already work.
///
/// # Errors
///
/// [`StartError::NoConfig`], [`StartError::Evaluation`] or
/// [`StartError::Config`].
pub fn evaluate(context: &Context) -> Result<Policy, StartError> {
    let config_file = context.config_file();
    if !config_file.exists() {
        return Err(StartError::NoConfig {
            looked_for: config_file,
        });
    }

    let invocation = Invocation::restricted(&context.project_dir, &config_file, &context.nixpkgs);
    let mut command = std::process::Command::new("nix");
    command.args(invocation.args());
    // `23` §2: `NIX_PATH` is load-bearing. Without clearing it the user's own
    // search-path entries stay reachable, so the import allowlist leaks
    // whatever their environment happens to hold.
    for name in invocation.cleared_env() {
        command.env_remove(name);
    }

    let output = command.output().map_err(|error| StartError::Evaluation {
        stderr: format!("could not run `nix`: {error}"),
    })?;
    if !output.status.success() {
        return Err(StartError::Evaluation {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let json = String::from_utf8_lossy(&output.stdout).into_owned();
    config::parse(&json, context.capabilities.clone())
        .map_err(|errors| StartError::Config { errors })
}

/// Everything between a policy and a launch, with no side effects.
///
/// Returns the gate's verdict. **Pure**, so the ordering of steps 3 and 4 is
/// testable without a filesystem — and both are refusals a user will meet
/// far more often than a successful first run.
///
/// # Errors
///
/// [`StartError::Unenforceable`] when the host cannot enforce the policy.
pub fn check(
    policy: &Policy,
    tap_capability: &tap::Capability,
    approval: Approval,
    interactive: bool,
) -> Result<Option<Started>, StartError> {
    // Step 3 BEFORE the gate, deliberately. `16` §5.3 measured that a
    // networked guest does not boot at all without the capability, so asking
    // a user to approve a grant set that cannot run would waste their
    // acknowledgement on an environment that then fails.
    let forwarded_ports = policy
        .grants
        .iter()
        .filter(|grant| matches!(grant, crate::grant::Grant::Port { .. }))
        .count();
    tap::check(policy.tier, forwarded_ports, tap_capability).map_err(StartError::Unenforceable)?;

    // Step 4: the grant set.
    let summary = AccessSummary::new(policy.tier, policy.profile, &policy.grants);
    if approval.permits_apply() {
        return Ok(None);
    }
    // A config that grants NOTHING needs no acknowledgement: `00` §3.10c's
    // gate exists so a user sees what they are about to permit, and there is
    // nothing to see. Found by running it — the prompt said "needs no
    // acknowledgement" and the gate refused anyway, which is a message and
    // a behaviour disagreeing in the most confusing possible way.
    //
    // `is_empty` is `summary.rs`'s own question, so this cannot drift from
    // what the summary printed: a `none (… forbids it)` line is not a grant.
    if summary.is_empty() {
        return Ok(None);
    }
    Ok(Some(Started::NeedsAcknowledgement {
        prompt: format!("{summary}\n{}", review_prompt(&summary, interactive)),
        summary,
    }))
}

/// Records a human's approval of a policy's grant set.
///
/// What `--accept` and the keypress call. Separate from [`check`] because
/// `00` §3.10c makes the acknowledgement a **read gate**: it records that
/// someone saw this set, and cannot create a permission.
///
/// # Errors
///
/// [`StartError::Store`] if the record cannot be written. **Refused rather
/// than proceeding**: an approval that was not stored means the next start
/// asks again, which is merely annoying — but silently proceeding would let
/// a user believe they had approved something that was never recorded.
pub fn accept(context: &Context, policy: &Policy, now_millis: i64) -> Result<(), StartError> {
    let summary = AccessSummary::new(policy.tier, policy.profile, &policy.grants);
    let store = open_store(context)?;
    store
        .approve(&summary, now_millis)
        .map_err(|error| StartError::Store {
            why: error.to_string(),
        })
}

/// The grants a user declined, as the `revoke` commands that remove them.
///
/// `00` §3.10c's selective acceptance: the selection **composes an edit**
/// rather than being stored, so `rachna.nix` stays the only authority.
#[must_use]
pub fn decline(policy: &Policy, keep: &[usize]) -> Selection {
    AccessSummary::new(policy.tier, policy.profile, &policy.grants).select(keep)
}

/// Opens this project's audit store, creating the directory if needed.
fn open_store(context: &Context) -> Result<Store, StartError> {
    let paths = context.paths();
    std::fs::create_dir_all(paths.root()).map_err(|error| StartError::Store {
        why: format!("cannot create {}: {error}", paths.root().display()),
    })?;
    Store::open(&paths.database()).map_err(|error| StartError::Store {
        why: error.to_string(),
    })
}

/// Reads the approval state for a policy's grant set.
///
/// # Errors
///
/// [`StartError::Store`] if the store cannot be read.
pub fn approval_of(context: &Context, policy: &Policy) -> Result<Approval, StartError> {
    let summary = AccessSummary::new(policy.tier, policy.profile, &policy.grants);
    let store = open_store(context)?;
    store
        .approval_of(&summary)
        .map_err(|error| StartError::Store {
            why: error.to_string(),
        })
}

/// What is already running for this project, if anything.
///
/// # Errors
///
/// A [`supervise::StateError`] if the record exists and is corrupt — which
/// is deliberately **not** treated as "nothing is running", because that
/// would start a second guest alongside the first.
pub fn already_running(context: &Context) -> Result<Running, supervise::StateError> {
    let file = supervise::state_file(&context.paths());
    match std::fs::read_to_string(&file) {
        Ok(text) => Running::from_text(&text),
        // No file means nothing started, which is the common case.
        Err(_) => Ok(Running::nothing()),
    }
}

/// Launches the guest and records what is running.
///
/// # Errors
///
/// [`StartError::Supervise`] if a process would not start, or
/// [`StartError::Store`] if the running record cannot be written — the
/// second **after killing what started**, because a guest nobody can stop is
/// `24` §6a's leak.
pub fn launch(context: &Context, plan: &StartPlan) -> Result<Started, StartError> {
    let paths = context.paths();
    let (running, children) =
        supervise::start(plan, &paths.runtime_dir()).map_err(StartError::Supervise)?;

    let file = supervise::state_file(&paths);
    if let Err(error) = std::fs::write(&file, running.to_text()) {
        // Nothing can stop this guest, so stop it now.
        let mut children = children;
        let _ = supervise::stop_with(&running, &mut children);
        return Err(StartError::Store {
            why: format!(
                "started, but could not record it in {}: {error}. The guest \
                 has been stopped, because one nobody can stop is worse",
                file.display()
            ),
        });
    }
    Ok(Started::Running { running, children })
}

/// Tears down whatever is running, and clears the record.
///
/// # Errors
///
/// A [`supervise::StateError`] if the record is corrupt. The processes are
/// **not** touched in that case: `stop` cannot know what to kill, and
/// guessing is worse than refusing.
pub fn stop(context: &Context) -> Result<supervise::StopReport, supervise::StateError> {
    let running = already_running(context)?;
    let report = supervise::stop(&running);
    // Only once the processes are gone: a record removed first would leave a
    // running guest nothing can find.
    if report.is_clean() {
        let _ = std::fs::remove_file(supervise::state_file(&context.paths()));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{Endpoint, Grant};
    use crate::policy::{Profile, Tier};
    use crate::resources::Resources;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rachna-run-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn context(name: &str) -> Context {
        let root = scratch(name);
        Context {
            project_dir: root.join("project"),
            rachna_root: root.join("rachna"),
            project: ProjectId::new("app-a3f2").expect("valid"),
            nixpkgs: PathBuf::from("/nixpkgs"),
            capabilities: Capabilities::all(),
            tap: tap::Capability::Present,
            interactive: false,
        }
    }

    fn policy(tier: Tier, grants: Vec<Grant>) -> Policy {
        Policy {
            tier,
            profile: Profile::Development,
            grants,
            resources: Resources::default(),
            capabilities: Capabilities::all(),
        }
    }

    fn network(host: &str) -> Grant {
        Grant::Network {
            endpoint: Endpoint::new(host, 443).expect("valid"),
        }
    }

    // ---- the order the security argument rests on ------------------------

    #[test]
    fn an_unenforceable_policy_is_refused_before_the_gate_asks() {
        // Step 3 BEFORE step 4, deliberately. `16` §5.3 measured that a
        // networked guest does not boot at all without CAP_NET_ADMIN, so
        // asking a user to approve a grant set that cannot run would spend
        // their acknowledgement on an environment that then fails.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let error = check(
            &policy,
            &tap::Capability::Missing {
                helper: PathBuf::from("/usr/local/bin/rachna-netd"),
            },
            // UNSEEN, so the gate would also have something to say — which
            // is what makes the ordering observable.
            Approval::Unseen,
            false,
        )
        .expect_err("an unenforceable policy must be refused");

        assert!(matches!(error, StartError::Unenforceable(_)), "{error:?}");
        // And the message is the capability one, not the grant summary.
        let text = error.to_string();
        assert!(text.contains("CAP_NET_ADMIN"), "{text}");
        assert!(
            !text.contains("has not run here before"),
            "the gate ran before the enforceability check: {text}"
        );
    }

    #[test]
    fn an_unapproved_grant_set_stops_before_launching() {
        // `00` §3.10c: a first run shows what it is about to permit and
        // waits. Returning `NeedsAcknowledgement` rather than an error is
        // the point — a script's exit code must not call this a failure.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let verdict = check(&policy, &tap::Capability::Present, Approval::Unseen, false)
            .expect("enforceable")
            .expect("must not proceed");

        let Started::NeedsAcknowledgement { prompt, summary } = verdict else {
            panic!("an unapproved grant set was allowed to launch")
        };
        // The summary names what it is about to permit.
        assert!(prompt.contains("github.com"), "{prompt}");
        // And the prompt names the command, per `00` §3.3.
        assert!(prompt.contains("rachna start --accept"), "{prompt}");
        assert!(!summary.is_empty());
    }

    #[test]
    fn a_config_granting_nothing_needs_no_acknowledgement() {
        // `00` §3.10c's gate exists so a user sees what they are about to
        // permit; an empty set has nothing to see. Found by RUNNING it: the
        // prompt said "needs no acknowledgement" and the gate refused
        // anyway — a message and a behaviour disagreeing.
        let sealed = policy(Tier::None, vec![]);
        assert!(
            check(&sealed, &tap::Capability::Present, Approval::Unseen, false)
                .expect("enforceable")
                .is_none(),
            "a config granting nothing was gated"
        );
    }

    #[test]
    fn a_config_granting_something_is_still_gated() {
        // The other half, so the exemption above cannot swallow the gate.
        let granting = policy(Tier::Allowlist, vec![network("github.com")]);
        assert!(
            check(
                &granting,
                &tap::Capability::Present,
                Approval::Unseen,
                false
            )
            .expect("enforceable")
            .is_some(),
            "a real grant set skipped the gate"
        );
    }

    #[test]
    fn an_approved_grant_set_proceeds() {
        // The positive path, so the two refusals above are not vacuous.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let verdict = check(
            &policy,
            &tap::Capability::Present,
            Approval::Approved,
            false,
        )
        .expect("enforceable");
        assert!(verdict.is_none(), "an approved set did not proceed");
    }

    #[test]
    fn a_sealed_policy_proceeds_without_the_network_capability() {
        // Most of what makes the refusal acceptable: a project wanting no
        // network must not be blocked by a capability it does not use.
        let policy = policy(Tier::None, vec![]);
        assert!(check(
            &policy,
            &tap::Capability::Missing {
                helper: PathBuf::from("/x")
            },
            Approval::Approved,
            false,
        )
        .expect("sealed is enforceable")
        .is_none());
    }

    #[test]
    fn a_forwarded_port_needs_the_capability_even_when_sealed() {
        // `16` §5.3 is about the VM not BOOTING, and a port needs the tap
        // whatever the tier says about outbound hosts.
        let policy = policy(
            Tier::None,
            vec![Grant::Port {
                guest: 3000,
                host: 3000,
            }],
        );
        assert!(
            check(
                &policy,
                &tap::Capability::Missing {
                    helper: PathBuf::from("/x")
                },
                Approval::Approved,
                false,
            )
            .is_err(),
            "a sealed project with a forwarded port was allowed to start"
        );
    }

    #[test]
    fn the_prompt_shape_follows_whether_a_terminal_is_attached() {
        // `00` §3.10c: CI needs a flag, because a pipeline blocked on a
        // keypress nobody can send is worse than one that refuses.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let rendered = |interactive: bool| -> String {
            match check(
                &policy,
                &tap::Capability::Present,
                Approval::Unseen,
                interactive,
            )
            .expect("enforceable")
            .expect("needs ack")
            {
                Started::NeedsAcknowledgement { prompt, .. } => prompt,
                other => panic!("expected an acknowledgement, got {other:?}"),
            }
        };
        assert!(rendered(true).contains("[a] accept all"));
        assert!(rendered(false).contains("rachna start --accept"));
    }

    // ---- the approval record -------------------------------------------

    #[test]
    fn accepting_records_the_grant_set_and_a_later_start_proceeds() {
        // End to end through the real store: the gate asks once and not
        // again, which is `00` §3.10c's "thereafter start is silent".
        let context = context("accept");
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);

        assert_eq!(
            approval_of(&context, &policy).expect("readable"),
            Approval::Unseen
        );
        accept(&context, &policy, 1).expect("records");
        assert_eq!(
            approval_of(&context, &policy).expect("readable"),
            Approval::Approved
        );
        assert!(check(
            &policy,
            &tap::Capability::Present,
            approval_of(&context, &policy).expect("readable"),
            false
        )
        .expect("enforceable")
        .is_none());
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn adding_a_grant_re_triggers_the_gate() {
        // `00` §3.11's supply-chain case, arriving for free: a grant added
        // by a `git pull` is an unapproved set.
        let context = context("widened");
        let narrow = policy(Tier::Allowlist, vec![network("github.com")]);
        accept(&context, &narrow, 1).expect("records");

        let wider = policy(
            Tier::Allowlist,
            vec![network("github.com"), network("evil.test")],
        );
        assert_eq!(
            approval_of(&context, &wider).expect("readable"),
            Approval::Unseen,
            "a widened grant set inherited the narrower one's approval"
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn declining_a_grant_yields_the_command_that_removes_it() {
        // `00` §3.10c: the selection composes an EDIT, so `rachna.nix` stays
        // the only authority and nothing is stored as a subset.
        // `Profile::Online`, not Development — `policy.rs`'s `forbids` has
        // "Development withholds credentials; online is what grants them",
        // so under Development the summary correctly does NOT list the
        // secret and there is nothing to decline. The same assumption caught
        // me in `credential.rs`; the summary agreeing with the engine is the
        // feature, not the bug.
        let policy = Policy {
            profile: Profile::Online,
            ..policy(
                Tier::Allowlist,
                vec![
                    network("github.com"),
                    Grant::Secret {
                        name: "aws".to_owned(),
                    },
                ],
            )
        };
        // Keep everything EXCEPT the secret, found by category rather than
        // by a guessed number: `AccessSummary` orders by `Category::ALL`,
        // so assuming the secret is item 1 made this test assert the
        // opposite of what it meant. The number is for a human reading the
        // list, not for a test to hard-code.
        let summary = AccessSummary::new(policy.tier, policy.profile, &policy.grants);
        let secret = summary
            .reviewable()
            .into_iter()
            .find(|item| item.category == crate::decision::Category::Secret)
            .expect("the fixture grants a secret");
        let keep: Vec<usize> = summary
            .reviewable()
            .iter()
            .map(|item| item.number)
            .filter(|number| *number != secret.number)
            .collect();

        let selection = decline(&policy, &keep);
        assert_eq!(selection.rejected().len(), 1);
        assert_eq!(selection.revocations(), vec!["rachna revoke secret aws"]);
    }

    // ---- what is already running ---------------------------------------

    #[test]
    fn nothing_running_reads_as_nothing() {
        let context = context("empty");
        assert!(already_running(&context)
            .expect("no file is not an error")
            .is_empty());
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn a_corrupt_record_refuses_rather_than_starting_a_second_guest() {
        // THE dangerous direction. Treating a corrupt record as "nothing is
        // running" would start a second guest alongside the first — two
        // hypervisors on one state image, which is the consistency defect
        // `15` §7 ranks tier 1.
        let context = context("corrupt");
        let paths = context.paths();
        std::fs::create_dir_all(paths.runtime_dir()).expect("runtime dir");
        std::fs::write(supervise::state_file(&paths), "mystery 1\n").expect("write");

        assert!(
            already_running(&context).is_err(),
            "a corrupt record was read as nothing running"
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn stopping_refuses_to_guess_from_a_corrupt_record() {
        // Same reasoning one step on: `stop` cannot know what to kill, and
        // killing a guessed pid is worse than refusing.
        let context = context("corrupt-stop");
        let paths = context.paths();
        std::fs::create_dir_all(paths.runtime_dir()).expect("runtime dir");
        std::fs::write(supervise::state_file(&paths), "cloud-hypervisor x\n").expect("write");
        assert!(stop(&context).is_err());
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    // ---- launching and stopping for real -------------------------------

    #[test]
    fn launching_records_what_is_running_and_stopping_clears_it() {
        // The round trip `start` and `stop` depend on, with `sleep` standing
        // in for the hypervisor — the thing under test is the wiring.
        let context = context("roundtrip");
        let plan = StartPlan {
            steps: vec![supervise::Step {
                role: supervise::Role::Hypervisor,
                program: "sleep".to_owned(),
                args: vec![std::ffi::OsString::from("30")],
                then_await: None,
            }],
        };

        let started = launch(&context, &plan).expect("launches");
        let Started::Running { running, .. } = started else {
            panic!("expected a running guest")
        };
        assert_eq!(running.processes.len(), 1);

        // The record is on disk, which is what makes `stop` possible at all.
        let recorded = already_running(&context).expect("readable");
        assert_eq!(recorded, running);

        let report = stop(&context).expect("stops");
        assert!(report.is_clean(), "{report}");
        // And the record is gone, so a later `start` does not think a dead
        // guest is alive.
        assert!(
            already_running(&context).expect("readable").is_empty(),
            "the record survived a clean stop"
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn a_missing_config_says_how_to_make_one() {
        // `00` §3.3's rule: a message that only reports cannot be acted on.
        let context = context("noconfig");
        std::fs::create_dir_all(&context.project_dir).expect("project dir");
        let error = evaluate(&context).expect_err("no rachna.nix");
        assert!(matches!(error, StartError::NoConfig { .. }), "{error:?}");
        assert!(error.to_string().contains("rachna init"), "{error}");
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }
}
