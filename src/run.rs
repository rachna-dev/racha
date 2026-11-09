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
use crate::summary::{review_prompt, AccessSummary, Reason, Selection};
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
/// Returns what to show the user and whether to wait for them. **Pure**, so
/// the ordering of steps 3 and 4 is testable without a filesystem.
///
/// # The summary is unconditional
///
/// An earlier version returned `None` for an approved grant set, meaning
/// "say nothing, proceed" — so a second `start` printed nothing and
/// launched. That is corrected in `00` §3.10c, and the reason is the one
/// §3.10c already gives for the first run: **a user about to hand a
/// directory to a VM should be told what that VM may do, every time.**
///
/// The approval record changes only whether *input* is required, never
/// whether the summary appears. Otherwise `rachna.db` would be deciding
/// whether a user sees their own permissions, and `08` §3.1 is explicit
/// that the database is a cache rather than truth.
///
/// # Errors
///
/// [`StartError::Unenforceable`] when the host cannot enforce the policy.
pub fn check(
    policy: &Policy,
    tap_capability: &tap::Capability,
    approval: Approval,
    history: History,
    resuming: Option<&crate::snapshot::ResumeApproval>,
    interactive: bool,
) -> Result<Gate, StartError> {
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

    // A config that grants NOTHING needs no keypress: the gate exists so a
    // user sees what they are about to permit, and there is nothing to
    // permit. The summary still prints — `00` §3.10c's "secrets none is
    // information" applies to the whole set.
    //
    // `is_empty` is `summary.rs`'s own question, so this cannot drift from
    // what the summary showed: a `none (… forbids it)` line is not a grant.
    let approved = approval.permits_apply();

    // Resume is the SAME gate, not a parallel one. `00` §3.10c's third
    // reason for making the summary unconditional is that a rule covering
    // only `start` leaves the steady-state path uncovered — §7 Layer A
    // makes resume the common case.
    //
    // A snapshot whose grant set differs from the file's, or that predates
    // grant recording, needs input even when the CURRENT set is approved:
    // what is coming back to life is the snapshot's policy, and approving
    // today's file never reviewed that.
    let snapshot_disagrees = resuming.is_some_and(|verdict| {
        matches!(
            *verdict,
            crate::snapshot::ResumeApproval::NeedsApproval { .. }
                | crate::snapshot::ResumeApproval::Unrecorded
        )
    });

    let needs_input = !summary.is_empty() && (!approved || snapshot_disagrees);

    // ONE reason drives both the header and the prompt's sentence, so the
    // two cannot disagree about why the gate is asking. They did: the
    // header said "first run" while the config had plainly run here.
    // `Widened` describes an UNAPPROVED set in a project with history. Once
    // the set is approved it is simply what is running, and keeping the
    // "widened since you approved" wording would describe the state before
    // the keypress — found by pressing `a` and running again, where an
    // approved config was still told it had widened.
    let reason = if snapshot_disagrees {
        Reason::SnapshotDiverged
    } else if history == History::RanBefore && !approved {
        Reason::Widened
    } else {
        Reason::FirstRun
    };

    Ok(Gate {
        shown: format!("{}{summary}", gate_header(approved, reason)),
        prompt: if needs_input {
            Some(review_prompt(&summary, reason, interactive))
        } else {
            None
        },
        divergence: resuming.and_then(describe_divergence),
        summary,
    })
}

/// The line above the grant list, saying which case this is.
///
/// Lives here rather than in [`AccessSummary`]'s `Display` because it
/// depends on the **approval record**, which the summary deliberately does
/// not know. It used to be hardcoded as `"rachna.nix grants, first run:"`,
/// and once `00` §3.10c made the summary unconditional that became a lie
/// told to every user on every subsequent start — found by running `start`
/// twice and reading the output.
fn gate_header(approved: bool, reason: Reason) -> String {
    let what = match (approved, reason) {
        // Resume is where "first run" would be most misleading: the config
        // has run here — that is why there is a snapshot.
        (_, Reason::SnapshotDiverged) => "resuming under these grants:",
        (_, Reason::Widened) => "grants, widened since you approved:",
        (true, Reason::FirstRun) => "running under these grants:",
        (false, Reason::FirstRun) => "grants, first run:",
    };
    format!("  rachna.nix {what}\n")
}

/// The sentence a resume gate adds, when the snapshot's policy is not the
/// file's.
///
/// `00` §3.3's rule applies here as everywhere: a user told "permissions
/// changed" cannot act, so the fingerprints are named. [`None`] for an
/// unchanged snapshot — there is nothing to say.
fn describe_divergence(verdict: &crate::snapshot::ResumeApproval) -> Option<String> {
    use crate::snapshot::ResumeApproval;
    match *verdict {
        ResumeApproval::Unchanged => None,
        ResumeApproval::Unrecorded => Some(
            "  this snapshot predates grant recording, so what it was\n  \
             permitted cannot be compared. review the grants above.\n"
                .to_owned(),
        ),
        ResumeApproval::NeedsApproval {
            ref taken_with,
            ref running,
        } => Some(format!(
            "  the grants changed since this snapshot was taken:\n  \
             taken with  {taken_with}\n  rachna.nix  {running}\n"
        )),
    }
}

/// Whether this project has ever had a grant set approved on this machine.
///
/// Needed because [`Approval`] answers only about the grant set in front of
/// it: `Unseen` is returned both for a genuine first run *and* for a config
/// that has run here for months and just gained a host. Telling the second
/// user "this config has not run here before" reads as a bug and costs the
/// gate its credibility — which is the one thing it cannot afford.
///
/// An enum rather than a `bool` because `check(…, true, …)` at a call site
/// says nothing about what is true (AGENTS.md, "prefer enums").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History {
    /// No grant set has ever been approved for this project here.
    Fresh,
    /// Some grant set was approved here before, so this config is not new.
    RanBefore,
}

/// What to show the user, and whether to wait for them.
///
/// The summary is **always** present; the prompt is present only when a
/// human has not yet approved this grant set. `00` §3.10c: the approval
/// record changes whether input is required, never whether the summary
/// appears.
#[derive(Debug)]
pub struct Gate {
    /// The grant summary, rendered. Always shown.
    pub shown: String,
    /// The prompt, when input is required.
    pub prompt: Option<String>,
    /// Why a resume's policy differs from the file's, when it does.
    ///
    /// Shown between the summary and the prompt: the summary says what the
    /// grants ARE, this says what changed about them.
    pub divergence: Option<String>,
    /// The summary itself, for a caller that needs to record it.
    pub summary: AccessSummary,
}

impl Gate {
    /// Whether the user must answer before anything starts.
    #[must_use]
    pub const fn needs_input(&self) -> bool {
        self.prompt.is_some()
    }
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

/// Deletes a running-record naming no live process.
///
/// Separate from [`already_running`] because that is a query and this is a
/// write — folding them together made a polling loop destroy the record it
/// was polling about.
///
/// `00` §5.2 makes `start` the command people type on `cd`, so a crash must
/// not leave an environment that refuses to start until a user finds and
/// deletes a file nobody told them about.
pub fn clear_stale_record(context: &Context) {
    let file = supervise::state_file(&context.paths());
    let stale = match std::fs::read_to_string(&file) {
        Ok(text) => Running::from_text(&text).is_ok_and(|recorded| {
            !recorded.processes.is_empty()
                && !recorded
                    .processes
                    .iter()
                    .any(|process| supervise::is_running(process.pid))
        }),
        Err(_) => false,
    };
    if stale {
        let _ = std::fs::remove_file(&file);
    }
}

/// Whether this project has approved anything on this machine before.
///
/// Read from the store, which `08` §3.1 makes a cache rather than truth —
/// and that is exactly the right status for this. It changes only the
/// *wording* of the gate, never whether the gate asks: delete the database
/// and a widened config is called a first run, which is conservative in the
/// safe direction.
///
/// # Errors
///
/// [`StartError::Store`] if the store cannot be opened or read.
pub fn history_of(context: &Context) -> Result<History, StartError> {
    let store = open_store(context)?;
    let ran_before = store
        .has_approved_anything()
        .map_err(|error| StartError::Store {
            why: error.to_string(),
        })?;
    Ok(if ran_before {
        History::RanBefore
    } else {
        History::Fresh
    })
}

/// How long `stop` waits for a guest to shut itself down before signalling.
///
/// Long enough for an init to unmount and sync a database, short enough
/// that a wedged guest does not make `rachna stop` feel broken. `05` §5
/// measured 6.97 s to boot a real NixOS guest; shutdown is the cheaper
/// direction.
const GRACEFUL_STOP: std::time::Duration = std::time::Duration::from_secs(20);

/// Whether a snapshot is waiting, and whether its policy is still the
/// file's.
///
/// `start` is also `resume` — there is no second verb — so this is what
/// gives resume the gate that `00` §3.10c requires. [`None`] means there is
/// no snapshot to come back to, which is a cold start and not a problem.
///
/// # Why the fingerprint is read from a file beside the snapshot
///
/// A snapshot has to carry the grant set it was **taken** under, and the
/// approval store only knows the set the file has **now**. Comparing the
/// file against itself would always say "unchanged" and the resume gate
/// would be unfalsifiable — exactly the design smell AGENTS.md names. So the
/// fingerprint is recorded next to the memory image when the snapshot is
/// written, and read back here.
///
/// A snapshot directory with no fingerprint file is
/// [`ResumeApproval::Unrecorded`], not "fine": it is either a snapshot from
/// before this field existed or one whose record was removed, and both
/// answer "ask".
///
/// # Errors
///
/// [`StartError::Store`] only if the approval store cannot be read. A
/// missing or unreadable fingerprint is a verdict, not an error — refusing
/// to start because a sidecar file is corrupt would strand a user with a
/// perfectly restorable guest.
pub fn resume_verdict(
    context: &Context,
    policy: &Policy,
) -> Result<Option<crate::snapshot::ResumeApproval>, StartError> {
    let snapshot_dir = context.paths().snapshot_dir();
    // An EMPTY directory is not a snapshot. `layout.rs` creates
    // `snapshots/` as part of the project's durable tree, so its existence
    // says nothing — and treating it as a snapshot would gate every cold
    // start on a policy no snapshot was ever taken under, which is a prompt
    // the user cannot act on.
    if !snapshot_dir.is_dir() || !has_snapshot(&snapshot_dir) {
        return Ok(None);
    }

    let summary = AccessSummary::new(policy.tier, policy.profile, &policy.grants);
    let running = summary.fingerprint();
    let approved = approval_of(context, policy)?.permits_apply();

    let taken_with =
        std::fs::read_to_string(snapshot_dir.join(GRANT_FINGERPRINT_FILE)).unwrap_or_default();

    // Delegated to `snapshot.rs` rather than re-decided here: one place
    // answers "may this resume", and it is the place with the tests.
    Ok(Some(crate::snapshot::resume_approval(
        &taken_with,
        &running,
        approved,
    )))
}

/// Whether a snapshot directory actually holds one.
///
/// Any entry other than our own sidecar counts: the memory image, the
/// device config, whatever a backend writes. Deliberately not a list of
/// expected filenames — `24` §6's completeness check is the place that
/// knows those, and duplicating it here would mean two definitions of "a
/// snapshot exists" that can disagree.
fn has_snapshot(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.file_name() != std::ffi::OsStr::new(GRANT_FINGERPRINT_FILE))
    })
}

/// Records the grant set a snapshot is being taken under.
///
/// The writer for what [`resume_verdict`] reads. **Called when a snapshot is
/// written**, so that resuming it can tell whether `rachna.nix` has moved
/// since — without this, `taken_with` is always empty, every resume reports
/// [`ResumeApproval::Unrecorded`], and the gate degrades to "always ask"
/// rather than answering the question it was built for.
///
/// # Errors
///
/// [`StartError::Store`] if the file cannot be written. **Refused rather
/// than proceeding**: a snapshot whose grant set was not recorded resumes
/// unreviewable, and silently taking one would build the gap `25`-era work
/// found in the first place.
pub fn record_snapshot_grants(context: &Context, policy: &Policy) -> Result<(), StartError> {
    let dir = context.paths().snapshot_dir();
    std::fs::create_dir_all(&dir).map_err(|error| StartError::Store {
        why: format!("cannot create {}: {error}", dir.display()),
    })?;
    let summary = AccessSummary::new(policy.tier, policy.profile, &policy.grants);
    std::fs::write(dir.join(GRANT_FINGERPRINT_FILE), summary.fingerprint()).map_err(|error| {
        StartError::Store {
            why: format!("cannot record the snapshot's grant set: {error}"),
        }
    })
}

/// The file beside a snapshot recording the grant set it was taken under.
///
/// A plain file rather than a column in `rachna.db`, deliberately: `08` §3.1
/// makes the database a cache, and a cache that can be deleted must not be
/// the only record of what a snapshot was permitted. Delete the database and
/// the next resume still asks.
pub const GRANT_FINGERPRINT_FILE: &str = "grants.fingerprint";

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
    let recorded = match std::fs::read_to_string(&file) {
        Ok(text) => Running::from_text(&text)?,
        // No file means nothing started, which is the common case.
        Err(_) => return Ok(Running::nothing()),
    };

    // THE PIDS ARE CHECKED, not trusted. A state file outlives its
    // processes — a crash, a reboot, `kill -9` — and an unchecked record
    // means `start` refuses forever with "already running" against
    // nothing, which a user can only fix by finding and deleting a file
    // they were never told about.
    //
    // Found the other way round, too: a second `start` left TWO
    // supervisors running because nothing confirmed the first was alive
    // before deciding what to do.
    let live: Vec<_> = recorded
        .processes
        .into_iter()
        .filter(|process| supervise::is_running(process.pid))
        .collect();

    if live.is_empty() {
        // Stale. NOT deleted here, and that is the point: this function is
        // a QUERY, and `stop` polls it in a loop. Deleting the record as a
        // side effect of reading meant the first poll that saw the
        // supervisor momentarily gone destroyed the very record `stop`
        // then needed to signal it — measured: "stopped 0 process(es)"
        // with the supervisor still running.
        //
        // `clear_stale_record` does the deleting, called where a decision
        // is being made rather than where a question is being asked.
        return Ok(Running::nothing());
    }

    Ok(Running {
        processes: live,
        transient: recorded.transient,
    })
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

    // ASK FIRST, then signal. A macOS supervisor holds the guest inside
    // itself, so killing it is a power cut: measured, that left the state
    // volume with `EXT4-fs error … deleted inode referenced` on the next
    // boot. The request file lets the supervisor shut the guest down
    // through its init, and the signal below is still the guarantee that
    // `stop` stops things.
    if !running.is_empty() {
        let paths = context.paths();
        let request = supervise::shutdown_request(&paths);
        if std::fs::write(&request, b"stop\n").is_ok() {
            let deadline = std::time::Instant::now() + GRACEFUL_STOP;
            while std::time::Instant::now() < deadline {
                if already_running(context).map(|now| now.is_empty()) == Ok(true) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        let _ = std::fs::remove_file(&request);
    }

    // Re-read: the supervisor may have gone on its own, and signalling a
    // pid that has exited would report a survivor that never survived.
    let remaining = already_running(context)?;
    let mut report = supervise::stop(&remaining);

    // CREDIT THE GRACEFUL STOP. `supervise::stop` counts what IT
    // signalled, so a supervisor that shut down when asked left the report
    // saying "stopped 0 process(es)" — about a guest that had just stopped
    // correctly. A user reads that as a failure, and it sent me debugging
    // `stop` three times while the graceful path was working.
    for process in &running.processes {
        let signalled = report
            .stopped
            .iter()
            .chain(report.survived.iter().map(|(process, _)| process))
            .any(|already| already.pid == process.pid);
        if !signalled && !supervise::is_running(process.pid) {
            report.stopped.push(process.clone());
        }
    }
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
            History::Fresh,
            None,
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
        let gate = check(
            &policy,
            &tap::Capability::Present,
            Approval::Unseen,
            History::Fresh,
            None,
            false,
        )
        .expect("enforceable");
        assert!(gate.needs_input(), "an unapproved grant set did not ask");
        // The summary names what it is about to permit.
        assert!(gate.shown.contains("github.com"), "{}", gate.shown);
        // And the prompt names the command, per `00` §3.3.
        let prompt = gate.prompt.as_deref().expect("a prompt");
        assert!(prompt.contains("rachna start --accept"), "{prompt}");
        assert!(!gate.summary.is_empty());
    }

    #[test]
    fn a_config_granting_nothing_needs_no_acknowledgement() {
        // `00` §3.10c's gate exists so a user sees what they are about to
        // permit; an empty set has nothing to see. Found by RUNNING it: the
        // prompt said "needs no acknowledgement" and the gate refused
        // anyway — a message and a behaviour disagreeing.
        let sealed = policy(Tier::None, vec![]);
        let gate = check(
            &sealed,
            &tap::Capability::Present,
            Approval::Unseen,
            History::Fresh,
            None,
            false,
        )
        .expect("enforceable");
        assert!(
            !gate.needs_input(),
            "a config granting nothing asked for input"
        );
        // But the summary still prints — `00` §3.10c's "secrets none is
        // information" applies to the whole set.
        assert!(!gate.shown.is_empty(), "the summary was suppressed");
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
                History::Fresh,
                None,
                false
            )
            .expect("enforceable")
            .needs_input(),
            "a real grant set skipped the gate"
        );
    }

    #[test]
    fn an_approved_grant_set_proceeds() {
        // The positive path, so the two refusals above are not vacuous.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let gate = check(
            &policy,
            &tap::Capability::Present,
            Approval::Approved,
            History::Fresh,
            None,
            false,
        )
        .expect("enforceable");
        assert!(!gate.needs_input(), "an approved set asked again");
        // THE CORRECTION. An approved set still SHOWS its permissions:
        // `00` §3.10c's earlier "thereafter start is silent" made a second
        // start print nothing and launch, which is the behaviour this
        // assertion exists to prevent.
        assert!(
            gate.shown.contains("github.com"),
            "an approved start was silent about what it permits: {}",
            gate.shown
        );
    }

    #[test]
    fn a_sealed_policy_proceeds_without_the_network_capability() {
        // Most of what makes the refusal acceptable: a project wanting no
        // network must not be blocked by a capability it does not use.
        let policy = policy(Tier::None, vec![]);
        // `expect` IS the assertion: a sealed policy must be ENFORCEABLE
        // without the capability. It then asks for nothing, because an
        // approved empty grant set has nothing to review.
        let gate = check(
            &policy,
            &tap::Capability::Missing {
                helper: PathBuf::from("/x"),
            },
            Approval::Approved,
            History::Fresh,
            None,
            false,
        )
        .expect("sealed is enforceable without CAP_NET_ADMIN");
        assert!(
            !gate.needs_input(),
            "a sealed approved policy asked for input"
        );
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
                History::Fresh,
                None,
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
            check(
                &policy,
                &tap::Capability::Present,
                Approval::Unseen,
                History::Fresh,
                None,
                interactive,
            )
            .expect("enforceable")
            .prompt
            .expect("an unapproved set needs input")
        };
        assert!(rendered(true).contains("[a] accept all"));
        assert!(rendered(false).contains("rachna start --accept"));
    }

    #[test]
    fn the_header_does_not_call_an_approved_start_a_first_run() {
        // Found by RUNNING `start` twice. The summary's header was the
        // hardcoded "rachna.nix grants, first run:", which was true exactly
        // once and became a lie on every later start the moment `00` §3.10c
        // made the summary unconditional.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let rendered = |approval: Approval| -> String {
            check(
                &policy,
                &tap::Capability::Present,
                approval,
                History::Fresh,
                None,
                false,
            )
            .expect("enforceable")
            .shown
        };

        // First assert the first-run wording EXISTS, or the negative below
        // would pass against a header that said nothing at all.
        let unseen = rendered(Approval::Unseen);
        assert!(unseen.contains("first run"), "{unseen}");

        let approved = rendered(Approval::Approved);
        assert!(
            !approved.contains("first run"),
            "an approved start was told it had never run here: {approved}"
        );
        // And it still says what the grants ARE, which is the whole point.
        assert!(approved.contains("github.com"), "{approved}");
    }

    #[test]
    fn a_widened_config_is_not_told_it_has_never_run_here() {
        // Found by widening a real policy and reading the output: a config
        // that had run and been approved, then gained one host, was shown
        // "grants, first run:" and "this config has not run here before".
        // Both false. A user who knows better reads that as a bug, and a
        // gate the user does not believe is a gate that gets bypassed.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);

        // First assert the first-run wording EXISTS for a fresh project,
        // so the negative below is not vacuous.
        let fresh = check(
            &policy,
            &tap::Capability::Present,
            Approval::Unseen,
            History::Fresh,
            None,
            false,
        )
        .expect("enforceable");
        let fresh_prompt = fresh.prompt.as_deref().expect("a prompt");
        assert!(fresh.shown.contains("first run"), "{}", fresh.shown);
        assert!(
            fresh_prompt.contains("has not run here before"),
            "{fresh_prompt}"
        );

        // The same unapproved set, in a project that HAS approved before.
        let widened = check(
            &policy,
            &tap::Capability::Present,
            Approval::Unseen,
            History::RanBefore,
            None,
            false,
        )
        .expect("enforceable");
        assert!(
            widened.needs_input(),
            "a widened grant set skipped the gate"
        );
        let prompt = widened.prompt.as_deref().expect("a prompt");
        assert!(
            !prompt.contains("has not run here before"),
            "a config that had run here was told it had not: {prompt}"
        );
        assert!(
            !widened.shown.contains("first run"),
            "a widened config was called a first run: {}",
            widened.shown
        );
        // And it says what IS true, per `00` §3.3 — a message that names no
        // reason is not actionable.
        assert!(prompt.contains("more than you approved"), "{prompt}");
    }

    #[test]
    fn the_header_and_the_prompt_agree_about_why_the_gate_asks() {
        // They are derived from ONE `Reason`, and this is what keeps that
        // true: they disagreed once, the header saying "first run" while
        // the config had plainly run here.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        for (history, in_header, in_prompt) in [
            (History::Fresh, "first run", "has not run here before"),
            (History::RanBefore, "widened", "more than you approved"),
        ] {
            let gate = check(
                &policy,
                &tap::Capability::Present,
                Approval::Unseen,
                history,
                None,
                false,
            )
            .expect("enforceable");
            assert!(
                gate.shown.contains(in_header),
                "{history:?}: {}",
                gate.shown
            );
            let prompt = gate.prompt.as_deref().expect("a prompt");
            assert!(prompt.contains(in_prompt), "{history:?}: {prompt}");
        }
    }

    #[test]
    fn an_approved_set_is_not_still_described_as_widened() {
        // Found by pressing `a` and running again: the header still read
        // "widened since you approved" for a set that had just BEEN
        // approved. `Widened` describes the state before the keypress.
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let rendered = |approval: Approval| -> String {
            check(
                &policy,
                &tap::Capability::Present,
                approval,
                History::RanBefore,
                None,
                false,
            )
            .expect("enforceable")
            .shown
        };

        // The wording EXISTS while unapproved, or the negative is vacuous.
        let before = rendered(Approval::Unseen);
        assert!(before.contains("widened"), "{before}");

        let after = rendered(Approval::Approved);
        assert!(
            !after.contains("widened"),
            "an approved set was still called widened: {after}"
        );
        assert!(after.contains("running under these grants"), "{after}");
    }

    // ---- resume goes through the SAME gate -------------------------------

    #[test]
    fn a_resume_whose_snapshot_predates_the_file_asks_even_when_approved() {
        // THE user-reported gap, at the layer below: `start` is also
        // `resume` (`cli.rs` help: "start or resume"), and a snapshot
        // carries the policy it was TAKEN under. Approving today's file
        // never reviewed yesterday's.
        use crate::snapshot::ResumeApproval;
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);

        // First assert what this attacks EXISTS: approved + no snapshot
        // asks nothing, so the resume verdict is the only variable.
        let plain = check(
            &policy,
            &tap::Capability::Present,
            Approval::Approved,
            History::Fresh,
            None,
            true,
        )
        .expect("enforceable");
        assert!(!plain.needs_input(), "the baseline already asked");

        let diverged = ResumeApproval::NeedsApproval {
            taken_with: "tier=open\nprofile=development\n".to_owned(),
            running: "tier=allowlist\nprofile=development\n".to_owned(),
        };
        let gate = check(
            &policy,
            &tap::Capability::Present,
            Approval::Approved,
            History::Fresh,
            Some(&diverged),
            true,
        )
        .expect("enforceable");
        assert!(
            gate.needs_input(),
            "a resume under a policy the snapshot never ran went unreviewed"
        );
        // And it says WHAT changed, not just that something did (`00` §3.3).
        let why = gate.divergence.as_deref().expect("a divergence note");
        assert!(why.contains("tier=open"), "{why}");
        assert!(why.contains("tier=allowlist"), "{why}");
    }

    #[test]
    fn a_resume_with_an_unrecorded_grant_set_asks_without_claiming_a_diff() {
        // A snapshot from before grant recording. The honest message has no
        // two sides to show, which is why `Unrecorded` is its own variant.
        use crate::snapshot::ResumeApproval;
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let gate = check(
            &policy,
            &tap::Capability::Present,
            Approval::Approved,
            History::Fresh,
            Some(&ResumeApproval::Unrecorded),
            true,
        )
        .expect("enforceable");
        assert!(
            gate.needs_input(),
            "an unrecorded grant set resumed unreviewed"
        );
        let why = gate.divergence.as_deref().expect("a divergence note");
        assert!(why.contains("predates grant recording"), "{why}");
    }

    #[test]
    fn an_unchanged_resume_still_prints_the_summary() {
        // The user's correction applied to resume: "same for resume". An
        // unchanged, approved snapshot needs no keypress — and must still
        // say what it is about to permit.
        use crate::snapshot::ResumeApproval;
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        let gate = check(
            &policy,
            &tap::Capability::Present,
            Approval::Approved,
            History::Fresh,
            Some(&ResumeApproval::Unchanged),
            true,
        )
        .expect("enforceable");
        assert!(!gate.needs_input(), "an unchanged resume asked again");
        assert!(
            gate.shown.contains("github.com"),
            "a resume was silent about what it permits: {}",
            gate.shown
        );
        // Nothing changed, so there is nothing to explain.
        assert!(gate.divergence.is_none(), "{:?}", gate.divergence);
    }

    // ---- what is actually running ----------------------------------------

    #[test]
    fn a_stale_state_file_does_not_make_start_refuse_forever() {
        // A state file outlives its processes — a crash, a reboot, a
        // `kill -9`. Trusting it unchecked meant `start` reported "already
        // running" against nothing, and the only fix was deleting a file
        // the user was never told about.
        let context = context("stale");
        let paths = context.paths();
        std::fs::create_dir_all(paths.runtime_dir()).expect("dirs");

        // A pid that cannot be alive: pid 0 is never a user process, and
        // `is_running` rejects it without signalling anything.
        let record = supervise::Running {
            processes: vec![supervise::Supervised {
                role: supervise::Role::Supervisor,
                pid: 0,
            }],
            transient: Vec::new(),
        };
        let file = supervise::state_file(&paths);
        std::fs::write(&file, record.to_text()).expect("write the stale record");

        // First assert the record EXISTS and parses, or this proves
        // nothing about liveness filtering.
        assert!(
            !supervise::Running::from_text(&std::fs::read_to_string(&file).expect("read"))
                .expect("parses")
                .is_empty(),
            "the fixture did not write a non-empty record"
        );

        let running = already_running(&context).expect("readable");
        assert!(
            running.is_empty(),
            "a dead pid was reported as running: {running:?}"
        );
        // The file is STILL THERE: reading is a query. `stop` polls this
        // in a loop, and deleting as a side effect of reading destroyed
        // the record `stop` then needed to signal.
        assert!(
            file.exists(),
            "reading the record deleted it, which breaks stop's polling loop"
        );

        // `clear_stale_record` is what deletes, and it is called where a
        // decision is made rather than where a question is asked.
        clear_stale_record(&context);
        assert!(
            !file.exists(),
            "the stale state file was left behind at {}",
            file.display()
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn a_live_process_is_still_reported_as_running() {
        // The other half, so the liveness filter cannot simply report
        // "nothing is running" and pass the test above. Our own pid is the
        // one process guaranteed to be alive.
        let context = context("live");
        let paths = context.paths();
        std::fs::create_dir_all(paths.runtime_dir()).expect("dirs");

        let record = supervise::Running {
            processes: vec![supervise::Supervised {
                role: supervise::Role::Supervisor,
                pid: std::process::id(),
            }],
            transient: Vec::new(),
        };
        std::fs::write(supervise::state_file(&paths), record.to_text()).expect("write");

        let running = already_running(&context).expect("readable");
        assert!(
            !running.is_empty(),
            "a live process was reported as not running"
        );
        assert_eq!(running.processes.len(), 1);

        // And `clear_stale_record` leaves it alone. If it did not, `stop`
        // would delete the record of the thing it is about to signal.
        clear_stale_record(&context);
        assert!(
            supervise::state_file(&paths).exists(),
            "a LIVE record was cleared as stale"
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    // ---- the snapshot's own grant record ---------------------------------

    #[test]
    fn a_cold_start_is_not_gated_by_an_empty_snapshot_directory() {
        // `layout.rs` creates `snapshots/` as part of the durable tree, so
        // its EXISTENCE says nothing. Treating it as a snapshot would gate
        // every cold start on a policy no snapshot was taken under — a
        // prompt about a diff that does not exist.
        let context = context("cold");
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        std::fs::create_dir_all(context.paths().snapshot_dir()).expect("dirs");

        assert_eq!(
            resume_verdict(&context, &policy).expect("readable"),
            None,
            "an empty snapshots/ directory was treated as a snapshot"
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn a_snapshot_taken_and_resumed_under_the_same_policy_needs_no_keypress() {
        // The round trip through the real filesystem: record, then read
        // back. This is what makes the resume gate falsifiable — without a
        // writer, `taken_with` is always empty, every resume reports
        // `Unrecorded`, and "always asks" would look like it worked.
        let context = context("warm");
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        accept(&context, &policy, 1).expect("approve");
        record_snapshot_grants(&context, &policy).expect("record");
        // A snapshot file, so the directory holds more than our sidecar.
        std::fs::write(context.paths().snapshot_dir().join("memory.img"), b"x")
            .expect("snapshot file");

        assert_eq!(
            resume_verdict(&context, &policy).expect("readable"),
            Some(crate::snapshot::ResumeApproval::Unchanged),
            "an unchanged, approved snapshot asked anyway"
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn a_snapshot_resumed_under_a_changed_policy_asks_and_names_both_sides() {
        // THE case the whole resume gate exists for: `git pull` changed
        // `rachna.nix`, and yesterday's guest is about to come back.
        let context = context("changed");
        let taken_under = policy(Tier::Allowlist, vec![network("github.com")]);
        record_snapshot_grants(&context, &taken_under).expect("record");
        std::fs::write(context.paths().snapshot_dir().join("memory.img"), b"x")
            .expect("snapshot file");

        // The file now grants more, and that wider set is itself approved —
        // so only the SNAPSHOT's divergence can make this ask.
        let now = policy(
            Tier::Allowlist,
            vec![network("github.com"), network("evil.test")],
        );
        accept(&context, &now, 2).expect("approve the wider set");

        let verdict = resume_verdict(&context, &now)
            .expect("readable")
            .expect("a snapshot is present");
        let crate::snapshot::ResumeApproval::NeedsApproval {
            taken_with,
            running,
        } = &verdict
        else {
            panic!("a resume under a changed policy went unreviewed: {verdict:?}")
        };
        assert_ne!(taken_with, running, "the two sides were identical");
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    #[test]
    fn a_snapshot_whose_grant_record_was_deleted_asks_rather_than_assuming() {
        // The adversarial case. The record is a plain file, so anyone can
        // remove it — and `08` §3.1 makes the store a cache precisely
        // because deleting state must not grant anything. Deleting this
        // must make the gate ASK, never wave the resume through.
        let context = context("deleted");
        let policy = policy(Tier::Allowlist, vec![network("github.com")]);
        accept(&context, &policy, 1).expect("approve");
        record_snapshot_grants(&context, &policy).expect("record");
        std::fs::write(context.paths().snapshot_dir().join("memory.img"), b"x")
            .expect("snapshot file");

        // First assert what this attacks EXISTS: with the record present
        // and the policy unchanged, the resume is silent.
        assert_eq!(
            resume_verdict(&context, &policy).expect("readable"),
            Some(crate::snapshot::ResumeApproval::Unchanged),
            "the baseline already asked, so deleting proves nothing"
        );

        std::fs::remove_file(context.paths().snapshot_dir().join(GRANT_FINGERPRINT_FILE))
            .expect("delete the record");

        assert_eq!(
            resume_verdict(&context, &policy).expect("readable"),
            Some(crate::snapshot::ResumeApproval::Unrecorded),
            "deleting the grant record let a snapshot resume unreviewed"
        );
        let _ = std::fs::remove_dir_all(context.rachna_root.parent().expect("parent"));
    }

    // ---- the approval record -------------------------------------------

    #[test]
    fn accepting_records_the_grant_set_and_a_later_start_proceeds() {
        // End to end through the real store: the gate asks once and not
        // again. NOT "thereafter start is silent" — `00` §3.10c rejects
        // that — the summary still prints; only the keypress is dropped.
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
        let after = check(
            &policy,
            &tap::Capability::Present,
            approval_of(&context, &policy).expect("readable"),
            History::Fresh,
            None,
            false,
        )
        .expect("enforceable");
        assert!(!after.needs_input(), "an accepted grant set asked again");
        // And it is STILL not silent, which is the correction.
        assert!(
            after.shown.contains("github.com"),
            "an accepted start stopped naming its permissions: {}",
            after.shown
        );
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
