//! Spawning and tracking the processes a guest needs.
//!
//! **The seam `01` §7.0b identified.** Every decision layer was built and
//! tested, and `grep 'Command::new'` across `src/` returned three hits — all
//! `codesign`. `Launch::args()` built Cloud Hypervisor's exact argument list,
//! a hand-run copy of that list booted a guest (`24` §7), and no code ever
//! ran it.
//!
//! # Why a supervisor and not a function call
//!
//! A guest is **two or more processes with an ordering constraint**, and
//! `16` §5.2 measured what happens when that is got wrong: restore failed
//! with `vhost-user: can't connect to peer: Connection refused`, because the
//! virtiofsd daemons had exited with the original VM while the snapshot
//! recorded their socket paths. The failure *reads as a networking fault*.
//!
//! So three rules, each from a measurement rather than from tidiness:
//!
//! 1. **virtiofsd before Cloud Hypervisor**, and CH does not start until the
//!    socket exists. `04` §4.1 and `16` §5.2: CH connects to the socket at
//!    launch, so a race here is a boot failure.
//! 2. **Every PID is recorded where `stop` can find it.** `24` §6a cost real
//!    time to a VM that outlived its shell, and the fix is not discipline —
//!    it is that the PID is written down.
//! 3. **Teardown is reverse order and unconditional.** CH first, then
//!    virtiofsd, then the socket files, whether or not each step succeeded.
//!    A half-stopped environment is what leaves the stale socket `24` §6
//!    lost 477 seconds to.
//!
//! # What this module does not do
//!
//! It holds no policy. `decide.rs` decides, `tap.rs` refuses an unenforceable
//! network, `lifecycle.rs` says which transitions are legal — and this
//! executes what they permit. That split is why the whole decision layer was
//! testable without a hypervisor (`01` §7's "no step needs a hypervisor until
//! step 7").

use crate::layout::ProjectPaths;
use core::fmt;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long to wait for a virtiofsd socket before giving up.
///
/// `24` §6 measured a **477-second** timeout caused by a *stale* socket, which
/// is the opposite failure: waiting for something that will never appear. A
/// bounded wait turns that into a message. Ten seconds is generous — the
/// socket appeared in well under one in every measured run — and the cost of
/// being wrong is a retry rather than a hang.
pub const SOCKET_WAIT: Duration = Duration::from_secs(10);

/// How often to look for it.
pub const SOCKET_POLL: Duration = Duration::from_millis(25);

/// One process this guest depends on.
///
/// Named rather than anonymous because `stop` has to report what it could
/// not kill, and "a process" is not something a user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supervised {
    /// What it is, for messages and for the state file.
    pub role: Role,
    /// The process id.
    pub pid: u32,
}

/// What a supervised process is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// `virtiofsd`, serving one share.
    ///
    /// Ordered **before** the hypervisor deliberately: `Ord` is what gives
    /// start and stop their sequence, so the ordering constraint lives in the
    /// type rather than in each call site remembering it.
    Virtiofsd,
    /// `cloud-hypervisor`.
    Hypervisor,
}

impl Role {
    /// Every role, in **start** order.
    pub const START_ORDER: [Self; 2] = [Self::Virtiofsd, Self::Hypervisor];

    /// The name a user sees.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Virtiofsd => "virtiofsd",
            Self::Hypervisor => "cloud-hypervisor",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything `stop` needs to tear down what `start` began.
///
/// Written to disk, because `start` and `stop` are **different processes**.
/// `01` §7.0b: *"nothing persists state between invocations, so `stop` cannot
/// find what `start` began."*
///
/// Deliberately small and append-only in spirit: a PID, a role, and the paths
/// to unlink. Anything derivable from `rachna.nix` or `layout.rs` is **not**
/// stored, so this file cannot disagree with them — the same reason
/// `layout.rs` derives paths rather than recording them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    /// The processes, in start order.
    pub processes: Vec<Supervised>,
    /// Sockets and other files to unlink on teardown.
    pub transient: Vec<PathBuf>,
}

impl Running {
    /// An empty record: nothing is running.
    #[must_use]
    pub fn nothing() -> Self {
        Self {
            processes: Vec::new(),
            transient: Vec::new(),
        }
    }

    /// Whether anything is supervised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    /// The teardown order: the reverse of start.
    ///
    /// Cloud Hypervisor before virtiofsd, because CH holds the vhost-user
    /// connection and killing its server first leaves it writing into a dead
    /// socket. Derived from `Role`'s `Ord` rather than written out, so the
    /// two orders cannot drift apart.
    #[must_use]
    pub fn stop_order(&self) -> Vec<&Supervised> {
        let mut out: Vec<&Supervised> = self.processes.iter().collect();
        // `Reverse` rather than a flipped comparator, so the intent —
        // reverse of start order — reads directly.
        out.sort_by_key(|process| core::cmp::Reverse(process.role));
        out
    }

    /// Serialises to the state file's one-record-per-line format.
    ///
    /// Plain text rather than JSON, and that is a deliberate trade: this file
    /// is read by `stop` when something has already gone wrong, so a human
    /// reading it with `cat` is worth more than a parser being elegant. The
    /// format is `role pid` and `unlink path`, one per line.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for process in &self.processes {
            out.push_str(&format!("{} {}\n", process.role.as_str(), process.pid));
        }
        for path in &self.transient {
            out.push_str(&format!("unlink {}\n", path.display()));
        }
        out
    }

    /// Reads the state file back.
    ///
    /// # Errors
    ///
    /// [`StateError`] naming the line that could not be read. **A malformed
    /// line is an error, not a skipped record** — skipping it would mean
    /// `stop` silently leaving a process running, which is `24` §6a's leak
    /// with a mechanism instead of an accident.
    pub fn from_text(text: &str) -> Result<Self, StateError> {
        let mut processes = Vec::new();
        let mut transient = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let number = index + 1;
            let Some((head, rest)) = line.split_once(' ') else {
                return Err(StateError {
                    line: number,
                    text: line.to_owned(),
                });
            };
            match head {
                "unlink" => transient.push(PathBuf::from(rest)),
                "virtiofsd" | "cloud-hypervisor" => {
                    let role = if head == "virtiofsd" {
                        Role::Virtiofsd
                    } else {
                        Role::Hypervisor
                    };
                    let pid: u32 = rest.parse().map_err(|_| StateError {
                        line: number,
                        text: line.to_owned(),
                    })?;
                    processes.push(Supervised { role, pid });
                }
                _ => {
                    return Err(StateError {
                        line: number,
                        text: line.to_owned(),
                    })
                }
            }
        }
        Ok(Self {
            processes,
            transient,
        })
    }
}

/// A line of the state file that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError {
    /// 1-based, as a reader would count.
    pub line: usize,
    /// The line itself, so the message can show it.
    pub text: String,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the running-state file is corrupt at line {}: {:?}. \
             `rachna stop` cannot know what to tear down, so it refuses \
             rather than leaving a process running. Check for stray \
             cloud-hypervisor or virtiofsd processes, then delete the file",
            self.line, self.text
        )
    }
}

impl core::error::Error for StateError {}

/// Where the running-state file lives.
///
/// Under the runtime directory, so `layout.rs`'s rule applies: everything
/// there dies with the VM, and `stop` has one place to clear.
#[must_use]
pub fn state_file(paths: &ProjectPaths) -> PathBuf {
    paths.runtime_dir().join("running")
}

/// The ordered plan for starting a guest.
///
/// A value rather than a function that does it, so the *order* is testable
/// without spawning anything — which is the property that made every layer
/// below this one testable without a hypervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartPlan {
    /// Each process to launch, in order.
    pub steps: Vec<Step>,
}

/// One process to launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// What it is.
    pub role: Role,
    /// The binary to run.
    pub program: String,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// A path that must exist before the *next* step runs.
    ///
    /// `None` for the last step. This is rule 1 made explicit: CH must not
    /// start until virtiofsd's socket is there, and `16` §5.2 measured the
    /// `Connection refused` that results from getting it wrong.
    pub then_await: Option<PathBuf>,
}

impl StartPlan {
    /// Builds the plan for a launch with these shares.
    ///
    /// Takes the already-built argument lists rather than the `Launch`, so
    /// this module holds no knowledge of Cloud Hypervisor's flags —
    /// `backend/linux.rs` owns those, and duplicating them here is how two
    /// argument lists come to disagree.
    #[must_use]
    pub fn new(hypervisor_args: Vec<OsString>, shares: Vec<(PathBuf, Vec<OsString>)>) -> Self {
        let mut steps = Vec::new();
        for (socket, args) in shares {
            steps.push(Step {
                role: Role::Virtiofsd,
                program: "virtiofsd".to_owned(),
                args,
                // The socket this daemon creates. Nothing after it starts
                // until it exists.
                then_await: Some(socket),
            });
        }
        steps.push(Step {
            role: Role::Hypervisor,
            program: "cloud-hypervisor".to_owned(),
            args: hypervisor_args,
            then_await: None,
        });
        Self { steps }
    }

    /// Whether every virtiofsd precedes the hypervisor.
    ///
    /// The invariant rule 1 states, checked rather than trusted: a plan that
    /// started CH first would fail with `16` §5.2's misleading
    /// `Connection refused`, so it is worth asserting on the plan instead of
    /// debugging it on a boot.
    #[must_use]
    pub fn is_correctly_ordered(&self) -> bool {
        let hypervisor_at = self
            .steps
            .iter()
            .position(|step| step.role == Role::Hypervisor);
        match hypervisor_at {
            None => false,
            Some(at) => {
                self.steps[..at]
                    .iter()
                    .all(|step| step.role == Role::Virtiofsd)
                    && self.steps[at + 1..].is_empty()
            }
        }
    }
}

/// Why starting failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// A binary was not on `PATH`.
    ///
    /// Its own variant because the fix is installation, and `06` §5 makes
    /// `cloud-hypervisor` and `virtiofsd` package dependencies — so this
    /// means the package is broken or the user built from source.
    NotInstalled { program: String },
    /// A process exited before it was useful.
    Exited { role: Role, status: String },
    /// A socket never appeared.
    ///
    /// Carries the path, because `16` §5.2's whole lesson is that a socket
    /// failure does not describe itself.
    SocketTimeout { role: Role, socket: PathBuf },
    /// Spawning failed for another reason.
    Spawn { role: Role, why: String },
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled { program } => write!(
                f,
                "{program} is not on PATH. It is a package dependency \
                 (06 §5), so either the rachna package is incomplete or this \
                 is a source build — install it and try again"
            ),
            Self::Exited { role, status } => {
                write!(f, "{role} exited before the guest was ready: {status}")
            }
            Self::SocketTimeout { role, socket } => write!(
                f,
                "{role} did not create {} within {} seconds. Cloud \
                 Hypervisor connects to this socket at launch, so starting \
                 without it fails as `Connection refused`, which reads as a \
                 networking fault rather than a missing daemon (16 §5.2)",
                socket.display(),
                SOCKET_WAIT.as_secs()
            ),
            Self::Spawn { role, why } => write!(f, "could not start {role}: {why}"),
        }
    }
}

impl core::error::Error for StartError {}

/// What `stop` managed to do.
///
/// Reported rather than returned as a bare `Result`, because teardown is
/// **unconditional**: a failure to kill one process must not skip the next,
/// and the user needs to know which ones survived.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StopReport {
    /// Processes signalled successfully.
    pub stopped: Vec<Supervised>,
    /// Processes that could not be signalled, with why.
    pub survived: Vec<(Supervised, String)>,
    /// Files removed.
    pub unlinked: Vec<PathBuf>,
}

impl StopReport {
    /// Whether the environment is fully down.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.survived.is_empty()
    }
}

impl fmt::Display for StopReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_clean() {
            return write!(
                f,
                "stopped {} process(es), removed {} file(s)",
                self.stopped.len(),
                self.unlinked.len()
            );
        }
        writeln!(
            f,
            "✗ {} process(es) could not be stopped:",
            self.survived.len()
        )?;
        for (process, why) in &self.survived {
            writeln!(f, "  {} (pid {}): {why}", process.role, process.pid)?;
        }
        write!(
            f,
            "  these hold the guest's memory and sockets. `kill -9` them, \
             then `rachna stop` again"
        )
    }
}

/// Whether a path looks like a usable virtiofsd socket.
///
/// Checks it is a **socket**, not merely present. A regular file at that path
/// — a leftover, or a typo in a config — would satisfy an existence check and
/// then fail at connect time with `16` §5.2's misleading error.
#[must_use]
pub fn is_socket(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        metadata.file_type().is_socket()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Waits for `socket` to exist and be a socket.
///
/// Separated from the spawning so the timeout is testable with a path that
/// will never appear, without waiting the real ten seconds for it.
///
/// # Errors
///
/// [`StartError::SocketTimeout`] after [`SOCKET_WAIT`].
pub fn await_socket(role: Role, socket: &Path, budget: Duration) -> Result<(), StartError> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Ok(metadata) = std::fs::metadata(socket) {
            if is_socket(&metadata) {
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(StartError::SocketTimeout {
                role,
                socket: socket.to_path_buf(),
            });
        }
        std::thread::sleep(SOCKET_POLL);
    }
}

/// The child handles `start` keeps so `stop` can reap them.
///
/// **Measured, and this is why the type exists.** A child we spawned and
/// never `wait()` on becomes a **zombie** when it exits: its pid stays
/// valid, so `test_kill_process` succeeds and the process looks alive. The
/// first version of this module had no handles and its round-trip test
/// failed with *"virtiofsd (pid 95045) survived stop"* — a correct signal
/// reported as a failure.
///
/// So the supervisor holds the handles for as long as it runs. `stop` in a
/// *later* process cannot reap (the child is not its own), but that case is
/// different: a child whose parent exited is re-parented to init, which
/// reaps it. The zombie only appears while the parent is alive, which is
/// exactly the in-process case.
#[derive(Debug, Default)]
pub struct Children {
    handles: Vec<(u32, std::process::Child)>,
}

impl Children {
    /// Reaps any of `pids` this supervisor spawned.
    ///
    /// Called after signalling, so a `wait` does not block on a process that
    /// has not been asked to exit.
    pub fn reap(&mut self, pid: u32) {
        if let Some(at) = self.handles.iter().position(|(known, _)| *known == pid) {
            let (_, mut child) = self.handles.swap_remove(at);
            // The signal has already been sent; this only collects the
            // status so the pid is released.
            let _ = child.wait();
        }
    }

    /// Whether this supervisor spawned `pid`.
    #[must_use]
    pub fn owns(&self, pid: u32) -> bool {
        self.handles.iter().any(|(known, _)| *known == pid)
    }
}

/// Runs a [`StartPlan`], returning what to record for `stop`.
///
/// **This is the function `01` §7.0b said did not exist.** Everything below
/// it was built and tested; nothing called `Command::new`.
///
/// # Errors
///
/// [`StartError`] naming the process and the fix. **Already-started
/// processes are killed before returning**, so a failure halfway leaves
/// nothing behind — `24` §6a measured what the alternative costs.
///
/// # Why the plan is a value and this takes it
///
/// The ordering is testable without spawning ([`StartPlan`]'s tests), and
/// this function is the only part that needs a real system. That split is
/// what let `16` §5.2's ordering rule be checked in CI rather than on a boot.
pub fn start(plan: &StartPlan, runtime_dir: &Path) -> Result<(Running, Children), StartError> {
    // The runtime directory must exist before anything writes a socket into
    // it. `layout.rs` derives the path; nothing creates it.
    if let Err(error) = std::fs::create_dir_all(runtime_dir) {
        return Err(StartError::Spawn {
            role: Role::Virtiofsd,
            why: format!("cannot create {}: {error}", runtime_dir.display()),
        });
    }

    let mut running = Running::nothing();
    let mut children = Children::default();
    for step in &plan.steps {
        let spawned = std::process::Command::new(&step.program)
            .args(&step.args)
            // Inherit nothing: a daemon holding the terminal would make
            // `rachna start` unable to return, and CH's own output goes to
            // the serial log (`05` §4.3) rather than stdout.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        let child = match spawned {
            Ok(child) => child,
            Err(error) => {
                // Clean up what already started, then report. A partial
                // launch left running is `24` §6a's leak.
                let _ = stop_with(&running, &mut children);
                return Err(if error.kind() == std::io::ErrorKind::NotFound {
                    StartError::NotInstalled {
                        program: step.program.clone(),
                    }
                } else {
                    StartError::Spawn {
                        role: step.role,
                        why: error.to_string(),
                    }
                });
            }
        };

        let pid = child.id();
        children.handles.push((pid, child));
        running.processes.push(Supervised {
            role: step.role,
            pid,
        });

        if let Some(socket) = &step.then_await {
            running.transient.push(socket.clone());
            if let Err(error) = await_socket(step.role, socket, SOCKET_WAIT) {
                let _ = stop_with(&running, &mut children);
                return Err(error);
            }
        }
    }
    Ok((running, children))
}

/// Tears down everything in `running`, in reverse start order.
///
/// **Unconditional**: a failure to signal one process does not skip the
/// next, and the report names what survived. `24` §6a's leak was a VM nobody
/// knew about; a stop that gave up halfway would be the same thing with our
/// name on it.
#[must_use]
pub fn stop(running: &Running) -> StopReport {
    stop_with(running, &mut Children::default())
}

/// Tears down `running`, reaping any children this process spawned.
///
/// The variant `start`'s own caller uses. Separate from [`stop`] because a
/// `rachna stop` in a *later* process has no handles to reap — and passing
/// an empty [`Children`] there is correct rather than a shortcut, since a
/// child whose parent has exited is re-parented to init and reaped by it.
#[must_use]
pub fn stop_with(running: &Running, children: &mut Children) -> StopReport {
    let mut report = StopReport::default();

    for process in running.stop_order() {
        match signal_term(process.pid) {
            Ok(()) => {
                // Reap BEFORE reporting success: an unreaped child becomes a
                // zombie whose pid still answers `test_kill_process`, which
                // is how the first version of this reported a correctly
                // signalled process as having survived.
                children.reap(process.pid);
                report.stopped.push(process.clone());
            }
            Err(why) => report.survived.push((process.clone(), why)),
        }
    }

    // Sockets last, and only after the processes holding them are gone —
    // unlinking first would leave a running daemon serving a path nothing
    // can reach, which is how a stale socket becomes `24` §6's 477-second
    // timeout on the NEXT start.
    for path in &running.transient {
        if std::fs::remove_file(path).is_ok() {
            report.unlinked.push(path.clone());
        }
    }
    report
}

/// Signals a process to exit.
///
/// `SIGTERM`, then `SIGKILL` if it is still there — a hypervisor given no
/// chance to flush is how a snapshot ends up two-of-three, which `24` §6
/// measured restoring with no error at all.
fn signal_term(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use rustix::process::{kill_process, test_kill_process, Pid, Signal};

        let raw = i32::try_from(pid).map_err(|_| format!("pid {pid} is out of range"))?;
        let target = Pid::from_raw(raw).ok_or_else(|| format!("pid {pid} is not a process"))?;

        match kill_process(target, Signal::TERM) {
            Ok(()) => {}
            // Already gone is success: the goal is "not running", not "I was
            // the one who stopped it". A stop that failed because the VM had
            // already crashed would leave a user unable to start again.
            Err(rustix::io::Errno::SRCH) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }

        // Give it a second to exit cleanly before insisting. A hypervisor
        // killed mid-write is how a snapshot ends up two-of-three, which
        // `24` §6 measured restoring with NO ERROR AT ALL.
        for _ in 0..GRACE_POLLS {
            std::thread::sleep(GRACE_POLL);
            if test_kill_process(target).is_err() {
                return Ok(());
            }
        }
        // It ignored SIGTERM. The alternative to SIGKILL is leaving a VM
        // holding the guest's memory, which `24` §6a measured at ~1 GiB for
        // hours.
        let _ = kill_process(target, Signal::KILL);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err("process control is Unix-only".to_owned())
    }
}

/// How many times to check whether a `SIGTERM`ed process has gone.
const GRACE_POLLS: u32 = 40;

/// How long between those checks — one second of grace in total.
const GRACE_POLL: Duration = Duration::from_millis(25);

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    fn plan_with_one_share() -> StartPlan {
        StartPlan::new(
            args(&["--kernel", "/b/vmlinux"]),
            vec![(
                PathBuf::from("/run/vfs-workspace.sock"),
                args(&["--socket-path", "/run/vfs-workspace.sock"]),
            )],
        )
    }

    // ---- the ordering 16 §5.2 measured --------------------------------

    #[test]
    fn virtiofsd_starts_before_the_hypervisor() {
        // `16` §5.2: CH connects to the socket at launch, so starting it
        // first fails with `vhost-user: can't connect to peer: Connection
        // refused` — which reads as a NETWORKING fault rather than a
        // missing daemon. Asserting on the plan beats debugging a boot.
        let plan = plan_with_one_share();
        assert!(plan.is_correctly_ordered());
        assert_eq!(plan.steps[0].role, Role::Virtiofsd);
        assert_eq!(plan.steps[1].role, Role::Hypervisor);
    }

    #[test]
    fn every_share_precedes_the_hypervisor() {
        // `16` §5.2 "applies four times" for a four-share guest, so the
        // property is about ALL of them rather than the first.
        let shares: Vec<(PathBuf, Vec<OsString>)> = ["workspace", "state", "cache", "secrets"]
            .iter()
            .map(|tag| {
                let socket = PathBuf::from(format!("/run/vfs-{tag}.sock"));
                (socket.clone(), args(&["--socket-path"]))
            })
            .collect();
        let plan = StartPlan::new(args(&["--kernel", "/b/vmlinux"]), shares);
        assert!(plan.is_correctly_ordered());
        assert_eq!(plan.steps.len(), 5);
        assert_eq!(
            plan.steps.last().expect("a last step").role,
            Role::Hypervisor
        );
    }

    #[test]
    fn a_misordered_plan_is_detectable() {
        // First assert the thing under attack exists: the correct plan
        // passes. Otherwise a predicate returning `false` always would
        // satisfy this test.
        assert!(plan_with_one_share().is_correctly_ordered());

        let mut wrong = plan_with_one_share();
        wrong.steps.reverse();
        assert!(
            !wrong.is_correctly_ordered(),
            "the hypervisor was allowed to start before virtiofsd"
        );

        // And a plan with no hypervisor at all is not "correctly ordered"
        // either — it would start a daemon and no guest.
        let no_vm = StartPlan {
            steps: vec![plan_with_one_share().steps[0].clone()],
        };
        assert!(!no_vm.is_correctly_ordered());
    }

    #[test]
    fn each_share_names_the_socket_the_next_step_waits_for() {
        // Rule 1 made explicit: the wait target is carried on the step
        // rather than re-derived, so the thing that is waited for cannot
        // differ from the thing virtiofsd was told to create.
        let plan = plan_with_one_share();
        assert_eq!(
            plan.steps[0].then_await,
            Some(PathBuf::from("/run/vfs-workspace.sock"))
        );
        // The last step waits for nothing.
        assert_eq!(plan.steps[1].then_await, None);
    }

    // ---- teardown is reverse order -----------------------------------

    #[test]
    fn stopping_goes_hypervisor_first_then_virtiofsd() {
        // CH holds the vhost-user connection; killing its server first
        // leaves it writing into a dead socket. Derived from `Role`'s `Ord`
        // so the two orders cannot drift.
        let running = Running {
            processes: vec![
                Supervised {
                    role: Role::Virtiofsd,
                    pid: 100,
                },
                Supervised {
                    role: Role::Hypervisor,
                    pid: 200,
                },
            ],
            transient: vec![],
        };
        let order: Vec<Role> = running.stop_order().iter().map(|p| p.role).collect();
        assert_eq!(order, vec![Role::Hypervisor, Role::Virtiofsd]);
    }

    #[test]
    fn the_stop_order_is_the_reverse_of_the_start_order() {
        // Stated as a property rather than two lists, so adding a role
        // cannot make them disagree.
        let running = Running {
            processes: Role::START_ORDER
                .iter()
                .enumerate()
                .map(|(i, role)| Supervised {
                    role: *role,
                    pid: 100 + u32::try_from(i).expect("a small index"),
                })
                .collect(),
            transient: vec![],
        };
        let stop: Vec<Role> = running.stop_order().iter().map(|p| p.role).collect();
        let mut expected: Vec<Role> = Role::START_ORDER.to_vec();
        expected.reverse();
        assert_eq!(stop, expected);
    }

    // ---- the state file start and stop share -------------------------

    #[test]
    fn the_running_record_round_trips() {
        // `start` and `stop` are different processes, so this file is the
        // only thing connecting them (`01` §7.0b).
        let running = Running {
            processes: vec![
                Supervised {
                    role: Role::Virtiofsd,
                    pid: 4242,
                },
                Supervised {
                    role: Role::Hypervisor,
                    pid: 4243,
                },
            ],
            transient: vec![PathBuf::from("/run/vfs-workspace.sock")],
        };
        let text = running.to_text();
        assert_eq!(Running::from_text(&text).expect("round trips"), running);
    }

    #[test]
    fn the_record_is_readable_with_cat() {
        // Plain text deliberately: this file is read when something has
        // already gone wrong, so a human reading it beats a parser being
        // elegant.
        let text = Running {
            processes: vec![Supervised {
                role: Role::Hypervisor,
                pid: 4243,
            }],
            transient: vec![PathBuf::from("/run/api.sock")],
        }
        .to_text();
        assert_eq!(text, "cloud-hypervisor 4243\nunlink /run/api.sock\n");
    }

    #[test]
    fn a_corrupt_line_is_an_error_not_a_skipped_process() {
        // THE property. Skipping a malformed line means `stop` silently
        // leaving a process running — `24` §6a's leak with a mechanism
        // instead of an accident.
        //
        // First assert the good case parses, so the failures below are not
        // vacuous.
        assert!(Running::from_text("cloud-hypervisor 1\n").is_ok());

        for (text, line) in [
            ("cloud-hypervisor\n", 1),
            ("cloud-hypervisor notanumber\n", 1),
            ("virtiofsd 1\nmystery 2\n", 2),
            ("virtiofsd 1\ncloud-hypervisor -5\n", 2),
        ] {
            let error = Running::from_text(text).expect_err("must refuse");
            assert_eq!(error.line, line, "{text:?} blamed the wrong line");
            // The message has to say what to do, since the user now has
            // possibly-orphaned processes.
            let message = error.to_string();
            assert!(message.contains("corrupt"), "{message}");
            assert!(message.contains("cloud-hypervisor"), "{message}");
        }
    }

    #[test]
    fn blank_lines_are_ignored_rather_than_fatal() {
        // A trailing newline or an editor's extra line must not make an
        // environment unstoppable.
        let running = Running::from_text("\nvirtiofsd 1\n\ncloud-hypervisor 2\n\n")
            .expect("blank lines are fine");
        assert_eq!(running.processes.len(), 2);
    }

    #[test]
    fn an_empty_record_means_nothing_is_running() {
        assert!(Running::nothing().is_empty());
        assert!(Running::from_text("").expect("empty is valid").is_empty());
    }

    #[test]
    fn the_state_file_lives_where_a_stop_clears() {
        // `layout.rs`'s rule: everything in the runtime directory dies with
        // the VM. A state file outside it would survive a stop and describe
        // processes that no longer exist.
        let project = crate::layout::ProjectId::new("app-a3f2").expect("valid");
        let paths = ProjectPaths::new(Path::new("/home/dev/.rachna"), &project);
        let file = state_file(&paths);
        assert!(file.starts_with(paths.runtime_dir()));
        assert!(!file.starts_with(paths.snapshot_dir()));
    }

    // ---- waiting for a socket ----------------------------------------

    #[test]
    fn a_socket_that_never_appears_times_out_with_the_path() {
        // `16` §5.2's lesson: the failure does not describe itself. A
        // timeout naming neither the daemon nor the path leaves the user
        // reading CH's `Connection refused` instead.
        let error = await_socket(
            Role::Virtiofsd,
            Path::new("/nonexistent/vfs.sock"),
            Duration::from_millis(60),
        )
        .expect_err("must time out");
        let message = error.to_string();
        assert!(message.contains("/nonexistent/vfs.sock"), "{message}");
        assert!(message.contains("virtiofsd"), "{message}");
        // And it explains why the downstream error is misleading.
        assert!(message.contains("Connection refused"), "{message}");
        assert!(message.contains("networking fault"), "{message}");
    }

    #[test]
    fn a_regular_file_is_not_accepted_as_a_socket() {
        // A leftover file, or a typo, would satisfy an existence check and
        // then fail at connect with `16` §5.2's misleading error. Checked
        // against a real file rather than mocked, because the thing being
        // tested is a filesystem predicate.
        let dir = std::env::temp_dir().join("rachna-socket-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let not_a_socket = dir.join("vfs.sock");
        std::fs::write(&not_a_socket, b"").expect("write");

        let metadata = std::fs::metadata(&not_a_socket).expect("stat");
        assert!(
            !is_socket(&metadata),
            "a regular file was accepted as a socket"
        );
        let error = await_socket(Role::Virtiofsd, &not_a_socket, Duration::from_millis(60))
            .expect_err("a regular file must not satisfy the wait");
        assert!(matches!(error, StartError::SocketTimeout { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_socket_satisfies_the_wait_immediately() {
        // The positive case, so the two rejections above are not vacuous —
        // a predicate returning false always would pass both.
        let dir = std::env::temp_dir().join("rachna-socket-ok");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("vfs.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");

        assert!(
            await_socket(Role::Virtiofsd, &path, Duration::from_millis(500)).is_ok(),
            "a real socket was not accepted"
        );

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- actually spawning and killing -------------------------------

    /// A plan that spawns real processes, using tools every host has.
    ///
    /// `sleep` stands in for virtiofsd and the hypervisor: the thing under
    /// test is the supervisor, not what it supervises. A test needing a real
    /// Cloud Hypervisor would not run in CI, and `01` §7's whole structure
    /// is that the layers below the backend are testable without one.
    fn sleeper_plan(socket: Option<PathBuf>) -> StartPlan {
        StartPlan {
            steps: vec![
                Step {
                    role: Role::Virtiofsd,
                    program: "sleep".to_owned(),
                    args: args(&["30"]),
                    then_await: socket,
                },
                Step {
                    role: Role::Hypervisor,
                    program: "sleep".to_owned(),
                    args: args(&["30"]),
                    then_await: None,
                },
            ],
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rachna-supervise-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn starting_spawns_every_step_and_stopping_kills_them() {
        // THE test this module exists for. `01` §7.0b: everything below was
        // built and tested and nothing called `Command::new`.
        let dir = scratch("roundtrip");
        let (running, mut children) =
            start(&sleeper_plan(None), &dir).expect("both sleepers start");

        assert_eq!(running.processes.len(), 2);
        // Both are genuinely alive — asserted, because a `start` that
        // returned PIDs without spawning would pass a weaker test.
        for process in &running.processes {
            assert!(
                is_alive(process.pid),
                "{} (pid {}) was not running after start",
                process.role,
                process.pid
            );
        }

        let report = stop_with(&running, &mut children);
        assert!(report.is_clean(), "{report}");
        assert_eq!(report.stopped.len(), 2);
        for process in &running.processes {
            assert!(
                !is_alive(process.pid),
                "{} (pid {}) survived stop",
                process.role,
                process.pid
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_binary_is_reported_as_not_installed() {
        // `06` §5 makes cloud-hypervisor and virtiofsd package
        // dependencies, so this means the package is broken or it is a
        // source build — a different fix from any other failure.
        let dir = scratch("missing");
        let plan = StartPlan {
            steps: vec![Step {
                role: Role::Hypervisor,
                program: "rachna-no-such-binary".to_owned(),
                args: vec![],
                then_await: None,
            }],
        };
        let error = start(&plan, &dir).expect_err("must fail");
        assert!(
            matches!(error, StartError::NotInstalled { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("not on PATH"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failure_halfway_leaves_nothing_running() {
        // `24` §6a measured a VM outliving its shell for hours, holding ~1
        // GiB. A `start` that failed on step two and left step one running
        // would be that leak with a mechanism instead of an accident.
        //
        // The first step writes a FILE and then sleeps; the second step's
        // binary does not exist. So the first is provably spawned when the
        // failure happens, and the file is a marker only this test creates.
        //
        // An earlier version counted `sleep` processes globally and was
        // FLAKY — other tests in this file spawn sleepers concurrently, so
        // `before`/`after` raced and the gate failed once. A test whose
        // result depends on what else is running measures the wrong thing.
        let dir = scratch("partial");
        let marker = dir.join("step-one-ran");
        let script = format!(
            "touch {}; exec sleep 30",
            marker.to_str().expect("utf8 temp path")
        );
        let plan = StartPlan {
            steps: vec![
                Step {
                    role: Role::Virtiofsd,
                    program: "sh".to_owned(),
                    args: args(&["-c", &script]),
                    then_await: None,
                },
                Step {
                    role: Role::Hypervisor,
                    program: "rachna-no-such-binary".to_owned(),
                    args: vec![],
                    then_await: None,
                },
            ],
        };

        // CONTROL FIRST: step one alone leaves a process running. Without
        // this the assertion below cannot tell cleanup from a step that
        // never started — and an earlier version failed exactly there,
        // because `start` kills step one faster than its `touch` lands.
        let control = StartPlan {
            steps: vec![plan.steps[0].clone()],
        };
        let (control_running, mut control_children) =
            start(&control, &dir).expect("step one alone starts");
        let pattern = marker.to_str().expect("utf8 temp path");
        for _ in 0..80 {
            if count_matching(pattern) > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            count_matching(pattern) > 0,
            "the control run left nothing behind, so this test proves nothing"
        );
        let _ = stop_with(&control_running, &mut control_children);
        std::thread::sleep(Duration::from_millis(200));

        // Now the real case: the same step one, with a step two that fails.
        let error = start(&plan, &dir).expect_err("the second step must fail");
        assert!(matches!(error, StartError::NotInstalled { .. }));

        std::thread::sleep(Duration::from_millis(300));
        let survivors = count_matching(pattern);
        assert_eq!(
            survivors, 0,
            "a process survived a failed start: {survivors} still matching"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_socket_that_never_appears_aborts_the_start_and_cleans_up() {
        // Rule 1 end to end: CH must not start until virtiofsd's socket
        // exists, and a socket that never appears must not leave the daemon
        // running while returning an error.
        let dir = scratch("nosocket");
        let plan = sleeper_plan(Some(dir.join("never-appears.sock")));

        let error = start(&plan, &dir).expect_err("the socket never appears");
        assert!(
            matches!(error, StartError::SocketTimeout { .. }),
            "{error:?}"
        );
        // And the hypervisor was never started: the error is about the
        // socket, not about CH.
        assert!(error.to_string().contains("virtiofsd"), "{error}");

        // Scoped to this test's own directory, for the same reason the
        // halfway test is: a global sleeper count races with sibling tests.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            count_matching(dir.to_str().expect("utf8")),
            0,
            "the daemon survived a socket timeout"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stopping_an_already_dead_process_is_not_a_failure() {
        // A VM that crashed must not make `rachna stop` fail, or the user
        // cannot start again. The goal is "not running", not "I stopped it".
        let dir = scratch("dead");
        let (running, mut children) = start(&sleeper_plan(None), &dir).expect("starts");
        assert!(stop_with(&running, &mut children).is_clean());
        // Stopping the same record twice: everything is already gone.
        let second = stop(&running);
        assert!(
            second.is_clean(),
            "stopping an already-stopped environment failed: {second}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stopping_removes_the_sockets_after_the_processes() {
        // Unlinking first would leave a running daemon serving a path
        // nothing can reach — which is how a stale socket becomes `24` §6's
        // 477-second timeout on the NEXT start.
        let dir = scratch("unlink");
        let socket = dir.join("vfs.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
        let plan = sleeper_plan(Some(socket.clone()));
        let (running, mut children) = start(&plan, &dir).expect("the socket already exists");
        drop(listener);

        assert!(socket.exists(), "fixture did not create the socket");
        let report = stop_with(&running, &mut children);
        assert!(report.unlinked.contains(&socket), "{report}");
        assert!(!socket.exists(), "the socket survived stop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_runtime_directory_is_created_rather_than_assumed() {
        // `layout.rs` derives the path and nothing creates it, so `start`
        // must — otherwise virtiofsd fails writing its socket into a
        // directory that does not exist.
        let dir = std::env::temp_dir().join("rachna-supervise-mkdir/nested/deep");
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("rachna-supervise-mkdir"));
        assert!(!dir.exists());

        let (running, mut children) =
            start(&sleeper_plan(None), &dir).expect("creates the directory");
        assert!(dir.exists(), "the runtime directory was not created");
        let _ = stop_with(&running, &mut children);
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("rachna-supervise-mkdir"));
    }

    /// Whether a pid is still running, via the same safe API `stop` uses.
    fn is_alive(pid: u32) -> bool {
        #[cfg(unix)]
        {
            use rustix::process::{test_kill_process, Pid};
            i32::try_from(pid)
                .ok()
                .and_then(Pid::from_raw)
                .is_some_and(|target| test_kill_process(target).is_ok())
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            false
        }
    }

    /// How many of this user's processes have `needle` in their command line.
    ///
    /// Scoped to a unique marker rather than counting `sleep` globally,
    /// because this file's other tests spawn sleepers concurrently and a
    /// global count raced. `-f` matches the full command line, and the
    /// pattern is a temp path no other process has.
    fn count_matching(needle: &str) -> usize {
        std::process::Command::new("pgrep")
            .args(["-u", &format!("{}", rustix::process::getuid().as_raw())])
            .arg("-f")
            .arg(needle)
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).lines().count())
            .unwrap_or(0)
    }

    // ---- what stop reports -------------------------------------------

    #[test]
    fn a_clean_stop_says_what_it_did() {
        let report = StopReport {
            stopped: vec![Supervised {
                role: Role::Hypervisor,
                pid: 1,
            }],
            survived: vec![],
            unlinked: vec![PathBuf::from("/run/api.sock")],
        };
        assert!(report.is_clean());
        let text = report.to_string();
        assert!(text.contains("stopped 1"), "{text}");
        assert!(text.contains("1 file"), "{text}");
    }

    #[test]
    fn a_surviving_process_is_named_with_what_to_do() {
        // `24` §6a: a VM that outlives its shell holds ~1 GiB and nothing
        // reports it. A stop that failed silently would be that leak with
        // our name on it.
        let report = StopReport {
            stopped: vec![],
            survived: vec![(
                Supervised {
                    role: Role::Hypervisor,
                    pid: 4243,
                },
                "Operation not permitted".to_owned(),
            )],
            unlinked: vec![],
        };
        assert!(!report.is_clean());
        let text = report.to_string();
        assert!(text.contains("4243"), "{text}");
        assert!(text.contains("Operation not permitted"), "{text}");
        assert!(text.contains("kill -9"), "{text}");
        // And it says WHY it matters, not just that it happened.
        assert!(text.contains("memory"), "{text}");
    }

    #[test]
    fn every_start_error_names_a_fix() {
        // `00` §3.3's rule applied to launch failures: a message that only
        // reports cannot be acted on.
        for error in [
            StartError::NotInstalled {
                program: "virtiofsd".to_owned(),
            },
            StartError::Exited {
                role: Role::Hypervisor,
                status: "exit status 1".to_owned(),
            },
            StartError::SocketTimeout {
                role: Role::Virtiofsd,
                socket: PathBuf::from("/run/vfs.sock"),
            },
            StartError::Spawn {
                role: Role::Hypervisor,
                why: "permission denied".to_owned(),
            },
        ] {
            let text = error.to_string();
            assert!(text.len() > 40, "{error:?} is too terse: {text}");
            // Each names the process it is about, which is the minimum for
            // a multi-process launch.
            assert!(
                text.contains("virtiofsd") || text.contains("cloud-hypervisor"),
                "{text} names no process"
            );
        }
    }
}
