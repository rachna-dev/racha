//! The in-guest agent: run what the host asks, report what happened.
//!
//! `transport.rs` and `protocol.rs` implement and test the wire format
//! against a mock. **This is the real end of that wire** — `01` §7.0b listed
//! it as one of four things standing between the parts and a usable tool.
//!
//! # The trust direction is the whole design
//!
//! `01` §2.5: the agent is **untrusted, enforced by types**. It runs *inside*
//! the guest, which is the thing being contained, so nothing it says may be
//! taken as authority. Two consequences this module is built around:
//!
//! - **It cannot send an `Exec`.** `transport.rs`'s `Side` enforces that on
//!   both send and receive, so an agent that tried would be refused by its
//!   own transport before the wire — and a compromised one cannot ask the
//!   host to run anything.
//! - **Its output is data, never instruction.** The host wraps what comes
//!   back in [`Untrusted`](crate::untrusted::Untrusted), so a guest that
//!   emits something policy-shaped cannot have it read as policy.
//!
//! # Why it is a loop over a stream rather than a service
//!
//! The transport is generic over `Read + Write`, so this works over vsock in
//! production and over a pipe in tests. That is what lets `01` §7's "no step
//! needs a hypervisor" hold one level further: the agent's behaviour is
//! testable without a VM, and `11` §7 is why that matters — two measurements
//! had to be redone host-side after the serial console proved unreliable.
//!
//! # What it deliberately does not do
//!
//! No policy. The host decides what may run and refuses what it cannot
//! enforce (`decide.rs`, `tap.rs`); the agent executes what arrives. An agent
//! that filtered would be a second policy engine inside the untrusted
//! boundary — the worst possible place for one.

use crate::protocol::{Exited, Kind};
use crate::transport::{Connection, TransportError};
use core::fmt;
use std::io::{Read, Write};

/// How much of a command's output to forward in one message.
///
/// The transport caps a body (`protocol.rs`), so output is chunked rather
/// than buffered whole: a command producing a gigabyte must not need a
/// gigabyte of guest memory to report it. `24` §7's guest runs with 2 GiB
/// total, and the overlay's writable half is RAM (`00` §7 Layer C).
pub const CHUNK: usize = 32 * 1024;

/// Why the agent stopped serving.
#[derive(Debug)]
pub enum AgentError {
    /// The host closed the connection.
    ///
    /// **Not an error in the usual sense** — it is how a session ends. Its
    /// own variant so a caller can exit zero rather than reporting a failure
    /// for the normal case.
    HostClosed,
    /// The transport failed.
    Transport(TransportError),
    /// A command could not be launched.
    ///
    /// Reported to the host as a non-zero exit rather than killing the
    /// agent: one bad command must not end the session, or a typo
    /// disconnects the editor.
    Spawn { command: String, why: String },
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostClosed => f.write_str("the host closed the connection"),
            Self::Transport(error) => write!(f, "transport: {error}"),
            Self::Spawn { command, why } => {
                write!(f, "could not run {command:?}: {why}")
            }
        }
    }
}

impl core::error::Error for AgentError {}

impl From<TransportError> for AgentError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// What the agent did with one request, for tests and for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Served {
    /// A command ran; this is its exit code.
    Executed { exit_code: i32 },
    /// A `Ping` was answered.
    Ponged,
    /// The host closed the connection.
    Closed,
}

/// Runs one request from the host.
///
/// Separated from the serving loop so a single exchange is testable without
/// a connection that has to be closed to end the test.
///
/// # Errors
///
/// [`AgentError`] if the transport fails. A command that *cannot be launched*
/// is **not** an error here: it is reported to the host as a non-zero exit,
/// because one bad command must not end the session.
pub fn serve_one<S: Read + Write>(
    connection: &mut Connection<S>,
    run: &mut impl FnMut(&str) -> Result<Output, String>,
) -> Result<Served, AgentError> {
    let request = match connection.receive() {
        Ok(message) => message,
        // A clean close is how a session ends, not a failure.
        Err(TransportError::Closed) => return Ok(Served::Closed),
        Err(error) => return Err(error.into()),
    };

    match request.kind {
        Kind::Ping => {
            connection.send(Kind::Pong, &[])?;
            Ok(Served::Ponged)
        }
        Kind::Exec => {
            // The body is bytes from the host. Lossy is correct *here* and
            // only here: this is a command line the host composed, not a
            // path. `17` §1 forbids lossy conversion for paths because it
            // does not round-trip — a command that cannot be represented is
            // the host's bug, and running a mangled one would be worse than
            // reporting it.
            // Through `validate`, because `Untrusted` has no `as_ref` BY
            // DESIGN (`01` §2.5): reading it must acknowledge where it came
            // from. Lossy is correct *here* and only here — this is a
            // command line the HOST composed, not a path. `17` §1 forbids
            // lossy conversion for paths because it does not round-trip; a
            // command the host could not represent is the host's bug, and
            // running a mangled one would be worse than reporting it.
            let command = request
                .body
                .validate(|bytes| -> Result<String, core::convert::Infallible> {
                    Ok(String::from_utf8_lossy(bytes).into_owned())
                })
                .unwrap_or_default();
            let output = match run(&command) {
                Ok(output) => output,
                Err(why) => {
                    // Reported, not fatal. The host sees a failed command;
                    // the session continues.
                    let message = format!("rachna-agent: {why}\n");
                    send_chunks(connection, Kind::Stderr, message.as_bytes())?;
                    connection.send(Kind::Exited, &Exited { code: 127 }.encode())?;
                    return Ok(Served::Executed { exit_code: 127 });
                }
            };
            send_chunks(connection, Kind::Stdout, &output.stdout)?;
            send_chunks(connection, Kind::Stderr, &output.stderr)?;
            connection.send(
                Kind::Exited,
                &Exited {
                    code: output.exit_code,
                }
                .encode(),
            )?;
            Ok(Served::Executed {
                exit_code: output.exit_code,
            })
        }
        // The host may not send these, and `transport.rs`'s `Side` already
        // refuses them on receive. Written out rather than left to a
        // wildcard so adding a kind is a compile error here.
        Kind::Stdout | Kind::Stderr | Kind::Exited | Kind::Pong => {
            Err(AgentError::Transport(TransportError::Protocol(
                crate::protocol::ProtocolError::WrongDirection { kind: request.kind },
            )))
        }
    }
}

/// What a command produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
    /// The exit code.
    pub exit_code: i32,
}

/// Sends `body` as however many messages the transport's limit requires.
///
/// Empty output sends **nothing**, rather than an empty message: a command
/// with no stderr should not make the host read one.
fn send_chunks<S: Write>(
    connection: &mut Connection<S>,
    kind: Kind,
    body: &[u8],
) -> Result<(), TransportError> {
    for chunk in body.chunks(CHUNK) {
        connection.send(kind, chunk)?;
    }
    Ok(())
}

/// Serves requests until the host closes the connection.
///
/// # Errors
///
/// [`AgentError`] on a transport failure. A clean close returns `Ok`.
pub fn serve<S: Read + Write>(
    connection: &mut Connection<S>,
    mut run: impl FnMut(&str) -> Result<Output, String>,
) -> Result<(), AgentError> {
    loop {
        match serve_one(connection, &mut run)? {
            Served::Closed => return Ok(()),
            Served::Executed { .. } | Served::Ponged => {}
        }
    }
}

/// Runs a command line with the system shell.
///
/// # Why a shell rather than an argv
///
/// `00` §5.1's shim story forwards a tool invocation verbatim, and `00` §6.3
/// has editors running `rust-analyzer --stdio` through it — but the
/// interactive path (`rachna --exec "npm run dev && npm test"`) needs shell
/// semantics. The host composes the line; the guest runs it.
///
/// **This is not a policy hole.** The guest already has a shell and a user
/// can type into it (`00` §5.2's interactive shell is Ring 0). The boundary
/// is the VM, not the command parser — `idea.md` §8.4's whole point is that
/// root in the guest does not escape it.
///
/// # Errors
///
/// A `String` describing why the command could not be launched. The caller
/// reports that to the host as exit 127 rather than treating it as fatal.
pub fn run_with_shell(command: &str) -> Result<Output, String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|error| error.to_string())?;
    Ok(Output {
        stdout: output.stdout,
        stderr: output.stderr,
        // 127 is the shell's own "command not found", and a signal-killed
        // process has no code — reporting 127 for both keeps the host from
        // reading "success" out of an absent status.
        exit_code: output.status.code().unwrap_or(127),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::pipe::{pair, Duplex};
    use crate::transport::Side;

    /// Reads a message body in a test.
    ///
    /// `Untrusted` has no `as_ref` by design (`01` §2.5), so even a test
    /// acknowledges the body came from the other side.
    fn body_of(message: &crate::transport::Message) -> Vec<u8> {
        message
            .body
            .validate(|bytes| -> Result<Vec<u8>, core::convert::Infallible> { Ok(bytes.clone()) })
            .expect("infallible")
    }

    /// A host and an agent joined by in-memory pipes.
    fn joined() -> (Connection<Duplex>, Connection<Duplex>) {
        let (host_side, agent_side) = pair();
        (
            Connection::new(host_side, Side::Host),
            Connection::new(agent_side, Side::Agent),
        )
    }

    fn echoing(
        stdout: &str,
        stderr: &str,
        code: i32,
    ) -> impl FnMut(&str) -> Result<Output, String> {
        let stdout = stdout.to_owned();
        let stderr = stderr.to_owned();
        move |_command: &str| {
            Ok(Output {
                stdout: stdout.clone().into_bytes(),
                stderr: stderr.clone().into_bytes(),
                exit_code: code,
            })
        }
    }

    // ---- the exchange the whole wire exists for --------------------------

    #[test]
    fn a_command_runs_and_its_output_and_exit_code_come_back() {
        // `01` §7 step 8's own success criterion: "a command runs in a mock
        // guest with framed stdio and an exit code, with no VM". This is the
        // same exchange with the real agent on one end.
        let (mut host, mut agent) = joined();
        host.send(Kind::Exec, b"echo hello").expect("send");

        let served = serve_one(&mut agent, &mut echoing("hello\n", "", 0)).expect("served");
        assert_eq!(served, Served::Executed { exit_code: 0 });

        let out = host.receive().expect("stdout");
        assert_eq!(out.kind, Kind::Stdout);
        assert_eq!(body_of(&out), b"hello\n");

        let exited = host.receive().expect("exited");
        assert_eq!(exited.kind, Kind::Exited);
        assert_eq!(Exited::validate(&exited.body).expect("an exit").code, 0);
    }

    #[test]
    fn a_failing_command_reports_its_code_rather_than_an_error() {
        // The host needs the real code: `00` §5.1 says "exit code propagated
        // verbatim; CI depends on it".
        let (mut host, mut agent) = joined();
        host.send(Kind::Exec, b"false").expect("send");
        let served = serve_one(&mut agent, &mut echoing("", "", 1)).expect("served");
        assert_eq!(served, Served::Executed { exit_code: 1 });

        let exited = host.receive().expect("exited");
        assert_eq!(Exited::validate(&exited.body).expect("an exit").code, 1);
    }

    #[test]
    fn stderr_and_stdout_are_kept_separate() {
        // Merging them would break every tool that reads one and not the
        // other — a formatter writing to stdout and a diagnostic to stderr
        // is the normal case (`00` §6.2).
        let (mut host, mut agent) = joined();
        host.send(Kind::Exec, b"build").expect("send");
        serve_one(&mut agent, &mut echoing("artifact\n", "warning\n", 0)).expect("served");

        let first = host.receive().expect("stdout");
        assert_eq!(first.kind, Kind::Stdout);
        assert_eq!(body_of(&first), b"artifact\n");
        let second = host.receive().expect("stderr");
        assert_eq!(second.kind, Kind::Stderr);
        assert_eq!(body_of(&second), b"warning\n");
    }

    #[test]
    fn a_command_with_no_output_sends_no_output_messages() {
        // An empty message is not nothing: the host would read it and wait.
        let (mut host, mut agent) = joined();
        host.send(Kind::Exec, b"true").expect("send");
        serve_one(&mut agent, &mut echoing("", "", 0)).expect("served");

        // The very next message is the exit, with no empty stdout before it.
        let next = host.receive().expect("a message");
        assert_eq!(
            next.kind,
            Kind::Exited,
            "an empty output message was sent before the exit"
        );
    }

    #[test]
    fn output_larger_than_one_message_is_chunked() {
        // A command producing a gigabyte must not need a gigabyte of guest
        // memory to report it — `24` §7's guest has 2 GiB total and the
        // overlay's writable half is RAM (`00` §7 Layer C).
        let big = vec![b'x'; CHUNK * 2 + 7];
        let (mut host, mut agent) = joined();
        host.send(Kind::Exec, b"cat big").expect("send");
        serve_one(&mut agent, &mut |_: &str| {
            Ok(Output {
                stdout: big.clone(),
                stderr: vec![],
                exit_code: 0,
            })
        })
        .expect("served");

        let mut received = Vec::new();
        let mut messages = 0;
        loop {
            let message = host.receive().expect("a message");
            if message.kind == Kind::Exited {
                break;
            }
            assert_eq!(message.kind, Kind::Stdout);
            let chunk = body_of(&message);
            assert!(chunk.len() <= CHUNK, "a chunk exceeded the limit");
            received.extend_from_slice(&chunk);
            messages += 1;
        }
        assert_eq!(messages, 3, "expected three chunks for {} bytes", big.len());
        assert_eq!(received, big, "chunking lost or reordered data");
    }

    // ---- the trust direction --------------------------------------------

    #[test]
    fn the_agent_cannot_send_an_exec() {
        // `01` §2.5: the agent is untrusted. `Exec` is the one message it
        // must never send, and `transport.rs`'s `Side` refuses it before the
        // wire — so a compromised agent cannot ask the host to run anything.
        let (_host, mut agent) = joined();
        assert!(
            agent.send(Kind::Exec, b"rm -rf /").is_err(),
            "the agent was allowed to send an Exec"
        );
    }

    #[test]
    fn the_agent_refuses_a_message_the_host_may_not_send() {
        // Belt to the transport's braces. If `Side`'s check were ever
        // loosened, the agent would still not act on an agent-only kind
        // arriving from the host.
        // Built as an AGENT on the host's end, so the direction check lets
        // an agent-only kind through — which is how a compromised host, or a
        // loosened `Side`, would look from the agent's side.
        let (host_side, agent_side) = pair();
        let mut rogue = Connection::new(host_side, Side::Agent);
        let mut agent = Connection::new(agent_side, Side::Agent);
        rogue
            .send(Kind::Stdout, b"not a request")
            .expect("raw send");
        let error = serve_one(&mut agent, &mut echoing("", "", 0))
            .expect_err("an agent-only kind is not a request");
        assert!(matches!(error, AgentError::Transport(_)), "{error:?}");
    }

    // ---- a session ends cleanly -----------------------------------------

    #[test]
    fn a_closed_connection_ends_the_session_without_an_error() {
        // How a session normally ends. Reporting it as a failure would make
        // every `rachna --exec` exit non-zero on success.
        let (host, mut agent) = joined();
        drop(host);
        assert_eq!(
            serve_one(&mut agent, &mut echoing("", "", 0)).expect("a close is not an error"),
            Served::Closed
        );
    }

    #[test]
    fn serving_continues_across_several_commands() {
        // A long-lived LSP sends many requests on one connection
        // (`00` §6.6: "long-lived servers connect once and are free
        // thereafter"), so one command must not end the session.
        let (mut host, mut agent) = joined();
        for _ in 0..3 {
            host.send(Kind::Exec, b"true").expect("send");
        }
        host.send(Kind::Ping, &[]).expect("ping");
        drop(host);

        let mut runs = 0;
        let mut pongs = 0;
        let mut run = echoing("", "", 0);
        loop {
            match serve_one(&mut agent, &mut run).expect("served") {
                Served::Executed { .. } => runs += 1,
                Served::Ponged => pongs += 1,
                Served::Closed => break,
            }
        }
        assert_eq!(runs, 3);
        assert_eq!(pongs, 1);
    }

    #[test]
    fn a_ping_is_answered_with_a_pong() {
        // `00` §6.6: shims connect to an already-running agent, so the host
        // needs to know it is there without running a command.
        let (mut host, mut agent) = joined();
        host.send(Kind::Ping, &[]).expect("ping");
        assert_eq!(
            serve_one(&mut agent, &mut echoing("", "", 0)).expect("served"),
            Served::Ponged
        );
        assert_eq!(host.receive().expect("pong").kind, Kind::Pong);
    }

    // ---- a command that cannot run is not fatal -------------------------

    #[test]
    fn a_command_that_cannot_launch_reports_127_and_keeps_serving() {
        // One bad command must not disconnect the editor. 127 is the
        // shell's own "command not found", so a host reading it sees
        // something it already understands.
        let (mut host, mut agent) = joined();
        host.send(Kind::Exec, b"no-such-tool").expect("send");
        host.send(Kind::Exec, b"true").expect("send");
        drop(host);

        let mut first = true;
        let mut run = move |_: &str| -> Result<Output, String> {
            if core::mem::take(&mut first) {
                Err("no such file or directory".to_owned())
            } else {
                Ok(Output::default())
            }
        };
        assert_eq!(
            serve_one(&mut agent, &mut run).expect("served"),
            Served::Executed { exit_code: 127 }
        );
        // The session continues.
        assert_eq!(
            serve_one(&mut agent, &mut run).expect("served"),
            Served::Executed { exit_code: 0 }
        );
    }

    #[test]
    fn a_launch_failure_explains_itself_on_stderr() {
        // The host shows this to a user, so "exit 127" alone is not enough.
        let (mut host, mut agent) = joined();
        host.send(Kind::Exec, b"no-such-tool").expect("send");
        serve_one(&mut agent, &mut |_: &str| {
            Err("no such file or directory".to_owned())
        })
        .expect("served");

        let message = host.receive().expect("stderr");
        assert_eq!(message.kind, Kind::Stderr);
        let text = String::from_utf8_lossy(&body_of(&message)).into_owned();
        assert!(text.contains("rachna-agent"), "{text}");
        assert!(text.contains("no such file"), "{text}");
    }

    // ---- running for real ------------------------------------------------

    #[test]
    fn the_shell_runner_actually_runs_a_command() {
        // The only test here that touches the system. Everything above is
        // the agent's behaviour; this is the one line that executes.
        let output =
            run_with_shell("printf hello; printf oops >&2; exit 3").expect("sh is present");
        assert_eq!(output.stdout, b"hello");
        assert_eq!(output.stderr, b"oops");
        assert_eq!(output.exit_code, 3);
    }

    #[test]
    fn a_shell_command_that_does_not_exist_is_127_not_an_error() {
        // `sh -c` itself succeeds; the command inside fails. So this is a
        // normal exit code, not a launch failure — the distinction the host
        // needs in order to show the right thing.
        let output = run_with_shell("rachna-no-such-command").expect("sh runs");
        assert_eq!(output.exit_code, 127);
    }
}
