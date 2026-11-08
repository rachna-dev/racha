//! Framed message transport over any byte stream.
//!
//! # Why this is generic over `Read`/`Write` rather than owning a socket
//!
//! `01-ARCHITECTURE.md` §5c settles the shape: macOS has **no host-side
//! `AF_VSOCK`** — it is `VZVirtioSocketDevice`, an Objective-C API — so an
//! **fd-level seam is required regardless of runtime**. Writing the framing
//! against `Read + Write` means the same code drives a real vsock on Linux, a
//! `VZVirtioSocketDevice` file descriptor on macOS, and an in-memory pipe in
//! tests, with no platform conditionals in the framing itself.
//!
//! It also means step 8's acceptance test — *a command runs in a mock guest
//! with framed stdio and an exit code* — needs no VM.
//!
//! # Reads are bounded before they allocate
//!
//! Every length comes from the guest. [`Connection::receive`] validates the
//! header *first* (`protocol::Header::validate`), so a claimed 4 GiB body is
//! refused before a buffer is sized. That ordering is the defence, not the
//! limit itself.

use crate::protocol::{Header, Kind, ProtocolError, VERSION};
use crate::untrusted::Untrusted;
use std::io::{self, Read, Write};

/// Why a transport operation failed.
#[derive(Debug)]
pub enum TransportError {
    /// The stream failed.
    Io(io::Error),
    /// The peer closed the connection cleanly.
    ///
    /// Distinct from an I/O error: a guest exiting is normal, and treating it
    /// as a failure would turn every completed session into an error log.
    Closed,
    /// The message violated the protocol.
    Protocol(ProtocolError),
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "the agent connection failed: {error}"),
            Self::Closed => f.write_str("the agent closed the connection"),
            Self::Protocol(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Closed => None,
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for TransportError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Which side of the connection this is.
///
/// Carried so [`Connection::receive`] can enforce direction (`protocol`'s
/// `is_from_agent`/`is_from_host`). Without it the host would accept an
/// `Exec` from the guest, which is the one message the guest must never be
/// able to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The host broker.
    Host,
    /// The in-guest agent.
    Agent,
}

impl Side {
    /// Whether a message of `kind` may arrive at this side.
    #[must_use]
    pub const fn accepts(self, kind: Kind) -> bool {
        match self {
            // The host receives what the agent is allowed to send.
            Self::Host => kind.is_from_agent(),
            Self::Agent => kind.is_from_host(),
        }
    }
}

/// One message, as received.
///
/// The body stays [`Untrusted`]: the header has been validated, so the
/// *framing* is sound, and the contents are still whatever the guest chose to
/// send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The validated kind.
    pub kind: Kind,
    /// The body, still a claim.
    pub body: Untrusted<Vec<u8>>,
}

/// A framed connection over a byte stream.
#[derive(Debug)]
pub struct Connection<S> {
    stream: S,
    side: Side,
}

impl<S> Connection<S> {
    /// Wraps `stream` as the given side.
    #[must_use]
    pub const fn new(stream: S, side: Side) -> Self {
        Self { stream, side }
    }

    /// Which side this is.
    #[must_use]
    pub const fn side(&self) -> Side {
        self.side
    }
}

impl<S: Write> Connection<S> {
    /// Sends a message.
    ///
    /// # Errors
    ///
    /// [`TransportError::Protocol`] if `kind` may not be sent from this side,
    /// or the body exceeds the limit — checked before anything is written, so
    /// a refused send leaves nothing half-framed on the wire.
    ///
    /// [`TransportError::Io`] if the stream fails.
    pub fn send(&mut self, kind: Kind, body: &[u8]) -> Result<(), TransportError> {
        // A side may only send what the *other* side accepts. Checked here as
        // well as on receive, because catching a bug in our own broker before
        // it reaches the wire is better than catching it in the guest.
        let sendable = match self.side {
            Side::Host => kind.is_from_host(),
            Side::Agent => kind.is_from_agent(),
        };
        if !sendable {
            return Err(ProtocolError::WrongDirection { kind }.into());
        }

        let body_length = u32::try_from(body.len()).map_err(|_| ProtocolError::BodyTooLarge {
            claimed: u32::MAX,
            limit: crate::protocol::MAX_BODY,
        })?;
        if body_length > crate::protocol::MAX_BODY {
            return Err(ProtocolError::BodyTooLarge {
                claimed: body_length,
                limit: crate::protocol::MAX_BODY,
            }
            .into());
        }

        let header = Header {
            version: VERSION,
            kind: kind.to_wire(),
            body_length,
        };
        self.stream.write_all(&header.encode())?;
        self.stream.write_all(body)?;
        self.stream.flush()?;
        Ok(())
    }
}

impl<S: Read> Connection<S> {
    /// Receives one message.
    ///
    /// # Errors
    ///
    /// [`TransportError::Closed`] if the peer closed cleanly — a guest
    /// exiting is normal, not a failure.
    ///
    /// [`TransportError::Protocol`] if the header is invalid, the body
    /// exceeds the limit, or the kind may not arrive at this side.
    ///
    /// [`TransportError::Io`] if the stream fails or the body is short.
    pub fn receive(&mut self) -> Result<Message, TransportError> {
        let mut header_bytes = [0_u8; Header::SIZE];
        match self.stream.read_exact(&mut header_bytes) {
            Ok(()) => {}
            // A clean close at a message boundary is the guest exiting.
            // Mid-header is a truncation, which is a real error.
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(TransportError::Closed)
            }
            Err(error) => return Err(error.into()),
        }

        // Validated BEFORE the body is sized. A guest claiming 4 GiB never
        // causes an allocation.
        let (kind, body_length) = Header::validate(&Header::decode(header_bytes))?;

        if !self.side.accepts(kind) {
            return Err(ProtocolError::WrongDirection { kind }.into());
        }

        let mut body = vec![0_u8; body_length as usize];
        self.stream.read_exact(&mut body)?;
        Ok(Message {
            kind,
            body: Untrusted::new(body),
        })
    }
}

/// An in-memory bidirectional pipe, for tests and the mock guest.
///
/// Two `Vec`s and a cursor each. Deliberately not a real socket: step 8's
/// acceptance test must run with no VM and no platform-specific socket API,
/// which is what makes it runnable in CI on every platform in the matrix.
#[cfg(test)]
pub mod pipe {
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};

    /// One direction of a pipe.
    #[derive(Debug, Clone, Default)]
    pub struct Channel {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Channel {
        /// How many bytes are waiting.
        #[must_use]
        pub fn pending(&self) -> usize {
            self.buffer.lock().map_or(0, |buffer| buffer.len())
        }
    }

    impl Write for Channel {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let mut buffer = self
                .buffer
                .lock()
                .map_err(|_| io::Error::other("pipe poisoned"))?;
            buffer.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for Channel {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let mut buffer = self
                .buffer
                .lock()
                .map_err(|_| io::Error::other("pipe poisoned"))?;
            let taken = out.len().min(buffer.len());
            out[..taken].copy_from_slice(&buffer[..taken]);
            buffer.drain(..taken);
            // Zero bytes read means empty, which `read_exact` reports as
            // UnexpectedEof — and `receive` maps that to `Closed`. That is
            // the behaviour a real socket has at a clean close.
            Ok(taken)
        }
    }

    /// A stream that reads one channel and writes another.
    #[derive(Debug)]
    pub struct Duplex {
        pub incoming: Channel,
        pub outgoing: Channel,
    }

    impl Read for Duplex {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(out)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.outgoing.write(data)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.outgoing.flush()
        }
    }

    /// A connected pair: what the host sees, and what the agent sees.
    #[must_use]
    pub fn pair() -> (Duplex, Duplex) {
        let host_to_agent = Channel::default();
        let agent_to_host = Channel::default();
        (
            Duplex {
                incoming: agent_to_host.clone(),
                outgoing: host_to_agent.clone(),
            },
            Duplex {
                incoming: host_to_agent,
                outgoing: agent_to_host,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::pipe::pair;
    use super::*;
    use crate::protocol::{Exited, MAX_BODY};

    fn connected() -> (Connection<pipe::Duplex>, Connection<pipe::Duplex>) {
        let (host, agent) = pair();
        (
            Connection::new(host, Side::Host),
            Connection::new(agent, Side::Agent),
        )
    }

    // ---- step 8's acceptance test ---------------------------------------

    #[test]
    fn a_command_runs_with_framed_stdio_and_an_exit_code() {
        // 01 §7 step 7's successor: "a command runs in a mock guest with
        // framed stdio and an exit code". No VM, no socket, no platform
        // conditionals — which is what makes it runnable on every platform in
        // the CI matrix.
        let (mut host, mut agent) = connected();

        host.send(Kind::Exec, b"echo hello")
            .expect("host sends exec");

        // The mock guest: receive the command, emit output, report an exit.
        let request = agent.receive().expect("agent receives");
        assert_eq!(request.kind, Kind::Exec);
        let command = request
            .body
            .validate(|bytes| String::from_utf8(bytes.clone()).map_err(|_| "not utf-8"))
            .expect("valid utf-8");
        assert_eq!(command, "echo hello");

        agent
            .send(Kind::Stdout, b"hello\n")
            .expect("agent sends stdout");
        agent
            .send(Kind::Exited, &Exited { code: 0 }.encode())
            .expect("agent sends exit");

        // The host reads the framed reply.
        let stdout = host.receive().expect("host receives stdout");
        assert_eq!(stdout.kind, Kind::Stdout);
        assert_eq!(stdout.body.for_diagnostics_only().as_slice(), b"hello\n");

        let exited = host.receive().expect("host receives exit");
        assert_eq!(exited.kind, Kind::Exited);
        let code = Exited::validate(&exited.body).expect("well-formed");
        assert_eq!(code.code, 0);
    }

    #[test]
    fn a_failing_command_reports_its_real_exit_code() {
        let (mut host, mut agent) = connected();
        host.send(Kind::Exec, b"false").expect("send");
        agent.receive().expect("receive");
        agent
            .send(Kind::Exited, &Exited { code: 1 }.encode())
            .expect("send");
        let exited = host.receive().expect("receive");
        assert_eq!(
            Exited::validate(&exited.body).expect("valid").code,
            1,
            "a non-zero exit must survive the round trip"
        );
    }

    #[test]
    fn a_signal_killed_command_reports_a_negative_code() {
        // Unix reports signal death as a negative code; an unsigned field
        // would turn SIGKILL into 4294967287 and the caller would read it as
        // success-adjacent nonsense.
        let (mut host, mut agent) = connected();
        host.send(Kind::Exec, b"sleep 100").expect("send");
        agent.receive().expect("receive");
        agent
            .send(Kind::Exited, &Exited { code: -9 }.encode())
            .expect("send");
        let exited = host.receive().expect("receive");
        assert_eq!(Exited::validate(&exited.body).expect("valid").code, -9);
    }

    // ---- framing holds under hostile payloads ---------------------------

    #[test]
    fn a_body_containing_what_a_delimiter_would_be_round_trips() {
        // The direct test of why framing is length-prefixed (`11` §7): a
        // marker-framed protocol would end the message here.
        let (mut host, mut agent) = connected();
        let hostile = b"\n---END---\n\0\xff\xfe binary".to_vec();
        agent.send(Kind::Stdout, &hostile).expect("send");
        let received = host.receive().expect("receive");
        assert_eq!(received.body.for_diagnostics_only(), &hostile);
    }

    #[test]
    fn an_empty_body_is_a_valid_message() {
        // `Ping` has no body, and a zero-length read must not be mistaken for
        // a closed connection.
        let (mut host, mut agent) = connected();
        host.send(Kind::Ping, b"").expect("send");
        let received = agent.receive().expect("receive");
        assert_eq!(received.kind, Kind::Ping);
        assert!(received.body.for_diagnostics_only().is_empty());
    }

    #[test]
    fn messages_stay_in_order_and_separate() {
        // Three messages back to back must not merge or reorder — the thing
        // a length prefix guarantees and a delimiter does not.
        let (mut host, mut agent) = connected();
        for chunk in [b"one".as_slice(), b"two", b"three"] {
            agent.send(Kind::Stdout, chunk).expect("send");
        }
        for expected in [b"one".as_slice(), b"two", b"three"] {
            let received = host.receive().expect("receive");
            assert_eq!(received.body.for_diagnostics_only().as_slice(), expected);
        }
    }

    #[test]
    fn a_one_mebibyte_body_is_accepted_at_the_limit() {
        let (mut host, mut agent) = connected();
        let large = vec![b'x'; MAX_BODY as usize];
        agent.send(Kind::Stdout, &large).expect("at the limit");
        let received = host.receive().expect("receive");
        assert_eq!(
            received.body.for_diagnostics_only().len(),
            MAX_BODY as usize
        );
    }

    #[test]
    fn a_body_over_the_limit_is_refused_before_anything_is_written() {
        // So a refused send leaves nothing half-framed on the wire — the
        // next message would otherwise be read as a continuation of a
        // phantom body.
        let (_, mut agent) = connected();
        let too_large = vec![b'x'; MAX_BODY as usize + 1];
        assert!(agent.send(Kind::Stdout, &too_large).is_err());
        assert_eq!(
            agent.stream.outgoing.pending(),
            0,
            "a refused send wrote bytes"
        );
    }

    // ---- direction, enforced on both ends -------------------------------

    #[test]
    fn the_host_refuses_an_exec_arriving_from_the_guest() {
        // THE direction case: the guest does not get to tell the host to run
        // things. Forged at the byte level, bypassing `send`'s own check, so
        // this tests the receive path rather than our politeness.
        let (mut host, _) = connected();
        let forged = Header {
            version: VERSION,
            kind: Kind::Exec.to_wire(),
            body_length: 2,
        };
        host.stream
            .incoming
            .write_all(&forged.encode())
            .expect("inject");
        host.stream.incoming.write_all(b"hi").expect("inject");

        match host.receive() {
            Err(TransportError::Protocol(ProtocolError::WrongDirection { kind })) => {
                assert_eq!(kind, Kind::Exec);
            }
            other => panic!("the host accepted a forged exec: {other:?}"),
        }
    }

    #[test]
    fn the_agent_refuses_output_arriving_from_the_host() {
        let (_, mut agent) = connected();
        let forged = Header {
            version: VERSION,
            kind: Kind::Stdout.to_wire(),
            body_length: 0,
        };
        agent
            .stream
            .incoming
            .write_all(&forged.encode())
            .expect("inject");
        assert!(matches!(
            agent.receive(),
            Err(TransportError::Protocol(
                ProtocolError::WrongDirection { .. }
            ))
        ));
    }

    #[test]
    fn a_side_cannot_send_what_it_may_not_send() {
        // Checked on send as well as receive: catching a bug in our own
        // broker before it reaches the wire beats catching it in the guest.
        let (mut host, mut agent) = connected();
        assert!(host.send(Kind::Stdout, b"").is_err(), "host sent output");
        assert!(agent.send(Kind::Exec, b"").is_err(), "agent sent an exec");
    }

    #[test]
    fn every_kind_is_sendable_by_exactly_one_side() {
        for kind in Kind::ALL {
            let (mut host, mut agent) = connected();
            let host_ok = host.send(kind, b"").is_ok();
            let agent_ok = agent.send(kind, b"").is_ok();
            assert_ne!(
                host_ok, agent_ok,
                "{kind} is sendable by both sides or neither"
            );
        }
    }

    #[test]
    fn side_accepts_is_the_mirror_of_what_the_other_side_sends() {
        for kind in Kind::ALL {
            assert_eq!(Side::Host.accepts(kind), kind.is_from_agent());
            assert_eq!(Side::Agent.accepts(kind), kind.is_from_host());
        }
    }

    // ---- the adversarial header on the wire -----------------------------

    #[test]
    fn a_forged_oversized_length_is_refused_without_allocating() {
        // The DoS case, injected at the byte level. If this allocated first,
        // the test would die rather than fail — so passing is the assertion.
        let (mut host, _) = connected();
        let forged = Header {
            version: VERSION,
            kind: Kind::Stdout.to_wire(),
            body_length: u32::MAX,
        };
        host.stream
            .incoming
            .write_all(&forged.encode())
            .expect("inject");
        assert!(matches!(
            host.receive(),
            Err(TransportError::Protocol(ProtocolError::BodyTooLarge { .. }))
        ));
    }

    #[test]
    fn a_forged_version_is_refused() {
        let (mut host, _) = connected();
        let forged = Header {
            version: VERSION + 7,
            kind: Kind::Stdout.to_wire(),
            body_length: 0,
        };
        host.stream
            .incoming
            .write_all(&forged.encode())
            .expect("inject");
        assert!(matches!(
            host.receive(),
            Err(TransportError::Protocol(
                ProtocolError::VersionMismatch { .. }
            ))
        ));
    }

    #[test]
    fn a_truncated_body_is_an_error_not_a_short_message() {
        // Accepting a short body would hand the caller a truncated exit code
        // or half a line of output as though it were complete.
        let (mut host, _) = connected();
        let header = Header {
            version: VERSION,
            kind: Kind::Stdout.to_wire(),
            body_length: 100,
        };
        host.stream
            .incoming
            .write_all(&header.encode())
            .expect("inject");
        host.stream.incoming.write_all(b"short").expect("inject");
        assert!(matches!(host.receive(), Err(TransportError::Io(_))));
    }

    // ---- closing ---------------------------------------------------------

    #[test]
    fn a_clean_close_is_not_an_error() {
        // A guest exiting is normal. Treating it as a failure would turn
        // every completed session into an error log.
        let (mut host, _) = connected();
        assert!(matches!(host.receive(), Err(TransportError::Closed)));
    }

    #[test]
    fn a_real_io_error_is_not_reported_as_a_clean_close() {
        // Mutation testing found this guard untested: replacing
        // `error.kind() == UnexpectedEof` with `true` made EVERY read failure
        // look like the guest exiting normally. A broken connection would
        // then be logged as a completed session, and the user would see a
        // command silently produce no output.
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset"))
            }
        }
        let mut host = Connection::new(Failing, Side::Host);
        match host.receive() {
            Err(TransportError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            }
            other => panic!("a reset connection was not an I/O error: {other:?}"),
        }
    }

    #[test]
    fn a_closed_connection_reports_it_distinctly_from_a_protocol_error() {
        let (mut host, _) = connected();
        let closed = host.receive().expect_err("closed");
        assert!(matches!(closed, TransportError::Closed));
        assert!(closed.to_string().contains("closed"));
    }

    #[test]
    fn a_transport_error_keeps_its_cause() {
        let protocol = TransportError::from(ProtocolError::UnknownKind { kind: 9 });
        assert!(core::error::Error::source(&protocol).is_some());
        let closed = TransportError::Closed;
        assert!(core::error::Error::source(&closed).is_none());
    }

    #[test]
    fn a_connection_reports_its_side() {
        let (host, agent) = connected();
        assert_eq!(host.side(), Side::Host);
        assert_eq!(agent.side(), Side::Agent);
    }
}
