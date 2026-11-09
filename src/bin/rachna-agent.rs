//! The in-guest agent binary.
//!
//! Runs inside the guest, serving commands the host sends over a stream. The
//! behaviour lives in `rachna::agent`, which is tested over in-memory pipes;
//! this is the small amount that needs a real file descriptor.
//!
//! # Why stdio rather than opening a vsock here
//!
//! The guest's init connects the socket and hands this process its stdin and
//! stdout, so the agent is a filter rather than a server. Three reasons, and
//! the third is the one that matters:
//!
//! - It is testable with a pipe, which is how `agent.rs`'s whole suite runs.
//! - It needs no address, so `08` §4.1's deterministic paths stay the host's
//!   business (`16` §5.2's socket-path lesson applies to the *host* side).
//! - **The vsock CID is the host's to choose**, and a guest that opened its
//!   own connection would be deciding where to connect — exactly the
//!   authority `01` §2.5 says the untrusted side must not have.
//!
//! # Exit codes
//!
//! `0` for a clean close, because that is how a session ends — reporting a
//! failure there would make every successful `rachna --exec` look broken.
//! Non-zero only for a transport failure, which means the wire itself broke.

#![allow(clippy::print_stderr, reason = "the only channel a guest binary has")]

use rachna::agent::{run_with_shell, serve};
use rachna::transport::{Connection, Side};
use std::io::{Read, Write};
use std::process::ExitCode;

/// Everything worked, including a clean disconnect.
const OK: u8 = 0;
/// The transport broke.
const TRANSPORT_FAILED: u8 = 74;

fn main() -> ExitCode {
    // stdin and stdout as one duplex stream. The guest's init pairs them
    // with the vsock connection, so this process never names an address.
    let stream = Stdio::new();
    let mut connection = Connection::new(stream, Side::Agent);

    match serve(&mut connection, run_with_shell) {
        Ok(()) => ExitCode::from(OK),
        Err(error) => {
            // To stderr, which the guest's journal captures. `05` §4.3
            // measured that the serial console is the only reliable channel
            // out of a guest, and the journal reaches it.
            eprintln!("rachna-agent: {error}");
            ExitCode::from(TRANSPORT_FAILED)
        }
    }
}

/// stdin and stdout as a single `Read + Write` stream.
///
/// `Connection` is generic over one stream, because a socket is one thing.
/// Split descriptors need joining, and doing it here keeps `agent.rs`
/// testable over a pipe.
#[derive(Debug)]
struct Stdio {
    input: std::io::Stdin,
    output: std::io::Stdout,
}

impl Stdio {
    fn new() -> Self {
        Self {
            input: std::io::stdin(),
            output: std::io::stdout(),
        }
    }
}

impl Read for Stdio {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for Stdio {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.write(buffer)
    }

    /// Flushed on every message, not at exit.
    ///
    /// An LSP waits for a reply before sending the next request, so a
    /// buffered response is a hang rather than a slow reply — and the host
    /// would report it as a timeout with nothing to point at.
    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}
