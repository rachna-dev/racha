//! The host↔agent wire format.
//!
//! `21-SPEC-AUDIT.md` §3.1 flagged this as the gap with the nearest deadline:
//! the trust model was settled (`01` §2.5 — untrusted, enforced by types) and
//! the wire format was never specified. This is that specification, and the
//! constraints come from measurement rather than taste.
//!
//! # Why framing is explicit and length-prefixed
//!
//! `11` §7 measured the serial console failing three ways: no framing, no
//! concurrency, no reliable completion signal. Marker-based framing broke
//! because the marker appeared in the echoed command line; long commands
//! wedged. That is the direct evidence for a length prefix over any
//! delimiter — a delimiter can appear in the payload, a length cannot.
//!
//! # Why messages are self-describing and versioned
//!
//! The agent ships *inside* the guest closure, so its version is pinned to
//! the guest version (`08` §4.1.1). But a snapshot restores an **old guest**
//! into a **new `rachna`** (`02` §4: a snapshot is tied to the guest it came
//! from), so host and agent versions genuinely diverge in normal use. A
//! mismatch must be a clear refusal, not a misparse.
//!
//! # Why every field is bounded
//!
//! A compromised guest controls every byte it sends, including a length
//! prefix claiming 4 GiB. An unbounded read is a trivial denial of service
//! against the host broker, so limits are part of the format rather than a
//! caller's responsibility.

use crate::untrusted::Untrusted;
use core::fmt;

/// The protocol version.
///
/// Bumped when the wire format changes incompatibly. Separate from the
/// `rachna` version, because the agent's version is the *guest's* and a
/// restored snapshot pairs an old guest with a new host.
pub const VERSION: u16 = 1;

/// The largest message body accepted, in bytes.
///
/// 1 MiB. Chosen because the largest legitimate message is a command's
/// captured output, and anything approaching this is a streaming problem
/// rather than one message. A compromised guest claiming more is refused
/// before a single byte of body is read — the allocation never happens.
pub const MAX_BODY: u32 = 1024 * 1024;

/// The fixed header on every message.
///
/// Fixed-size and read first, so the body length is known before any
/// allocation. `21` §3.1 asked for framing, versioning and size limits; this
/// is all three in eight bytes.
///
/// ```text
/// 0      2      4              8
/// +------+------+--------------+
/// | ver  | kind | body length  |
/// +------+------+--------------+
///   u16    u16        u32          all big-endian
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Protocol version. Checked before `kind` is interpreted.
    pub version: u16,
    /// What kind of message follows.
    pub kind: u16,
    /// Body length in bytes.
    pub body_length: u32,
}

impl Header {
    /// Wire size of a header.
    pub const SIZE: usize = 8;

    /// Encodes to bytes, big-endian.
    ///
    /// Big-endian because it is the conventional network order and makes a
    /// hexdump readable in field order during debugging. Both our platforms
    /// are little-endian, so there is no "native" shortcut to be tempted by.
    #[must_use]
    pub const fn encode(self) -> [u8; Self::SIZE] {
        let version = self.version.to_be_bytes();
        let kind = self.kind.to_be_bytes();
        let length = self.body_length.to_be_bytes();
        [
            version[0], version[1], kind[0], kind[1], length[0], length[1], length[2], length[3],
        ]
    }

    /// Decodes a header from exactly [`Self::SIZE`] bytes.
    ///
    /// Returns an [`Untrusted`] header: the bytes came from the guest, so
    /// even a well-formed header is a *claim*. [`Self::validate`] is what
    /// turns it into something usable.
    #[must_use]
    pub const fn decode(bytes: [u8; Self::SIZE]) -> Untrusted<Self> {
        Untrusted::new(Self {
            version: u16::from_be_bytes([bytes[0], bytes[1]]),
            kind: u16::from_be_bytes([bytes[2], bytes[3]]),
            body_length: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }

    /// Checks a claimed header against the protocol's limits.
    ///
    /// # Errors
    ///
    /// - [`ProtocolError::VersionMismatch`] if the version is not [`VERSION`].
    ///   Checked **first**, because a different version means `kind` and the
    ///   body layout cannot be interpreted at all.
    /// - [`ProtocolError::BodyTooLarge`] if the length exceeds [`MAX_BODY`].
    ///   Checked before any allocation, which is the point.
    /// - [`ProtocolError::UnknownKind`] if `kind` is not a [`Kind`].
    pub fn validate(claimed: &Untrusted<Self>) -> Result<(Kind, u32), ProtocolError> {
        claimed.validate(|header| {
            if header.version != VERSION {
                return Err(ProtocolError::VersionMismatch {
                    expected: VERSION,
                    found: header.version,
                });
            }
            if header.body_length > MAX_BODY {
                return Err(ProtocolError::BodyTooLarge {
                    claimed: header.body_length,
                    limit: MAX_BODY,
                });
            }
            let kind = Kind::from_wire(header.kind)
                .ok_or(ProtocolError::UnknownKind { kind: header.kind })?;
            Ok((kind, header.body_length))
        })
    }
}

/// What a message is.
///
/// A closed set with explicit wire numbers, so a renumbering is a deliberate
/// protocol change rather than a side effect of reordering an enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Host → agent: run a command.
    Exec,
    /// Agent → host: a chunk of stdout.
    Stdout,
    /// Agent → host: a chunk of stderr.
    Stderr,
    /// Agent → host: the command finished, with its exit code.
    Exited,
    /// Host → agent: are you there?
    Ping,
    /// Agent → host: yes.
    Pong,
}

impl Kind {
    /// Every kind, for exhaustive tests.
    pub const ALL: [Self; 6] = [
        Self::Exec,
        Self::Stdout,
        Self::Stderr,
        Self::Exited,
        Self::Ping,
        Self::Pong,
    ];

    /// The wire number.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::Exec => 1,
            Self::Stdout => 2,
            Self::Stderr => 3,
            Self::Exited => 4,
            Self::Ping => 5,
            Self::Pong => 6,
        }
    }

    /// The kind for a wire number, or `None` if unrecognised.
    ///
    /// Returns `Option` rather than defaulting: an unknown kind from a
    /// compromised guest must be a refusal, and a catch-all variant would
    /// defeat exhaustive matching (`AGENTS.md`, "never add `Unknown`").
    #[must_use]
    pub const fn from_wire(wire: u16) -> Option<Self> {
        match wire {
            1 => Some(Self::Exec),
            2 => Some(Self::Stdout),
            3 => Some(Self::Stderr),
            4 => Some(Self::Exited),
            5 => Some(Self::Ping),
            6 => Some(Self::Pong),
            _ => None,
        }
    }

    /// Whether this kind may legitimately arrive *from* the agent.
    ///
    /// The host must refuse an `Exec` claiming to come from the guest: the
    /// guest does not get to tell the host to run things. A direction check
    /// in the protocol means that is structural rather than a missing `if`
    /// somewhere in the broker.
    #[must_use]
    pub const fn is_from_agent(self) -> bool {
        matches!(
            self,
            Self::Stdout | Self::Stderr | Self::Exited | Self::Pong
        )
    }

    /// Whether this kind may legitimately arrive *at* the agent.
    #[must_use]
    pub const fn is_from_host(self) -> bool {
        matches!(self, Self::Exec | Self::Ping)
    }

    /// The name used in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Exited => "exited",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// The agent speaks a different protocol version.
    ///
    /// Expected in normal use, not just under attack: a snapshot restores an
    /// old guest into a new `rachna` (`02` §4).
    VersionMismatch { expected: u16, found: u16 },
    /// The claimed body length exceeds [`MAX_BODY`].
    BodyTooLarge { claimed: u32, limit: u32 },
    /// The `kind` field is not a known [`Kind`].
    UnknownKind { kind: u16 },
    /// A message arrived from the wrong side.
    WrongDirection { kind: Kind },
    /// The body did not match what the kind requires.
    MalformedBody { kind: Kind, reason: &'static str },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch { expected, found } => write!(
                f,
                "the guest agent speaks protocol {found}, this rachna speaks \
                 {expected} — the guest is from a different release"
            ),
            Self::BodyTooLarge { claimed, limit } => write!(
                f,
                "the guest claimed a {claimed}-byte message; the limit is {limit}"
            ),
            Self::UnknownKind { kind } => {
                write!(f, "the guest sent an unknown message kind {kind}")
            }
            Self::WrongDirection { kind } => {
                write!(f, "a {kind} message cannot arrive from that direction")
            }
            Self::MalformedBody { kind, reason } => {
                write!(f, "a {kind} message was malformed: {reason}")
            }
        }
    }
}

impl core::error::Error for ProtocolError {}

/// A command's outcome, as reported by the agent.
///
/// The one message with structure beyond bytes, and therefore the one that
/// needs validating rather than merely bounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exited {
    /// The process exit code.
    pub code: i32,
}

impl Exited {
    /// Wire size: a single big-endian `i32`.
    pub const SIZE: usize = 4;

    /// Encodes to bytes.
    #[must_use]
    pub const fn encode(self) -> [u8; Self::SIZE] {
        self.code.to_be_bytes()
    }

    /// Validates a claimed exit body.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::MalformedBody`] if the body is not exactly
    /// [`Self::SIZE`] bytes. A short body would otherwise be padded or a long
    /// one truncated, and either turns a malformed message into a plausible
    /// exit code — which the caller would then believe.
    pub fn validate(body: &Untrusted<Vec<u8>>) -> Result<Self, ProtocolError> {
        body.validate(|bytes| {
            let exact: [u8; Self::SIZE] =
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ProtocolError::MalformedBody {
                        kind: Kind::Exited,
                        reason: "an exit code is exactly 4 bytes",
                    })?;
            Ok(Self {
                code: i32::from_be_bytes(exact),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u16, kind: u16, body_length: u32) -> Untrusted<Header> {
        Header::decode(
            Header {
                version,
                kind,
                body_length,
            }
            .encode(),
        )
    }

    // ---- framing ---------------------------------------------------------

    #[test]
    fn a_header_round_trips_through_bytes() {
        let original = Header {
            version: VERSION,
            kind: Kind::Exec.to_wire(),
            body_length: 1234,
        };
        let decoded = Header::decode(original.encode());
        assert_eq!(*decoded.for_diagnostics_only(), original);
    }

    #[test]
    fn the_header_is_exactly_eight_bytes() {
        // Fixed size is what makes the body length knowable before any
        // allocation, which is the whole defence in `MAX_BODY`.
        assert_eq!(Header::SIZE, 8);
        assert_eq!(
            Header {
                version: 1,
                kind: 1,
                body_length: 1
            }
            .encode()
            .len(),
            8
        );
    }

    #[test]
    fn the_encoding_is_big_endian() {
        // Pinned: a silent switch to native order would make two hosts of
        // different endianness unable to talk, and the failure would look
        // like corruption rather than a format change.
        let encoded = Header {
            version: 0x0102,
            kind: 0x0304,
            body_length: 0x0506_0708,
        }
        .encode();
        assert_eq!(encoded, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn framing_uses_a_length_not_a_delimiter() {
        // `11` §7 measured marker-based framing failing because the marker
        // appeared in the echoed command line. A length prefix cannot be
        // forged by payload content — this asserts the payload is free to
        // contain anything, including what a delimiter would be.
        let hostile_body = b"\n---END---\n\0\xff".to_vec();
        let length = u32::try_from(hostile_body.len()).expect("small");
        let claimed = header(VERSION, Kind::Stdout.to_wire(), length);
        let (kind, body_length) = Header::validate(&claimed).expect("valid");
        assert_eq!(kind, Kind::Stdout);
        assert_eq!(body_length as usize, hostile_body.len());
    }

    // ---- the adversarial cases ------------------------------------------

    #[test]
    fn a_body_length_beyond_the_limit_is_refused_before_any_allocation() {
        // The denial-of-service case: a compromised guest claims 4 GiB and
        // the host allocates it. Refused on the header, so the allocation
        // never happens.
        let claimed = header(VERSION, Kind::Stdout.to_wire(), u32::MAX);
        assert_eq!(
            Header::validate(&claimed),
            Err(ProtocolError::BodyTooLarge {
                claimed: u32::MAX,
                limit: MAX_BODY,
            })
        );
    }

    #[test]
    fn the_limit_is_one_mebibyte() {
        // Pinned by VALUE, not symbolically. Mutation testing replaced
        // `1024 * 1024` with `1024 + 1024` and every other test still passed,
        // because they all refer to `MAX_BODY` rather than to a number — so
        // the limit could silently become 2 KiB and only a real command's
        // output would notice, by being truncated.
        assert_eq!(MAX_BODY, 1_048_576);
    }

    #[test]
    fn the_limit_boundary_is_inclusive() {
        // Exactly MAX_BODY is allowed; one more is not. Pinned because an
        // off-by-one here either rejects a legitimate largest message or
        // accepts one byte more than the documented limit.
        assert!(Header::validate(&header(VERSION, Kind::Stdout.to_wire(), MAX_BODY)).is_ok());
        assert!(Header::validate(&header(VERSION, Kind::Stdout.to_wire(), MAX_BODY + 1)).is_err());
    }

    #[test]
    fn a_version_mismatch_is_checked_before_the_kind() {
        // A different version means `kind` and the body layout cannot be
        // interpreted at all, so reporting "unknown kind" would be a lie
        // about which thing is wrong — and would send the user looking in the
        // wrong place.
        let claimed = header(VERSION + 1, 9999, 0);
        assert_eq!(
            Header::validate(&claimed),
            Err(ProtocolError::VersionMismatch {
                expected: VERSION,
                found: VERSION + 1,
            }),
            "an unknown kind was reported for a version we cannot parse"
        );
    }

    #[test]
    fn a_version_mismatch_is_also_checked_before_the_size_limit() {
        let claimed = header(VERSION + 1, Kind::Stdout.to_wire(), u32::MAX);
        assert!(matches!(
            Header::validate(&claimed),
            Err(ProtocolError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn a_version_mismatch_explains_itself_in_terms_a_user_can_act_on() {
        // Expected in NORMAL use: a snapshot restores an old guest into a new
        // rachna (`02` §4). So the message has to say "the guest is from a
        // different release", not "protocol error".
        let error = ProtocolError::VersionMismatch {
            expected: 2,
            found: 1,
        };
        let message = error.to_string();
        assert!(message.contains("different release"), "{message}");
    }

    #[test]
    fn an_unknown_kind_is_refused_rather_than_defaulted() {
        // A catch-all variant would defeat exhaustive matching, so an
        // unrecognised kind from a compromised guest must be a refusal.
        let claimed = header(VERSION, 9999, 0);
        assert_eq!(
            Header::validate(&claimed),
            Err(ProtocolError::UnknownKind { kind: 9999 })
        );
    }

    #[test]
    fn kind_zero_is_not_a_valid_kind() {
        // Zero is what an all-zero or truncated read produces, so it must not
        // map to a real message.
        assert_eq!(Kind::from_wire(0), None);
    }

    // ---- direction -------------------------------------------------------

    #[test]
    fn the_guest_cannot_send_an_exec() {
        // The sharpest direction case: the guest does not get to tell the
        // host to run things. Structural rather than a missing `if` in the
        // broker.
        assert!(!Kind::Exec.is_from_agent());
        assert!(!Kind::Ping.is_from_agent());
    }

    #[test]
    fn the_host_cannot_send_output() {
        assert!(!Kind::Stdout.is_from_host());
        assert!(!Kind::Stderr.is_from_host());
        assert!(!Kind::Exited.is_from_host());
        assert!(!Kind::Pong.is_from_host());
    }

    #[test]
    fn every_kind_belongs_to_exactly_one_direction() {
        // A kind valid in both directions would be a channel the guest could
        // use to impersonate the host, or vice versa.
        for kind in Kind::ALL {
            assert_ne!(
                kind.is_from_agent(),
                kind.is_from_host(),
                "{kind} is valid in both directions or neither"
            );
        }
    }

    // ---- the wire numbers ------------------------------------------------

    #[test]
    fn every_wire_number_round_trips_and_is_distinct() {
        let mut seen: Vec<u16> = Vec::new();
        for kind in Kind::ALL {
            let wire = kind.to_wire();
            assert_eq!(Kind::from_wire(wire), Some(kind));
            assert!(!seen.contains(&wire), "{kind} reuses wire number {wire}");
            seen.push(wire);
        }
    }

    #[test]
    fn the_wire_numbers_are_pinned() {
        // Renumbering is a protocol change, not a refactor: an old agent and
        // a new host would silently disagree about what a message means.
        assert_eq!(Kind::Exec.to_wire(), 1);
        assert_eq!(Kind::Stdout.to_wire(), 2);
        assert_eq!(Kind::Stderr.to_wire(), 3);
        assert_eq!(Kind::Exited.to_wire(), 4);
        assert_eq!(Kind::Ping.to_wire(), 5);
        assert_eq!(Kind::Pong.to_wire(), 6);
        assert_eq!(VERSION, 1);
    }

    #[test]
    fn every_kind_has_a_distinct_name() {
        let mut names: Vec<&str> = Kind::ALL.iter().map(|k| k.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
        for kind in Kind::ALL {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    // ---- the exit body ---------------------------------------------------

    #[test]
    fn an_exit_code_round_trips_including_negatives() {
        // A signal-terminated process reports a negative code on Unix, so
        // treating the field as unsigned would turn SIGKILL into 4294967287.
        for code in [0, 1, 127, -1, i32::MIN, i32::MAX] {
            let encoded = Exited { code }.encode();
            let decoded = Exited::validate(&Untrusted::new(encoded.to_vec())).expect("well-formed");
            assert_eq!(decoded.code, code);
        }
    }

    #[test]
    fn a_short_exit_body_is_refused_rather_than_padded() {
        // Padding would turn a malformed message into a plausible exit code,
        // which the caller would then believe — reporting success for a
        // command whose outcome is unknown.
        for truncated in [vec![], vec![0], vec![0, 0], vec![0, 0, 0]] {
            assert!(
                Exited::validate(&Untrusted::new(truncated.clone())).is_err(),
                "a {}-byte exit body was accepted",
                truncated.len()
            );
        }
    }

    #[test]
    fn a_long_exit_body_is_refused_rather_than_truncated() {
        let overlong = vec![0, 0, 0, 0, 0];
        assert_eq!(
            Exited::validate(&Untrusted::new(overlong)),
            Err(ProtocolError::MalformedBody {
                kind: Kind::Exited,
                reason: "an exit code is exactly 4 bytes",
            })
        );
    }

    // ---- the untrusted boundary -----------------------------------------

    #[test]
    fn decoding_yields_an_untrusted_header() {
        // `01` §2.5: anything from the agent is a claim. The type makes
        // "forgot to validate" a compile error — this asserts the decode
        // entry point actually returns the wrapper rather than a bare header.
        let claimed = Header::decode([0; Header::SIZE]);
        // Reaching the value requires validate() or the awkwardly-named
        // diagnostics accessor; there is no Deref.
        assert_eq!(claimed.for_diagnostics_only().version, 0);
        assert!(Header::validate(&claimed).is_err(), "version 0 is not ours");
    }

    #[test]
    fn a_refused_header_can_still_be_reported() {
        // A denial must say WHAT was rejected (`00` §3.3), so validation
        // cannot consume the claim.
        let claimed = header(VERSION, 9999, 0);
        let error = Header::validate(&claimed).expect_err("unknown kind");
        assert!(error.to_string().contains("9999"));
        assert_eq!(claimed.for_diagnostics_only().kind, 9999);
    }

    #[test]
    fn every_protocol_error_explains_itself() {
        let every = [
            ProtocolError::VersionMismatch {
                expected: 1,
                found: 2,
            },
            ProtocolError::BodyTooLarge {
                claimed: 99,
                limit: 10,
            },
            ProtocolError::UnknownKind { kind: 7 },
            ProtocolError::WrongDirection { kind: Kind::Exec },
            ProtocolError::MalformedBody {
                kind: Kind::Exited,
                reason: "why",
            },
        ];
        for error in every {
            let message = error.to_string();
            assert!(!message.is_empty(), "{error:?} renders empty");
            assert!(
                message.len() > 20,
                "{error:?} renders too briefly to act on: {message:?}"
            );
        }
    }
}
