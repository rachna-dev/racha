//! Multi-call dispatch.
//!
//! The binary decides what it is by looking at `argv[0]`. Anything other than
//! `rachna` itself is a tool shim, and its arguments belong to the guest tool.

use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;

/// How this process was invoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Invocation {
    /// The CLI proper.
    Rachna,
    /// A tool shim: the name is the declared tool to forward to.
    Shim(String),
}

/// Classify the current process by `argv[0]`.
pub(crate) fn invoked_as() -> Invocation {
    std::env::args_os()
        .next()
        .as_deref()
        .map_or(Invocation::Rachna, |arg0| classify(arg0))
}

/// Pure classification, so the interesting cases are testable.
fn classify(arg0: &OsStr) -> Invocation {
    let name = Path::new(arg0)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("rachna");

    // Strip a `.exe` suffix so the same logic holds if Windows support lands.
    let name = name.strip_suffix(".exe").unwrap_or(name);

    if name == "rachna" || name.is_empty() {
        Invocation::Rachna
    } else {
        Invocation::Shim(name.to_owned())
    }
}

/// Forward a tool invocation to the guest.
///
/// Three things this must get right, or the IDE story does not work
/// (design-docs/00-PRODUCT.md §5.1, §6.6):
///
/// - **stdio fidelity** — TTY passthrough when the host side is a TTY, raw
///   pipes otherwise; signals forwarded; exit code propagated verbatim.
/// - **path translation** — via `rachna-paths`, never ad hoc here.
/// - **warm connection** — connect to the already-running broker over a unix
///   socket, which holds the vsock session open. Paying VM-connection cost per
///   format-on-save would be felt immediately.
pub(crate) fn run(_tool: &str) -> ExitCode {
    todo!("step 10: forward stdio to the guest over the broker's warm session")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn classify_str(s: &str) -> Invocation {
        classify(&OsString::from(s))
    }

    #[test]
    fn plain_invocation_is_the_cli() {
        assert_eq!(classify_str("rachna"), Invocation::Rachna);
        assert_eq!(classify_str("/usr/local/bin/rachna"), Invocation::Rachna);
        assert_eq!(classify_str("./target/debug/rachna"), Invocation::Rachna);
    }

    #[test]
    fn symlink_name_selects_the_tool() {
        assert_eq!(
            classify_str(".rachna/bin/rust-analyzer"),
            Invocation::Shim("rust-analyzer".to_owned())
        );
        assert_eq!(
            classify_str("/Users/you/Projects/app/.rachna/bin/rustfmt"),
            Invocation::Shim("rustfmt".to_owned())
        );
    }

    #[test]
    fn exe_suffix_is_stripped() {
        assert_eq!(classify_str("rachna.exe"), Invocation::Rachna);
        assert_eq!(
            classify_str("rust-analyzer.exe"),
            Invocation::Shim("rust-analyzer".to_owned())
        );
    }

    #[test]
    fn unreadable_arg0_falls_back_to_the_cli() {
        // Better to show help than to try forwarding to a tool named "".
        assert_eq!(classify_str(""), Invocation::Rachna);
        assert_eq!(classify_str("/"), Invocation::Rachna);
    }
}
