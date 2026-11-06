//! The `rachna` binary.
//!
//! This is a **multi-call binary**, busybox-style. `.rachna/bin/` holds
//! symlinks back to it — `rust-analyzer`, `rustfmt`, `cargo` — and each one,
//! when executed, forwards stdio to the real tool in the guest. Your editor
//! thinks it is running `rust-analyzer`; it is running `rachna` wearing a hat
//! (design-docs/00-PRODUCT.md §6.3).
//!
//! So dispatch happens on `argv[0]` *before* clap ever sees the arguments: a
//! shim must pass `--version`, `--help`, and every other flag through to the
//! guest tool untouched rather than having clap interpret them.

mod cli;
mod shim;

use std::process::ExitCode;

fn main() -> ExitCode {
    init_tracing();

    // argv[0] decides everything. Invoked through a shim symlink, the arguments
    // belong to the guest tool and must not be parsed here.
    match shim::invoked_as() {
        shim::Invocation::Shim(tool) => shim::run(&tool),
        shim::Invocation::Rachna => cli::run(),
    }
}

/// Structured diagnostics from day one, filtered by `RUST_LOG`.
///
/// Writes to stderr so it never corrupts a shim's stdout — an LSP shim's stdout
/// is a JSON-RPC stream, and a stray log line there breaks the editor.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
