//! The guest-side agent.
//!
//! Runs inside the VM and does three things: executes commands with full stdio
//! fidelity, bridges tool invocations from the host shims, and coordinates
//! lifecycle operations — flushing filesystems, quiescing databases, restarting
//! service units.
//!
//! **It is not the security authority.** It helps with graceful operations, but
//! a compromised guest can lie to it or refuse to cooperate, so the host makes
//! every policy decision and uses hypervisor-level primitives for anything that
//! must be trustworthy (idea.md §15.3). Everything this agent sends is
//! [`rachna_proto::Untrusted`] on the host side.
//!
//! Builds for a Linux target only; it is never run on the host.

fn main() -> anyhow::Result<()> {
    todo!("step 10: guest-side exec, stdio bridging, service control")
}
