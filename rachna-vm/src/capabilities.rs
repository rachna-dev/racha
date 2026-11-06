//! What a backend can actually do.
//!
//! Snapshot semantics differ sharply between hypervisors — Firecracker and
//! Cloud Hypervisor expose memory snapshots, Apple's framework saves machine
//! state with its own constraints, and Hyper-V distinguishes standard from
//! production checkpoints (idea.md §14.6). Rather than paper over that, each
//! backend declares its capabilities and the broker checks the policy against
//! them at startup.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Can save and restore guest RAM. This is what makes resume fast enough
    /// for the product to feel right (<300ms), so a backend without it is
    /// substantially weaker (design-docs/00-PRODUCT.md §7 Layer A).
    pub memory_snapshot: bool,
    /// Restores pages on demand rather than eagerly, cutting resume latency.
    pub lazy_memory_restore: bool,
    /// Disk-only recovery points, without live process memory.
    pub disk_checkpoint: bool,
    /// Copy-on-write disk layers, so snapshots do not duplicate a full disk.
    pub cow_disks: bool,
    /// Network can be mediated by the host rather than trusted to the guest.
    /// Without this, a network allowlist is not enforceable.
    pub controlled_networking: bool,
    pub fs_sharing: FsSharing,
    /// vsock, which the tool shims depend on for low-latency stdio proxying
    /// (design-docs/01-ARCHITECTURE.md §7).
    pub vsock: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FsSharing {
    /// virtiofs or equivalent: a live host directory visible in the guest.
    Virtiofs,
    /// Network filesystem fallback — generally slower, especially on metadata.
    NetworkFs,
    /// No sharing; the workspace must be copied in and out.
    None,
}
