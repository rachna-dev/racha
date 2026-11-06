//! The trait every backend implements.

use async_trait::async_trait;
use rachna_core::{ExecSpec, Result, SnapshotId};

use crate::capabilities::Capabilities;

/// A handle to one running environment.
///
/// Opaque by design: the broker holds it, and backend-specific details stay
/// behind the trait. If one `rachna.nix` ever supports multiple live
/// environments, env identity threads through here
/// (design-docs/01-ARCHITECTURE.md §11.4 — still open).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmHandle(pub String);

#[async_trait]
pub trait VmBackend: Send + Sync {
    /// What this backend can enforce. Checked against the policy at startup.
    fn capabilities(&self) -> Capabilities;

    /// Human name, used in capability-gap errors.
    fn name(&self) -> &'static str;

    async fn start(&self, spec: &ExecSpec) -> Result<VmHandle>;

    /// Freeze execution, keeping RAM allocated.
    async fn pause(&self, vm: &VmHandle) -> Result<()>;

    async fn resume(&self, vm: &VmHandle) -> Result<()>;

    /// Save state durably and release the VM's host RAM.
    ///
    /// Must not release the live VM until the save is confirmed durable: if a
    /// save fails, the original environment stays recoverable
    /// (idea.md §15.2).
    async fn suspend(&self, vm: &VmHandle) -> Result<SnapshotId>;

    async fn restore(&self, id: &SnapshotId) -> Result<VmHandle>;

    async fn shutdown(&self, vm: &VmHandle) -> Result<()>;
}
