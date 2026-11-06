//! An in-process backend, so the whole product can be built without a
//! hypervisor.
//!
//! Also the reference for the conformance suite: the same tests run against
//! this and against every real backend.

use async_trait::async_trait;
use rachna_core::{ExecSpec, Result, SnapshotId};

use crate::backend::{VmBackend, VmHandle};
use crate::capabilities::{Capabilities, FsSharing};

#[derive(Debug, Default)]
pub struct MockBackend;

#[async_trait]
impl VmBackend for MockBackend {
    fn capabilities(&self) -> Capabilities {
        // Claims everything, so policy checks pass and the rest of the system
        // can be exercised. A backend that *lacks* a capability is a separate
        // fixture, used to test that Rachna refuses rather than downgrades.
        Capabilities {
            memory_snapshot: true,
            lazy_memory_restore: true,
            disk_checkpoint: true,
            cow_disks: true,
            controlled_networking: true,
            fs_sharing: FsSharing::Virtiofs,
            vsock: true,
        }
    }

    fn name(&self) -> &'static str {
        "mock"
    }

    async fn start(&self, _spec: &ExecSpec) -> Result<VmHandle> {
        todo!("step 6: simulate state transitions and timing")
    }

    async fn pause(&self, _vm: &VmHandle) -> Result<()> {
        todo!("step 6")
    }

    async fn resume(&self, _vm: &VmHandle) -> Result<()> {
        todo!("step 6")
    }

    async fn suspend(&self, _vm: &VmHandle) -> Result<SnapshotId> {
        todo!("step 6")
    }

    async fn restore(&self, _id: &SnapshotId) -> Result<VmHandle> {
        todo!("step 6")
    }

    async fn shutdown(&self, _vm: &VmHandle) -> Result<()> {
        todo!("step 6")
    }
}
