//! The macOS VZ binding surface, pinned.
//!
//! Every method `02` §4 makes a hard constraint EXISTS with the signature
//! claimed. These are method REFERENCES, not string lookups: the file
//! compiles only if each name and signature exists. That is deliberate —
//! `12` §2's error was probing for a capability by guessed name, and this
//! probe's own first draft repeated it
//! (`validateSaveRestoreSupportAndReturnError`, which does not exist; the
//! compiler supplied `…WithError`).
//!
//! # What this file does NOT establish, and once claimed to
//!
//! It used to be titled "reachable as **safe** Rust", and `17` recorded
//! `SAFE` against each method on its evidence. **That was false.** All 502
//! functions in the binding are `pub unsafe fn`, and this file cannot show
//! otherwise: **taking a reference to an `unsafe fn` is safe; only calling
//! it is not.** So every assertion here passed while the claim built on
//! them was wrong.
//!
//! The lesson is narrower than "verify your claims" and worth keeping: a
//! probe is evidence only for the question it actually asks. Using the
//! compiler is not itself a guarantee of *which* question got answered —
//! here it answered "does this symbol exist?" and the answer was written
//! down against "is this call safe?". Calling one in the real
//! configuration is what settled it (`17`, the 2026-11-09 correction).
//!
//! A macOS SDK change that renames a method breaks this at **compile time**,
//! which is the better end of the trade.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use objc2_virtualization::{
    VZVirtioBlockDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioTraditionalMemoryBalloonDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration, VZVirtualMachineState,
};

#[test]
fn every_hard_constraint_in_02_section_4_exists_with_the_claimed_signature() {
    // `02` §4: validateSaveRestoreSupport is a SEPARATE gate from validate,
    // and must be surfaced as a capability rather than discovered at the
    // first suspend.
    let _validate_save_restore = VZVirtualMachineConfiguration::validateSaveRestoreSupportWithError;

    // `02` §4: the VM must be Paused before saving, and restore lands Paused
    // — which is why `lifecycle.rs` makes suspend and resume compound.
    let _save = VZVirtualMachine::saveMachineStateToURL_completionHandler;
    let _restore = VZVirtualMachine::restoreMachineStateFromURL_completionHandler;

    let _start = VZVirtualMachine::startWithCompletionHandler;
    let _pause = VZVirtualMachine::pauseWithCompletionHandler;
    let _resume = VZVirtualMachine::resumeWithCompletionHandler;
    let _can_pause = VZVirtualMachine::canPause;
    let _can_request_stop = VZVirtualMachine::canRequestStop;
}

#[test]
fn the_devices_the_product_needs_are_reachable() {
    // `02` §6's inventory, as types. Each maps to something the product
    // requires rather than something that merely exists.
    let _closure_and_state_disks = core::any::type_name::<VZVirtioBlockDeviceConfiguration>();
    let _workspace_mount = core::any::type_name::<VZVirtioFileSystemDeviceConfiguration>();

    // `12` §2's correction: an earlier doc claimed macOS had no balloon
    // device, because it probed for `VZVirtioBalloonDeviceConfiguration` by
    // guessed name. The real class is this one, and guest RAM CAN be
    // reclaimed without suspending.
    let _balloon = core::any::type_name::<VZVirtioTraditionalMemoryBalloonDeviceConfiguration>();
}

#[test]
fn the_vz_states_the_lifecycle_machine_mirrors_all_exist() {
    // `lifecycle.rs`'s states are ours, not VZ's — but they have to be
    // expressible in terms of these, or the backend cannot report honestly.
    let states = [
        VZVirtualMachineState::Stopped,
        VZVirtualMachineState::Running,
        VZVirtualMachineState::Paused,
        VZVirtualMachineState::Error,
    ];
    assert_eq!(states.len(), 4);
    // Distinct discriminants, so a match on one cannot silently cover another.
    for (index, state) in states.iter().enumerate() {
        for other in states.iter().skip(index + 1) {
            assert_ne!(state, other);
        }
    }
}
