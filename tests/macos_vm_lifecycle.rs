//! The macOS VM lifecycle, against the real framework.
//!
//! Not a mock. `01` §3 has `backend.rs`'s conformance suite for the mock;
//! this is the other end — an actual aarch64 Linux guest, booted, paused,
//! snapshotted, restored and resumed on this host.
//!
//! # Why this needs a real kernel, and skips without one
//!
//! `02` §6.5 measured that the guest kernel **fetches** from
//! `cache.nixos.org` onto an `aarch64-darwin` host with no Linux builder.
//! So the fixture is obtainable, but it is a 31 MiB download, and a test
//! suite that fails on a machine with no network is a test suite people
//! stop running. `RACHNA_TEST_KERNEL` and `RACHNA_TEST_INITRD` name the
//! fixture; without them these skip and say so.
//!
//! **A skip is printed, not silent.** `21` §3.3's rule about reading a
//! gate's verdict applies to this file too: a test that quietly passes when
//! it did nothing is worse than no test.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rachna::backend::linux::Launch;
use rachna::backend::macos_vm::{Guest, VmState};
use std::path::PathBuf;
use std::time::Duration;

/// The fixture, or `None` with a printed reason.
fn fixture(name: &str) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let (Ok(kernel), Ok(initrd)) = (
        std::env::var("RACHNA_TEST_KERNEL"),
        std::env::var("RACHNA_TEST_INITRD"),
    ) else {
        println!(
            "SKIP {name}: set RACHNA_TEST_KERNEL and RACHNA_TEST_INITRD to run \
             against a real guest (see 02 §6.5 for how to fetch one)"
        );
        return None;
    };
    let dir = std::env::temp_dir().join(format!("rachna-vm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    Some((PathBuf::from(kernel), PathBuf::from(initrd), dir))
}

fn launch(kernel: PathBuf, initrd: PathBuf, dir: &std::path::Path) -> Launch {
    Launch {
        kernel,
        initrd,
        // `rdinit` because the fixture is an initramfs with no root disk.
        cmdline: "console=hvc0 rdinit=/init".to_owned(),
        memory_mib: 1024,
        cpus: 2,
        disks: Vec::new(),
        shares: Vec::new(),
        console_log: dir.join("console.log"),
        api_socket: dir.join("api.sock"),
    }
}

#[test]
fn a_guest_boots_and_reaches_userspace() {
    // The claim this whole backend rests on. `01` §7.0c recorded that
    // nothing on macOS launched a VM at all; this is what changed.
    let Some((kernel, initrd, dir)) = fixture("boot") else {
        return;
    };
    let plan = launch(kernel, initrd, &dir);
    let guest = Guest::new(&plan).expect("the configuration is valid on this host");

    assert_eq!(
        guest.state(),
        VmState::Stopped,
        "a new guest is not stopped"
    );
    guest.start().expect("the guest starts");

    // The marker the fixture's init writes. Not "did VZ say Running" — a
    // VM reports Running while the guest is starved of CPU (`02` §6.3), so
    // the only honest proof is output the GUEST produced.
    assert!(
        guest.wait_for_console(&plan.console_log, "RACHNA-BOOT-OK", Duration::from_secs(45)),
        "the guest never reached userspace. Console:\n{}",
        std::fs::read_to_string(&plan.console_log).unwrap_or_default()
    );

    let log = std::fs::read_to_string(&plan.console_log).unwrap_or_default();
    assert!(log.contains("Run /init as init process"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_booted_guest_pauses_and_resumes() {
    // `02` §4: pause retains memory, and Paused is the only state a
    // snapshot may be taken from — so this is the step `suspend` is built
    // out of, tested on its own before the compound operation.
    let Some((kernel, initrd, dir)) = fixture("pause") else {
        return;
    };
    let plan = launch(kernel, initrd, &dir);
    let guest = Guest::new(&plan).expect("valid configuration");
    guest.start().expect("starts");
    assert!(
        guest.wait_for_console(
            &plan.console_log,
            "RACHNA-GUEST-ALIVE",
            Duration::from_secs(45)
        ),
        "the guest never came up"
    );

    guest.pause().expect("pauses");
    assert_eq!(
        guest.state(),
        VmState::Paused,
        "pause did not land in Paused"
    );

    guest.resume().expect("resumes");
    assert_eq!(
        guest.state(),
        VmState::Running,
        "resume did not land in Running"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_guest_snapshots_and_restores_its_memory() {
    // THE compound path, and the one `02` §4 has the most constraints on:
    // pause before save, restore lands Paused, and the SAME config object
    // must be reused or restore fails with VZErrorRestore.
    let Some((kernel, initrd, dir)) = fixture("snapshot") else {
        return;
    };
    let plan = launch(kernel, initrd, &dir);
    let snapshot = dir.join("memory.vzvmsave");

    let guest = Guest::new(&plan).expect("valid configuration");
    // First assert the capability EXISTS, or the save below proves nothing
    // about whether this host can snapshot at all.
    assert!(
        guest.can_snapshot(),
        "validateSaveRestoreSupport refused this device set, so the rest of \
         this test cannot distinguish a bug from an unsupported host"
    );

    guest.start().expect("starts");
    assert!(
        guest.wait_for_console(
            &plan.console_log,
            "RACHNA-GUEST-ALIVE",
            Duration::from_secs(45)
        ),
        "the guest never came up"
    );

    // suspend = pause -> save -> stop (`02` §4).
    guest.pause().expect("pauses");
    guest.save(&snapshot).expect("saves its memory");
    assert!(snapshot.exists(), "save reported success and wrote nothing");
    let size = std::fs::metadata(&snapshot)
        .expect("snapshot metadata")
        .len();
    // MEASURED, not assumed: a 1 GiB guest running a busybox init produced
    // **32 MiB**. This assertion first demanded >64 MiB on the strength of
    // `24` §4's "the file is the full configured memory", and failed — so
    // that claim is Cloud-Hypervisor-specific, and VZ writes only the pages
    // the guest has touched. `02` §6.6 records the correction.
    //
    // The bound is therefore "not empty and not absurd": a few MiB means a
    // guest that never ran, and more than the configured memory is
    // impossible. Both are real failures; 32 MiB is not.
    assert!(
        size > 4 * 1024 * 1024,
        "a running guest produced a {size}-byte snapshot, which is too small \
         to contain a booted kernel"
    );
    assert!(
        size <= 1024 * 1024 * 1024,
        "the snapshot is {size} bytes, larger than the guest's configured memory"
    );
    guest.stop().expect("stops");
    assert_eq!(guest.state(), VmState::Stopped);

    // resume = restore -> resume, on the SAME Guest so the config object is
    // the one the snapshot was taken with.
    guest.restore(&snapshot).expect("restores");
    assert_eq!(
        guest.state(),
        VmState::Paused,
        "`02` §4 says restore lands Paused, which is why resume is compound"
    );
    guest.resume().expect("resumes");
    assert_eq!(
        guest.state(),
        VmState::Running,
        "the restored guest is not running"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn measured_whether_a_rebuilt_configuration_can_restore_at_all() {
    // THE question cross-process resume depends on, and `02` §4 only half
    // answers it: *"restore initially failed until the same config object
    // was reused"*. If a rebuilt configuration can never restore, then a
    // supervisor — which is a NEW PROCESS and cannot hold the original
    // object — cannot resume, and `rachna resume` needs a different design
    // rather than a smaller fix.
    //
    // This test exists to record the answer rather than to assert a
    // behaviour I want. It prints what each path does and asserts only the
    // thing that must hold either way: the SAME object restores.
    let Some((kernel, initrd, dir)) = fixture("rebuilt-config") else {
        return;
    };
    let plan = launch(kernel, initrd, &dir);
    let snapshot = dir.join("memory.vzvmsave");

    let original = Guest::for_restore(&plan).expect("valid configuration");
    if !original.can_snapshot() {
        println!("SKIP: this host cannot snapshot this device set");
        return;
    }
    original.start().expect("starts");
    assert!(
        original.wait_for_console(
            &plan.console_log,
            "RACHNA-GUEST-ALIVE",
            Duration::from_secs(45)
        ),
        "the guest never came up"
    );
    original.pause().expect("pauses");
    original.save(&snapshot).expect("saves");
    original.stop().expect("stops");

    // THE BASELINE: the same object must restore, or the snapshot itself
    // is bad and nothing below means anything.
    original
        .restore(&snapshot)
        .expect("the SAME configuration object must restore its own snapshot");
    assert_eq!(original.state(), VmState::Paused);
    original.resume().expect("resumes");
    original.stop().expect("stops");
    println!("same object:    restore OK");

    // AND THE MEASUREMENT, now asserted rather than printed: a rebuilt
    // configuration is REFUSED. This is what makes the design necessary —
    // the supervisor holds its guest across a suspend because nothing else
    // can restore it — so if this ever starts passing, the simpler design
    // (suspend exits, resume rebuilds) becomes available and this test is
    // where that is noticed.
    let rebuilt = Guest::for_restore(&plan).expect("valid configuration");
    let refused = rebuilt.restore(&snapshot);
    assert!(
        refused.is_err(),
        "a REBUILT configuration restored successfully. `02` §6.11 says it \
         cannot, and the whole held-supervisor design exists because of \
         that — re-measure before simplifying, but this is good news"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_is_refused_unless_the_guest_is_paused() {
    // `02` §4 makes this a hypervisor rule, and `lifecycle.rs` §2 declines
    // to be clever about it. Refusing on our side turns a framework
    // exception into a sentence.
    let Some((kernel, initrd, dir)) = fixture("unpaused") else {
        return;
    };
    let plan = launch(kernel, initrd, &dir);
    let guest = Guest::new(&plan).expect("valid configuration");
    guest.start().expect("starts");
    assert!(
        guest.wait_for_console(
            &plan.console_log,
            "RACHNA-GUEST-ALIVE",
            Duration::from_secs(45)
        ),
        "the guest never came up"
    );

    // Running, not paused.
    let error = guest
        .save(&dir.join("should-not-exist.vzvmsave"))
        .expect_err("saving a running guest must be refused");
    let text = error.to_string();
    assert!(text.contains("must be paused"), "{text}");
    assert!(
        !dir.join("should-not-exist.vzvmsave").exists(),
        "a refused save still wrote a file"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}
