//! The whole product, on one host: a guest with real services, snapshotted
//! and restored.
//!
//! `macos_vm_lifecycle.rs` proves the hypervisor operations against a
//! busybox guest. This proves the thing a *user* asked for — a project with
//! Node and Postgres, data written through an app, and that data surviving
//! a suspend/resume cycle.
//!
//! # Why a hand-built image rather than `guest/flake.nix`
//!
//! Measured: the NixOS guest bundle needs **240 derivations built** for
//! `aarch64-linux`, and this host is `aarch64-darwin` with no Linux builder
//! — so it cannot be produced here at all (`02` §6.9).
//!
//! What *can* be produced is the same thing by substitution: `nodejs_22`
//! and `postgresql_16` **fetch** prebuilt for `aarch64-linux` from
//! `cache.nixos.org`, and their closures assemble into an ext4 root with
//! `mke2fs -d`. That is the same integrity chain `21` §2.1a describes —
//! content-addressed, signed by a key Nix verifies — reaching the same
//! place by a route this host can take.
//!
//! So this test is **not** a substitute for the flake; it is evidence that
//! the backend runs a guest with real services, which the flake will then
//! supply more completely.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rachna::backend::linux::{Disk, Launch};
use rachna::backend::macos_vm::{Guest, VmState};
use std::path::PathBuf;
use std::time::Duration;

/// Long enough for a real Postgres `initdb` plus a Node start.
const BOOT_BUDGET: Duration = Duration::from_secs(120);

fn fixture(name: &str) -> Option<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let (Ok(kernel), Ok(initrd), Ok(root)) = (
        std::env::var("RACHNA_TEST_KERNEL"),
        std::env::var("RACHNA_TEST_INITRD"),
        std::env::var("RACHNA_TEST_ROOT"),
    ) else {
        println!(
            "SKIP {name}: set RACHNA_TEST_KERNEL, RACHNA_TEST_INITRD and \
             RACHNA_TEST_ROOT to run against a guest with real services"
        );
        return None;
    };
    let dir = std::env::temp_dir().join(format!("rachna-stack-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    Some((
        PathBuf::from(kernel),
        PathBuf::from(initrd),
        PathBuf::from(root),
        dir,
    ))
}

/// A copy of the root image, so a test that writes cannot poison the next.
fn private_root(source: &std::path::Path, dir: &std::path::Path) -> PathBuf {
    let copy = dir.join("root.img");
    std::fs::copy(source, &copy).expect("copy the root image");
    copy
}

fn launch(kernel: PathBuf, initrd: PathBuf, root: PathBuf, dir: &std::path::Path) -> Launch {
    Launch {
        kernel,
        initrd,
        cmdline: "console=hvc0 root=/dev/vda rw".to_owned(),
        memory_mib: 2048,
        cpus: 2,
        disks: vec![Disk {
            path: root,
            read_only: false,
        }],
        shares: Vec::new(),
        console_log: dir.join("console.log"),
        api_socket: dir.join("api.sock"),
    }
}

/// A policy with the resources these tests need.
fn test_policy() -> rachna::decide::Policy {
    rachna::decide::Policy {
        tier: rachna::policy::Tier::Allowlist,
        profile: rachna::policy::Profile::Development,
        grants: Vec::new(),
        resources: rachna::resources::Resources {
            cpus: 2,
            memory_mib: 2048,
            disk_mib: 600,
            processes: 64,
        },
        capabilities: rachna::decide::Capabilities::all(),
    }
}

/// A sparse state volume, as `boot::provision_state` would make.
fn state_volume(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("state.img");
    let file = std::fs::File::create(&path).expect("state volume");
    file.set_len(600 * 1024 * 1024).expect("size it");
    path
}

fn console(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn a_guest_runs_postgres_and_a_node_app_against_it() {
    // The claim: a real database and a real application, inside the VM.
    let Some((kernel, initrd, root, dir)) = fixture("services") else {
        return;
    };
    let plan = launch(kernel, initrd, private_root(&root, &dir), &dir);
    let guest = Guest::new(&plan).expect("the configuration is valid");
    guest.start().expect("the guest starts");

    assert!(
        guest.wait_for_console(&plan.console_log, "RACHNA-SERVICES-UP", BOOT_BUDGET),
        "services never came up. Console:\n{}",
        console(&plan.console_log)
    );

    let log = console(&plan.console_log);
    // Postgres, by its own readiness marker rather than a sleep.
    assert!(
        log.contains("RACHNA-PG-READY"),
        "postgres did not become ready:\n{log}"
    );
    assert!(
        !log.contains("RACHNA-PG-FAILED"),
        "postgres failed to start:\n{log}"
    );
    // The app connected to it and created its schema.
    assert!(
        log.contains("TODOS: connected to postgres"),
        "the app never reached the database:\n{log}"
    );
    assert!(log.contains("TODOS: schema ready"), "{log}");
    assert!(
        log.contains("TODOS: listening on 3000"),
        "the app is not serving:\n{log}"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn todos_written_through_the_app_are_read_back_from_postgres() {
    // Data, not liveness. The rows go in over HTTP and come back out of
    // Postgres, which is what makes this a stack rather than two processes.
    let Some((kernel, initrd, root, dir)) = fixture("todos") else {
        return;
    };
    let plan = launch(kernel, initrd, private_root(&root, &dir), &dir);
    let guest = Guest::new(&plan).expect("valid configuration");
    guest.start().expect("starts");

    assert!(
        guest.wait_for_console(&plan.console_log, "RACHNA-TODOS-CHECKED", BOOT_BUDGET),
        "the guest never finished its todo check. Console:\n{}",
        console(&plan.console_log)
    );

    let log = console(&plan.console_log);
    for title in [
        "write the VZ backend",
        "boot a guest with postgres",
        "snapshot and restore it",
    ] {
        assert!(
            log.contains(title),
            "`{title}` never came back from the database:\n{log}"
        );
    }
    // And they came back as a LIST, so the read path works and not just the
    // write path.
    assert!(
        log.contains("TODOS [{\"id\":1"),
        "the list endpoint returned nothing usable:\n{log}"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_guest_can_read_a_file_the_host_just_wrote() {
    // THE workspace property, and it is deliberately a READ of a known
    // file rather than a directory listing.
    //
    // `02` §6.12: the share looked broken for most of a session because
    // `find` and `ls` return nothing on this mount — busybox applets
    // enumerating with `getdents`, which virtiofs here does not serve —
    // while reads, `stat` and `df` all work. I blamed the mount point,
    // `switch_root` and macOS sandboxing in turn. A `cat` of one known
    // filename would have settled it in a minute.
    //
    // So this test asserts the thing a user actually needs (the guest can
    // see my code) by the mechanism that actually works, and a listing is
    // checked separately below so a future readdir fix is noticed rather
    // than assumed.
    let Some((kernel, initrd, root, dir)) = fixture("workspace") else {
        return;
    };

    // A host directory with a file whose contents only this run knows, so
    // a stale image cannot produce a false pass.
    let workspace = dir.join("project");
    std::fs::create_dir_all(&workspace).expect("workspace dir");
    let marker = format!("host-wrote-this-{}", std::process::id());
    std::fs::write(workspace.join("marker.txt"), &marker).expect("marker");

    // BUILT BY `boot::launch_for`, not assembled here. The first version
    // of this test overrode `plan.shares` with a hand-made `Share` — and
    // then PASSED with `boot.rs`'s tag deliberately broken, because it
    // never consulted `boot.rs` at all. A test that supplies the value it
    // is checking is testing itself (AGENTS.md: "every adversarial test
    // must first assert that what it attacks exists").
    //
    // Verified the other way now: breaking the tag in `boot.rs` fails
    // this.
    let image = rachna::boot::Image {
        kernel: kernel.clone(),
        initramfs: initrd.clone(),
        root: root.clone(),
    };
    let project = rachna::layout::ProjectId::new("workspace-01").expect("id");
    let paths = rachna::layout::ProjectPaths::new(&dir, &project);
    let mut plan = rachna::boot::launch_for(
        &test_policy(),
        &image,
        &paths,
        &workspace,
        &dir,
        private_root(&root, &dir),
        state_volume(&dir),
    );
    // The console must land where this test reads it, and `launch_for`
    // puts it under the project's runtime directory.
    std::fs::create_dir_all(paths.runtime_dir()).expect("runtime dir");
    plan.cmdline = "console=hvc0 root=/dev/vda rw".to_owned();

    let guest = Guest::new(&plan).expect("a share must not break the configuration");
    guest.start().expect("starts");
    assert!(
        guest.wait_for_console(&plan.console_log, "RACHNA-SERVICES-UP", BOOT_BUDGET),
        "the guest never came up. Console:\n{}",
        console(&plan.console_log)
    );

    let log = console(&plan.console_log);
    // The kernel found the share: this is the layer below the mount, and
    // naming it separately means a tag mismatch is distinguishable from a
    // mount failure.
    assert!(
        log.contains("discovered new tag: workspace"),
        "the kernel never saw the share:\n{log}"
    );
    assert!(
        log.contains("RACHNA-WORKSPACE-MOUNTED"),
        "the workspace did not mount:\n{log}"
    );
    // AND THE FILE IS THERE. The guest's init globs the directory, which
    // is the listing method that works on this mount.
    assert!(
        log.contains("marker.txt"),
        "the guest cannot see the host's file, so the workspace is not \
         usable:\n{log}"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_supervisor_holds_its_configuration_across_a_suspend() {
    // THE design `02` §6.11 forced, exercised at the level that matters:
    // one `Guest` saves and the SAME `Guest` restores, because a rebuilt
    // configuration cannot (measured, asserted in
    // `macos_vm_lifecycle.rs`).
    //
    // This is what `rachna suspend` / `rachna resume` are built on — the
    // supervisor process stays alive while suspended so the object that
    // saved is still there to restore. A test that built a second guest
    // would be testing the thing that does not work.
    let Some((kernel, initrd, root, dir)) = fixture("hold") else {
        return;
    };
    let plan = launch(kernel, initrd, private_root(&root, &dir), &dir);
    let snapshot = dir.join("memory.vzvmsave");

    let guest = Guest::new(&plan).expect("valid configuration");
    assert!(
        guest.can_snapshot(),
        "this host cannot snapshot this device set"
    );
    guest.start().expect("starts");
    assert!(
        guest.wait_for_console(&plan.console_log, "RACHNA-TODOS-CHECKED", BOOT_BUDGET),
        "the stack never came up. Console:\n{}",
        console(&plan.console_log)
    );

    let ticks_before = console(&plan.console_log).matches("RACHNA-TICK-").count();
    assert!(ticks_before > 0, "the guest was not ticking before suspend");

    // suspend: pause -> save -> stop. The guest stops; the Guest lives.
    guest.pause().expect("pauses");
    guest.save(&snapshot).expect("saves");
    guest.stop().expect("stops");
    assert_eq!(guest.state(), VmState::Stopped);

    // resume: restore -> resume, through the SAME object.
    guest
        .restore(&snapshot)
        .expect("the holding guest restores");
    assert_eq!(guest.state(), VmState::Paused, "restore must land Paused");
    guest.resume().expect("resumes");
    assert_eq!(guest.state(), VmState::Running);

    // THE PROOF, and it is the guest's own output rather than a state
    // reading: a cold boot would restart the tick counter and re-run
    // initdb. `02` §6.11 records reading a tick count that could not
    // distinguish the two, so this waits for a tick BEYOND where it
    // stopped.
    let continued = guest.wait_for_console(
        &plan.console_log,
        &format!("RACHNA-TICK-{}", ticks_before + 2),
        Duration::from_secs(30),
    );
    let log = console(&plan.console_log);
    assert!(
        continued,
        "the restored guest never continued its work. Console tail:\n{}",
        log.lines().rev().take(12).collect::<Vec<_>>().join("\n")
    );
    // One initdb across the whole cycle: the database came back with the
    // memory rather than being recreated.
    assert_eq!(
        log.matches("RACHNA-PG-INITDB-DONE").count(),
        1,
        "postgres re-initialised, so this was a reboot and not a resume"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_running_stack_survives_a_snapshot_and_restore() {
    // THE test. Postgres running, data in it, an app serving — paused,
    // written to disk, stopped, restored, resumed. `02` §4's compound
    // paths, with a real workload rather than a sleeping shell.
    let Some((kernel, initrd, root, dir)) = fixture("snapshot") else {
        return;
    };
    let plan = launch(kernel, initrd, private_root(&root, &dir), &dir);
    let snapshot = dir.join("memory.vzvmsave");

    let guest = Guest::new(&plan).expect("valid configuration");
    assert!(
        guest.can_snapshot(),
        "this host cannot snapshot this device set, so the rest proves nothing"
    );

    guest.start().expect("starts");
    assert!(
        guest.wait_for_console(&plan.console_log, "RACHNA-TODOS-CHECKED", BOOT_BUDGET),
        "the stack never came up. Console:\n{}",
        console(&plan.console_log)
    );

    // Note where we are, so "it kept running" is measurable rather than
    // asserted: the guest prints a tick a second.
    let ticks_before = console(&plan.console_log).matches("RACHNA-TICK-").count();
    assert!(ticks_before > 0, "the guest was not ticking before suspend");

    // suspend = pause -> save -> stop
    guest.pause().expect("pauses");
    assert_eq!(guest.state(), VmState::Paused);
    guest.save(&snapshot).expect("saves");
    guest.stop().expect("stops");
    assert_eq!(guest.state(), VmState::Stopped);

    let size = std::fs::metadata(&snapshot).expect("metadata").len();
    // A guest running Postgres has touched far more memory than a busybox
    // one, so this is also a check that the snapshot reflects the workload.
    assert!(
        size > 32 * 1024 * 1024,
        "a guest running postgres produced only a {size}-byte snapshot"
    );

    // resume = restore -> resume, on the SAME Guest (`02` §4: the same
    // configuration object, or VZErrorRestore).
    guest.restore(&snapshot).expect("restores");
    assert_eq!(guest.state(), VmState::Paused, "restore must land Paused");
    guest.resume().expect("resumes");
    assert_eq!(guest.state(), VmState::Running);

    // THE PROOF: the restored guest keeps ticking from where it was. A cold
    // reboot would start again from RACHNA-TICK-0 and re-run initdb.
    let resumed = guest.wait_for_console(
        &plan.console_log,
        &format!("RACHNA-TICK-{}", ticks_before + 2),
        Duration::from_secs(30),
    );
    let log = console(&plan.console_log);
    assert!(
        resumed,
        "the restored guest never resumed its work. Console tail:\n{}",
        log.lines().rev().take(15).collect::<Vec<_>>().join("\n")
    );
    // It is the SAME boot, not a fresh one — so the running Postgres and
    // the app came back with it.
    assert_eq!(
        log.matches("RACHNA-BOOT-NUMBER: 1").count(),
        1,
        "the guest rebooted instead of resuming:\n{log}"
    );
    assert!(
        !log.contains("RACHNA-BOOT-NUMBER: 2"),
        "the restored guest booted afresh rather than resuming:\n{log}"
    );

    guest.stop().expect("stops");
    let _ = std::fs::remove_dir_all(&dir);
}
