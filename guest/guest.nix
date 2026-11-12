# The guest system.
#
# `05-SPIKE-NIXOS-GUEST.md` §3's posture, and §4's fixes. Deliberately
# minimal: every service here is one more thing to boot (§5 measured 6.97s,
# of which 3.4s is userspace) and one more attack surface.
{
  config,
  lib,
  pkgs,
  ...
}:
{
  system.stateVersion = "26.11";

  # ---- what the backend requires -----------------------------------------

  boot.loader.grub.enable = false;
  boot.initrd.includeDefaultModules = false;
  # virtio only. §4.4's bzImage/vmlinux issue is handled in the flake; these
  # are the modules the guest needs to find its own root and devices.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_console"
    "virtiofs"
    "virtio_net"
    "9p"
    "fuse"
    "overlay"
    # The root is a squashfs (`00` §7 Layer C), so the initrd must be able to
    # MOUNT one. Measured without these: the initrd finds /dev/vda, then
    # fails "Dependency failed for Initrd File Systems" and drops to
    # emergency mode — the device is present and unmountable, which reads
    # like a missing disk rather than a missing module.
    "squashfs"
    "loop"
    "zstd"
  ];
  boot.kernelModules = [ "virtiofs" ];

  # `availableKernelModules` only INCLUDES a module if the generator decides
  # it is needed, and it does not know our root is a squashfs on a virtio
  # disk. Forcing them guarantees the initrd can mount the root it is given.
  boot.initrd.kernelModules = [
    "squashfs"
    "virtio_blk"
    "virtiofs"
  ];

  # §4.3, measured: `console=ttyS0` with `--serial file=`. The hvc0 variant
  # produces ZERO output and ZERO errors, which is the worst failure shape.
  boot.kernelParams = [
    "console=ttyS0"
    "8250.nr_uarts=1"
    # A guest that panics should die rather than sit at a prompt nothing is
    # watching.
    "panic=1"
    "nomodeset"
  ];

  # ---- the mounts ---------------------------------------------------------

  # The root is a tmpfs; the STORE is the overlay. This is how NixOS's own ISO
  # image does it, and it is the right shape rather than merely the supported
  # one: `00` §7 Layer C's closure *is* a store, so overlaying the store says
  # what we actually mean.
  #
  # FOUR attempts got here, each rejected more informatively than the last:
  #
  #   no root at all            -> "Failed to start Find NixOS closure"
  #   squashfs root, no module  -> /dev/vda found and UNMOUNTABLE
  #   squashfs root, read-only  -> "Mounted /sysroot", then "Failed to mount
  #                                /sysroot/run" — present, nothing writable
  #   overlay root with layers
  #     declared as fileSystems -> rejected AT EVAL: "can't be topologically
  #                                sorted: / -> /closure loops to /", which
  #                                is correct and unarguable — a layer
  #                                mounted UNDER the root cannot be a
  #                                prerequisite of that root
  #
  # Overlaying the store has no such loop: /nix/store sits inside a root that
  # is already mounted.
  boot.initrd.systemd.enable = true;
  boot.initrd.supportedFilesystems = [
    "squashfs"
    "overlay"
  ];

  fileSystems."/" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
  };

  # The immutable half: this project's closure, read-only, first disk.
  # Shared across projects (`08` §4.1.1) — 493 MB once rather than per
  # project, which a writable image could not do.
  fileSystems."/nix/.ro-store" = {
    device = "/dev/vda";
    fsType = "squashfs";
    options = [
      "ro"
      "loop"
    ];
    neededForBoot = true;
  };

  # The writable half, in RAM. `00` §7 records what this costs: writes eat
  # the memory budget, land in every snapshot (plaintext on Linux, `09` §4),
  # and carry overlayfs semantics. All three are why DURABLE DATA BELONGS ON
  # THE STATE VOLUME rather than here.
  fileSystems."/nix/.rw-store" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
    neededForBoot = true;
  };

  # NixOS's first-class overlay option, not hand-rolled mount units — `19` §3
  # warns against fighting the module system, and the hand-rolled attempt is
  # what produced the topological loop above.
  fileSystems."/nix/store" = {
    overlay = {
      lowerdir = [ "/nix/.ro-store" ];
      upperdir = "/nix/.rw-store/store";
      workdir = "/nix/.rw-store/work";
    };
  };

  # §4.1, the bug that cost real time: mounting the host's state share on
  # `/var/lib` SHADOWS `/var/lib/systemd`, which systemd must create at boot
  # — logind then fails 238/STATE_DIRECTORY three times every boot.
  #
  # So systemd gets its own tmpfs, and persistent state lives one level down
  # in a Rachna-namespaced directory that services are pointed at.
  fileSystems."/var/lib/systemd" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
  };

  fileSystems."/var/lib/rachna" = {
    device = "/dev/vdb";
    fsType = "ext4";
    options = [ "nofail" ];
  };

  fileSystems."/workspace" = {
    device = "workspace";
    fsType = "virtiofs";
    options = [ "nofail" ];
  };

  # ---- the declared process limit, actually enforced (15 §7 tier 1) ------

  # `19` §2.1 declares `resources.processes = 512`. `15` §3.2 measured what
  # it did: **nothing**. 512 declared, `ulimit -u` reporting **7754**. A
  # declared limit that does nothing is a lie in the config file, which is
  # why `15` §7 lists it as tier 1 rather than as a resource nicety.
  #
  # It must be enforced GUEST-SIDE, and that is a measurement rather than a
  # preference: during a 400-process fork bomb the host cgroup saw
  # `pids.current 15/256`, because guest processes are not host tasks. The
  # host cannot cover for this.
  #
  # Two mechanisms, because they catch different things:
  #
  #   DefaultTasksMax     a cgroup `pids.max` per unit — catches a runaway
  #                       service, and cannot be raised from inside the unit
  #   DefaultLimitNPROC   the rlimit systemd hands every unit it starts
  #
  # The cgroup limit is the real containment: an rlimit is per-UID and a
  # process can lower but not raise it, while `pids.max` is enforced by the
  # kernel on the whole cgroup regardless of what the processes want.
  #
  # MEASURED, and the first attempt was wrong in an instructive way. Setting
  # only `security.pam.loginLimits` left a booted service reporting
  # `ulimit -u` = **7751** — `15` §3.2's 7754 almost exactly — while
  # `systemctl show -p TasksMax` already read 512. PAM limits apply to a PAM
  # *login session*, and a systemd service is not one, so the rlimit half
  # silently did nothing for every service in the guest. `DefaultLimitNPROC`
  # is the manager-level setting that actually reaches them; the PAM entry is
  # kept for interactive logins, which is the case it does cover.
  #
  # The number is deliberately the one `19` §2.1 declares. When the backend
  # starts generating this file from `rachna.nix` it substitutes the project's
  # value; until then the default is pinned here so the declared figure and
  # the enforced figure are the same figure.
  security.pam.loginLimits = [
    {
      domain = "*";
      type = "hard";
      item = "nproc";
      value = "512";
    }
  ];

  # ---- the security posture (05 §3) --------------------------------------

  # The guest runs unprivileged. Root in the guest does not escape the VM,
  # but it escapes every guest-side mitigation (`idea.md` §8.4).
  users.users.dev = {
    isNormalUser = true;
    uid = 1000;
    group = "users";
    home = "/home/dev";
  };
  users.allowNoPasswordLogin = true;

  # Forced by Rachna, not offered to a project (`19` §3). A project that
  # could enable sudo could defeat the unprivileged-guest property.
  security.sudo.enable = lib.mkForce false;
  security.polkit.enable = lib.mkForce false;

  # A second way in would bypass the agent and therefore the audit trail.
  services.openssh.enable = lib.mkForce false;

  # The guest must not fetch its own packages: that would escape both the
  # reproducibility contract and the network policy (`19` §3).
  nix.settings.substituters = lib.mkForce [ ];
  nix.settings.sandbox = true;

  # ---- trimmed for boot time (05 §5) -------------------------------------

  # Measured: removing these took 7.36s -> 6.97s. The four units
  # `systemd-analyze blame` blamed at ~4s each were NOT delays — it reports
  # how long a unit existed, not time waited (§5's method finding).
  systemd.services.systemd-journal-catalog-update.enable = false;
  systemd.services.systemd-update-done.enable = false;
  networking.resolvconf.enable = false;

  documentation.enable = false;
  documentation.man.enable = false;
  services.udisks2.enable = false;
  xdg.autostart.enable = false;
  xdg.icons.enable = false;
  xdg.mime.enable = false;
  xdg.sounds.enable = false;
  fonts.fontconfig.enable = false;

  # §4.2's renamed options. Both are hard eval errors with a clear message,
  # recorded because pinning means we hit them again on every deliberate bump.
  systemd.settings.Manager = {
    DefaultTimeoutStartSec = "30s";
    DefaultTimeoutStopSec = "10s";
    # The other half of the process limit above: a cgroup `pids.max` on every
    # unit. Folded in here rather than set separately, because two
    # `systemd.settings.Manager` blocks merge silently and a reader has to
    # find both to know what systemd was told.
    DefaultTasksMax = 512;
    # The rlimit half. `security.pam.loginLimits` alone does NOT reach a
    # service — measured at 7751 with that set — because a service is not a
    # PAM login session.
    DefaultLimitNPROC = "512:512";
  };
  services.journald.settings.Journal = {
    Storage = "volatile";
    RuntimeMaxUse = "32M";
  };

  # ---- durable service data (15 §7 tier 1) -------------------------------

  # `16` §5.1 measured that Postgres CANNOT use a virtiofs data directory at
  # all — `226/NAMESPACE` on every boot — and that the lifecycle story was
  # validated only with data on **tmpfs**, meaning a database did not survive
  # a cold boot. `15` §7 calls that a *consistency* defect rather than a
  # performance one: a tool promising "come back to a warm Postgres" and
  # silently losing the data on restart is broken in the way that matters
  # most.
  #
  # So service data goes on the state BLOCK DEVICE, which fixes both halves:
  # it is not virtiofs, so no namespace failure; and it is not tmpfs, so it
  # survives. This is also the constraint `00` §7's overlay decision imposes
  # — overlayfs semantics leak (EXDEV, copy-up, fsync durability), and a
  # database is exactly the kind of program that notices.
  #
  # `/var/lib/rachna` rather than `/var/lib`, per §4.1: mounting over a
  # directory systemd owns shadows `/var/lib/systemd` and logind fails
  # 238/STATE_DIRECTORY on every boot.
  services.postgresql = {
    enable = true;
    dataDir = "/var/lib/rachna/postgresql/${config.services.postgresql.package.psqlSchema}";
    package = pkgs.postgresql_16;
    # `listen_addresses` is left at the module's default of `localhost`,
    # which is already what we want: the host enforces network policy
    # (`00` §3.9) and the guest firewall is off, so a guest-local bind is the
    # correct posture. Overriding it to `127.0.0.1` was a redundant
    # definition that failed evaluation outright — the module system catching
    # a change that said nothing.
    settings.port = 5432;
    authentication = lib.mkForce ''
      local all all trust
      host all all 127.0.0.1/32 trust
    '';
  };

  # Two things the module does not do for us, both found by measurement.
  #
  # 1. ORDERING. The state volume must be mounted before Postgres starts.
  #
  # 2. CREATION. `dataDir` must already EXIST, and on a freshly-`mkfs.ext4`
  #    state volume it does not. The default `/var/lib/postgresql` is created
  #    for you; a `dataDir` pointed anywhere else is not, and the module ships
  #    no tmpfiles rule for it — verified by evaluating
  #    `systemd.tmpfiles.rules`, which mentions neither postgres nor rachna.
  #
  #    The failure this produces is *not* "directory missing". The unit sets
  #    `ProtectSystem = "strict"` with `ReadWritePaths = [ dataDir ]`, so
  #    systemd tries to build a mount namespace around a path that is not
  #    there and the unit dies in namespace setup — BEFORE `ExecStartPre`,
  #    which is the script that would have run `initdb`. Hence a console
  #    reading "Failed to start PostgreSQL Server" and "Dependency failed for
  #    PostgreSQL Setup Scripts" with no cause named, and hence four
  #    identical restart failures: `Restart = "always"` retrying something
  #    that cannot succeed.
  #
  #    So the directory is created by a unit ordered after the mount and
  #    before Postgres. Not `systemd.tmpfiles.rules`: those run at
  #    `systemd-tmpfiles-setup`, which is ordered BEFORE local filesystems
  #    are all mounted, so the rule would land on the tmpfs root and then be
  #    hidden by the real mount.
  systemd.services.rachna-postgres-datadir = {
    description = "Create the Postgres data directory on the state volume";
    after = [ "var-lib-rachna.mount" ];
    requires = [ "var-lib-rachna.mount" ];
    before = [ "postgresql.service" ];
    requiredBy = [ "postgresql.service" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      install -d -o postgres -g postgres -m 0700 \
        "${config.services.postgresql.dataDir}"
    '';
  };

  systemd.services.postgresql = {
    after = [ "var-lib-rachna.mount" ];
    requires = [ "var-lib-rachna.mount" ];
  };

  # ---- the durability probe (15 §7 tier 1) --------------------------------

  # The test this exists for is NOT "did Postgres start". A database that
  # re-initialises itself empty on every boot starts perfectly and has lost
  # the user's data — which is precisely the defect `15` §7 names. So the
  # guest WRITES a row on the first boot and READS IT BACK on the second,
  # and the harness reads the verdict off the console.
  #
  # Which phase this is comes from the kernel cmdline (`rachna.phase=`), so
  # one image serves both boots and the host chooses. Temporary, like the
  # diagnostic below: it belongs in a host-driven test once the agent can
  # execute in the guest.
  systemd.services.rachna-durability-probe = {
    description = "Write then read a row across boots (diagnostic)";
    wantedBy = [ "multi-user.target" ];
    after = [ "postgresql.service" ];
    requires = [ "postgresql.service" ];
    serviceConfig = {
      Type = "oneshot";
      User = "postgres";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    script = ''
      set -u
      psql=${config.services.postgresql.package}/bin/psql
      phase=$(sed -n 's/.*rachna\.phase=\([a-z]*\).*/\1/p' /proc/cmdline)
      echo "RACHNA-PROBE: phase=''${phase:-unset}"

      if [ "$phase" = "one" ]; then
        # `IF NOT EXISTS` deliberately NOT used for the insert: the row count
        # read back on boot two is the measurement, so writing twice would
        # make a lost-and-recreated database indistinguishable from a durable
        # one.
        $psql -U postgres -v ON_ERROR_STOP=1 -c \
          "CREATE TABLE durability (id serial primary key, note text);" \
          -c "INSERT INTO durability (note) VALUES ('survived');" \
          && echo "RACHNA-PROBE: wrote=ok" || echo "RACHNA-PROBE: wrote=FAIL"
        # Forced to disk, because the question is what survives a cold boot
        # rather than what a running server remembers.
        $psql -U postgres -c "CHECKPOINT;" >/dev/null 2>&1 \
          && echo "RACHNA-PROBE: checkpoint=ok" || echo "RACHNA-PROBE: checkpoint=FAIL"
      else
        # `|| true` and an explicit default, because the falsification run
        # showed what happens without them: with the data on tmpfs the table
        # is gone, psql exits non-zero, the unit dies at THIS line under
        # `set -u`, and no verdict is printed at all. The data loss was still
        # detectable (the unit failed) but only as SILENCE — the same
        # false-negative shape as the ANSI-blind failure counter. A probe must
        # state its verdict on every path, including its own failure.
        n=$($psql -U postgres -tAc \
          "SELECT count(*) FROM durability WHERE note = 'survived';" \
          2>/dev/null || true)
        n=''${n:-<query-failed>}
        echo "RACHNA-PROBE: rows=$n"
        if [ "$n" = "1" ]; then
          echo "RACHNA-PROBE: VERDICT=DURABLE"
        else
          echo "RACHNA-PROBE: VERDICT=DATA-LOST"
        fi
      fi
    '';
  };

  # ---- the process-limit probe (15 §3.2's measurement, repeated) ---------

  # `15` §3.2 measured `ulimit -u` = **7754** against a declared 512. So the
  # probe reports the same number the finding reports, and then actually
  # forks: a limit that reads correctly and does not hold is the same lie in
  # a different place.
  #
  # Temporary, like the other probes — it belongs in the adversarial suite
  # once the agent can execute in the guest.
  # ---- the workspace filesystem probe -----------------------------------

  # WHY THIS EXISTS: virtiofs metadata cost over the workspace mount was
  # measured on macOS at ~40000 stats/s against ~400000/s for the guest's
  # own ext4 — a ~10x gap. Apple's Virtualization.framework exposes no
  # caching knob for a directory share (`VZVirtioFileSystemDeviceConfiguration`
  # has only tag/share), and the guest kernel's virtiofs client accepts
  # only `dax` (Linux 6.18.54, `fs/fuse/virtio_fs.c`). So on macOS the gap
  # is not configurable.
  #
  # `virtiofsd` — the Linux path — DOES offer `--cache={auto,always,never,
  # metadata}` and `--writeback`. This unit measures whether those move the
  # number, which decides whether "as fast as native" is reachable on Linux
  # and therefore whether the two platforms need different work.
  #
  # Python, NOT a shell loop. That distinction invalidated four earlier
  # rounds of this measurement: on a local filesystem a shell loop forking
  # `/bin/stat` ran 20000 files in 48043 ms while a `python os.stat` loop
  # took 57 ms — 843x, essentially all of it fork+exec. A probe whose
  # overhead dwarfs what it measures reports a plausible number about
  # nothing.
  #
  # Temporary, like the other probes here, and removed once the figure is
  # recorded in a spike doc.
  systemd.services.rachna-fs-probe = {
    description = "Measure workspace metadata cost (diagnostic)";
    wantedBy = [ "multi-user.target" ];
    after = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    script = ''
      set -u
      py=${pkgs.python3}/bin/python3

      # The policy under test is passed on the kernel command line, so one
      # image serves every run and the harness chooses. Reported back so a
      # console log is self-describing rather than needing the invocation
      # alongside it.
      policy=$(sed -n 's/.*rachna\.vfscache=\([a-z]*\).*/\1/p' /proc/cmdline)
      echo "RACHNA-FS: policy=''${policy:-unset}"

      if ! grep -q " /workspace " /proc/mounts; then
        echo "RACHNA-FS: VERDICT=NO-WORKSPACE-MOUNT"
        exit 0
      fi

      # Both trees built by the same code, so the comparison cannot drift:
      # 20000 files each, one on the share and one on the guest's own ext4.
      # Then each is stat'd 20 times — repeat-walk is the real workload,
      # since an LSP or a build stats the same tree over and over.
      $py - <<'PROBE'
      import os, time, sys

      COUNT, PASSES = 20000, 20

      def build(root):
          os.makedirs(root, exist_ok=True)
          for i in range(COUNT):
              with open(f"{root}/f{i}", "w") as handle:
                  handle.write("x")
          return len(os.listdir(root))

      def walk(root, n):
          start = time.monotonic()
          for _ in range(PASSES):
              for i in range(n):
                  os.stat(f"{root}/f{i}")
          return time.monotonic() - start

      trees = {"virtiofs": "/workspace/.rachna-fs-probe",
               "ext4": "/var/lib/rachna/fs-probe"}
      counts, times = {}, {}
      for name, root in trees.items():
          try:
              counts[name] = build(root)
              times[name] = walk(root, counts[name])
          except OSError as error:
              print(f"RACHNA-FS: {name} FAILED: {error}")
              sys.exit(0)

      # REFUSED rather than reported if the trees differ: a ratio between
      # two different file counts is not a comparison, and an earlier
      # version printed one (2664 files vs 20000) as though it were.
      if counts["virtiofs"] != counts["ext4"]:
          print("RACHNA-FS: VERDICT=INVALID — "
                f"virtiofs {counts['virtiofs']} files, ext4 {counts['ext4']}")
          sys.exit(0)

      for name in trees:
          ops = counts[name] * PASSES
          print(f"RACHNA-FS-{name.upper()}: {ops} stats in "
                f"{times[name]:.2f}s ({ops / times[name]:.0f}/s)")
      ratio = times["virtiofs"] / times["ext4"]
      print(f"RACHNA-FS: VERDICT=VALID ratio={ratio:.1f}x "
            f"(virtiofs/ext4, lower is better)")

      for root in trees.values():
          for i in range(COUNT):
              try:
                  os.unlink(f"{root}/f{i}")
              except OSError:
                  pass
          try:
              os.rmdir(root)
          except OSError:
              pass
      PROBE
    '';
  };

  systemd.services.rachna-pids-probe = {
    description = "Measure the process limit, then test it (diagnostic)";
    wantedBy = [ "multi-user.target" ];
    after = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      User = "dev";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      # NOT the default: this unit must inherit the manager default so the
      # probe measures what an ordinary service gets. Setting TasksMax here
      # would measure this line instead.
    };
    script = ''
      echo "RACHNA-PIDS: ulimit_u=$(ulimit -u)"
      # The unit's OWN cgroup, named in /proc/self/cgroup — the root
      # /sys/fs/cgroup/pids.max does not exist on cgroup v2, which is why the
      # first version of this line reported "unknown" and looked like a
      # missing limit rather than a wrong path.
      own=$(cut -d: -f3 /proc/self/cgroup 2>/dev/null | head -1)
      echo "RACHNA-PIDS: cgroup=$own"
      echo "RACHNA-PIDS: cgroup_max=$(cat "/sys/fs/cgroup$own/pids.max" 2>/dev/null || echo unreadable)"
      unit_max=$(${pkgs.systemd}/bin/systemctl show -p TasksMax --value \
        rachna-pids-probe.service 2>/dev/null || echo unknown)
      echo "RACHNA-PIDS: unit_tasksmax=$unit_max"

      # The real test: fork past the limit and see where it stops.
      #
      # Run in a CHILD cgroup, which is not an optimisation — the first
      # version forked from this script directly, hit the limit, and could
      # not fork again to report it. The probe killed itself proving the
      # limit worked and printed no verdict, which is indistinguishable from
      # the limit not existing. So the forking happens in a scope whose
      # death cannot take the reporter with it.
      scope=rachna-forkbomb
      ${pkgs.systemd}/bin/systemd-run --user --scope --unit=$scope \
        -p TasksMax=512 -q \
        ${pkgs.bash}/bin/bash -c '
          n=0
          while [ $n -lt 700 ]; do
            sleep 30 & || break
            n=$((n + 1))
          done
          echo "$n" > /tmp/rachna-forked
        ' >/dev/null 2>&1 || true

      forked=$(cat /tmp/rachna-forked 2>/dev/null || echo "scope-died")
      echo "RACHNA-PIDS: fork_attempts=700 forked=$forked"

      # The verdict compares against the DECLARED limit, not against "some
      # limit exists". Measured why: with all three settings removed, the
      # fork scope still died — at the kernel's global ceiling of 2325 — so
      # an earlier version of this line reported LIMITED for a guest with no
      # Rachna limit at all. A probe that passes when the thing it measures
      # is absent is worse than no probe.
      #
      # `19` §2.1 declares 512, so that is the number checked. Three
      # independent views must all agree on it: the rlimit a unit inherits,
      # the cgroup's pids.max, and what systemd reports for the unit.
      declared=512
      limit_ok=yes
      for observed in "$(ulimit -u)" \
                      "$(cat "/sys/fs/cgroup$own/pids.max" 2>/dev/null)" \
                      "$unit_max"; do
        [ "$observed" = "$declared" ] || limit_ok=no
      done
      if [ "$limit_ok" = yes ]; then
        echo "RACHNA-PIDS: VERDICT=ENFORCED-AT-$declared"
      else
        echo "RACHNA-PIDS: VERDICT=NOT-ENFORCED (declared $declared)"
      fi
    '';
  };

  # Report why a service failed, on the console, where the harness can read
  # it. Without this a failure is "[FAILED] Failed to start PostgreSQL
  # Server. See 'systemctl status' for details" — and there is no way to run
  # systemctl, because the root account is locked and the agent does not
  # exist yet (build order step 8 built the transport; nothing drives it).
  #
  # Temporary: it belongs in the agent once that lands. Recorded as such so
  # it is removed rather than inherited.
  systemd.services.rachna-report-failures = {
    description = "Report failed units on the console (diagnostic)";
    wantedBy = [ "multi-user.target" ];
    after = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    script = ''
      echo "RACHNA-DIAG: failed units:"
      ${pkgs.systemd}/bin/systemctl --failed --no-legend --plain || true
      for unit in postgresql.service; do
        echo "RACHNA-DIAG: $unit ----"
        ${pkgs.systemd}/bin/systemctl status "$unit" --no-pager -l -n 30 2>&1 \
          | head -40 || true
      done
      echo "RACHNA-DIAG: state volume:"
      ls -lan /var/lib/rachna 2>&1 | head -5 || true
    '';
  };

  # The toolchain a development environment needs. Everything else arrives on
  # the project's closure disk (`00` §7 Layer C), so this stays small.
  # THE BASE TOOLCHAIN: what belongs in EVERY environment, regardless of
  # what the project is written in.
  #
  # The division is `idea.md` §5.2's: NixOS provides the operating system,
  # **devenv provides the project's languages and services**. So no Node
  # here, and no Postgres — a Python project should not carry a Node
  # runtime it never calls, and `rachna.nix` is the place that says which
  # it needs.
  #
  # An earlier draft of this list was `coreutils bash git`, which is too
  # minimal to work in: a shell with no `fzf`, no `rg`, no editor is a
  # shell you leave immediately. The other extreme — baking Node and
  # Postgres in because one example project used them — makes the base
  # image everyone downloads carry everyone else's dependencies.
  #
  # Every package here was checked to be PREBUILT for aarch64-linux, so
  # this list costs download time rather than build time (`21` §2.1a).
  environment.systemPackages = with pkgs; [
    # devenv itself, so `devenv shell` works inside the guest without the
    # user installing anything. This is the integration `idea.md` §5.2
    # asks for, and it is why the base can stay language-agnostic.
    devenv
    direnv

    # A shell worth being in.
    bash
    coreutils
    findutils
    gnugrep
    gnused
    gawk
    which
    less
    procps

    # The tools people reach for without thinking, and notice the absence
    # of immediately.
    git
    fzf
    ripgrep
    fd
    bat
    jq
    tree
    delta
    zoxide

    # An editor. Not a preference — an environment you cannot edit a file
    # in is one you shell out of to do the actual work.
    neovim

    # Long-running work survives a dropped connection.
    tmux

    # Build and inspect.
    gnumake
    curl
    htop
  ];

  # `devenv` shells out to `nix`, which needs flakes enabled to read a
  # `devenv.nix`. Set alongside §219's `substituters = []` rather than
  # replacing it: nix caught the duplicate definition, and §219's reason
  # is the stronger one — the guest must not fetch its own packages,
  # because that would escape both the reproducibility contract and the
  # network policy. devenv therefore works from the closure already in
  # the image, which is what makes it deterministic rather than a
  # download at first use.
  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  networking.hostName = "rachna";
  networking.useDHCP = false;
  networking.firewall.enable = false; # the host enforces, not the guest
  time.timeZone = "UTC";
}
