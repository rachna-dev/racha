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

  # The data directory must exist on the state volume before Postgres starts,
  # and the state volume is mounted by then (`nofail` + the fileSystems
  # dependency), so this is ordering rather than creation-on-demand.
  systemd.services.postgresql = {
    after = [ "var-lib-rachna.mount" ];
    requires = [ "var-lib-rachna.mount" ];
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
  environment.systemPackages = with pkgs; [
    coreutils
    bash
    git
  ];

  networking.hostName = "rachna";
  networking.useDHCP = false;
  networking.firewall.enable = false; # the host enforces, not the guest
  time.timeZone = "UTC";
}
