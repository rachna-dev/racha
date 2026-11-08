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
