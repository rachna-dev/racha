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

  # The root is the closure squashfs, read-only, attached as the FIRST disk.
  #
  # `00` §7 Layer C: the project closure is a separate read-only disk on a
  # generic base, so changing a package swaps one disk instead of rebuilding
  # an OS image — and store paths dedupe naturally.
  #
  # Measured: without a root to switch into, the initrd reaches 15 targets,
  # fails "Find NixOS closure" and drops to emergency mode.
  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "squashfs";
    options = [ "ro" ];
  };

  # Everything writable is a tmpfs overlay or the state disk. A read-only
  # root is not a limitation here: it is what makes the guest reproducible
  # and what lets the closure be shared across projects (`08` §4.1.1).
  fileSystems."/tmp" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=1777" ];
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
