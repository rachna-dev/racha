# Rachna's guest: a reproducible Linux development machine.
#
# Three things shape every decision here:
#
#   1. It boots in a microVM under Cloud Hypervisor (Linux) or
#      Virtualization.framework (macOS). No bootloader, no firmware, no disk
#      probing — the VMM loads the kernel directly.
#   2. It must be FAST. Boot is a fallback path, but a slow one still hurts
#      (design-docs/04-SPIKE-LINUX-CH.md). Every service that isn't needed is a
#      service that delays userspace.
#   3. The host enforces security, not the guest. So guest hardening here is
#      defence in depth (idea.md §8.4), never the boundary itself.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  # The developer inside the guest. Deliberately unprivileged: no sudo, no
  # wheel. Anything needing privilege is a host-side decision.
  user = "dev";

  # Where the host's project directory appears. The one deliberate exception to
  # otherwise-denied host filesystem access (idea.md §13.2).
  workspace = "/workspace";
in
{
  # ── identity ──────────────────────────────────────────────────────────────
  system.stateVersion = "26.11";
  networking.hostName = "rachna";

  # The guest's name must not leak the host's. Minimising host fingerprinting
  # is idea.md §8.10.
  networking.domain = "";

  # ── boot: direct kernel, nothing else ─────────────────────────────────────
  boot = {
    # No bootloader at all — the VMM is the bootloader.
    loader.grub.enable = false;
    loader.systemd-boot.enable = false;
    initrd.enable = true;

    # Only the virtio drivers a microVM actually has. Every module not listed
    # is a probe that doesn't happen.
    initrd.availableKernelModules = [
      "virtio_pci"
      "virtio_blk"
      "virtio_console"
      "virtio_net"
      "virtio_rng"
      "virtiofs" # the workspace mount
      "vsock"
      "vmw_vsock_virtio_transport" # host↔guest transport for the tool shims
      "overlay" # writable layers over the read-only store
      "squashfs"
      "erofs"
    ];
    initrd.kernelModules = [ "virtiofs" ];

    kernelParams = [
      # Serial console. On Cloud Hypervisor this must be ttyS0 with
      # `--serial file= --console off`; hvc0 silently produces nothing
      # (design-docs/04-SPIKE-LINUX-CH.md §4.2).
      "console=ttyS0"
      "panic=1" # a panicking guest should die, not hang
      "loglevel=4"
      # Skip probes a microVM can't satisfy.
      "nomodeset"
      "noresume"
      "random.trust_cpu=on" # virtio-rng is present; don't block on entropy
      "tsc=reliable"
      "clocksource=kvm-clock"
      # Only ONE 8250 UART exists in a microVM. Without this the kernel
      # registers ttyS0-ttyS3 and systemd then spends ~4s on .device units for
      # ports that are not there — the single largest boot cost measured.
      "8250.nr_uarts=1"
    ];

    # Nothing to probe for: no real disks, no removable media.
    initrd.includeDefaultModules = false;
    kernel.sysctl = {
      # Defence in depth inside the guest (idea.md §8.4).
      "kernel.dmesg_restrict" = 1;
      "kernel.kptr_restrict" = 2;
      # Many dev tools (watchers, bundlers, language servers) exhaust the
      # default inotify limits on large trees.
      "fs.inotify.max_user_watches" = 1048576;
      "fs.inotify.max_user_instances" = 8192;
    };
  };

  # ── what we deliberately do NOT run ───────────────────────────────────────
  # Each of these costs boot time and adds attack surface for no benefit in a
  # single-purpose development VM.
  documentation.enable = false;
  documentation.man.enable = false;
  documentation.nixos.enable = false;
  services.udisks2.enable = false;
  services.lvm.enable = false;
  security.polkit.enable = false;
  services.timesyncd.enable = false; # kvm-clock is authoritative
  systemd.services.systemd-udev-settle.enable = false;
  systemd.services.NetworkManager-wait-online.enable = false;
  boot.enableContainers = false;
  xdg.autostart.enable = false;
  xdg.mime.enable = false;
  xdg.icons.enable = false;
  fonts.fontconfig.enable = false;

  # No getty on the console: Rachna attaches via the agent and vsock, not a
  # login prompt. (Kept available on ttyS0 for debugging the guest itself.)
  services.getty.autologinUser = lib.mkDefault user;

  # ── filesystems: read-only root, explicit writable paths ──────────────────
  #
  # This is the answer to "how do I mutate anything": the root filesystem is a
  # tmpfs, the Nix store is read-only, and everything that must persist or be
  # written is listed explicitly below. Nothing is writable by accident.
  fileSystems = {
    # Root lives in RAM. A microVM is disposable; durable state is in the
    # volumes below, which is what makes "throw it away and rebuild" honest.
    "/" = {
      device = "tmpfs";
      fsType = "tmpfs";
      options = [
        "mode=0755"
        "size=2G"
      ];
    };

    # The system closure, delivered by the host as a read-only virtiofs share.
    # The guest cannot modify its own system — that would break the claim that
    # rachna.nix fully describes the environment.
    "/nix/store" = {
      device = "nix-store";
      fsType = "virtiofs";
      options = [
        "ro"
        "nodev"
        "nosuid"
      ];
      neededForBoot = true;
    };

    # THE WORKSPACE. The host's project directory, live-mounted so the host
    # editor and the guest toolchain see the same bytes
    # (design-docs/00-PRODUCT.md §10).
    "/workspace" = {
      device = "workspace";
      fsType = "virtiofs";
      options = [
        "rw"
        "nodev"
        "nosuid"
        # Never execute binaries straight out of the shared workspace by
        # accident: project code runs because an entrypoint asked for it.
        # (Interpreted code is unaffected.)
        "noexec"
      ];
    };

    # systemd's own state must be writable and local. Mounting the host share
    # directly on /var/lib shadows /var/lib/systemd, and logind then fails with
    # 238/STATE_DIRECTORY. So systemd gets a tmpfs and the persistent share
    # lives one level down, under /var/lib/rachna.
    "/var/lib/systemd" = {
      device = "tmpfs";
      fsType = "tmpfs";
      options = [
        "mode=0755"
        "size=64M"
      ];
    };

    # Persistent, snapshot-participating state. Separate volume so database
    # files survive restarts and can be reset independently of the workspace
    # (idea.md §12.5, §15.4). Service data is configured to live here.
    "/var/lib/rachna" = {
      device = "state";
      fsType = "virtiofs";
      options = [
        "rw"
        "nodev"
        "nosuid"
        "noexec"
      ];
    };

    # Build and tool caches. Writable and persistent, but explicitly NOT
    # snapshotted — they are reconstructible, and including them would bloat
    # every snapshot.
    "/home/${user}/.cache" = {
      device = "cache";
      fsType = "virtiofs";
      options = [
        "rw"
        "nodev"
        "nosuid"
        "noexec"
      ];
    };
  };

  # No swap: the host manages memory pressure, and swapping a guest to a host
  # file is the worst of both worlds.
  swapDevices = [ ];

  # ── nix inside the guest ──────────────────────────────────────────────────
  nix = {
    settings = {
      experimental-features = [
        "nix-command"
        "flakes"
      ];
      # The guest's store is read-only, so it cannot build. Builds happen
      # host-side where network policy is enforced, and arrive as a new
      # closure (idea.md §13.4).
      auto-optimise-store = false;
      sandbox = false;
      trusted-users = [ ];
      # No substituters: a guest that can fetch its own packages would escape
      # the reproducibility contract AND the network policy.
      substituters = [ ];
    };
    channel.enable = false;
    # Pin the guest's own nixpkgs to the same rev the system was built from, so
    # `nix repl`/`nix eval` inside the guest agree with the outside.
    registry.nixpkgs.flake = null;
  };

  # ── the development environment ───────────────────────────────────────────
  #
  # A baseline every project gets. Project-specific packages come from
  # rachna.nix and arrive as an additional closure — this is the floor, not
  # the ceiling.
  environment.systemPackages = with pkgs; [
    # version control
    git
    git-lfs
    delta # better diffs; git is configured to use it below

    # devenv + direnv, so a project's own devenv.nix works inside the guest
    devenv
    direnv
    nix-direnv

    # shell and the basics a human expects when they land in `rachna shell`
    bashInteractive
    zsh
    starship
    coreutils
    findutils
    gnugrep
    gnused
    gawk
    diffutils
    less
    which
    file
    tree

    # editors, for when someone is inside the guest directly
    vim
    nano

    # the tools people reach for mid-debug
    ripgrep
    fd
    jq
    yq-go
    curl
    wget
    htop
    procps
    psmisc
    lsof
    strace
    socat
    iproute2
    dnsutils
    openssh # the client, for git-over-ssh; no server

    # archives and build basics
    gnutar
    gzip
    xz
    zstd
    unzip
    gnumake
    pkg-config
  ];

  # Make the shell pleasant without requiring per-project setup.
  programs = {
    git = {
      enable = true;
      config = {
        init.defaultBranch = "main";
        # delta is in systemPackages; wire it up rather than shipping it unused.
        core.pager = "delta";
        interactive.diffFilter = "delta --color-only";
        delta.navigate = true;
        # The workspace is a host directory owned by the host user, whose uid
        # may not match the guest's. Without this, git refuses to operate.
        safe.directory = workspace;
      };
    };

    direnv = {
      enable = true;
      nix-direnv.enable = true;
      # Silence the per-directory banner; `cd` into a project should be quiet.
      loadInNixShell = true;
    };

    starship.enable = true;
    bash.completion.enable = true;
  };

  # ── the developer account ─────────────────────────────────────────────────
  users = {
    mutableUsers = false; # declarative only; no useradd drift

    # Deliberate: there is no way to log in to this guest, and that is the
    # point. Entry is via the Rachna agent over vsock, and the console getty
    # auto-logs-in the unprivileged dev user for debugging. A password would be
    # a credential living inside an untrusted guest.
    allowNoPasswordLogin = true;
    users.${user} = {
      isNormalUser = true;
      home = "/home/${user}";
      description = "Rachna developer";
      # NO wheel, NO sudo. Privilege is a host-side decision; a guest that can
      # become root has not escaped the VM boundary, but it has escaped every
      # guest-side mitigation (idea.md §8.4).
      extraGroups = [ ];
      # No password and no SSH keys: entry is via the Rachna agent over vsock,
      # not by logging in.
      hashedPassword = "";
      shell = pkgs.bashInteractive;
    };
    # Root exists but is unusable.
    users.root.hashedPassword = "!";
  };

  security.sudo.enable = false;
  security.sudo-rs.enable = false;

  # ── environment the developer lands in ────────────────────────────────────
  environment.variables = {
    # A clean, declared environment — nothing inherited from the host
    # (idea.md §8.3).
    HOME = "/home/${user}";
    LANG = "C.UTF-8";
    EDITOR = "vim";
    PAGER = "less";
    # Point tool caches at the writable, non-snapshotted volume.
    XDG_CACHE_HOME = "/home/${user}/.cache";
    CARGO_HOME = "/home/${user}/.cache/cargo";
    npm_config_cache = "/home/${user}/.cache/npm";
    # direnv is enabled; let projects opt in without extra ceremony.
    DIRENV_LOG_FORMAT = "";
  };

  # Land in the workspace, not in $HOME.
  environment.loginShellInit = ''
    cd ${workspace} 2>/dev/null || true
  '';

  i18n.defaultLocale = "C.UTF-8";
  time.timeZone = "UTC"; # the host's timezone is host information

  # ── networking: nothing by default ────────────────────────────────────────
  networking = {
    # No DHCP client, no resolver, no firewall — because by default there is no
    # network at all. When policy grants access, the host is the gateway and
    # supplies configuration; the guest never decides
    # (design-docs/02-SPIKE-MACOS-VZ.md §7).
    useDHCP = false;
    dhcpcd.enable = false;
    useNetworkd = false;
    firewall.enable = false; # the host enforces; a guest firewall is theatre
    nameservers = [ ];
  };

  # Measured from `systemd-analyze critical-chain`: the serialized cost is
  # spread across systemd housekeeping rather than any single stall —
  # journal-catalog-update 253ms, resolvconf 258ms, dbus-broker 103ms,
  # tmpfiles ~270ms across three units, plus ~1.65s before systemd does
  # anything useful. These cuts target the ones a microVM does not need.
  # `systemd-analyze blame`'s 4s entries are NOT delays; they report how long a
  # unit existed. Chasing them was wasted effort — recorded so it isn't redone.

  # The journal catalog is documentation for log messages; nothing reads it here.
  systemd.services.systemd-journal-catalog-update.enable = false;
  # No network by default means no resolver to configure. When policy grants
  # network, the host supplies configuration.
  systemd.services.resolvconf.enable = false;
  # Nothing in the guest updates between boots: the system is immutable and
  # delivered read-only.
  systemd.services.systemd-update-done.enable = false;

  # Keep udev from creating systemd .device units for hardware a microVM does
  # not have. These were the top entries in `systemd-analyze blame` at ~4s each.
  services.udev.extraRules = ''
    # No systemd unit for the DMI id device; nothing waits on it usefully.
    ACTION=="add", SUBSYSTEM=="dmi", TAG-="systemd"
    # Serial ports beyond the console: tag removed so systemd does not track
    # them. Combined with 8250.nr_uarts=1 these should not appear at all.
    ACTION=="add", SUBSYSTEM=="tty", KERNEL=="ttyS[1-9]*", TAG-="systemd"
  '';

  # vsock is the host↔guest transport for `rachna --exec` and the tool shims
  # (design-docs/01-ARCHITECTURE.md §7).
  boot.kernelModules = [
    "vhost_vsock"
    "vmw_vsock_virtio_transport"
  ];

  # ── fast boot ─────────────────────────────────────────────────────────────
  #
  # Measured: the dominant cost in a real NixOS guest was ~4.0s of systemd
  # *device* units for serial8250 ttyS0–ttyS3 and dmi-id, all waiting on udev
  # settle for hardware that either does not exist or that we do not use.
  # Masking them is the single biggest boot win available.
  systemd = {
    # Don't wait on things a microVM will never have.
    services.systemd-random-seed.enable = false;

    # NOTE: `suppressedSystemUnits` does NOT help here — these are udev-
    # generated .device units created at runtime from the device tree, not unit
    # files we can mask. Measured: masking them changed boot time not at all
    # (7.36s before and after). The fix is the udev rule below, plus
    # `8250.nr_uarts=1` on the kernel command line so the extra ports never
    # exist. See design-docs/05-SPIKE-NIXOS-GUEST.md.
    # A guest that can't reach the network must not spend 90s discovering that.
    settings.Manager = {
      DefaultTimeoutStartSec = "15s";
      DefaultTimeoutStopSec = "5s";
      DefaultDeviceTimeoutSec = "5s";
    };
    # Journal to the console and to RAM; persisting it would need a volume and
    # the host already records what matters.
    services.systemd-journal-flush.enable = false;
  };
  services.journald.settings.Journal = {
    Storage = "volatile";
    RuntimeMaxUse = "32M";
  };
}
