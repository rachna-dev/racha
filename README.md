# Rachna

> **One tool on your machine. Everything else runs in an isolated Linux VM you can
> pause, snapshot, or throw away.**

Each project gets a Linux virtual machine with **deny-by-default** access to your
host — no network, no filesystem, no credentials — unless `rachna.nix` says so.
The config file is the only authority, it lives in your repo, and its permissions
are shown to you every single time the environment starts.

```
$ cd ~/Projects/todo-api
$ rachna init
wrote rachna.nix
edit it, then: rachna start

$ rachna start

  rachna.nix grants, first run:

  network   registry.npmjs.org:443
  fs        none
  tool      none
  port      none
  secret    none (development profile forbids it)

  this config has not run here before.

  [a] accept all and start
  [q] quit, and change rachna.nix first

started
  console: ~/.rachna/projects/todo-api-ae1b5d9d/run/console.log
  stop it with: rachna stop
```

You press `a`. There is no flag that skips this at a terminal — `--accept` exists
for CI and does nothing when stdin is a TTY, deliberately: a flag that worked
interactively would let you accept a cloned repo's permissions in the same breath
as asking to start it.

## Platform support

| | |
|---|---|
| macOS, Apple Silicon | Virtualization.framework — working |
| Linux | Cloud Hypervisor — in progress |

Early days: the CLI and the macOS backend work, the guest is assembled from
prebuilt packages rather than the NixOS system it is designed around, and
`guest/guest.nix` is where that is headed once a Linux builder is in the loop.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/rachna-dev/racha/main/ci/install.sh | sh
```

Fetches the binary and the Linux guest image for your machine, verifies both
against published checksums, and puts `rachna` in `~/.local/bin`. No Nix
needed.

Downloading the binary in a **browser** instead will get you a macOS malware
dialog — `rachna` links Virtualization.framework, which Gatekeeper
scrutinises when no Developer ID vouches for it. `curl` does not set the
quarantine attribute, so the installer sidesteps that; if you do download it
by hand, run `xattr -d com.apple.quarantine rachna` first.

## Building from source

Needs [Nix](https://nixos.org/download) with flakes, and macOS on Apple Silicon.

```sh
git clone git@github.com:rachna-dev/racha.git && cd racha
devenv shell -- build          # compiles and signs it for Virtualization.framework
bash ci/build-guest.sh         # the guest image, ~10 min, 615 MB
```

Use `devenv shell -- build` rather than `cargo build` on macOS: the binary
needs the `com.apple.security.virtualization` entitlement to create a VM at
all, and every relink discards it. The signature is ad-hoc — no certificate
or Apple account involved.

Then in any project directory:

```sh
rachna init && rachna start
```

The build is a one-time cost — the guest image is shared across every project
(`~/.rachna/guests/`), so ten projects cost one image plus whatever each writes.

## What `rachna.nix` accepts today

```nix
{
  # ── what is in the environment ──────────────────────────────────────────
  environment.packages  = [ "nodejs_22" "postgresql_16" ];   # any nixpkgs name
  environment.variables = { NODE_ENV = "development"; };

  services.postgres = { enable = true; port = 5432; };
  entrypoints       = { dev = "npm run dev"; };              # rachna run dev

  # ── what it is allowed to do ────────────────────────────────────────────
  tier = "allowlist";                              # open | internet | allowlist | none
  profile = "development";                         # sealed | development | online

  network.allow = [ "registry.npmjs.org:443" ];    # empty list = no network

  ports = [ { guest = 3000; host = 3000; } ];

  tools = [                                        # a tool is its own principal
    { kind = "lsp"; name = "rust-analyzer";
      network = false; }                           # defaults to false
  ];

  resources = { cpus = 4; memory = "2GB";
                disk = "500MB"; processes = 512; }; # disk default 20GB, sparse

  filesystem.mounts = [
    { source = "~/.gitconfig";                     # ~ = your home
      target = "~/.gitconfig";                     # ~ = the guest's home
      access = "read-only"; }                      # read-only unless stated
  ];
}
```

Every field is optional. An empty `rachna.nix` is valid and gives you the base
guest, which ships `devenv`, `direnv`, `git`, `fzf`, `ripgrep`, `fd`, `jq`,
`neovim` and `tmux` — a shell worth being in, with no language runtime.

`environment.packages` takes **any nixpkgs attribute name**, and Rachna does not
check the list: Nix does, against the pinned revision, and it gives a better
answer than a copy of the package set would. A project that declares packages
gets its own guest image, keyed by the package set — so two projects declaring
the same thing share one image and the second one's first start is a cache hit.

Deleting a line makes the environment **stricter**, never looser. An empty
allowlist denies all network rather than permitting it.

A project cannot pin its own nixpkgs revision — that belongs to the `rachna`
version, so two people with the same `rachna.nix` get the same machine.

## Commands

| | |
|---|---|
| `rachna init` | write a starter `rachna.nix` |
| `rachna start` | show the grants, wait for `a`, boot the VM |
| `rachna status` | running, suspended, or stopped — and what is parked |
| `rachna suspend [name]` | write the guest's memory to disk and stop |
| `rachna resume [name]` | bring a suspended environment back |
| `rachna snapshots` | what is parked, and which can be resumed |
| `rachna stop` | tear it down |

Suspend and resume are measured at **1.3s** and **0.8s** for a ~128 MiB snapshot
of a guest running Postgres and Node. A suspended project costs no vCPU.

## Where things live

```
~/.rachna/
├── guests/26.11-3181085-aarch64/     the guest image — SHARED by all projects
└── projects/todo-api-ae1b5d9d/
    ├── rachna.db                     approvals and the audit trail
    ├── disks/root.img, state.img      this project's own disks
    ├── snapshots/<name>.vzvmsave      named snapshots
    └── run/                           console, pids — dies with the VM
```

Deleting `~/.rachna/` removes every trace. Nothing is installed elsewhere.

## Why a VM and not a container

A container shares your kernel. The isolation claim here is that a compromised
dependency in one project cannot read your SSH keys, reach your other projects,
or phone home — and a shared kernel makes that a much harder claim to keep.
Hardware virtualization is the boundary; the policy file decides what crosses it.

On macOS this is Apple's Virtualization.framework, which is also why
`ci/sign-macos.sh` exists: the binary needs an entitlement to create VMs at all.

## License

Not yet chosen.
