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

## What state it is in

Honest status, because the distinction matters if you try it:

**Working, verified on macOS (Apple Silicon):**

- `init` · `start` · `status` · `suspend` · `resume` · `stop` · `snapshots`
- The permission gate, on every start and every resume
- A real Linux VM via Virtualization.framework — kernel 6.18.54, Postgres 16, Node 22
- Your project directory visible inside the guest at `/workspace`
- Host→guest path mapping with `~` resolving on both sides
- Named snapshots: suspend one, list them, resume by name
- 740 tests, plus 5 integration tests that boot an actual VM

**Not working yet:**

- **Service data does not survive `stop` → `start`.** The guest reformats its
  state volume on the second boot, so Postgres re-runs `initdb` and the data is
  gone. Under active debugging; the host keeps the volume correctly, the guest
  decides to reformat it.
- The Linux backend (Cloud Hypervisor) is written and not yet exercised end to end.
- The guest is a **stand-in**: `guest/guest.nix` is the real NixOS system this is
  designed around, and building it needs a Linux builder. `ci/build-guest.sh`
  assembles an equivalent by downloading prebuilt signed packages, which is what a
  Mac can do without one.

## Trying it

Needs [Nix](https://nixos.org/download) with flakes, and macOS on Apple Silicon.

```sh
git clone git@github.com:rachna-dev/racha.git && cd racha
devenv shell -- cargo build
./ci/sign-macos.sh target/debug/rachna     # the VZ entitlement
bash ci/build-guest.sh                     # the guest image, ~10 min, 615 MB
```

Then in any project directory:

```sh
rachna init && rachna start
```

The build is a one-time cost — the guest image is shared across every project
(`~/.rachna/guests/`), so ten projects cost one image plus whatever each writes.

## What `rachna.nix` accepts today

```nix
{
  tier = "allowlist";                              # network: allowlist | isolated
  profile = "development";                         # fs, devices, credentials

  network.allow = [ "registry.npmjs.org:443" ];    # empty list = no network

  resources.disk = "500MB";                        # default 20GB, sparse

  filesystem.mounts = [
    { source = "~/.gitconfig";                     # ~ = your home
      target = "~/.gitconfig";                     # ~ = the guest's home
      access = "read-only"; }                      # read-only unless stated
  ];
}
```

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
