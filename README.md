# Rachna

> **`rachna` is the only development tool on your machine. Everything else lives in an isolated Linux computer you can pause, resume, snapshot, or throw away.**

A declarative, security-focused development environment manager. Each project gets a reproducible Linux microVM with **deny-by-default** access to your host — no network, no filesystem, no credentials, no sockets, unless `rachna.nix` says so.

**Status: design + completed feasibility spike. No implementation yet.**

---

## The idea in one example

```nix
# rachna.nix — the ONLY authority for what this project may do
{ pkgs, ... }:
{
  name = "some-api";

  environment.packages = with pkgs; [ nodejs_22 postgresql_16 ];
  services.postgres = { enable = true; port = 5432; };

  isolation = {
    profile = "development";
    network.allow = [ "registry.npmjs.org:443" ];
    credentials.default = "deny";          # your SSH keys are not in there
  };

  tools.expose = [
    # even your language server is a scoped permission
    { name = "rust-analyzer"; kind = "lsp"; workspace = "read-write"; network = false; }
  ];
}
```

A command that needs something undeclared fails and tells you the narrowest grant that would fix it. Weeks later, `rachna audit` tells you which grants were never used and offers to remove them. **There are no prompts** — the file is the only place a permission can exist, so `git diff` is a complete audit of your environment's authority.

## Why not a container

Dev Containers solved "reproducible environment, editor works," and Rachna does not try to beat them at that. It targets four things container-based tooling structurally cannot do:

1. **Real isolation** — a VM boundary with host-enforced policy, not a shared kernel with `~/.ssh` mounted in for convenience.
2. **The permission loop** — deny-by-default made survivable: diagnose what was blocked, then audit what went unused and narrow it.
3. **Suspend / resume / snapshot** — close the laptop, come back to a warm Postgres and a still-running server.
4. **Nix-grade reproducibility** — actually pinned, with a binary cache instead of a Dockerfile that rots.

## What the spike established

Measured on an M2 Pro (macOS 15.3.2) and a NixOS x86_64 host. Full numbers in `design-docs/02`–`05`.

| | Result |
|---|---|
| Pause / resume | **7 ms / 4 ms** (Cloud Hypervisor), **0.6 ms / 0.2 ms** (macOS) |
| Restore + resume | **150 ms** @ 2 GiB (Linux), ~190 ms/GiB (macOS) |
| Snapshots reusable | **yes, verified** — restored the same snapshot repeatedly, state preserved |
| Network policy enforceable | **yes** — direct-IP TCP SYN, UDP, IPv6 and ARP all intercepted host-side |
| Live workspace mount | **yes** — a `git commit` made inside the guest was visible on the host |
| Cold boot, real dev guest | **6.97 s** (so resume, not boot, is the steady state) |

Decisions that now rest on evidence rather than reputation:

- **Cloud Hypervisor, not Firecracker.** Firecracker has no virtiofs at all, cannot accept a network FD, and documents re-restoring a snapshot as insecure. Each alone is disqualifying for this use case.
- **Always `--memory shared=on`.** The documented virtiofs/fast-restore conflict does not exist — `shared=on` *is* the fast path, 38× faster.
- **macOS needs only ad-hoc codesigning**; Linux needs `CAP_NET_ADMIN` for the tap.

## Documentation

| | |
|---|---|
| [`06-VISION-AND-DX.md`](design-docs/06-VISION-AND-DX.md) | **Start here.** The pitch, the workflow, installation. |
| [`00-PRODUCT.md`](design-docs/00-PRODUCT.md) | Product model: the permission loop, feature rings, the CLI. |
| [`01-ARCHITECTURE.md`](design-docs/01-ARCHITECTURE.md) | Seams, testing posture, build order. |
| [`02-SPIKE-MACOS-VZ.md`](design-docs/02-SPIKE-MACOS-VZ.md) | Virtualization.framework lifecycle, measured. |
| [`03-ENFORCEABILITY.md`](design-docs/03-ENFORCEABILITY.md) | Which policy categories each backend can actually enforce. |
| [`04-SPIKE-LINUX-CH.md`](design-docs/04-SPIKE-LINUX-CH.md) | Cloud Hypervisor lifecycle, measured. |
| [`05-SPIKE-NIXOS-GUEST.md`](design-docs/05-SPIKE-NIXOS-GUEST.md) | The pinned guest, and three bugs worth not rediscovering. |
| [`idea.md`](idea.md) | The original brain-dump. Superseded where it disagrees with the above. |

Each spike doc has an explicit **"what was NOT tested"** section. The largest remaining gap is that no spike ran a real service: nothing yet says anything about application-consistent snapshots with Postgres mid-transaction.

## Development

```bash
devenv shell      # Rust toolchain, plus cloud-hypervisor + virtiofsd on Linux
```

Implementation starts at `01-ARCHITECTURE.md` §7 step 1 — the TDD harness, before any product code. The milestone that matters is step 9: the complete permission loop demoable with **no hypervisor at all**.

## Name

**रचना** (*rachanā*) — composition, construction, arrangement.
