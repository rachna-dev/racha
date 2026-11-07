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
    tier    = "allowlist";                 # network: only what you allow
    profile = "development";               # filesystem, devices, credentials

    network.allow = [ "registry.npmjs.org:443" ];
    credentials = "placeholder";           # the guest never holds a real token
  };

  tools.expose = [
    # even your language server is a scoped permission
    { name = "rust-analyzer"; kind = "lsp"; workspace = "read-write"; network = false; }
  ];
}
```

A command that needs something undeclared fails and tells you the narrowest grant that would fix it. Weeks later, `rachna audit` tells you which grants were never used and offers to remove them. **There are no prompts** — the file is the only place a permission can exist, so `git diff` is a complete audit of your environment's authority.

## What is actually new here

Isolation is **not** the differentiator. Several projects ship per-project microVMs with host-enforced deny-by-default networking — [`devvm`](https://github.com/devvmhq/devvm) is the nearest neighbour and independently arrived at much of this design — and Docker now ships a first-party microVM sandbox. Treat that as parity, not a pitch. ([`07-LANDSCAPE.md`](design-docs/07-LANDSCAPE.md) is the full survey.)

What is unclaimed, sharpest first:

1. **Tool exposure as a scoped permission.** Your LSP, formatter and debugger are policy objects — `rust-analyzer` gets the workspace and no network. **Not found anywhere in the field.** The proxy mechanics are a solved, crowded problem; tool-as-permission exists only for LLM/MCP allowlisting; the two have never been joined. Dev Containers structurally cannot do it — the extension host in a container holds the container's full ambient authority by construction.
2. **Suspend / resume / snapshot.** Close the laptop, come back to a warm Postgres and a running server. Nearly unclaimed in a cohort that treats VMs as disposable. Measured: 150 ms restore.
3. **The permission loop closing.** Diagnose what was blocked, then audit what went *unused* and narrow it. Unclaimed in shipped dev tooling — but a competitor has it planned, and the pattern is twenty years old elsewhere (`aa-logprof`, `audit2rbac`). **A race, not a moat.**
4. **Project-local, version-controlled policy as sole authority.** The one clean separation from `devvm`, which keeps policy host-side on purpose. Their reasoning is sound and Rachna answers it differently — by hiding the file from the guest rather than moving it off the repo (see below).

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
| [`07-LANDSCAPE.md`](design-docs/07-LANDSCAPE.md) | What already exists, what is unclaimed, and ideas adopted from the field. |
| [`08-POLICY-AND-STORE.md`](design-docs/08-POLICY-AND-STORE.md) | The policy engine's two query shapes, decision records, the SQLite store, and where state lives. |
| [`09-ISOLATION.md`](design-docs/09-ISOLATION.md) | Memory, CPU and filesystem isolation: the design and the threat model. |
| [`10-SPIKE-ISOLATION-MEASURED.md`](design-docs/10-SPIKE-ISOLATION-MEASURED.md) | Measured against a real guest: filesystem escape, memory, CPU, snapshots, process limits. |
| [`11-SPIKE-ISOLATION-ROUND2.md`](design-docs/11-SPIKE-ISOLATION-ROUND2.md) | Landlock, SMT scheduling, I/O quotas, hardlinks, virtiofsd's own confinement. |
| [`12-SPIKE-ISOLATION-MACOS.md`](design-docs/12-SPIKE-ISOLATION-MACOS.md) | The same on macOS, where three mechanisms differ — and one earlier claim was wrong. |
| [`13-SPIKE-ISOLATION-ROUND3.md`](design-docs/13-SPIKE-ISOLATION-ROUND3.md) | The last open questions closed: I/O throttling, TOCTOU, virtiofsd's confinement, macOS escapes. |
| [`idea.md`](idea.md) | The original brain-dump. Superseded where it disagrees with the above. |
| [`AGENTS.md`](AGENTS.md) | Rules for anyone — human or agent — changing this repo: the gate, code quality, testing bar. |

Each spike doc has an explicit **"what was NOT tested"** section. The largest remaining gap is that no spike ran a real service: nothing yet says anything about application-consistent snapshots with Postgres mid-transaction.

**Isolation, measured on both platforms.** What holds: filesystem escape (every symlink and traversal attempt failed), memory ceilings (the guest kernel OOM-kills at its declared limit), host CPU quotas (the kernel throttled 119 times), and VMM self-confinement via Landlock (a write outside granted paths is denied). `core_scheduling=vm`, the SMT side-channel mitigation, costs nothing measurable and should be on by default.

What does not hold: the declared guest **process limit is silently ignored** (512 declared, 7754 actual — and a host `TasksMax` cannot cover for it, because guest processes are not host tasks). **Linux snapshots are plaintext guest memory**: three planted secrets were all recovered, and the image gzips to 0.8 %. **macOS snapshots are encrypted** — the same test gives 100 % and zero hits — so this is a platform gap, not a universal one. And the policy-file exclusion **must be inode-based, not name-based** — both bypasses are now demonstrated from inside a guest, on both platforms: a hardlink into the share reaches a host file outside it, and on macOS `RACHNA.NIX` returns the content of `rachna.nix`.

**On keeping policy in the repo.** `devvm` deliberately does not, reasoning that *"Rules never come from the project folder, because the VM can write it."* The objection is correct: a guest that can write its own policy file can grant itself permissions — concretely, via an `npm` postinstall script appending an `allow` rule. Rachna's answer is to **exclude `rachna.nix` from the workspace mount**, so the guest cannot see or write it and the host evaluates it before any guest exists. The policy stays committed, diffable and shared with the team; it simply is not visible from inside the thing it governs. ([`00-PRODUCT.md` §3.11](design-docs/00-PRODUCT.md))

## Development

```bash
devenv shell      # Rust toolchain, plus cloud-hypervisor + virtiofsd on Linux
```

**[`AGENTS.md`](AGENTS.md) is the contract for changing this repo** — the gate that must pass before and after every task, one-crate-until-forced, extend-the-owner, and a testing bar measured by surviving mutants rather than a coverage percentage.

Implementation starts at `01-ARCHITECTURE.md` §7 step 1 — the TDD harness, before any product code. The milestone that matters is step 9: the complete permission loop demoable with **no hypervisor at all**.

## Name

**रचना** (*rachanā*) — composition, construction, arrangement.
