# Spike index

The code cites numbered design documents — `14` §3, `15` §3.2, `16` §5.2 and
so on. **Those documents are not in this repository.** They were internal
working notes (26 files, plus `AGENTS.md` and `idea.md`) and were removed
from the history before the repo was made public.

That removal destroyed them rather than archiving them: `git-filter-repo`
rewrites every ref, including a backup branch made beforehand, and the
original objects were garbage-collected afterwards. The loss is recorded
here rather than left as a puzzle for whoever meets a `16 §5.2` citation.

**What survives is the finding, not the document.** Each citation sits
beside a comment that states the measurement it came from, and those
comments were written to stand alone. This index says which area each
number covers, so a reference can at least be placed.

| | |
|---|---|
| `00` | the product: what Rachna is, and the permission gate's rules |
| `01` | architecture: one crate, and the enforcement rings |
| `02` | macOS / Virtualization.framework: boot, snapshot, restore, the entitlement |
| `05` | guest boot time |
| `08` | the policy store, the audit trail, and `~/.rachna`'s layout |
| `11` `13` | config evaluation, and the restricted-eval sandbox |
| `12` | isolation on macOS: cgroups absent, case-insensitive APFS |
| `14` | workspace exclusions: hardlinks, mount points, name leakage |
| `15` | resource limits: which are enforceable, which are advisory |
| `16` | snapshots and the state disk: block device vs share, absolute paths |
| `19` | the `rachna.nix` surface: what a project may and may not declare |
| `21` | release engineering: exit codes as an API, integrity of what we ship |
| `23` | the eval sandbox: four concrete attacks a config can attempt |
| `24` | snapshot cost, measured |
| `26` | workspace filesystem performance: 1.5× of local on Linux with one flag, 10× on macOS with no flag available |

Where a citation matters to understanding the code, the comment next to it
carries the substance. Where it does not, treat it as provenance: somebody
measured this rather than guessed it.
