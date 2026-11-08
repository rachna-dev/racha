-- Rachna's audit store.
--
-- `08-POLICY-AND-STORE.md` §3 is the specification; this is its DDL, which
-- `21-SPEC-AUDIT.md` §3.2 flagged as the gap. Every note below records a
-- decision the prose settled and the schema has to honour.
--
-- IT IS A CACHE, NOT TRUTH (§3.1). Deleting this file loses audit history and
-- nothing else: permissions are in rachna.nix, VM state in disks and
-- snapshots, the guest rebuildable from a pinned closure. So nothing
-- load-bearing may live here, and a corrupt database is recoverable by
-- deletion rather than repair.
--
-- THE GUEST MUST NEVER WRITE HERE (§3.4). Not expressible in SQL — it is a
-- filesystem property, enforced by `src/exclusion.rs` and by the store living
-- outside the workspace mount (§4). Recorded here so a reader of the schema
-- knows the threat: a guest that could write this forges usage so an
-- exfiltration channel survives `revoke --unused`, or forges silence so real
-- grants look revocable.

-- One row per `rachna` invocation.
CREATE TABLE IF NOT EXISTS config_revisions (
    id                TEXT PRIMARY KEY,   -- content hash of rachna.nix
    ts                INTEGER NOT NULL,
    approved          INTEGER NOT NULL,   -- the first-run ack, `00` §3.10c
    CHECK (approved IN (0, 1))
) STRICT;

CREATE TABLE IF NOT EXISTS runs (
    id                TEXT PRIMARY KEY,   -- ULID: sortable by time (`17`)
    argv              TEXT NOT NULL,      -- JSON array, as invoked
    cwd               TEXT NOT NULL,
    started           INTEGER NOT NULL,   -- epoch millis, UTC
    ended             INTEGER,            -- NULL while running
    exit_code         INTEGER,            -- NULL while running
    config_revision   TEXT NOT NULL REFERENCES config_revisions(id)
) STRICT;

-- Every grant ever seen, keyed by content hash so the same rule in two
-- revisions is one row.
--
-- §2: the fingerprint is written explicitly and never derived from Debug or a
-- serializer, because changing its format orphans every usage record and must
-- therefore be a deliberate migration.
CREATE TABLE IF NOT EXISTS grants (
    id                TEXT PRIMARY KEY,   -- content hash of the fingerprint
    fingerprint       TEXT NOT NULL,      -- human-readable, stable
    category          TEXT NOT NULL,      -- Category::as_str
    first_seen        INTEGER NOT NULL,
    first_revision    TEXT NOT NULL REFERENCES config_revisions(id),
    last_revision     TEXT NOT NULL REFERENCES config_revisions(id)
) STRICT;

-- One row per decision. NOT rolled up (§3.2): `rachna explain run/a3f2` must
-- replay a run exactly, which is what makes a policy question answerable
-- after the fact rather than reconstructable by guesswork.
--
-- The cost is real and accepted: a chatty `npm install` makes thousands of
-- rows. Batched writes, WAL and a retention window make it affordable —
-- never a write per syscall.
CREATE TABLE IF NOT EXISTS decisions (
    id                INTEGER PRIMARY KEY,
    run_id            TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts                INTEGER NOT NULL,
    category          TEXT NOT NULL,
    target            TEXT NOT NULL,      -- what was asked for
    verdict           TEXT NOT NULL,      -- 'allow' | 'deny'
    grant_id          TEXT REFERENCES grants(id),  -- NULL on a denial
    scope             TEXT,               -- value touched; NULL on a denial
    deny_reason       TEXT,               -- NULL on an allow
    process_chain     TEXT,               -- JSON array, when known

    -- An allow records WHAT it touched; a denial records WHY. Both halves are
    -- load-bearing: a missing scope on an allow makes narrowing impossible
    -- (§1.3 says to treat one as a bug), and a denial with no reason makes
    -- `explain` useless. Enforced in the schema so a writer bug cannot
    -- silently degrade the audit trail — here the data IS the product.
    CHECK (verdict IN ('allow', 'deny')),
    CHECK ((verdict = 'allow') = (scope IS NOT NULL)),
    CHECK ((verdict = 'deny') = (deny_reason IS NOT NULL))
) STRICT;

-- A derived rollup (§3.3), kept because `audit` and `status` must be instant:
-- recomputing "last used" from millions of decision rows on every `status`
-- call would make the unused-grant nag unaffordable.
--
-- Rebuildable from `decisions` within the retention window, which keeps
-- §3.1 true.
CREATE TABLE IF NOT EXISTS usage (
    grant_id          TEXT PRIMARY KEY REFERENCES grants(id) ON DELETE CASCADE,
    count             INTEGER NOT NULL,
    runs              INTEGER NOT NULL,   -- DISTINCT runs: the evidence
                                          -- threshold needs both days and
                                          -- runs (`synthesize`, §1.4)
    first_used        INTEGER NOT NULL,
    last_used         INTEGER NOT NULL,
    CHECK (count >= 0),
    CHECK (runs >= 0),
    CHECK (last_used >= first_used)
) STRICT;

-- What `synthesize` reads (§3.3). Separate from `usage` because "used 412
-- times" and "covered these 2 hosts" are different queries with different
-- cardinality; folding them would make narrowing a table scan.
CREATE TABLE IF NOT EXISTS observed_scopes (
    grant_id          TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    scope             TEXT NOT NULL,
    count             INTEGER NOT NULL,
    first_seen        INTEGER NOT NULL,
    last_seen         INTEGER NOT NULL,
    PRIMARY KEY (grant_id, scope),
    CHECK (count >= 0)
) STRICT;

-- Indices for the queries that actually run, not speculative ones.

-- `explain <run-id>` replays one run in order.
CREATE INDEX IF NOT EXISTS decisions_by_run ON decisions(run_id, ts);

-- Retention prunes by timestamp, which would otherwise full-scan the largest
-- table.
CREATE INDEX IF NOT EXISTS decisions_by_ts ON decisions(ts);

-- Per-grant drilldown: "which decisions came from this rule".
CREATE INDEX IF NOT EXISTS decisions_by_grant
    ON decisions(grant_id) WHERE grant_id IS NOT NULL;

-- The reverse lookup "who touched this host". The primary key already covers
-- grant-ordered access.
CREATE INDEX IF NOT EXISTS observed_scopes_by_scope ON observed_scopes(scope);
