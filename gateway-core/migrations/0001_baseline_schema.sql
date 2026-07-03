-- gateway-core schema baseline.
--
-- The engine owns two Postgres schemas and never writes to the host database's
-- `public` schema. `cw_core` is the engine's private namespace; `cw_api` is the
-- stable extension contract a vendor may FK-reference. Both schemas are created
-- by sqlx's migrator ahead of this file (see sqlx.toml create-schemas), so this
-- migration only creates objects inside them, and a migration-enforcement test
-- asserts a role with REVOKE CREATE ON SCHEMA public still applies it cleanly.
--
-- GRANT MODEL (engineering rationale, not policy boilerplate)
--   - The engine migrator role owns `cw_core` and `cw_api`: it created both and
--     holds full DDL on them. It deliberately holds NO privilege on any vendor
--     schema, so a stray engine migration physically cannot touch vendor data.
--   - A vendor role owns its own schema and is granted only USAGE + SELECT +
--     REFERENCES on `cw_api`. REFERENCES is the exact privilege a foreign key
--     needs and nothing more: the vendor can point a FK at `cw_api.account` but
--     can neither write the anchor rows nor read `cw_core`.
--   - Tenant deletion is a soft-delete (`deleted_at`); a hard DELETE of an
--     anchor row is gated by its dependents. Durable and historical dependents
--     (balance, the PoE / ledger / quote records and their indexes) reference
--     the anchor ON DELETE RESTRICT, so Postgres refuses to erase an anchor that
--     still has real history rather than silently dropping a graph of rows. The
--     few ephemeral per-account config rows that are cleanup rather than history
--     (a wallet grant's account scope, the margin / token override, an
--     account-scoped webhook endpoint) are ON DELETE CASCADE so they fall away
--     with the account.
--
-- State machines throughout are expressed as CHECK-constrained `status`/`state`
-- columns; the *transitions* are enforced in code (the claim / release / apply
-- paths), never by triggers, so a transition is always a fenced UPDATE the
-- caller can reason about rather than a hidden side effect. The CHECK pins the
-- legal *set* of states; the unique keys pin the by-construction invariants.


-- ===========================================================================
-- SECTION 1 — The job runtime: queue policy, the live work table, terminal
-- history, the cron double-fire guard, and the durable per-subject event log.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- queue_policy: per-queue runtime configuration.
--
-- The runtime seeds and reconciles these rows from code-declared config at
-- startup. The row is the live source of truth the claim/retry/sweep paths
-- read; code drift (a queue whose code config differs from its row) is
-- reconciled by UPDATE-ing the row and logging a warning.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.queue_policy (
    queue        text PRIMARY KEY,
    -- 'standard'      : ordinary worker-pool concurrency.
    -- 'singleton_loop': at most one in-flight job; the handler typically takes a
    --                   session advisory lock to serialize work across replicas.
    policy       text NOT NULL CHECK (policy IN ('standard', 'singleton_loop')),
    max_attempts integer NOT NULL CHECK (max_attempts >= 1),
    -- {kind: 'fixed'|'exponential', base_secs: <int>}
    backoff      jsonb NOT NULL,
    -- Reclaim lease: a running job whose heartbeat is older than this is swept
    -- back to 'available'.
    lease_secs   integer NOT NULL CHECK (lease_secs >= 1),
    -- Advisory worker-pool fan-out for this queue. The runtime uses it to size
    -- how many rows it claims per tick; it is not a hard DB-enforced limit.
    concurrency  integer NOT NULL CHECK (concurrency >= 1),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Seed the webhook queue policies so the transactional fan-out wake is valid
-- from the first event onward. Appending a subject event enqueues a
-- webhook_fanout wake job inside the SAME transaction as the delivery_outbox
-- row, and an enqueue resolves its attempt/backoff defaults from the queue's
-- policy row and refuses an unknown queue. The two webhook queues must
-- therefore have policy rows before the first event is appended, including on a
-- freshly migrated database that has never run the runtime (whose startup
-- reconciliation would otherwise be the first writer). The values mirror the
-- code-declared policies; the startup reconciliation remains the source of
-- truth and corrects any future drift in place.
INSERT INTO cw_core.queue_policy (queue, policy, max_attempts, backoff, lease_secs, concurrency)
VALUES
    ('webhook_fanout',   'singleton_loop', 5, '{"kind": "fixed", "base_secs": 5}', 120, 1),
    ('webhook_delivery', 'standard',       5, '{"kind": "fixed", "base_secs": 5}', 120, 4);

-- ---------------------------------------------------------------------------
-- job: the live work table. FLAT (not partitioned) on purpose.
--
-- The singleton partial-unique index below must hold globally across all
-- in-flight jobs for a queue; a partitioned parent cannot carry a partial
-- unique index that spans partitions, so the live table stays flat and small.
-- Terminal rows are moved out to job_history by the maintenance job, which is
-- what keeps this table small.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.job (
    id            uuid PRIMARY KEY,
    queue         text NOT NULL,
    payload       jsonb NOT NULL,
    state         text NOT NULL
                  CHECK (state IN ('available', 'running', 'completed', 'failed', 'cancelled')),
    run_at        timestamptz NOT NULL DEFAULT now(),
    attempts      integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts  integer NOT NULL CHECK (max_attempts >= 1),
    -- {kind: 'fixed'|'exponential', base_secs: <int>}
    backoff       jsonb NOT NULL,
    -- When set, (queue, singleton_key) is unique among in-flight jobs (see the
    -- partial unique index). NULL opts the job out of singleton semantics.
    singleton_key text,
    -- Per-claim fencing token. Heartbeat/complete/fail/defer all guard on it so
    -- a reclaimed (stale) worker's writes no-op instead of clobbering the row a
    -- new owner now holds.
    claim_token   uuid,
    claimed_by    text,
    heartbeat_at  timestamptz,
    -- Telemetry: how many times the handler voluntarily deferred this job.
    defer_count   integer NOT NULL DEFAULT 0 CHECK (defer_count >= 0),
    -- Hard lifetime bound. Enforced at claim time and at defer time: once
    -- now() > deadline the job is failed with a 'deadline_exceeded' error.
    deadline      timestamptz,
    -- {kind: <text>, message: <text>, ...} of the last failure/defer reason.
    last_error    jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz
);

-- The claim loop selects by (state, run_at, queue) ordered by (run_at, id).
-- This index serves both the predicate and the ordering for available rows.
CREATE INDEX job_claim_idx
    ON cw_core.job (queue, run_at, id)
    WHERE state = 'available';

-- The sweeper scans running rows whose heartbeat has expired.
CREATE INDEX job_reclaim_idx
    ON cw_core.job (heartbeat_at)
    WHERE state = 'running';

-- The maintenance job sweeps terminal rows into history by finished_at.
CREATE INDEX job_terminal_idx
    ON cw_core.job (finished_at)
    WHERE state IN ('completed', 'failed', 'cancelled');

-- Singleton uniqueness: at most one in-flight (available|running) job per
-- (queue, singleton_key). Terminal rows are excluded so a completed singleton
-- does not block the next enqueue. Because the live table is flat, this holds
-- globally.
CREATE UNIQUE INDEX job_singleton_inflight_idx
    ON cw_core.job (queue, singleton_key)
    WHERE singleton_key IS NOT NULL AND state IN ('available', 'running');

-- ---------------------------------------------------------------------------
-- job_history: terminal jobs, RANGE-partitioned monthly by finished_at.
--
-- The maintenance job moves completed/failed/cancelled rows here and deletes
-- them from cw_core.job. Uniqueness guarantees (singleton) never need to span
-- history, so a partitioned parent is fine here. A partitioned table's primary
-- key must include the partition key, so the PK is (id, finished_at).
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.job_history (
    id            uuid NOT NULL,
    queue         text NOT NULL,
    payload       jsonb NOT NULL,
    state         text NOT NULL CHECK (state IN ('completed', 'failed', 'cancelled')),
    run_at        timestamptz NOT NULL,
    attempts      integer NOT NULL,
    max_attempts  integer NOT NULL,
    backoff       jsonb NOT NULL,
    singleton_key text,
    defer_count   integer NOT NULL,
    deadline      timestamptz,
    last_error    jsonb,
    created_at    timestamptz NOT NULL,
    started_at    timestamptz,
    finished_at   timestamptz NOT NULL,
    PRIMARY KEY (id, finished_at)
) PARTITION BY RANGE (finished_at);

CREATE INDEX job_history_queue_idx ON cw_core.job_history (queue, finished_at);

-- ---------------------------------------------------------------------------
-- cron_tick: double-fire prevention for the in-process scheduler.
--
-- Every replica runs the scheduler. Before a replica enqueues a cron
-- occurrence it INSERTs (queue, tick_id) here with ON CONFLICT DO NOTHING; the
-- row that wins the insert is the one allowed to enqueue. tick_id is the
-- deterministic scheduled instant (RFC3339 UTC of the occurrence), so all
-- replicas compute the same id and exactly one enqueue happens. No leader
-- election. Rows are pruned by the maintenance job after a retention window.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.cron_tick (
    queue       text NOT NULL,
    tick_id     text NOT NULL,
    enqueued_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (queue, tick_id)
);

CREATE INDEX cron_tick_prune_idx ON cw_core.cron_tick (enqueued_at);

-- ---------------------------------------------------------------------------
-- repair_completion: the one-shot repair scans' completion markers.
--
-- Some sweeps open with a repair scan that heals damage only a SUPERSEDED code
-- path could produce (e.g. the orphan-refund intent backfill, which emits the
-- operator-facing intent for uploads a pre-atomic sweep credited without one).
-- Such a scan finds work at most once per deployment history: after the code
-- that produced the damage is gone and the backlog is healed, every later scan
-- is a guaranteed-empty pass over a growing table. Recording "this repair has
-- observed a clean state" here lets the scan disable itself durably — across
-- restarts and replicas — instead of re-scanning forever. One row per repair,
-- keyed on a stable name the repair owns.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.repair_completion (
    repair       text PRIMARY KEY,
    completed_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- subject_event: durable per-subject event log, RANGE-partitioned monthly by
-- created_at.
--
-- subject_seq is allocated transactionally by the writer (pg_advisory_xact_lock
-- on the subject, then 1 + max(subject_seq)), so it is gap-free and
-- commit-ordered per subject. The PK includes created_at because a partitioned
-- table's primary key must contain the partition key; (subject_kind,
-- subject_id, subject_seq) is what callers treat as the logical identity.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.subject_event (
    subject_kind text NOT NULL,
    subject_id   text NOT NULL,
    subject_seq  bigint NOT NULL CHECK (subject_seq >= 1),
    event_type   text NOT NULL,
    payload      jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_kind, subject_id, subject_seq, created_at)
) PARTITION BY RANGE (created_at);

-- ---------------------------------------------------------------------------
-- subject_seq: durable per-subject sequence high-water counter.
--
-- subject_seq must be gap-free and strictly increasing per
-- (subject_kind, subject_id) for the life of the subject. Deriving the next
-- value from max(subject_seq) over cw_core.subject_event is unsafe: that table
-- is range-partitioned by created_at and old partitions are dropped past the
-- retention window. A subject that goes silent past the window, then
-- reactivates after its partitions are dropped, would see max() return NULL and
-- the allocator would restart its sequence at 1. The regressed value collides
-- on the never-pruned delivery_outbox dedupe_key and aborts the wrapping
-- transaction on every retry.
--
-- This table anchors the next sequence durably and independently of which event
-- partitions still exist. The writer bumps next_seq under the same per-subject
-- advisory lock that orders the append, so allocation stays single-writer and
-- commit-ordered while surviving retention pruning of the event rows. A subject
-- whose partitions were already dropped contributes no row and is created
-- lazily on its next append, which is correct: there is no surviving event
-- whose sequence it could collide with.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.subject_seq (
    subject_kind text NOT NULL,
    subject_id   text NOT NULL,
    -- The sequence to hand out on the next append for this subject. Always the
    -- value of the most-recently-allocated subject_seq plus one; starts at 1.
    next_seq     bigint NOT NULL CHECK (next_seq >= 1),
    PRIMARY KEY (subject_kind, subject_id)
);

-- ---------------------------------------------------------------------------
-- delivery_outbox: outbound delivery queue for subject events.
--
-- The delivery loop ships rows per subject strictly in subject_seq order: an
-- undelivered earlier event blocks later events for the SAME subject only.
-- dedupe_key is unique so the same logical delivery is never enqueued twice.
--
-- `fanned_out_at` is the presence-based webhook fan-out marker (see the webhook
-- section). A NULL marker means the row has not yet been exploded into
-- webhook_delivery rows; a stamped marker means it has. A dedicated column
-- rather than an overload of delivered_at keeps SSE semantics and webhook
-- fan-out independent on this shared spine.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.delivery_outbox (
    id              uuid PRIMARY KEY,
    subject_kind    text NOT NULL,
    subject_id      text NOT NULL,
    subject_seq     bigint NOT NULL CHECK (subject_seq >= 1),
    event_type      text NOT NULL,
    payload         jsonb NOT NULL,
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    dedupe_key      text NOT NULL UNIQUE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Presence-based webhook fan-out marker. NULL = not yet fanned out.
    fanned_out_at   timestamptz
);

-- The SSE delivery loop scans undelivered rows ordered per subject by sequence.
CREATE INDEX delivery_outbox_pending_idx
    ON cw_core.delivery_outbox (subject_kind, subject_id, subject_seq)
    WHERE delivered_at IS NULL;

-- The fan-out drain claims un-fanned rows as a SET (order within a pass does
-- not affect completeness; every un-fanned row is visited on some pass and
-- stamped once). The partial index keeps the claim scan to the un-fanned
-- working set, which shrinks toward empty under steady state. Per-subject
-- DELIVERY ordering is imposed downstream on each webhook_delivery row, so the
-- fan-out stage itself needs no ordering and the index is keyed on created_at
-- only (oldest-first fairness).
CREATE INDEX delivery_outbox_fanout_idx
    ON cw_core.delivery_outbox (created_at)
    WHERE fanned_out_at IS NULL;

-- The firehose-retention outbox sweep selects the oldest fanned-out rows by
-- created_at and prunes them with bounded batch deletes (the table is not
-- partitioned: dedupe_key is globally unique). A row still awaiting fan-out
-- (fanned_out_at IS NULL) is never indexed here and so is never swept.
CREATE INDEX delivery_outbox_fanned_age_idx
    ON cw_core.delivery_outbox (created_at)
    WHERE fanned_out_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- NOTIFY wake-hint triggers.
--
-- After a job row is inserted, fire a NOTIFY carrying the queue name; after a
-- subject_event row is inserted, fire a NOTIFY carrying the subject's kind and
-- id. The runtime / an open SSE stream LISTENs and uses these only to wake
-- early; correctness never depends on a notification arriving, because the
-- consumer always re-reads the durable table on an interval fallback. pg_notify
-- delivers on COMMIT, so a listener never sees a row it cannot yet act on.
-- ---------------------------------------------------------------------------
CREATE FUNCTION cw_core.notify_job_available()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('cw_core_job_available', NEW.queue);
    RETURN NULL;
END;
$$;

CREATE TRIGGER job_available_notify
    AFTER INSERT ON cw_core.job
    FOR EACH ROW
    EXECUTE FUNCTION cw_core.notify_job_available();

CREATE FUNCTION cw_core.notify_subject_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('cw_core_subject_event', NEW.subject_kind || ':' || NEW.subject_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER subject_event_notify
    AFTER INSERT ON cw_core.subject_event
    FOR EACH ROW
    EXECUTE FUNCTION cw_core.notify_subject_event();

-- ---------------------------------------------------------------------------
-- Initial partitions.
--
-- The maintenance job creates future partitions ahead of time, but a fresh
-- database needs the current opening range to exist before the first insert.
-- The partition-maintenance framework takes over from here (create-ahead next
-- months, drop old ones).
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.job_history_2026_06
    PARTITION OF cw_core.job_history
    FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');

CREATE TABLE cw_core.job_history_2026_07
    PARTITION OF cw_core.job_history
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');

CREATE TABLE cw_core.subject_event_2026_06
    PARTITION OF cw_core.subject_event
    FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');

CREATE TABLE cw_core.subject_event_2026_07
    PARTITION OF cw_core.subject_event
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');

-- DEFAULT-partition backstops for both range-partitioned tables. Monthly
-- partition provisioning is a liveness property, not a schema guarantee: a
-- deployment whose maintenance lapsed for longer than the provisioned
-- lookahead, or a database attached out of band, would face an INSERT with no
-- partition to route to — and subject_event sits on the publish hot path, so a
-- missing partition there turns directly into failed publishes.
--
-- A DEFAULT partition converts that failure mode into a routed row: an insert
-- can never fail for lack of a partition. The classical trade-off — rows
-- accumulated in DEFAULT block a later CREATE TABLE ... PARTITION OF for their
-- range — is owned by the maintenance pass itself: every ensure pass first
-- drains the DEFAULT partition into real monthly partitions (detach, create
-- the months its rows span, move them, re-attach, all in one transaction under
-- the parent's lock) before creating ahead, so DEFAULT rows are a self-healing
-- transient rather than a wedge. In the healthy steady state both DEFAULT
-- partitions are empty.
CREATE TABLE cw_core.job_history_default
    PARTITION OF cw_core.job_history DEFAULT;

CREATE TABLE cw_core.subject_event_default
    PARTITION OF cw_core.subject_event DEFAULT;


-- ===========================================================================
-- SECTION 2 — Cardano substrate: cached protocol parameters, operators, the
-- operator-wallet identity, and the durable per-UTxO state machine.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- cardano_protocol_params: cached protocol parameters, one row per
-- (network, epoch).
--
-- The fee a Proof-of-Existence transaction pays and the minimum-ADA a change
-- output must clear are both functions of the network's on-chain protocol
-- parameters. Those parameters change at most once per epoch, so caching the
-- values per epoch lets every quote and every build read them from Postgres
-- without an oracle call. A single background loop is the only writer; it
-- inserts the row for a freshly observed epoch and never overwrites an epoch
-- that is already stored, so a recorded epoch's values are immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.cardano_protocol_params (
    -- The Cardano network the parameters belong to ('mainnet' | 'preprod').
    -- Stored as free text rather than an enum so a new network is a data
    -- concern, not a schema migration.
    network             text NOT NULL,
    -- The epoch the parameters were in force for. Together with `network` this
    -- is the natural key: parameters are constant within an epoch.
    epoch               integer NOT NULL CHECK (epoch >= 0),
    -- Linear fee coefficient (lovelace per transaction byte).
    min_fee_a           bigint NOT NULL CHECK (min_fee_a >= 0),
    -- Linear fee constant (lovelace).
    min_fee_b           bigint NOT NULL CHECK (min_fee_b >= 0),
    -- Lovelace charged per byte of a serialised output, the input to the
    -- minimum-ADA computation.
    coins_per_utxo_byte bigint NOT NULL CHECK (coins_per_utxo_byte >= 0),
    -- Maximum serialised transaction size in bytes.
    max_tx_size         bigint NOT NULL CHECK (max_tx_size >= 0),
    -- The full provider response for this epoch, retained verbatim so a future
    -- reader can extract a parameter this schema does not yet have a column for
    -- without re-fetching from the network.
    raw                 jsonb NOT NULL,
    -- When this row was written. Diagnostic only; it never participates in
    -- which row a reader selects (that is decided by the highest epoch).
    fetched_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (network, epoch)
);

-- Readers ask for "the newest stored epoch for this network", which is an
-- index-only descending scan of the leading key columns.
CREATE INDEX cardano_protocol_params_latest_idx
    ON cw_core.cardano_protocol_params (network, epoch DESC);

-- ---------------------------------------------------------------------------
-- cardano_params_refresh: loop-liveness marker for the protocol-parameter
-- populate loop.
--
-- The fee cache above carries one immutable row per (network, epoch): its
-- `fetched_at` is stamped only at INSERT and is never updated, so once an
-- epoch is recorded that timestamp freezes at the instant the epoch first
-- appeared. A Cardano epoch lasts about five days, so in steady state the
-- populate loop runs every few minutes but finds the current epoch already
-- cached and writes nothing — leaving `fetched_at` hours, then days, old even
-- though the loop is perfectly healthy. Driving a read-path staleness warning
-- off `fetched_at` therefore fires on every read for most of each epoch and
-- means nothing.
--
-- This table separates "is the populate loop alive?" from "how old is the
-- newest epoch?". Every successful populate pass — including the common no-op
-- pass that finds the epoch already cached — upserts `last_checked_at` here.
-- The read path then reports staleness when the loop has not checked in
-- recently (a true liveness signal), while leaving the fee table genuinely
-- immutable per epoch.
--
-- One row per network. An absent row means the loop has not completed a pass
-- since deploy, which the read path treats as not-yet-observed (not stale)
-- rather than alarming on first boot.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.cardano_params_refresh (
    -- The Cardano network this liveness marker tracks ('mainnet' | 'preprod' |
    -- 'preview'). Free text to match `cardano_protocol_params.network`, so a new
    -- network is a data concern, not a schema migration.
    network         text NOT NULL PRIMARY KEY,
    -- The instant the populate loop last completed a successful pass for this
    -- network (a fetch-and-insert OR a found-already-cached no-op). Updated on
    -- every healthy pass, so its age is the loop's true staleness.
    last_checked_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- operator: a tenant.
--
-- An operator registers and administers wallets and may be entitled to spend
-- them. The scheduler ranks wallets a spending operator is entitled to within a
-- single network. A disabled operator's wallets stay on the books (their UTxO
-- history is preserved) but the scheduler skips them.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.operator (
    id         uuid PRIMARY KEY,
    -- Operator-facing display name. Free text; the stable identity is `id`.
    label      text NOT NULL,
    status     text NOT NULL DEFAULT 'active'
               CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- operator_wallet: one signing wallet, a global on-chain identity.
--
-- A wallet is its on-chain payment address: a given address signs exactly one
-- way for everyone, so there is exactly one row per `(network, address)`. That
-- UNIQUE is what makes the alias attack unrepresentable at the schema layer: a
-- second tenant cannot mint a parallel row for an address another tenant
-- already registered, so two rows can never disagree about who may spend one
-- address.
--
-- `registrar_operator_id` is who REGISTERED and administers the row (it drives
-- the drain/reactivate lifecycle, holds the key in its keyring, and authors the
-- audit). It is NOT the spend scope: who may SPEND a wallet is expressed in
-- `wallet_grant`. A shared-key multi-vendor setup is the registrar issuing
-- `operator` grants on its wallet, never a second operator minting a row.
--
-- `network` pins the wallet to a single Cardano network so the scheduler never
-- mixes a preprod wallet into a mainnet submit. The lifecycle column drives the
-- scheduler:
--   - active   : eligible to be picked for new submits.
--   - draining : no new claims, but already-leased UTxOs may finish their tx.
--   - retired  : terminal; the wallet is off the books for scheduling.
-- The two counters are denormalised hints the scheduler reads to spread load;
-- they are decayed/reset by the daily decay job and bumped on submit.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.operator_wallet (
    id                    uuid PRIMARY KEY,
    registrar_operator_id uuid NOT NULL REFERENCES cw_core.operator (id),
    label                 text NOT NULL,
    address               text NOT NULL,
    network               text NOT NULL CHECK (network IN ('mainnet', 'preprod', 'preview')),
    status                text NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'draining', 'retired')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    -- Set when the wallet first entered `retired`; NULL while it is active or
    -- draining. Diagnostic; the scheduler keys off `status`, not this column.
    retired_at            timestamptz,
    -- Rolling count of submits in the trailing 24h, reset by the decay job.
    -- The scheduler prefers the least-used wallet to spread load evenly.
    submission_count_24h  bigint NOT NULL DEFAULT 0 CHECK (submission_count_24h >= 0),
    -- Last time a submit picked this wallet; NULL until first use. Used as the
    -- final tie-break (oldest-used first) so round-robin emerges under ties.
    last_used_at          timestamptz,
    -- When the wallet's local UTxO view was last reconciled against the chain.
    -- The replenish idle gate trusts the cached canonical count only while this
    -- is fresh; once it goes stale the gate falls through to a fresh
    -- snapshot+ingest (running the vanished-output reconciliation) before
    -- deciding, so an out-of-band deficit (a shared keyring across replicas, or
    -- a manual operator spend) is always discovered. NULL means never ingested,
    -- treated as stale so a wallet's first replenish pass always reconciles.
    last_ingest_at        timestamptz,
    -- Global identity: a payment address signs one way for everyone, so exactly
    -- one row per (network, address). A second operator that registers an
    -- already-registered address collides here and is rejected, rather than
    -- minting a parallel row that aliases the first.
    UNIQUE (network, address)
);

CREATE INDEX operator_wallet_registrar_idx
    ON cw_core.operator_wallet (registrar_operator_id, network)
    WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- wallet_utxo: the durable, per-UTxO state machine.
--
-- One row per unspent output the engine tracks for a wallet, with a per-UTxO
-- state column so concurrent submits lease distinct outputs without clobbering
-- each other. The composite primary key is the on-chain UTxO reference
-- `(wallet_id, tx_hash, output_index)`.
--
-- State machine (transitions enforced in code, fenced on `lease_token`):
--   available      -> in_flight       (claim_utxo, stamps lease_token + expiry)
--   in_flight      -> available       (release, or the lease reaper on expiry)
--   in_flight      -> pending_spent   (apply_submit, on an accepted submit)
--   pending_spent  -> confirmed_spent (apply_confirmed, when the spend confirms)
--
-- `canonical` is computed on ingest and is the predicate the quote relies on:
-- a pure-ADA output at a low index whose value sits inside the configured band,
-- so a one-input + one-change-output transaction over it has a fee that depends
-- only on the record length, never on which specific UTxO was chosen.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.wallet_utxo (
    wallet_id     uuid NOT NULL REFERENCES cw_core.operator_wallet (id),
    -- 32-byte transaction id of the output's origin transaction.
    tx_hash       bytea NOT NULL,
    output_index  integer NOT NULL CHECK (output_index >= 0),
    lovelace      bigint NOT NULL CHECK (lovelace >= 0),
    state         text NOT NULL DEFAULT 'available'
                  CHECK (state IN ('available', 'in_flight', 'pending_spent', 'confirmed_spent')),
    -- Computed on ingest: pure-ADA, low output index, value inside the band.
    -- A canonical UTxO is what makes the quote fee exact.
    canonical     boolean NOT NULL DEFAULT false,
    -- A `source = 'change'` row inserted by apply_submit is NOT spendable for
    -- chaining until the spend confirms unless policy opts in. Defaults to false
    -- so the replenisher/scheduler never builds on unconfirmed change.
    spendable_unconfirmed boolean NOT NULL DEFAULT false,
    -- Set while the row is `in_flight`: the fencing token the builder holds.
    -- Every transition out of in_flight guards on this token so a stale builder
    -- cannot move a UTxO a fresh claimant now owns.
    lease_token   uuid,
    -- When the lease expires. The reaper returns an expired in_flight row to
    -- available. This is the SHORT submit lease (minutes), distinct from the
    -- 15-minute quote TTL.
    lease_expires_at timestamptz,
    -- Where the row came from: a chain snapshot ingest, or the expected change
    -- output apply_submit recorded locally before the spend confirmed.
    source        text NOT NULL CHECK (source IN ('snapshot', 'change')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- For an 'in_flight' row, the state a rollback must restore it TO. NULL for
    -- an ordinary claim/claim_source lease (whose rollback target is
    -- 'available') and set to the prior spent state by claim_replacement, so a
    -- cancelling replacement's borrowed input returns to the original's
    -- reservation rather than to the free pool: handing a still-reserved input
    -- back to the free pool would let a fresh claim build a conflicting
    -- transaction over it (a double-spend / UTxO-exclusivity break). Only the
    -- chain-truth-proven restore path (gated on a settlement-deep conflicting
    -- spend or a deterministic node reject of a FIRST submit) returns a spent
    -- input to 'available'.
    restore_state text
                  CHECK (restore_state IS NULL
                         OR restore_state IN ('pending_spent', 'confirmed_spent')),
    PRIMARY KEY (wallet_id, tx_hash, output_index),
    -- An in_flight row always carries its lease; a row in any other state never
    -- does. This keeps the fencing invariant a schema property, not just a code
    -- convention.
    CHECK (
        (state = 'in_flight' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state <> 'in_flight' AND lease_token IS NULL AND lease_expires_at IS NULL)
    ),
    -- A restore target is meaningful only while the row is leased: it is the
    -- state the lease's rollback must return the row to. A row in any
    -- non-in_flight state has no pending rollback, so it must never carry a
    -- stale target that a later ordinary lease could resurrect to a spent state.
    CONSTRAINT wallet_utxo_restore_state_only_in_flight
        CHECK (restore_state IS NULL OR state = 'in_flight')
);

-- The scheduler counts a wallet's canonical, available UTxOs and the reaper
-- scans expired leases; both are served by this partial index.
CREATE INDEX wallet_utxo_available_idx
    ON cw_core.wallet_utxo (wallet_id)
    WHERE state = 'available' AND canonical;

-- The lease reaper scans in_flight rows whose lease has expired.
CREATE INDEX wallet_utxo_lease_idx
    ON cw_core.wallet_utxo (lease_expires_at)
    WHERE state = 'in_flight';

-- The confirmation path resolves a pending_spent row by its spending
-- transaction; index the pending rows for that scan.
CREATE INDEX wallet_utxo_pending_idx
    ON cw_core.wallet_utxo (wallet_id)
    WHERE state = 'pending_spent';


-- ===========================================================================
-- SECTION 3 — The cw_api extension contract and the tenant anchor.
--
-- `cw_api` is the STABLE EXTENSION CONTRACT: the small set of tables an
-- embedding application (a "vendor") is allowed to build foreign keys against.
-- Everything volatile stays in `cw_core`; only the identity columns a vendor
-- must be able to reference live in `cw_api`. A vendor FK-references
-- `cw_api.account(id)` / `cw_api.records(tx_hash)`, never a `cw_core` table, so
-- a `cw_core` redesign can never break a vendor's foreign keys. A privilege test
-- proves a vendor role can reference `cw_api` with only SELECT + REFERENCES (no
-- write grants), while the engine's own migrator role cannot create, alter, or
-- drop anything inside the vendor schema.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- cw_api.account: the tenant anchor (the primary tenant identity).
--
-- A tenant ("account") is the unit a balance, a quote, and a published record
-- belong to. Its STABLE identity columns live here in `cw_api` so a vendor can
-- FK-reference an account without depending on any `cw_core` table. The columns
-- are intentionally minimal: an id, when it was created, and a soft-delete
-- marker. Everything else about a tenant (which operator owns it, its lifecycle
-- status) is volatile engine state and lives in the `cw_core.account_detail`
-- satellite below, a strict 1:1 of this row.
--
-- Hard deletion is structurally prevented: the satellite references this row ON
-- DELETE RESTRICT, so an account with a detail row (every account has one) can
-- never be DELETEd. Tenant removal is `deleted_at`, never a row delete.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_api.account (
    id         uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Soft-delete marker. NULL while the account is live; set to the deletion
    -- instant when the tenant is removed. The engine never hard-deletes an
    -- account row (the RESTRICT FKs throughout make it impossible anyway).
    deleted_at timestamptz
);

-- ---------------------------------------------------------------------------
-- cw_core.account_detail: the volatile 1:1 satellite of cw_api.account.
--
-- Holds the engine-internal attributes of a tenant that a vendor must NOT FK
-- against: the owning operator and the tenant's lifecycle status. Separating it
-- from the anchor keeps the anchor's column set frozen even as the engine adds
-- internal tenant attributes over time. The FK to `cw_api.account` is ON DELETE
-- RESTRICT: it is what makes an account hard-delete impossible (the satellite
-- always exists, so the anchor always has a dependent).
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.account_detail (
    account_id  uuid PRIMARY KEY REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    operator_id uuid NOT NULL REFERENCES cw_core.operator (id),
    status      text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'disabled')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- An operator's accounts, for operator-scoped reads.
CREATE INDEX account_detail_operator_idx
    ON cw_core.account_detail (operator_id);

-- ---------------------------------------------------------------------------
-- cw_api.records: the thin on-chain record anchor.
--
-- A vendor that wants to attach its own per-record data (a display title, a
-- folder assignment) FK-references THIS table, not `cw_core.chain_records`: the
-- anchor exposes only the transaction hash and when it was indexed, so the
-- engine can restructure the rich `chain_records` columns without breaking a
-- vendor's foreign keys.
--
-- It is written ONLY by the single chain-records writer (records.rs), in the
-- SAME transaction that writes the matching `chain_records` row, so the anchor
-- and the rich row are always created together. `cw_core.chain_records.tx_hash`
-- gains a FK to this anchor ON DELETE RESTRICT, so the rich row can never
-- outlive its anchor and an anchor with a rich child cannot be hard-deleted.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_api.records (
    tx_hash    bytea PRIMARY KEY,
    indexed_at timestamptz NOT NULL DEFAULT now()
);


-- ===========================================================================
-- SECTION 4 — The PoE record lifecycle and the issuer-agnostic on-chain index.
--
-- ZERO-KNOWLEDGE INVARIANT. The on-chain index is zero-knowledge about who a
-- sealed record was addressed to. No object in this section carries a recipient
-- pubkey, an account/identity reference, a slot-match hint, or any per-user
-- correlator: the only signer columns are the chain-public signer Ed25519 keys
-- (already in every COSE_Sign1 protected header on chain), and the only
-- transaction-bytes columns are the verbatim metadata / transaction CBOR
-- (already public on the ledger). A CI guard scans the indexer blocks for
-- forbidden vocabulary.
--
-- chain_records / chain_record_signer have exactly ONE writer MODULE
-- (src/chain/records.rs): every statement that mutates them lives there. Two
-- producers feed it — the confirm threshold-flip enqueues an 'index_tx' job the
-- writer loop drains, and the forward scan calls the same module's insert helper
-- inside its own atomic iteration transaction (so a reorg delete, the record
-- insert, and the cursor advance all commit in lockstep). The insert converges
-- by tx_hash: the job path is ON CONFLICT DO NOTHING and the scan path is
-- ON CONFLICT DO UPDATE that only fills the nullable tx_cbor enrichment, never
-- the identity columns. An architecture test asserts no other module names them
-- in SQL.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- poe_record: the per-record submit/confirm state machine.
--
-- One row per Proof-of-Existence the engine is asked to publish. The row is the
-- subject of `subject_event`s (subject_kind = 'poe_record'), so an SSE consumer
-- rides the durable event log rather than a transient NOTIFY. The lifecycle:
--
--   draft       -> submitting        (the submit job is enqueued)
--   submitting  -> submitted         (the network accepted the transaction)
--   submitting  -> permanent_failure (build/gateway/byte-budget terminal arm)
--   submitted   -> confirmed         (crossed the confirmation threshold)
--   submitted   -> permanent_failure (mempool give-up, or rollback cap)
--   submitted   -> submitted         (rollback retry clears coords, resubmits)
--   confirmed   -> permanent_failure (post-confirm reorg, rollback cap exhausted)
--
-- The record keeps its customer-visible status, but its
-- spent_inputs / actual_fee_lovelace / tx_hash / block_height / block_time /
-- first_seen_on_chain_at columns are PROJECTIONS the confirm authority copies
-- from the winning chain_attempt when it flips the record. `current_attempt_id`
-- is the join from a record to the attempt it currently rides; the FK is added
-- after chain_attempt exists (the two tables reference each other).
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.poe_record (
    id                    uuid PRIMARY KEY,
    -- The operator whose wallet pool publishes this record.
    operator_id           uuid NOT NULL REFERENCES cw_core.operator (id),
    -- The canonical Label 309 record bytes published under the metadata label.
    record_bytes          bytea NOT NULL,
    status                text NOT NULL DEFAULT 'draft'
                          CHECK (status IN ('draft', 'submitting', 'submitted', 'confirmed', 'permanent_failure')),
    -- 32-byte transaction id once a submit lands; NULL while draft/submitting,
    -- and cleared again by a rollback retry before the resubmit.
    tx_hash               bytea,
    -- On-chain coordinates, populated when the transaction is observed in a
    -- block and cleared by a rollback retry.
    block_height          bigint CHECK (block_height IS NULL OR block_height >= 0),
    block_time            timestamptz,
    -- When the transaction was first seen on chain (set once, preserved across a
    -- confirmation; cleared by a rollback retry). Drives the reorg safety window.
    first_seen_on_chain_at timestamptz,
    -- How many times a reorg has rolled this record back and resubmitted it. The
    -- confirm path caps it and then refunds instead of retrying again.
    rollback_retry_count  integer NOT NULL DEFAULT 0 CHECK (rollback_retry_count >= 0),
    -- The wallet the submit bound the record to (set on submit, preserved across
    -- a rollback so a retry can prefer the same wallet's change lineage). NULL
    -- until the first submit binds one.
    wallet_id             uuid REFERENCES cw_core.operator_wallet (id),
    -- The wallet inputs the accepted transaction spent, as a JSON array of
    -- {tx_hash, index, lovelace}. Recorded on submit so a reorg rollback can
    -- cancel the rolled-back transaction by construction: a cancelling
    -- replacement must spend at least one of these inputs, so the old
    -- metadata-only transaction can never re-enter the chain. NULL until a submit
    -- lands; cleared by a rollback retry alongside the on-chain coordinates.
    spent_inputs          jsonb,
    -- The exact fee the accepted transaction paid, recorded for quote-variance
    -- accounting. NULL until a submit lands (and best-effort even then).
    actual_fee_lovelace   bigint CHECK (actual_fee_lovelace IS NULL OR actual_fee_lovelace >= 0),
    -- The request id that originated this record, propagated onto refund/events
    -- for end-to-end tracing.
    request_id            text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    -- The tenancy reference a record carries: the strongly-typed account anchor
    -- id, or NULL for an operator-direct submit with no downstream account.
    -- RESTRICT keeps an account with records from being hard-deleted.
    account_id            uuid REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    -- The data-plane publish dedup column: SHA-256 over the record bytes, set at
    -- insert by the publish path. Submitting the identical canonical-CBOR record
    -- for the same account a second time returns the prior row (HTTP 200) rather
    -- than inserting a new one and charging again (HTTP 202). NULL for
    -- operator-direct submits that bypass the data plane.
    record_sha256         bytea,
    -- The chain_attempt this record currently rides. The FK is added below, once
    -- chain_attempt exists; set when an attempt is recorded, re-pointed on a
    -- replacement, cleared when the confirm authority supersedes the prior one.
    current_attempt_id    uuid
);

-- The submit path loads a record by id; the confirm path scans live records by
-- status and coordinates. Pass A / A-reverify: status in (submitted, confirmed)
-- with a block height.
CREATE INDEX poe_record_onchain_idx
    ON cw_core.poe_record (block_height)
    WHERE status IN ('submitted', 'confirmed') AND tx_hash IS NOT NULL AND block_height IS NOT NULL;

-- An account's records, for account-scoped reads.
CREATE INDEX poe_record_account_idx
    ON cw_core.poe_record (account_id)
    WHERE account_id IS NOT NULL;

-- One record per (account, record-hash): the dedup uniqueness the publish path
-- relies on to distinguish a fresh publish (202) from a replay (200). Partial,
-- so operator-direct submits with a NULL account or hash are exempt.
CREATE UNIQUE INDEX poe_record_account_record_sha256_idx
    ON cw_core.poe_record (account_id, record_sha256)
    WHERE account_id IS NOT NULL AND record_sha256 IS NOT NULL;

-- NOTE: there is deliberately no created_at-keyed mempool index on poe_record.
-- The mempool reconcile/alert enumeration keys on chain_attempt.mempool_entered_at
-- (see chain_attempt_reconcile_idx), and there is no cull-by-age path at all, so
-- a record-level mempool index would serve nothing.

-- ---------------------------------------------------------------------------
-- chain_records: the issuer-agnostic on-chain PoE index.
--
-- One row per on-chain Proof-of-Existence transaction, keyed on its 32-byte
-- transaction id. The derived columns mirror the host indexer's contract:
-- `signer_ed25519` is the first record signer's raw Ed25519 pubkey (COSE path-2
-- wins, else the path-1 protected-header kid), `item_count` is the number of
-- content items, and `scheme` is the encryption scheme of the first item
-- (0 open / 1 sealed / 2 passphrase). NO per-recipient column is ever stored:
-- the index is zero-knowledge about who a sealed record was addressed to.
--
-- Not partitioned: the global PK uniqueness (one row per tx_hash, spanning every
-- source) is the load-bearing invariant, and a partitioned parent cannot carry a
-- primary key that does not include the partition key.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.chain_records (
    -- 32-byte transaction id. The global natural key. The FK to the thin
    -- cw_api.records anchor (RESTRICT, so the rich row can never outlive its
    -- anchor) is added as a named constraint just below this CREATE.
    tx_hash         bytea PRIMARY KEY,
    block_height    bigint NOT NULL CHECK (block_height >= 0),
    block_time      timestamptz NOT NULL,
    -- The verbatim Label 309 metadata CBOR the transaction carried, retained so
    -- a verifier can re-derive any column without re-fetching from chain.
    metadata_cbor   bytea NOT NULL,
    -- The first record signer's raw 32-byte Ed25519 pubkey, or NULL when the
    -- record carries no signatures or the first key is unresolvable. This is the
    -- PRIMARY projected signer; the full verified-signer set lives in the
    -- chain_record_signer side table below.
    signer_ed25519  bytea,
    -- Number of content items in the record (>= 0).
    item_count      integer NOT NULL CHECK (item_count >= 0),
    -- Encryption scheme of the first item: 0 open, 1 recipient-sealed,
    -- 2 passphrase.
    scheme          smallint NOT NULL CHECK (scheme IN (0, 1, 2)),
    indexed_at      timestamptz NOT NULL DEFAULT now(),
    -- The full on-chain transaction bytes. Nullable: the forward scan inserts a
    -- record as soon as it decodes the Label 309 metadata, before the heavier
    -- full-transaction fetch resolves, so a row can exist with a NULL tx_cbor
    -- that a bounded backfill pass fills in later. The bytes are the verbatim
    -- transaction already public on the ledger; they carry no recipient data
    -- beyond what the chain itself reveals.
    tx_cbor         bytea
);

-- The list view scans recent records newest-first by block coordinates.
CREATE INDEX chain_records_block_idx
    ON cw_core.chain_records (block_height DESC, tx_hash);

-- Ascending range scans and keyset pagination on (block_height, tx_hash): a
-- from_block/to_block window walked oldest-first with a (block_height, tx_hash)
-- cursor boundary.
CREATE INDEX chain_records_block_asc_idx
    ON cw_core.chain_records (block_height, tx_hash);

-- Sealed-record fast path. The read feed's "sealed only" filter selects every
-- record whose first item carries an encryption envelope: scheme <> 0, which
-- covers both the recipient-sealed class (scheme 1) and the passphrase-sealed
-- class (scheme 2). The partial index is over that exact predicate so the sealed
-- feed never scans the open records, in both keyset-pagination directions.
CREATE INDEX chain_records_sealed_idx
    ON cw_core.chain_records (block_height, tx_hash)
    WHERE scheme <> 0;

-- A single signer's records, newest-first (by the PRIMARY signer): list every
-- PoE a given publisher key signed first, without scanning the whole table. The
-- ?signer= filter that matches ANY verified signer rides chain_record_signer.
CREATE INDEX chain_records_signer_idx
    ON cw_core.chain_records (signer_ed25519, block_height DESC);

-- Index coverage for the public records-list time-window filter. Every other
-- narrowing filter the anonymous `GET /records` surface accepts rides an
-- index: the plain and cursored walks ride the block-coordinate indexes above,
-- the sealed filter its partial twin, the signer filter the verified-signer
-- set, and the block-range bounds the same block-coordinate indexes. Without
-- an index of its own, a `from_time`/`to_time` window that matches few (or no)
-- rows degrades to a walk of the whole block index filtering row by row — a
-- full-table read an anonymous caller could request at will, bounded only by
-- the read path's statement timeout. Indexing `block_time` gives the planner a
-- selective access path for the time window; the statement timeout remains the
-- backstop for plans no index can serve.
CREATE INDEX chain_records_block_time_idx
    ON cw_core.chain_records (block_time);

-- The rich chain-record row references its thin anchor. RESTRICT, not CASCADE:
-- an anchor with a rich child cannot be deleted out from under it; a reorg
-- deletes the rich row (the child) directly, which is always permitted.
ALTER TABLE cw_core.chain_records
    ADD CONSTRAINT chain_records_anchor_fk
    FOREIGN KEY (tx_hash) REFERENCES cw_api.records (tx_hash) ON DELETE RESTRICT;

-- ---------------------------------------------------------------------------
-- chain_record_signer: one row per verified signer of an indexed record.
--
-- `chain_records.signer_ed25519` holds the FIRST verified signer (the primary,
-- projected column). That alone makes a record findable only by its first
-- signer: a record co-signed by another tool that ordered a different key first,
-- or genuinely co-authored by several keys, is invisible to a query for any
-- non-first signer. This side table records one row per VERIFIED signer, so the
-- public `?signer=` filter discovers a record by ANY of its
-- cryptographically-verified signers while the rich row keeps its single primary
-- signer for projection.
--
-- Membership is by VERIFIED signature only. A row is written for a signer key
-- only when that key's record-level signature cryptographically verifies (and,
-- on the wallet path, binds its stake address under the carrying network) —
-- never for a key a forged `sigs[]` entry merely names. So a forgery naming a
-- victim's key can never plant that key here and poison the victim's publisher
-- view. The only key stored is the chain-public signer key already present in
-- the record's COSE_Sign1 protected header on chain.
--
-- The composite primary key (signer_ed25519, tx_hash) makes a re-observation of
-- the same (signer, transaction) pair a converging upsert. The FK to
-- chain_records(tx_hash) ON DELETE CASCADE means a reorg that deletes a rich row
-- drops its signer rows in lockstep, with no separate cleanup statement.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.chain_record_signer (
    -- A verified signer's raw 32-byte Ed25519 public key.
    signer_ed25519 bytea NOT NULL,
    -- The transaction whose record this key verifiably signed.
    tx_hash        bytea NOT NULL REFERENCES cw_core.chain_records (tx_hash) ON DELETE CASCADE,
    -- The block height the transaction landed in, denormalized from the rich row
    -- so a signer-scoped list orders newest-first straight off the index below
    -- without joining back to chain_records just to order. Re-pinned on a reorg
    -- re-inclusion exactly as the rich row's coordinates are.
    block_height   bigint NOT NULL CHECK (block_height >= 0),
    PRIMARY KEY (signer_ed25519, tx_hash)
);

-- A single signer's records, newest-first: the access path the `?signer=` list
-- filter and count both ride. The membership equality on signer_ed25519 derives
-- a selective Index Cond reading only that one key's slice, and the descending
-- block_height serves the feed's newest-first keyset ordering directly.
CREATE INDEX chain_record_signer_signer_idx
    ON cw_core.chain_record_signer (signer_ed25519, block_height DESC);

-- ---------------------------------------------------------------------------
-- cardano_tip: the materialised chain tip, one row per network.
--
-- The indexer is the single owner of the `/tip` HTTP call and writes this row;
-- the confirm loop's Pass A reads it to derive confirmations with zero HTTP
-- (numConfirmations = max(0, tip - block_height + 1)). The upsert uses GREATEST
-- so a behind-the-times observation can never regress a higher tip already
-- known. `tip_epoch` is materialised from the same `/tip` response so the
-- protocol-parameter populate loop learns the current epoch from a pure Postgres
-- read instead of its own `/tip` call every tick; nullable because a tip row
-- written by an older binary carries no epoch until the scan refreshes it.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.cardano_tip (
    network          text PRIMARY KEY,
    tip_block_height bigint NOT NULL CHECK (tip_block_height >= 0),
    tip_observed_at  timestamptz NOT NULL DEFAULT now(),
    tip_epoch        integer CHECK (tip_epoch IS NULL OR tip_epoch >= 0)
);

-- ---------------------------------------------------------------------------
-- indexer_cursor: the durable scan frontier, one row per network.
--
-- `last_processed_block_height` is the SCAN frontier: the highest block whose
-- Label 309 contents the forward scan has already considered, NOT the highest
-- record it persisted. A record sitting at the cursor height re-appears in every
-- subsequent fetch (the gateway returns records strictly above the cursor), so
-- the frontier must move past a scanned-but-empty window or the scan rescans it
-- forever and burns provider quota.
--
-- `last_processed_block_hash` anchors reorg detection: the scan re-fetches the
-- frontier block and compares its hash here. It is NULL after a caught-up jump
-- straight to the tip; the reorg check skips a NULL-hash frontier naturally.
--
-- The stuck-gap columns make a persistent stall observable and recoverable. The
-- scan never advances past a height whose Label 309 record the provider could
-- not hydrate (doing so would permanently skip that record), but a single
-- unhydratable transaction at the frontier would otherwise STALL the whole
-- global feed indefinitely. `stuck_gap_height` is the frontier height the scan
-- has failed to advance past (NULL when making progress);
-- `stuck_gap_first_seen_at` is when the current stall began (so the handler
-- alerts once a stall outlives a short duration rather than on a transient
-- tick); `stuck_gap_tick_count` counts consecutive non-advancing ticks so the
-- handler can escalate to an alternate-provider re-fetch on a threshold.
--
-- `intra_block_done_tx_hashes` lets the scan page THROUGH a single block whose
-- Label 309 transaction count exceeds the per-tick record cap. The cursor
-- advances by block height and the next fetch requests records strictly above
-- it, so a block carrying more label-309 transactions than one window holds
-- would otherwise be unconsumable: the scan could neither anchor inside the
-- block nor advance past it, and the tick would fail forever — a single
-- over-stuffed block (reachable adversarially with a few hundred tiny
-- transactions) would stall the whole global records feed with no recovery.
-- NULL means the block at `last_processed_block_height` is FULLY consumed and
-- the next fetch resumes strictly above it. Non-NULL means that block is
-- PARTIALLY consumed: the listed hashes are the transactions within it the
-- scan has already indexed, pooled, or deliberately skipped, and the next
-- fetch re-reads the block excluding exactly those hashes. Progress through
-- the block is set-growth, not height-growth, so the per-tick cap degrades to
-- a page size and can never wedge the frontier. The set is bounded by the
-- ledger itself (one block holds at most a few hundred label-309
-- transactions), and it is written in the same transaction as the records it
-- accounts for, so a crash can never desynchronise the exclusion set from the
-- index. Reorg safety needs no extra machinery: a partial cursor stores the
-- boundary block's own hash in `last_processed_block_hash`, so the standing
-- per-tick frontier-hash check re-verifies exactly the block being consumed,
-- and a rewind clears this column alongside the records it deletes.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.indexer_cursor (
    network                     text PRIMARY KEY,
    last_processed_block_height bigint NOT NULL DEFAULT 0
                                CHECK (last_processed_block_height >= 0),
    last_processed_block_hash   text,
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    stuck_gap_height            bigint
                                CHECK (stuck_gap_height IS NULL OR stuck_gap_height >= 0),
    stuck_gap_first_seen_at     timestamptz,
    stuck_gap_tick_count        bigint NOT NULL DEFAULT 0
                                CHECK (stuck_gap_tick_count >= 0),
    intra_block_done_tx_hashes  bytea[]
);

-- ---------------------------------------------------------------------------
-- confirmation_pool: the durable below-threshold record pool.
--
-- A Label 309 record the forward scan discovers on chain but below the
-- confirmation threshold is not yet persisted to `chain_records`; it is held
-- here until a later tick re-checks it and either promotes it (now confirmed) or
-- drops it (orphaned by a reorg). Keeping the pool in Postgres rather than
-- process memory makes it restart-safe by construction.
--
-- Every column is derived from the same record bytes the persisted row would
-- carry (`signer_ed25519`, `item_count`, `scheme`, `signer_set`), so a promotion
-- writes identical `chain_records` (and chain_record_signer) rows regardless of
-- which tick promoted it. `signer_set` is the FULL verified-signer set carried
-- through the pool (alongside the scalar primary `signer_ed25519`) so a
-- promotion fans the signer rows out without re-verifying — the single
-- signature-verification pass runs once, when the record is first pooled.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.confirmation_pool (
    -- 32-byte transaction id. The natural key.
    tx_hash        bytea PRIMARY KEY,
    block_height   bigint NOT NULL CHECK (block_height >= 0),
    block_time     timestamptz NOT NULL,
    -- The verbatim Label 309 metadata CBOR, so a re-check promotes the entry
    -- without re-fetching the record from chain.
    metadata_cbor  bytea NOT NULL,
    -- The first record signer's raw 32-byte Ed25519 pubkey (the primary,
    -- projected signer), or NULL when unsigned/unresolvable.
    signer_ed25519 bytea,
    -- Number of content items in the record (>= 0).
    item_count     integer NOT NULL CHECK (item_count >= 0),
    -- Encryption scheme of the first item: 0 open, 1 recipient-sealed,
    -- 2 passphrase.
    scheme         smallint NOT NULL CHECK (scheme IN (0, 1, 2)),
    -- When the scan first saw this record (drives oldest-first eviction when the
    -- pool reaches its cap).
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- The FULL verified-signer set, a bytea[] of raw 32-byte keys, exactly the
    -- values fanned into chain_record_signer on promotion. NOT NULL with a '{}'
    -- default: an unsigned record carries an empty set, never a NULL, so the
    -- promotion path reads one consistent shape.
    signer_set     bytea[] NOT NULL DEFAULT '{}'
);

-- Oldest-first eviction scans this when the pool reaches its size cap.
CREATE INDEX confirmation_pool_first_seen_idx
    ON cw_core.confirmation_pool (first_seen_at);

-- ---------------------------------------------------------------------------
-- chain_provider_cooldown: a restart-survivable rate-limit gate.
--
-- When a chain provider returns 429 the gateway writes a cooldown row (per
-- provider + network) and consults it before any subsequent call, so a sustained
-- rate-limit storm parks the loop instead of burning attempts. The row survives
-- a process restart, so a fresh replica does not immediately re-hammer a
-- provider that was already rate-limiting us.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.chain_provider_cooldown (
    -- The provider key ('koios' | 'blockfrost').
    provider       text NOT NULL,
    network        text NOT NULL,
    -- No call to this provider+network should be made before this instant.
    cooldown_until timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, network)
);

-- ---------------------------------------------------------------------------
-- chain_provider_request_day: per-day chain-provider request accounting.
--
-- Every chain provider this instance talks to enforces a daily request quota,
-- and exhausting one is a silent operational failure: the failover wrapper
-- routes everything to the surviving provider until that one exhausts too and
-- the chain loops park. The egress gate already bounds the request rate locally;
-- this table is the visibility half — it records how many requests were actually
-- issued to (and denied for) each provider per UTC day, so the operator can see
-- quota consumption trending toward a limit before the providers start refusing.
-- One row per (provider, network, day), incremented by the egress gate as each
-- request is admitted or denied. `denied_count` counts requests the LOCAL budget
-- refused — a non-zero value means the backstop fired, itself a signal.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.chain_provider_request_day (
    -- The provider the requests were issued to ('koios' | 'blockfrost').
    provider      text        NOT NULL,
    -- The network the provider was serving ('mainnet' | 'preprod' | 'preview').
    network       text        NOT NULL,
    -- The UTC day the bucket covers.
    day           date        NOT NULL,
    -- Requests admitted by the egress gate and issued to the provider.
    request_count bigint      NOT NULL DEFAULT 0,
    -- Requests the local egress budget refused to issue.
    denied_count  bigint      NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, network, day)
);

-- ---------------------------------------------------------------------------
-- refund_intent: the durable single-refund hook.
--
-- Inserted ON CONFLICT (record_id) DO NOTHING in the SAME transaction as the
-- permanent_failure flip, across every terminal arm. The PK on record_id makes
-- single-refund a by-construction property: no matter how many terminal paths
-- converge on a record, at most one refund intent exists. A matching outbox
-- event ('poe.refund-intent') is emitted in the same transaction; the host's
-- billing hook consumes it downstream. The engine itself never moves money.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.refund_intent (
    record_id  uuid PRIMARY KEY REFERENCES cw_core.poe_record (id),
    -- A stable machine-readable reason ('tx_build_failed', 'gateway_exhausted',
    -- 'byte_budget_exceeded', 'rollback_retries_exhausted', 'mempool_timeout').
    reason     text NOT NULL,
    -- Structured context for the billing hook (original record/account ids,
    -- last-known coordinates, attempt counts).
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);


-- ===========================================================================
-- SECTION 5 — The chain-effect ledger (chain_attempt) and the record↔attempt
-- back-reference.
--
-- chain_attempt and poe_record reference each other: an attempt names the
-- record it serves, and a record names the attempt it currently rides. The
-- record was created above without that FK; it is added here once chain_attempt
-- exists, closing the cycle.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- chain_attempt: the per-action chain-effect ledger.
--
-- Every action that puts bytes on chain (a publish submit, a cancelling
-- replacement, a replenish split) inserts a row here INSIDE the same
-- wallet-locked transaction that fences its UTxO inputs, and BEFORE it
-- broadcasts the transaction. The row carries everything a later path needs
-- without a chain read: the deterministically computed tx id, the exact signed
-- bytes (so a retry re-broadcasts THIS transaction rather than building a fresh
-- one), the spent inputs and produced outputs, the fee and wallet, the action
-- kind and the subject it serves, a lifecycle status the confirm/reorg
-- authority drives, and the replacement linkage that ties an original to its
-- cancelling replacement.
--
-- This is the transactional-outbox discipline specialised to chain effects:
-- recording the spend before it can exist on chain makes a crashed broadcast
-- impossible to lose, and the single-active-broadcaster unique index makes a
-- redelivered job re-broadcast the recorded transaction instead of minting a
-- second one. The confirm authority reconciles the ledger against chain truth:
-- confirming an attempt promotes its inputs/outputs, abandoning a provably-dead
-- attempt restores them.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.chain_attempt (
    -- UUIDv7 attempt id.
    id                 uuid PRIMARY KEY,
    -- What kind of chain action this attempt is.
    kind               text NOT NULL
                       CHECK (kind IN ('publish', 'replacement', 'split')),
    -- The subject this attempt serves. For publish/replacement it is a
    -- poe_record.id; for a split it is NULL (a split serves the wallet named
    -- below). The subject discriminant CHECK pins exactly one shape per kind.
    record_id          uuid REFERENCES cw_core.poe_record (id),
    -- The wallet whose pool funds and tracks this attempt's spend.
    wallet_id          uuid NOT NULL REFERENCES cw_core.operator_wallet (id),
    -- The deterministically computed 32-byte transaction id, known BEFORE
    -- broadcast because the builder computes it. The natural chain key.
    tx_hash            bytea NOT NULL,
    -- The exact signed transaction bytes, recorded before broadcast so a retry
    -- re-broadcasts THIS transaction rather than rebuilding a fresh one. The
    -- bytes are public-on-chain anyway, so storing them carries no secret.
    signed_tx          bytea NOT NULL,
    fee_lovelace       bigint NOT NULL CHECK (fee_lovelace >= 0),
    -- There is deliberately NO invalid_hereafter / TTL column. The transaction
    -- carries no validity interval, so it can land at any later block and a
    -- mempool timeout is a reconcile state, never a refund. Because the
    -- transaction is valid indefinitely, the only proof it can never land (and
    -- thus the only trigger for input restore or refund) is a CONFIRMED
    -- conflicting spend of one of this attempt's inputs, confirmed to the
    -- settlement depth — not an "absent" lookup, not an elapsed horizon, and not
    -- a ledger TTL slot.
    --
    -- The wallet inputs this transaction spends, as a JSON array of
    -- {tx_hash, index, lovelace}. The confirm authority restores these on
    -- abandon and promotes them on confirm.
    spent_inputs       jsonb NOT NULL,
    -- The outputs this transaction produces that the wallet tracks (change for a
    -- publish, the minted band-mid set for a split), as a JSON array of
    -- {index, lovelace}. Promoted on confirm, tombstoned on abandon.
    produced_outputs   jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- The transaction this attempt replaces, set when kind='replacement', NULL
    -- otherwise. Pairs with superseded_by to link an original and its cancelling
    -- replacement so the confirm authority reconciles BOTH for one record.
    replaces_tx_hash   bytea,
    -- The attempt that supersedes THIS one, set on the superseded original when
    -- a replacement is created. Lets the authority walk original -> replacement
    -- and terminalise the loser once either lands. The self-reference is
    -- DEFERRABLE INITIALLY DEFERRED because the atomic handoff supersedes the
    -- original (which points at the replacement) and inserts that replacement
    -- row in the SAME transaction: deferring the check to commit lets the
    -- original reference a replacement recorded later in the transaction, while
    -- still rejecting a dangling reference at commit.
    superseded_by      uuid REFERENCES cw_core.chain_attempt (id)
                       DEFERRABLE INITIALLY DEFERRED,
    -- The status lifecycle the confirm/reorg authority drives:
    --   recorded   -> durable but not yet on the wire
    --   broadcast  -> sent to the node (the active broadcaster for its record)
    --   stuck      -> broadcast, past the alert threshold, awaiting reconcile
    --                 (operator-visible, NOT a refund); still reconcilable
    --   confirmed  -> seen on chain at/above the confirm threshold (terminal)
    --   superseded -> a replacement has taken over the active-broadcaster role;
    --                 STILL reconcilable until provably dead, because the
    --                 original transaction can still land before the replacement
    --   abandoned  -> provably dead: a CONFIRMED conflicting transaction spent
    --                 one of this attempt's inputs and that conflicting spend has
    --                 itself reached the settlement depth, so a shallow reorg of
    --                 the conflicting spend cannot un-prove the death (terminal).
    -- Non-terminal = {recorded, broadcast, stuck, superseded};
    -- terminal = {confirmed, abandoned}.
    status             text NOT NULL DEFAULT 'recorded'
                       CHECK (status IN ('recorded', 'broadcast', 'stuck',
                                         'confirmed', 'abandoned', 'superseded')),
    -- When this attempt's transaction most recently (re-)entered the mempool.
    -- Set on the first broadcast and on every re-broadcast. The reconcile/alert
    -- predicate keys on THIS, never on the record's created_at, and never drives
    -- a refund.
    mempool_entered_at timestamptz,
    -- When the transaction was first observed on chain, set once by the confirm
    -- authority. Gates the two-source reorg decision.
    first_seen_on_chain_at timestamptz,
    -- Observed coordinates once on chain; cleared if the attempt is abandoned.
    block_height       bigint CHECK (block_height IS NULL OR block_height >= 0),
    block_time         timestamptz,
    -- Bounded-backoff retry hint for a confirm/abandon wallet mutation that
    -- yielded because the wallet advisory lock was held. The confirm pass
    -- re-enumerates this attempt every cycle and re-attempts the mutation once
    -- now() >= next_attempt_after, so a yielded mutation is never permanently
    -- skipped. yield_count tracks repeated yields to surface a pathologically
    -- contended wallet as an alert.
    next_attempt_after timestamptz,
    yield_count        integer NOT NULL DEFAULT 0 CHECK (yield_count >= 0),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    -- Exactly one subject discriminant matches the kind: a publish/replacement
    -- names a record, a split names none (it serves only its wallet).
    CONSTRAINT chain_attempt_subject CHECK (
        (kind IN ('publish', 'replacement') AND record_id IS NOT NULL)
     OR (kind = 'split' AND record_id IS NULL)
    )
);

-- At most ONE active-broadcaster attempt per record at a time. This is the
-- durable backstop for the submit generation claim: a second non-replacement
-- submit cannot record a fresh attempt while one is broadcasting for the record.
-- It covers the active-broadcaster states only (recorded/broadcast/stuck) and
-- NOT 'superseded': a cancelling replacement supersedes the original (which
-- stays reconcilable) and itself becomes the single active broadcaster, so
-- exactly one active broadcaster exists across the handoff.
CREATE UNIQUE INDEX chain_attempt_one_active_per_record
    ON cw_core.chain_attempt (record_id)
    WHERE record_id IS NOT NULL
      AND status IN ('recorded', 'broadcast', 'stuck');

-- The chain key is unique per attempt row: the same tx_hash is never recorded
-- twice, so a redelivered record-before-broadcast is an idempotent no-op.
CREATE UNIQUE INDEX chain_attempt_tx_hash_uk
    ON cw_core.chain_attempt (tx_hash);

-- The reconcile/watch set: every non-terminal attempt with no block height yet,
-- oldest mempool entry first. Includes 'superseded' originals: an original
-- whose replacement is now the active broadcaster can still land, so it stays in
-- the enumeration until it is provably dead.
CREATE INDEX chain_attempt_reconcile_idx
    ON cw_core.chain_attempt (mempool_entered_at)
    WHERE status IN ('broadcast', 'stuck', 'superseded')
      AND block_height IS NULL;

-- The on-chain confirm set: any non-terminal-or-confirmed attempt that has a
-- block height, by height. Includes 'superseded' so an original that lands after
-- the handoff is still confirmed and terminalised by the same authority.
CREATE INDEX chain_attempt_onchain_idx
    ON cw_core.chain_attempt (block_height)
    WHERE status IN ('broadcast', 'stuck', 'superseded', 'confirmed')
      AND block_height IS NOT NULL;

-- Replacement linkage walk: find the original a replacement supersedes (and the
-- reverse) without scanning.
CREATE INDEX chain_attempt_superseded_by_idx
    ON cw_core.chain_attempt (superseded_by)
    WHERE superseded_by IS NOT NULL;

-- A split attempt is reconciled by wallet; index live split attempts.
CREATE INDEX chain_attempt_split_idx
    ON cw_core.chain_attempt (wallet_id)
    WHERE kind = 'split'
      AND status IN ('broadcast', 'stuck', 'superseded', 'confirmed');

-- The stranded-attempt recovery scan and the operator's wedged-attempt list
-- both select status='recorded' AND mempool_entered_at IS NULL ordered by
-- created_at: an attempt recorded before broadcast whose broadcast never reached
-- the wire (a provider rate-limit storm, a transport error the node never saw, a
-- crash between record-before-broadcast and the broadcast). A recorded attempt
-- is normally flipped to 'broadcast' within milliseconds, so the indexed set is
-- tiny in steady state and only ever holds genuinely stranded rows. The recovery
-- sweep re-enqueues a submit (the safe idempotent re-broadcast) past a grace; it
-- NEVER refunds or restores inputs on age.
CREATE INDEX chain_attempt_stranded_idx
    ON cw_core.chain_attempt (created_at)
    WHERE status = 'recorded'
      AND mempool_entered_at IS NULL;

-- Close the record↔attempt cycle: the record's current_attempt_id now
-- references the attempt it rides. Defined as a column above (so the rich
-- poe_record shape is complete) and constrained here, once chain_attempt exists.
ALTER TABLE cw_core.poe_record
    ADD CONSTRAINT poe_record_current_attempt_id_fkey
    FOREIGN KEY (current_attempt_id) REFERENCES cw_core.chain_attempt (id);


-- ===========================================================================
-- SECTION 6 — The money journal: the materialised balance, the ledger-kind
-- registry, the append-only balance ledger, and the durable publish quote.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- cw_core.balance: the materialised per-account balance.
--
-- One row per account, holding the running sum of its ledger entries in
-- micro-USD. It is maintained entirely by the `balance_apply` trigger on the
-- ledger insert (below); no code path UPDATEs it directly. A missing row reads
-- as a zero balance, so an account with no ledger activity needs no row.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.balance (
    account_id     uuid PRIMARY KEY REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    balance_micros bigint NOT NULL DEFAULT 0,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- cw_core.ledger_kind_registry: the catalogue of legal ledger-entry kinds.
--
-- A ledger kind must be registered here before an entry of that kind can be
-- inserted. The registry is consulted ONLY at insert time, by the Rust ledger
-- module, which validates the kind exists and STAMPS the entry's
-- `allows_overdraft` from this row. The `balance_apply` trigger never reads this
-- table: it enforces the non-negativity rule purely from the stamped column on
-- the entry, so the trigger has no dependency on registry contents and stays a
-- pure function of the row it fires for.
--
-- The engine seeds its own neutral kinds (publish debit, the two refund credits,
-- and the four storage kinds); a vendor registers its own kinds (top-ups,
-- grants, disputes) by inserting more rows, declaring per kind whether an entry
-- may drive the balance negative.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.ledger_kind_registry (
    kind             text PRIMARY KEY,
    -- Whether an entry of this kind may drive the account balance below zero.
    -- The engine's own kinds are all false (a publish, refund, or storage charge
    -- never overdraws); a vendor may register a kind (a chargeback clawback) that
    -- does. The value is copied onto each entry at insert time.
    allows_overdraft boolean NOT NULL DEFAULT false,
    -- Who registered the kind: 'core' for the engine's seeded kinds, an arbitrary
    -- vendor-chosen tag otherwise. Diagnostic; the registry key is `kind`.
    registered_by    text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- The engine's own neutral kinds. NONE may overdraw: a publish debit and a
-- storage debit are each affordability-gated before insert, a refund/release
-- only ever credits. The three publish/refund kinds and the four storage kinds
-- are one catalogue; the storage ledger reuses the balance-ledger machinery
-- untouched (overdraft stamped at insert, idempotency on (kind, ref), the
-- balance_apply trigger maintaining the materialised balance).
INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) VALUES
    ('poe_publish',          false, 'core'),  -- the publish debit
    ('refund_rollback',      false, 'core'),  -- auto-refund credit (reorg cap)
    ('refund_user',          false, 'core'),  -- operator-issued refund credit
    ('storage_hold',         false, 'core'),  -- reserve user USD before the provider write
    ('storage_hold_release', false, 'core'),  -- release a failed/superseded reservation (credit)
    ('storage_upload',       false, 'core'),  -- final success-gated storage debit
    ('storage_refund',       false, 'core');  -- narrow credit: uncommitted / overcharge / orphan only

-- ---------------------------------------------------------------------------
-- cw_core.balance_ledger: the append-only money journal.
--
-- Every balance change is one immutable row here. Append-only is enforced by
-- triggers that block UPDATE, DELETE, and TRUNCATE (below): the journal can only
-- grow. The materialised `cw_core.balance` is derived from it by the
-- `balance_apply` trigger on insert.
--
-- IDEMPOTENCY. Partial unique indexes make a retried insert a no-op rather than
-- a double charge: a given (kind, ref) lands at most once; a record is refunded
-- at most once ACROSS the two PoE refund kinds; and a storage upload is refunded
-- at most once on its attempt id.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.balance_ledger (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id       uuid NOT NULL REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    kind             text NOT NULL REFERENCES cw_core.ledger_kind_registry (kind),
    -- Signed micro-USD delta. Nonzero by CHECK: a zero-value ledger entry carries
    -- no information and would muddy the journal. A debit is negative, a credit
    -- positive.
    amount_micros    bigint NOT NULL CHECK (amount_micros <> 0),
    -- Idempotency / cross-reference key. For a publish debit and a refund credit
    -- this is the `poe_record` id; for the storage kinds it is the
    -- storage_upload_attempt id. This is what makes a retry converge. NULL for
    -- entries that carry no natural idempotency key.
    ref              text,
    -- The quote a publish debit consumed, stamped for audit replay. NULL for
    -- non-publish entries.
    quote_id         uuid,
    -- Copied from the kind registry at insert time. The `balance_apply` trigger
    -- reads ONLY this column (never the registry) to decide whether a resulting
    -- negative balance is permitted, so the overdraft rule is a property of the
    -- row, fixed at insert, not of mutable registry state.
    allows_overdraft boolean NOT NULL DEFAULT false,
    -- Opaque structured context for the entry (the fee/margin snapshot of a
    -- publish, a vendor's settlement detail). Never interpreted by the engine.
    metadata         jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- The request id that originated the entry, for end-to-end tracing.
    request_id       uuid,
    occurred_at      timestamptz NOT NULL DEFAULT now()
);

-- An account's journal, newest-first: the balance history read path.
CREATE INDEX balance_ledger_account_occurred_idx
    ON cw_core.balance_ledger (account_id, occurred_at DESC);

-- Idempotency: a given (kind, ref) lands at most once.
CREATE UNIQUE INDEX balance_ledger_kind_ref_idx
    ON cw_core.balance_ledger (kind, ref)
    WHERE ref IS NOT NULL;

-- A record is refunded at most once across BOTH PoE refund kinds.
CREATE UNIQUE INDEX balance_ledger_refund_ref_idx
    ON cw_core.balance_ledger (ref)
    WHERE kind IN ('refund_rollback', 'refund_user') AND ref IS NOT NULL;

-- A storage upload is refunded at most once, keyed on the attempt id (a
-- storage_refund_intent references its storage_upload, whose attempt_id is the
-- key the refund debit uses).
CREATE UNIQUE INDEX balance_ledger_storage_refund_ref_idx
    ON cw_core.balance_ledger (ref)
    WHERE kind = 'storage_refund' AND ref IS NOT NULL;

-- ---------------------------------------------------------------------------
-- balance_apply(): maintain the materialised balance on every ledger insert.
--
-- Race-safe upsert by loop-and-catch: UPDATE the balance row first, and if no
-- row existed, INSERT it; a concurrent peer that inserted between our UPDATE and
-- our INSERT raises a unique_violation we catch and loop on, re-running the
-- UPDATE which now finds the peer's row. This converges without an advisory lock
-- because the PK uniqueness is the serialisation point.
--
-- ENFORCEMENT (engine-neutral). After applying the delta the trigger refuses a
-- resulting negative balance UNLESS the entry is itself a debit and its stamped
-- `allows_overdraft` is false. Only a debit can overdraw, so a positive credit
-- is always accepted (it can never drive the balance below zero); a debit that
-- lands a negative balance is refused unless its own stamped flag permits it.
-- The decision reads only the entry row, never the kind registry and never any
-- vendor table: NO hardcoded kind carve-outs, NO arrears mirror. A vendor that
-- wants an overdrawing kind registers it with allows_overdraft=true; a vendor
-- that wants an arrears flag maintains it in its own schema.
-- ---------------------------------------------------------------------------
CREATE FUNCTION cw_core.balance_apply()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    new_balance bigint;
BEGIN
    LOOP
        UPDATE cw_core.balance
           SET balance_micros = balance_micros + NEW.amount_micros,
               updated_at = now()
         WHERE account_id = NEW.account_id
        RETURNING balance_micros INTO new_balance;
        IF FOUND THEN
            EXIT;
        END IF;

        BEGIN
            INSERT INTO cw_core.balance (account_id, balance_micros, updated_at)
            VALUES (NEW.account_id, NEW.amount_micros, now())
            RETURNING balance_micros INTO new_balance;
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            -- A concurrent insert beat us to the row; loop and the UPDATE above
            -- will now find it.
        END;
    END LOOP;

    -- Non-negativity, decided purely from the entry row. Only a debit can
    -- overdraw, so a positive credit is always accepted (it can never drive the
    -- balance below zero); a debit that lands a negative balance is refused unless
    -- its own stamped flag permits the overdraft.
    IF new_balance < 0 AND NEW.amount_micros < 0 AND NOT NEW.allows_overdraft THEN
        RAISE EXCEPTION
            'balance_ledger entry % would overdraw account % (kind %, amount %)',
            NEW.id, NEW.account_id, NEW.kind, NEW.amount_micros
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER balance_ledger_apply
    AFTER INSERT ON cw_core.balance_ledger
    FOR EACH ROW
    EXECUTE FUNCTION cw_core.balance_apply();

-- ---------------------------------------------------------------------------
-- Append-only enforcement: the journal can only grow.
--
-- A single trigger function refuses any UPDATE, DELETE, or TRUNCATE on the
-- ledger, so an immutable journal is a schema property rather than a code
-- convention. The balance is derived from the journal, so mutating a past entry
-- would silently desynchronise it; forbidding mutation removes that whole class
-- of bug.
-- ---------------------------------------------------------------------------
CREATE FUNCTION cw_core.balance_ledger_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cw_core.balance_ledger is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER balance_ledger_no_update
    BEFORE UPDATE ON cw_core.balance_ledger
    FOR EACH ROW
    EXECUTE FUNCTION cw_core.balance_ledger_append_only();

CREATE TRIGGER balance_ledger_no_delete
    BEFORE DELETE ON cw_core.balance_ledger
    FOR EACH ROW
    EXECUTE FUNCTION cw_core.balance_ledger_append_only();

CREATE TRIGGER balance_ledger_no_truncate
    BEFORE TRUNCATE ON cw_core.balance_ledger
    FOR EACH STATEMENT
    EXECUTE FUNCTION cw_core.balance_ledger_append_only();

-- ---------------------------------------------------------------------------
-- cw_core.publish_quote: the durable, replay-safe publish-cost snapshot.
--
-- One row captures the full cost of a publish at quote time and binds it to the
-- record at consume time. It is engine-owned because it stores the
-- engine-computed resource cost (the network fee and the storage bytes) and the
-- derived total in one atomic, idempotent row. The only vendor INPUTS are the
-- markup (`margin_pct`, supplied by a pricing hook) and the FX values (carried
-- verbatim in `fx_snapshot`); the engine persists them but does not source them.
--
-- LIFECYCLE. `status` is pending -> consumed (a publish spent it) or pending ->
-- expired (its TTL lapsed). Consume is a single transaction: lock the quote,
-- lock the balance, check affordability, insert the signed-negative publish
-- debit, flip the quote consumed, and bind `poe_record_id`. The partial unique
-- index on `poe_record_id` makes a record bind to at most one quote.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.publish_quote (
    id                 uuid PRIMARY KEY,
    account_id         uuid NOT NULL REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    issued_at          timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    -- The canonical Label 309 record length the network fee was metered over.
    record_bytes       integer NOT NULL CHECK (record_bytes >= 0),
    -- The total content bytes the storage cost was computed over.
    file_bytes_total   bigint NOT NULL CHECK (file_bytes_total >= 0),
    -- The exact Cardano fee in lovelace the canonical-shape build priced.
    network_lovelace   bigint NOT NULL CHECK (network_lovelace >= 0),
    -- The cost components in micro-USD: network (the lovelace fee converted),
    -- storage (the content bytes priced), and service (the margin applied).
    network_usd_micros bigint NOT NULL CHECK (network_usd_micros >= 0),
    storage_usd_micros bigint NOT NULL CHECK (storage_usd_micros >= 0),
    -- The markup the pricing hook resolved, as a fraction (e.g. 0.2500 = 25%),
    -- and where it came from (diagnostic attribution from the hook).
    margin_pct         numeric(6, 4) NOT NULL CHECK (margin_pct >= 0),
    margin_source      text NOT NULL,
    service_usd_micros bigint NOT NULL CHECK (service_usd_micros >= 0),
    -- The locked total a consume charges: network + storage + service.
    total_usd_micros   bigint NOT NULL CHECK (total_usd_micros >= 0),
    -- The verbatim FX inputs the cost was computed from, retained so the cost is
    -- reproducible from the row alone. Vendor-supplied; engine only persists it.
    fx_snapshot        jsonb NOT NULL,
    status             text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'consumed', 'expired')),
    consumed_at        timestamptz,
    -- The record this quote was consumed for; set at consume. NULL while pending.
    poe_record_id      uuid,
    -- The request id that issued the quote, for tracing.
    request_id         uuid,
    -- The sealed-PoE recipient count (the envelope shape it was priced for) and
    -- the FX snapshot age the wire quote request carried, recorded so the price
    -- stays reproducible from the row alone and the wire response can surface how
    -- fresh the conversion was. Defaulted because the operator-direct quote path
    -- does not supply them.
    recipient_count    integer NOT NULL DEFAULT 0 CHECK (recipient_count >= 0),
    fx_age_seconds     bigint NOT NULL DEFAULT 0 CHECK (fx_age_seconds >= 0)
);

-- An account's quotes, and the expire job's scan over pending rows past TTL.
CREATE INDEX publish_quote_account_idx
    ON cw_core.publish_quote (account_id, issued_at DESC);

CREATE INDEX publish_quote_pending_expiry_idx
    ON cw_core.publish_quote (expires_at)
    WHERE status = 'pending';

-- A record binds to at most one consumed quote.
CREATE UNIQUE INDEX publish_quote_poe_record_idx
    ON cw_core.publish_quote (poe_record_id)
    WHERE poe_record_id IS NOT NULL;


-- ===========================================================================
-- SECTION 7 — The HTTP data-plane substrate: bearer credentials, sliding-window
-- rate-limit buckets, and idempotency replay storage.
--
-- These tables back the middleware the data-plane router runs (authenticate,
-- throttle, replay); the API surface itself is code, not schema. Every secret is
-- stored only as its SHA-256, split into an 8-byte lookup prefix (the index the
-- auth path queries on) and the full 32-byte hash (compared in constant time
-- after the prefix narrows to a candidate), so a leaked database cannot recover
-- a usable credential. The same hashing discipline is shared by the control
-- credential and the access token in the next section.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- cw_core.api_key: the bearer credential a data-plane caller presents.
--
-- A request authenticates with `Authorization: Bearer <secret>`. The
-- human-readable secret PREFIX (the `sk-…` style label a caller sees) is an
-- OPERATOR-CONFIGURED column, not a hardcoded brand string: the engine ships no
-- default prefix, so a deployment chooses its own and the auth path validates a
-- presented secret against the stored prefix rather than a baked-in regex.
--
-- `scopes` is a text array drawn from the scope registry below; an authorize
-- check tests membership. `rate_limit_per_min` is the per-key budget the
-- sliding-window bucket meters against; NULL means "no custom budget" and the
-- limiter applies its fixed default, exactly as a NULL-budget account token
-- does. Revocation is a timestamp, never a row delete, so an audited key's
-- history survives.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.api_key (
    id                 uuid PRIMARY KEY,
    account_id         uuid NOT NULL REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    -- The operator-chosen human-readable secret prefix (e.g. a deployment's
    -- `sk-…` label). Stored, not hardcoded. Diagnostic + display only; the
    -- cryptographic identity is the hash below.
    prefix             text NOT NULL,
    -- The first 8 bytes of SHA-256(secret), the lookup index. Not unique on its
    -- own (an 8-byte prefix can collide); the full hash disambiguates.
    key_lookup         bytea NOT NULL,
    -- The full 32-byte SHA-256(secret), compared in constant time once the
    -- lookup prefix narrows the candidates. Unique: one row per distinct secret.
    key_hash_sha256    bytea NOT NULL UNIQUE,
    -- The scopes this key carries, e.g. {poe:read, poe:create}. Validated
    -- against cw_core.api_scope at insert by the issuing path; an authorize
    -- check tests membership here.
    scopes             text[] NOT NULL DEFAULT '{}',
    -- The per-minute request budget the sliding-window limiter meters against.
    -- NULL = no custom budget (the limiter applies its fixed default); a positive
    -- value overrides it. The CHECK admits only a positive budget; a NULL passes
    -- it by SQL semantics, so the absence of a budget is expressed by NULL.
    rate_limit_per_min integer CHECK (rate_limit_per_min > 0),
    -- Free-text operator label for the key (which integration it belongs to).
    label              text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz,
    -- Revocation marker. NULL while live; the auth path requires it IS NULL.
    revoked_at         timestamptz
);

-- The auth path's hot index: narrow to candidate rows by the 8-byte lookup
-- prefix among live (un-revoked) keys, then constant-time compare the full hash.
CREATE INDEX api_key_lookup_idx
    ON cw_core.api_key (key_lookup)
    WHERE revoked_at IS NULL;

-- An account's keys, for an operator-scoped key listing.
CREATE INDEX api_key_account_idx
    ON cw_core.api_key (account_id);

-- ---------------------------------------------------------------------------
-- cw_core.api_scope: the extensible scope registry.
--
-- A scope must be registered here before a key may carry it. The engine seeds
-- its own core scopes; a vendor registers its own (`inbox:read`, `billing:*`,
-- arbitrary vendor scopes) by inserting more rows, so scopes are NEVER a
-- hardcoded enum in code. `registered_by` is 'core' for the seeded scopes and a
-- vendor tag otherwise, purely diagnostic.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.api_scope (
    scope         text PRIMARY KEY,
    description   text NOT NULL,
    registered_by text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- The core data-plane scopes. A vendor extends the registry with INSERTs; the
-- engine never hardcodes the legal set. The two webhooks scopes gate the
-- account-arm webhook routes (read = list + read a subscription, write = create,
-- patch, delete) and are 'core' because the engine's own routes require them.
INSERT INTO cw_core.api_scope (scope, description, registered_by) VALUES
    ('poe:read',       'Read records and stream PoE events.',                              'core'),
    ('poe:create',     'Quote, publish, and upload content.',                              'core'),
    ('account:read',   'Read the account balance and stream balance events.',             'core'),
    ('billing:read',   'Read billing/invoice state (reserved for a vendor billing plane).', 'core'),
    ('webhooks:read',  'List and read the account''s webhook subscriptions.',             'core'),
    ('webhooks:write', 'Create, update, and delete webhook subscriptions.',               'core');

-- ---------------------------------------------------------------------------
-- cw_core.rate_limit_bucket: a restart-survivable sliding-window record.
--
-- One row per (subject, window-start) the limiter has seen. The limiter meters a
-- sliding 60-second window with a 2x burst allowance: a request is admitted when
-- the weighted count across the current and previous windows is under the
-- budget, and the bucket's `count` is the number of tokens spent in its fixed
-- window. `subject` is the api-key id (live keys) or a hashed client address
-- (anonymous reads), so the same table serves both.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.rate_limit_bucket (
    -- The throttled subject: an api-key id, or a hashed remote address for
    -- anonymous reads. Opaque to the table.
    subject      text NOT NULL,
    -- The fixed 60-second window's start (truncated to the window boundary).
    window_start timestamptz NOT NULL,
    -- Tokens spent in this window.
    count        integer NOT NULL DEFAULT 0 CHECK (count >= 0),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, window_start)
);

-- The maintenance pass prunes buckets whose window has fully lapsed.
CREATE INDEX rate_limit_bucket_window_idx
    ON cw_core.rate_limit_bucket (window_start);

-- ---------------------------------------------------------------------------
-- cw_core.idempotency_keys: byte-for-byte replay storage.
--
-- A mutating request may carry an `Idempotency-Key`. The first time a
-- (account_id, key) pair is seen the handler runs and its committed response is
-- persisted here; a later request with the same pair replays the stored status
-- and body verbatim. A same-key request whose payload hash differs from the
-- stored one is a conflict (409). `request_hash` is SHA-256 over the canonical
-- (method, path, body) so the conflict check is exact. A non-committing outcome
-- (a 402 that charged nothing) is NOT persisted, so a retry after a top-up runs
-- fresh; that is a property of the writing path, not the table.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.idempotency_keys (
    account_id      uuid NOT NULL REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    -- The caller-supplied key, scoped to the account.
    idempotency_key text NOT NULL,
    -- SHA-256 over the canonical (method, path, body); the conflict discriminator.
    request_hash    bytea NOT NULL,
    -- The committed HTTP status to replay.
    response_status smallint NOT NULL,
    -- The committed response body to replay verbatim.
    response_body   bytea NOT NULL,
    -- The committed response content-type to replay alongside the body.
    response_content_type text NOT NULL DEFAULT 'application/json',
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- When the row may be pruned and the key reused.
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (account_id, idempotency_key)
);

-- The maintenance pass prunes expired idempotency rows.
CREATE INDEX idempotency_keys_expiry_idx
    ON cw_core.idempotency_keys (expires_at);


-- ===========================================================================
-- SECTION 8 — The control-plane substrate: operator root credentials,
-- short-lived access tokens, and the append-only administrative audit log.
--
-- The data plane authenticates third-party callers with account-scoped Bearer
-- api keys. The control plane is a SEPARATE, operator-only surface: it
-- provisions accounts, mints keys on their behalf, registers wallets, and
-- adjusts balances. It authenticates with a long-lived OPERATOR ROOT credential
-- (created once out of band by the binary's bootstrap subcommand, the single
-- bearer that may mint operator tokens) and short-lived ACCESS TOKENS it mints.
-- Every control-plane mutation appends one row to cw_core.admin_audit.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- cw_core.control_credential: the operator root bearer.
--
-- The same never-store-the-secret discipline as cw_core.api_key. `kind` is
-- constrained to the single root kind today; it is a column rather than an
-- implied invariant so a later credential class (a scoped service credential) is
-- an additive value, not a schema change. Revocation is a timestamp, never a row
-- delete, so a rotated credential's history survives.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.control_credential (
    id            uuid PRIMARY KEY,
    operator_id   uuid NOT NULL REFERENCES cw_core.operator (id),
    -- The credential class. Only `operator_root` exists today; constrained so a
    -- new class is a reviewed, additive change.
    kind          text NOT NULL DEFAULT 'operator_root'
                  CHECK (kind IN ('operator_root')),
    -- The first 8 bytes of SHA-256(secret), the lookup index. Not unique on its
    -- own (an 8-byte prefix can collide); the full hash disambiguates.
    secret_lookup bytea NOT NULL,
    -- The full 32-byte SHA-256(secret), compared in constant time once the
    -- lookup prefix narrows the candidates. Unique: one row per distinct secret.
    secret_hash   bytea NOT NULL UNIQUE,
    -- Free-text operator label (which laptop / vault the root lives in).
    label         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- Revocation marker. NULL while live; the auth path requires it IS NULL.
    revoked_at    timestamptz
);

-- The auth path's hot index: narrow to live (un-revoked) credentials by the
-- 8-byte lookup prefix, then constant-time compare the full hash.
CREATE INDEX control_credential_lookup_idx
    ON cw_core.control_credential (secret_lookup)
    WHERE revoked_at IS NULL;

-- An operator's credentials, for an operator-scoped credential listing.
CREATE INDEX control_credential_operator_idx
    ON cw_core.control_credential (operator_id);

-- ---------------------------------------------------------------------------
-- cw_core.access_token: a short-lived minted bearer.
--
-- The control plane mints these; they expire (a config TTL: shorter for an
-- account token, longer for an operator token). Two shapes share the table:
--   - account_id IS NULL     -> an OPERATOR token: authorizes the operator
--     control surface (create account, register wallet, adjust balance, read
--     audit).
--   - account_id IS NOT NULL -> an ACCOUNT-scoped token: authorizes the data
--     plane AS that account, carrying the same scopes an api key would. This is
--     the dogfood bridge, with no privileged backdoor.
--
-- `rate_limit_per_min` lets the minting call carry a custom per-token budget the
-- limiter honours; NULL applies the fixed account-token fallback.
--
-- Tokens carry the same revocation discipline as every other credential class:
-- a timestamp, never a row delete, so a leaked token has a kill switch before
-- its TTL lapses while a revoked token's history survives. `minted_by` is an
-- honest lineage pointer the auth path walks on every resolve — it requires
-- `revoked_at IS NULL` on the token's own row AND on every ancestor in the
-- mint chain, so revoking a credential transitively invalidates everything
-- minted under it.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.access_token (
    id           uuid PRIMARY KEY,
    operator_id  uuid NOT NULL REFERENCES cw_core.operator (id),
    -- The account a token is scoped to, or NULL for an operator token. A non-NULL
    -- value FK-references the stable account anchor (RESTRICT, like every other
    -- account reference, so a token never keeps a deleted account hard-deletable).
    account_id   uuid REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    -- The scopes an account-scoped token carries (the data-plane scopes it may
    -- exercise). Empty for an operator token (its authority is the operator
    -- surface, not a data-plane scope set).
    scopes       text[] NOT NULL DEFAULT '{}',
    -- The first 8 bytes of SHA-256(secret), the lookup index.
    token_lookup bytea NOT NULL,
    -- The full 32-byte SHA-256(secret), compared in constant time. Unique.
    token_hash   bytea NOT NULL UNIQUE,
    -- When the token stops authenticating. The auth path requires now() < this.
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- The row id of the credential that minted this token: a
    -- cw_core.control_credential root, another cw_core.access_token, or a
    -- cw_core.api_key acting self-service. This is the lineage the auth path
    -- walks on every resolve, so a revoked ancestor invalidates this token
    -- too; a descendant can still see its ancestor's revocation because
    -- revocation never deletes a row. NULL only when no credential lineage
    -- exists to record.
    minted_by    uuid,
    -- An optional per-token request budget. NULL = no custom budget: the
    -- data-plane limiter applies its fixed account-token fallback. A positive
    -- value overrides that fallback for the token. The CHECK admits only a
    -- positive budget; the absence of a budget is expressed by NULL, not zero.
    rate_limit_per_min integer
                 CHECK (rate_limit_per_min IS NULL OR rate_limit_per_min > 0),
    -- Revocation marker. NULL while live; the auth path requires it IS NULL,
    -- both here and on every ancestor in the mint lineage.
    revoked_at   timestamptz
);

-- The auth path's hot index: narrow to candidate tokens by the 8-byte lookup
-- prefix, then constant-time compare the full hash. The auth query also filters
-- `expires_at > now()`, but the predicate cannot live in the index (a partial
-- index predicate must be IMMUTABLE, and `now()` is not), so the index is on the
-- lookup column alone; the expiry filter is applied at query time.
CREATE INDEX access_token_lookup_idx
    ON cw_core.access_token (token_lookup);

-- An account's tokens, for an account-scoped token listing.
CREATE INDEX access_token_account_idx
    ON cw_core.access_token (account_id)
    WHERE account_id IS NOT NULL;

-- The expiry-prune scan over lapsed tokens.
CREATE INDEX access_token_expiry_idx
    ON cw_core.access_token (expires_at);

-- ---------------------------------------------------------------------------
-- cw_core.admin_audit: the append-only administrative journal.
--
-- One immutable row per control-plane mutation. Append-only is enforced by
-- triggers that block UPDATE, DELETE, and TRUNCATE (below), the same discipline
-- the balance ledger uses. The row records the actor (an operator, an account
-- acting on itself, or the system), the action verb, the target it touched, the
-- before/after state as JSON, and the request id that originated the change.
-- `prev_state` / `new_state` are opaque structured snapshots the engine never
-- interprets; they exist so an operator can read exactly what a mutation changed.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.admin_audit (
    id          uuid PRIMARY KEY,
    -- Who acted: an operator (a control-plane mutation), an account (a self-serve
    -- key action), or the system (an automated transition).
    actor_kind  text NOT NULL CHECK (actor_kind IN ('operator', 'account', 'system')),
    -- The acting principal's id, when there is one: the operator id for an
    -- operator action, the account id for an account action, NULL for a system
    -- action. Free of an FK so a deleted operator/account never blocks an insert.
    actor_id    uuid,
    -- The action verb, a stable lowercase token (e.g. 'account.create',
    -- 'key.revoke', 'wallet.drain', 'ledger.adjust'). Diagnostic, not constrained
    -- to an enum so a new action is an additive code change, not a schema change.
    action      text NOT NULL,
    -- The kind of thing acted on ('account', 'api_key', 'operator_wallet',
    -- 'ledger', 'access_token') and its id, as text so any id shape fits.
    target_type text NOT NULL,
    target_id   text NOT NULL,
    -- The before/after snapshots of the mutated state. NULL prev for a create,
    -- NULL new for nothing-removed; both opaque to the engine.
    prev_state  jsonb,
    new_state   jsonb,
    -- The request id that originated the mutation, for end-to-end correlation.
    request_id  uuid,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

-- The audit read path: newest-first, filterable by actor, action, and target.
CREATE INDEX admin_audit_occurred_idx
    ON cw_core.admin_audit (occurred_at DESC);

CREATE INDEX admin_audit_target_idx
    ON cw_core.admin_audit (target_type, target_id, occurred_at DESC);

CREATE INDEX admin_audit_actor_idx
    ON cw_core.admin_audit (actor_kind, actor_id, occurred_at DESC);

-- Append-only enforcement: the audit journal can only grow. An administrative
-- record that could be edited after the fact would be worthless as an audit
-- trail; forbidding mutation removes that whole class of tampering.
CREATE FUNCTION cw_core.admin_audit_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cw_core.admin_audit is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER admin_audit_no_update
    BEFORE UPDATE ON cw_core.admin_audit
    FOR EACH ROW
    EXECUTE FUNCTION cw_core.admin_audit_append_only();

CREATE TRIGGER admin_audit_no_delete
    BEFORE DELETE ON cw_core.admin_audit
    FOR EACH ROW
    EXECUTE FUNCTION cw_core.admin_audit_append_only();

CREATE TRIGGER admin_audit_no_truncate
    BEFORE TRUNCATE ON cw_core.admin_audit
    FOR EACH STATEMENT
    EXECUTE FUNCTION cw_core.admin_audit_append_only();


-- ===========================================================================
-- SECTION 9 — Spend & storage authority, the winc credit ledger, and the
-- durable storage-upload pipeline.
--
-- Two authority relations sit side by side, deliberately the same shape so a
-- reader sees one pattern twice: wallet_grant decides who may SPEND a wallet,
-- and storage_grant decides who may DRAW a storage funding source's credit. Both
-- are relations separate from ownership/identity; both entitle a principal at
-- service / operator / account scope; both are live while revoked_at IS NULL and
-- gate NEW picks only (in-flight settlement keys on the wallet/source id and is
-- unaffected).
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- wallet_grant: wallet spend authority, separate from wallet identity.
--
-- A wallet is a global on-chain identity registered and administered by one
-- operator (its registrar). Registration does NOT confer a spend scope on anyone
-- else: who may spend is decided entirely by the live grants here (plus the
-- always-entitled registrar, enforced in code). A grant entitles a principal at
-- one of three scopes:
--   - service  : every operator/account on the instance may spend it (the
--                single-tenant default).
--   - operator : a named operator may spend it (a registrar sharing its wallet).
--   - account  : a named account may spend it (per-account wallets; the scope
--                turns on additively, schema + index already present).
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.wallet_grant (
    id          uuid PRIMARY KEY,
    wallet_id   uuid NOT NULL REFERENCES cw_core.operator_wallet (id) ON DELETE CASCADE,
    scope_kind  text NOT NULL CHECK (scope_kind IN ('service', 'operator', 'account')),
    -- Set iff scope_kind = 'operator'.
    operator_id uuid REFERENCES cw_core.operator (id) ON DELETE CASCADE,
    -- Set iff scope_kind = 'account'.
    account_id  uuid REFERENCES cw_api.account (id) ON DELETE CASCADE,
    -- The operator that issued the grant (audit handle); NULL for a system mint.
    granted_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    -- Exactly the scope's own subject column is set, the other NULL. A 'service'
    -- grant names neither subject (it entitles everyone), so the schema cannot
    -- hold a grant whose scope and subject columns disagree.
    CHECK (
        (scope_kind = 'service'  AND operator_id IS NULL     AND account_id IS NULL) OR
        (scope_kind = 'operator' AND operator_id IS NOT NULL AND account_id IS NULL) OR
        (scope_kind = 'account'  AND account_id  IS NOT NULL AND operator_id IS NULL)
    )
);

-- At most one LIVE grant of each scope subject per wallet, so re-issuing a grant
-- is an idempotent no-op rather than a duplicate the spend check would
-- double-count, and a wallet never carries two contradictory live service grants.
CREATE UNIQUE INDEX wallet_grant_service_uniq ON cw_core.wallet_grant (wallet_id)
    WHERE scope_kind = 'service' AND revoked_at IS NULL;
CREATE UNIQUE INDEX wallet_grant_operator_uniq ON cw_core.wallet_grant (wallet_id, operator_id)
    WHERE scope_kind = 'operator' AND revoked_at IS NULL;
CREATE UNIQUE INDEX wallet_grant_account_uniq ON cw_core.wallet_grant (wallet_id, account_id)
    WHERE scope_kind = 'account' AND revoked_at IS NULL;

-- Hot paths: the spend check resolves the live grants for one wallet, and the
-- scheduler join finds the wallets a given operator (or any operator, via a
-- service grant) is entitled to. Each partial index serves one lookup and stays
-- small by excluding revoked rows.
CREATE INDEX wallet_grant_wallet_idx ON cw_core.wallet_grant (wallet_id)
    WHERE revoked_at IS NULL;
CREATE INDEX wallet_grant_operator_idx ON cw_core.wallet_grant (operator_id)
    WHERE revoked_at IS NULL AND scope_kind = 'operator';
CREATE INDEX wallet_grant_account_idx ON cw_core.wallet_grant (account_id)
    WHERE revoked_at IS NULL AND scope_kind = 'account';

-- ---------------------------------------------------------------------------
-- storage_funding_source: the credit identity (mirrors operator_wallet).
--
-- One Arweave key + the winc/credit balance attached to that key's Arweave
-- address at a storage provider (Turbo by default). A funding source is OWNED by
-- exactly one operator: a winc balance is a private prepaid balance the operator
-- funds out-of-band through the provider's own rails, not a public on-chain
-- identity. `owner_operator_id` is the owner (always entitled to draw, like a
-- wallet registrar); who else may draw is decided by storage_grant.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_funding_source (
    id                uuid PRIMARY KEY,
    owner_operator_id uuid NOT NULL REFERENCES cw_core.operator (id),
    label             text NOT NULL,
    backend           text NOT NULL CHECK (backend IN ('turbo', 'direct-arweave', 'arlocal')),
    arweave_address   text NOT NULL,
    key_ref           text NOT NULL,
    status            text NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'draining', 'retired')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    retired_at        timestamptz,
    -- Integrity guard so one credit pool maps to one row.
    UNIQUE (backend, arweave_address),
    -- The composite key the storage_grant composite FK references. It lets a
    -- grant prove, in the database, that its denormalized `backend` equals this
    -- source's backend. `backend` is immutable after creation (no UPDATE path
    -- exposes it), so the referenced key never changes.
    UNIQUE (id, backend)
);

CREATE INDEX storage_funding_source_owner_idx
    ON cw_core.storage_funding_source (owner_operator_id)
    WHERE status = 'active';

-- At most one ACTIVE source per backend may carry a live service grant; the
-- service-selection guard is anchored here plus the grant index below.
CREATE INDEX storage_funding_source_backend_active_idx
    ON cw_core.storage_funding_source (backend)
    WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- storage_grant: the charge authority (twin of wallet_grant).
--
-- Who may DRAW storage charges from a funding source, as a relation separate
-- from ownership. The scope arms mirror wallet_grant exactly.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_grant (
    id                uuid PRIMARY KEY,
    funding_source_id uuid NOT NULL,
    -- Denormalized from the source so the per-(backend,subject) uniqueness guard
    -- can be a single-table partial unique index. NOT merely engine-synced: the
    -- composite FK below proves, in the database, that this value equals the
    -- referenced source's backend, so a grant whose backend disagrees with its
    -- source is unrepresentable.
    backend           text NOT NULL CHECK (backend IN ('turbo', 'direct-arweave', 'arlocal')),
    scope_kind        text NOT NULL CHECK (scope_kind IN ('service', 'operator', 'account')),
    operator_id       uuid REFERENCES cw_core.operator (id) ON DELETE CASCADE,
    account_id        uuid REFERENCES cw_api.account (id) ON DELETE CASCADE,
    -- The operator that issued the grant (audit handle); NULL for a system mint.
    granted_by        uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    revoked_at        timestamptz,
    -- Composite FK: ties the denormalized backend to the source it draws. The
    -- source carries UNIQUE(id, backend); a grant can only reference an
    -- (id, backend) pair that exists, so storage_grant.backend = source.backend
    -- is a structural invariant. ON UPDATE RESTRICT because the source backend is
    -- immutable; ON DELETE CASCADE mirrors the single-column wallet_grant FK.
    FOREIGN KEY (funding_source_id, backend)
        REFERENCES cw_core.storage_funding_source (id, backend)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    -- Exactly the scope's own subject column is set, the other NULL.
    CHECK (
        (scope_kind = 'service'  AND operator_id IS NULL     AND account_id IS NULL) OR
        (scope_kind = 'operator' AND operator_id IS NOT NULL AND account_id IS NULL) OR
        (scope_kind = 'account'  AND account_id  IS NOT NULL AND operator_id IS NULL)
    )
);

-- Structural cardinality guard: uniqueness is per (backend, subject), NOT per
-- (source, subject). Storage selection is single-source (there is no
-- least-loaded scheduler across many sources, unlike wallets), so "two live
-- service sources for one backend" and "one subject draws two sources at the
-- same scope for one backend" must be unrepresentable as live state, leaving
-- "the" drawing source always unambiguous.
CREATE UNIQUE INDEX storage_grant_service_per_backend_uniq
    ON cw_core.storage_grant (backend)
    WHERE scope_kind = 'service' AND revoked_at IS NULL;
CREATE UNIQUE INDEX storage_grant_operator_per_backend_uniq
    ON cw_core.storage_grant (backend, operator_id)
    WHERE scope_kind = 'operator' AND revoked_at IS NULL;
CREATE UNIQUE INDEX storage_grant_account_per_backend_uniq
    ON cw_core.storage_grant (backend, account_id)
    WHERE scope_kind = 'account' AND revoked_at IS NULL;

-- Hot-path partial indexes for the charge-time selection joins.
CREATE INDEX storage_grant_source_idx   ON cw_core.storage_grant (funding_source_id) WHERE revoked_at IS NULL;
CREATE INDEX storage_grant_operator_idx ON cw_core.storage_grant (operator_id)
    WHERE revoked_at IS NULL AND scope_kind = 'operator';
CREATE INDEX storage_grant_account_idx  ON cw_core.storage_grant (account_id)
    WHERE revoked_at IS NULL AND scope_kind = 'account';

-- ---------------------------------------------------------------------------
-- storage_credit_ledger + storage_credit: the operator's append-only winc
-- ledger and its materialized balance (the balance_ledger / balance analogue).
--
-- winc is a REMOTE prepaid balance the gateway can neither buy nor convert. A
-- 'charge' (negative) is appended in the upload reserve transaction recording
-- believed consumption; a 'reconcile' (signed) is appended by the
-- credit-reconcile cron after reading the AUTHORITATIVE live balance and
-- correcting drift; a 'refund' (positive) records a rare provider-side reversal;
-- a 'topup' (positive) journals a landed AR -> winc top-up into the believed
-- balance, appended in the same transaction that marks the storage_topup row
-- credited, so the believed balance absorbs the credit before the drift
-- comparison and the storage.credit.drift alert keeps meaning "the live balance
-- moved in a way the gateway cannot account for".
-- affords reads the materialized balance, never the provider, so the request
-- path makes zero provider calls. This is a DISTINCT ledger from the user's USD
-- balance_ledger: the two never share a row, a kind, or a balance.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_credit_ledger (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    funding_source_id uuid NOT NULL REFERENCES cw_core.storage_funding_source (id) ON DELETE RESTRICT,
    kind              text NOT NULL CHECK (kind IN ('charge', 'reconcile', 'refund', 'topup')),
    -- winc is an integer winston-credit count that can exceed bigint; never used
    -- in float math. Nonzero by CHECK so a journal row always carries information.
    winc_delta        numeric(40, 0) NOT NULL CHECK (winc_delta <> 0),
    -- Idempotency / cross-reference key. For 'charge' this is the
    -- storage_upload_attempt id (the same key the USD storage entries use, since
    -- the winc charge is appended in the reserve transaction BEFORE any
    -- storage_upload row exists); for 'reconcile' the reconcile tick id; for
    -- 'refund' the attempt id; for 'topup' the storage_topup id. The uniqueness
    -- index INCLUDES funding_source_id so two sources reconciled in the same
    -- tick never collide.
    ref               text,
    occurred_at       timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX storage_credit_ledger_source_kind_ref_idx
    ON cw_core.storage_credit_ledger (funding_source_id, kind, ref)
    WHERE ref IS NOT NULL;

-- Materialized winc balance per source, maintained by an insert trigger (the
-- storage_credit_ledger analogue of balance_apply). Missing row = unknown,
-- treated as unfunded by affords until the first reconcile stamps it.
CREATE TABLE cw_core.storage_credit (
    funding_source_id    uuid PRIMARY KEY REFERENCES cw_core.storage_funding_source (id) ON DELETE RESTRICT,
    winc_balance         numeric(40, 0) NOT NULL DEFAULT 0,
    fundable_bytes       bigint,                 -- provider-reported, when available
    last_reconciled_winc numeric(40, 0),
    last_reconciled_at   timestamptz,
    last_error           text,                   -- set when a refresh attempt failed (stale visibility)
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- storage_credit_apply(): maintain the materialized winc balance on every
-- journal insert. The storage_credit_ledger analogue of balance_apply: race-safe
-- upsert by UPDATE-then-INSERT-on-miss, the PK uniqueness the serialization
-- point. A 'reconcile' row additionally stamps the last-reconciled diagnostics.
-- winc is a remote prepaid balance the gateway can drive below zero in its BELIEF
-- (a charge raced ahead of a reconcile); unlike the USD ledger there is no
-- non-negativity gate here, because the reconcile corrects drift and affords
-- enforces the safety floor.
CREATE FUNCTION cw_core.storage_credit_apply()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    LOOP
        UPDATE cw_core.storage_credit
           SET winc_balance = winc_balance + NEW.winc_delta,
               last_reconciled_winc = CASE WHEN NEW.kind = 'reconcile'
                   THEN winc_balance + NEW.winc_delta ELSE last_reconciled_winc END,
               last_reconciled_at = CASE WHEN NEW.kind = 'reconcile'
                   THEN now() ELSE last_reconciled_at END,
               updated_at = now()
         WHERE funding_source_id = NEW.funding_source_id;
        IF FOUND THEN
            EXIT;
        END IF;
        BEGIN
            INSERT INTO cw_core.storage_credit (funding_source_id, winc_balance)
            VALUES (NEW.funding_source_id, NEW.winc_delta);
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            -- A concurrent insert beat us to the row; loop and the UPDATE finds it.
        END;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER storage_credit_ledger_apply
    AFTER INSERT ON cw_core.storage_credit_ledger
    FOR EACH ROW EXECUTE FUNCTION cw_core.storage_credit_apply();

-- Append-only: the winc journal can only grow (same discipline as balance_ledger).
CREATE FUNCTION cw_core.storage_credit_ledger_append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'cw_core.storage_credit_ledger is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;
CREATE TRIGGER storage_credit_ledger_no_update
    BEFORE UPDATE ON cw_core.storage_credit_ledger
    FOR EACH ROW EXECUTE FUNCTION cw_core.storage_credit_ledger_append_only();
CREATE TRIGGER storage_credit_ledger_no_delete
    BEFORE DELETE ON cw_core.storage_credit_ledger
    FOR EACH ROW EXECUTE FUNCTION cw_core.storage_credit_ledger_append_only();
CREATE TRIGGER storage_credit_ledger_no_truncate
    BEFORE TRUNCATE ON cw_core.storage_credit_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION cw_core.storage_credit_ledger_append_only();

-- ---------------------------------------------------------------------------
-- storage_upload_attempt: the durable pre-upload reservation + crash-recovery
-- vehicle.
--
-- A row is written, with a 'storage_hold' ledger entry that reserves the user's
-- USD, BEFORE the provider POST, so the operator never pays the provider for
-- bytes the user's balance cannot cover, and a crash after the provider 2xx is
-- recoverable. The route signs the ANS-104 data item ONCE and persists its id +
-- the small signed ENVELOPE here BEFORE the POST: the Arweave signature is
-- randomized (RSA-PSS), so a re-sign would change the id (id = SHA-256(sig)).
-- The content payload is NEVER stored here, it stays on a durable staged file
-- named by `staged_path`. A retry or the reconcile sweep rebuilds the IDENTICAL
-- serialized data item from the persisted envelope plus the staged content.
--
--   reserved  : hold placed, provider write may or may not have happened
--   committed : provider accepted + receipt + final debit landed
--   released  : provider write never confirmed; hold refunded, no charge
--
-- Every transition out of 'reserved' is a compare-and-set (UPDATE ... WHERE
-- state='reserved' RETURNING), so the live handler and the reconcile sweep cannot
-- both settle one attempt.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_upload_attempt (
    id                  uuid PRIMARY KEY,
    account_id          uuid NOT NULL REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    operator_id         uuid NOT NULL REFERENCES cw_core.operator (id),
    funding_source_id   uuid NOT NULL REFERENCES cw_core.storage_funding_source (id) ON DELETE RESTRICT,
    backend             text NOT NULL CHECK (backend IN ('turbo', 'direct-arweave', 'arlocal')),
    sha256              bytea NOT NULL CHECK (octet_length(sha256) = 32),
    bytes               bigint NOT NULL CHECK (bytes >= 0),
    chargeable_bytes    bigint NOT NULL CHECK (chargeable_bytes >= 0),
    charged_usd_micros  bigint NOT NULL CHECK (charged_usd_micros >= 0),
    estimated_winc      numeric(40, 0) NOT NULL CHECK (estimated_winc >= 0),
    -- The data-item id (SHA-256 of the signature), stamped from the one signing.
    data_item_id        text NOT NULL,
    -- The signed ENVELOPE: bounded, content-independent. With the owner (the
    -- funding key the `key_ref` names), the staged content, and these three
    -- fields, `serialize` rebuilds the byte-identical data item; nothing here
    -- scales with content size. Nulled when the attempt leaves 'reserved'. The
    -- octet-length CHECKs keep each field within the ANS-104 bound (RSA-4096
    -- signature = 512 bytes, anchor = 32, tag block = 4096), so a multi-GB upload
    -- puts nothing content-sized in Postgres.
    data_item_signature bytea CHECK (data_item_signature IS NULL
                                     OR octet_length(data_item_signature) = 512),  -- RSA-4096
    data_item_anchor    bytea CHECK (data_item_anchor IS NULL
                                     OR octet_length(data_item_anchor) = 32),
    data_item_tag_bytes bytea CHECK (data_item_tag_bytes IS NULL
                                     OR octet_length(data_item_tag_bytes) <= 4096),  -- MAX_TAG_BYTES
    -- The path to the DURABLE staged content file (promoted off the tmpfs
    -- TempPath so it survives a crash). The content payload itself is NEVER a
    -- column. Nulled and the file deleted when the attempt leaves 'reserved'.
    staged_path         text,
    -- External-POST claim-lease. Exactly one contender (the live handler, an
    -- attached retry, or a sweep worker) may hold this lease at a time; only the
    -- holder may POST/re-POST the data item. The settlement CAS on `state`
    -- serializes the DATABASE transition; this lease serializes the EXTERNAL side
    -- effect. NULL token = unclaimed; an expired `upload_claim_expires_at` means
    -- the prior owner died mid-POST and the window is reclaimable.
    upload_claim_token       uuid,
    upload_claim_expires_at  timestamptz,
    state               text NOT NULL DEFAULT 'reserved'
                        CHECK (state IN ('reserved', 'committed', 'released')),
    -- The terminal cause a released attempt carries, so the poll route can report
    -- WHY an upload failed by reading the row alone:
    --   provider_rejected                 : the upload reached the provider and
    --                                       was definitively refused; the client
    --                                       may retry.
    --   unrecoverable_staged_content_lost : the crash-recovery sweep found the
    --                                       provider does not hold the data item
    --                                       AND the durable staged content did not
    --                                       survive; the client MUST re-upload.
    -- Set in the same compare-and-set transaction that flips to 'released'; NULL
    -- while 'reserved' or 'committed'.
    created_at          timestamptz NOT NULL DEFAULT now(),
    settled_at          timestamptz,
    -- The terminal cause a released attempt carries (NULL while 'reserved' or
    -- 'committed'): provider_rejected (definitively refused; client may retry) or
    -- unrecoverable_staged_content_lost (the crash-recovery sweep found neither
    -- the provider copy nor the durable staged content; client MUST re-upload).
    -- Bound to the state machine by the CHECK below.
    release_reason      text
                        CHECK (release_reason IS NULL
                               OR release_reason IN ('provider_rejected', 'unrecoverable_staged_content_lost')),
    -- The USD actually debited when the attempt settled, so the poll route can
    -- report what the user was REALLY charged rather than the reserve-time
    -- estimate. A fresh committed receipt debits the held amount; a committed
    -- attempt that deduped against an existing receipt debits 0; a released
    -- attempt debits 0. Stamped in the same CAS that leaves 'reserved'; NULL while
    -- 'reserved' and NON-NULL once settled.
    settled_charge_usd_micros bigint
                        CHECK (settled_charge_usd_micros IS NULL OR settled_charge_usd_micros >= 0),
    -- The reason is set exactly when the attempt is released, binding the column
    -- to the state machine so a future writer cannot leave a released attempt with
    -- no cause or stamp a reason on a still-reserved one.
    CONSTRAINT storage_upload_attempt_release_reason_state CHECK (
        (state = 'released' AND release_reason IS NOT NULL) OR
        (state <> 'released' AND release_reason IS NULL)
    ),
    -- The realized debit is NULL while 'reserved' (no settlement has run) and
    -- NON-NULL once settled, so a settled attempt always carries a realized
    -- amount and a reserved one never does.
    CONSTRAINT storage_upload_attempt_settled_charge_state CHECK (
        (state = 'reserved' AND settled_charge_usd_micros IS NULL) OR
        (state <> 'reserved' AND settled_charge_usd_micros IS NOT NULL)
    )
);

-- At-most-one-live-attempt guard. A logical upload is identified by
-- (account_id, backend, sha256): the content-dedup identity extended with the
-- backend it draws. This partial unique makes a second LIVE attempt for the same
-- logical upload unrepresentable, so a live client retry cannot mint a second
-- hold, a second signature, and a second charge before the first receipt commits.
-- Once the attempt leaves 'reserved' the slot frees, and the committed dedup is
-- the storage_upload (account_id, backend, sha256) unique, the same identity.
CREATE UNIQUE INDEX storage_upload_attempt_live_uniq
    ON cw_core.storage_upload_attempt (account_id, backend, sha256)
    WHERE state = 'reserved';

CREATE INDEX storage_upload_attempt_reserved_idx
    ON cw_core.storage_upload_attempt (created_at)
    WHERE state = 'reserved';
CREATE INDEX storage_upload_attempt_source_idx
    ON cw_core.storage_upload_attempt (funding_source_id);

-- ---------------------------------------------------------------------------
-- storage_upload: the storage-backend receipt ledger.
--
-- One row per accepted upload to a storage backend (Turbo, direct Arweave, or
-- the dev ArLocal): "a row exists iff the backend returned a confirmed receipt"
-- (uri / data_item_id / backend stay NOT NULL). The row records the content
-- identity (sha256, bytes), the resulting addressable URI and data-item id, the
-- raw provider receipt (retained verbatim), the bundling parent once known, and
-- the billing/ownership link back to the attempt that paid for the bytes.
--
-- Dedup is by content hash per account AND backend: re-uploading identical bytes
-- to the SAME backend converges on the existing receipt rather than paying the
-- provider twice, while the SAME bytes on a DIFFERENT backend is a distinct
-- artifact with its own receipt and charge. The committed dedup key matches the
-- in-flight attempt dedup key (account_id, backend, sha256), so a charge can
-- never land without a receipt.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_upload (
    id            uuid PRIMARY KEY,
    account_id    uuid REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    -- The SHA-256 of the stored bytes (the content identity).
    sha256        bytea NOT NULL,
    -- The number of stored bytes.
    bytes         bigint NOT NULL CHECK (bytes >= 0),
    -- The addressable URI the upload resolves at (e.g. ar://<data-item-id>).
    uri           text NOT NULL,
    -- The ANS-104 data-item id (the bundled item's address).
    data_item_id  text NOT NULL,
    -- The verbatim provider response, retained for reconciliation.
    raw_receipt   jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- The top-level Arweave transaction that bundled this item, once known.
    root_tx_id    text,
    -- Which backend produced the receipt ('turbo' | 'direct-arweave' | 'arlocal').
    backend       text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- The attempt that reserved + paid for these bytes (1:1 with the committed
    -- attempt). The storage LEDGER ref is this attempt id; the
    -- storage_refund_intent table separately keys on this receipt row's id.
    attempt_id        uuid REFERENCES cw_core.storage_upload_attempt (id) ON DELETE RESTRICT,
    funding_source_id uuid REFERENCES cw_core.storage_funding_source (id) ON DELETE RESTRICT,
    -- Owning operator, denormalized so the per-operator visibility query does not
    -- re-join through the account on every row.
    charged_operator_id uuid REFERENCES cw_core.operator (id),
    chargeable_bytes   bigint NOT NULL DEFAULT 0 CHECK (chargeable_bytes >= 0),
    -- The user-facing storage debit actually applied (0 for a free-window upload).
    charged_usd_micros bigint NOT NULL DEFAULT 0 CHECK (charged_usd_micros >= 0)
);

-- Content-hash dedup per account and backend: an account re-uploading identical
-- bytes to the same backend lands on the existing receipt, while the same bytes
-- on another backend is a separately stored, separately charged artifact. A NULL
-- account_id (operator-direct upload) is not deduped here (the partial index
-- excludes it).
CREATE UNIQUE INDEX storage_upload_account_sha256_idx
    ON cw_core.storage_upload (account_id, backend, sha256)
    WHERE account_id IS NOT NULL;

-- The orphan-refund sweep claims the oldest charged account uploads and, for
-- each, tests whether any poe_record embeds its URI. A partial index over
-- exactly the candidate population — an account upload that was actually billed
-- (charged_usd_micros > 0, charged against an attempt) — ordered by created_at
-- lets the claim read only the rows old enough to consider. A free-window or
-- deduped upload (charged_usd_micros = 0) is never billed and so excluded.
CREATE INDEX storage_upload_charged_age_idx
    ON cw_core.storage_upload (created_at)
    WHERE account_id IS NOT NULL
      AND attempt_id IS NOT NULL
      AND charged_usd_micros > 0;

-- ---------------------------------------------------------------------------
-- storage_refund_intent: the durable single-refund hook (twin of refund_intent).
--
-- Mirrors cw_core.refund_intent: the engine never moves money on a refund; it
-- writes a durable single-emit intent + an outbox event, and a downstream
-- consumer credits storage_refund. Keyed on the upload (single refund per
-- upload), NOT the record. The three reasons are all narrow, single-refund
-- reversals: an upload whose bytes never durably landed (upload_uncommitted), a
-- charge applied more than once for the same bytes (overcharge_replay), and an
-- upload whose bytes DID land and were charged but which no record ever
-- referenced (upload_orphaned, the abort-then-re-wrap orphan a self-correcting
-- sweep refunds after a grace window). A committed upload a record DID reference
-- keeps its charge because the bytes are permanently stored. There is
-- deliberately no 'published_record_failed' reason: a publish that permanently
-- fails does not refund storage.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_refund_intent (
    storage_upload_id uuid PRIMARY KEY REFERENCES cw_core.storage_upload (id) ON DELETE RESTRICT,
    reason            text NOT NULL CHECK (reason IN ('upload_uncommitted', 'overcharge_replay', 'upload_orphaned')),
    detail            jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- storage_topup: the operator's AR -> provider-credit conversion journal.
--
-- A top-up is an on-chain AR transfer from the operator's funding wallet to the
-- storage provider's deposit wallet, then a registration of that transfer's tx
-- id with the provider so the winston is credited as prepaid upload credit
-- (winc). The conversion is ONE-WAY: credits can never be turned back into AR.
-- The row is inserted AFTER signing but BEFORE broadcast, and persists the
-- COMPLETE signed transaction JSON; the Arweave tx id is fixed at signing
-- (SHA-256 of the signature), so recovery always works FORWARD: re-broadcast the
-- byte-identical persisted transaction (idempotent, same id) and re-register.
-- Re-signing is never part of recovery — the PSS signature is randomised.
--
-- This is distinct from the winc credit ledger (storage_credit_ledger): the
-- credit ledger records BELIEVED winc movements against the provider balance,
-- while this table records the on-chain transfers that fund it. The two meet
-- only through the reconcile loop reading the provider's authoritative balance.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_topup (
    id                    uuid PRIMARY KEY,
    funding_source_id     uuid NOT NULL REFERENCES cw_core.storage_funding_source (id) ON DELETE RESTRICT,
    -- The operator that initiated the conversion (always the source's owner at
    -- the time of the call; denormalised so the journal row stands alone even if
    -- ownership is ever transferred).
    initiated_by_operator uuid NOT NULL REFERENCES cw_core.operator (id),
    -- The transferred amount and the node-quoted transfer fee, in winston.
    -- numeric: winston amounts (10^12 per AR) overflow bigint inside the AR supply.
    ar_amount_winston     numeric NOT NULL CHECK (ar_amount_winston > 0),
    fee_winston           numeric NOT NULL CHECK (fee_winston >= 0),
    -- The provider deposit wallet the transfer pays (resolved from the payment
    -- service at top-up time, persisted so the row is auditable on its own).
    target_address        text NOT NULL,
    -- The Arweave transfer transaction id, fixed at signing. Unique: one row per
    -- transfer, and a registration retry resolves the SAME row.
    tx_id                 text NOT NULL UNIQUE,
    -- The complete signed transaction JSON (the node's POST /tx body). Persisted
    -- so recovery re-broadcasts byte-identical bytes instead of re-signing. It
    -- contains only public material (the signature, the owner modulus, the
    -- transfer fields), never a key.
    tx_json               jsonb NOT NULL,
    --   signed        : signed and durably recorded but broadcast not confirmed.
    --   submitted     : accepted by the Arweave node; registration not yet done.
    --   submit_failed : node refused or broadcast failed in transit (the outcome
    --                   may be INDETERMINATE; the retry re-broadcasts the
    --                   persisted transaction, safe either way).
    --   registered    : the payment service ACCEPTED the fund transaction, which
    --                   still credits at confirmation depth; the register/poll
    --                   step advances the row until the service reports the
    --                   transfer credited.
    --   credited      : terminal — the provider credit landed and the
    --                   believed-balance 'topup' journal row was appended.
    status                text NOT NULL CHECK (status IN ('signed', 'submitted', 'submit_failed', 'registered', 'credited')),
    -- The most recent failure detail (broadcast or registration), cleared on a
    -- later success, so the operator sees why a top-up is stuck.
    last_error            text,
    -- The winc the payment service reported it will credit for this transfer,
    -- when the registration response carried it.
    registered_winc       numeric,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    -- Caller-supplied idempotency key, unique per initiating operator. A top-up
    -- signs and broadcasts an IRREVERSIBLE on-chain AR transfer, so its create
    -- call must be safe to retry: a caller whose response was lost (a timeout,
    -- a proxy 502, a UI double-submit) re-sends the same logical top-up and
    -- must get the SAME journalled conversion back, never a second signed
    -- transfer. The `tx_id` unique key cannot provide this — the PSS signature
    -- is randomised, so a re-sign always mints a fresh id — hence this key,
    -- which the create path checks BEFORE signing and replays on a duplicate,
    -- mirroring the balance ledger's `ref` idempotency (the pattern every
    -- other irreversible money movement on the control plane follows). The key
    -- is an API-level contract (required on every create), not a storage
    -- invariant, so the column is nullable and the partial unique index below
    -- constrains exactly the keyed rows; the CHECK is a backstop for the
    -- API-level validation (non-empty, bounded), not a substitute for it.
    idempotency_key       text
                          CHECK (idempotency_key IS NULL
                                 OR (btrim(idempotency_key) <> '' AND octet_length(idempotency_key) <= 200)),
    -- Stamped when the payment service reports the transfer credited and the
    -- winc journal row is appended, so the journal row and the top-up row
    -- corroborate each other; NULL while the credit is still pending
    -- confirmation depth.
    credited_at           timestamptz
);

-- The operator-facing listing reads newest-first within the operator's sources.
CREATE INDEX storage_topup_source_created_idx
    ON cw_core.storage_topup (funding_source_id, created_at DESC);

-- One conversion per (operator, key). A same-key create finds this row and
-- replays it; a concurrent duplicate loses the insert race here and falls back
-- to replaying the winner — in both cases exactly one transfer is ever signed
-- for one logical top-up.
CREATE UNIQUE INDEX storage_topup_operator_idempotency_key
    ON cw_core.storage_topup (initiated_by_operator, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- ---------------------------------------------------------------------------
-- storage_upload_session + storage_upload_session_chunk: the resumable /
-- chunked-upload ingress precursor that assembles a large file from client-sent
-- chunks before it enters the existing paid-upload pipeline.
--
-- A session is content-addressed: the client declares the whole-file sha256 and
-- total_bytes at create, so the gateway can dedup and check affordability BEFORE
-- a single byte flows. The client then PUTs each chunk at its deterministic
-- offset into one durable assembling file; the received-chunk bitmap is the
-- truth, so a reconnecting client re-PUTs only the missing indices. At complete
-- the assembled file is verified against the declared hash and handed into the
-- existing store_one -> reserve_attempt path UNCHANGED.
--
-- The session is a PRECURSOR to the attempt, NOT the attempt. It carries NO
-- ledger state: chunks never touch money. The only billing event is the storage
-- upload attempt reserve at complete, reached exactly once. Two clients may
-- legitimately open two sessions for the SAME content simultaneously;
-- convergence happens at reserve_attempt, where the existing ATTACH semantics
-- handle it. Forcing the session into storage_upload_attempt would break that
-- table's (account, backend, sha256) WHERE state='reserved' live-uniqueness, so
-- the session is a separate, permissive object.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.storage_upload_session (
    id                uuid PRIMARY KEY,
    account_id        uuid NOT NULL REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    operator_id       uuid NOT NULL REFERENCES cw_core.operator (id),
    backend           text NOT NULL CHECK (backend IN ('turbo', 'direct-arweave', 'arlocal')),
    -- The declared whole-file content digest: the dedup/affordability key at
    -- create and the integrity target the assembled rolling hash is checked
    -- against at complete. A lying client only fails its own session.
    sha256            bytea NOT NULL CHECK (octet_length(sha256) = 32),
    -- The declared total size; no product max (the per-file DoS ceiling applies).
    total_bytes       bigint NOT NULL CHECK (total_bytes >= 0),
    -- The authoritative, server-clamped chunk size, FIXED for the session
    -- lifetime so offset = index * chunk_bytes is a pure function and the
    -- received set is a compact bitmap. > 0 even for a zero-byte file.
    chunk_bytes       bigint NOT NULL CHECK (chunk_bytes > 0),
    chunk_count       integer NOT NULL CHECK (chunk_count >= 0),
    -- Recorded for the data-item Content-Type tag the single signing applies.
    content_type      text NOT NULL DEFAULT 'application/octet-stream',
    -- The received-chunk set as a bitmap, one bit per chunk index (little-endian
    -- within each byte: index i is byte i/8, bit i%8). The chunk-receipt CAS ORs
    -- the index bit AFTER the bytes are durably on disk, so the bitmap never
    -- claims an index whose bytes are not fsynced. received_count is the popcount,
    -- maintained in the same CAS so /complete's all-received precondition is O(1).
    received_bitmap   bytea NOT NULL DEFAULT ''::bytea,
    received_count    integer NOT NULL DEFAULT 0 CHECK (received_count >= 0),
    -- The durable assembling file (named <id>.assembling under the assembling dir,
    -- which IS the durable_staging_dir the attempt promotion uses). Cleared when
    -- the session reserves the attempt (the file is adopted as the attempt's
    -- staged content) or when the janitor reclaims an abandoned session.
    assembling_path   text,
    state             text NOT NULL DEFAULT 'open'
                      CHECK (state IN ('open', 'assembling', 'completed', 'failed', 'expired')),
    -- Set when /complete reserves the attempt: the bridge to the existing poll
    -- route. ON DELETE SET NULL because the attempt outlives the session
    -- bookkeeping.
    attempt_id        uuid REFERENCES cw_core.storage_upload_attempt (id) ON DELETE SET NULL,
    -- The terminal URI a completed session resolved to (a fresh receipt, a dedup
    -- hit, or an attached attempt's eventual URI). Lets a re-complete read back
    -- the recorded outcome without re-reserving.
    uri               text,
    -- The terminal disposition a re-complete replays: 'committed' (ok + uri),
    -- 'accepted' (attached, poll attempt_id), or 'deduplicated' (ok + uri, 0
    -- charge). Set together with state='completed'.
    settled_disposition text CHECK (settled_disposition IS NULL
                          OR settled_disposition IN ('committed', 'accepted', 'deduplicated')),
    -- The realized USD charge a completed session reports (0 for free-window,
    -- dedup, or an attach; the billed amount otherwise).
    charged_usd_micros bigint,
    failure_reason    text,   -- sha256_mismatch | ... (only in 'failed')
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    settled_at        timestamptz
);

-- Resume hot path: the per-account open-session lookup (backpressure cap + a
-- caller listing its own live sessions) and the dedup-at-create lookup.
CREATE INDEX storage_upload_session_account_open_idx
    ON cw_core.storage_upload_session (account_id)
    WHERE state IN ('open', 'assembling');

-- Janitor hot path: the expired-but-still-live set the sweep CAS-marks expired.
CREATE INDEX storage_upload_session_expiry_idx
    ON cw_core.storage_upload_session (expires_at)
    WHERE state IN ('open', 'assembling');

-- One row per received chunk, recorded in the same CAS that flips the received
-- bit. It lets a re-PUT verify "same bytes for this index" (a matching digest is
-- an idempotent no-op; a differing one is a chunk-conflict), and records the
-- exact byte length the chunk carried for auditing. CASCADE so abandoning or
-- deleting a session reclaims its chunk rows with it.
CREATE TABLE cw_core.storage_upload_session_chunk (
    session_id   uuid NOT NULL REFERENCES cw_core.storage_upload_session (id) ON DELETE CASCADE,
    index        integer NOT NULL CHECK (index >= 0),
    chunk_sha256 bytea NOT NULL CHECK (octet_length(chunk_sha256) = 32),
    bytes        integer NOT NULL CHECK (bytes >= 0),
    received_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, index)
);


-- ===========================================================================
-- SECTION 10 — Pricing/FX cache, the price-oracle cooldown, the per-account
-- margin override, and the clamped-debit idempotency log.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- fx_rate: live FX snapshot cache for the quote pricing path.
--
-- The network fee and minimum-ADA are priced from the cached protocol
-- parameters. The two market PRICES the quote also needs are different in kind:
-- the ADA->USD rate that converts the lovelace fee to micro-USD, and the
-- per-byte Arweave storage price. Those move continuously and have no on-chain
-- source, so they come from external oracles. A single background loop polls the
-- oracles on a cadence and inserts one row here per tick; every quote reads the
-- NEWEST row, never the oracles. A thousand concurrent quotes therefore make
-- zero oracle calls. Reads serve the newest row regardless of age (the read path
-- surfaces the age rather than blocking on freshness): undercharging on a
-- slightly stale conversion is recoverable, refusing to quote on a transient
-- oracle outage is not. This table deliberately carries ONLY the two price
-- oracles; the fee-relevant protocol parameters keep their own per-epoch cache.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.fx_rate (
    -- Surrogate key; the newest row (highest id, equivalently latest fetched_at)
    -- is the one every quote reads.
    id                     bigserial PRIMARY KEY,
    -- USD per ADA, in micro-USD (USD x 1e6) per 1 ADA. Converts the lovelace
    -- network fee to micro-USD. Must be positive: a zero or negative rate would
    -- silently price every network fee at nothing.
    ada_usd_micros         bigint NOT NULL CHECK (ada_usd_micros > 0),
    -- USD per stored byte, in femto-USD (USD x 1e15) per byte. Femto retains
    -- precision on sub-megabyte payloads where micro-USD would round to zero.
    -- Must be positive for the same reason as above.
    ar_usd_per_byte_femto  bigint NOT NULL CHECK (ar_usd_per_byte_femto > 0),
    -- When this snapshot was taken. The read path reports `now() - fetched_at`
    -- as the snapshot age on each quote; it never participates in which row a
    -- reader selects (that is the highest id).
    fetched_at             timestamptz NOT NULL DEFAULT now(),
    -- Which oracle path produced the per-byte price (and, suffixed, which price
    -- tier supplied ADA/USD + AR/USD), retained for observability. Free text so a
    -- new oracle is a data concern, not a schema migration.
    source                 text NOT NULL,
    -- The verbatim oracle responses that produced this row, retained so a future
    -- reader can audit or recover a value this schema does not name a column for.
    raw_response           jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- Readers ask for "the newest snapshot", an index-only descending scan on the
-- surrogate key.
CREATE INDEX fx_rate_latest_idx ON cw_core.fx_rate (id DESC);

-- ---------------------------------------------------------------------------
-- coingecko_cooldown: restart-survivable cooldown for the price-oracle quota.
--
-- The cheapest oracle tiers carry a finite request budget; exceeding it returns
-- an HTTP 429 / quota signal. The refresh loop must NOT retry into an exhausted
-- quota: a retry storm accelerates the saturation and can burn budget another
-- project on the same shared key needs. Instead a quota signal persists a
-- `cooldown_until` instant here, and every subsequent tick reads this row BEFORE
-- making any oracle call: while the gate is closed the tick exits immediately,
-- with no network spend. A successful call after the gate reopens clears the
-- row. The cooldown lives in Postgres (not process memory) so a worker restart
-- inherits it. A single logical gate suffices, so the table is pinned to one row
-- by a constant primary key.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.coingecko_cooldown (
    -- One logical gate per deployment: a CHECK-pinned constant key allows exactly
    -- one row, so an upsert always targets the same gate.
    id              boolean PRIMARY KEY DEFAULT true CHECK (id = true),
    -- The instant oracle calls may resume. NULL means no cooldown is in effect.
    cooldown_until  timestamptz,
    -- When the most recent quota signal was observed, for observability.
    last_quota_at   timestamptz,
    -- The HTTP status of the most recent quota signal (429 or equivalent).
    last_quota_status integer,
    -- A bounded excerpt of the most recent quota-signal body, for diagnostics. A
    -- provider's quota response can be an oversized HTML intercept page, so the
    -- writer truncates before storing.
    last_quota_body text,
    -- When this gate row was last written.
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- account_margin_override: at most one markup override per account.
--
-- The pricing seam resolves the effective margin per account: this override when
-- a row exists, else the operator-default margin the deployment configured. The
-- base plane knows only "default vs override"; any richer policy (tiers, badges,
-- delegation) lives in a control plane that COMPUTES an effective percentage and
-- PUSHES it here. The markup is stored as a fraction in the same numeric(6,4)
-- shape the durable quote row records (e.g. 0.2500 = 25%), so a resolved override
-- flows onto the quote with no unit conversion.
--
-- The FK to cw_api.account is ON DELETE CASCADE: an override is pure pricing
-- policy with no audit value once its account is gone, so it follows the account
-- out rather than blocking its deletion (unlike the RESTRICT references that
-- protect ledger history).
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.account_margin_override (
    account_id  uuid PRIMARY KEY REFERENCES cw_api.account (id) ON DELETE CASCADE,
    -- The markup as a fraction, matching the publish_quote.margin_pct shape.
    margin_pct  numeric(6, 4) NOT NULL CHECK (margin_pct >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- clamp_debit_log: the clamped-debit idempotency / result log.
--
-- A clamped debit removes min(requested, available) from the balance, clamps at
-- zero, and reports the amount actually debited. That RESULT is path-dependent:
-- it is whatever the balance could cover at the instant the first call ran. A
-- retry MUST return the same amount the first call returned — the caller (a
-- vendor's clawback flow) derives its arrears remainder as requested - debited,
-- so a re-clamp against a balance that has since moved would compute a different
-- remainder. The balance_ledger row cannot memoize this on its own: a zero-debit
-- call writes NO ledger row (the CHECK amount_micros <> 0 forbids a zero entry),
-- and the only stored figure is the entry magnitude, not the original requested.
--
-- This table memoizes EVERY clamp result, including a zero debit, keyed on the
-- idempotency `ref` (the primary key: one clamp result per ref, globally unique).
-- The clamp primitive serialises against concurrent balance writers by locking
-- the cw_core.balance row FOR UPDATE — the same row publish-quote consume and
-- storage-attempt debits lock — so there is no lock-order inversion. The account
-- FK mirrors balance_ledger's posture so an account with clamp history can never
-- be hard-deleted.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.clamp_debit_log (
    ref              text PRIMARY KEY,
    account_id       uuid NOT NULL REFERENCES cw_api.account (id) ON DELETE RESTRICT,
    -- The amount the caller asked to debit (before clamping). Stored so a
    -- same-ref replay carrying a different requested amount (a must-never-happen,
    -- since the originating Stripe id's amount is immutable) is detected and
    -- refused rather than silently resolved to either amount.
    requested_micros bigint NOT NULL,
    -- The amount actually removed from the balance: 0 <= debited <= requested.
    -- A zero is a legitimate, memoized result (the balance was empty).
    debited_micros   bigint NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT clamp_debit_log_requested_positive CHECK (requested_micros > 0),
    CONSTRAINT clamp_debit_log_debited_bounds CHECK (debited_micros >= 0 AND debited_micros <= requested_micros)
);

-- An account's clamp history, for operator-scoped audit reads.
CREATE INDEX clamp_debit_log_account_idx ON cw_core.clamp_debit_log (account_id);


-- ===========================================================================
-- SECTION 11 — Durable webhook delivery: the registration model, the
-- per-(event, subscription) delivery state, and the live health view.
--
-- Two-stage design. cw_core.delivery_outbox (created in Section 1) is the
-- durable record that an event happened and must be delivered; SSE already rides
-- it as the per-subject event spine. Webhook fan-out reuses it as the *fan-out
-- spine*: a fan-out reader drains un-fanned rows (delivery_outbox.fanned_out_at
-- IS NULL) and explodes each into one webhook_delivery row per matching
-- subscription, so one slow endpoint never blocks another subscriber, and adding
-- or removing a subscription never rewrites history. The mid-stream-subscribe
-- boundary is presence-based: a subscription created at T receives exactly the
-- events fanned out after it commits — no global ordering key, no cursor table.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- webhook_endpoint: a registered delivery target.
--
-- Polymorphic owner: an account-scoped subscription (data plane) or an
-- operator-scoped firehose (control plane). Exactly one owner column is set,
-- mirroring the wallet-grant scope/subject discipline.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.webhook_endpoint (
    id              uuid PRIMARY KEY,                 -- UUIDv7
    scope_kind      text NOT NULL CHECK (scope_kind IN ('account', 'operator')),
    -- Set iff scope_kind = 'account'. The account anchor is the stable contract
    -- table, so an account-scoped endpoint FK-references it; ON DELETE CASCADE
    -- removes the endpoint when its account is hard-removed.
    account_id      uuid REFERENCES cw_api.account (id) ON DELETE CASCADE,
    -- Set iff scope_kind = 'operator'.
    operator_id     uuid REFERENCES cw_core.operator (id) ON DELETE CASCADE,
    url             text NOT NULL,                    -- https:// target
    -- AEAD-encrypted at rest under the webhook secret-wrap data key; the signer
    -- unwraps to compute HMACs at delivery time, then zeroizes the plaintext. The
    -- secret is never returned after create.
    secret_enc      bytea NOT NULL,
    -- One-way fingerprint of the secret for display/audit (never the secret
    -- itself): sha256(secret).
    secret_fp       bytea NOT NULL,
    -- Which webhook-wrap data key encrypted secret_enc/secret_next_enc. Recording
    -- it per row lets a wrap-key rotation re-encrypt row-by-row and stay
    -- resumable.
    wrap_key_id     text NOT NULL,
    -- Rotation window: a second active secret. While both are present the signer
    -- dual-signs (one MAC per secret) and the receiver accepts either.
    secret_next_enc bytea,
    secret_next_fp  bytea,
    -- Empty = every wire event type. Filter values are PUBLIC wire event names,
    -- not internal event_type literals.
    enabled_events  text[] NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'paused', 'disabled')),
    disabled_reason text,
    -- Auto-disable accounting: consecutive fully-exhausted deliveries, and the
    -- last instant a delivery to this endpoint succeeded.
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_success_at timestamptz,
    label           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    -- Exactly one owner column is populated, and it matches scope_kind. This
    -- binds the polymorphic owner so a future writer cannot create an
    -- account-scoped row with an operator owner (or a row with neither/both set).
    CONSTRAINT webhook_endpoint_owner_matches_scope CHECK (
        (scope_kind = 'account'  AND account_id  IS NOT NULL AND operator_id IS NULL) OR
        (scope_kind = 'operator' AND operator_id IS NOT NULL AND account_id  IS NULL)
    )
);

-- The fan-out matcher resolves live subscriptions for an owner. The partial
-- indexes keep that lookup to active, non-deleted rows of each scope.
CREATE INDEX webhook_endpoint_account_idx ON cw_core.webhook_endpoint (account_id)
    WHERE scope_kind = 'account' AND deleted_at IS NULL AND status <> 'disabled';
CREATE INDEX webhook_endpoint_operator_idx ON cw_core.webhook_endpoint (operator_id)
    WHERE scope_kind = 'operator' AND deleted_at IS NULL AND status <> 'disabled';

-- ---------------------------------------------------------------------------
-- webhook_delivery: per-(event, subscription) delivery state.
--
-- One row per matched subscription per event. The fan-out reader creates these
-- from a delivery_outbox row; the delivery worker drains them with independent
-- backoff/attempts so one slow endpoint never blocks another subscriber.
--
-- The claim_token / claim_expires_at pair fences the egress POST window: the
-- delivery worker signs and POSTs outside any database transaction (a blocking
-- network call must not hold a connection), so without a lease a pool of workers
-- could each claim the same pending row and POST it concurrently. Exactly one
-- worker owns a delivery's POST window at a time; a crashed owner's lease lapses
-- by TTL so another worker reclaims and redelivers (at-least-once preserved; the
-- receiver dedupes on Webhook-Id). The terminal CAS on `state` serializes the
-- DATABASE transition; this lease serializes the EXTERNAL POST side effect.
-- ---------------------------------------------------------------------------
CREATE TABLE cw_core.webhook_delivery (
    id              uuid PRIMARY KEY,                 -- UUIDv7
    endpoint_id     uuid NOT NULL REFERENCES cw_core.webhook_endpoint (id) ON DELETE CASCADE,
    -- The logical event identity, carried so a redelivery reuses the same
    -- Webhook-Id and the per-subject ordering claim can order by subject_seq.
    subject_kind    text NOT NULL,
    subject_id      text NOT NULL,
    subject_seq     bigint NOT NULL CHECK (subject_seq >= 1),
    event_type      text NOT NULL,                    -- internal type (projected at send)
    -- The frozen wire envelope, signed verbatim, so a retry signs the same body.
    body            jsonb NOT NULL,
    -- Webhook-Id == dedupe_key == 'subject_kind:subject_id:subject_seq:endpoint_id',
    -- unique per (event, subscription). This is BOTH the receiver's idempotency
    -- key AND the fan-out conflict target: the fan-out INSERT uses
    -- ON CONFLICT (dedupe_key) DO NOTHING so a crash-replayed fan-out of the same
    -- outbox row is a no-op rather than a unique violation.
    dedupe_key      text NOT NULL UNIQUE,
    -- The outbox row this delivery was fanned out from. Carried so the
    -- per-delivery inserts and the outbox fanned_out_at stamp share one
    -- transaction keyed on it.
    outbox_id       uuid NOT NULL REFERENCES cw_core.delivery_outbox (id) ON DELETE CASCADE,
    state           text NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts    integer NOT NULL DEFAULT 12 CHECK (max_attempts >= 1),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    last_status     integer,                          -- last HTTP status seen
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Exclusive claim-lease on the egress POST. NULL token = unclaimed; a
    -- claim_expires_at in the past means the prior owner died mid-POST and the
    -- window is reclaimable.
    claim_token      uuid,
    claim_expires_at timestamptz
);

-- The delivery worker claims the lowest-seq pending row per (endpoint, subject)
-- that is due, so per-subject ordering holds PER subscription independently. The
-- lease predicate is evaluated on the few rows the frontier surfaces, so it needs
-- no dedicated index column beyond this due index.
CREATE INDEX webhook_delivery_due_idx
    ON cw_core.webhook_delivery (endpoint_id, subject_kind, subject_id, subject_seq)
    WHERE state = 'pending';

-- The operator's deliveries list (which doubles as the dead-letter view) reads
-- by endpoint, newest first.
CREATE INDEX webhook_delivery_endpoint_idx
    ON cw_core.webhook_delivery (endpoint_id, created_at DESC);

-- The firehose-retention terminal-delivery sweep selects the oldest
-- delivered/failed rows by created_at and prunes them with bounded batch deletes
-- (the table is not partitioned: it carries a cascading FK to delivery_outbox). A
-- pending row (still mid-retry, or a redrivable dead-letter within the window) is
-- excluded from the index entirely.
CREATE INDEX webhook_delivery_terminal_age_idx
    ON cw_core.webhook_delivery (created_at)
    WHERE state IN ('delivered', 'failed');

-- The outbox sweep keeps any outbox row still referenced by a surviving delivery
-- (NOT EXISTS over webhook_delivery.outbox_id), and the FK is ON DELETE CASCADE.
-- Indexing outbox_id makes both the reference check and the cascade a point probe
-- rather than a per-outbox-row scan of the deliveries table.
CREATE INDEX webhook_delivery_outbox_idx
    ON cw_core.webhook_delivery (outbox_id);

-- ---------------------------------------------------------------------------
-- webhook_health: a live read-only aggregate per endpoint.
--
-- A view (not a table) so it is always current and costs no write path. It backs
-- the operator health summary and carries each endpoint's failure population so a
-- growing dead-delivery count is observable without scanning the deliveries list.
-- ---------------------------------------------------------------------------
CREATE VIEW cw_core.webhook_health AS
SELECT e.id            AS endpoint_id,
       e.scope_kind,
       e.status,
       e.consecutive_failures,
       e.last_success_at,
       count(*) FILTER (WHERE d.state = 'failed')                 AS dead_deliveries,
       count(*) FILTER (WHERE d.state = 'pending')                AS pending_deliveries,
       min(d.next_attempt_at) FILTER (WHERE d.state = 'pending')  AS oldest_pending_due,
       min(d.created_at)      FILTER (WHERE d.state = 'pending')  AS oldest_pending_at
FROM cw_core.webhook_endpoint e
LEFT JOIN cw_core.webhook_delivery d ON d.endpoint_id = e.id
WHERE e.deleted_at IS NULL
GROUP BY e.id;
