# gateway

A single Rust binary plus Postgres that runs a complete Label 309
Proof-of-Existence publishing service: it serves a per-account **data plane**
(`/api/v1/*` — quote, upload, publish, records, balance, webhooks), an
operator-only **control plane** (`/control/v1/*` — accounts, credentials,
wallets, storage funding, the firehose, the audit log), and a bundled **admin
console** at `/admin`. Behind the HTTP planes it runs the background planes
that keep the service true: Cardano transaction submit/confirm/reorg handling,
the on-chain records indexer, the operator wallet pool, Arweave content
storage, FX pricing, webhook delivery, and engine maintenance — all supervised
together, so a failing loop stops the process instead of silently degrading.

## Quickstart

The shortest path from nothing to a publish-ready gateway. Each step is
explained in depth in [docs/operators.md](../docs/operators.md).

```sh
# 1. Create the operator keyring (one encrypted file holds every signing key).
export GATEWAY_KEYRING_PASSPHRASE='correct horse battery staple'
gateway keyring init             --path /etc/gateway/keyring.age
gateway keyring add-cardano      --path /etc/gateway/keyring.age --network preprod
gateway keyring add-arweave      --path /etc/gateway/keyring.age
gateway keyring add-webhook-wrap --path /etc/gateway/keyring.age
# Fund the two printed addresses: the Cardano address pays anchoring fees,
# the Arweave address funds storage credits.
```

```sh
# 2. Write a minimal config (full reference below).
cat > /etc/gateway/gateway.toml <<'EOF'
network = "preprod"
keyring_path = "/etc/gateway/keyring.age"

[band]
min = 4000000
max = 8000000
mid = 6000000

[wallet]
lease_secs = 120
min_canonical_count = 4

[http]
bind = "0.0.0.0:8080"
problem_type_base = "https://errors.example/v1"
ada_usd_micros = 500000
margin_pct = 0.25
EOF
export GATEWAY_CONFIG=/etc/gateway/gateway.toml
export GATEWAY_DATABASE_URL=postgres://user:pass@host/gateway
```

```sh
# 3. Provision the operator (prints the root secret EXACTLY ONCE — store it).
gateway operator bootstrap --label acme

# 4. Serve.
gateway
```

```sh
# 5. Register the funded keys (root credential required; never pass it as argv).
# GATEWAY_CONTROL_URL is the FULL control-plane base, version segment included;
# the admin CLI appends only bare resource suffixes to it.
export GATEWAY_CONTROL_URL=http://127.0.0.1:8080/control/v1
export GATEWAY_CONTROL_TOKEN='ctl_…the printed root secret…'
gateway admin wallet register primary addr_test1… preprod
gateway storage bootstrap --backend turbo --label primary   # only with [storage] configured

# 6. Create an account, credit it, mint its api key.
gateway admin account create
gateway admin account fund <account_id> 10000000 "starter credit"   # $10
gateway admin key create <account_id> poe:create,poe:read,account:read
```

The printed api key drives the data plane: interactive API docs are served per
plane at `/api/v1/docs` and `/control/v1/docs` (the renderer is vendored, so the
pages work fully offline — no CDN), the machine-readable OpenAPI documents at
`/api/v1/openapi.json` and `/control/v1/openapi.json`, and the admin console at
`/admin` (paste an operator token).

The walkthrough targets preprod end to end, matching the example config. For a
production deployment the Cardano keyring key, the config `network`, and the
wallet registration must all say `mainnet` together.

## Configuration

The config file path comes from `GATEWAY_CONFIG` (default `gateway.toml`).
The reference below is a valid file: keys appear with their default values
where a default exists; sections marked optional can be deleted wholesale.
Operational depth for every knob lives in
[docs/operators.md](../docs/operators.md).

```toml
# The Cardano network every transaction lands on: "mainnet", "preprod", or "preview".
network = "mainnet"

# Identity stamped onto background-job claims. Optional — defaults to the host
# name; pin it so claim attribution survives container recreation.
worker_id = "gateway-1"

# Path to the age-encrypted operator keyring (created with `gateway keyring`).
# GATEWAY_KEYRING_PATH overrides it; the passphrase always comes from the environment.
keyring_path = "/etc/gateway/keyring.age"

# Record byte-lengths the startup fee-stability check certifies the band
# against. Must include the largest record you accept; see docs/operators.md.
fee_shape_record_sizes = [1, 64, 65, 1024, 14000]

# The lovelace range a wallet UTxO must fall in to fund one publish; the wallet
# loops groom funds into mid-band UTxOs. See docs/operators.md before changing.
[band]
min = 4000000
max = 8000000
mid = 6000000

# Wallet-pool tuning: how long one publish may hold a UTxO it is spending, and
# how many ready UTxOs each wallet keeps groomed.
[wallet]
lease_secs = 120
min_canonical_count = 4

# The HTTP planes (/api/v1, /control/v1, /admin). Optional — delete the
# section to run the background plane alone.
[http]
# The socket all three surfaces bind.
bind = "0.0.0.0:8080"

# Base URL RFC 7807 problem `type` members are built from. An identifier — it
# does not need to be a served URL.
problem_type_base = "https://errors.example/v1"

# Static ADA->USD rate (micro-USD per ADA) and the quote markup (0.25 = 25%).
# With [fx] present the live snapshot supersedes the static rate.
ada_usd_micros = 500000
margin_pct = 0.25

# Wall-clock ceiling (seconds) on an ordinary request. Streaming surfaces — the
# SSE streams and the content-upload ingress — are exempt (they are long-lived
# by design and carry their own bounds); everything else is cut off with a 408.
request_timeout_secs = 30

# Per-client-address budget (requests/minute) for ANONYMOUS reads on the public
# records routes (list / count / get). Authenticated callers meter against
# their credential's own budget instead. The address is the socket peer; behind
# a reverse proxy all anonymous traffic shares the proxy's address (one pooled
# budget), so size it for the proxy's aggregate.
anon_rate_limit_per_min = 120

# Ceilings on concurrently LIVE SSE streams (instance-wide / per account). A
# stream's cost is concurrency, not request rate, so it is capped separately;
# an open beyond a ceiling is refused with a 429 and the slot frees the moment
# a stream disconnects.
sse_max_streams = 1024
sse_max_streams_per_account = 32

# Live FX: one refresh cron is the only oracle caller; every quote reads its
# cached snapshot. Optional — delete to price from the static [http] rate.
# Coin prices (ADA/USD + AR/USD) come from keyless CoinPaprika by default — no
# API key, no registration — so this whole section can be just `[fx]`.
[fx]
# Optional: use CoinGecko as the PRIMARY price provider (CoinPaprika stays the
# fallback). Requires GATEWAY_COINGECKO_API_KEY; "demo" (free key) or "pro" (paid).
# Omit entirely to price from keyless CoinPaprika alone.
# coingecko_tier = "demo"

# Cron the refresh loop fires on.
refresh_schedule = "0 */15 * * * *"

# Freshness ceiling (seconds): once the newest cached snapshot is older than
# this, quotes are refused (503) rather than priced at a stale rate. A ceiling,
# not the refresh interval — a few missed ticks still serve the last snapshot.
max_fx_snapshot_age_seconds = 3600

# Content storage. Optional — delete the section for a hash-only deployment
# (uploads report unavailable; quotes skip storage pricing).
[storage]
# "turbo" (production Arweave via a bundler), "arlocal" (local emulator,
# refused on mainnet), or "direct-arweave" (reserved, not yet implemented).
backend = "turbo"

# The two Turbo hosts: uploads POST to the upload service; the credit
# reconcile loop reads the live winc balance from the payment service.
upload_url = "https://upload.ardrive.io"
payment_url = "https://payment.ardrive.io"

# Local ArLocal emulator endpoint. Required only for backend = "arlocal" (dev
# and integration tests, refused on mainnet); ignored by the turbo backend.
# arlocal_endpoint = "http://localhost:1984"

# Read-only Arweave gateway: ar:// lookups, crash-recovery checks, and the
# per-byte price fallback oracle.
gateway_url = "https://arweave.net"

# Scratch dir streamed uploads pass through (tmpfs is fine), and the durable
# dir staged content is promoted to (must survive a crash — never tmpfs).
#
# Both paths must be WRITABLE BY THE CONTAINER'S RUNTIME USER. The published
# image runs as a non-root user (uid 1001) and pre-creates + chowns
# /var/lib/gateway to it, so the defaults below "just work" when that path is a
# Docker volume (or any dir owned by uid 1001). If you point these at a CUSTOM
# location — e.g. a host bind-mount owned by root — the gateway cannot create or
# write the staging dirs and uploads fail; chown that path to uid 1001 (or keep
# it under /var/lib/gateway). `durable_staging_dir` has no default and is
# required, so it must always name a writable location.
staging_dir = "/var/lib/gateway/staging"
durable_staging_dir = "/var/lib/gateway/durable"

# Uploads at or under this many bytes are stored free of charge (default 100 KiB).
free_storage_bytes = 102400

# Static per-byte storage rate (femto-USD per byte) quotes forecast storage
# cost from. With [fx] present the live snapshot supersedes it.
ar_usd_per_byte_femto = 20955000

# Winc-credit housekeeping: the reconcile cron (the only winc network caller),
# the credit floor below which uploads are refused, and the drift alert.
winc_refresh_schedule = "0 */5 * * * *"
winc_safety_floor = 0
winc_drift_alert_threshold = 0

# Upload lifecycle clocks (seconds). The horizon and the lease must both
# exceed the timeout — validated at load; see docs/operators.md.
upload_timeout_secs = 300
reconcile_horizon_secs = 900
upload_claim_lease_ttl_secs = 360
attempt_stuck_passes = 12

# Resumable-upload sessions. Optional keys — the defaults shown fit under a
# ~100 MB proxy body cap. A create request's chunk_bytes is clamped into
# [min_chunk_bytes, max_chunk_bytes]; the floor keeps a session's chunk count
# small, and a hard engine ceiling of 16384 chunks per session bounds it
# regardless of configuration.
[storage.sessions]
max_chunk_bytes = 67108864
min_chunk_bytes = 1048576
default_chunk_bytes = 50331648
session_ttl_secs = 86400
max_open_sessions_per_account = 64

# Control-plane knobs. Optional — the defaults shown apply when absent.
[control]
# Human-readable prefix minted credentials and api keys carry.
secret_prefix = "ctl_"

# Minted-token lifetimes (seconds): operator tokens a day, account tokens an hour.
operator_token_ttl_secs = 86400
account_token_ttl_secs = 3600

# Largest single balance adjustment (micro-USD; default $10,000). Every credit
# a billing wrapper applies rides one — see docs/operators.md for the cap's role.
adjustment_cap_usd_micros = 10000000000

# Serve the bundled /admin console.
admin_ui_enabled = true

# Grant a fresh wallet / funding source receives at registration when the call
# names none: "service" (usable by every account) or "operator" (registrar-only).
default_wallet_scope = "service"
default_storage_scope = "service"

# Webhook delivery posture. Optional — the defaults shown are the production
# posture (HTTPS-only targets, loopback/private ranges blocked). The knobs are
# independent: allow_insecure_http never loosens the IP range-block.
[webhooks]
allow_insecure_http = false
egress_allow_loopback = false

# Chain providers. Optional — absent runs keyless public Koios (~5,000
# requests/day) with a second Koios call as the failover.
[chain]
# Per-provider egress budget: sustained requests/minute + burst. The defaults
# keep a runaway loop under the keyless Koios daily quota.
egress_requests_per_minute = 30
egress_burst = 300

# Full base URL of a self-hosted or alternative Koios instance (no trailing
# slash). MUST serve this deployment's network; see docs/operators.md.
# koios_url = "https://koios.example/api/v1"

# Path to a file holding a Blockfrost project id, enabling Blockfrost failover
# on Koios rate limits. GATEWAY_BLOCKFROST_PROJECT_ID(_FILE) takes precedence.
# blockfrost_project_id_path = "/run/secrets/blockfrost-project-id"
```

## Environment

Secrets and deploy-time values come from the environment, never the file.
Every secret supports the docker-secrets convention through a `_FILE` twin
naming a file whose contents are read with trailing whitespace trimmed;
supplying both the plain variable and its `_FILE` twin is a load error.

| Variable                            | Purpose                                                                                                                                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GATEWAY_DATABASE_URL`              | Postgres connection URL (required).                                                                                                                                                             |
| `GATEWAY_KEYRING_PASSPHRASE`        | Operator keyring passphrase (required for serving; `_FILE` twin available).                                                                                                                     |
| `GATEWAY_KEYRING_PASSPHRASE_FILE`   | Path to a file holding the keyring passphrase; mutually exclusive with the plain variable.                                                                                                      |
| `GATEWAY_KEYRING_NEW_PASSPHRASE`    | New passphrase for `gateway keyring change-passphrase` only (`_FILE` twin available).                                                                                                           |
| `GATEWAY_KEYRING_PATH`              | Overrides `keyring_path` from the file (optional).                                                                                                                                              |
| `GATEWAY_WORKER_ID`                 | Identity stamped onto job claims (optional).                                                                                                                                                    |
| `GATEWAY_COINGECKO_API_KEY`         | Optional CoinGecko API key. Set it (with `[fx] coingecko_tier = "demo"`/`"pro"`) to use CoinGecko as the primary price provider; unset prices from keyless CoinPaprika. `_FILE` twin available. |
| `GATEWAY_KOIOS_API_KEY`             | Koios API key, sent as `Authorization: Bearer` on every Koios request; absent stays on the keyless public tier (~5,000 requests/day). `_FILE` twin available.                                   |
| `GATEWAY_BLOCKFROST_PROJECT_ID`     | Blockfrost project id for the chain failover secondary (optional; `_FILE` twin available).                                                                                                      |
| `GATEWAY_SENTRY_DSN`                | Turns on optional error monitoring (Sentry / GlitchTip). Unset leaves it fully inert. `_FILE` twin available. See [Error monitoring](#error-monitoring).                                        |
| `GATEWAY_SENTRY_ENVIRONMENT`        | `environment` tag for the monitoring (optional; default `production`). Read only when a DSN is set.                                                                                             |
| `GATEWAY_SENTRY_TRACES_SAMPLE_RATE` | Performance-tracing sample rate `0.0..=1.0` (optional; default `0.0` = errors only). Read only when a DSN is set.                                                                               |
| `GATEWAY_RELEASE`                   | `release` tag for the monitoring (optional; default the compiled-in `name@version`). Read only when a DSN is set.                                                                               |
| `GATEWAY_CONFIG`                    | Config file path (optional; default `gateway.toml`).                                                                                                                                            |
| `RUST_LOG`                          | Tracing filter (optional; default `info`).                                                                                                                                                      |
| `GATEWAY_CONTROL_URL`               | `admin` CLI: control-plane base URL (optional; or `--url`).                                                                                                                                     |
| `GATEWAY_CONTROL_TOKEN`             | `admin` CLI: bearer credential (operator token or root secret). The recommended source; the only alternative is `--token-stdin` (a pipe) — a bearer never rides argv.                           |

## Subcommands

With no subcommand the binary serves (the background plane plus, when
configured, the HTTP planes). `gateway --help` (or `-h`, or `help`) prints the
top-level usage and `gateway --version` (or `-V`) prints the version, both to
stdout. Serving is the no-argument behavior only: any other unrecognized
argument prints the usage to stderr and exits nonzero rather than falling
through to serve.

### Keyring

The operator keyring is a single age-encrypted file holding every key the
gateway signs with: Cardano ed25519 wallet keys (anchoring transactions),
Arweave RSA keys (storage data items), and webhook secret-wrap data keys
(webhook signing secrets encrypted at rest). One file, one passphrase, one
unlock at boot. The `gateway keyring` commands own its whole lifecycle —
file-local, no database, no network — and never print secret material, only
labels, addresses, and key ids. The passphrase comes from
`GATEWAY_KEYRING_PASSPHRASE(_FILE)`; with neither set, the commands prompt
interactively on a terminal.

```sh
# Create an empty keyring (refuses to overwrite an existing file).
gateway keyring init --path <file>

# Generate a Cardano signing key for a network and print its derived address;
# or import an existing CIP-5 key (ed25519_sk1…) from stdin.
gateway keyring add-cardano --path <file> --network <mainnet|preprod|preview> [--label <l>] [--secret-stdin]

# Generate a fresh 4096-bit Arweave RSA key (or import a JWK file) and print
# its derived Arweave address.
gateway keyring add-arweave --path <file> [--label <l>] [--jwk <jwk-file>]

# Mint a webhook secret-wrap data key. The newest webhook-wrap entry is the
# active one, so adding another later is a rotation.
gateway keyring add-webhook-wrap --path <file> [--label <l>]

# Unlock and list entries (kind, label, address/key id). Never prints secrets;
# a clean inspect also proves the gateway could boot with the file.
gateway keyring inspect --path <file>

# Remove one entry by its stable identity.
gateway keyring remove --path <file> (--address <addr> | --key-id <id>)

# Re-encrypt under a new passphrase (sourced from
# GATEWAY_KEYRING_NEW_PASSPHRASE(_FILE) or a confirmed prompt).
gateway keyring change-passphrase --path <file>
```

Key custody, offline creation, and rotation procedures are covered in
[docs/operators.md](../docs/operators.md).

### Bootstrap

```sh
# Provision a fresh deployment's control plane from an empty (migrated)
# database: one operator, the manual-adjustment ledger kind, and the operator
# root secret printed EXACTLY ONCE. Creates no account. A re-run refuses unless
# --allow-additional opts into a multi-operator instance.
gateway operator bootstrap [--label <operator-name>] [--allow-additional]

# Register one service-scoped storage funding source for a backend, inferring
# the keyring Arweave key and the operator when each is unique. Idempotent.
gateway storage bootstrap --backend <turbo|direct-arweave|arlocal> [--label <l>] [--key-address <addr>] [--operator-id <uuid>]
```

### Admin CLI

A thin HTTP client of the control plane (never a direct database connection).
The base URL comes from `--url` or `GATEWAY_CONTROL_URL`. The bearer credential
is resolved in order: `GATEWAY_CONTROL_TOKEN` (preferred), then `--token-stdin`
(read from standard input). Both keep the credential off argv, so it never
lands in shell history or process listings; an argv `--token` flag no longer
exists.

```sh
gateway admin account create
gateway admin account list
gateway admin account disable <account_id>
gateway admin account enable  <account_id>
gateway admin account fund    <account_id> <amount_usd_micros> <reason>
gateway admin account clamp-debit <account_id> <amount_usd_micros> <reason> <ref>
gateway admin account usage   <account_id>
gateway admin account margin set   <account_id> <margin_pct>
gateway admin account margin unset <account_id>
gateway admin key create  <account_id> <scopes,csv> [rate_limit_per_min]
gateway admin key list    <account_id>
gateway admin key revoke  <account_id> <key_id>
gateway admin key relabel <account_id> <key_id> [label]
gateway admin credential rotate-root [label]
gateway admin credential list
gateway admin credential revoke <credential_id>
gateway admin wallet list
gateway admin wallet operator-balance
gateway admin wallet drain      <wallet_id>
gateway admin wallet reactivate <wallet_id>
gateway admin wallet register   <label> <address> <network> [scope] [scope_account_id]
gateway admin wallet grant      <wallet_id> <service|operator|account> [account_id]
gateway admin wallet grant-revoke <wallet_id> <grant_id>
gateway admin storage source register     <label> <backend> <address> [scope] [scope_account_id]
gateway admin storage source grant        <source_id> <service|operator|account> [account_id]
gateway admin storage source grant-revoke <source_id> <grant_id>
gateway admin storage source drain        <source_id>
gateway admin storage sources
gateway admin storage top-up          <ar_amount_winston> <idempotency_key> [funding_source_id]
gateway admin storage top-up-register <topup_id>
gateway admin storage top-ups
gateway admin storage funding
gateway admin storage operator-balance
gateway admin chain provider-usage [days]
gateway admin pricing fx
gateway admin webhook health
gateway admin webhook create <url> [events,csv] [label]
gateway admin webhook list
gateway admin webhook get    <id>
gateway admin webhook update <id> <status|events|url|label> <value>
gateway admin webhook delete <id>
gateway admin webhook rotate-secret        <id>
gateway admin webhook rotate-secret-commit <id>
gateway admin webhook deliveries    <id> [limit]
gateway admin webhook delivery-retry <id> <delivery_id>
gateway admin token mint operator
gateway admin token mint account <account_id> [scopes,csv]
gateway admin token list
gateway admin token revoke <token_id>
gateway admin audit tail [limit]
```

The CLI covers the whole control plane — every `/control/v1/*` route is
drivable without curl.

`wallet register`, `storage source register`, `credential rotate-root`, and
`credential revoke` bind or replace high-authority credentials, so the control
plane gates them on the operator **root** credential; everything else accepts a
24-hour operator token. `credential rotate-root` replaces the presented root in
one transaction (printing the successor secret once); `credential revoke` and
`token revoke` are the targeted kill switches for a single leaked credential or
access token without a full rotation. `credential list` and `token list` show
ids and lifecycle only — secrets are unrecoverable by design.

`storage top-up` converts AR from the operator's funding wallet into prepaid
provider upload credits — an **irreversible** fund movement, which is why the
idempotency key is a required argument: retrying a lost response with the SAME
key replays the journalled conversion instead of signing a second transfer
(use a fresh key, e.g. a UUID, for each new top-up). A conversion that stalls
mid-flight (broadcast or registration failure) is retried FORWARD with
`storage top-up-register <topup_id>`, never re-signed. `storage funding` is
the cached roll-up across sources; `storage operator-balance` is the LIVE
provider read (on-chain AR balance plus, on Turbo, the prepaid winc balance);
`storage sources` lists the sources with their cached credit diagnostics; and
`storage source drain` stops a source taking new charges while in-flight uploads
settle.

The remaining commands are day-2 diagnostics and pricing/webhook control:
`account usage` reads an account's counters, `account margin set`/`unset` push a
per-account markup override, `account clamp-debit` is the clawback primitive, and
`key relabel` renames an api key. `wallet operator-balance` is the LIVE per-wallet
ADA read, `chain provider-usage` reports the egress gate's per-day request and
denial counts, and `pricing fx` shows the live FX snapshot every quote is priced
from (and whether it is stale). The `webhook …` group drives the operator
firehose end to end — `create`/`list`/`get`/`update`/`delete`, `health`,
`rotate-secret` and `rotate-secret-commit` for zero-downtime secret rotation, and
`deliveries`/`delivery-retry` for the dead-letter view.

## Running

```sh
GATEWAY_DATABASE_URL=postgres://user:pass@host/db \
GATEWAY_KEYRING_PASSPHRASE=... \
GATEWAY_CONFIG=/etc/gateway/gateway.toml \
gateway
```

On boot the binary unlocks the keyring once, applies its own migrations into
the `cw_core` schema (idempotent), certifies the configured lovelace band is
fee-shape-stable under live protocol parameters (refusing to start if not),
and then serves until SIGTERM/SIGINT requests a graceful shutdown.

## Error monitoring

The gateway has optional, opt-in error monitoring for any Sentry-compatible
backend — self-hosted [GlitchTip](https://glitchtip.com), hosted Sentry, or any
compatible ingest. It is **off by default**: with no DSN configured there is no
client, no transport, and nothing leaves the process. Set one environment
variable to turn it on:

```sh
# The DSN is the on/off switch. Supply it directly…
export GATEWAY_SENTRY_DSN='https://<key>@glitchtip.example.com/<project>'
# …or via a file (docker-secrets convention; trailing whitespace trimmed):
export GATEWAY_SENTRY_DSN_FILE=/run/secrets/gateway-sentry-dsn

# Optional tuning (all read only when a DSN is set):
export GATEWAY_SENTRY_ENVIRONMENT=production        # default: production
export GATEWAY_SENTRY_TRACES_SAMPLE_RATE=0.0        # default: 0.0 (errors only)
export GATEWAY_RELEASE="$(git rev-parse --short HEAD)"  # default: name@version
```

What it reports, once enabled:

- `tracing` **ERROR** events become issues; **WARN/INFO** ride along as
  breadcrumbs for context; DEBUG/TRACE are ignored.
- **Panics** are captured as issues.
- It sits **alongside** the structured JSON logs (`RUST_LOG`), never replacing
  them.

Safety properties:

- **No PII** is ever attached, and a redaction pass scrubs any field, tag, or
  header whose key looks like a secret (`dsn`, `token`, `passphrase`,
  `authorization`, `seed`, `mnemonic`, …) before an event is sent.
- A **malformed** DSN (or an out-of-range sample rate) fails the boot loudly,
  rather than silently disabling — a monitoring rollout never quietly no-ops on
  a typo. An **absent** DSN is the silent, inert path.
- The monitoring transport talks **only** to the operator-configured DSN host.
  Because that host is operator configuration (not user input) it does not pass
  through the gateway's user-facing outbound egress guard; the carve-out is
  intentional and bounded to your own telemetry endpoint. See
  [docs/operators.md](../docs/operators.md).

The `keyring` and `admin` subcommands never initialise monitoring (they handle
key material and only print to stdout).

## Documentation

- [docs/operators.md](../docs/operators.md) — running the gateway in
  production: provisioning, funding, credentials, money semantics, chain
  providers, webhooks, day-2 operations, and a glossary.
- [docs/building-a-service.md](../docs/building-a-service.md) — building your
  own product on top of a gateway: the three integration surfaces and the
  patterns that keep your service honest.
- `/api/v1/docs` — interactive data-plane API reference, served by the binary.
- `/api/v1/openapi.json` and `/control/v1/openapi.json` — the machine-readable
  API contracts.
