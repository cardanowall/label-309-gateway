# Operating a gateway in production

This guide is for the person running the gateway as a service that handles
real money: real ADA paying anchoring fees, real AR funding storage, real USD
balances debited on every publish. It walks the full operator lifecycle —
provisioning, funding, credentials, money semantics, chain providers,
webhooks, and day-2 operations — and ends with a glossary of every term of
art the gateway documentation uses.

The [README](../gateway/README.md) covers the quickstart and the full
configuration reference; this document explains what each moving part does and
what breaks when it is set wrong. Integrators building a product **on top of**
a gateway should read [building-a-service.md](building-a-service.md) instead.

## 1. Provisioning

### 1.1 Create the keyring offline

The keyring is the single age-encrypted file holding every key the gateway
signs with. On a production deployment those keys control real funds — the
Cardano key spends the ADA that pays anchoring fees, the Arweave key spends
the AR that funds storage credits — so create the keyring **on an offline
machine**, never on the server:

```sh
export GATEWAY_KEYRING_PASSPHRASE='…a strong passphrase…'
gateway keyring init             --path keyring.age
gateway keyring add-cardano      --path keyring.age --network mainnet
gateway keyring add-arweave      --path keyring.age
gateway keyring add-webhook-wrap --path keyring.age
gateway keyring inspect          --path keyring.age
```

Record the printed Cardano and Arweave addresses — both are funded and
registered later. Then move the ciphertext to the server and keep an offline
backup of **both** the file and the passphrase: the keyring is the only thing
that can spend the operator funds. The gateway has no key-export or sweep
path, so losing the keyring strands whatever ADA and AR sit on its addresses.

Properties you can rely on:

- The commands are file-local (no database, no network) and never print
  secret material — only labels, addresses, and key ids.
- Every entry's identity (the address a signing key derives to, or a
  webhook-wrap key's `whk_…` id) is re-derived at every unlock; any mismatch
  refuses the whole file. A keyring the CLI produces is always one the
  gateway can boot with — `keyring inspect` performs a real unlock, so a
  clean inspect is a boot rehearsal.
- Writes are atomic (temp file + rename) with owner-only permissions on
  Unix; a crash mid-write can never leave a truncated keyring.

### 1.2 Secrets via `_FILE` environment variables

Every secret the binary reads supports the docker-secrets convention: set
`GATEWAY_KEYRING_PASSPHRASE_FILE=/run/secrets/keyring-passphrase` instead of
putting the passphrase itself into the environment, and the gateway reads the
file with trailing whitespace trimmed (a mounted secret usually carries a
trailing newline). The same `_FILE` twin exists for the (optional) CoinGecko
key, the Koios key, the Blockfrost project id, and the new-passphrase input of
`keyring change-passphrase`. Supplying both the plain variable and its
`_FILE` twin is a load error — an ambiguous deployment fails loudly rather
than letting one source silently win.

Coin prices (ADA/USD and AR/USD, which a quote needs alongside the on-chain
fee) come from **keyless CoinPaprika** by default — no API key, no
registration, ~1,000 requests/day, well above the refresh cadence — so a
self-hosted gateway prices publishes with nothing to configure. To use
**CoinGecko** as the primary provider instead (CoinPaprika stays the
automatic fallback if it rate-limits), set `GATEWAY_COINGECKO_API_KEY` and
`[fx] coingecko_tier` to `"demo"` (free key) or `"pro"` (paid). A tier
without a key, or a key without a tier, is a boot error.

The config file itself never carries a secret: it can be committed and
reviewed. The keyring ciphertext is referenced by path only.

### 1.3 Bootstrap the operator and guard the root secret

```sh
gateway operator bootstrap --label acme
```

Against an empty (freshly migrated) database this creates exactly one
operator, registers the `manual_adjustment` ledger kind (so balance credits
work — see §4), and prints the **operator root secret exactly once**. It
cannot be re-printed, only re-minted. Store it immediately, with the same
care as the keyring passphrase.

The root credential is the instance-administrator authority: it is the only
credential that can register wallets and storage funding sources, and the
only one that can mint operator tokens. Day-to-day administration should run
on short-lived operator tokens (24 h default) minted from it; the root secret
itself should live in a secret store and surface only for the operations that
demand it. Always pass it through `GATEWAY_CONTROL_TOKEN` (or pipe it via
`--token-stdin`); the admin CLI deliberately has no argv token flag, because
argv leaks into shell history and process listings.

A re-run of `operator bootstrap` against an already-bootstrapped database
refuses rather than minting a surprise credential. `--allow-additional` opts
into provisioning a second operator for a genuinely multi-operator instance.

### 1.4 Register the wallet and the funding source

Registration is what turns a keyring entry into infrastructure the engine
will use. Both registrations are **root-gated and possession-checked**: the
control plane refuses any address the unlocked keyring holds no signing key
for, so a wallet the submit path could never sign — or a funding source no
key could draw from — is unrepresentable.

```sh
# GATEWAY_CONTROL_URL is the FULL control-plane base, including the version
# segment; every admin call and the curl examples below append only a bare
# resource suffix.
export GATEWAY_CONTROL_URL=http://127.0.0.1:8080/control/v1
export GATEWAY_CONTROL_TOKEN='ctl_…root secret…'

# The Cardano wallet (the address printed by `keyring add-cardano`).
gateway admin wallet register primary addr1… mainnet

# The Arweave funding source — the one-shot bootstrap infers the single
# keyring Arweave key and the single operator, and converges on re-runs.
gateway storage bootstrap --backend turbo --label primary
```

Each registration auto-issues a grant that says who may use the asset. With
no explicit scope it uses the configured default (`default_wallet_scope` /
`default_storage_scope`, both `service` out of the box): `service` means
every account on the instance may use it — the single-tenant posture.
`operator` restricts it to the registering operator until further grants are
issued, and an `account` grant dedicates it to one named account. Grants can
be issued and revoked later (`gateway admin wallet grant`, `storage source
grant`), which is how a multi-tenant instance gives a customer a dedicated,
self-funded wallet.

## 2. Funding lifecycle

### 2.1 ADA: the band and UTxO grooming

Send ADA to the registered wallet address. You do not manage UTxOs yourself —
the wallet maintenance and replenish loops continuously groom the wallet into
**canonical UTxOs**: outputs whose value falls inside the configured
`[band]`, minted at the band's `mid` value. Each publish leases exactly one
canonical UTxO (for at most `lease_secs`; a reaper reclaims leases whose
holder died), spends it as the fee input, and returns change the grooming
loop folds back into fresh canonical outputs.

The band exists so that **fees are exact, not estimated**. The band's
endpoints must share a CBOR integer width and must leave room for a change
output under the largest record the deployment accepts; at boot the binary
certifies the band is _fee-shape-stable_ against every size in
`fee_shape_record_sizes` under the live protocol parameters, and refuses to
start otherwise. The practical consequences:

- If you raise the maximum record size you accept, extend
  `fee_shape_record_sizes` to cover it — otherwise a record larger than the
  certified spread could produce a fee the quote did not predict.
- `min_canonical_count` is the per-wallet concurrency floor: publishes queue
  when no canonical UTxO is free, so a wallet serving many concurrent
  publishes needs a higher count (and enough ADA to back it).
- A wallet running dry of groomable ADA stops replenishing; the symptom is
  publishes queueing on the lease. Watch the wallet statistics
  (`gateway admin wallet list` / `GET /control/v1/wallets`).

### 2.2 AR → winc: the storage top-up rail

Turbo uploads are not paid in raw AR — they draw **winc** (winston credits),
a prepaid balance held at the upload provider. Funding storage is therefore
two steps: send AR to the keyring's Arweave address, then convert a chosen
amount into winc through the control plane:

```sh
gateway admin storage top-up 500000000000 topup-2026-07-01-a

# The same call over raw HTTP (POST /control/v1/storage/top-up):
curl -X POST "$GATEWAY_CONTROL_URL/storage/top-up" \
  -H "authorization: Bearer $GATEWAY_CONTROL_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"ar_amount_winston": "500000000000", "idempotency_key": "topup-2026-07-01-a"}'
```

`ar_amount_winston` is a decimal string in winston (1 AR = 10¹² winston; the
example converts 0.5 AR). `idempotency_key` is required: your unique name for
this conversion (a UUID works). `funding_source_id` may be supplied explicitly
and is inferred while the operator owns exactly one active source for the
backend. What the call does, and the guarantees it gives:

- It signs and broadcasts an on-chain AR transfer from your funding wallet to
  the provider's deposit wallet, then registers the transaction id with the
  payment service, which credits the winc once the transfer confirms.
- The live wallet balance must cover amount + network fee or the request is
  refused **before signing** — a top-up can never bounce after moving funds.
- The conversion is **irreversible**: winc never converts back to AR. Start
  small and top up incrementally rather than converting your reserve.
- The call is **idempotent on `idempotency_key`** (scoped to your operator),
  like a ledger adjustment on its `ref`. If the response is lost — a timeout,
  a proxy error, a double-submit — retry with the **same key**: the gateway
  replays the journalled conversion (a 200 with the same record, nudged
  forward if it had not finished registering) instead of signing a second
  transfer. Only a new key creates a new conversion (a 201). Reusing a key
  with a different amount or source is refused.
- A broadcast or registration failure is recorded on the returned journal
  record and is retried **forward** with
  `gateway admin storage top-up-register <topup_id>`
  (`POST /control/v1/storage/top-ups/{topup_id}/register`), which
  re-broadcasts the persisted, byte-identical transaction and re-registers the
  same id. It never re-signs — a re-sign would mint a second transfer and move
  the funds twice. The journal (`gateway admin storage top-ups`, or
  `GET /control/v1/storage/top-ups`, newest first) is the audit trail for
  every conversion.

The credited balance becomes visible to the upload path when the **winc
reconcile loop** next runs (`winc_refresh_schedule`, every five minutes by
default — it is the only winc network caller). Until then, uploads above the
free window may be refused as unfunded; that is expected, not a fault.

Two safety knobs ride the believed-winc balance:

- `winc_safety_floor` — uploads are refused when the believed balance is
  below this. Zero (the default) refuses only a truly unfunded source; set a
  positive floor to keep a reserve that in-flight uploads can settle against.
- `winc_drift_alert_threshold` — the reconcile loop alerts when the live
  provider balance differs from the believed balance by more than this, i.e.
  the balance moved in a way the gateway's own charges do not explain (a
  shared key being drawn elsewhere, or a provider-side adjustment).

Visibility: `gateway admin storage operator-balance`
(`GET /control/v1/storage/operator-balance`) is a **live** provider read
(on-chain AR per funding wallet, live winc on Turbo) for an explicit operator
refresh; `gateway admin storage funding` (`GET /control/v1/storage/funding`)
is the cached cross-source roll-up (believed winc, provider-reported fundable
bytes, stale-source count) and makes no provider call. The admin console's
Storage tab surfaces both.

### 2.3 The free storage window

`free_storage_bytes` (default 100 KiB) is the per-upload size at or under
which content is stored without a storage charge — neither the account's USD
balance nor your winc pays for it. It exists so that hashes-plus-tiny-payload
use stays frictionless. Every byte above the window is charged to the account
at the quoted per-byte rate and drawn from your winc at upload time. Raising
the window is a marketing decision with a direct winc cost: you pay the
provider for every "free" byte.

## 3. The credential model

Four credential classes, strictly layered. The control plane resolves a typed
principal from every bearer; a credential class presented to the wrong plane
is rejected outright (an operator credential can never act on the data plane,
and vice versa).

| Credential         | Lifetime                       | Minted by                                               | Authority                                                                                                                          |
| ------------------ | ------------------------------ | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Root secret**    | until rotated or revoked       | `gateway operator bootstrap` / `credential rotate-root` | Everything an operator token can do, **plus** wallet/source registration, token/credential revocation, and operator-token minting. |
| **Operator token** | 24 h (config.) / until revoked | `POST /control/v1/operator/token` (root only)           | The control plane: accounts, keys, tokens, adjustments, margins, grants, drains, webhooks, audit.                                  |
| **Account token**  | 1 h (config.) / until revoked  | `POST /control/v1/accounts/{id}/token`                  | The data plane, as that account, with exactly the scopes named at mint.                                                            |
| **API key**        | until revoked                  | `POST /control/v1/accounts/{id}/keys`                   | The data plane, as that account, with exactly the scopes granted at creation.                                                      |

Account tokens are the bridge a wrapper service uses for its own end users:
the wrapper's backend holds the operator credential, mints a short-lived
account token per user session, and hands only that token to the client. API
keys are the long-lived form for programmatic integrators. Both carry an
optional `rate_limit_per_min` budget (1 to 1,000,000); without one they meter
against the data-plane default of 600 requests/minute. A batch publish costs
one rate token per record.

Revocation is layered the same way the authority is. Every minted token
records the credential that minted it, and a token authenticates only while
its whole mint lineage is un-revoked — so revoking a root credential
instantly kills the operator tokens it minted and the account tokens minted
beneath them, and revoking one operator token kills the account tokens minted
under just that token. Expiry is not part of the chain: an ancestor lapsing
naturally never invalidates a still-live child. See §8.1 for the rotation and
targeted-revocation runbook.

### 3.1 Scopes

A scope names a slice of the data plane a credential may use. The legal set
is a **registry** (`cw_core.api_scope`), not a hardcoded enum: minting
validates every requested scope against the registry and rejects unknown ones
with a problem that lists the registered names, so a typo cannot mint a dead
credential. The core scopes and what each actually gates:

| Scope            | Gates                                                                                                                                                             |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `poe:create`     | `POST /poe/quote`, `/poe/publish`, `/poe/publish-batch`, `/poe/uploads`, and the resumable upload sessions. The spend scope: everything that can debit a balance. |
| `poe:read`       | The records list/get/count routes and the per-record SSE stream — when called **with** a bearer. The same routes also serve anonymous callers (see below).        |
| `account:read`   | `GET /account/balance`, `GET /account/ledger`, and the balance SSE stream.                                                                                        |
| `webhooks:read`  | Listing and reading the account's webhook subscriptions and their deliveries.                                                                                     |
| `webhooks:write` | Creating, patching, deleting subscriptions; retrying deliveries; rotating signing secrets.                                                                        |
| `billing:read`   | Reserved in the registry for vendor billing surfaces; gates no engine route today.                                                                                |

A vendor may register additional scope rows and enforce them in its own
routes; the engine treats a vendor scope exactly like a core one.

The records read surface is deliberately **anonymous-friendly**: `GET
/records`, `/records/count`, and `/records/{tx_hash}` serve
callers with no bearer at all, returning the public anchored rows with no
ownership projection. A bearer, when present, must still be valid and scoped
— a bad token is rejected, not downgraded to anonymous. This is what makes
the records index a public good rather than a per-tenant view.

Anonymous does not mean unmetered: callers with no bearer meter against a
per-client-address budget (`[http] anon_rate_limit_per_min`, default 120/min
with the limiter's usual 2x burst), keyed on the hashed socket peer address —
never a forgeable `X-Forwarded-For`. Behind a reverse proxy every anonymous
caller shares the proxy's address and therefore one pooled budget; size the
knob for that aggregate. The reads themselves run under a server-side
statement timeout, so a pathological filter is killed rather than left pinning
a database backend.

### 3.2 Abuse bounds on long-lived and slow requests

Two bounds sit beside the per-request rate limits, because neither abuse is a
request-rate problem:

- **Live SSE streams are capped** (`[http] sse_max_streams`, default 1024
  instance-wide; `sse_max_streams_per_account`, default 32). A stream is
  long-lived state, so its cost is concurrency: an open beyond a ceiling is a
  `429`, and the slot frees the moment a stream disconnects. All streams share
  ONE Postgres listener connection per instance, so stream count never
  translates into database backends.
- **Ordinary requests carry a wall-clock ceiling** (`[http]
request_timeout_secs`, default 30): a drip-fed body or a wedged handler is
  cut off with a `408` instead of holding its connection open indefinitely.
  The streaming surfaces — both SSE streams, the single-shot upload, the chunk
  PUT, and session `complete` — are exempt: they are long-running by design
  and carry their own bounds (the stream caps above; the upload byte ceilings
  and the storage `upload_timeout`).

## 4. Money semantics

The gateway is the **authority on account balances**. Every account has one
USD balance (stored in micro-USD), and every movement is a ledger entry —
there is no out-of-band balance write.

### 4.1 The spend path: quote → publish → (auto-refund)

1. `POST /api/v1/poe/quote` prices a publish — network fee from the FX
   snapshot (or the static rate), storage from the per-byte rate, your margin
   on top — and locks it for 15 minutes under a `quote_id`. Quoting reads
   only cached pricing rows; it never calls an external oracle.
2. `POST /api/v1/poe/publish` debits the quoted amount and runs the chain
   pipeline. Overdraft is refused — a publish an account cannot afford never
   starts.
3. Uploads are charged per byte at upload time (over the free window),
   independent of the publish debit.
4. If a publish fails **permanently** (the chain pipeline exhausts its
   options), the engine reverses the debit itself with a refund ledger entry.
   The operator does not reconcile failed publishes by hand, and a wrapper's
   UX can treat the ledger as truth.

### 4.2 Ledger adjustments — how money enters an account

A **ledger adjustment** (`POST
/control/v1/accounts/{account_id}/ledger-adjustment`) is the one way an
operator moves an account balance directly: a signed micro-USD delta plus a
mandatory reason. It is how _every_ credit reaches an account in practice —
when your billing system collects a payment (a card charge, an invoice, a
welcome grant), the confirmed payment becomes a positive adjustment. Negative
adjustments handle corrections and manual settlements; like every
non-overdrawing kind, one that would drive the balance negative is refused.

Two properties make adjustments safe to drive from an at-least-once billing
pipeline:

- **Idempotency.** Pass the originating event's id as `ref` (e.g. the
  payment id). The entry is keyed on (kind, ref), so a redelivered webhook or
  a retried job applies the credit exactly once. Omit `ref` and a fresh
  per-call ref is minted — fine for a one-off manual grant, wrong for
  anything automated.
- **The adjustment cap.** `adjustment_cap_usd_micros` (default $10,000)
  bounds the absolute size of a single adjustment. It is a blast-radius
  limit, not a business rule: a fat-fingered `amount_usd_micros` (entering
  cents as dollars), a buggy retry loop, or a compromised operator token can
  each move at most one cap's worth per call, and every call lands in the
  audit log. If your business legitimately credits more than the cap in one
  event, raise the cap deliberately — do not split a real payment into
  cap-sized pieces, which only blunts the audit trail.

The `manual_adjustment` ledger kind is registered by `operator bootstrap`
(the engine itself seeds only its own kinds: the publish debit and the two
refunds). The adjustment reason (minimum 3 characters) is stored on the
entry, so the ledger always says _why_ a balance moved.

### 4.3 Margins

Quotes are priced as cost of goods plus a markup. `margin_pct` in `[http]` is
the operator default; `gateway admin account margin set <account_id>
<margin_pct>` (`PUT /control/v1/accounts/{account_id}/margin`) sets a per-account
override, and `gateway admin account margin unset <account_id>` (`DELETE`)
reverts to the default. The engine models
only default-vs-override — a wrapper with its own pricing policy computes the
effective percentage and pushes it here.

## 5. Chain providers

The gateway talks to Cardano through HTTP providers. The primary is **Koios**;
the optional secondary is **Blockfrost**.

- **Keyless Koios** (the default) allows roughly 5,000 requests/day — enough
  for development and a cold start, weak at production cadence. The symptom
  of exhaustion is 429s: submits retry, the indexer falls behind, the tip
  goes stale, and `/api/v1/health` reports degraded.
- **A Koios API key** (`GATEWAY_KOIOS_API_KEY(_FILE)`) is sent as
  `Authorization: Bearer` on every Koios request and lifts the deployment to
  the registered tier's quota. This is the cheapest production fix.
- **A self-hosted Koios** (`[chain] koios_url`) replaces the per-network
  public URL for _every_ Koios call — the chain gateway, the
  protocol-parameter source, and the replenisher's UTxO source — removing the
  public tiers' limits entirely. One hard responsibility transfers to you:
  the URL **must** serve this deployment's network. The gateway cannot verify
  that cheaply (a Koios `/tip` carries no network identifier); on a mismatch
  the index scans the wrong chain while submits are deterministically
  rejected by the nodes — each rejected publish is abandoned and
  auto-refunded, so users are made whole, but the service is effectively
  down.
- **Blockfrost failover** (`GATEWAY_BLOCKFROST_PROJECT_ID(_FILE)` or `[chain]
blockfrost_project_id_path`): with a project id configured, a Koios rate
  limit fails over to Blockfrost instead of parking both provider arms behind
  one Koios tier.

Independently of provider quotas, the gateway enforces its own **egress
budget** per provider (`egress_requests_per_minute` = 30, `egress_burst` =
300 by default). The defaults cap a runaway loop below the keyless Koios
daily quota while sitting far above the legitimate steady state; raise them
when you run a keyed or self-hosted provider. `gateway admin chain
provider-usage [days]` (`GET /control/v1/chain/provider-usage`) reports
per-(provider, network, day) counts of requests issued and requests the local
budget denied — the first place to look when chain operations feel slow.

## 6. Webhook operations

The gateway pushes events over webhooks on two surfaces: **account
subscriptions** on the data plane (`/api/v1/webhooks`, an account watching
its own activity) and the **operator firehose** on the control plane
(`/control/v1/webhooks`, every event on the instance — the feed a wrapper
builds its read-models from). Both seal their signing secrets at rest under
the keyring's webhook-wrap key; a keyring without one reports the feature
unavailable on both planes.

The published event vocabulary (the same names the SSE streams use):
`poe_status_changed`, `cardano_submission_failed`, `balance_changed`,
`storage_upload_failed`, `poe_refund_intent`, `storage_refund_intent`, and
`webhook_endpoint_disabled`. Refund-intent events are operator-only — they
drive billing hooks and never reach an account subscription.

Operational facts:

- **Signing.** Every delivery carries
  `Webhook-Signature: t=<unix>,v1=<hex>` — an HMAC-SHA256 over
  `"{timestamp}.{body}"` per active secret — plus `Webhook-Id` (the dedupe
  key, stable across redeliveries) and `Webhook-Timestamp` (re-stamped fresh
  on each send so the receiver's tolerance window passes).
- **Secret rotation is two-phase.** `POST …/{id}/rotate-secret` mints a
  successor secret and returns its plaintext exactly once; while the window
  is open every delivery is dual-signed (one `v1` per active secret), so a
  receiver fleet validates with either. When the fleet is cut over, `POST
…/rotate-secret/commit` promotes the successor. The commit is explicit —
  never automatic on first success — so a multi-instance receiver is not cut
  over before all of its instances are ready.
- **Delivery health.** Failed deliveries land in the dead-letter view
  (`gateway admin webhook deliveries <id>`) and can be redriven
  (`gateway admin webhook delivery-retry <id> <delivery_id>`). A flapping
  endpoint is auto-disabled by the delivery worker, announced by
  `webhook_endpoint_disabled`. `gateway admin webhook health`
  (`GET /control/v1/webhooks/health`) summarizes delivery health across the
  operator's subscriptions — put it on a dashboard.
- **Egress posture.** Registration and delivery share one URL-safety
  configuration: HTTPS-only targets and the loopback/private-range block,
  both always on by default. The two opt-outs are independent axes:
  `[webhooks] allow_insecure_http` (self-host) permits `http://` targets and
  nothing else — the range-block stays enforced, so tenants still cannot point
  deliveries at loopback, RFC 1918, or cloud-metadata addresses — while
  `egress_allow_loopback` (test rigs only) opens the range-block. Neither
  belongs in production, where the range-block is the SSRF guard.

## 7. The admin console

With `admin_ui_enabled = true` (the default) the binary serves a static,
no-build admin page at `/admin`: a thin HTTP client of the control plane with
tabs for Accounts, Keys, Wallets, Storage, Webhooks, and Audit. It holds no
authority of its own — you paste an operator token (or, for the root-gated
registrations, the root secret) and every action is an ordinary control-plane
call under that credential, audit-logged like any other.

Because the console is served on the same socket as the APIs, "who can reach
`/admin`" equals "who can reach the control plane". The recommended posture
is to not expose the gateway's port publicly at all — front the data plane
with your own ingress and reach `/admin` over an SSH tunnel or private
network. Set `admin_ui_enabled = false` if your deployment must not serve it.

## 8. Day-2 operations

### 8.1 Rotations

- **Cardano wallet**: `gateway keyring add-cardano` (new key, new address) →
  restart the gateway (it unlocks the keyring at boot) → `gateway admin
wallet register` the new address → fund it → `gateway admin wallet drain
<old-wallet-id>`. A draining wallet takes no new publish leases; in-flight
  work settles. Keep the old key in the keyring until its address is empty —
  remember there is no sweep path, so move remaining ADA with the drain +
  natural spend-down, or reclaim it manually from the decrypted key.
- **Arweave funding source**: `gateway keyring add-arweave` → restart →
  register the new source → top it up → `gateway admin storage source drain
<source_id>` on the old one. A draining source takes no new charges; in-flight
  uploads settle by source id and are never stranded.
- **Webhook-wrap key**: `gateway keyring add-webhook-wrap` — the newest
  wrap entry is the active one, so adding a key _is_ the rotation. Existing
  sealed secrets still open under the older entry; remove it only after
  re-sealing (rotating) the subscriptions you care about.
- **Keyring passphrase**: `gateway keyring change-passphrase`, then update
  the deployed passphrase secret and restart. The ciphertext changes;
  refresh your offline backup.
- **Operator root secret**: `gateway admin credential rotate-root` (or `POST
/control/v1/operator/root/rotate`, presenting the root). One transaction
  revokes the presented root and mints its successor, printed exactly once —
  you are never left rootless, and a revoked root can never mint its own
  replacement. Revocation cascades through the mint lineage instantly: every
  operator token minted from the old root, and every account token minted
  beneath those, stops authenticating the moment the rotation commits. API
  keys are **not** touched — they are account-owned data-plane credentials,
  not derivations of control-plane authority. After rotating, mint fresh
  operator tokens from the new root and update wherever your automation
  stores them. For a suspected leak: rotate first (the kill switch), then
  read the audit trail (`gateway admin audit tail`) for what the old
  credential chain did while exposed.
- **A single leaked token**: `gateway admin token revoke <token_id>` kills
  one operator or account token without a full rotation; anything minted
  under it dies with it. Enumerate candidates with `gateway admin token
list` (mint time, account binding, lineage) — token secrets are
  unrecoverable by design, so the roster shows ids and lifecycle only.
  `gateway admin credential list` / `credential revoke <credential_id>` do
  the same for root credentials; revoking your only live root is refused
  (rotate instead, or provision an additional root first). Otherwise tokens
  simply expire on their own (24 h default for operator tokens); mint
  replacements as needed.

### 8.2 The audit trail

Every control-plane mutation lands in the administrative audit log: who (the
resolved principal), what (the action and target), and when. Query it with
`GET /control/v1/audit` — filterable by actor kind (`operator`, `account`,
`system`), action, and target type — or `gateway admin audit tail [limit]`
for the recent slice. Ledger adjustments, credential mints, grants, drains,
and registrations all appear here; the audit log plus the balance ledger
together reconstruct every money-relevant decision.

### 8.3 What to monitor

| Signal                                        | Where                                                  | Meaning when it fires                                                             |
| --------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------- |
| Health probe degraded (503)                   | `GET /api/v1/health`                                   | Database unreachable or the chain tip is stale (indexer behind / provider quota). |
| Canonical UTxO count low / publishes queueing | `gateway admin wallet list`, `GET /control/v1/wallets` | Wallet under-funded or `min_canonical_count` too low for the load.                |
| Believed winc near the safety floor           | `GET /control/v1/storage/funding`                      | Storage about to refuse paid uploads; run a top-up.                               |
| Winc drift alert                              | gateway logs (reconcile loop)                          | Provider balance moved in a way the gateway's charges do not explain.             |
| `storage.attempt.stuck`                       | gateway logs (recovery sweep)                          | An upload attempt has been provider-unreachable for `attempt_stuck_passes`.       |
| Webhook health / `webhook_endpoint_disabled`  | `GET /control/v1/webhooks/health`, the firehose        | A receiver is failing; deliveries are dead-lettering.                             |
| Provider egress denials                       | `GET /control/v1/chain/provider-usage`                 | The local egress budget is throttling — raise it or fix the loop driving it.      |

The binary logs structured JSON (filtered by `RUST_LOG`, default `info`),
designed for a log aggregator.

### 8.4 Error monitoring (Sentry / GlitchTip)

Alongside the JSON logs, the gateway can report errors and panics to any
Sentry-compatible backend — self-hosted [GlitchTip](https://glitchtip.com),
hosted Sentry, or any compatible ingest. It is **opt-in and off by default**:
with no DSN configured there is no client, no transport, and nothing leaves the
process.

Turn it on by setting the DSN (the on/off switch), supplied like every other
secret either directly or through a `_FILE` twin (§1.2):

```sh
export GATEWAY_SENTRY_DSN_FILE=/run/secrets/gateway-sentry-dsn
# Optional, read only when a DSN is set:
export GATEWAY_SENTRY_ENVIRONMENT=production            # default: production
export GATEWAY_SENTRY_TRACES_SAMPLE_RATE=0.0            # default: 0.0 (errors only)
export GATEWAY_RELEASE="$(git rev-parse --short HEAD)"  # default: name@version
```

Once enabled, `tracing` ERROR events become issues (WARN/INFO ride along as
breadcrumbs) and panics are captured. Operationally:

- **It complements, never replaces, the JSON logs.** Everything in the table
  above is still the source of truth; the monitoring is for getting paged on the
  errors and panics among it.
- **Secrets never leave the box.** No PII is attached, and a redaction pass
  blanks any field, tag, or header whose key looks sensitive (`dsn`, `token`,
  `passphrase`, `authorization`, `seed`, `mnemonic`, `keyring`, …) before an
  event is sent. This is defense-in-depth on top of the field hygiene the binary
  already applies (the keyring passphrase is zeroized, provider keys redact in
  debug output).
- **A bad DSN fails the boot.** A malformed DSN — or a sample rate outside
  `0.0..=1.0` — aborts startup loudly, so a monitoring rollout never silently
  no-ops on a typo. Leaving the DSN unset is the only way to disable it.
- **Egress carve-out.** The monitoring transport is a separate client that
  talks **only** to the DSN host you configured. Because that host is operator
  configuration rather than user input, it deliberately does **not** pass
  through the user-facing outbound-egress guard (the SSRF/range-block that wraps
  user-influenced requests, §6). The carve-out is intentional and bounded to
  your own telemetry endpoint — there is no deny-host list on your DSN.
- The `keyring` and `admin` subcommands never initialise monitoring (they
  handle key material and only print to stdout).

## Glossary

- **Operator** — the party that runs and administers a gateway instance (or a
  tenant on a shared instance). The hard isolation boundary: accounts,
  wallets, sources, and audit rows all hang off an operator.
- **Account** — a customer of an operator: the unit that owns a balance,
  publishes records, and holds credentials. There is no separate "user"
  entity below it.
- **Credential** — anything a bearer header can carry: the root secret, an
  operator token, an account token, or an API key. Each resolves to a typed
  principal valid on exactly one plane.
- **Root secret / root credential** — the instance-administrator credential
  printed once by `operator bootstrap`. The only credential that can register
  wallets/sources or mint operator tokens.
- **Operator token** — a short-lived (default 24 h) control-plane credential
  minted from the root secret; the day-to-day administration credential.
- **Account token** — a short-lived (default 1 h) data-plane credential an
  operator mints for one account, carrying explicit scopes; the bridge a
  wrapper uses for its end users.
- **API key** — a long-lived, revocable data-plane credential bound to one
  account with explicit scopes and an optional rate budget.
- **Scope (API scope)** — a registry-validated string naming a slice of the
  data plane a credential may use (`poe:create`, `account:read`, …). Distinct
  from a grant scope (below).
- **Grant** — the authorization record that lets a party use a wallet (spend
  grant) or a funding source (draw grant). Its scope is `service` (everyone
  on the instance), `operator` (the registrar), or `account` (one named
  account).
- **Possession check** — the registration-time proof that the keyring
  actually holds the signing key behind an address, so unspendable wallets
  and unbackable sources cannot be registered.
- **Keyring** — the single age-encrypted file holding every key the gateway
  signs with (Cardano, Arweave, webhook-wrap). One passphrase, one unlock at
  boot.
- **Webhook-wrap key** — the keyring data key webhook signing secrets are
  encrypted under at rest. The newest wrap entry is the active one.
- **Band** — the closed lovelace range `[min, max]` a canonical UTxO must
  fall in, with `mid` the value the replenisher mints. Sized so fees are
  exact for every certified record size.
- **Canonical UTxO** — a wallet output groomed into the band, ready to fund
  exactly one publish.
- **Fee-shape certification** — the boot-time check that the band stays
  fee-stable across `fee_shape_record_sizes` under live protocol parameters;
  the gateway refuses to start if it fails.
- **Lease** — the exclusive short-lived claim a publish takes on a canonical
  UTxO (`lease_secs`); a reaper reclaims leases whose holder died.
- **Funding source** — a registered (backend, Arweave address) pair: the
  prepaid credit pool storage uploads draw from.
- **Winston** — the smallest AR unit (1 AR = 10¹² winston).
- **Winc** — winston credits: the prepaid balance held at the upload
  provider. Bought irreversibly from AR via the top-up rail; spent per
  uploaded byte.
- **Top-up** — the journaled, forward-retryable conversion of on-chain AR
  into winc (`POST /control/v1/storage/top-up`).
- **Free storage window** — the per-upload byte size (`free_storage_bytes`)
  at or under which content is stored without charge.
- **Ledger kind** — the registered type of a balance ledger entry (publish
  debit, the refunds, `manual_adjustment`, vendor kinds). A kind declares
  whether it may overdraw.
- **Ledger adjustment** — the operator-applied signed balance delta (a
  credit from your billing rail, a correction); idempotent on its `ref`,
  capped per call by `adjustment_cap_usd_micros`.
- **Idempotency ref** — the caller-supplied key pinning a ledger entry to
  its originating event so retries and redeliveries apply exactly once.
- **Quote** — the 15-minute price lock a publish must reference; priced from
  the cached FX snapshot plus the effective margin.
- **Margin** — the markup over cost of goods: an operator default with an
  optional per-account override.
- **FX snapshot** — the cached pricing row the `[fx]` refresh cron writes;
  the only thing quotes read (quote requests never call an external oracle).
- **Records index** — the gateway's forward scan of all Label 309 records on
  its network, served operator- and account-agnostically at `/api/v1/records`
  (anonymous reads welcome).
- **Hash-only deployment** — a gateway with no `[storage]` section: publishes
  carry hashes (and externally hosted URIs) but the instance stores nothing.
- **Staging / durable staging** — the scratch directory uploads stream
  through, and the crash-safe directory a reserved attempt's content is
  promoted to so the recovery sweep can re-POST it.
- **Recovery sweep / reconcile horizon** — the loop that resolves upload
  attempts left in flight by a crash, acting only after
  `reconcile_horizon_secs` so a slow-but-live upload is never swept.
- **Firehose** — the operator-scoped webhook stream of every event on the
  instance; the feed a wrapper builds its read-models from.
- **Subscription** — one registered webhook endpoint (account-scoped or
  operator firehose) with its sealed signing secret and event filter.
- **Rotation window** — the period between `rotate-secret` and its `commit`,
  during which deliveries are dual-signed with both secrets.
- **Drain** — the graceful retirement state for a wallet or funding source:
  no new work, in-flight work settles; reversible for wallets via
  `reactivate`.
- **Egress budget** — the gateway's own per-provider request rate cap
  (sustained + burst), protecting provider quotas from runaway loops.
- **Problem type** — the RFC 7807 `type` URL on every API error, built from
  `problem_type_base`; every code is dereferenceable at `/api/v1/errors`.
