# Building a service on top of the gateway

This guide is for a developer building their own product on a gateway — a
notarization app, a compliance archive, a publishing tool, anything that
wants Label 309 Proof-of-Existence under its own brand, auth, and billing.
The gateway was designed so that the hard parts (chain, storage, money) are
already a service; what you build is everything your users actually see.

This is a working model, not a proposal: the reference operator (CardanoWall)
runs its commercial product on exactly the surfaces described here. There is
no private door — if a flow works for the reference product, it works for
you, because it is the same API.

## The division of responsibility

The gateway — call it the **base plane** — owns the full publish pipeline
and the state behind it:

- PoE publish: quote → upload → publish, with exact fees.
- Cardano: transaction build, submit, confirm, reorg handling, and
  auto-refund on permanent failure.
- Storage: content upload to Arweave, charged per byte, with operator-side
  funding.
- The on-chain records index: a shared, anonymous-friendly feed of every
  Label 309 record on the network.
- The account balance ledger and pricing (FX, margins).

Your service — the **vendor plane** — owns everything vendor-shaped:

- Your user accounts, sessions, and authentication.
- Your billing rail (cards, invoices, crypto — whatever you collect money
  with) and your pricing presentation.
- Your UI, your email, your product semantics on top of records.

The base plane keeps its state in its own Postgres schemas (`cw_core`,
`cw_api`). **Your tables never go in those schemas, and your code never
queries them.** Sharing one Postgres instance is fine — schema coexistence
is the supported deployment shape — but the boundary is the schema, not the
database: your vendor plane lives in its own schemas and talks to the base
plane only over HTTP and webhooks. Everything below follows from that one
rule.

## The three integration surfaces

Each plane has a single configured **base URL that already includes its version
segment** — the data-plane base ends `/api/v1`, the control-plane base ends
`/control/v1`. Configure those two bases once (the published SDKs take them
verbatim); every call below is written as the bare resource suffix you append to
the matching base. Reaching a future `v2` surface is a base-URL change
(`…/api/v2`), not a client rewrite.

### 1. The data plane — acting as your user

Each of your users maps to a gateway **account**. When a user does something
that touches the base plane — requests a price, uploads content, publishes,
reads their balance — your backend mints a short-lived **account token** for
that user's account and the call proceeds under it:

```
POST {control base}/accounts/{account_id}/token   (your backend, operator credential)
  → { token, expires_at }                          (default 1 h, scoped)
```

The flow your product drives is quote → upload → publish (suffixes on the data
base):

1. `POST /poe/quote` — locks the price for 15 minutes.
2. `POST /poe/uploads` (or the resumable session routes for large files) —
   stores content, returns `ar://` URIs, charges per byte.
3. `POST /poe/publish` — debits the quoted amount and anchors the record on
   Cardano.

Balance reads (`GET /account/balance`, the SSE stream at
`/account/balance/events`) ride the same token. The records read surface
(`GET /records…`) is even simpler: it serves anonymous callers, so public verify
pages and explorers need no credential at all.

### 2. The control plane — your backend only

Your backend holds the **operator credential** (a 24-hour operator token in
steady state; the root secret only for wallet/source registration). With it
you:

- **Provision accounts** (`POST /accounts`) when your users sign up, and
  disable/enable them as your product demands.
- **Apply ledger adjustments** (`POST /accounts/{id}/ledger-adjustment`) when
  _your_ billing collects money. This is the credit rail: payment confirmed on
  your side → one positive adjustment with the payment id as the idempotency
  `ref`.
- **Set margins** (`PUT /accounts/{id}/margin`) when your pricing gives a
  customer a non-default rate.
- **Mint credentials** — account tokens for sessions, API keys
  (`POST /accounts/{id}/keys`) if your product exposes programmatic access.

### 3. The webhook firehose — your read-models

Register an operator firehose subscription (`POST /webhooks` on the control
base) pointing at your backend. The gateway pushes every lifecycle event on the
instance — `poe_status_changed`, `balance_changed`, the refund intents,
upload failures — signed with `Webhook-Signature` headers you verify against
the subscription secret.

The firehose is how you build **read-models** instead of polling or (worse)
reading base-plane tables. A "sent items" view — show each user the records
they published, with live status — is the canonical example: consume
`poe_status_changed` events, project them into your own table in your own
schema, and render from there. The same pattern serves billing
reconciliation (`balance_changed`, the refund intents) and ops dashboards.
Events are at-least-once: key your projections on the event/delivery id so a
redelivery is a no-op.

## Patterns that keep the integration honest

**The token-minting proxy.** Operator credentials never reach a browser or a
mobile app — not in JS, not in a cookie, not "temporarily". The client
authenticates against _your_ session system; your backend exchanges the
session for a short-lived, narrowly scoped account token and returns only
that. The token's scopes are the permission boundary: a publish page needs
`poe:create`, a balance widget needs `account:read`, and neither needs more.

**Credit-on-payment with idempotency refs.** Billing pipelines deliver
at-least-once: payment webhooks redeliver, jobs retry. Make the adjustment
idempotent by passing the payment's own id as `ref` — the gateway keys the
ledger entry on it, so five deliveries of one payment credit one balance,
once. Never apply a credit from a handler that lacks a stable originating
id.

**Displayed balance = gateway balance − your overlay.** The gateway's ledger
is the authority on spendable funds. If your product has its own
balance-affecting state (arrears from chargebacks, holds, promotional
display credits), subtract it at display time as an overlay — do not try to
mirror the gateway's ledger into your own tables and serve the mirror as
truth. Cache for rendering if you must, but every decision that gates a
spend should read the gateway.

**Trust the auto-refund.** When a publish fails permanently, the gateway
reverses the debit itself. Your UX can therefore promise "you are only
charged for what lands on-chain" without running reconciliation jobs: show
the failure (the firehose tells you), show the refunded balance, and move
on. Do not build a vendor-side refund path for publish failures — it would
double-refund.

**Verify webhooks, plan for rotation.** Verify every delivery's
`Webhook-Signature` (HMAC-SHA256 over `"{timestamp}.{body}"`) and enforce a
timestamp tolerance window. Secret rotation is two-phase on the gateway
side: during a rotation window deliveries are dual-signed, so a verifier
that accepts _any_ valid `v1` signature keeps working through the cutover.
Build that loop — fetch-secret, verify-either — before you need it.

## What you must NOT do

- **No SQL into `cw_core` or `cw_api`** — not even reads. The schemas are
  engine-internal and change without notice; the HTTP planes and the
  firehose are the contract. If a query feels missing, that is an API gap to
  raise, not a license to join across schemas.
- **No long-lived account tokens in clients.** Tokens default to one hour
  for a reason; mint per session and re-mint on expiry. A leaked token
  should be a one-hour problem, not an incident.
- **No balance caching as authority.** A cached balance is a rendering hint.
  The moment it gates a spend or a payout, you have re-implemented the
  ledger — wrongly, because the gateway debits, refunds, and adjusts without
  consulting your cache.
- **No scraping the index.** `GET /records` (with filters, pagination, and a
  count endpoint) serves the on-chain record feed, anonymously. Do not
  crawl explorers or replicate the chain scan — one gateway scan serves
  every consumer, which is the point of the shared index.
- **No operator credentials outside your backend.** Not in client bundles,
  not in mobile apps, not in a partner's hands. Anything that must act with
  operator authority is a backend endpoint of yours.

## Where the boundary pays off

Run this way, your service can be rebuilt, re-branded, or re-platformed
without touching chain or money state; the gateway can be upgraded without
knowing you exist; and an audit of "who moved money and why" reads from two
places only — the gateway's ledger and audit log, and your billing system —
joined by the idempotency refs you chose. The operator's own runbook for the
gateway side is [operators.md](operators.md).
