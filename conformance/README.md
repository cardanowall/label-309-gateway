# Conformance harness

Proves the gateway's `/api/v1/*` surface is byte-stable against the PUBLISHED
Label 309 SDK/CLI artifacts. Every driver pins the exact released version as a
normal registry dependency (never an in-repo path), so a regression in the
gateway's wire shape surfaces as a deserialize failure in the real artifact a
third party would install.

The pinned release is `0.8.0`. It is declared in the manifests (`Cargo.toml`
for the Rust SDK, `tools/package.json` for the TypeScript SDK) and passed to
`cargo install` for the CLI; bump it there when the published Label 309
artifacts advance. The versions named below track those manifests.

The harness BOOTS the in-repo gateway over a fresh, isolated database
(`BootedGateway::start`), wires the pricing seam a deployment supplies, serves the
engine router on an ephemeral port, and seeds an operator/account/api-key
directly (key issuance is a later milestone). The published clients then drive it
over real HTTP. The chain side is stubbed (`BootedGateway::stub_confirm` anchors a
record into the indexer exactly as the confirm loop's threshold flip would); the
one live preprod leg lives in the gate.

## What it drives

- **Rust SDK** (`tests/published_clients.rs`) — the published `cardanowall`
  crate (`=0.8.0`), a registry dependency of this crate. Drives the full
  quote -> publish -> dedup -> confirm -> records list/get -> balance flow and
  proves: the quote `amount`/`currency` decode, the 202-vs-200 dedup signal (one
  debit), the owner-only `account_id` projection, and the anonymous-reader
  privacy invariant.
- **TypeScript SDK** (`tools/sdk-ts-flows.mjs`, driven by
  `tests/published_ts_sdk.rs`) — the published `@cardanowall/sdk-ts@0.8.0` via
  npm. Same quote/publish/dedup/balance flow through the real TS deserializers.
- **CLI** (`tests/published_cli.rs`) — the installed `cardanowall` binary
  (`cargo install cardanowall-cli --version 0.8.0`). Its `submit` drives the
  gateway's quote + publish; its `verify` runs the standalone verifier against a
  real, already-anchored transaction through a public explorer.
- **SSE durable resume** (`tests/sse_resume.rs`) — a raw HTTP/1.1 client (the
  published SDK does not consume SSE). Disconnects mid-stream, reconnects with
  `Last-Event-ID`, and asserts exactly the missed events replay, none lost, none
  duplicated.
- **Webhooks** (`tests/webhook_conformance.rs`) — the account-scoped and
  operator-firehose webhook surface plus a harness-local receiver sink
  (`src/receiver.rs`). Covers registration/lifecycle, signed delivery and receiver
  verification, retry-on-500 and dedupe, per-subject ordering with no
  cross-subscription head-of-line blocking, the dual-signed rotation window,
  sustained-failure auto-disable and redrive, the operator firehose across
  accounts, the presence-based mid-stream cutoff (no replay / no miss / no wedge),
  fan-out crash dedupe, strict invalid-signature rejection, and the SSRF
  redirect/deny guard. Events are injected through the harness seam and the fan-out
  and delivery workers are driven in process; the receiver is inherently
  harness-local (the suite must observe what was delivered), reached through the
  egress test seam without weakening the production range-block.
- **Control plane** (`tests/control_conformance.rs`) — the operator surface driven
  over real HTTP: bootstrap to operator token to account to key create/list/revoke,
  wallet register/grant/revoke, plane isolation (an operator token rejected on the
  data plane, an account bearer rejected on operator routes), and a manual ledger
  adjustment that moves the balance and is audited.
- **Storage uploads** (`tests/storage_conformance.rs`) — the content-upload surface
  over real HTTP against a stub backend: a free-window upload signs an ANS-104 data
  item, POSTs it, and returns an `ar://` URI plus the content sha256; a
  byte-identical re-upload is deduped on `(account, backend, sha256)` and never
  POSTs the provider a second time. The billed charge-at-upload saga and the
  poll-authoritative terminal read on a billed attempt are proven at the engine
  level (a non-zero per-byte price produces the billed attempt rows those contracts
  read); the live Turbo leg is the gate.

## Running

The suite is gated behind the `live` Cargo feature.

```
cargo test -p conformance --features live
```

By default it boots its own gateway and database; it needs a Postgres reachable
at the default URL (or `GATEWAY_CONFORMANCE_DATABASE_URL` to override the base).
The TS leg needs `node`/`npm` on PATH (it `npm install`s the pinned SDK into
`tools/`); the CLI leg needs the `cardanowall` binary on PATH or at
`CARDANOWALL_CLI_BIN`. Each leg skips (passing) when its toolchain is absent, so
a partial environment never fails the suite.

The CLI verify leg is additionally gated on `CONFORMANCE_VERIFY_TX` (a 64-hex
preprod tx carrying a Label 309 record) and `CONFORMANCE_VERIFY_GATEWAY` (a
Koios-compatible preprod gateway URL); it skips when either is unset.

## Chain side

Every flow stubs the chain except the live preprod leg in the gate, which boots
the real binary against real Koios and drives a real submission end to end.
