# Label 309 Gateway

The open-source backend of a [Label 309](https://github.com/cardanowall/label-309)
Proof-of-Existence service. A single Rust binary plus Postgres that takes content
from a user, anchors its hash on the Cardano blockchain under metadata label 309,
and serves the records back for standalone verification. It owns the whole
publish pipeline and the money, chain, and storage state behind it, so an
operator runs one process and one database rather than assembling a chain node, a
storage uploader, an index, a pricing oracle, and a ledger.

The gateway exposes two HTTP planes. The **data plane** (`/api/v1`) is what an
application drives on behalf of its users: quote a publish, upload content, publish,
list and retrieve records, read a balance, and stream lifecycle events. The
**control plane** (`/control/v1`) is the operator surface: provision accounts,
mint and revoke credentials, register wallets and storage funding sources, adjust
balances, and convert funds into prepaid storage credits. A Standard-Webhooks
firehose streams lifecycle events (status, balance, refund) to a subscriber, and a
bundled static console at `/admin` drives the control plane from a browser.

The gateway is multi-tenant. One instance serves many **operators**, each with
many **accounts**, each holding many **credentials** (API keys and tokens). The
on-chain records index is operator- and account-agnostic and shared: every
publish lands in one global feed that any reader can page, while balances,
credentials, and funding grants stay scoped to their owner.

## What it owns

- **Publish pipeline** — quote, resumable content upload, and publish, with a
  two-phase quote/consume protocol so a publish is priced and debited atomically.
- **Cardano transactions** — an in-tree, pallas-based Proof-of-Existence
  transaction builder with fee estimation (see [`cardano-poe-tx`](./cardano-poe-tx)).
- **Submit, confirm, reorg, refund** — the transaction is submitted, tracked to
  confirmation, held correct across rollbacks, and automatically refunded on
  permanent failure.
- **Arweave storage** — streamed, resumable content and ciphertext uploads via
  Turbo in production (or the ArLocal emulator in development), with a
  crash-recoverable reservation lifecycle and prepaid-credit reconciliation.
- **Shared records index** — a forward on-chain scan feeding the operator- and
  account-agnostic global records feed.
- **Balance ledger** — an append-only per-account journal with an
  overdraft-refused balance and a vendor-extensible adjustment-kind registry.
- **FX and pricing** — a live price-oracle refresh loop that caches one snapshot
  per tick, with an operator-default margin and a per-account override. No
  hardcoded fallback rate: when no snapshot is fresh, a quote is refused rather
  than priced at a stale rate.
- **Two planes plus a firehose** — the data plane (API keys), the control plane
  (operator tokens), and the Standard-Webhooks lifecycle firehose.
- **Multi-tenancy** — the operator → account → credential model, with scoped
  wallet and storage-funding grants.

## Quickstart

The shortest path from nothing to a publish-ready gateway. Every step is
explained in depth in [`gateway/README.md`](./gateway/README.md).

```sh
# 1. Create the operator keyring (one encrypted file holds every signing key).
export GATEWAY_KEYRING_PASSPHRASE='correct horse battery staple'
gateway keyring init             --path /etc/gateway/keyring.age
gateway keyring add-cardano      --path /etc/gateway/keyring.age --network preprod
gateway keyring add-arweave      --path /etc/gateway/keyring.age
gateway keyring add-webhook-wrap --path /etc/gateway/keyring.age
# Fund the two printed addresses (Cardano pays anchoring fees, Arweave funds storage).

# 2. Write the config from the example, then point the binary at it.
cp gateway.example.toml /etc/gateway/gateway.toml   # then edit
export GATEWAY_CONFIG=/etc/gateway/gateway.toml
export GATEWAY_DATABASE_URL=postgres://user:pass@host/gateway

# 3. Provision the operator (prints the root secret EXACTLY ONCE, store it) and serve.
gateway operator bootstrap --label acme
gateway

# 4. Register the funded keys, create an account, credit it, mint an API key.
export GATEWAY_CONTROL_URL=http://127.0.0.1:8080/control/v1
export GATEWAY_CONTROL_TOKEN='ctl_…the printed root secret…'
gateway admin wallet register primary addr_test1… preprod
gateway admin account create
gateway admin account fund <account_id> 10000000 "starter credit"   # $10
gateway admin key create <account_id> poe:create,poe:read,account:read
```

The printed API key drives the data plane: request a quote at
`POST /api/v1/poe/quote`, and read the interactive docs at `/api/v1/docs`.

The walkthrough targets preprod end to end, matching the example config. For a
production deployment the Cardano keyring key, the config `network`, and the
wallet registration must all say `mainnet` together.

## Documentation

| Where                                                                                  | What                                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`gateway/README.md`](./gateway/README.md)                                             | The configuration, CLI, and environment reference.                                                                                                                                                                                                                                              |
| [`docs/operators.md`](./docs/operators.md)                                             | The operator runbook: provisioning, funding, credentials, money semantics, chain providers, webhooks, and day-2 operations.                                                                                                                                                                     |
| [`docs/building-a-service.md`](./docs/building-a-service.md)                           | Building your own product on top of a gateway: the integration surfaces and the patterns that keep your service honest.                                                                                                                                                                         |
| `/api/v1/docs`, `/api/v1/openapi.json`, `/control/v1/docs`, `/control/v1/openapi.json` | The live API reference, served by the binary — an interactive page per plane plus its machine-readable OpenAPI document, all served fully offline (the renderer is vendored, never a CDN). Each plane versions its OpenAPI document independently and bumps it with any route or schema change. |

## Workspace

The repository is one Cargo workspace.

| Crate                                | Role                                                                                                              |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| [`gateway`](./gateway)               | The application binary: the two HTTP planes, the webhook firehose, the admin console, and the operator CLIs.      |
| [`gateway-core`](./gateway-core)     | The engine: chain, storage, ledger, pricing, events, webhook, wallet, runtime, maintenance, and the HTTP surface. |
| [`cardano-poe-tx`](./cardano-poe-tx) | The pallas-based Proof-of-Existence transaction builder and fee estimation.                                       |
| [`ans104`](./ans104)                 | Arweave ANS-104 bundle and data-item encoding and signing.                                                        |
| [`conformance`](./conformance)       | A harness that drives the published Label 309 SDK and CLI artifacts against a running gateway.                    |

## Docker

A multi-stage [`Dockerfile`](./Dockerfile) builds the release binary into a slim
Debian runtime image that runs as a non-root user and healthchecks the data
plane. A minimal single-host deployment example (Postgres plus the gateway) lives
in [`deploy/docker-compose.yml`](./deploy/docker-compose.yml); see
[`deploy/README.md`](./deploy/README.md) for bootstrap and the recommended
network posture.

```sh
docker build -t label-309-gateway .
```

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
