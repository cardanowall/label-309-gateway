# Deploy example

A minimal single-host [`docker-compose.yml`](./docker-compose.yml): Postgres
plus the gateway. It is a starting point, not a turnkey production stack. For
the full configuration and CLI reference see
[`../gateway/README.md`](../gateway/README.md) and
[`../docs/operators.md`](../docs/operators.md).

## Prerequisites

From this directory:

```sh
# 1. Config: copy the example and edit it (network, band, storage, pricing).
cp ../gateway.example.toml gateway.toml

# 2. Secrets: create the operator keyring and its passphrase file.
mkdir -p secrets
printf '%s' 'a-strong-passphrase' > secrets/gateway-keyring-passphrase
GATEWAY_KEYRING_PASSPHRASE="$(cat secrets/gateway-keyring-passphrase)" \
  gateway keyring init             --path secrets/gateway-keyring.age
GATEWAY_KEYRING_PASSPHRASE="$(cat secrets/gateway-keyring-passphrase)" \
  gateway keyring add-cardano      --path secrets/gateway-keyring.age --network preprod
GATEWAY_KEYRING_PASSPHRASE="$(cat secrets/gateway-keyring-passphrase)" \
  gateway keyring add-arweave      --path secrets/gateway-keyring.age
GATEWAY_KEYRING_PASSPHRASE="$(cat secrets/gateway-keyring-passphrase)" \
  gateway keyring add-webhook-wrap --path secrets/gateway-keyring.age
chmod 600 secrets/*

# 3. Database password: put it in a .env file beside this compose (gitignored).
echo 'POSTGRES_PASSWORD=a-strong-db-password' > .env
```

Fund the two printed addresses: the Cardano address pays anchoring fees, the
Arweave address funds storage credits.

## Bring it up

```sh
# Apply migrations and provision the operator (prints the root secret ONCE).
docker compose run --rm gateway operator bootstrap --label acme

# Start the stack.
docker compose up -d
```

Then register the funded keys and create a first account. The gateway publishes
no host port, so drive the control plane from inside the network:

```sh
export GATEWAY_CONTROL_URL=http://127.0.0.1:8080/control/v1
export GATEWAY_CONTROL_TOKEN='ctl_…the printed root secret…'
docker compose exec gateway sh -c \
  'GATEWAY_CONTROL_URL='"$GATEWAY_CONTROL_URL"' GATEWAY_CONTROL_TOKEN='"$GATEWAY_CONTROL_TOKEN"' \
   gateway admin wallet register primary addr_test1… preprod'
```

## Network posture

The data plane (`/api/v1`) and control plane (`/control/v1`, `/admin`) share one
socket, so publishing the port would expose the control plane too. The compose
therefore publishes nothing by default. To go further:

- **Reach the data plane locally during setup** — uncomment the loopback
  `ports` mapping in the compose (`127.0.0.1:8080:8080`). Loopback only, never
  `0.0.0.0`.
- **Serve the data plane publicly** — put a reverse proxy in front that forwards
  only `/api/v1/*` and keeps `/control/v1` and `/admin` unexposed. The control
  plane and admin console stay reachable through `docker compose exec` or an
  SSH-tunnelled bridge.

## Optional secrets

Add these to the compose `secrets:` block (and the gateway service's `secrets:`
list) as the deployment needs them, each `mode: 0400`, `uid/gid 1001`:

| File-secret                 | Environment variable                 | Purpose                                       |
| --------------------------- | ------------------------------------ | --------------------------------------------- |
| `gateway-coingecko-api-key` | `GATEWAY_COINGECKO_API_KEY_FILE`     | CoinGecko as the primary price provider.      |
| `gateway-koios-api-key`     | `GATEWAY_KOIOS_API_KEY_FILE`         | Koios registered-tier key (raises the quota). |
| `blockfrost-project-id`     | `GATEWAY_BLOCKFROST_PROJECT_ID_FILE` | Blockfrost failover on a Koios rate limit.    |
| `gateway-sentry-dsn`        | `GATEWAY_SENTRY_DSN_FILE`            | Error monitoring (Sentry / GlitchTip).        |

Leaving them out runs keyless public Koios, keyless CoinPaprika pricing, and no
error monitoring.
