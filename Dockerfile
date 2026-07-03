# syntax=docker/dockerfile:1
#
# Multi-stage build for the Label 309 gateway: the Rust single binary that owns
# the publish pipeline (Cardano transaction build/submit/confirm, Arweave
# storage, the on-chain records index, the balance ledger, and FX pricing)
# behind an HTTP data plane and control plane.
#
# The build context is the repository root, which is the Cargo workspace itself,
# so the build is self-contained: it copies the whole workspace and builds the
# `gateway` binary with no path dependency reaching outside the tree. The binary
# applies its own database migrations at boot (and under its bootstrap
# subcommands), so there is no separate migrate step or image.

# ---------------------------------------------------------------------------
# Stage 1 — builder. Compiles the release binary.
#
# rust:1-bookworm tracks the moving stable toolchain. The workspace is
# rustls-only (no system OpenSSL) and its sqlx `migrate!()` macro reads the
# migration tree from source at compile time, so the build needs no system libs
# beyond the base image and no live database. --locked builds against the
# committed Cargo.lock so the image resolves exactly the pinned dependency graph.
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

WORKDIR /build

COPY . .

RUN cargo build --release --locked -p gateway

# ---------------------------------------------------------------------------
# Stage 2 — runtime. A slim Debian with the binary, CA certificates, and curl.
#
# ca-certificates: the gateway egresses over HTTPS (the chain providers, the
# coin-price oracles, the storage upload/payment services, the Arweave gateway,
# and webhook delivery), all through rustls, which loads the system trust store.
#
# curl backs the container healthcheck (a real HTTP probe of /api/v1/health, so
# a wedged HTTP plane fails where a bare TCP probe would pass) and lets an
# operator drive root-gated control-plane routes from inside the network when
# the control plane is not published (e.g. `docker compose exec gateway curl`).
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user.
RUN groupadd --system --gid 1001 gateway \
 && useradd --system --uid 1001 --gid gateway gateway

COPY --from=builder /build/target/release/gateway /usr/local/bin/gateway

# Staging directories for in-flight uploads. /var/lib/gateway is a named volume
# in the deploy compose (resumable-upload sessions and durable staging must
# survive container recreation); creating the paths here with gateway ownership
# lets Docker seed a fresh volume with the right owner, so the non-root process
# can write to it from the first start.
RUN mkdir -p /var/lib/gateway/staging /var/lib/gateway/durable \
 && chown -R gateway:gateway /var/lib/gateway

USER gateway

EXPOSE 8080

# Probe the data plane, but pass on ANY HTTP response (no -f): /api/v1/health
# answers 503 when the chain tip is stale, which is a Cardano-network signal,
# not a process-liveness one, and restarting the gateway during a chain stall
# would kill in-flight uploads for nothing. Only a connection failure or timeout
# (the process not serving) fails the probe. 127.0.0.1, not localhost, so an
# ::1-first resolution cannot fail a healthy IPv4 bind.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -s -o /dev/null --max-time 5 http://127.0.0.1:8080/api/v1/health || exit 1

# The binary serves when invoked with no arguments; subcommands ride the same
# entrypoint, e.g. `docker compose run --rm gateway operator bootstrap`.
ENTRYPOINT ["gateway"]
