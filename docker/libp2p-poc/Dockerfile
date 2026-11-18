FROM rust:bookworm AS builder

WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --profile libp2p-poc \
      -p stacks-node -p stacks-signer \
      --features stacks-node/monitoring_prom,stacks-node/network_observer,stacks-node/otel,stacks-signer/monitoring_prom,stacks-signer/otel \
    && install -D /src/target/libp2p-poc/stacks-node /out/stacks-node \
    && install -D /src/target/libp2p-poc/stacks-signer /out/stacks-signer

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/stacks-node /usr/local/bin/stacks-node
COPY --from=builder /out/stacks-signer /usr/local/bin/stacks-signer
