ARG RUST_IMAGE=1.96.0-bookworm
ARG CARGO_CHEF_VERSION=0.1.77

FROM lukemathwalker/cargo-chef:${CARGO_CHEF_VERSION}-rust-${RUST_IMAGE} AS chef

WORKDIR /src

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build

ARG STACKS_NODE_VERSION="attacknet-dev"
ARG GIT_BRANCH="unknown"
ARG GIT_COMMIT="unknown"
ENV CARGO_INCREMENTAL=0

WORKDIR /src
COPY --from=planner /src/recipe.json recipe.json
RUN --mount=type=cache,id=stacks-attacknet-cargo,target=/usr/local/cargo/registry \
    --mount=type=cache,id=stacks-attacknet-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=stacks-attacknet-target,target=/src/target \
    cargo chef cook \
    --profile release-lite \
    --features monitoring_prom,slog_json \
    --bin stacks-node \
    --bin stacks-signer \
    --bin stacks-inspect \
    --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,id=stacks-attacknet-cargo,target=/usr/local/cargo/registry \
    --mount=type=cache,id=stacks-attacknet-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=stacks-attacknet-target,target=/src/target \
    cargo build \
    --profile release-lite \
    --features monitoring_prom,slog_json \
    --bin stacks-node \
    --bin stacks-signer \
    --bin stacks-inspect \
    && mkdir /out \
    && cp /src/target/release-lite/stacks-node /out/stacks-node \
    && cp /src/target/release-lite/stacks-signer /out/stacks-signer \
    && cp /src/target/release-lite/stacks-inspect /out/stacks-inspect

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/stacks-node /bin/stacks-node
COPY --from=build /out/stacks-signer /bin/stacks-signer
COPY --from=build /out/stacks-inspect /bin/stacks-inspect
CMD ["stacks-node", "mainnet"]
