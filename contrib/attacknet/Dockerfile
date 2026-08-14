FROM rust:bookworm AS build

ARG STACKS_NODE_VERSION="attacknet-dev"
ARG GIT_BRANCH="unknown"
ARG GIT_COMMIT="unknown"

WORKDIR /src
COPY . .
RUN --mount=type=cache,id=stacks-attacknet-cargo,target=/usr/local/cargo/registry \
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
