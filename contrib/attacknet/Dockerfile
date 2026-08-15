ARG RUST_IMAGE=1.96.0-bookworm
ARG CARGO_CHEF_VERSION=0.1.77
ARG CARGO_CHEF_IMAGE=lukemathwalker/cargo-chef:${CARGO_CHEF_VERSION}-rust-${RUST_IMAGE}
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${CARGO_CHEF_IMAGE} AS chef

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
    && command -v objcopy \
    && command -v strip \
    && install -d /out/runtime/bin /out/debug/usr/lib/debug/bin \
    && for binary in stacks-node stacks-signer stacks-inspect; do \
        install -m 0755 "/src/target/release-lite/${binary}" "/out/runtime/bin/${binary}"; \
        objcopy --only-keep-debug \
            "/out/runtime/bin/${binary}" \
            "/out/debug/usr/lib/debug/bin/${binary}.debug"; \
        strip --strip-debug "/out/runtime/bin/${binary}"; \
        objcopy \
            --add-gnu-debuglink="/out/debug/usr/lib/debug/bin/${binary}.debug" \
            "/out/runtime/bin/${binary}"; \
    done \
    && cd /out/runtime \
    && sha256sum bin/* > SHA256SUMS \
    && cd /out \
    && sha256sum runtime/bin/* debug/usr/lib/debug/bin/* > debug/SHA256SUMS \
    && printf '%s\n' \
        'schema=stacks-attacknet-debug-symbols/v1' \
        "stacks_node_version=${STACKS_NODE_VERSION}" \
        "git_branch=${GIT_BRANCH}" \
        "git_commit=${GIT_COMMIT}" \
        'cargo_profile=release-lite' \
        'strip_mode=strip-debug' \
        > debug/BUILD-INFO \
    && cp debug/BUILD-INFO runtime/BUILD-INFO

# This target is optional: the default runtime image below does not contain
# DWARF. Export it separately with `--target debug-symbols --output ...` and
# retain it beside the runtime image digest when source-level debugging is
# required. Each runtime ELF also carries the matching GNU debuglink CRC.
FROM scratch AS debug-symbols
ARG STACKS_NODE_VERSION="attacknet-dev"
ARG GIT_BRANCH="unknown"
ARG GIT_COMMIT="unknown"
LABEL org.opencontainers.image.title="Stacks Attacknet debug symbols" \
      org.opencontainers.image.version="${STACKS_NODE_VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.stacks.attacknet.git-branch="${GIT_BRANCH}" \
      org.stacks.attacknet.cargo-profile="release-lite"
COPY --from=build /out/debug/ /

FROM ${RUNTIME_IMAGE}
ARG STACKS_NODE_VERSION="attacknet-dev"
ARG GIT_BRANCH="unknown"
ARG GIT_COMMIT="unknown"
LABEL org.opencontainers.image.title="Stacks Attacknet node tools" \
      org.opencontainers.image.version="${STACKS_NODE_VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.stacks.attacknet.git-branch="${GIT_BRANCH}" \
      org.stacks.attacknet.cargo-profile="release-lite" \
      org.stacks.attacknet.debug-symbols="external"
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/runtime/bin/stacks-node /bin/stacks-node
COPY --from=build /out/runtime/bin/stacks-signer /bin/stacks-signer
COPY --from=build /out/runtime/bin/stacks-inspect /bin/stacks-inspect
COPY --from=build /out/runtime/SHA256SUMS /usr/share/stacks-attacknet/SHA256SUMS
COPY --from=build /out/runtime/BUILD-INFO /usr/share/stacks-attacknet/BUILD-INFO
CMD ["stacks-node", "mainnet"]
