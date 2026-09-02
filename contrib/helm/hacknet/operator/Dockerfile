# syntax=docker/dockerfile:1.7
FROM golang:1.26-bookworm AS builder

ARG BINARY=topology-operator
ARG SOURCE_DATE_EPOCH=0

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build \
      -trimpath -ldflags="-s -w -buildid=" \
      -o /out/controller "./cmd/${BINARY}"

FROM gcr.io/distroless/static-debian12:nonroot

ARG BINARY=topology-operator
LABEL org.opencontainers.image.title="Stacks ${BINARY}" \
      org.opencontainers.image.description="Namespaced controller-runtime manager for disposable Stacks test networks" \
      org.opencontainers.image.source="https://github.com/stacks-network/stacks-core"

COPY --from=builder /out/controller /controller
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/controller"]
