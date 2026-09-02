FROM golang:1.24.6-alpine3.22 AS builder

ARG TARGETOS=linux
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=0
WORKDIR /src
COPY contrib/attacknet/images/io-pressure/main.go ./main.go
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/attacknet-io-pressure ./main.go

FROM scratch
ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="Stacks Attacknet bounded I/O pressure" \
      org.opencontainers.image.description="Controller-owned, non-shell disk pressure workload" \
      org.opencontainers.image.source="https://github.com/stacks-network/stacks-core"
COPY --from=builder --chown=65532:65532 /out/attacknet-io-pressure /attacknet-io-pressure
USER 65532:65532
ENTRYPOINT ["/attacknet-io-pressure"]
