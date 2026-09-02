FROM node:22-alpine

ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="Stacks Attacknet trusted probe" \
      org.opencontainers.image.description="Credential-free bounded active probe for disposable Stacks attacknets" \
      org.opencontainers.image.source="https://github.com/stacks-network/stacks-core"

WORKDIR /app
COPY probe.mjs /app/probe.mjs

USER 65532:65532
EXPOSE 18080
ENTRYPOINT ["node", "/app/probe.mjs"]
