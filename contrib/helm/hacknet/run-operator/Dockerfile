FROM node:22.18.0-alpine3.22

ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="Stacks Attacknet run controller" \
      org.opencontainers.image.description="Trusted namespaced FaultCampaign and AttacknetRun reconciler" \
      org.opencontainers.image.source="https://github.com/stacks-network/stacks-core"

WORKDIR /app
COPY contrib/helm/hacknet/run-operator/controller.mjs /app/contrib/helm/hacknet/run-operator/controller.mjs
COPY contrib/helm/hacknet/run-operator/probe-client.mjs /app/contrib/helm/hacknet/run-operator/probe-client.mjs
COPY contrib/attacknet/fault-campaign.mjs /app/contrib/attacknet/fault-campaign.mjs
COPY contrib/attacknet/campaign-targets.mjs /app/contrib/attacknet/campaign-targets.mjs
COPY contrib/attacknet/fault-effect-evidence.mjs /app/contrib/attacknet/fault-effect-evidence.mjs
COPY contrib/attacknet/attacknet-run-schedule.mjs /app/contrib/attacknet/attacknet-run-schedule.mjs
COPY contrib/attacknet/run-descriptor.mjs /app/contrib/attacknet/run-descriptor.mjs
COPY contrib/attacknet/signer-set-parity.mjs /app/contrib/attacknet/signer-set-parity.mjs

ENV NODE_ENV=production
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["node", "/app/contrib/helm/hacknet/run-operator/controller.mjs"]
