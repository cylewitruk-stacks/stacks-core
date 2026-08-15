FROM node:22.18.0-alpine3.22

ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="Stacks Attacknet run controller" \
      org.opencontainers.image.description="Trusted namespaced FaultCampaign and AttacknetRun reconciler" \
      org.opencontainers.image.source="https://github.com/stacks-network/stacks-core"

WORKDIR /app
COPY contrib/helm/hacknet/run-operator/controller.mjs /app/contrib/helm/hacknet/run-operator/controller.mjs
COPY contrib/attacknet/fault-campaign.mjs /app/contrib/attacknet/fault-campaign.mjs
COPY contrib/attacknet/campaign-targets.mjs /app/contrib/attacknet/campaign-targets.mjs

ENV NODE_ENV=production
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["node", "/app/contrib/helm/hacknet/run-operator/controller.mjs"]
