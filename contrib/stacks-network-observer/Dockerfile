FROM node:22.22-alpine AS build
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci
COPY . ./
RUN npm run build

FROM node:22.22-alpine AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4319
WORKDIR /app
COPY --from=build --chown=node:node /workspace/dist ./dist
COPY --from=build --chown=node:node /workspace/package.json ./package.json
COPY --from=build --chown=node:node /workspace/federation/poc-enrollments.json ./federation/poc-enrollments.json
USER node
EXPOSE 4319
HEALTHCHECK --interval=5s --timeout=2s --start-period=5s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:4319/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/server/server/index.js"]
