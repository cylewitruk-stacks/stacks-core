FROM node:20-bookworm

RUN npm install --global pnpm@10
WORKDIR /stacker
COPY package.json ./
RUN pnpm install
COPY common.ts stacking.ts ./

CMD ["npx", "tsx", "/stacker/stacking.ts"]
