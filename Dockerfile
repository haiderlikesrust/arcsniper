# syntax=docker/dockerfile:1

# ---------- build stage ----------
# Pinned digest-free tag is fine here; the runtime stage is what ships.
FROM node:20-bookworm-slim AS build
WORKDIR /app

# Install deps against the lockfile for reproducibility.
COPY package.json package-lock.json* ./
RUN npm ci

# Compile TypeScript to plain JS. The runtime image runs `node dist/index.js`,
# so tsx is not needed at runtime.
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Drop dev dependencies for the runtime copy.
RUN npm prune --omit=dev

# ---------- runtime stage ----------
# node:20-slim (glibc) rather than distroless so we keep a shell for the
# operator's `docker compose run ... import/export/claim` commands. No native
# addons are used (crypto is Node built-in), so the image stays small.
FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

# tini as PID 1 for correct signal handling (clean SIGTERM -> bot.stop()).
RUN apt-get update && apt-get install -y --no-install-recommends tini && rm -rf /var/lib/apt/lists/*

# Copy only what the runtime needs. NO secrets, NO data/, NO .env - see
# .dockerignore. Config is bind-mounted read-only at run time, not baked in.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# data/ is where encrypted keystores + audit log live. Create it owned by the
# non-root user; it is mounted as a volume at run time.
RUN mkdir -p /app/data /app/config && chown -R node:node /app

# Never run as root.
USER node

# Long-polling only - no inbound port is exposed. The bot reaches out to
# api.telegram.org and the RPCs; nothing needs to reach in.

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/index.js", "telegram", "--live"]
