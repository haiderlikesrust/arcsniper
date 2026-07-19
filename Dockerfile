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

# Signal handling (clean SIGTERM -> bot.stop()) comes from docker-compose's
# `init: true`, which injects its own init as PID 1. Adding tini here too would
# leave it running as a non-PID-1 child, which just emits a subreaper warning
# and does nothing useful.

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

CMD ["node", "dist/index.js", "telegram", "--live"]
