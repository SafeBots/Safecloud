# ─── Safecloud Jet — Docker image ────────────────────────────────────────────
#
# Multi-stage build:
#   stage 1 (deps)  — install production npm dependencies
#   stage 2 (app)   — copy source + deps into a slim runtime image
#
# Build:
#   docker build -t safecloud-jet:latest .
#
# Run (filesystem backend, port 8080):
#   docker run -d \
#     -p 8080:8080 \
#     -v /path/to/local:/app/local \
#     -v /path/to/chunks:/var/safecloud/chunks \
#     safecloud-jet:latest
#
# Config is read from /app/local/app.json. Mount a directory there that
# contains an app.json. On first run the Jet generates a wallet and writes
# the private key back into that file — the directory must be writable.

# ─── Stage 1: dependencies ───────────────────────────────────────────────────
FROM node:22-slim AS deps

WORKDIR /build

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# ─── Stage 2: runtime image ──────────────────────────────────────────────────
FROM node:22-slim

# Install tini for proper signal handling and clean process reaping
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source (exclude dev/test files via .dockerignore)
COPY --chown=node:node . .
# Overwrite node_modules with the production-only set from deps stage
COPY --from=deps --chown=node:node /build/node_modules ./node_modules

# Default chunk storage directory (override via config or mount)
RUN mkdir -p /var/safecloud/chunks && chown node:node /var/safecloud/chunks

# Config directory — operators should mount a volume here
RUN mkdir -p /app/local && chown node:node /app/local

# Drop privileges
USER node

# Expose default port; override with SAFECLOUD_PORT env var or config
EXPOSE 8080

# Health check — hits the /Safecloud/health endpoint added in Jets.listen()
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "require('http').get('http://localhost:' + (process.env.SAFECLOUD_PORT || 8080) + '/Safecloud/health', function(r){ process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', function(){ process.exit(1); })"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "bin/jet.js"]
