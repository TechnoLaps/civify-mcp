# ==============================================================================
# Civify MCP Server — Production Dockerfile
# Optimized multi-stage build for Dokploy & Traefik
# ==============================================================================

# --- Stage 1: Build Stage ---
FROM node:22-alpine AS builder

WORKDIR /app

# Copy package descriptors
COPY package*.json tsconfig.json ./

# Install all dependencies (including devDependencies for tsc)
RUN npm ci

# Copy source code
COPY src/ ./src/

# Compile TypeScript to dist/
RUN npm run build

# Remove development dependencies to keep final image slim
RUN npm prune --production

# --- Stage 2: Production Runtime ---
FROM node:22-alpine AS runner

WORKDIR /app

# Environment defaults
ENV NODE_ENV=production
ENV PORT=8080
ENV TRANSPORT=sse
ENV CIVIFY_API_URL=https://civify.cv/apis

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy only production dependencies and compiled artifacts from builder
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./package.json

# Switch to unprivileged user
USER nodejs

# Expose HTTP port for Traefik reverse proxy
EXPOSE 8080

# Healthcheck for Dokploy & Docker daemon
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/health || exit 1

# Start the Remote SSE Server
CMD ["node", "dist/index.js"]
