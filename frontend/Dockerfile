# ── Stage 1: Build Stage ──────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Deterministic dependency installation
RUN npm ci

# Copy application source code
COPY . .

# Build production bundle with Vite + TypeScript (generates dist/)
RUN npm run build

# ── Stage 2: Production Nginx Runtime ─────────────────────────────────────────
FROM nginx:1.27-alpine AS runtime

# Remove default Nginx site and files
RUN rm -rf /etc/nginx/conf.d/* /usr/share/nginx/html/*

# Copy security-hardened Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

# Health check probe
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost/nginx-health || exit 1

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
