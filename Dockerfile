# ── Etapa 1: build de la SPA (Vite + TypeScript) ─────────────────────────────
FROM node:24-alpine AS build
WORKDIR /app

# Copiar manifiestos primero para cachear capas de dependencias
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ── Etapa 2: servir dist/ con nginx sin privilegios ──────────────────────────
# nginx-unprivileged: corre como usuario no-root (UID 101) y escucha en 8080,
# apto para el SCC restricted-v2 de OpenShift (Quay/Red Hat).
FROM nginxinc/nginx-unprivileged:1.28-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

# Los orquestadores (k8s/OpenShift) ignoran HEALTHCHECK y usan sus propias
# sondas contra /healthz; esto sirve para `docker run` / Compose.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
