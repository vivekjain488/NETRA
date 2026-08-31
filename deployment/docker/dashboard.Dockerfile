# NETRA SOC dashboard image: built with Node, served as static files by nginx.

FROM node:24-alpine AS build
WORKDIR /src
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
ARG VITE_NETRA_API_URL=http://localhost:8080
ENV VITE_NETRA_API_URL=${VITE_NETRA_API_URL}
RUN npm run build

FROM nginx:1.27-alpine AS runtime
COPY --from=build /src/dist /usr/share/nginx/html
COPY deployment/docker/dashboard-nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
