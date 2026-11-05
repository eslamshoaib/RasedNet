# Optional Linux deployment / scanning worker. Build once on a connected build machine,
# then `docker save` the image and load it on the offline server.
FROM node:22-bookworm-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build && npm run check-offline

FROM python:3.12-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /app rased
WORKDIR /app/backend
COPY backend/requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY backend/ ./
COPY --from=web /src/frontend/dist /app/frontend/dist
ENV RASED_FRONTEND_DIST=/app/frontend/dist PYTHONUNBUFFERED=1
USER rased
EXPOSE 8443
CMD ["sh", "-c", "python -m rased init-db && exec python -m rased serve --host 0.0.0.0 --port 8443 --cert /certs/rased.crt --key /certs/rased.key"]
