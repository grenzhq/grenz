# syntax=docker/dockerfile:1

# --- Build the single-binary proxy --------------------------------------------
FROM oven/bun:1.3.11 AS build
WORKDIR /app

# Install deps first for layer caching (workspace needs each package manifest).
COPY package.json bun.lock ./
COPY proxy/package.json ./proxy/
COPY console/package.json ./console/
RUN bun install --frozen-lockfile --ignore-scripts

COPY . .
RUN cd proxy && bun run build   # -> /app/proxy/dist/grenz

# --- Runtime ------------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10001 --create-home --home-dir /home/grenz grenz \
  && mkdir -p /data && chown grenz:grenz /data

COPY --from=build /app/proxy/dist/grenz /usr/local/bin/grenz

# The Grenz home (identity, vault, admin token, request log) is a mounted
# volume — secrets never live in the image. Runs as a non-root user; use a named
# volume (`-v grenz-data:/data`) so it inherits writable ownership.
ENV GRENZ_HOME=/data/.grenz
USER grenz
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8787

# Bind 0.0.0.0 so a published port (-p) is reachable; the GRENZ_TOKEN and the
# container/host network boundary gate access.
ENTRYPOINT ["grenz"]
CMD ["run", "--host", "0.0.0.0"]
