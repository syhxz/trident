# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
# Pinned to a Debian Bookworm-based Rust image so the glibc version matches
# the distroless runtime image below (both track Debian 12).
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

# Copy the full source. Trident has no native/system dependencies (no
# OpenSSL, no rustls) so no extra apt packages are needed to build it.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY console ./console

# BuildKit cache mounts persist the Cargo registry and the incremental
# build directory across builds (without baking them into any image
# layer), so repeated builds after a small source change are fast without
# needing a separate "build deps first with a dummy main.rs" trick.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp target/release/trident /app/trident

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
# distroless "cc" image: glibc + libgcc only, no shell, no package manager,
# runs as the built-in non-root "nonroot" user (uid 65532) by default --
# there is intentionally no attack surface beyond the binary itself.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /app

COPY --from=builder /app/trident /app/trident
# Baked-in fallback config, purely so `docker run` works out of the box for
# a quick local smoke test. Production deployments should always mount a
# real config over this path (see README examples in DEPLOYMENT.md) or
# point TRIDENT_CONFIG elsewhere.
COPY config.yaml /app/config.yaml

ENV TRIDENT_CONFIG=/app/config.yaml
# Matches the default `proxy.listen_addr` in config.yaml; override the
# port mapping at `docker run -p` / compose / k8s level if you change it.
EXPOSE 6432

ENTRYPOINT ["/app/trident"]
