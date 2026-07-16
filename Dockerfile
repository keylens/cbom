# ============================================================================
# cbom — Multi-stage Docker build
# ============================================================================
# Stage 1: Build the Rust binary using the official Rust image.
# Stage 2: Copy the binary into a minimal Debian slim image for production.
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM rust:1.79-slim AS builder

# Install build dependencies for tree-sitter C compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/cbom

# Copy manifests first to cache dependency builds
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main.rs to pre-build dependencies (layer caching)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true

# Now copy real source and rebuild
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# ---------------------------------------------------------------------------
# Stage 2 — Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/cbom/target/release/cbom /usr/local/bin/cbom

ENTRYPOINT ["cbom"]
