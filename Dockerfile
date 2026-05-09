# JOTL — JAM On The Lisp
# Docker image for the fuzz-v1 target server
#
# Build:
#   docker build -t jotl .
#
# Run as fuzz target (standard packaging):
#   docker run --rm \
#     -e JAM_FUZZ=1 \
#     -e JAM_FUZZ_SPEC=tiny \
#     -e JAM_FUZZ_DATA_PATH=/tmp/jam/data/ \
#     -e JAM_FUZZ_SOCK_PATH=/tmp/jam/fuzz.sock \
#     -e JAM_FUZZ_LOG_LEVEL=info \
#     -v /tmp/jam:/tmp/jam \
#     jotl

# ── Stage 1: Build Rust crypto FFI ──────────────────────────────────
FROM rust:slim-bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY crypto/ crypto/
COPY jam-crypto.asd .

RUN cargo build --manifest-path crypto/jam-crypto/Cargo.toml --release

# ── Stage 2: Runtime ────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    sbcl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with explicit UID to avoid conflicts with host UID 1000
RUN useradd -m -s /bin/bash -u 10001 jotl
USER jotl
ENV HOME=/home/jotl
WORKDIR /home/jotl

# Install Quicklisp
RUN curl -sO https://beta.quicklisp.org/quicklisp.lisp \
    && sbcl --noinform --non-interactive \
         --load quicklisp.lisp \
         --eval '(quicklisp-quickstart:install :path "/home/jotl/quicklisp/")' \
    && echo '(load "/home/jotl/quicklisp/setup.lisp")' > /home/jotl/.sbclrc \
    && rm quicklisp.lisp

# Pre-fetch Lisp dependencies (alexandria, cffi)
RUN sbcl --noinform --non-interactive \
      --eval '(ql:quickload :alexandria)' \
      --eval '(ql:quickload :cffi)'

WORKDIR /home/jotl/jotl

# Copy Rust build artifacts
COPY --chown=jotl:jotl --from=rust-builder /build/crypto/jam-crypto/target/release/libjam_crypto.so \
     crypto/jam-crypto/target/release/libjam_crypto.so

# Copy JOTL source
COPY --chown=jotl:jotl . .

# Bandersnatch SRS is bundled in data/ — no external download needed.
# Pre-compile JOTL (warm FASL cache for faster startup)
RUN sbcl --noinform --non-interactive \
      --load scripts/load-jotl.lisp \
      --eval '(format t "JOTL loaded successfully~%")' \
    || true

ENTRYPOINT ["./scripts/fuzz-target.sh"]
