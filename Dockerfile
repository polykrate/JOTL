# JOTL — JAM On The Lisp
# Multi-stage Docker build for the fuzz-v1 target server
#
# Build:
#   docker build -t jotl .
#
# Run conformance tests:
#   docker run --rm jotl ./scripts/test.sh
#
# Run as fuzz target (mount socket from host):
#   docker run --rm -v /tmp:/tmp jotl ./scripts/fuzz-target.sh /tmp/jam_target.sock

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
    sbcl curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install Quicklisp
ENV HOME=/root
RUN curl -sO https://beta.quicklisp.org/quicklisp.lisp \
    && sbcl --noinform --non-interactive \
         --load quicklisp.lisp \
         --eval '(quicklisp-quickstart:install :path "/root/quicklisp/")' \
    && echo '(load "/root/quicklisp/setup.lisp")' > /root/.sbclrc \
    && rm quicklisp.lisp

# Pre-fetch Lisp dependencies (alexandria, cffi)
RUN sbcl --noinform --non-interactive \
      --eval '(ql:quickload :alexandria)' \
      --eval '(ql:quickload :cffi)'

WORKDIR /jotl

# Copy Rust build artifacts
COPY --from=rust-builder /build/crypto/jam-crypto/target/release/libjam_crypto.so \
     crypto/jam-crypto/target/release/libjam_crypto.so

# Copy JOTL source
COPY . .

# Clone test data
RUN git clone --depth 1 https://github.com/w3f/jamtestvectors.git /jamtestvectors \
    && ln -sf /jamtestvectors tests/jamtestvectors \
    && git clone --depth 1 https://github.com/w3f/jam-conformance.git /jam-conformance

# Pre-compile JOTL (warm FASL cache for faster startup)
RUN sbcl --noinform --non-interactive \
      --load scripts/load-jotl.lisp \
      --eval '(format t "JOTL loaded successfully~%")' \
    || true

# Default: launch fuzz target on /tmp/jam_target.sock
CMD ["./scripts/fuzz-target.sh", "/tmp/jam_target.sock"]
