# JOTL — JAM On The Lisp
# Docker image for the fuzz-v1 target server
#
# Build:
#   docker build -t jotl .
#
# Run as fuzz target:
#   docker run --rm -v /tmp:/tmp jotl /tmp/jam_target.sock

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

# Create non-root user
RUN useradd -m -s /bin/bash jotl
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

# Bandersnatch SRS for Ring VRF verification (577KB)
RUN mkdir -p tests/jamtestvectors/stf/safrole \
    && curl -fsSL "https://raw.githubusercontent.com/w3f/jamtestvectors/master/stf/safrole/zcash-srs-2-11-uncompressed.bin" \
       -o tests/jamtestvectors/stf/safrole/zcash-srs-2-11-uncompressed.bin \
    && test $(wc -c < tests/jamtestvectors/stf/safrole/zcash-srs-2-11-uncompressed.bin) -gt 500000 \
    || (echo "ERROR: SRS download failed or truncated" && exit 1)

# Pre-compile JOTL (warm FASL cache for faster startup)
RUN sbcl --noinform --non-interactive \
      --load scripts/load-jotl.lisp \
      --eval '(format t "JOTL loaded successfully~%")' \
    || true

# Usage: docker run --rm -v /tmp:/tmp jotl /tmp/jam_target.sock
ENTRYPOINT ["./scripts/fuzz-target.sh"]
CMD ["/tmp/jam_target.sock"]
