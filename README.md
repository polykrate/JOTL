# JOTL — JAM On The Lisp

Common Lisp implementation of the JAM protocol state transition function Υ(σ, B) → σ'.

[Gray Paper](https://graypaper.com) v0.7.2 · [Test vectors](https://github.com/w3f/jamtestvectors)

## Status

| Trace | Chain | Step |
|-------|------:|-----:|
| fallback | 100/100 | 100/100 |
| safrole | 100/100 | 100/100 |
| storage | 100/100 | 100/100 |
| storage_light | 100/100 | 100/100 |
| preimages | 100/100 | 100/100 |
| preimages_light | 100/100 | 100/100 |
| fuzzy | 5/200 | 32/200 |
| fuzzy_light | 5/200 | 38/200 |

**600/600 deterministic traces pass.** Byte-exact state root match on every
block, both chain and step modes. Zero errors, zero panics.

Fuzzy traces require `refine` (Ψ_R), which is not yet implemented.

## What it does

Lisp implements the full STF: block decoding, state transitions for all 17
components (τ η κ λ β ψ ρ ι γ α ϕ δ π χ ω ξ θ), Merkle trie, and the
4-wave dependency graph from GP §4.2.1. Crypto (Blake2b, Keccak, Ed25519,
Bandersnatch Ring VRF) and PVM (PolkaVM with GP Appendix B host calls) run
in Rust via CFFI.

The architecture is let-over-lambda closures: each state component is an
immutable closure that responds to messages (`:load`, `:save`, `:transition`).
No classes, no CLOS, no mutation. One macro (`define-state-closure`) generates
all closure boilerplate. σ is the supervisor — it births components from bytes,
orchestrates transitions, and collects the primes.

## What it doesn't do

- **Networking** — no p2p, no block propagation, no gossip
- **Refine** (Ψ_R) — PVM `is_authorized` and `accumulate` work; `refine` does not
- **Production** — no persistence, no caching, single-threaded, ~90 blocks/sec

## Quick start

```bash
# Build Rust crypto/PVM
cargo build --manifest-path crypto/jam-crypto/Cargo.toml --release

# Load JOTL
sbcl --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :jotl)'

# Run a trace
sbcl --noinform --load scripts/load-jotl.lisp --eval '
  (jotl::fuser-run-trace
    (merge-pathnames "tests/jamtestvectors/traces/storage/"
                     (uiop:getcwd)))' --quit
```

## Layout

```
src/
├── lib/           Codecs, constants, Merkle trie, MMR
├── bloc/          Block structure: header, extrinsics, work reports
├── state/         17 state components (one file each)
├── accumulate.lisp   §12 Accumulate: R*, queues, PVM orchestration
├── upsilon.lisp      Υ(σ,B)→σ' — 4-wave dependency graph
├── import.lisp       Binary trace importer
└── fuser.lisp        Unix socket interface

crypto/jam-crypto/    Rust FFI: crypto primitives + PolkaVM host calls
tests/                Test scripts + jamtestvectors (submodule)
```

## Dependencies

- SBCL, Alexandria, CFFI
- Rust toolchain (for `crypto/jam-crypto`)
- [jamtestvectors](https://github.com/w3f/jamtestvectors) in `tests/`

## License

MIT
