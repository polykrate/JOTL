# JOTL — JAM On The Lisp

Common Lisp implementation of the JAM state transition function **Υ(σ, B) → σ'**,
conforming to [Gray Paper](https://graypaper.com) **v0.7.2**.

JOTL is a **state-transition client**: it validates and applies blocks to protocol
state. Networking, persistence, and block production are out of scope (Milestone 1).

| Layer | Language | Role |
|-------|----------|------|
| STF, PVM, host calls | Common Lisp | Protocol logic (GP §4–§13, Appendices A–B) |
| Cryptography | Rust (CFFI) | Blake2b, Bandersnatch Ring VRF, Ed25519 |

---

## How it works

A block **B = (H, E)** is processed in three stages:

```
  Binary block          Trust boundary              Pure STF
  ────────────          ──────────────              ────────
  trace / fuzz-v1  →   import-block(σ, B)   →   transition-state(σ, B)
                              │                         │
                              │                    dependency waves 0–4 (GP §4.2.1)
                              │                    (accumulation in wave 3)
                              ▼                         ▼
                       env checks (parent,        σ'  +  state root M_r(σ')
                       timeslot, H_r)              Merkle trie over 17 segments
```

1. **Import** (`import.lisp`) — decodes the block, checks preconditions (parent
   hash, state root in header, timeslot), and hands a structured block to the STF.
   This is the only place environmental context enters; everything below is
   deterministic.

2. **Transition** (`upsilon.lisp`) — runs Υ following GP §4.2.1 as **five ordered
   waves (0–4)**. Wave **1** is a bundle of **independent** transitions (the GP
   draws them side-by-side; JOTL runs them in one `let*` but they only depend on
   σ and B, not on each other): β†, η′, κ′, λ′, ψ′, ρ†. Wave **2** joins outputs from
   wave 1: γ′ (Safrole, with header checks), ρ‡, and R*. Wave **3** computes ρ′
   from guarantees, then **§12 accumulation** (ω, ξ, δ†, χ, ι, ϕ, θ via
   `accumulate.lisp`). Wave **4** merges β′, δ′ (preimages), α′, and π′.

3. **State root** — each of the 17 GP segments is a Merkle leaf; `sigma` assembles
   the trie and returns **M_r(σ')**, compared against test vectors or the fuzzer.

The same path serves unit tests (`import-block`), trace replay (`tests/conformance.lisp`),
and the **fuzz-v1** target (`fuzz-target.lisp`) used for official conformance runs.

---

## What is different

**Immutable state closures.** Every GP component (τ η κ λ β ψ ρ ι γ α ϕ δ π χ ω ξ θ)
is built by one macro, `define-state-closure`: data, codec, and `:transition` live
behind a single message-passing interface. Transitions return new closures; nothing
is mutated in place. Forking and fuzz sessions can keep multiple σ branches without
defensive copying.

**Sovereign components.** Orchestrators (`upsilon`, `accumulate`) wire inputs and
outputs; they do not reach into segment internals. Multi-stage segments expose
`:transition-dagger` / `:transition-ddagger` where the Gray Paper defines
intermediate states (e.g. δ†, ρ†, ρ‡).

**PVM in Lisp.** The interpreter (GP Appendix A) precomputes basic-block boundaries
and a skip table; instructions decode on first use and stay cached. All host calls
(GP Appendix B) live under `src/jam-host/`. Only cryptographic primitives sit in
Rust — business logic stays in Lisp, per the JAM Prize language-set rules.

**Spec-first codebase.** Transition code is annotated against GP equations; the
implementation is intended to be read alongside the Gray Paper, not as a black box.

---

## Conformance

| Suite | Scope | Result |
|-------|-------|--------|
| [jamtestvectors](https://github.com/w3f/jamtestvectors) | 8 traces, 1000 blocks | **1000/1000** |
| [polkajam fuzz-reports](https://github.com/paritytech/polkajam/) | 205 traces, 760 steps | **735 pass**, 25 expected reject, **0 fail** |
| minifuzz `no_forks` | fuzz-v1 | **102/102** |
| minifuzz `forks` | fuzz-v1 | **102/102** |

<details>
<summary>Per-trace breakdown (jamtestvectors)</summary>

| Trace | Chain | Step | Errors |
|-------|------:|-----:|-------:|
| fallback | 100/100 | 100/100 | 0 |
| safrole | 100/100 | 100/100 | 0 |
| storage | 100/100 | 100/100 | 0 |
| storage_light | 100/100 | 100/100 | 0 |
| preimages | 100/100 | 100/100 | 0 |
| preimages_light | 100/100 | 100/100 | 0 |
| fuzzy_light | 200/200 | 200/200 | 0 |
| fuzzy | 200/200 | 200/200 | 0 |

</details>

Continuous integration against the public harness:
[![Performance](https://github.com/FluffyLabs/jam-testing/actions/workflows/jotl-performance.yml/badge.svg)](https://github.com/FluffyLabs/jam-testing/actions/workflows/jotl-performance.yml)

---

## Quick start

### Docker (fuzz-v1 target)

Image follows [standard target packaging](https://github.com/davxy/jam-conformance/tree/main/fuzz-proto#standard-target-packaging)
(`JAM_FUZZ_*` environment variables).

```bash
docker build -t jotl .
mkdir -p /tmp/jam/data
docker run --rm \
  -e JAM_FUZZ=1 \
  -e JAM_FUZZ_SPEC=tiny \
  -e JAM_FUZZ_DATA_PATH=/tmp/jam/data/ \
  -e JAM_FUZZ_SOCK_PATH=/tmp/jam/fuzz.sock \
  -e JAM_FUZZ_LOG_LEVEL=info \
  -v /tmp/jam:/tmp/jam \
  jotl
```

### Standalone binary

```bash
./scripts/build.sh                  # → ./jotl
./jotl test                         # conformance (jamtestvectors)
./jotl test -v storage              # one trace, verbose
./jotl fuzz /tmp/jam/fuzz.sock      # fuzz-v1 server (set JAM_FUZZ_* yourself)
./jotl version
```

### Native development

**Prerequisites:** [SBCL](http://www.sbcl.org/) ≥ 2.3, [Quicklisp](https://www.quicklisp.org/), [Rust](https://rustup.rs/) stable.

```bash
cargo build --manifest-path crypto/jam-crypto/Cargo.toml --release

git clone https://github.com/w3f/jamtestvectors.git ../jamtestvectors
git clone https://github.com/w3f/jam-conformance.git ../jam-conformance

./scripts/test.sh                           # all traces
./scripts/test.sh storage -v                # one trace
./scripts/test-reports.sh                   # polkajam fuzz-reports
./scripts/fuzz-target.sh /tmp/jam/fuzz.sock # local fuzz target (needs JAM_FUZZ=1, …)
```

**Test data discovery**

| Method | `test.sh` | `test-reports.sh` |
|--------|-----------|-------------------|
| CLI | `--vectors PATH` | `--conformance PATH` |
| Env | `JAM_TEST_VECTORS` | `TRACES_DIR` |
| Default | `../jamtestvectors/traces/` | `../jam-conformance/fuzz-reports/0.7.2/traces/` |

---

## Repository layout

```
src/
├── import.lisp         Block import / trust boundary
├── upsilon.lisp        Υ(σ, B) → σ'  (GP §4)
├── accumulate.lisp     Accumulation (GP §12)
├── fuzz-target.lisp    fuzz-v1 protocol server
├── jamvm/              PVM interpreter (GP Appendix A)
├── jam-host/           Host calls (GP Appendix B)
├── lib/                Codecs, constants, Merkle trie, MMR
├── bloc/               Header, extrinsics, work reports
└── state/              17 state segments (one file each)

crypto/jam-crypto/      Rust FFI
tests/                  Conformance runners
scripts/                Build and test entry points
```

### Size

| Domain | Lines (approx.) |
|--------|----------------:|
| STF (state, orchestration, codecs, Merkle) | ~12k |
| PVM + host | ~5.5k |
| Crypto FFI | ~2k |
| **Total** | **~21k** |

---

## License

GPL-3.0 — see [LICENSE](LICENSE).
