# JOTL — JAM On The Lisp

Common Lisp implementation of the **JAM state transition function** Υ(σ, B) → σ'.

[Gray Paper](https://graypaper.com) v0.7.2 · [Test vectors](https://github.com/w3f/jamtestvectors)

## Conformance

### Static test vectors (1000 blocks)

| Trace | Chain | Step | Errors |
|-------|------:|-----:|-------:|
| fallback | 100/100 ✓ | 100/100 ✓ | 0 |
| safrole | 100/100 ✓ | 100/100 ✓ | 0 |
| storage | 100/100 ✓ | 100/100 ✓ | 0 |
| storage\_light | 100/100 ✓ | 100/100 ✓ | 0 |
| preimages | 100/100 ✓ | 100/100 ✓ | 0 |
| preimages\_light | 100/100 ✓ | 100/100 ✓ | 0 |
| fuzzy\_light | 200/200 ✓ | 200/200 ✓ | 0 |
| fuzzy | 200/200 ✓ | 200/200 ✓ | 0 |
| **TOTAL** | **1000/1000** | **1000/1000** | **0** |

### STF sub-component tests

| Suite | Result |
|-------|--------|
| safrole (tiny, 21 tests) | **21/21 ✓** — τ η κ λ ι γP γZ γS γA offenders |

### polkajam-fuzz traces (205 traces, 760 steps)

| Metric | Value |
|--------|-------|
| Pass | **704** |
| Correct reject | **40** |
| Fail | **16** |
| Errors | **0** |

### Minifuzz (fuzz-v1 protocol)

| Suite | Result |
|-------|--------|
| no\_forks | **102/102 ✓** |
| forks | **78/102** (mismatch at pair 79) |

### Fuzzer target (fuzz-v1)

JOTL implements a **fuzz-v1 protocol server** for real-time conformance testing
via the [jam-conformance](https://github.com/davxy/jam-conformance) fuzzer.

VRF verification is **fully enabled** — Bandersnatch IETF VRF for both seal
and entropy source, in both fallback and tickets modes:
- Seal VRF: `ad = EU(H)` (header without seal, GP §6.4)
- Entropy VRF: `ad = []` (empty, GP §6.17)
- Fallback mode key: `γ'S[HT mod E]` (GP §6.16)
- Tickets mode key: `κ'[HI].kb` (GP §6.15)

```bash
# Launch fuzzer target
./scripts/fuzz-target.sh /tmp/jam_target.sock

# Run minifuzz self-test (from jam-conformance/fuzz-proto/)
python minifuzz/minifuzz.py --target-sock /tmp/jam_target.sock \
  -d examples/0.7.2/no_forks

# With forks (simple forking support)
python minifuzz/minifuzz.py --target-sock /tmp/jam_target.sock \
  -d examples/0.7.2/forks
```

### Known bugs (investigation in progress)

| # | Component | Status | Description |
|---|-----------|--------|-------------|
| 1 | `omega-new-service` (HC18) | **FIXED** | New services were created without the initial lookup entry `{((c,l) ↦ [])}` required by GP B.10. This caused `omega-provide-preimage` (HC26) to return `HUH` instead of `OK` on the newly created service, leading to a different PVM execution path and a Δ=62 gas divergence in PI stats (sid 3101749195). Fix: `(setf (gethash (cons c l) (sa-lookup new-acct)) nil)`. |
| 2 | `omega-provide-preimage` (HC26) | **FIXED** | HC26 did not update the lookup entry from `[]` to `[τ']` after successfully providing a preimage (GP B.6: `a_l'[(H(i),\|i\|)] = [τ']`). This caused DELTA-KVS divergences where the lookup trie value stayed at `compact(0)` (1 byte) instead of `compact(1).E4(τ')` (5 bytes). Additionally, `delta.lisp` did not update lookup entries for cross-service provided preimages (HC26 on a newly-created service). |
| 3 | `accumulate-service` gas=0 OOG | **FIXED** | When a service received a deferred transfer with `gas=0`, the PVM was run and went OOG immediately. `last-accumulation-slot` was incorrectly updated to current timeslot. GP B.9: with gas=0, no code runs → skip PVM, credit balance, do NOT update `last-accumulation-slot`. Fix: early return with `:no-code t` when `(zerop gas-limit)`. **+2 traces fixed** (695→697 pass). |
| 4 | PI `ACCUM-GAS` for privileged service 0 | **INVESTIGATING** | Δ=-3682 gas divergence on service 0 (privileged — calls HC14 bless, HC18 new-service, 3×HC20 transfer). All host call gas deltas match expected (10 base + gas-limit for HC20). The gap is entirely in instruction-level gas. Remaining source unknown — possibly related to PVM instruction model divergence. |
| 5 | IOTA not updated (PVM PANIC → empower rollback) | **ROOT-CAUSED** | 2 traces (`1766243861_7323`, `1766479507_7943`) show IOTA+PI+DELTA-KVS divergence. **Cause**: Service 0 (privileged, χ_M=χ_V=χ_R=0) PVM exits with `PANIC` (outcome=1) instead of `HALT`. Guest hits `trap` opcode (0x00) at PC=97133 — a conditional branch earlier in execution diverges from the reference due to an upstream PVM execution difference (same root cause as bug #4). On PANIC, all empower effects are rolled back (GP B.13), including the designated validators from ΩD (HC16). Thus ι stays unchanged = pre-state. Fix depends on resolving the upstream PVM instruction-level divergence. |
| 6 | `omega-solicit-preimage` (HC23) | **FIXED** | HC23 was checking the `FULL` condition against the *pre-mutation* state, allowing a `u32` overflow in the `footprint` calculation (when `z` was large, `footprint + 81 + z` overflowed). This caused a subsequent `omega-write-storage` (HC4) to fail with `FULL`, leading to a PVM `PANIC` instead of `HALT` and thus BETA+PI+THETA+DELTA-KVS divergences (no yield, no commitments). Fix: compute `a_t` from hypothetical *post-mutation* `items-count` and `footprint` before mutating state, returning `FULL` early if threshold exceeds balance. **+7 traces fixed** (697→704 pass). |

## Architecture

Each GP state component (τ η κ λ β ψ ρ ι γ α ϕ δ π χ ω ξ θ) is a
**let-over-lambda closure** generated by one macro: `define-state-closure`.
A closure receives a message, returns a new version of itself. No CLOS,
no mutation.

**Uniform `:transition` protocol** — every closure follows the same contract:

- `:transition` returns the **new closure**, period.
- Side-data computed during transition (e.g. R\* from ω, emitted validators
  from χ) is stored as **transient fields** queryable on the returned closure.
- Multi-stage transitions use `:transition-dagger` / `:transition-ddagger`
  (e.g. δ†, ρ†, ρ‡).
- Components are **sovereign**: each owns its data, its codec, and its
  transition logic. The orchestrators (`upsilon.lisp`, `accumulate.lisp`)
  only send messages and coordinate data flow.

σ owns the raw byte store and dispatches to component closures.
Υ orchestrates the 4-wave dependency graph from GP §4.2.1.
`accumulate.lisp` orchestrates §12 (R\*, PVM execution, privilege resolution).
`import-block` is the boundary — pure below, observation above.

Crypto (Blake2b, Bandersnatch VRF, Ed25519) is Rust via CFFI (`ark-vrf` 0.2.1).

PVM (GP Appendix A) is **pure Common Lisp** (`src/jamvm/`), with host calls
(GP Appendix B) in `src/jam-host/`. Arguments are mapped at `ARGS_SEGMENT`
(0xFEFF0000) as read-only per GP A.8 / SPI convention.

### Line count

| | Code | Comments | Total |
|-|-----:|---------:|------:|
| **Lisp** | 12 907 | 4 242 | 19 314 |
| **Rust** | 1 525 | 422 | 2 277 |
| **All** | **14 432** | **4 664** | **21 591** |

<details><summary>Lisp breakdown</summary>

| Module | Code | Comments |
|--------|-----:|---------:|
| State (17 components) | 3 055 | 1 224 |
| Host calls (GP B) | 2 365 | 820 |
| PVM interpreter (GP A) | 2 105 | 975 |
| Tests & scripts | 1 768 | 245 |
| Orchestration (Υ, §12, import) | 1 140 | 316 |
| Library (codecs, Merkle) | 1 137 | 364 |
| Block/extrinsics | 845 | 231 |
| Crypto FFI bindings | 492 | 67 |

</details>

## Run

```bash
cargo build --manifest-path crypto/jam-crypto/Cargo.toml --release

# Static test vectors (1000 blocks)
./scripts/test.sh                    # all traces
./scripts/test.sh storage -v         # verbose, per-block output
./scripts/test.sh safrole preimages  # specific traces

# Polkajam fuzz-reports (205 traces, 760 steps)
./scripts/test-reports.sh                    # all traces
./scripts/test-reports.sh 1766241867         # single trace
NO_STOP=1 ./scripts/test-reports.sh          # don't stop on first fail

# Fuzzer target (fuzz-v1 protocol)
./scripts/fuzz-target.sh /tmp/jam_target.sock
```

## Layout

```
src/
├── upsilon.lisp        Υ(σ,B)→σ'  4-wave graph
├── accumulate.lisp     §12  R*, PVM orchestration
├── import.lisp         Block import, chain logging
├── fuzz-target.lisp    fuzz-v1 protocol server
├── jamvm/              PVM interpreter (GP Appendix A)
├── jam-host/           Host calls (GP Appendix B)
├── lib/                Codecs, constants, Merkle trie, MMR
├── bloc/               Header, extrinsics, work reports
└── state/              17 components (one file each)

crypto/jam-crypto/      Rust: Blake2b, Bandersnatch, Ed25519, erasure coding
scripts/
├── test.sh             Static test vectors (1000 blocks)
├── test-reports.sh     Polkajam fuzz-reports traces (205 traces)
├── fuzz-target.sh      Launch fuzzer target server
├── load-jotl.lisp      SBCL loader script
└── diag/               Diagnostic tools (gas, delta, gamma, forks)
tests/
├── conformance.lisp    Static trace runner
├── polkajam-traces.lisp  Fuzz-reports trace runner
└── stf-safrole.lisp    Safrole STF sub-component tests (21/21)
```

## License

GPL-3.0
