# JOTL — JAM On The Lisp

Common Lisp implementation of the JAM state transition function Υ(σ, B) → σ'.

[Gray Paper](https://graypaper.com) v0.7.2 · [Test vectors](https://github.com/w3f/jamtestvectors)

## Conformance

| Trace | Chain | Step | Errors |
|-------|------:|-----:|-------:|
| fallback | 100/100 | 100/100 | 0 |
| safrole | 100/100 | 100/100 | 0 |
| storage | 100/100 | 100/100 | 0 |
| storage_light | 100/100 | 100/100 | 0 |
| preimages | 100/100 | 100/100 | 0 |
| preimages_light | 100/100 | 100/100 | 0 |
| fuzzy_light | 200/200 | 200/200 | 0 |
| fuzzy | 22/23 | 164/200 | 0 |

**964/1000 deterministic traces pass** — byte-exact state root match,
both chain and step modes. 0 silent errors.

### Remaining failures — 36 steps (fuzzy only)

All 36 failures are in `fuzzy` (random service profile, max 6 work items).
`fuzzy_light` (empty service profile, max 1 work item) passes 200/200.

| Category | Pattern | Count | Root cause | Status |
|----------|---------|------:|------------|--------|
| A | `delta-kvs` u64 on key `#(5)` | ~31 | Guest Blake2b hash loop reads wrong data → wrong u64 at key 5 | **Narrowed** |
| B | `pi` + `delta-kvs` | ~4 | Gas diff + cascading storage diff | Investigating |
| C | `beta + theta + delta-kvs` | 1 | block 68: wrong β/θ + cascading δ diff | Investigating |

#### Category A deep dive — Block 23 reference

Only **2 delta-KVs differ** (out of 58 total), both on raw storage key `#(5)`:

| h27 key | Expected | Got |
|---------|----------|-----|
| `17D710...` | `24AED661DE8D80F6` | `CDF76F2989A9B8FF` |
| `68D7B1...` | `C4E2386B810E0ED5` | `44E3DDA088EFB288` |

**Mechanism (understood):**
1. Guest receives ΩY kind=14 data at buffer 0x328E0 (RW data section, NOT heap)
2. Guest processes data, then **reuses same buffer** for ΩR (read storage) etc.
3. Blake2b hash loop later reads 8 bytes from 0x328E0+2, but buffer now has different data
4. Hash written to key `#(5)` via ΩW is computed from whatever is at 0x328E0 at that time
5. This is **normal guest behavior** — the buffer is intentionally reused
6. The divergence comes from an **earlier host call returning different data** than expected, cascading into different buffer contents at hash time

**Verified correct (ruled out):**
- PVM instructions: `load-ind-u8`, `xor`, `move_reg`(100), `sbrk`(101), `count_set_bits`(102–103), `leading_zero_bits`(104–105) — all match GP spec
- `sbrk` heap init: heap-base=0x33000, page-aligned, starts on inaccessible page
- ΩY fetch kind=14: correctly writes 172 bytes of accumulate items to guest memory
- AccumulateItem encoding (WorkItemRecord, TransferRecord, AccumulateParams) verified against codec test vectors
- Service info encoding (ΩI, host call 5) produces correct 96-byte records
- Host call context gating (`context-allows-p`) correct for accumulate context
- JAM compact integer encoding matches GP C.5

**Next step — find the divergent host call:**
- Host call sequence for SID=3953987607 block 23: 4×ΩY, 1×ΩI, 4×ext_log, 4×ΩR, 2×ΩW, 2×ΩC, 1×ΩY(entropy) = 18 calls total
- Need to compare each host call's output with expected values
- Best approach: step-trace PVM execution and compare register snapshots, or generate a reference host-call trace and diff

**Host call ID mapping (verified against `defomega`):**
```
 0:ΩG(gas)     1:ΩY(fetch)   2:ΩL(lookup)   3:ΩR(read)     4:ΩW(write)    5:ΩI(info)
 6:ΩH(hist)    7:ΩE(export)  8:ΩM(make)     9:ΩP(peek)    10:ΩO(poke)    11:ΩZ(pages)
12:ΩK(invoke) 13:expunge    14:ΩB(bless)   15:ΩA(assign)  16:ΩD(designate) 17:ΩC(checkpoint)
18:ΩN(new)    19:upgrade    20:transfer    21:eject       22-26:preimage   99:ΩX(abort)
100:ext_log
```

**Diagnostic tools:**
- `tests/diag-opcode-diff.lisp` — PVM register ring buffer around ΩW key(5) writes
- `tests/diag-decode-loop.lisp` — decode loop diagnostic

### Fixed bugs

| Fix | Impact | Details |
|-----|-------:|---------|
| **Page fault handling** | +6 steps | `vm-run` now handles page faults: allocates faulting page as R/W and retries instruction. Gas stays charged per GP: "some gas is always charged whenever execution is attempted" |
| **OOB PC trap decode** | correctness | `decode-instruction` returns trap (opcode 0, gas=1) for OOB PC instead of NIL → gas always charged on trap |
| **RA halt sentinel** | +42 steps | `argument-invoke` now sets RA to dynamic halt sentinel `Z_A*(|j|+1)` per GP spec, fixing outermost return |
| **next-service-id init** | +2 steps | `hctx-next-service-id` defaulted to 0, causing ΩN to overwrite manager service. Now initialized via GP B.14 formula |
| **Checkpoint balance revert** | correctness | Balance, code-hash, min-gas fields now saved/restored in checkpoint on panic/OOG rollback |
| **Created services (list/cons)** | 0 errors | `collect-effects` used `cdr` on 2-element list; fixed to `second` — eliminated 32 TYPE-ERRORs |
| **read-guest OOM cap** | 0 crashes | Safety cap (64 MB) on `read-guest` prevents heap exhaustion from adversarial lengths |
| **Invalid block handling** | +8 blocks | Blocks with bad-code-hash guarantee → return pre-state unchanged (no-op) |
| **Silent error display** | — | Step-mode errors now shown in conformance table instead of being swallowed |
| **χ privilege (ΩB)** | +1 block | Removed incorrect `existing_services` check. GP B.7: `N_S = N_{2^32}` |
| **δ-KVS code_hash** | +6 blocks | PVM `:upgrades`/`:created` side-effects applied to δ-KVS via extended wire format |
| **β accumulate-root** | +2 blocks | Binary Merkle N function (GP E.1) now uses `$node` prefix |
| **θ/β yield** | +54 blocks | PVM yield detected via A0/A1 return registers, not just `omega_yield` host call |

## Architecture

Each GP state component (τ η κ λ β ψ ρ ι γ α ϕ δ π χ ω ξ θ) is a
let-over-lambda closure generated by one macro: `define-state-closure`.
A closure receives a message, returns a new version of itself. No CLOS,
no mutation.

**Uniform `:transition` protocol** — every closure follows the same contract:

- `:transition` returns the **new closure**, period. No `multiple-value-bind`.
- Side-data computed during transition (e.g. R* from ω, emitted validators
  from χ) is stored as **transient fields** queryable on the returned closure,
  same pattern as ρ‡ `:reported`.
- Multi-stage transitions use `:transition-dagger` / `:transition-ddagger`
  (e.g. δ†, ρ†, ρ‡).
- Components are **sovereign**: each owns its data, its codec, and its
  transition logic. The orchestrators (`upsilon.lisp`, `accumulate.lisp`)
  only send messages and coordinate data flow.

σ owns the raw byte store and dispatches to component closures.
Υ orchestrates the 4-wave dependency graph from GP §4.2.1.
`accumulate.lisp` orchestrates §12 (R*, PVM execution, privilege resolution).
`import-block` is the boundary — pure below, observation above.

Crypto (Blake2b, Bandersnatch, Ed25519) is Rust via CFFI.
PVM (GP Appendix A) is pure Common Lisp (`src/jamvm/`), with host calls
(GP Appendix B) in `src/jam-host/`. Instruction tracing (`*vm-trace-stream*`)
available for step-level debugging.

~12K lines Lisp · ~3K lines Rust

## Run

```bash
cargo build --manifest-path crypto/jam-crypto/Cargo.toml --release

./scripts/test.sh                    # all traces
./scripts/test.sh storage -v         # verbose, per-block output
./scripts/test.sh safrole preimages  # specific traces
```

## Layout

```
src/
├── upsilon.lisp        Υ(σ,B)→σ'  4-wave graph
├── accumulate.lisp     §12  R*, PVM orchestration
├── import.lisp         Block import, chain logging
├── lib/                Codecs, constants, Merkle trie, MMR
├── bloc/               Header, extrinsics, work reports
└── state/              17 components (one file each)

crypto/jam-crypto/      Rust: crypto primitives + PolkaVM host calls
tests/conformance.lisp  Trace runner (colored diff on 800+ blocks)
```

## License

GPL-3.0
