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

| Category | Pattern | Blocks | Count | Status |
|----------|---------|--------|------:|--------|
| A | `delta-kvs` only | 45,48,74,78,110,122,123,126,127,131,145,152,156,164,168,170,173,174,175,185,188 | 21 | Investigating |
| B | `pi` + `delta-kvs` | 23,30,56,77,90,103,105,111,119,191,196 | 11 | Investigating |
| C | `beta` + `theta` ± `pi` ± `delta-kvs` | 68,82,102,179 | 4 | **Deep dive** |

#### Category A — `delta-kvs` storage divergence

Only 2 delta-KVs differ per block, both on raw storage key `#(5)` (u64 values).
Root cause: guest Blake2b hash loop reads a buffer that has been reused by
a prior host call, producing a different hash. The divergence traces back to
an **earlier host call returning different data** than expected.

#### Category B — `pi` gas divergence + `delta-kvs`

Gas field (`pi`) is slightly off, causing cascading storage differences.
Likely the same root cause as Category A (incorrect host call → different
execution path → different gas consumption).

#### Category C — `beta` + `theta` yield hash divergence

4 blocks produce wrong yield hashes (θ), which cascade into wrong β
(recent block history contains MMR of θ). Block 82 is the cleanest case
(β+θ only, no δ or π divergence).

**Investigation status (Block 82 deep dive):**

| Verified correct | Details |
|-----------------|---------|
| PVM instructions | 64-bit XOR, rotate, shift, memory load/store all match GP spec |
| `write-guest` / `read-guest` | Cross-page writes correct, byte-level access validated |
| Protocol params (ΩY kind=0) | 134 bytes, encoding matches Rust reference |
| Entropy (ΩY kind=1) | 128 bytes, passed correctly from state |
| Accumulate items (ΩY kind=14) | Encoding verified, blob sizes match |
| Service info (ΩI, HC5) | 96-byte encoding correct; Rust uses mutated state for self-lookup |
| Storage read/write (ΩR/ΩW) | Correct h27 hashing, proper footprint tracking |
| Yield (HC25) | Correctly stores 32-byte hash from guest memory |
| Checkpoint (HC17) | Snapshot/rollback works correctly |
| AccumulateParams encoding | JAM compact `(slot, sid, item_count)` verified |
| `encode-accumulate-items-list` | WorkItemRecord structure matches codec test vectors |
| θ assembly from commitments | Correctly built from yield outputs |

| Large blob encoding | SID 516569628 has 11325-byte result data → 11462-byte WorkItemRecord. Compact prefix correct, total fetch = 11463 bytes |
| JAM compact codec | Verified for all value sizes (1/2/4/8-byte modes), matches GP C.5 |
| `encode-accumulate-params` | compact(slot) + compact(sid) + compact(item_count) correct |

**Remaining hypotheses:**
- PVM instruction bug on a specific opcode/data pattern (rare enough to pass most tests)
- Host call returning subtly wrong data that cascades through guest logic
- Instruction decoder edge case for specific immediate/skip values

**Next step:** Step-trace PVM execution for block 82 SID 516569628 and compare
register snapshots with reference, or generate a reference host-call trace and diff.

**Host call ID mapping (verified against `defomega`):**
```
 0:ΩG(gas)     1:ΩY(fetch)   2:ΩL(lookup)   3:ΩR(read)     4:ΩW(write)    5:ΩI(info)
 6:ΩH(hist)    7:ΩE(export)  8:ΩM(make)     9:ΩP(peek)    10:ΩO(poke)    11:ΩZ(pages)
12:ΩK(invoke) 13:expunge    14:ΩB(bless)   15:ΩA(assign)  16:ΩD(designate) 17:ΩC(checkpoint)
18:ΩN(new)    19:upgrade    20:transfer    21:eject       22-26:preimage   99:ΩX(abort)
100:ext_log
```

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

PVM (GP Appendix A) is **pure Common Lisp** (`src/jamvm/`), with host calls
(GP Appendix B) in `src/jam-host/`. The Rust code in `crypto/jam-crypto/src/pvm/`
is an early prototype (draft) and **does NOT handle all edge cases** — it is
superseded by the Lisp PVM implementation. The ASN schema in
`tests/jamtestvectors/` is the authoritative reference for data types.

Instruction tracing (`*vm-trace-stream*`) available for step-level debugging.

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
