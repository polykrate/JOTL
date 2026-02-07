# JOTL Tests

## Test Files

| File | What | Vectors |
|------|------|---------|
| `test-block-roundtrip.lisp` | **Main test suite** — 3 parts | |
| | Part 1: Block decode↔encode + JSON cross-validation | `codec/{tiny,full}/block.{bin,json}` |
| | Part 2: HX trace verification (authoritative) | `trace-vectors/extrinsic_hash/*.json` |
| | Part 3: Individual codec roundtrips (24 vectors) | `codec/{tiny,full}/*.{bin,json}` |
| `test-beta.lisp` | β (Recent History) STF — §7 | `stf/history/{tiny,full}/*.json` |
| `test-eta.lisp` | η (Entropy) STF — §7 | `stf/safrole/{tiny,full}/*.json` |
| `test-hx-trace.lisp` | HX encode-from-JSON helpers (used by roundtrip) | `trace-vectors/` |
| `test-utils.lisp` | Shared helpers: `hex-to-bytes`, `bytes=`, `load-json`, `load-bin` | — |

## Running

```bash
cd /home/polycrate/Projets/JOTL

# Full codec + block suite
sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-block-roundtrip.lisp")'

# STF tests
sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-beta.lisp")'

sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-eta.lisp")'
```

## Test Vectors

### `jamtestvectors/codec/` — Structural encoding/decoding
- `block.{bin,json}` — full block (header + extrinsic)
- `header_0` — epoch_mark=Some, tickets_mark=None, offenders=1
- `header_1` — epoch_mark=None, tickets_mark=Some, offenders=0
- `tickets_extrinsic`, `preimages_extrinsic`, `assurances_extrinsic`, `disputes_extrinsic`, `guarantees_extrinsic`
- `extrinsic` — full extrinsic (all 5 components)
- `work_report`, `work_result_0`, `work_result_1`, `refine_context`

**Note:** Codec vectors are syntactically correct only. The HX in the header is a placeholder — semantic correctness is tested via STF and trace vectors.

### `jamtestvectors/stf/` — State transition functions
- `history/` — β (Recent History) — 4 vectors per spec
- `safrole/` — η (Entropy) extracted from safrole vectors

### `trace-vectors/extrinsic_hash/` — Real block traces
- `tickets.json` — block with 1 ticket
- `preimages_guarantees_assurances.json` — block with mixed extrinsics

These have **correct HX values** (unlike codec vectors).

## Architecture

```
import-block(bytes, env)      ← node layer (future, impure)
  ├── decode-block(bytes)      codec
  ├── validate env checks      wall-clock (HT·P ≤ T), parent hash (HP)
  └── apply-block(σ, B)       Υ(σ, B) → σ'  (stf/upsilon.lisp) — PURE
        │
        ├── validate-block(B)      intrinsic: HX only (block/validation.lisp)
        │
        └── transition-state(σ, B)  sub-STFs in wave order
              ├── WAVE 1: τ', η', ψ', ρ†, β†
              ├── WAVE 2: κ', λ', ρ‡, R*
              ├── WAVE 3: ρ', γ'
              ├── WAVE 4: accumulate → ω', ξ', δ‡, χ', ι', ϕ', θ', S
              └── WAVE 5: β', δ', α', π'  →  make-state → σ'
```

**Key separation:**
- `σ` = data (closure) — `sigma.lisp` — passive container, calls nothing
- `B` = data (closure) — `block.lisp` — passive container
- `Υ` = `apply-block(σ, B) → σ'` — `upsilon.lisp` — pure computation
- `import-block` = node API — not yet implemented — owns I/O and env context
