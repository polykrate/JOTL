# JOTL Tests

## Test Suites

| File | STF | Vectors | Exhaustif ? |
|------|------|---------|------------|
| `test-block-roundtrip.lisp` | Codec | `codec/{tiny,full}/*.{bin,json}` + `trace-vectors/` | bin⇄json⇄roundtrip |
| `test-eta.lisp` | η (Entropy) §7 | `stf/safrole/{tiny,full}/*.json` | JSON byte-by-byte + codec roundtrip |
| `test-beta.lisp` | β (History) §7 | `stf/history/{tiny,full}/*.{bin,json}` | bin⇄json + STF + encode roundtrip |
| `test-psi.lisp` | ψ (Disputes) §10 | `stf/disputes/{tiny,full}/*.json` | JSON deep content + codec roundtrip |
| `test-utils.lisp` | — | — | Shared helpers |

## Scores

```
η:  30/42 passed (12 skipped — safrole error cases)
β:   8/8  passed
ψ:  56/56 passed (28 tiny + 28 full)
```

### η skips (12)

All 12 are safrole validation errors (block rejected → σ'=σ):

| Error | VRF? | Count |
|-------|------|-------|
| `bad_slot` | ❌ | 2 |
| `bad_ticket_attempt` | ❌ | 2 |
| `duplicate_ticket` | ❌ | 2 |
| `bad_ticket_order` | ❌ | 2 |
| `bad_ticket_proof` | ✅ | 2 |
| `unexpected_ticket` | ❌ | 2 |

Only `bad_ticket_proof` is VRF-related. These will be covered when safrole STF is implemented.

## Running

```bash
cd /path/to/JOTL

# All tests
sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-eta.lisp")' \
  --eval '(load "tests/test-beta.lisp")' \
  --eval '(load "tests/test-psi.lisp")'
```

## Architecture

```
import-block(bytes, env)        ← node layer (future, impure)
  ├── decode-block(bytes)        codec
  ├── validate env checks        wall-clock, parent hash
  └── apply-block(σ, B)         Υ(σ, B) → σ'  — PURE
        │
        ├── validate-block(B)        intrinsic: HX only
        │
        └── transition-state(σ, B)   GP §4.2.1 — 4 waves
              │
              ├── WAVE 1: τ', η', β†, κ', λ', ψ'/v
              ├── WAVE 2: ρ†, γ', ρ‡, R*
              ├── WAVE 3: ρ', (ω',ξ',δ‡,χ',ι',ϕ',θ',S)
              └── WAVE 4: β', δ', α', π'  →  σ'
```
