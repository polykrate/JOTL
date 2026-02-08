# JOTL Tests

## Test Suites

| File | STF | GP § | Vectors | Exhaustif ? |
|------|------|------|---------|------------|
| `test-block-roundtrip.lisp` | Codec | App. C | `codec/{tiny,full}/*.{bin,json}` + `trace-vectors/` | bin⇄json⇄roundtrip |
| `test-eta.lisp` | η (Entropy) | §6.21-23 | `stf/safrole/{tiny,full}/*.json` (42) | JSON byte-by-byte + codec roundtrip + error cases |
| `test-beta.lisp` | β (History) | §7.5 | `stf/history/{tiny,full}/*.json` (8) | bin⇄json + STF + encode roundtrip |
| `test-psi.lisp` | ψ (Disputes) | §10 | `stf/disputes/{tiny,full}/*.json` (56) | JSON deep content + codec roundtrip |
| `test-safrole.lisp` | γ (Safrole) | §6 | `stf/safrole/{tiny,full}/*.json` (42) | All 10 state segments + marks + codec roundtrip + Ring VRF |
| `test-utils.lisp` | — | — | — | Shared helpers |

## Scores — 190/190 ✅

```
η:  42/42  ✅  (includes error cases: η unchanged on bad blocks)
β:   8/8   ✅  (4 tiny + 4 full)
ψ:  56/56  ✅  (28 tiny + 28 full)
γ:  42/42  ✅  (21 tiny + 21 full, Ring VRF verified)
─────────────
   148/148  ✅  + block codec roundtrips
```

## Running

```bash
cd /path/to/JOTL

# All STF tests
sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-eta.lisp")' \
  --eval '(load "tests/test-beta.lisp")' \
  --eval '(load "tests/test-psi.lisp")' \
  --eval '(load "tests/test-safrole.lisp")'
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
              ├── WAVE 3: ρ', accumulate(ω',ξ',δ‡,χ',ι',ϕ',θ',S)
              └── WAVE 4: β', δ', α', π'  →  σ'
```

## What's Next

| STF | GP § | Vectors | Status |
|-----|------|---------|--------|
| ρ‡ (assurances) | §11 | 20 | 🟡 stub |
| ρ' (guarantees) | §11-12 | 84 | 🟡 stub |
| accumulate | §8 | 60 | 🔴 needs PVM |
| δ' (preimages) | §7 | 16 | 🟡 stub |
| α' (authorizations) | §13 | 6 | 🟡 stub |
| π' (statistics) | §15 | 6 | 🟡 stub |
