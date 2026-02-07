# JOTL — JAM On The Lisp

Pure Functional JAM Protocol implementation in Common Lisp.

Gray Paper: [graypaper.com](https://graypaper.com) (v0.7.2)

## What Works

- **Block codec** — Full decode/encode of B = (H, E) against all test vectors
  - Header H = (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
  - Extrinsic E = (ET, EP, EG, EA, ED)
  - WorkReport, RefineContext, WorkResult structures
  - Header hash H(E(H)) = blake2b(sealed header)
  - Extrinsic hash HX = H(H(ET)‖H(EP)‖H(g)‖H(EA)‖H(ED))
- **State σ** — Immutable closure with 17 segments (GP §4.4)
- **Υ(σ, B) → σ'** — Block-level STF with dependency graph (GP §4.2.1)
- **Timeslot τ** — STF with epoch/phase derivation (GP §6)
- **Entropy η** — STF with randomness accumulator (GP §7)
- **Recent History β** — STF with MMR peaks (GP §7)
- **Structural validation** — HX, HP, HT checks (GP §5)
- **Crypto FFI** — Blake2b, Keccak, Ed25519, Bandersnatch VRF, PVM
- **Chainspec** — tiny/full configs switchable at runtime

## Architecture

```
src/
├── core/
│   ├── constants.lisp      Chainspec (tiny/full), protocol constants
│   └── macros.lisp         define-value-object macro
│
├── codec/
│   ├── primitives.lisp     HOW to encode: El, compact, sequence, option
│   ├── types.lisp          WHAT to encode: Hash, Key, Signature, Validator
│   └── state-keys.lisp     Merklization keys C(1)..C(16), C(255,s)
│
├── block/
│   ├── header.lisp         H closure + encode/decode + hash (GP §5)
│   ├── work-report.lisp    WorkReport + RefineContext + WorkResult
│   ├── extrinsic/
│   │   ├── tickets.lisp        ET (GP §6.4)
│   │   ├── preimages.lisp      EP (GP §7.4)
│   │   ├── assurances.lisp     EA (GP §11)
│   │   ├── disputes.lisp       ED (GP §10)
│   │   ├── guarantees.lisp     EG (GP §11-12)
│   │   └── extrinsic.lisp      E closure + encode/decode + HX
│   ├── block.lisp          B closure + decode-block
│   └── validation.lisp     Structural checks: HX, HP, HT
│
├── stf/
│   ├── sigma.lisp          σ closure — 17 segments (GP §4.4)
│   ├── tau.lisp             τ STF + state codec (GP §6)
│   ├── eta.lisp             η STF + state codec (GP §7)
│   ├── beta.lisp            β STF + MMR + state codec (GP §7)
│   └── upsilon.lisp         Υ(σ,B)→σ' orchestrator (GP §4.2.1)
│
├── utils/
│   ├── mmr.lisp            Merkle Mountain Range
│   ├── merkle-trie.lisp    Merkle Trie (GP Appendix D)
│   └── display.lisp        Display utilities
│
crypto/                     FFI to Rust (jam-crypto)
tests/                      Test vectors (w3f/jamtestvectors)
```

### Design Principles

**One representation, everywhere.** `decode-block` returns closures.
No `(if (functionp x) ...)` dispatch. Closures all the way down.

**Three domains, zero overlap:**
- `codec/` = HOW to serialize (encoding primitives, protocol types)
- `block/` = WHAT a block is (pure data + its codec + structural validation)
- `stf/`   = HOW state evolves (σ, τ, η, β, Υ — pure computation + state codec)

**Block is data, not computation.** A block is immutable, self-sufficient,
and carries its own encoding/hashing. It's not an STF.

**STF owns its codec.** Each STF file contains the state transition logic
AND the encode/decode functions for its state segment.

### Pure FP with Closures

`define-value-object` generates immutable closures with accessors, `:memo` fields, and `self` reference:

```lisp
(define-value-object header
  ((parent-hash nil) (slot nil) ...)
  (:encoded :memo (encode-header parent-hash ...))
  (:hash :memo (blake2b-256 (self :encoded))))
```

## Quick Start

```bash
sbcl --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :jotl)'
```

## Tests

```bash
# Full test suite: codec roundtrips + HX traces + block roundtrip
sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-block-roundtrip.lisp")'

# STF tests
sbcl ... --eval '(load "tests/test-beta.lisp")'   # Recent History β
sbcl ... --eval '(load "tests/test-eta.lisp")'     # Entropy η
```

### Test Coverage

| Test | Vectors | What |
|------|---------|------|
| `test-block-roundtrip` | codec/{tiny,full}/ | Block, headers×2, extrinsics×5, work-report, work-result×2, refine-context — all byte-exact roundtrip + JSON cross-val |
| `test-block-roundtrip` | trace-vectors/ | HX verification (authoritative) |
| `test-beta` | stf/history/{tiny,full}/ | β STF against 4 test vectors |
| `test-eta` | stf/safrole/{tiny,full}/ | η STF against safrole test vectors |

## Roadmap

- [x] JAM Codec (Appendix C)
- [x] Block B = (H, E) — full codec, all test vectors
- [x] Header hash H(E(H))
- [x] Extrinsic hash HX
- [x] State σ closure (17 segments)
- [x] Υ(σ, B) → σ' dependency graph
- [x] Timeslot τ STF (§6)
- [x] Entropy η STF (§7)
- [x] Recent History β STF (§7)
- [x] Structural validation (§5)
- [x] Unified architecture — closures everywhere, define-value-object
- [ ] Safrole γ STF (§6) — tickets, VRF, validator selection
- [ ] Disputes ψ STF (§10)
- [ ] Assurances/Guarantees ρ STF (§11-12)
- [ ] Accumulate STF (§8) + PVM
- [ ] Refine STF (§9) + PVM
- [ ] State Merklization HR (Appendix D)
- [ ] Bandersnatch VRF validation (HV, HS)

## Dependencies

- SBCL (Common Lisp)
- Alexandria, cl-json
- CFFI + Rust crypto (`cargo build --release` in `crypto/jam-crypto/`)
- Test vectors: `git clone https://github.com/w3f/jamtestvectors tests/jamtestvectors`

## License

MIT
