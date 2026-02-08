# JOTL — JAM On The Lisp

Pure Functional JAM Protocol implementation in Common Lisp.

Gray Paper: [graypaper.com](https://graypaper.com) (v0.7.2)

## What Works — 190 tests ✅

- **Block codec** — Full decode/encode of B = (H, E) against all test vectors
  - Header H = (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
  - Extrinsic E = (ET, EP, EG, EA, ED)
  - WorkReport, RefineContext, WorkResult structures
  - Header hash H(E(H)) = blake2b(sealed header)
  - Extrinsic hash HX = H(H(ET)‖H(EP)‖H(g)‖H(EA)‖H(ED))
- **State σ** — Immutable closure with 17 segments (GP §4.4)
- **Υ(σ, B) → σ'** — Block-level STF with 4-wave dependency graph (GP §4.2.1)
- **Safrole γ** — Complete: seal/entropy VRF, tickets, epoch rotation (GP §6) — 42/42
- **Disputes ψ** — Complete: verdicts, culprits, faults, offenders (GP §10) — 56/56
- **Timeslot τ** — STF with epoch/phase derivation (GP §6)
- **Entropy η** — STF with randomness accumulator (GP §6.21-23) — 42/42
- **Recent History β** — STF with MMR peaks (GP §7.5) — 8/8
- **Validator keys κ, λ, ι** — Epoch rotation with offender filtering (GP §6.14-16)
- **Assignments ρ†** — Invalidation on bad/wonky verdicts (GP §10.15)
- **Structural validation** — HX, HP, HT checks (GP §5)
- **Crypto FFI** — Blake2b, Keccak, Ed25519, Bandersnatch VRF (Ring VRF + SRS)
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
│   ├── tau.lisp             τ timeslot + state codec (GP §6)
│   ├── eta.lisp             η entropy + state codec (GP §6.21-23)
│   ├── beta.lisp            β recent history + MMR + state codec (GP §7)
│   ├── psi.lisp             ψ disputes + state codec (GP §10)
│   ├── rho.lisp             ρ assignments: ρ†, ρ‡, ρ' (GP §10-12)
│   ├── kappa.lisp           κ current validators + state codec (GP §6.15)
│   ├── lambda.lisp          λ archived validators + state codec (GP §6.16)
│   ├── iota.lisp            ι enqueued validators + state codec
│   ├── gamma.lisp           γ safrole: seal, VRF, tickets (GP §6)
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
- `stf/`   = HOW state evolves (σ, τ, η, β, ψ, γ, κ, λ, ι, ρ, Υ — pure computation + state codec)

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

## Tests — 190/190 ✅

```bash
# All STF tests
sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-eta.lisp")' \
  --eval '(load "tests/test-beta.lisp")' \
  --eval '(load "tests/test-psi.lisp")' \
  --eval '(load "tests/test-safrole.lisp")'

# Block codec roundtrip
sbcl ... --eval '(load "tests/test-block-roundtrip.lisp")'
```

### Test Coverage

| Test | GP § | Vectors | What |
|------|------|---------|------|
| `test-safrole` | §6 | 42 (21+21) | γ STF: all 10 state segments + epoch/tickets marks + Ring VRF + codec roundtrip |
| `test-psi` | §10 | 56 (28+28) | ψ STF: deep byte-by-byte hash comparison + codec roundtrip |
| `test-eta` | §6.21-23 | 42 (21+21) | η STF: entropy accumulator + error cases (η unchanged) + codec roundtrip |
| `test-beta` | §7.5 | 8 (4+4) | β STF: MMR peaks + codec roundtrip |
| `test-block-roundtrip` | App. C | codec/ + traces/ | Block, headers×2, extrinsics×5, work-report — bin⇄json roundtrip + HX |

## Roadmap

- [x] JAM Codec (Appendix C)
- [x] Block B = (H, E) — full codec, all test vectors
- [x] Header hash H(E(H))
- [x] Extrinsic hash HX
- [x] State σ closure (17 segments)
- [x] Υ(σ, B) → σ' dependency graph (4 waves)
- [x] Timeslot τ STF (§6)
- [x] Entropy η STF (§6.21-23) — 42/42
- [x] Recent History β† STF (§7.5) — 8/8
- [x] Disputes ψ STF (§10) — 56/56
- [x] Safrole γ STF (§6) — seal, VRF, tickets, epoch rotation — 42/42
- [x] Validator keys κ, λ, ι (§6.14-16)
- [x] Assignments ρ† invalidation (§10.15)
- [x] Structural validation (§5)
- [x] Unified architecture — closures everywhere, define-value-object
- [x] Bandersnatch Ring VRF — seal + ticket validation with SRS
- [ ] Assurances ρ‡ (§11) — 20 vectors
- [ ] Guarantees ρ' (§11-12) — 84 vectors
- [ ] Preimages δ' (§7) — 16 vectors
- [ ] Authorizations α' (§13) — 6 vectors
- [ ] Statistics π' (§15) — 6 vectors
- [ ] Accumulate STF (§8) + PVM — 60 vectors
- [ ] Refine STF (§9) + PVM
- [ ] State Merklization HR (Appendix D)

## Dependencies

- SBCL (Common Lisp)
- Alexandria, cl-json
- CFFI + Rust crypto (`cargo build --release` in `crypto/jam-crypto/`)
- Test vectors: `git clone https://github.com/w3f/jamtestvectors tests/jamtestvectors`

## License

MIT
