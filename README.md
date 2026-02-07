# JOTL v3.1 — JAM On The Lisp

Pure Functional JAM Protocol implementation in Common Lisp.

Gray Paper: [graypaper.com](https://graypaper.com) (v0.7.2)

## What Works

- **Block codec** — Full decode/encode of B = (H, E) against test vectors
  - Header H = (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
  - Extrinsic E = (ET, EP, EG, EA, ED)
  - WorkReport structure within EG
  - Header hash H(E(H)) = blake2b(sealed header)
  - Extrinsic hash HX = H(ET‖EP‖g‖EA‖ED)
- **State σ** — Immutable closure with 17 segments (GP §4.4)
- **Υ(σ, B) → σ'** — Block-level STF with dependency graph (GP §4.2.1)
- **Timeslot τ** — STF with epoch/phase derivation (GP §6.1-6.2)
- **Structural validation** — HX, HP, HT·P≤T checks (GP §5)
- **Crypto FFI** — Blake2b, Keccak, Ed25519, Bandersnatch VRF, PVM
- **Chainspec** — tiny/full configs switchable at runtime

## Architecture

```
src/
├── core/               CONSTANTS
│   └── constants.lisp      Chainspec (tiny/full)
│
├── codec/              ENCODING PRIMITIVES (GP Appendix C)
│   ├── primitives.lisp     HOW to encode: El, compact, sequence, option
│   └── types.lisp          WHAT to encode: Hash, Key, Signature, Validator
│
├── block/              BLOCK DATA — B=(H,E) + encode/decode/hash/validation
│   ├── header.lisp         H closure + encode/decode + hash (GP §5)
│   ├── work-report.lisp    WorkReport structures (GP §11-12)
│   ├── extrinsic/          Extrinsic sub-types + orchestrator + HX
│   │   ├── tickets.lisp        ET (GP §6.4)
│   │   ├── preimages.lisp      EP (GP §7.4)
│   │   ├── assurances.lisp     EA (GP §11)
│   │   ├── disputes.lisp       ED (GP §10)
│   │   ├── guarantees.lisp     EG (GP §11-12)
│   │   └── extrinsic.lisp      E closure + encode/decode + HX (GP §4.3, §5.4-5.6)
│   ├── block.lisp          B closure + decode-block (→closures) (GP §4.2)
│   └── validation.lisp     Structural checks: HX, HP, HT (GP §5)
│
├── stf/                STATE TRANSITION FUNCTIONS
│   ├── sigma.lisp          σ closure — 17 segments (GP §4.4)
│   ├── tau.lisp            τ STF — epoch, phase (GP §6.1-6.2)
│   └── upsilon.lisp        Υ(σ,B)→σ' + sub-STF stubs (GP §4.2.1)
│
├── utils/
│   └── merkle-trie.lisp    Merkle Trie (GP Appendix D)
│
crypto/                 FFI to Rust (jam-crypto)
tests/                  Test vectors (w3f/jamtestvectors)
```

### Design Principles

**One representation, everywhere.** `decode-block` returns closures.
No `(if (functionp x) ...)` dispatch. Closures all the way down.

**Three domains, zero overlap:**
- `codec/` = HOW to serialize (encoding primitives, protocol types)
- `block/` = WHAT a block is (pure data + its codec + structural validation)
- `stf/`   = HOW state evolves (σ, τ, Υ — pure computation)

**Block is data, not computation.** A block is immutable, self-sufficient,
and carries its own encoding/hashing. It's not an STF.

### Pure FP with Closures

No `defstruct`. Everything is functions returning functions:

```lisp
;; State is an immutable closure
(let* ((σ  (make-state :tau 0))
       (σ' (apply-block σ block)))
  (state-tau σ)   ; → 0  (unchanged)
  (state-tau σ'))  ; → 42 (new state)
```

### STF Pipeline: Υ(σ, B) → σ'

```
apply-block (Υ)
  │
  ├─ 1. validate-block    structural checks (HX, HP, HT)
  │
  └─ 2. transition-state  pure composition of sub-STFs
         │
         ├─ WAVE 1: τ', η', ψ', ρ†, β†  (independent)
         ├─ WAVE 2: κ', λ', ρ‡, R*      (depends on wave 1)
         ├─ WAVE 3: ρ', γ'              (depends on wave 2)
         ├─ WAVE 4: accumulate → ω', ξ', δ‡, χ', ι', ϕ', θ', S
         └─ WAVE 5: β', δ', α', π'     (merge/join)
```

Each sub-STF owns its domain: math AND conditions.

## Quick Start

```bash
./scripts/repl.sh

# Or
sbcl --eval '(asdf:load-system :jotl)' --eval '(asdf:load-system :jam-crypto)'
```

## Tests

```bash
./scripts/test-load.sh              # Compile check
./scripts/test-header-roundtrip.sh  # Header codec round-trip
./scripts/test-hx-trace.sh          # HX against trace vectors
```

## Roadmap

- [x] JAM Codec (Appendix C)
- [x] Block B = (H, E) full codec
- [x] Header hash H(E(H))
- [x] Extrinsic hash HX
- [x] State σ closure (17 segments)
- [x] Υ(σ, B) → σ' dependency graph
- [x] Timeslot τ STF (§6)
- [x] Structural validation (§5)
- [x] **Unified architecture** — codec→block merge, closures everywhere
- [ ] Safrole γ STF (§6) — tickets, VRF, validator selection
- [ ] Entropy η STF (§7)
- [ ] Disputes ψ STF (§10)
- [ ] Assurances/Guarantees ρ STF (§11-12)
- [ ] Accumulate STF (§8) + PVM
- [ ] Refine STF (§9) + PVM
- [ ] State Merklization HR (Appendix D)
- [ ] Bandersnatch VRF validation (HV, HS)

## Dependencies

- SBCL (Common Lisp)
- Alexandria
- CFFI + Rust crypto (`cargo build --release` in `crypto/jam-crypto/`)
- Test vectors: `git clone https://github.com/w3f/jamtestvectors tests/jamtestvectors`

## License

MIT
