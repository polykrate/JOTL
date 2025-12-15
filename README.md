# JOTL - JAM On The Lisp

**Declarative Common Lisp implementation of the JAM Protocol**

[![Roundtrip](https://img.shields.io/badge/roundtrip-19%2F19-brightgreen)]()
[![Gray Paper](https://img.shields.io/badge/Gray%20Paper-v0.7.2-blue)](https://graypaper.com)
[![Tests](https://img.shields.io/badge/MPT-11%2F11-green)]()

---

## Overview

JOTL implements the JAM (Join-Accumulate Machine) Protocol in Common Lisp, leveraging macros for declarative state transitions and codec generation. The implementation prioritizes correctness and Gray Paper fidelity over performance, validated against official test vectors with byte-perfect roundtrip encoding.

### Status

| Component | Coverage | Notes |
|-----------|----------|-------|
| State Codec | 19/19 keyvals | All state fields (τ, κ, λ, β, ψ, χ, φ, η, ρ, γ) |
| JAM Compact | Modes 0-N | Including reserved prefix handling |
| Merkle Patricia Trie | 11/11 tests | Blake2b-256, binary trie |
| Validator Keys | 256-byte format | Bandersnatch + Ed25519 + BLS + metadata |
| Block Import | Codec validated | STF integration in progress |

---

## Methodology

JOTL was developed through iterative reverse engineering of the Gray Paper, test vectors, and reference implementations.

### Development Phases

**1. Direct Mapping**: Initial implementation mapping GP mathematical expressions 1:1 to Lisp functions. Established baseline understanding through REPL-driven development.

**2. Architectural Reset**: Identified brittleness in naive approach (scattered constants, duplicated codec logic, mixed concerns). Rebuilt with declarative macros and centralized primitives.

**3. Iterative Refinement**: Systematic debugging via test vector analysis, GP cross-referencing, and comparison with Strawberry (Go). Key discoveries:
- JAM compact ≠ SCALE compact
- State fields have heterogeneous formats (κ: u16 count, λ: no count)
- Test vector edge cases (β 1-byte padding, χ iterative decode)

**4. Modular Architecture**: Replaced direct mappings with composable primitives and declarative macros (`defstate-field`, `defrecord`, `defvalidation`).

### Architecture

```
Primitives → State Fields → Subsystems
    ↓            ↓              ↓
codec.lisp   greek-macros   stf/*.lisp
primitives   defstate-field  apply_*()
```

---

## Implementation

### State Codec

19 state fields implemented per GP Section 3:

| Symbol | Field | Disc. | Format | Implementation |
|--------|-------|-------|--------|----------------|
| τ | Timeslot | 0x0B | u32 LE | primitives.lisp |
| κ | Current validators | 0x01 | u16 count + keys[] | state-fields.lisp:169 |
| λ | Previous validators | 0x02 | keys[] | state-fields.lisp:179 |
| β | History | 0x03 | compact-len + entries[] + 0x00 | state-fields.lisp:128 |
| ψ | Past judgements | 0x05 | plist (good/bad/wonky) | state-fields.lisp:231 |
| χ | Statistics | 0x07/0x08 | iterative decode (252 validators) | state-fields.lisp:26 |
| φ | Authorizations | 0x0D | pools + queues (305b padded) | state-fields.lisp:69 |
| η | Entropy | 0x0A | 4×H256 or genesis stub | state-fields.lisp:214 |
| ρ | Reports | 0x0C | work reports | - |
| γ | Safrole | 0x04 | tickets + markers | - |

### JAM Compact Encoding

GP Appendix I.2 implementation with full Mode N support:

```
Mode 0: 0xxxxxxx        → 1 byte  (0-127)
Mode 2: 10xxxxxx        → 2 bytes (128-16383)
Mode 4: 110xxxxx        → 4 bytes (16384-2³⁰-1)
Mode N: 1111nnnn        → 5-20 bytes (2³⁰-2¹³⁶-1)
Reserved: 1110xxxx      → Error
```

### Validator Keys

256-byte fixed format per GP G.1:

```
[ Bandersnatch 32b ][ Ed25519 32b ][ BLS 144b ][ Metadata 48b ]
```

- κ encoding: u16-LE expected-count (from test vector, not chainspec) + keys
- λ encoding: keys only (no count prefix)
- Metadata preservation required for roundtrip

### Merkle Patricia Trie

Binary MPT implementation (GP Appendix D):

```lisp
(defun merkle-root (kv-pairs)
  "Compute state root from sorted key-value pairs.
   Leaf: 0x00 + key + H(value)
   Branch: 0x01 + H(left) + H(right)"
  ...)
```

11/11 official tests passing with exact root matches.

---

## Architecture

```
src/
├── common/
│   ├── codec.lisp          # JAM compact (I.2), hex conversion
│   ├── crypto.lisp         # Blake2b, Ed25519, Keccak (FFI)
│   ├── types.lisp          # validator-keys, history-entry
│   └── chainspec.lisp      # TINY/FULL config
│
├── stf/
│   ├── codec/
│   │   ├── primitives.lisp     # u8/u32/h256/compact codecs
│   │   ├── state-fields.lisp   # defstate-field for each Greek letter
│   │   └── greek-macros.lisp   # Macro infrastructure
│   ├── state.lisp              # jam-state struct
│   └── state-parser.lisp       # keyvals ↔ jam-state
│
├── trie/
│   └── mpt.lisp                # Binary MPT (Appendix D)
│
└── test/
    ├── traces/
    │   ├── test-roundtrip.lisp     # Parse/encode validation
    │   └── test-block-import.lisp  # STF tests (202 vectors)
    └── trie/test-mpt.lisp          # MPT validation
```

---

## Build

### Prerequisites

- SBCL 2.4+
- Quicklisp
- Rust (optional, for FFI crypto)

### Usage

```bash
# Clone
git clone https://github.com/your-org/jotl.git
cd jotl

# Load
sbcl
(require :asdf)
(push #P"/path/to/jotl/" asdf:*central-registry*)
(asdf:load-system :jotl)

# Test
sbcl --non-interactive --load test/traces/test-roundtrip.lisp
sbcl --non-interactive --load test/trie/test-mpt.lisp
```

### Expected Output

```
=== Testing Genesis State Roundtrip ===
Matches: 19, Mismatches: 0
✅ PERFECT ROUNDTRIP! All keyvals match.
```

---

## Technical Notes

### Debugging Methodology

```
1. Isolate: Minimal reproduction in debug-*.lisp
2. Hexdump: Byte-by-byte analysis of encoded output
3. Iterate: Single-issue fixes with atomic commits
```

### Key Insights

- **Test vectors are source of truth**: GP sometimes underspecifies formats
- **Roundtrip validates codec**: Must achieve 100% before STF testing
- **Macro-generated code**: Reduces boilerplate, enforces consistency
- **Declarative > Imperative**: `defstate-field` more maintainable than manual parse/encode

---

## Roadmap

### Current: Phase 2 - Block Processing
- [x] State codec (19/19 keyvals)
- [x] MPT implementation (11/11 tests)
- [x] Block header codec
- [ ] Extrinsics codec
- [ ] STF integration (202 block import tests)

### Future: Phase 3 - Full Protocol
- [ ] FULL chainspec support
- [ ] Service accounts (σ) with indices
- [ ] PVM integration
- [ ] Accumulation

---

### Development Guidelines

1. All code must reference specific GP sections
2. Test vectors override GP when underspecified
3. Declarative macros preferred over imperative code
4. Document edge cases and test vector quirks
5. Atomic commits: one fix per commit

---

## References

- **Gray Paper**: https://graypaper.com (v0.7.2)
- **Test Vectors**: https://github.com/w3f/jamtestvectors
- **Strawberry**: https://github.com/eigerco/strawberry (Go reference)

---

## License

MIT

---

*"Code is law. Les bugs sont l'ennemi commun."* ⚙️

