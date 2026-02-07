# JOTL Project Reorganization Plan

## Current Structure (❌ Flat)
```
/
├── constants.lisp
├── timeslot.lisp
├── codec.lisp
├── header.lisp
├── header-encoding.lisp
├── extrinsic.lisp
├── block.lisp
├── package.lisp
└── crypto/
```

## Proposed Structure (✅ Organized by Gray Paper sections)

```
jotl/
├── jotl.asd
├── package.lisp          # Main package
│
├── src/
│   ├── core/             # Protocol foundations (GP §3-4)
│   │   ├── constants.lisp    # Chainspec (tiny/full)
│   │   ├── types.lisp        # Core types (ℍ, 𝔹, ℕ, etc.)
│   │   └── notation.lisp     # Mathematical operators
│   │
│   ├── codec/            # JAM Codec (GP Appendix C)
│   │   ├── primitives.lisp   # encode-u8, encode-u32, etc.
│   │   └── structures.lisp   # encode-header, encode-block
│   │
│   ├── block/            # Block structure (GP §4-5)
│   │   ├── header.lisp       # H ≡ (HP, HR, HX, ...)
│   │   ├── extrinsic.lisp    # E ≡ (ET, ED, EP, ...)
│   │   └── block.lisp        # B ≡ (H, E)
│   │
│   ├── state/            # State components (GP §6-7)
│   │   ├── timeslot.lisp     # τ (timeslot)
│   │   ├── entropy.lisp      # η (entropy)
│   │   ├── history.lisp      # β (block history)
│   │   ├── statistics.lisp   # π (validator statistics)
│   │   └── safrole.lisp      # γ (validator selection)
│   │
│   ├── stf/              # State Transition Functions (GP §8-13)
│   │   ├── accumulate.lisp   # Α - Accumulation (GP §8)
│   │   ├── refine.lisp       # Ρ - Refinement (GP §9)
│   │   ├── disputes.lisp     # Ψ - Disputes (GP §10)
│   │   ├── guarantees.lisp   # Ϝ - Guarantees (GP §11)
│   │   ├── assurances.lisp   # Φ - Assurances (GP §12)
│   │   └── main.lisp         # Ω - Main STF orchestrator
│   │
│   └── crypto/           # Cryptography (FFI to Rust)
│       ├── bindings.lisp
│       ├── primitives.lisp
│       └── ...
│
├── tests/
│   ├── core-tests.lisp
│   ├── codec-tests.lisp
│   ├── block-tests.lisp
│   ├── state-tests.lisp
│   └── stf-tests.lisp
│
├── scripts/
│   ├── repl.sh
│   └── load-jotl.lisp
│
└── test/
    └── jamtestvectors/
```

## Rationale

### 1. `src/core/` - Protocol Foundations
- Constants, types, mathematical notation
- Gray Paper §3 (Mathematical Notation)
- Always needed, never changes

### 2. `src/codec/` - JAM Codec
- Encoding/decoding primitives
- Gray Paper Appendix C
- Separate from structures

### 3. `src/block/` - Block Structure
- Header, Extrinsic, Block
- Gray Paper §4-5
- Pure data structures

### 4. `src/state/` - State Components
- Individual state components (τ, η, β, π, γ, etc.)
- Gray Paper §6-7
- State queries, not transitions

### 5. `src/stf/` - State Transition Functions
- Accumulate, Refine, etc.
- Gray Paper §8-13
- State transformations

### 6. `src/crypto/` - Already good!
- Keep as is

## Migration Order

1. ✅ Create directory structure
2. Move files:
   - constants.lisp → src/core/
   - codec.lisp → src/codec/primitives.lisp
   - header.lisp, extrinsic.lisp, block.lisp → src/block/
   - timeslot.lisp → src/state/
   - header-encoding.lisp → src/codec/structures.lisp (or merge with block/)
3. Update `jotl.asd` with new paths
4. Update package exports
5. Test everything still loads

## Alternative: Simpler Structure

If too complex, start with:
```
src/
├── core/      # constants, types
├── codec/     # encoding
├── block/     # header, extrinsic, block
├── state/     # τ, η, β, etc.
└── stf/       # Α, Ρ, Ψ, etc. (future)
```

## Benefits

✅ **Clear separation of concerns**
✅ **Follows Gray Paper structure**
✅ **Easier to navigate**
✅ **Room to grow** (STF modules coming)
✅ **Professional organization**

## Recommendation

Start with **simple structure** (5 dirs), expand later as STF grows.
