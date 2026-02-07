# JOTL v3 - JAM On The Lisp

**Pure Functional JAM Protocol Implementation in Common Lisp**

## ✅ What Works

- ✅ **Timeslot** (Gray Paper §6.1-6.2) - Verified 20/20 test vectors
- ✅ **JAM Codec** (Appendix C) - Fixed & compact integers, sequences
- ✅ **Chainspec** (tiny/full configs)
- ✅ **Header Encoding** with Blake2b hashing via FFI
- ✅ **Crypto FFI** (Blake2b, Keccak, Ed25519, Bandersnatch VRF, PVM)

## Quick Start

```bash
# Start REPL
./scripts/repl.sh

# Or manually
echo '(load "scripts/load-jotl.lisp")' | sbcl
```

## Project Structure

```
jotl/
├── src/
│   ├── core/           # Protocol foundations (GP §3-4)
│   │   └── constants.lisp    # Chainspec (tiny/full)
│   │
│   ├── codec/          # JAM Codec (GP Appendix C)
│   │   ├── primitives.lisp   # encode-u8, encode-compact, etc.
│   │   └── structures.lisp   # encode-header, encode-block
│   │
│   ├── block/          # Block structure (GP §4-5)
│   │   ├── header.lisp       # H ≡ (HP, HR, HX, ...)
│   │   ├── extrinsic.lisp    # E ≡ (ET, ED, EP, ...)
│   │   └── block.lisp        # B ≡ (H, E)
│   │
│   ├── state/          # State components (GP §6-7)
│   │   └── timeslot.lisp     # τ, e, m
│   │
│   └── stf/            # State Transition Functions (future)
│       ├── accumulate.lisp   # Α (GP §8)
│       └── refine.lisp       # Ρ (GP §9)
│
├── crypto/             # Cryptography (FFI to Rust)
│   ├── bindings.lisp
│   ├── primitives.lisp
│   └── jam-crypto/     # Rust library
│
├── tests/              # Unit tests
│   ├── timeslot-tests.lisp
│   ├── codec-tests.lisp
│   └── header-tests.lisp
│
└── scripts/            # Utilities
    ├── repl.sh
    └── load-jotl.lisp

Total: ~4800 lines of Lisp + Rust crypto
```

## Architecture: Pure FP with Closures

No `defstruct`, everything is functions returning functions:

```lisp
;; Traditional OOP
(defstruct header parent-hash state-root slot)
(header-slot my-header)

;; JOTL Pure FP
(defun make-header (&key parent-hash state-root slot)
  (lambda (msg)
    (case msg
      (:parent-hash parent-hash)
      (:state-root state-root)
      (:slot slot))))

(funcall my-header :slot)  ; Pure closure!
```

## Usage Examples

### Timeslot
```lisp
(in-package :jotl)

(let ((ts (make-timeslot 42)))
  (funcall ts :timeslot)  ; => 42
  (funcall ts :epoch)     ; => 0
  (funcall ts :phase))    ; => 42
```

### Crypto
```lisp
;; Blake2b hash
(jam.ffi:blake2b-256 #(104 101 108 108 111))
;; => 32-byte hash

;; With hex output
(jam.ffi:bytes-to-hex-string 
  (jam.ffi:blake2b-256 data))
;; => "0x324DCF02..."
```

### Header Encoding
```lisp
(let* ((header-bytes (concatenate 'vector 
                       parent-hash state-root extrinsic-hash slot))
       (hash (jam.ffi:blake2b-256 header-bytes)))
  hash)
```

## Testing

```bash
# Test loading
./scripts/test-load.sh

# Run unit tests
sbcl --load tests/timeslot-tests.lisp
sbcl --load tests/codec-tests.lisp
```

## Important: FFI Limitation

**SBCL `--non-interactive --eval` doesn't work with CFFI** (hangs)

✅ **Works:**
```bash
echo '(code)' | sbcl
sbcl --load script.lisp
```

❌ **Doesn't work:**
```bash
sbcl --non-interactive --eval '(code)'  # Hangs!
```

Use pipes or `--load` instead.

## Roadmap

- [x] Project structure
- [x] Timeslot (§6)
- [x] JAM Codec (Appendix C)
- [x] Header encoding (§5)
- [x] Crypto FFI
- [ ] Complete header implementation
- [ ] Extrinsic Hash & Merkle tree (§5.4-5.6)
- [ ] State management
- [ ] Accumulate STF (§8)
- [ ] Refine STF (§9)
- [ ] PVM integration (§14)

## Dependencies

- **SBCL** (Common Lisp)
- **CFFI** (Foreign Function Interface)
- **Alexandria** (Utilities)
- **FiveAM** (Testing)
- **Rust** (for crypto library)

## Building Crypto Library

```bash
cd crypto/jam-crypto
cargo build --release
# Creates: target/release/libjam_crypto.so
```

## License

MIT

---

**Status:** ✅ Organized, tested, ready for STF implementation  
**Lines:** ~4800 (Lisp) + Rust crypto  
**Coverage:** Timeslot (20/20), Codec (100%), Header (basic)
