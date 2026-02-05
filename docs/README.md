# 📚 JOTL Documentation

Complete documentation for JOTL (JAM On The Lisp) - A Common Lisp implementation of the JAM protocol.

---

## 📖 Documentation Index

### **Architecture & Design**

- **[architecture.md](architecture.md)** - Full architecture audit and best practices
  - Module organization
  - Common Lisp conventions compliance
  - Refactoring recommendations

### **Protocol Specifications**

- **[block-structure.md](block-structure.md)** - JAM Block structure documentation
  - Block header (H)
  - Extrinsic data (E)
  - All sub-components explained

- **[work-result-structure.md](work-result-structure.md)** - Work result codec details
  - Byte-by-byte breakdown
  - Test vector analysis
  - Implementation notes

---

## 🎯 Quick Start

### Running Tests

```bash
# Run all tests
sbcl --load test/suite.lisp --quit

# Run specific test
sbcl --load test/codec/test-block.lisp --quit
```

### Loading the System

```lisp
(require :asdf)
(push #P"/path/to/JOTL/" asdf:*central-registry*)
(asdf:load-system :jotl)
```

### Encoding/Decoding a Block

```lisp
;; Load system
(asdf:load-system :jotl)

;; Set chainspec
(jotl-bloc:set-chainspec :tiny)  ; or :full

;; Decode a block
(let ((octets (read-binary-file "block.bin")))
  (jotl-bloc:decode-block octets))

;; Encode a block
(jotl-bloc:encode-block my-block :as-blob t)
```

---

## 📂 Module Structure

```
JOTL/
├── src/                     # Top-level configuration
│   ├── package.lisp         # jotl-config package
│   └── config.lisp          # Chainspec parameters
│
├── codec/                   # Codec implementations
│   ├── primitives/          # JAM codec primitives (C.1-C.15)
│   ├── bloc/                # Block structures (C.16-C.35)
│   └── state/               # State structures (Appendix D)
│
├── STF/                     # State Transition Functions
│
├── test/                    # Test suite
│   ├── suite.lisp           # Main test runner
│   ├── codec/               # Codec tests
│   └── jamtestvectors/      # Official w3f test vectors
│
└── docs/                    # Documentation (you are here!)
```

---

## 🔗 External Resources

- **[JAM Graypaper](https://graypaper.com/)** - Official JAM protocol specification
- **[w3f/jamtestvectors](https://github.com/w3f/jamtestvectors)** - Official test vectors
- **[Common Lisp Cookbook](https://lispcookbook.github.io/)** - CL best practices
- **[ASDF Manual](https://asdf.common-lisp.dev/)** - Build system documentation

---

## 🤝 Contributing

See [architecture.md](architecture.md) for:
- Code organization conventions
- Common Lisp style guide compliance
- Testing requirements
- Refactoring priorities

---

## 📜 License

MIT License - See LICENSE file for details

---

**Last Updated:** 2026-02-05  
**Status:** Phase 1 (Block Codec) Complete ✅
