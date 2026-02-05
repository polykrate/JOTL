# JOTL - JAM On The Lisp

A Common Lisp implementation of the JAM (Join-Accumulate Machine) protocol.

## Project Structure

```
JOTL/
├── codec/
│   ├── primitives/     # Encoding/decoding primitives
│   ├── state/          # State management
│   └── bloc/           # Block operations
├── STF/                # State Transition Functions
└── jotl.asd            # ASDF system definition
```

## Codec Primitives

The codec primitives provide various encoding schemes:

- **Trivial Encodings**: Basic encoding schemes
- **Sequence Encoding**: For ordered collections
- **Discriminator Encoding**: For tagged unions/variants
- **Bit Sequence Encoding**: Compact binary representations
- **Dictionary Encoding**: Key-value mappings
- **Set Encoding**: Unordered unique collections
- **Fixed-Length Integer Encoding**: Fixed-size integer encoding

## Getting Started

Load the system with ASDF:

```lisp
(asdf:load-system :jotl)
```

## License

MIT
