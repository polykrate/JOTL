# State Codec - JAM State Serialization (Appendix D)

## 📋 Overview

The JAM state `σ` is composed of **17 components** that track all on-chain data:

```
σ ≡ (α, β, θ, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ)
```

Each component is serialized into a mapping from 31-byte state-keys to octet sequences, then committed to a Merkle root (32 bytes).

---

## 🗂️ State Components

### Service & Execution
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **δ** | `service-accounts` | Service accounts (like smart contracts in Ethereum) | `service-accounts.lisp` |
| **χ** | `privileged-services` | Services with privileged status | `privileged-services.lisp` |

### Validators & Keys
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **κ** | `current-validators` | Current validator set (epoch keys) | `current-validators.lisp` |
| **λ** | `archived-validators` | Historical validator keys | `archived-validators.lisp` |
| **ι** | `validator-queue` | Queue of validators to be enrolled | `validator-queue.lisp` |
| **γ** | `safrole-state` | SAFROLE state (validator rotation) | `safrole-state.lisp` |
| **π** | `validator-statistics` | Validator performance statistics | `validator-statistics.lisp` |

### Core Management
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **α** | `core-authorizations` | Authorization requirements for each core | `core-authorizations.lisp` |
| **ϕ** | `authorization-queue` | Queue filling core authorizations | `authorization-queue.lisp` |
| **ρ** | `pending-reports` | Work-reports pending availability assurance | `pending-reports.lisp` |

### Work Processing
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **ω** | `pending-work-reports` | Work-reports ready to accumulate | `pending-work-reports.lisp` |
| **ξ** | `accumulated-work-packages` | Recently accumulated work-packages | `accumulated-work-packages.lisp` |

### Chain State
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **β** | `recent-blocks` | Recent block hashes (βH) | `recent-blocks.lisp` |
| **τ** | `timeslot` | Current timeslot index | `timeslot.lisp` |
| **η** | `entropy-pool` | On-chain entropy for randomness | `entropy-pool.lisp` |

### Disputes
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **ψ** | `judgements` | Dispute judgements | `judgements.lisp` |

### Accumulation
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **θ** | `accumulation-outputs` | Most recent Accumulation outputs (eq. 7.4, 12.25) | `accumulation-outputs.lisp` |

### Unknown/Reserved
| Symbol | Name | Description | File |
|--------|------|-------------|------|
| **θ** | `theta` | (Reserved/unclear in Graypaper) | `theta.lisp` |

---

## 📐 State Serialization (Appendix D.1)

### State-Key Constructor Functions

Each component is mapped to a unique 31-byte key using constructor functions `C`:

```
C_δ(s, h)    : Service account key (service s, hash h)
C_α(c)       : Core authorization key (core c)
C_ρ(c)       : Pending report key (core c)
C_ω(h)       : Pending work-report key (hash h)
...
```

### Merkle Root Commitment

All state keys and values are serialized into a Merkle trie, producing a 32-byte commitment (state root).

---

## 🏗️ Implementation Plan

### Phase 2.1: Core State Structures
1. ✅ Define types in `codec/state/types.lisp`
2. Implement serialization for each component (17 files)
3. Implement state-key constructors (C functions)

### Phase 2.2: State Codec
1. Encoder/decoder for each component
2. State merklization (Merkle trie construction)
3. State root calculation

### Phase 2.3: Validation
1. Test vectors for state serialization
2. Round-trip tests
3. Merkle root verification

---

## 📚 References

- **Graypaper Section 3**: State definitions
- **Graypaper Section 5**: State transitions
- **Graypaper Appendix D**: State merklization and serialization
- **Test vectors**: `test/jamtestvectors/stf/*/`

---

## 🎯 Current Status

- [x] Types defined in `src/types.lisp` (global JAM types)
- [ ] State component structures (`codec/state/types.lisp`)
- [ ] State serialization (17 component files)
- [ ] State-key constructors
- [ ] Merkle trie implementation
- [ ] State codec tests

---

**Code is law. State is merklized. Serialize everything.**
