# State Codec - JAM State Structures (Appendix D)

## 📋 Overview

The JAM state `σ` is composed of **17 primary components** that track all on-chain data:

```
σ ≡ (α, β, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ, θ)
```

Several components have **sub-components** (denoted with subscripts like γA, βH, etc.) that represent their internal structure.

---

## 🗂️ State Components (Graypaper Section 4.2)

### Core & Authorization
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **α** | `core-authorization` | 8.1 | Core authorization requirements |
| **ϕ** | `authorization-queue-entry` | 8.1 | Queue filling core authorizations |

### Block History & Accumulation
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **β** | `recent-blocks` | 7.1 | Log of recent activity (composite) |
| **βH** | `recent-blocks-info` | 7.2 | Information on most recent blocks |
| **βB** | `merkle-mountain-belt` | 7.3, 7.7 | Merkle belt for Accumulation outputs |
| **θ** | `accumulation-output` | 7.4, 12.25 | Most recent Accumulation outputs |

### SAFROLE (Validator Rotation)
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **γ** | `safrole-state` | 6.3 | SAFROLE state (composite) |
| **γA** | `ticket-accumulator` | 6.5 | Sealing lottery ticket accumulator |
| **γP** | `next-validators` | 6.7 | Keys for validators of next epoch |
| **γS** | `seal-keys` | 6.5 | Sealing-key sequence (current epoch) |
| **γZ** | `tickets-root` | 6.4 | Bandersnatch root for tickets |

### Validators
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **κ** | `validator-keys` | 6.7 | Current epoch validator keys |
| **λ** | `archived-validator` | 6.7 | Historical validator keys |
| **ι** | `validator-queue-entry` | 6.7 | Validators to be enrolled next |
| **π** | `validator-stats` | 13.1 | Validator performance statistics |

### Services
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **δ** | `service-account` | 9.1 | Service accounts (like smart contracts) |
| **χ** | `privileged-services` | 9.9 | Privileged service indices (composite) |
| **χM** | `blessed` | 12.27 | Index of blessed service |
| **χA** | `authorizer-assigners` | 12.27 | Services assigning core authorizers |
| **χV** | `designate` | 12.27 | Index of designate service |
| **χR** | `registrar` | 12.27 | Index of registrar service |
| **χZ** | `always-accumulate` | 12.27 | Always-accumulate services + gas |

### Work Processing
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **ρ** | `pending-report` | 11.1 | Reports pending availability assurance |
| **ω** | `pending-accumulation` | 12.3 | Work-reports ready to accumulate |
| **ξ** | `accumulated-package` | 12.1 | Recently accumulated work-packages |

### Disputes
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **ψ** | `judgements` | 10.1 | Past judgments (composite) |
| **ψB** | `incorrect-reports` | 10.17 | Work-reports judged incorrect |
| **ψG** | `correct-reports` | 10.16 | Work-reports judged correct |
| **ψW** | `unknowable-reports` | 10.18 | Work-reports with unknowable validity |
| **ψO** | `offending-validators` | 10.19 | Validators with incorrect judgments |

### Chain State
| Symbol | Name | Equation | Description |
|--------|------|----------|-------------|
| **τ** | `timeslot` | 6.1 | Current timeslot (natural, no struct) |
| **η** | `entropy-pool` | 6.21 | On-chain entropy (hash32, no struct) |

---

## 🏗️ Structure Hierarchy

### Composite Structures (with sub-components)

```lisp
;; β - Recent blocks (composite)
(defstruct recent-blocks
  (info nil :type (or null recent-blocks-info))     ; βH
  (merkle-belt nil :type (or null merkle-mountain-belt))) ; βB

;; γ - SAFROLE state (composite)
(defstruct safrole-state
  (ticket-accumulator nil :type list)  ; γA
  (next-validators nil :type list)      ; γP
  (seal-keys nil :type list)            ; γS
  (tickets-root nil :type (or null hash32)))  ; γZ

;; χ - Privileged services (composite)
(defstruct privileged-services
  (blessed nil :type (or null service-id))  ; χM
  (authorizer-assigners nil :type list)     ; χA
  (designate nil :type (or null service-id)) ; χV
  (registrar nil :type (or null service-id)) ; χR
  (always-accumulate nil :type list))        ; χZ

;; ψ - Judgements (composite)
(defstruct judgements
  (incorrect-reports nil :type list)      ; ψB
  (correct-reports nil :type list)        ; ψG
  (unknowable-reports nil :type list)     ; ψW
  (offending-validators nil :type list))  ; ψO
```

---

## 📦 Complete State Structure (σ)

```lisp
(defstruct jam-state
  "Complete JAM state (σ) - Graypaper Section 4.2"
  
  (core-authorizations nil :type list)         ; α
  (recent-blocks nil :type (or null recent-blocks))  ; β (composite)
  (safrole nil :type (or null safrole-state))  ; γ (composite)
  (service-accounts nil :type list)            ; δ
  (entropy-pool nil :type (or null hash32))    ; η (simple hash32)
  (validator-queue nil :type list)             ; ι
  (current-validators nil :type list)          ; κ
  (archived-validators nil :type list)         ; λ
  (pending-reports nil :type list)             ; ρ
  (timeslot nil :type (or null timeslot))      ; τ (simple natural)
  (authorization-queue nil :type list)         ; ϕ
  (privileged-services nil :type (or null privileged-services))  ; χ (composite)
  (judgements nil :type (or null judgements))  ; ψ (composite)
  (validator-statistics nil :type list)        ; π
  (pending-work-reports nil :type list)        ; ω
  (accumulated-packages nil :type list)        ; ξ
  (accumulation-outputs nil :type list))       ; θ
```

---

## 🚀 Implementation Status

### ✅ Phase 2.1: State Structures (COMPLETE)
- All 17 primary components defined
- Composite structures (β, γ, χ, ψ) implemented with sub-components
- Types aligned with Graypaper equations

### 🔜 Phase 2.2: State Codecs (NEXT)
Create individual files for each component's encoder/decoder:
- `codec/state/service-accounts.lisp` (δ)
- `codec/state/validators.lisp` (κ, λ, ι)
- `codec/state/safrole.lisp` (γ with sub-components)
- `codec/state/recent-blocks.lisp` (β with sub-components)
- `codec/state/privileged-services.lisp` (χ with sub-components)
- `codec/state/judgements.lisp` (ψ with sub-components)
- ... etc for all 17 components

### 📝 Phase 2.3: State Serialization
- Implement state-key constructor functions (Appendix D.1)
- Implement Merkle trie logic for state commitment
- Create comprehensive round-trip tests

---

## 📚 References

- **Graypaper Section 4.2**: State component definitions
- **Graypaper Appendix D**: State Merklization and Serialization
- **Equations 6.x**: SAFROLE state (γ)
- **Equations 7.x**: Block history and accumulation (β, θ)
- **Equations 8.x, 9.x**: Core authorizations and services (α, ϕ, δ, χ)
- **Equations 10.x**: Disputes and judgements (ψ)
- **Equations 11.x-13.x**: Work processing (ρ, ω, ξ, π)
