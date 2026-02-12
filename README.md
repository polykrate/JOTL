# JOTL — JAM On The Lisp

Pure Functional JAM Protocol implementation in Common Lisp.

Gray Paper: [graypaper.com](https://graypaper.com) (v0.7.2)

## What Works

| Trace | Chain | Step | 1st divergence | Notes |
|-------|-------|------|----------------|-------|
| fallback | **100/100** | 100/100 | — | No work reports |
| safrole | **100/100** | 100/100 | — | No work reports |
| storage | 84/100 | 40/100 | block 6 (step) | PI gas diff |
| preimages | 7/100 | 38/100 | block 2 (step) | PI gas diff |

### Current divergence: C(13)=PI `accumulate-gas-used`

The remaining failures are all caused by **gas differences** in the validator
activity statistics segment (π). Specifically, the `accumulate-gas-used` field
of service activity records diverges.

**Root cause under investigation:** the PVM produces slightly different gas
consumption during `accumulate_ext` execution. All service data (storage,
preimages, items/footprint metadata) is now correct — the only remaining
divergence is the gas value reported in π.

Hypotheses being investigated:
- Service metadata fields `a_r` / `a_a` / `a_p` mapping (last 3 u32 fields of
  the 89-byte ServiceInfo are passed to the PVM as `recent_count`,
  `accum_gas_limit`, `preimage_pages` — may be incorrect mapping)
- Entropy or header-hash passed to the PVM context may differ from reference
- Accumulate items encoding (field ordering, hash computation)

- **M1 Block Importer** — `genesis.bin → σ₀`, then `Υ(σ, B) → σ'` with state_root verification
  - Chain mode: genesis → block 1 → block 2 → ... (our σ' becomes next σ)
  - Step mode: each block independently verified from trace pre_state
- **Block codec** — Full decode/encode of B = (H, ET, ED, EP, EA, EG)
  - Header H is a state closure (hash, seal, genesis sovereignty)
  - Extrinsic data (ET, ED, EP, EA, EG) is open — consumed directly
  - WorkReport, RefineContext, WorkResult structures
  - Header hash H(E(H)) = blake2b(sealed header)
  - Extrinsic hash HX = H(H(ET)‖H(EP)‖H(g)‖H(EA)‖H(ED))
- **State σ** — Immutable byte store with 17 segments + extra-kvs for service accounts (GP §4.4)
- **Υ(σ, B) → σ'** — Block-level STF with 4-wave dependency graph (GP §4.2.1)
- **Safrole γ** — Seal/entropy VRF, tickets, epoch rotation (GP §6) — 42/42
- **Disputes ψ** — Verdicts, culprits, faults, offenders (GP §10) — 56/56
- **Timeslot τ** — STF with epoch/phase derivation (GP §6)
- **Entropy η** — Randomness accumulator with Y(HV) extraction (GP §6.21-23) — 42/42
- **Recent History β** — Full 2-phase transition: β† (wave 1) + β' (wave 4) with MMR (GP §7.5-7.8) — 8/8
- **Statistics π** — Full 4-component transition: π_V, π_L (validator), π_C (cores), π_S (services) (GP §13)
- **Validator keys κ, λ, ι** — Epoch rotation, offender filtering, fallback keys, non-banned indices (GP §6.14-16)
- **Assignments ρ** — 3-wave transition: invalidation, assurances, guarantees (GP §10-12)
- **Authorizations α** — Epoch rotation with ϕ' head, offender filtering (GP §8.1)
- **Accumulate orchestrator** — R* computation, queue editing, priority ordering (GP §12.1-12.12)
- **Service accounts δ** — ServiceInfo codec (89 bytes), sub-key classification, Merkle trie integration
- **Structural validation** — HX, HP, HT checks (GP §5)
- **Crypto FFI** — Blake2b, Keccak, Ed25519, Bandersnatch VRF (Ring VRF + SRS)
- **PVM FFI** — PolkaVM engine, host calls (GP Appendix B), JAM-codec wire protocol
- **Chainspec** — tiny/full configs switchable at runtime
- **Codec roundtrip** — 10 components: decode → encode → byte-exact across 201 states
- **State Merklization HR** — Merkle trie (GP Appendix D) verified on genesis + 100 blocks
- **Binary import API** — `decode-genesis-bin`, `decode-trace-step-bin`, `load-state-from-keyvals`

## Architecture

```
src/
├── lib/
│   ├── macros.lisp         define-value-object (v1) + define-state-closure (v2)
│   ├── constants.lisp      Chainspec (tiny/full), protocol constants
│   ├── primitives.lisp     HOW to encode: El, compact, sequence, option
│   ├── types.lisp          WHAT to encode: Hash, Key, Signature, Validator
│   ├── protocol.lisp       Shared GP helpers: super-majority, signing contexts
│   ├── state-keys.lisp     Merklization keys C(1)..C(16), C(255,s)
│   ├── merkle-trie.lisp    Merkle Trie (GP Appendix D)
│   ├── mmr.lisp            Merkle Mountain Range
│   └── display.lisp        Display utilities
│
├── bloc/
│   ├── tickets.lisp        ET codec (GP §6.4)
│   ├── disputes.lisp       ED codec (GP §10)
│   ├── preimages.lisp      EP codec (GP §7.4)
│   ├── assurances.lisp     EA codec (GP §11)
│   ├── work-report.lisp    WorkReport, WorkResult codec
│   ├── guarantees.lisp     EG codec (GP §11-12)
│   ├── header.lisp         H closure + epoch-mark, tickets-mark closures
│   ├── extrinsic.lisp      E standalone functions (encode/decode/HX)
│   ├── block.lisp          B ≡ (H, ET, ED, EP, EA, EG) — block as message
│   └── validation.lisp     HX, HO, offenders-mark checks
│
├── state/
│   ├── sigma.lisp      σ   overall state (17 segments)
│   ├── tau.lisp        τ   timeslot           ✓ define-state-closure
│   ├── eta.lisp        η   entropy            ✓ define-state-closure
│   ├── kappa.lisp      κ   current validators ✓ define-state-closure
│   ├── lambda.lisp     λ   archived validators ✓ define-state-closure
│   ├── beta.lisp       β   recent history     ✓ define-state-closure
│   ├── psi.lisp        ψ   judgments          ✓ define-state-closure
│   ├── rho.lisp        ρ   core assignments   ✓ define-state-closure
│   ├── iota.lisp       ι   enqueued validators ✓ define-state-closure
│   ├── gamma.lisp      γ   safrole            ✓ define-state-closure
│   ├── alpha.lisp      α   authorizations     ✓ define-state-closure
│   ├── phi.lisp        ϕ   auth queue         ✓ define-state-closure (codec)
│   ├── delta.lisp      δ   services           ✓ define-state-closure + sub-key parsing
│   ├── pi.lisp         π   statistics         ✓ define-state-closure (V+L+C+S)
│   ├── chi.lisp        χ   privileged IDs     ✓ define-state-closure (codec)
│   ├── omega.lisp      ω   accum queue        ✓ define-state-closure (codec)
│   ├── xi.lisp         ξ   accum history      ✓ define-state-closure (codec)
│   └── theta.lisp      θ   accum outputs      ✓ define-state-closure (codec)
│
├── accumulate.lisp     §12 Accumulate orchestrator (R*, queues, PVM)
├── upsilon.lisp        Υ(σ,B)→σ' orchestrator (GP §4.2.1)
└── import.lisp         M1 Block Importer: binary parsers + chain runner

crypto/                 FFI to Rust (jam-crypto)
tests/                  Test vectors (w3f/jamtestvectors)
```

### Design Principles — State Closures

Inspired by Alan Kay's original OOP vision: objects are autonomous units
that communicate exclusively via messages. No shared memory, no extraction
of internals, no class hierarchies. Each state closure is self-governing
over its own data and lifecycle.

**State closures.** Every state component (τ, η, κ, γ, ψ, ρ, β, …) is a
self-sufficient closure that manages its complete lifecycle:

```lisp
(funcall gamma :decode bytes offset)  ;; I know how to read myself
(funcall gamma :encoded)              ;; I know how to write myself
(funcall gamma :transition ...)       ;; I know how to transform myself
(funcall gamma :pending-keys)         ;; I know how to describe myself
(funcall gamma :sealing-variant)      ;; I know my own internals
(funcall iota  :filter-offenders xs)  ;; I know how to filter my own data
```

No class hierarchy, no slots, no CLOS. Let-over-lambda all the way down.
The `case` dispatch inside the closure IS the method table.

**When does a state closure answer a message?** A closure answers a message
when the response requires knowledge of its internal state. This is the
single rule that determines whether logic lives inside the closure (as a
message) or outside (as a standalone function):

| The answer requires… | Where the logic lives | Example |
|---|---|---|
| Iterating over internal state | **Message on the closure** | `(funcall kappa :filter-offenders offenders)` — κ iterates its own validators |
| A targeted lookup in internal state | **Message on the closure** | `(funcall kappa :ed25519-key idx)` — κ looks up one key |
| A computed property of internal state | **Message on the closure** | `(funcall beta :find-record hash)` — β searches its own history |
| Abstracting internal structure | **Message on the closure** | `(funcall gamma :seal-entry-at slot)` — γ hides its variant layout |
| Only raw values (no internal state) | **Standalone function** | `(validate-culprit-signature culprit)` — pure Ed25519 check on raw bytes |
| Coordinating multiple closures | **Boundary (transition/pipeline)** | upsilon wires γ' ← (η', κ', ψ') |

The distinction is clear: **if you need to open the closure to answer, the
closure must answer itself.** Outside code never reaches inside a closure; it
either asks a question (message) or works with values that were never inside a
closure to begin with (header fields, extrinsic bytes, etc.). Closures are
never dismantled — they travel through the transition and answer for themselves.

**Duck typing / protocols.** Closures are not typed — they are
protocol-compatible. A function receiving a "validator set" doesn't check if
it's κ, λ, or ι. It only knows the protocol: "this thing responds to
`:ed25519-key idx`." If it quacks, it's a duck. Three different closures,
one protocol:

```lisp
;; κ, λ, and ι all respond to the same validator protocol
(funcall kappa  :ed25519-key 5)   ;; kappa-state closure
(funcall lambda :ed25519-key 5)   ;; lambda-state closure
(funcall iota   :ed25519-key 5)   ;; iota-state closure
;; The caller doesn't know or care which one it has
```

**Closures circulate freely.** When a standalone function needs information
from a closure, it receives the closure and sends targeted messages. The
closure answers; the function never opens it. This is message passing, not
extraction:

```lisp
;; The function receives κ as a closure, sends it a message
(defun validate-assurance-signature (assurance kappa parent-hash)
  (let* ((idx (getf assurance :validator-index))
         (ed-key (funcall kappa :ed25519-key idx)))  ;; message to κ
    ;; Pure signature verification with the raw key
    (jam.ffi:ed25519-verify ed-key message signature)))
```

**Two macros, two roles:**

- `define-value-object` (v1) — Block data structures (`bloc/`). No state
  transitions, no Merkle keys. Pure data + codec.
- `define-state-closure` (v2) — State components (`state/`). Fields, memoized
  derived properties, integrated codec (`:encoded` / `:decode`), and state
  transitions (`:transition`). Merkle position C(n) owned by σ, not by the
  component.

**σ — the meta-closure.** `sigma` is itself a state closure, but at a
different level: it is the container of all other closures' encoded forms.
It stores raw bytes, not live closures. It has no `:encoded` (it IS bytes),
no `:decode` (it is assembled from Merkle segments), and no `:transition`
(the transition is Υ, orchestrated by upsilon). Instead it provides:
- `:load kw` — lazy decode of a component from bytes to closure
- `:merkle-kvs` — pairs C(n) + bytes for the Merkle trie
- `:state-root` — H(trie) = the state root HR

**B — the message, not an actor.** In Kay's model, σ is the actor and B is the
message sent to it. Υ is the handler. The block holds the header H (a closure
with genuine sovereignty: hash, seal, genesis check) and the extrinsic
sub-elements ET, ED, EP, EA, EG as raw open data. Extrinsics have no lifecycle,
no transitions, no sovereignty — they are consumed directly by state closures
during Υ. The block is never an actor; it is data that travels through the
transition and is consumed.

**Immutability.** Closures never mutate. Transitions return new instances.
This aligns with the Gray Paper's functional STF model and ensures the
dependency graph (GP §4.2.1) is safe.

**σ as byte store, closures decode lazily.** `sigma` holds raw bytes for each
segment. Closures are decoded on demand via `(funcall sigma :load :kw)`, which
dispatches to the right `decode-NAME-state` function. After transitions,
closures re-encode to bytes for σ'. Only the needed components are decoded
per wave.

**Pipeline knows WHAT, closures know HOW.** The orchestrator (`upsilon.lisp`)
manages the dependency graph (GP §4.2.1) and injects dependencies via
`:transition` keyword arguments. The closure encapsulates the transformation
logic (the GP equations). This is dependency injection via message passing:

```lisp
;; Upsilon (pipeline) knows γ needs η', κ', ψ' — wiring
(funcall gamma :transition
  :tau tau :tau-prime tau-prime :tickets e-t
  :iota iota :eta-prime eta-prime
  :kappa-prime kappa-prime :psi-prime psi-prime)

;; Gamma knows equations §6.13-6.35 — logic
```

**Locality of consumption.** A function lives where it is consumed, not where
its data originates. `compute-offenders-mark` operates on block data and
validates headers, so it lives in `bloc/validation.lisp`, not in `psi.lisp`.

**Three domains, zero overlap:**

- `lib/` = HOW to serialize + shared protocol helpers + protocol constants
- `bloc/` = WHAT a block is (pure data + codec + structural validation)
- `state/` = HOW state evolves (per-component state closures + Υ orchestrator)

## Quick Start

```bash
sbcl --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :jotl)'
```

## M1 Block Importer

```bash
# Run 100 fallback blocks (chain mode — genesis → sequential blocks)
sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(in-package :jotl)' \
  --eval '(with-chain :tiny
            (run-trace "tests/jamtestvectors/traces/fallback/"
                       :from 1 :to 100 :mode :chain))'
```

The block importer API:

```lisp
;; Load genesis from binary
(load-genesis "path/to/genesis.bin")    ;; → (values header σ₀ state-root)

;; Load a trace step (pre-state + block + post-state)
(load-trace-step "path/to/00000001.bin") ;; → (values pre-σ block post-σ pre-root post-root)

;; Import a block: Υ(σ, B) → σ' with state_root
(import-block sigma block)              ;; → (values σ' state-root)

;; Run full trace directory
(run-trace dir :from 1 :to 100 :mode :chain) ;; → (values pass fail)
```

## Tests

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

| Test | GP section | Vectors | What |
|------|-----------|---------|------|
| `test-safrole` | §6 | 42 (21+21) | gamma STF: all state segments + epoch/tickets marks + Ring VRF + codec roundtrip |
| `test-psi` | §10 | 56 (28+28) | psi STF: deep byte-by-byte hash comparison + codec roundtrip |
| `test-eta` | §6.21-23 | 42 (21+21) | eta STF: entropy accumulator + error cases + codec roundtrip |
| `test-beta` | §7.5 | 8 (4+4) | beta STF: MMR peaks + codec roundtrip |
| `test-block-roundtrip` | App. C | codec/ + traces/ | Block, headers, extrinsics, work-report — bin/json roundtrip + HX |
| `test-assurances` | §11 | 20 | rho transition-ddagger: assurance processing |
| `test-reports` | §11-12 | 84 | rho transition: guarantee processing |

## Roadmap

- [x] JAM Codec (Appendix C)
- [x] Block B = (H, ET, ED, EP, EA, EG) — message with open extrinsic data
- [x] Header hash H(E(H))
- [x] Extrinsic hash HX
- [x] State sigma closure (17 segments + extra-kvs)
- [x] Upsilon dependency graph (4 waves)
- [x] Timeslot tau STF (§6)
- [x] Entropy eta STF (§6.21-23) — 42/42
- [x] Recent History beta STF (§7.5-7.8) — full 2-phase transition — 8/8
- [x] Disputes psi STF (§10) — 56/56
- [x] Safrole gamma STF (§6) — 42/42
- [x] Validator keys kappa, lambda, iota (§6.14-16)
- [x] Assignments rho: 3-wave transition (§10-12)
- [x] Statistics pi (§13) — full 4-component transition (π_V, π_L, π_C, π_S)
- [x] Authorizations alpha (§8.1) — epoch rotation + offender filtering
- [x] Accumulate orchestrator (§12.1-12.12) — R*, queue editing, priority ordering
- [x] Service accounts delta — ServiceInfo codec, sub-key parsing, Merkle trie
- [x] PVM FFI — PolkaVM engine, host calls (Appendix B), JAM-codec wire protocol
- [x] Structural validation (§5)
- [x] State closure architecture — closures as actors, message-passing, lazy σ decode
- [x] Bandersnatch Ring VRF — seal + ticket validation with SRS
- [x] State Merklization HR (Appendix D) — verified on genesis + 100 blocks
- [x] Codec roundtrip — 10 components byte-exact across 201 states
- [x] **M1 Block Importer** — 100/100 fallback blocks (chain + step modes)
- [x] Binary import API — `genesis.bin` → σ₀, trace steps, `import-block`, `run-trace`
- [~] **Accumulate PVM execution** (§12.2) — PVM run + side-effects + collapse working. Gas divergence in π (PI segment) under investigation.
- [~] Preimage integration delta' (§9.2/§4.18) — integrate-preimages implemented, lookup/blob updates
- [x] PVM host calls audit (Appendix A) — A.1–A.8 verified, gas formula fixed (max(ϱ',0))
- [x] PVM host calls audit (Appendix B.1–B.4) — constants, is-authorized, refine, accumulate verified
- [~] PVM host calls audit (Appendix B.5–B.7) — general/refine/accumulate functions (in progress)
- [x] Incremental items/footprint tracking — PVM tracks a_i/a_o per host-call (ΩW/ΩS/ΩF)
- [x] WorkItemRecord.result encoding — error variants (Panic/OOG/BadExports) now passed correctly
- [x] Deferred transfers — balance augmentation (B.9) + AccumulateItem::Transfer encoding (12.24)
- [ ] On-transfer invocations (§12.3) — PC=10 never called yet
- [ ] Refine STF (§9) + PVM
- [ ] Fuser API — init-state / add-block / debug endpoints

## Fuser API

The fuser exposes three operations over binary state:

```
init-state(genesis.bin)  →  state-root (32 bytes)
add-block(block.bin)     →  state-root (32 bytes)
debug(block.bin)         →  raw-state.bin
```

### Current Internal API (what exists today)

```lisp
;; 1. Load genesis → σ₀
(load-genesis "genesis.bin")
;; → (values header σ₀ state-root)

;; 2. Apply block: Υ(σ, B) → σ'
(import-block sigma block)
;; → (values σ' state-root)

;; 3. State is a closure — query it
(funcall sigma :state-root)     ;; → 32-byte hash
(funcall sigma :merkle-kvs)     ;; → list of (31-byte-key . value-bytes)
(funcall sigma :load :tau)      ;; → τ closure (lazy decode)
(funcall sigma :segment :tau)   ;; → raw bytes (no decode)

;; 4. Decode a block from binary
(decode-block bytes 0)          ;; → (values block-closure consumed)

;; 5. Encode state back to Merkle KV pairs
(funcall sigma :merkle-kvs)     ;; → [(key . val), ...] — ready for trie
```

### Architecture for the Fuser

The fuser holds **one mutable slot** — the current σ — and applies blocks
sequentially. Each operation is a pure STF call:

```
┌─────────────┐     genesis.bin     ┌──────────┐
│   External   │ ──────────────────▶│          │
│   Caller     │     block.bin      │  Fuser   │
│  (Rust/C/    │ ──────────────────▶│          │
│   HTTP/etc)  │                    │  σ slot  │
│              │ ◀────────────────  │          │
└─────────────┘   state-root (32B)  └──────────┘
                  or raw-state.bin
```

**init-state(bin):** Parse genesis binary → `load-state-from-keyvals` → σ₀ stored
in fuser slot. Returns `(funcall σ₀ :state-root)`.

**add-block(bin):** Decode block from binary → `import-block(σ, block)` → σ'
replaces σ in fuser slot. Returns `(funcall σ' :state-root)`.

**debug(bin):** Same as add-block, but instead of returning just the root,
serializes the full post-state σ' as `RawState = state-root(32) + Vec<KeyValue>`.
Each KeyValue = `key(31) + compact-len + value-bytes`. This is the same format
as trace `.bin` files, allowing diff against reference.

## Dependencies

- SBCL (Common Lisp)
- Alexandria, cl-json
- CFFI + Rust crypto (`cargo build --release` in `crypto/jam-crypto/`)
- Test vectors: `git clone https://github.com/w3f/jamtestvectors tests/jamtestvectors`

## License

MIT
