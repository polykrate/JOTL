# JOTL — JAM On The Lisp

Pure Common Lisp implementation of the JAM State Transition Function.

Gray Paper: [graypaper.com](https://graypaper.com) (v0.7.2)

## Conformance

| Trace suite | Chain | Step | Root cause |
|-------------|------:|-----:|------------|
| fallback | **100/100** | **100/100** | — |
| safrole | **100/100** | **100/100** | — |
| storage | 88/100 | **98/100** | π gas |
| storage_light | **99/100** | **99/100** | π gas |
| preimages | 33/100 | 91/100 | π gas |
| preimages_light | 70/100 | 94/100 | π gas |
| fuzzy | 5/200 | 32/200 | θ/guarantees |
| fuzzy_light | 5/200 | 38/200 | θ/guarantees |
| **Total** | **500/1000** | **652/1000** | **0 errors** |

**Step mode** tests each block independently from the reference pre-state.
**Chain mode** applies blocks sequentially — failures cascade (a wrong σ
produces wrong σ' for all subsequent blocks).

### Step-mode divergence breakdown

All non-PVM transitions pass 100%. Failures are PVM-only:

| Suite | Pass | Fail | Root cause |
|-------|-----:|-----:|------------|
| storage | 98 | 2 | π gas (basic block charging) |
| storage_light | 99 | 1 | π gas |
| preimages | 91 | 9 | π gas |
| preimages_light | 94 | 6 | π gas |
| fuzzy | 32 | 168 | θ/guarantees not implemented |
| fuzzy_light | 38 | 162 | θ/guarantees not implemented |

Root causes:
- **π gas** (~20 blocks): PolkaVM 0.29 charges gas per basic block, not per
  instruction. When a host call (`ecalli`) interrupts a basic block, the full
  block cost was already charged — the guest sees 1–3 extra gas consumed per
  host call. This shifts `accumulate-gas-used` in π_S, which changes the gas
  refund, which changes `a_b` (balance) in ServiceInfo → δ's Merkle trie.
  All host call gas costs verified correct (10 per call, ΩT = 10+l on success).
  Instruction gas = 1 per RISC-V instruction (PolkaVM `GasMeteringKind::Sync`).
- **θ/guarantees**: fuzzy traces exercise `refine`, which is not yet implemented.

**0 errors** — no panics, no parse failures across all 1100 blocks.

## Why a second implementation matters

The Gray Paper is a **claim**: "here is a function Υ(σ, B) → σ' that
defines the entire protocol, unambiguously, from mathematics alone."

If only Rust implements it, you have one interpretation of that claim.
You cannot distinguish the spec from the implementation — every bug looks
like a feature, every ambiguity is resolved silently by the compiler.
The spec and the code fuse into one artifact.

A second implementation in a radically different language **separates
the spec from any single codebase**. When JOTL (closures, immutable,
garbage-collected, no types) and a Rust client (structs, mutable, manual
memory, statically typed) produce the same state root on the same block,
that is evidence that:

1. **The math is unambiguous.** Every equation in the GP has exactly one
   computational meaning. If two languages disagree, the equation was
   ambiguous — and that's a spec bug found before production.

2. **The protocol is the math, not the code.** JAM is defined by
   Υ(σ, B) → σ', not by any `.rs` file. Multi-implementation proves the
   notation works as a specification, not as pseudocode for one language.

3. **Consensus failures are caught early.** In blockchain, "consensus"
   means all nodes agree on every state transition, forever. A single
   ambiguous edge case — how gas is counted, how a trie key is hashed,
   when a service is ejected — can split the network. You only find
   these before mainnet if two independent teams implement the same spec
   and compare outputs on thousands of test vectors.

Ethereum learned this the hard way. Its multi-client strategy (Geth,
Prysm, Lighthouse, Teku, Nimbus...) has caught dozens of consensus bugs
that a single implementation would have shipped to production. JAM adopts
the same principle from day one: the [test vectors](https://github.com/w3f/jamtestvectors)
are the shared truth, and every implementation is a peer reviewer.

JOTL is not a production client. It is a **proof that the Gray Paper
works** — that its mathematical notation maps cleanly to a computational
substrate with no mutation, no types, no structs, and no classes. If the
spec survives Common Lisp, it survives anything.

### Performance

| Trace | Blocks | Time | blk/s |
|-------|-------:|-----:|------:|
| fallback (no PVM) | 100 | 0.39s | ~254 |
| safrole (Bandersnatch VRF) | 100 | 1.15s | ~87 |
| storage (PVM accumulate) | 100 | 1.1s | ~90 |

Breakdown (storage, 100 step blocks): I/O 2%, **STF 87%**, Merkle 11%.
Crypto and PVM execute in Rust via FFI. Lisp does the routing.
JAM slot time is 6 seconds; JOTL processes test blocks in ~11ms each.

## What Works

- **Υ(σ, B) → σ'** — Full block-level STF with 4-wave dependency graph (GP §4.2.1)
- **Block codec** — Decode/encode B = (H, E_T, E_D, E_P, E_A, E_G), byte-exact roundtrip
- **Header H** — Closure with sovereignty: hash, seal, genesis check, extrinsic hash H_X
- **State σ** — Immutable byte store, 17 segments + service account extra-kvs (GP §4.4)
- **Safrole γ** — Seal/entropy VRF, tickets, epoch rotation, Ring VRF (GP §6)
- **Disputes ψ** — Verdicts, culprits, faults, offender extraction (GP §10)
- **Timeslot τ** — Epoch/phase derivation (GP §6)
- **Entropy η** — Randomness accumulator with Y(H_V) extraction (GP §6.21-23)
- **Recent history β** — 2-phase transition: β† (wave 1) + β' (wave 4) with MMR (GP §7.5-7.8)
- **Statistics π** — 4-component transition: π_V, π_L, π_C, π_S (GP §13)
- **Validator keys κ, λ, ι** — Epoch rotation, offender filtering, fallback, non-banned indices (GP §6.14-16)
- **Assignments ρ** — 3-wave transition: invalidation → assurances → guarantees (GP §10-12)
- **Authorizations α** — Epoch rotation with ϕ' head, offender filtering (GP §8.1)
- **Accumulate** — R\* computation, queue editing, priority ordering (GP §12.1-12.12)
- **Service accounts δ** — ServiceInfo codec (89B), sub-key classification, Merkle trie
- **Structural validation** — H_X, H_P, H_T checks (GP §5)
- **Crypto FFI** — Blake2b, Keccak, Ed25519, Bandersnatch VRF (Ring VRF + SRS)
- **PVM FFI** — PolkaVM engine, host calls (GP Appendix B), JAM-codec wire protocol
- **Codec roundtrip** — 10 components: decode → encode → byte-exact across 201 states
- **State merklization H_R** — Merkle trie (GP Appendix D) verified on genesis + 100 blocks
- **Fuser** — Unix socket server: `init-state`, `add-block`, `debug` over binary protocol

## Architecture

```
src/
├── lib/
│   ├── macros.lisp         define-state-closure — the single macro
│   ├── constants.lisp      Chainspec (tiny/full), protocol constants
│   ├── primitives.lisp     HOW to encode: E_l, compact, sequence, option
│   ├── types.lisp          WHAT to encode: Hash, Key, Signature, Validator
│   ├── protocol.lisp       Shared GP helpers: super-majority, signing contexts
│   ├── state-keys.lisp     Merklization keys C(1)..C(16), C(255,s)
│   ├── merkle-trie.lisp    Merkle Trie (GP Appendix D)
│   ├── mmr.lisp            Merkle Mountain Range
│   └── display.lisp        Display utilities
│
├── bloc/
│   ├── tickets.lisp        E_T codec (GP §6.4)
│   ├── disputes.lisp       E_D codec (GP §10)
│   ├── preimages.lisp      E_P codec (GP §7.4)
│   ├── assurances.lisp     E_A codec (GP §11)
│   ├── work-report.lisp    WorkReport, WorkResult codec
│   ├── guarantees.lisp     E_G codec (GP §11-12)
│   ├── header.lisp         H closure + epoch-mark, tickets-mark closures
│   ├── extrinsic.lisp      Extrinsic standalone functions (encode/decode/H_X)
│   ├── block.lisp          B ≡ (H, E_T, E_D, E_P, E_A, E_G) — block closure
│   └── validation.lisp     H_X, H_O, offenders-mark checks
│
├── state/
│   ├── sigma.lisp      σ   overall state — byte store & supervisor
│   ├── tau.lisp        τ   timeslot
│   ├── eta.lisp        η   entropy
│   ├── kappa.lisp      κ   current validators
│   ├── lambda.lisp     λ   archived validators
│   ├── beta.lisp       β   recent history
│   ├── psi.lisp        ψ   judgments
│   ├── rho.lisp        ρ   core assignments
│   ├── iota.lisp       ι   enqueued validators
│   ├── gamma.lisp      γ   safrole
│   ├── alpha.lisp      α   authorizations
│   ├── phi.lisp        ϕ   auth queue
│   ├── delta.lisp      δ   services
│   ├── pi.lisp         π   statistics
│   ├── chi.lisp        χ   privileged IDs
│   ├── omega.lisp      ω   accum queue
│   ├── xi.lisp         ξ   accum history
│   └── theta.lisp      θ   accum outputs
│
├── accumulate.lisp     §12 Accumulate orchestrator (R*, queues, PVM)
├── upsilon.lisp        Υ(σ,B)→σ' — implementation of σ :transition
├── import.lisp         Block importer: binary parsers + chain runner
└── fuser.lisp          Unix socket fuser server

crypto/                 FFI to Rust (jam-crypto)
tests/                  Test vectors (w3f/jamtestvectors)
```

## Design Principles — Hewitt Actors, not Smalltalk Objects

The architecture implements Hewitt's Actor Model (1973/Agha 1986), not
Smalltalk-style OOP. No classes, no inheritance, no CLOS, no mutation.
Let-over-lambda closures all the way down.

### The six concepts

Hewitt's original model defines six core concepts. Five map naturally
to JOTL; one is intentionally absent.

| # | Hewitt concept | Definition | JOTL mapping |
|---|----------------|------------|--------------|
| 1 | **Send** | Send a message to an actor | `(funcall closure :msg ...)` |
| 2 | **Create** | Create new actors with initial behavior | σ `:load` → `load-NAME-state` |
| 3 | **Become** | Designate the replacement behavior | `:transition` returns the prime |
| 4 | **Acquaintances** | The actors this actor knows | Fields (private), kwargs (introduced), make-\* (created) |
| 5 | **Customer** | Continuation actor for the reply | Implicit — synchronous `funcall` return |
| 6 | **Mail address** | Stable identity, separate from behavior | Absent — closure IS the address |

Plus two structural properties that hold:
- **One-at-a-time** — deterministic STF, single-threaded, no concurrency
- **Unserialized actors** — standalone pure functions (codecs, validators)

### Send — `(funcall closure :message ...)`

Every interaction is a message. A closure never exposes its internals;
you ask a question, it answers:

```lisp
(funcall kappa :ed25519-key 5)              ;; κ looks up one key
(funcall rho :offender-auth-hashes e-d)     ;; ρ scans its own assignments
(funcall beta :find-record hash)            ;; β searches its own history
(funcall gamma :seal-entry-at slot)         ;; γ hides its variant layout
```

The rule is absolute: **if the answer requires internal state, the closure
answers itself.** Outside code never reaches inside a closure.

### Create — σ births components from bytes

σ is the supervisor (Erlang/OTP pattern). It holds raw bytes — the
specifications — for all 17 child actors and births them on demand:

```lisp
(funcall sigma :load :gamma)   ;; σ fetches γ's bytes, calls load-gamma-state
                               ;; → γ closure is born, ready to receive messages
```

`load-NAME-state` is a standalone function generated by the macro — the
DNA reader. σ's `:load` message dispatches to it. The component itself
has no say in its own birth; σ is the sole creator.

After transitions, components serialize themselves back to bytes:

```lisp
(funcall gamma-prime :save)    ;; γ' knows how to encode itself → bytes
```

σ' collects those bytes. The lifecycle is:
**σ holds bytes → σ births closure → closure lives → closure saves → σ' holds bytes**

### Become — `:transition` returns the prime

This is the key primitive. Closures are immutable — they cannot mutate
themselves. `:transition` is Hewitt's `become`: the actor produces its
successor and ceases to exist.

```lisp
;; η receives a message, creates η', designates η' as successor
(funcall eta :transition :header h :tau tau :tau-prime tau-prime)
;; → η' (new closure with different acquaintances)
;; η is gone — only η' exists now
```

**`:transition` fuses three Hewitt operations** into a single synchronous call:

1. **Send** — the caller sends `:transition` with dependencies
2. **Create** — the closure creates its prime via `make-NAME-state`
3. **Become** — the closure designates the prime as successor (by returning it)

This fusion works because the STF is deterministic and sequential. In an
async actor system these would be three separate acts; in a functional
STF, the return value IS the become.

**Identity become** — when nothing changes, a closure returns itself:

```lisp
;; λ: if no epoch change, I become myself
(:transition (&key tau tau-prime kappa)
  (if (funcall tau :epoch-changed? tau-prime)
      (make-lambda-state :validators (funcall kappa :validators))
      #'self))   ;; ← identity become: λ designates itself as successor
```

`#'self` is Hewitt's identity become — the actor explicitly designates
its current behavior as the behavior for the next message.

**The full STF as an actor conversation:**

```
Υ(σ, B) → σ':

  1. σ receives B                            ← B is the message
  2. σ births {τ, η, κ, γ, ...} from bytes  ← CREATE (load-NAME-state)
  3. Each component transitions itself        ← BECOME (returns prime)
  4. Primes serialize themselves              ← SEND   (:save → bytes)
  5. σ' is assembled from the bytes          ← σ BECOMES σ'
```

### Acquaintances — who knows whom

Hewitt defines three types of acquaintances. All three appear in JOTL:

| Hewitt | JOTL mechanism | Example |
|--------|---------------|---------|
| **Private** — known from creation | Closure fields | η knows `eta-0`, `eta-1`, `eta-2`, `eta-3` |
| **Introduced** — carried by message | `:transition` kwargs | γ is introduced to `eta-prime`, `kappa-prime`, `psi-prime` |
| **Created** — made during processing | `make-NAME-state` inside `:transition` | η creates η' with new field values |

After `:transition`, the prime's acquaintances differ from the original's.
η' knows `eta-0-prime` where η knew `eta-0`. This is exactly Hewitt:
`become` produces a new behavior with different acquaintances.

The orchestrator (`upsilon.lisp`) manages the **introduction graph** — the
dependency graph from GP §4.2.1 determines which actors are introduced
to which via `:transition` kwargs. This is dependency injection via
message passing:

```lisp
;; Upsilon introduces γ to five other actors via kwargs
(funcall gamma :transition
  :tau tau :tau-prime tau-prime :tickets e-t
  :iota iota :eta-prime eta-prime
  :kappa-prime kappa-prime :psi-prime psi-prime)

;; γ knows equations §6.13-6.35 — it uses the introduced acquaintances
;; to compute γ'. Upsilon only knows the wiring.
```

### Customer — implicit (and that's correct)

In Hewitt's async model, every message carries a **customer** — an actor
that will receive the reply. There is no "return value." The receiver
sends the result to the customer.

In JOTL, the customer is implicit: `funcall` returns the result directly.
This is correct for a deterministic STF — the caller IS the customer,
and the return value IS the send-to-customer. CPS would add complexity
for zero benefit in a sequential computation.

### Mail address — fused with behavior (and that's correct)

In Hewitt's model, an actor has a stable address that survives `become`.
Other actors keep referencing the same address; the behavior behind it
changes.

In JOTL, the closure IS both the address and the behavior. After
`:transition`, γ' is a new function pointer — a new "address." The
orchestrator explicitly rebinds `gamma` → `gamma-prime`. No stale
references are possible because the STF is sequential and the
orchestrator controls the entire introduction graph.

Address indirection would be necessary in a concurrent system where
multiple actors hold references to γ. In a deterministic STF, the
orchestrator is the sole holder.

### σ as supervisor

σ is itself a closure, but at a different level: it stores raw bytes,
not live closures. Like an Erlang supervisor holding child specifications:

- `:load kw` → birth a component from bytes (lazy, on demand)
- `:transition (&key block)` → delegates to `transition-state` in `upsilon.lisp`
- `:save` — σ IS bytes, no encoding needed
- `:merkle-kvs` → pairs C(n) + bytes for the Merkle trie (GP Appendix D)
- `:state-root` → H(trie) = H_R

σ transforms itself via `:transition`, just like every other closure.
The implementation lives in `upsilon.lisp` (the 4-wave dependency graph),
but σ owns the message:

```lisp
(funcall sigma :transition :block block)   ;; σ becomes σ'
```

### B — the message, not an actor

The block is data that triggers the `become`. It holds H (a closure with
sovereignty: hash, seal, genesis) and the extrinsics E_T, E_D, E_P, E_A,
E_G as raw open data. Extrinsics have no lifecycle, no transitions, no
sovereignty — they are consumed by closures during Υ. The block is
never an actor; it is the message.

### Duck typing / protocols

Closures are not typed — they are protocol-compatible. A function that
needs a "validator set" doesn't care if it receives κ, λ, or ι. It only
knows the protocol: "this thing responds to `:ed25519-key idx`."

```lisp
(funcall kappa  :ed25519-key 5)   ;; kappa-state
(funcall lambda :ed25519-key 5)   ;; lambda-state
(funcall iota   :ed25519-key 5)   ;; iota-state
;; Same protocol, three different actors — the caller doesn't know or care
```

### `define-state-closure` — the single macro

Every closure in JOTL is built with one macro. It generates:

- `make-NAME-state` — internal constructor (used inside `:transition`)
- `load-NAME-state` — public bytes→closure loader (used by σ `:load`)
- Message dispatch via `case` — the method table
- Memoized computed properties (`:memo`)
- `:save` — self-serialization to bytes
- `:transition` — the `become` handler

```lisp
(define-state-closure eta-state
  ((eta-0 nil) (eta-1 nil) (eta-2 nil) (eta-3 nil))

  (:save :memo
    (concatenate '(vector (unsigned-byte 8))
                 (or eta-0 +zero-hash+) (or eta-1 +zero-hash+)
                 (or eta-2 +zero-hash+) (or eta-3 +zero-hash+)))

  (:decode (bytes offset)
    (values (make-eta-state
             :eta-0 (subseq bytes offset (+ offset 32))
             :eta-1 (subseq bytes (+ offset 32) (+ offset 64))
             :eta-2 (subseq bytes (+ offset 64) (+ offset 96))
             :eta-3 (subseq bytes (+ offset 96) (+ offset 128)))
            128))

  (:transition (&key header tau tau-prime)
    (let* ((y-hv (funcall header :vrf-entropy))
           (epoch-change-p (funcall tau :epoch-changed? tau-prime))
           (eta-0-prime (blake2b-256
                         (concatenate '(vector (unsigned-byte 8))
                                      (or eta-0 +zero-hash+)
                                      (or y-hv +zero-hash+)))))
      (if epoch-change-p
          (make-eta-state :eta-0 eta-0-prime
                          :eta-1 eta-0 :eta-2 eta-1 :eta-3 eta-2)
          (make-eta-state :eta-0 eta-0-prime
                          :eta-1 eta-1 :eta-2 eta-2 :eta-3 eta-3)))))
```

46 lines. Four hashes in, four hashes out. The GP equations (§6.21-23)
are visible in the `:transition` body. The codec is the `:decode` clause.
The Merkle position C(6) is σ's concern, not η's.

### Three domains, zero overlap

- `lib/` — HOW to serialize + shared protocol helpers + constants
- `bloc/` — WHAT a block is (pure data + codec + structural validation)
- `state/` — HOW state evolves (per-component closures + Υ orchestrator)

### Known gap: accumulate closures

Seven closures (ω, ξ, δ, χ, θ, ι in part, ϕ in part) are constructed
externally by the accumulate orchestrator rather than becoming themselves.
This is the PVM boundary: the Δ\* loop is inherently imperative and
cross-cutting (side-effects flow between services, gas is global, transfers
chain). These closures are born, serialized, but never `become` — they
lack `:transition`.

This is acknowledged debt, not an oversight. The accumulate orchestrator
is comparable to Υ itself: a multi-component coordinator that cannot be
owned by any single closure.

## Quick Start

```bash
sbcl --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :jotl)'
```

## Block Importer

```bash
# Run 100 fallback blocks (chain mode)
sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(in-package :jotl)' \
  --eval '(with-chain :tiny
            (run-trace "tests/jamtestvectors/traces/fallback/"
                       :from 1 :to 100 :mode :chain))'
```

```lisp
;; Load genesis → σ₀
(load-genesis "genesis.bin")             ;; → (values header σ₀ state-root)

;; Import block: Υ(σ, B) → σ'
(import-block sigma block)               ;; → (values σ' state-root)

;; Load trace step (pre-state + block + post-state)
(load-trace-step "00000001.bin")         ;; → (values pre-σ block post-σ pre-root post-root)

;; Run full trace suite
(run-trace dir :from 1 :to 100 :mode :chain)   ;; → (values pass fail)
```

## Tests

```bash
sbcl --noinform --non-interactive \
  --eval '(push (truename ".") asdf:*central-registry*)' \
  --eval '(asdf:load-system :jotl)' \
  --eval '(ql:quickload :cl-json :silent t)' \
  --eval '(load "tests/test-eta.lisp")' \
  --eval '(load "tests/test-beta.lisp")' \
  --eval '(load "tests/test-psi.lisp")' \
  --eval '(load "tests/test-safrole.lisp")'
```

| Test | GP section | Vectors | What |
|------|-----------|---------|------|
| `test-safrole` | §6 | 42 | γ STF: all segments + epoch/tickets marks + Ring VRF + codec roundtrip |
| `test-psi` | §10 | 56 | ψ STF: byte-by-byte hash comparison + codec roundtrip |
| `test-eta` | §6.21-23 | 42 | η STF: entropy accumulator + error cases + codec roundtrip |
| `test-beta` | §7.5 | 8 | β STF: MMR peaks + codec roundtrip |
| `test-block-roundtrip` | App. C | traces/ | Block, headers, extrinsics, work-report — bin/json roundtrip + H_X |
| `test-assurances` | §11 | 20 | ρ transition-ddagger: assurance processing |
| `test-reports` | §11-12 | 84 | ρ transition: guarantee processing |

## Fuser API

Binary protocol over Unix socket. Three operations:

```
init-state(genesis.bin)  →  state-root (32 bytes)
add-block(block.bin)     →  state-root (32 bytes)
debug(block.bin)         →  raw-state.bin
```

The fuser holds one mutable slot — the current σ — and applies blocks
sequentially. Each operation is a pure STF call internally:

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

## Dependencies

- SBCL (Steel Bank Common Lisp)
- Alexandria, cl-json
- CFFI + Rust crypto (`cargo build --release` in `crypto/jam-crypto/`)
- Test vectors: `git clone https://github.com/w3f/jamtestvectors tests/jamtestvectors`

## License

MIT
