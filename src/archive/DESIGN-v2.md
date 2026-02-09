# v2 State Closure Architecture

## 1. Philosophical Foundation: Between Objects and Functions

### 1.1 The Problem

A blockchain state transition function (STF) needs to:
- Hold immutable state data (fields)
- Derive computed properties from that data (epoch, phase, rotation)
- Encode/decode itself for persistence (Merkle trie serialization)
- Transform itself deterministically into its successor (the "prime")

Classical approaches fall short:

| Approach | Problem |
|---|---|
| Pure functions | State, codec, and transition scattered across separate files. No cohesion. |
| CLOS objects | Mutable by default. Inheritance hierarchy is overhead for 17 flat state components. Generic dispatch is overkill. |
| Structs | No behavior attachment. Same scattering problem as pure functions. |

### 1.2 The Insight: Kay's Original OOP

Alan Kay's original vision of object-oriented programming (1967-72, Smalltalk) was **not**
about classes, inheritance, or mutable fields. It was about:

> "I thought of objects being like biological cells and/or individual computers
> on a network, only able to communicate with messages."
> — Alan Kay, 2003

The three pillars:
1. **Message passing** — objects respond to messages, not method calls
2. **Encapsulation** — internal state is private, only messages expose behavior
3. **Late binding** — the receiver decides how to handle each message

This maps directly to Common Lisp closures:

```lisp
;; A closure IS Kay's object
(let ((value 42))
  (lambda (msg)
    (case msg
      (:value value)
      (:double (* value 2)))))
```

The closure captures `value` (encapsulation), responds to messages via `case` dispatch
(message passing), and can be extended at definition time (late binding via macros).

### 1.3 The State Closure

A **state closure** is a deterministic actor:

```
                    ┌─────────────────────────┐
                    │     State Closure        │
   :value ────────▶│  Fields (immutable)      │
   :epoch ────────▶│  Derived (lazy/memo)     │
   :encoded ──────▶│  Codec (self-encoding)   │
   :transition ───▶│  STF (self-transforming) │──────▶ prime closure
   :state-key ────▶│  Merkle position         │
   :type ─────────▶│  Identity                │
                    └─────────────────────────┘
```

Not an object (no mutation, no inheritance). Not a pure function (carries state and
behavior). A **deterministic actor** that knows how to transform itself.

---

## 2. Closures in Common Lisp: Deep Dive

### 2.1 Let-Over-Lambda

The foundational pattern: a `let` binding closed over by a `lambda`.

```lisp
;; The simplest closure
(let ((x 0))
  (lambda () (incf x)))  ;; mutation! — we don't want this

;; Immutable variant (our pattern)
(let ((x 42))
  (lambda (msg)
    (case msg
      (:value x)
      (:double (* x 2)))))
```

Key properties:
- The `let` bindings become the closure's private "fields"
- The `lambda` becomes the message dispatch function
- Once created, the captured values are **frozen** (if we don't use `setf`)
- Each call to the constructor creates a **new** closure with fresh bindings

### 2.2 Labels for Self-Reference

CL `labels` creates named local functions visible to themselves:

```lisp
(labels ((self (msg)
           (case msg
             (:value 42)
             (:encoded (E4 (self :value))))))  ;; self-reference!
  #'self)
```

This is critical for computed properties that depend on other messages —
e.g., `:merkle-kv` needs `(self :state-key)` and `(self :encoded)`.

### 2.3 Memoization via Setf-Once

Lazy evaluation in CL closures uses a simple pattern:

```lisp
(let ((memo-epoch nil))  ;; cache slot
  (labels ((self (msg)
             (case msg
               (:epoch (or memo-epoch
                           (setf memo-epoch (floor value (epoch-duration))))))))
    #'self))
```

The first access computes and caches. Subsequent accesses return the cached value.
This is **not mutation** in the OOP sense — it's memoization of a pure computation.
The value is deterministic: given the same `value`, `:epoch` always returns the same
result. The `setf` is an optimization, not a state change.

**Thread safety**: In a single-threaded STF execution (which blockchain transitions
are), this is safe. If parallelism is needed later, `bordeaux-threads:make-lock`
wrapping the `or`/`setf` is sufficient — but the GP execution model is sequential
within a block.

### 2.4 Variadic Dispatch

v1 closures take a single argument: `(funcall obj :msg)`.
v2 closures become variadic to support `:transition` with keyword dependencies:

```lisp
;; v1 protocol: single message
(labels ((self (msg) (case msg ...)))
  #'self)

;; v2 protocol: message + optional keyword arguments
(labels ((self (&rest args)
           (let ((msg (car args)))
             (case msg
               ;; Simple accessors — no extra args needed
               (:value value)
               (:epoch (or memo-epoch ...))
               ;; Transition — keyword deps from (cdr args)
               (:transition
                 (destructuring-bind (&key header) (cdr args)
                   (let ((tau-prime-val (funcall header :slot)))
                     (make-tau-state :value tau-prime-val))))
               ...))))
  #'self)
```

**Backward compatible**: `(funcall tau :value)` → `args = (:value)`, `(car args) = :value`,
`(cdr args) = nil`. Existing code works unchanged.

**Performance**: `&rest` allocates a list on every call. For hot paths (field access),
the CL compiler can optimize this to stack allocation via `dynamic-extent` declarations:

```lisp
(labels ((self (&rest args)
           (declare (dynamic-extent args))
           ...))
  #'self)
```

With SBCL, this eliminates heap allocation for the rest list entirely.

---

## 3. The `define-state-closure` Macro

### 3.1 Syntax

```lisp
(define-state-closure NAME
  ;; Fields: (PARAM DEFAULT) pairs — the closure's immutable data
  ((field1 default1)
   (field2 default2))

  ;; Merkle position
  (:state-key EXPR)

  ;; Encoding — how to serialize to bytes
  (:encoded :memo BODY)

  ;; Decoding — how to deserialize from bytes (used by sigma dispatch)
  (:decode (bytes offset) BODY)

  ;; Lazy accessors — computed once, cached
  (:accessor-name :memo BODY)

  ;; Regular accessors — computed on every access
  (:accessor-name BODY)

  ;; STF — transition logic with keyword dependencies
  (:transition (&key dep1 dep2 ...) BODY)

  ;; Multi-stage transitions (for rho)
  (:transition-dagger (&key ...) BODY)
  (:transition-ddagger (&key ...) BODY))
```

### 3.2 Expansion: tau-state Example

Input:

```lisp
(define-state-closure tau-state
  ((value 0))
  (:state-key +C11+)
  (:encoded :memo (E4 value))
  (:epoch    :memo (floor value (epoch-duration)))
  (:phase    :memo (mod value (epoch-duration)))
  (:rotation :memo (floor value (rotation-period)))
  (:decode (bytes offset)
    (multiple-value-bind (val consumed) (decode-u32 bytes offset)
      (values (make-tau-state :value val) consumed)))
  (:transition (&key header)
    (let ((tau-prime-val (funcall header :slot)))
      (assert (> tau-prime-val value) ()
              "GP §5.7: τ'=~D must be > τ=~D" tau-prime-val value)
      (make-tau-state :value tau-prime-val))))
```

Expands (conceptually) to:

```lisp
(progn
  ;; Constructor
  (defun make-tau-state (&key (value 0))
    "Creates tau-state state closure (immutable, self-transforming)."
    (let ((memo-encoded nil)
          (memo-epoch nil)
          (memo-phase nil)
          (memo-rotation nil))
      (labels ((self (&rest args)
                 (declare (dynamic-extent args))
                 (let ((msg (car args)))
                   (case msg
                     ;; Field access
                     (:value value)
                     ;; Memoized accessors
                     (:encoded  (or memo-encoded
                                    (setf memo-encoded (E4 value))))
                     (:epoch    (or memo-epoch
                                    (setf memo-epoch (floor value (epoch-duration)))))
                     (:phase    (or memo-phase
                                    (setf memo-phase (mod value (epoch-duration)))))
                     (:rotation (or memo-rotation
                                    (setf memo-rotation (floor value (rotation-period)))))
                     ;; Decode (class-like: dispatched via sigma)
                     (:decode
                       (destructuring-bind (bytes offset) (cdr args)
                         (multiple-value-bind (val consumed) (decode-u32 bytes offset)
                           (values (make-tau-state :value val) consumed))))
                     ;; Transition — GP (4.5): τ' < (H)
                     (:transition
                       (destructuring-bind (&key header) (cdr args)
                         (let ((tau-prime-val (funcall header :slot)))
                           (assert (> tau-prime-val value) ()
                                   "GP §5.7: τ'=~D must be > τ=~D" tau-prime-val value)
                           (make-tau-state :value tau-prime-val))))
                     ;; State-key
                     (:state-key +C11+)
                     (:merkle-kv (cons (self :state-key) (self :encoded)))
                     ;; Introspection
                     (:as-plist (list :value value))
                     (:type :tau-state)
                     (otherwise
                       (error "Unknown tau-state message: ~a" msg))))))
        #'self)))

  ;; Accessors
  (defun tau-state-value (obj) (funcall obj :value))

  ;; Register decoder in sigma dispatch table
  (register-state-decoder +C11+ (lambda (bytes offset)
    (multiple-value-bind (val consumed) (decode-u32 bytes offset)
      (values (make-tau-state :value val) consumed)))))
```

### 3.3 Differences from `define-value-object`

| Feature | `define-value-object` (v1) | `define-state-closure` (v2) |
|---|---|---|
| Dispatch arity | Single arg `(msg)` | Variadic `(&rest args)` |
| `:transition` | Not supported — separate `defun` | Built-in, keyword args |
| `:decode` | Not supported — separate `defun` | Built-in, registered in sigma |
| Stack alloc | N/A | `(declare (dynamic-extent args))` |
| Backward compat | N/A | Full — field access unchanged |
| Self-reference | `(self :msg)` | `(self :msg ...)` — variadic too |

---

## 4. Sigma Decode Dispatch

### 4.1 The Registry

Each `define-state-closure` auto-registers its decoder. Sigma holds the dispatch table:

```lisp
;; Global registry: state-key → decoder-fn
(defvar *state-decoders* (make-hash-table :test 'equalp)
  "Maps C(n) byte-vector → (lambda (bytes offset) → (values closure consumed))")

(defun register-state-decoder (state-key decoder-fn)
  "Register a state component decoder. Called by define-state-closure expansion."
  (setf (gethash state-key *state-decoders*) decoder-fn))

(defun decode-state-segment (state-key bytes offset)
  "Decode a state segment given its Merkle key and raw bytes."
  (let ((decoder (gethash state-key *state-decoders*)))
    (unless decoder
      (error "No decoder registered for state-key ~A" state-key))
    (funcall decoder bytes offset)))
```

### 4.2 Sigma Reconstruction from Merkle Trie

```lisp
(defun decode-sigma-from-trie (trie)
  "Reconstruct σ from a Merkle trie.
   Walks C(1)..C(16), extracts bytes, dispatches to registered decoders."
  (make-state
    :alpha   (decode-from-trie trie +C1+)
    :phi     (decode-from-trie trie +C2+)
    :beta    (decode-from-trie trie +C3+)
    :gamma   (decode-from-trie trie +C4+)
    :psi     (decode-from-trie trie +C5+)
    :eta     (decode-from-trie trie +C6+)
    :iota    (decode-from-trie trie +C7+)
    :kappa   (decode-from-trie trie +C8+)
    :lambda* (decode-from-trie trie +C9+)
    :rho     (decode-from-trie trie +C10+)
    :tau     (decode-from-trie trie +C11+)
    :chi     (decode-from-trie trie +C12+)
    :pi*     (decode-from-trie trie +C13+)
    :omega   (decode-from-trie trie +C14+)
    :xi      (decode-from-trie trie +C15+)
    :theta   (decode-from-trie trie +C16+)))

(defun decode-from-trie (trie state-key)
  "Extract bytes for a state-key from the Merkle trie and decode."
  (let ((bytes (trie-lookup trie state-key)))
    (when bytes
      (values (decode-state-segment state-key bytes 0)))))
```

### 4.3 Why Sigma Dispatch (Not Instance Decode)

Alternative: `(funcall (make-tau-state) :decode bytes offset)` — prototype pattern.

Problems:
1. Requires creating a throw-away instance just to call `:decode`
2. `:decode` is a class-level operation, not an instance operation
3. Conceptually wrong: the instance doesn't "decode itself", it **is created by** decoding

Sigma dispatch is cleaner: sigma is the aggregate root, it knows the full state
structure, and it delegates decoding to each registered component.

---

## 5. GP Equation Mapping

### 5.1 v2 Upsilon (Complete)

Each GP equation maps to a `:transition` call with keyword deps matching the GP
dependency specification:

```lisp
(defun transition-state (sigma block)
  (let* ((h   (funcall block :header))
         (e   (funcall block :extrinsic))
         (e-t (funcall e :tickets))
         (e-d (funcall e :disputes))
         (e-p (funcall e :preimages))
         (e-a (funcall e :assurances))
         (e-g (funcall e :guarantees))
         ;; Prior state (closures from sigma)
         (tau   (or (funcall sigma :tau) (make-tau-state)))
         (eta   (or (funcall sigma :eta) (make-eta)))
         (kappa (or (funcall sigma :kappa) (make-kappa)))
         ;; ... etc for all 17 components
         )
    ;; ══ WAVE 1 ══
    ;; (4.5) τ' < (H)
    (let* ((tau-prime   (funcall tau :transition :header h))
           ;; (4.8) η' < (H, τ, τ', η)
           (eta-prime   (funcall eta :transition
                          :header h :tau tau :tau-prime tau-prime))
           ;; (4.9) κ' < (τ, τ', κ, γ)
           (kappa-prime (funcall kappa :transition
                          :tau tau :tau-prime tau-prime :gamma gamma))
           ;; (4.10) λ' < (τ, τ', λ, κ)
           (lambda-prime (funcall lambda-prev :transition
                           :tau tau :tau-prime tau-prime :kappa kappa))
           ;; ...
           )
      ;; ══ WAVE 2 ══
      ;; (4.7) γ' < (H, τ, τ', ET, γ, ι, η', κ', ψ')
      (let* ((gamma-prime (funcall gamma :transition
                            :header h :tau tau :tau-prime tau-prime
                            :tickets e-t :iota iota
                            :eta-prime eta-prime :kappa-prime kappa-prime
                            :psi-prime psi-prime))
             ;; ...
             )
        ;; ══ WAVE 3 ══
        ;; (4.14) ρ' < (EG, ρ‡, κ, τ')
        (let* ((rho-prime (funcall rho-ddagger :transition
                            :guarantees e-g :tau-prime tau-prime
                            :kappa kappa ...))
               ;; ...
               )
          ;; BUILD σ'
          (make-state
            :tau tau-prime
            :eta eta-prime
            ;; ...
            ))))))
```

### 5.2 Full Dependency Table

| Eq. | Component | v2 `:transition` keyword args |
|---|---|---|
| (4.5) | τ' | `:header` |
| (4.6) | β† | `:header` |
| (4.7) | γ' | `:header :tau :tau-prime :tickets :iota :eta-prime :kappa-prime :psi-prime` |
| (4.8) | η' | `:header :tau :tau-prime` |
| (4.9) | κ' | `:tau :tau-prime :gamma` |
| (4.10) | λ' | `:tau :tau-prime :kappa` |
| (4.11) | ψ' | `:disputes :tau :kappa :lambda-prev` |
| (4.12) | ρ† | `:v-list` |
| (4.13) | ρ‡ | `:assurances :tau-prime :parent-hash :kappa` |
| (4.14) | ρ' | `:guarantees :tau-prime :kappa :lambda-prev :eta :offenders :recent-blocks :auth-pools :accounts` |
| (4.16) | accumulate | stays as function (sub-orchestrator) |
| (4.17) | β' | `:header :guarantees :beta-dagger :theta-prime` |
| (4.18) | δ' | `:preimages :delta-ddagger :tau-prime` |
| (4.19) | α' | `:header :guarantees :phi-prime` |
| (4.20) | π' | `:guarantees :preimages :assurances :tickets :tau :kappa-prime :header :s-reports` |

Note: `tau` and `tau-prime` are both passed explicitly to components that need
epoch-boundary detection. The prior `tau` provides `:epoch` for the old timeslot,
`tau-prime` provides `:epoch` for the new timeslot. `new-epoch-p` becomes:

```lisp
(defun new-epoch-p (tau tau-prime)
  (/= (funcall tau :epoch) (funcall tau-prime :epoch)))
```

This is cleaner than the v1 "enriched tau" pattern where tau held its own prime.

---

## 6. Multi-Value Returns

### 6.1 The Problem

Some transitions return side-products alongside the prime state:
- `transition-psi`: returns `(values ψ' v-list)` — v-list used by ρ†
- `transition-rho-ddagger`: returns `(values ρ‡ R*)` — R* used by accumulate

### 6.2 CL Preserves Multiple Values Through `funcall`

```lisp
(multiple-value-bind (psi-prime v-list)
    (funcall psi :transition :disputes e-d :tau tau ...)
  ;; psi-prime = ψ' closure
  ;; v-list = side-product
  ...)
```

CL's `funcall` transparently propagates multiple values. The `:transition` body
just uses `(values ...)`:

```lisp
(:transition (&key disputes tau kappa lambda-prev)
  ;; ... validation and computation ...
  (values (make-psi :good good-prime :bad bad-prime
                    :wonky wonky-prime :offenders offenders-prime)
          v-list))
```

No special handling needed. This is one of CL's strengths over languages that
only support single-value returns.

---

## 7. Special Case: rho (Multi-Stage Transitions)

### 7.1 Three Stages

ρ has three transition stages:
- ρ† (dagger): clear bad/wonky assignments based on judgments — GP (4.12)
- ρ‡ (ddagger): clear stale/available assignments based on assurances — GP (4.13)
- ρ' (prime): register new guaranteed work-reports — GP (4.14)

### 7.2 Design: Multiple Transition Messages

```lisp
(define-state-closure rho
  ((assignments nil))
  (:state-key +C10+)
  (:encoded :memo ...)
  ;; (4.12) ρ† < (ED, ρ) via v-list from ψ'
  (:transition-dagger (&key v-list)
    ...)
  ;; (4.13) ρ‡ < (EA, ρ†)
  (:transition-ddagger (&key assurances tau-prime parent-hash kappa)
    ...)
  ;; (4.14) ρ' < (EG, ρ‡, κ, τ')
  (:transition (&key guarantees tau-prime kappa lambda-prev eta
                     offenders recent-blocks auth-pools accounts)
    ...))
```

In upsilon:
```lisp
(let* ((rho-dagger  (funcall rho :transition-dagger :v-list v-list))
       (rho-ddagger (funcall rho-dagger :transition-ddagger
                      :assurances e-a :tau-prime tau-prime ...))
       (rho-prime   (funcall rho-ddagger :transition
                      :guarantees e-g :tau-prime tau-prime ...)))
  ...)
```

Each stage returns a new rho closure that can be further transitioned.
This is the natural chaining pattern for multi-stage components.

---

## 8. Comparison with Alternatives

### 8.1 CLOS Generic Functions

```lisp
;; CLOS approach
(defclass tau-state ()
  ((value :initarg :value :reader tau-value)))

(defmethod transition ((tau tau-state) &key header)
  (make-instance 'tau-state :value (slot header :slot)))

(defmethod epoch ((tau tau-state))
  (floor (tau-value tau) (epoch-duration)))
```

Problems for JOTL:
- **Mutable by default**: slots are `setf`-able unless you carefully use `:reader` only
- **Dispatch overhead**: generic function dispatch is heavier than `case` dispatch
- **No memoization**: CLOS has no built-in lazy slots; needs MOP or manual caching
- **Class hierarchy**: 17 state components with no shared behavior don't benefit from inheritance
- **Slot access protocol**: `slot-value` / readers are less uniform than message passing

### 8.2 Plain Structs

```lisp
(defstruct tau-state value)
(defun tau-epoch (tau) (floor (tau-state-value tau) (epoch-duration)))
(defun transition-tau (tau header) ...)
```

Problems:
- **No cohesion**: data, accessors, codec, transition scattered across files
- **No computed properties**: every access recomputes (no memoization)
- **No self-knowledge**: the struct doesn't know its state-key or how to encode itself

### 8.3 State Closures (v2)

```lisp
(define-state-closure tau-state
  ((value 0))
  (:state-key +C11+)
  (:encoded :memo (E4 value))
  (:epoch :memo (floor value (epoch-duration)))
  (:transition (&key header) ...))
```

Advantages:
- **Cohesion**: data + derived + codec + transition in one declaration
- **Immutability**: enforced by closure capture (no setf on fields)
- **Lazy evaluation**: memoized accessors computed once
- **Self-knowledge**: knows its state-key, can encode itself, can transition itself
- **Uniform protocol**: everything is `(funcall obj :msg ...)` — simple and composable
- **GP-aligned**: keyword args in `:transition` match GP dependency specifications exactly

---

## 9. Implementation Plan

### Phase 1: Macro (this PR)
1. Implement `define-state-closure` in `src/v2/macros.lisp`
2. Port `tau-state` as first prototype in `src/v2/tau.lisp`
3. Validate with existing test vectors (42/42 safrole tests)

### Phase 2: Port All Components
4. Port eta, kappa, lambda (simple epoch-boundary components)
5. Port gamma, psi (complex multi-dependency components)
6. Port rho (multi-stage transitions)

### Phase 3: Sigma & Upsilon
7. Implement sigma decode dispatch (`*state-decoders*` registry)
8. Rewrite upsilon to use `:transition` messages
9. Full regression test (294/294)

### Phase 4: Cleanup
10. Remove `define-value-object` (v1 macro)
11. Remove standalone `transition-*` functions
12. Remove standalone `encode-state-*` / `decode-state-*` functions
