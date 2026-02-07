# Timeslot API Reference

**Gray Paper §6.1-6.2**

## Constants

- `+c11+` → `11` - State key identifier for timeslot

## Core Functions

### Euclidean Division (§6.2)

```lisp
(timeslot-to-epoch-and-phase timeslot)
;; Returns: (values epoch phase)
;; Example: (timeslot-to-epoch-and-phase 25) => 2, 1

(timeslot-epoch timeslot)
;; Returns: epoch index (quotient)
;; Example: (timeslot-epoch 25) => 2

(timeslot-phase timeslot)
;; Returns: phase within epoch (remainder)
;; Example: (timeslot-phase 25) => 1

(epoch-phase-to-timeslot epoch phase)
;; Returns: timeslot number
;; Example: (epoch-phase-to-timeslot 2 1) => 25
```

### State Access

```lisp
(timeslot-state-key)
;; Returns: 31-byte state key for C11
;; => #(11 0 0 0 ... 0)

(get-timeslot-from-state state)
;; Retrieves τ from state closure
;; state must respond to :get message

(set-timeslot-in-state state new-timeslot)
;; Sets τ in state closure
;; Returns: new immutable state
```

### Epoch Transitions

```lisp
(new-epoch-p tau tau-prime)
;; Checks if crossing epoch boundary
;; Example: (new-epoch-p 11 12) => T
```

### Display

```lisp
(show-timeslot-info timeslot)
;; Prints epoch and phase info

(show-epoch-info epoch)
;; Prints epoch boundaries and duration
```

## Architecture

**τ = Simple Number** (not a closure)
- Timeslot is just a natural number (ℕT)
- Operations are pure functions
- State is a separate closure

**Why?**
- τ ∈ ℕT per Gray Paper §6.1
- Simple arithmetic operations
- No need for encapsulation

## Examples (tiny chain, E=12)

```lisp
;; Epoch and phase
(timeslot-epoch 25)   ; => 2
(timeslot-phase 25)   ; => 1

;; Conversion
(epoch-phase-to-timeslot 2 1)  ; => 25

;; Epoch transitions
(new-epoch-p 11 12)   ; => T  (epoch boundary)
(new-epoch-p 10 11)   ; => NIL (same epoch)

;; Display
(show-timeslot-info 25)
; Timeslot 25:
;   Epoch:              2
;   Phase in epoch:     1 / 12
```

---

**Status:** ✅ Complete and verified  
**Test Coverage:** 20/20 official JAM test vectors pass
