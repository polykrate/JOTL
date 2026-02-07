;;;; timeslot.lisp - JAM Timeslot Implementation (Pure FP)
;;;; Gray Paper Section 6.1-6.2

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 6.1-6.2: TIMESLOT
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §6.1:

  τ ∈ ℕT, τ' ≡ HT                                      (6.1)

Where:
  τ = current timeslot (natural number)
  τ' = new timeslot (from header HT)
  ℕT = natural numbers for timeslot

We track the slot index in state as τ in order that we are able
to easily both identify a new epoch and determine the slot at which
the prior block was authored.

Gray Paper §6.2:

  let e ℛ m = τ/E, e' ℛ m' = τ'/E                      (6.2)

Where:
  τ = timeslot number
  E = epoch duration (number of timeslots per epoch)
  e = epoch index (quotient of division)
  m = slot phase within epoch (remainder, 0 to E-1)
  e' = new epoch index
  m' = new slot phase
  ℛ = euclidean division operator (quotient ℛ remainder)
  
Example (tiny chain, E=12):
  τ=25 : 25/12 = 2 ℛ 1, so e=2, m=1

State key:
  C11 = 11 (constant identifier)
  State key = 31-byte array: 0x0b followed by 30 zeros
  Full key (hex): 0x0b000000000000000000000000000000000000000000000000000000000000
  Length: 64 chars (0x + 62 hex digits = 31 bytes)
|#

;;; Constants from Gray Paper
(defconstant +c11+ 11
  "C11 - Timeslot constant identifier")

(defun make-state-key (index)
  "Creates a 31-byte state key from an index
   
   Format: first byte = index, remaining 30 bytes = 0
   Total: 31 bytes (not 32!)
   
   Example:
   C11 = 11 → 0x0b000000...00 (31 bytes, 64 hex chars with 0x prefix)"
  
  (let ((key (make-array 31 :element-type '(unsigned-byte 8) 
                            :initial-element 0)))
    (setf (aref key 0) index)
    key))

(defun timeslot-state-key ()
  "Returns the 31-byte state key for timeslot
   
   C11 = 11
   Key = 0x0b000000000000000000000000000000000000000000000000000000000000
   (31 bytes, 64 hex chars with 0x prefix)"
  
  (make-state-key +c11+))

;;; ═══════════════════════════════════════════════════════════════
;;; EUCLIDEAN DIVISION (Gray Paper §6.2)
;;; ═══════════════════════════════════════════════════════════════

(defun timeslot-to-epoch-and-phase (timeslot)
  "Euclidean division: τ/E = e ℛ m
   
   Gray Paper §6.2:
   let e ℛ m = τ/E
   
   Where:
     τ = timeslot number
     E = epoch_duration (constant: 12 for tiny, 600 for full)
     e = epoch index (quotient of division)
     m = slot phase within epoch (remainder: 0 to E-1)
   
   Returns: (values epoch phase)
   
   Example (tiny chain, E=12):
   τ=0  : 0/12  = 0 ℛ 0  => epoch=0, phase=0
   τ=11 : 11/12 = 0 ℛ 11 => epoch=0, phase=11
   τ=12 : 12/12 = 1 ℛ 0  => epoch=1, phase=0
   τ=25 : 25/12 = 2 ℛ 1  => epoch=2, phase=1"
  
  (floor timeslot (epoch-duration)))

(defun timeslot-epoch (timeslot)
  "Returns epoch index e from timeslot τ
   
   Gray Paper §6.2: e = quotient(τ/E)
   
   Example (tiny, E=12):
   (timeslot-epoch 0)   => 0
   (timeslot-epoch 25)  => 2"
  
  (floor timeslot (epoch-duration)))

(defun timeslot-phase (timeslot)
  "Returns slot phase m within epoch from timeslot τ
   
   Gray Paper §6.2: m = remainder(τ/E)
   
   Example (tiny, E=12):
   (timeslot-phase 0)   => 0  (first slot of epoch)
   (timeslot-phase 11)  => 11 (last slot of epoch)
   (timeslot-phase 12)  => 0  (first slot of next epoch)"
  
  (mod timeslot (epoch-duration)))

(defun epoch-phase-to-timeslot (epoch phase)
  "Inverse operation: (e, m) → τ
   
   τ = e × E + m
   
   Where:
     e = epoch index
     m = phase within epoch (0 to E-1)
     E = epoch_duration (constant)
     τ = resulting timeslot number
   
   Example (tiny, E=12):
   e=0, m=0  : τ = 0×12 + 0  = 0
   e=0, m=11 : τ = 0×12 + 11 = 11
   e=1, m=0  : τ = 1×12 + 0  = 12
   e=2, m=1  : τ = 2×12 + 1  = 25"
  
  (+ (* epoch (epoch-duration)) phase))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE ACCESS (Gray Paper: τ stored at C11)
;;; ═══════════════════════════════════════════════════════════════

(defun get-timeslot-from-state (state)
  "Retrieves timeslot τ from state at key C11
   
   Gray Paper §6.1: τ stored in state
   
   C11 = 11
   State key = 0x0b000000...00 (31 bytes)
   
   state is a closure with :get operation"
  
  (funcall state :get (timeslot-state-key)))

(defun set-timeslot-in-state (state new-timeslot)
  "Sets timeslot τ in state at key C11
   
   Gray Paper §6.1: τ' ≡ HT
   New timeslot comes from header
   
   C11 = 11
   State key = 0x0b000000...00 (31 bytes)
   
   Returns: new state (immutable)"
  
  (funcall state :set (timeslot-state-key) new-timeslot))

;;; ═══════════════════════════════════════════════════════════════
;;; EPOCH TRANSITIONS (Gray Paper §6.2)
;;; ═══════════════════════════════════════════════════════════════

(defun new-epoch-p (tau tau-prime)
  "Checks if transition from τ to τ' crosses epoch boundary
   
   Gray Paper §6.2:
   let e ℛ m = τ/E
   let e' ℛ m' = τ'/E
   
   New epoch if e' > e
   
   Example (tiny, E=12):
   (new-epoch-p 11 12)  => T  (0→1)
   (new-epoch-p 10 11)  => NIL (same epoch)
   (new-epoch-p 23 24)  => T  (1→2)"
  
  (let ((e (timeslot-epoch tau))
        (e-prime (timeslot-epoch tau-prime)))
    (> e-prime e)))

;;; ═══════════════════════════════════════════════════════════════
;;; DISPLAY / INSPECTION
;;; ═══════════════════════════════════════════════════════════════

(defun show-timeslot-info (timeslot)
  "Display information about a timeslot
   
   Example (tiny, E=12):
   (show-timeslot-info 25)
   =>
   Timeslot 25:
     Epoch:              2
     Phase in epoch:     1 / 12"
  (format t "~%Timeslot ~D:~%" timeslot)
  (format t "  Epoch:              ~D~%" (timeslot-epoch timeslot))
  (format t "  Phase in epoch:     ~D / ~D~%~%" 
          (timeslot-phase timeslot)
          (epoch-duration)))

(defun show-epoch-info (epoch)
  "Display information about an epoch
   
   Example (tiny, E=12):
   (show-epoch-info 2)
   =>
   Epoch 2:
     First timeslot:     24
     Last timeslot:      35
     Duration:           12 timeslots"
  (let ((first-slot (epoch-phase-to-timeslot epoch 0))
        (last-slot (1- (epoch-phase-to-timeslot (1+ epoch) 0))))
    (format t "~%Epoch ~D:~%" epoch)
    (format t "  First timeslot:     ~D~%" first-slot)
    (format t "  Last timeslot:      ~D~%" last-slot)
    (format t "  Duration:           ~D timeslots~%~%" (epoch-duration))))

;;; ═══════════════════════════════════════════════════════════════
;;; USAGE EXAMPLES
;;; ═══════════════════════════════════════════════════════════════

#|
Usage examples (tiny chain, E=12):

;; Find epoch from timeslot
(timeslot-epoch 25)          ; => 2

;; Find phase within epoch
(timeslot-phase 25)          ; => 1

;; Get both at once
(timeslot-to-epoch-and-phase 25)  ; => (values 2 1)

;; Convert epoch+phase to timeslot
(epoch-phase-to-timeslot 2 1)     ; => 25

;; Check epoch transitions
(new-epoch-p 11 12)          ; => T  (epoch 0 → 1)
(new-epoch-p 10 11)          ; => NIL (same epoch)

;; Display info
(show-timeslot-info 25)
; Timeslot 25:
;   Epoch:              2
;   Phase in epoch:     1 / 12

(show-epoch-info 2)
; Epoch 2:
;   First timeslot:     24
;   Last timeslot:      35
;   Duration:           12 timeslots

;; State access (with state closure)
(let ((state (make-state)))
  (set-timeslot-in-state state 42)
  (get-timeslot-from-state state))  ; => 42

Code is Law - Pure FP Timeslots ! 🚀
|#
