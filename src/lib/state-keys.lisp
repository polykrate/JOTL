;;;; lib/state-keys.lisp — State Merklization Keys C(n) (Gray Paper §D)
;;;;
;;;; Each state segment has a 32-byte Merkle key:
;;;;   C(n)     = [n, 0, 0, ..., 0]            for n ∈ {1..16}
;;;;   C(255,s) = [255] ⌢ E4(s) ⌢ [0...0]     for service accounts δ
;;;;
;;;; OWNERSHIP: σ (sigma.lisp) owns the mapping C(n) → component.
;;;; Individual state components do NOT know their Merkle key.
;;;; These constants are consumed by σ and by tests.
;;;;
;;;; Mapping (GP Appendix D, state encoding):
;;;;   C(1)   → α    Core authorizations
;;;;   C(2)   → ϕ    Authorization queue
;;;;   C(3)   → β    Recent history
;;;;   C(4)   → γ    Safrole state
;;;;   C(5)   → ψ    Judgments
;;;;   C(6)   → η    Entropy
;;;;   C(7)   → ι    Enqueued validator keys
;;;;   C(8)   → κ    Current validator keys
;;;;   C(9)   → λ    Archived validator keys
;;;;   C(10)  → ρ    Core assignments
;;;;   C(11)  → τ    Timeslot
;;;;   C(12)  → χ    Privileged services
;;;;   C(13)  → π    Validator statistics
;;;;   C(14)  → ω    Ready work-reports
;;;;   C(15)  → ξ    Recent accumulations
;;;;   C(16)  → θ    Accumulation queue
;;;;   C(255,s) → δ[s]  Service account s

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; KEY GENERATION
;;; ═══════════════════════════════════════════════════════════════

(defun state-key (n)
  "Generate 32-byte Merklization key C(n) for state segment n ∈ {1..16}.
   C(n) = [n, 0, 0, ..., 0]"
  (assert (<= 1 n 16) () "State key index must be 1..16, got ~A" n)
  (let ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref key 0) n)
    key))

(defun service-key (service-id)
  "Generate 32-byte Merklization key C(255, s) for service account.
   C(255,s) = [255] ⌢ E4(s) ⌢ [0...0]"
  (let ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (s-bytes (E4 service-id)))
    (setf (aref key 0) 255)
    (loop for i from 0 below 4
          do (setf (aref key (1+ i)) (aref s-bytes i)))
    key))

;;; ═══════════════════════════════════════════════════════════════
;;; NAMED CONSTANTS — C(n) for each state segment
;;; ═══════════════════════════════════════════════════════════════

(defparameter +C1+  (state-key  1) "C(1)  → α  Core authorizations")
(defparameter +C2+  (state-key  2) "C(2)  → ϕ  Authorization queue")
(defparameter +C3+  (state-key  3) "C(3)  → β  Recent history")
(defparameter +C4+  (state-key  4) "C(4)  → γ  Safrole state")
(defparameter +C5+  (state-key  5) "C(5)  → ψ  Judgments")
(defparameter +C6+  (state-key  6) "C(6)  → η  Entropy")
(defparameter +C7+  (state-key  7) "C(7)  → ι  Enqueued validator keys")
(defparameter +C8+  (state-key  8) "C(8)  → κ  Current validator keys")
(defparameter +C9+  (state-key  9) "C(9)  → λ  Archived validator keys")
(defparameter +C10+ (state-key 10) "C(10) → ρ  Core assignments")
(defparameter +C11+ (state-key 11) "C(11) → τ  Timeslot")
(defparameter +C12+ (state-key 12) "C(12) → χ  Privileged services")
(defparameter +C13+ (state-key 13) "C(13) → π  Validator statistics")
(defparameter +C14+ (state-key 14) "C(14) → ω  Ready work-reports")
(defparameter +C15+ (state-key 15) "C(15) → ξ  Recent accumulations")
(defparameter +C16+ (state-key 16) "C(16) → θ  Accumulation queue")

;;; ═══════════════════════════════════════════════════════════════
;;; KEY → SEGMENT NAME MAPPING (for debugging/display)
;;; ═══════════════════════════════════════════════════════════════

(defparameter +state-key-names+
  '((1  :alpha  "α" "Core authorizations")
    (2  :phi    "ϕ" "Authorization queue")
    (3  :beta   "β" "Recent history")
    (4  :gamma  "γ" "Safrole state")
    (5  :psi    "ψ" "Judgments")
    (6  :eta    "η" "Entropy")
    (7  :iota   "ι" "Enqueued validator keys")
    (8  :kappa  "κ" "Current validator keys")
    (9  :lambda "λ" "Archived validator keys")
    (10 :rho    "ρ" "Core assignments")
    (11 :tau    "τ" "Timeslot")
    (12 :chi    "χ" "Privileged services")
    (13 :pi     "π" "Validator statistics")
    (14 :omega  "ω" "Ready work-reports")
    (15 :xi     "ξ" "Recent accumulations")
    (16 :theta  "θ" "Accumulation queue"))
  "Mapping from C(n) index to (n keyword greek-letter description).")

(defun state-key-for-segment (segment-keyword)
  "Return the 32-byte Merkle key for a state segment keyword.
   Example: (state-key-for-segment :tau) → C(11)"
  (let ((entry (find segment-keyword +state-key-names+ :key #'second)))
    (if entry
        (state-key (first entry))
        (error "Unknown state segment: ~A" segment-keyword))))


