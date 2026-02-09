;;;; tests/test-v2-tau.lisp — Validate v2 tau-state-v2 (define-state-closure)
;;;;
;;;; Tests:
;;;;   1. Field access: :slot
;;;;   2. Memoized accessors: :epoch, :phase, :rotation, :min-allowed-slot
;;;;   3. Transition: :transition :header h  → τ' closure
;;;;   4. Codec: :encoded, :decode
;;;;   5. State-key: :state-key, :merkle-kv
;;;;   6. Cross-validation against v1 tau-state
;;;;   7. Sigma decoder registry
;;;;   8. Epoch boundary: :epoch-changed? message
;;;;   9. Semantic queries: :stale?, :slot>=, :lookup-fresh?

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; TEST INFRASTRUCTURE
;;; ═════════════════════════════════════════════════════════════════

(defvar *v2-tau-pass* 0)
(defvar *v2-tau-fail* 0)

(defmacro v2-assert (name test-form)
  `(if ,test-form
       (progn (incf *v2-tau-pass*)
              (format t "  ✅ ~A~%" ,name))
       (progn (incf *v2-tau-fail*)
              (format t "  ❌ ~A~%" ,name))))

;;; ═════════════════════════════════════════════════════════════════
;;; TESTS
;;; ═════════════════════════════════════════════════════════════════

(defun run-v2-tau-tests ()
  "Run all v2 tau-state-v2 tests."
  (setf *v2-tau-pass* 0 *v2-tau-fail* 0)
  (format t "~%═══ v2 tau-state-v2 tests ═══~%")

  ;; Use tiny chain for deterministic epoch/rotation values
  (with-chain :tiny

    ;; ── 1. Field access ──────────────────────────────────────────
    (let ((tau (make-tau-state-v2 :slot 100)))
      (v2-assert "field :slot"
        (= (funcall tau :slot) 100))
      (v2-assert "field :type"
        (eq (funcall tau :type) :tau-state-v2))
      (v2-assert "field :as-plist"
        (equal (funcall tau :as-plist) '(:slot 100))))

    ;; ── 2. Memoized accessors ────────────────────────────────────
    (let* ((E (epoch-duration))
           (R (rotation-period))
           (tau (make-tau-state-v2 :slot 100)))
      (v2-assert "memo :epoch"
        (= (funcall tau :epoch) (floor 100 E)))
      (v2-assert "memo :phase"
        (= (funcall tau :phase) (mod 100 E)))
      (v2-assert "memo :rotation"
        (= (funcall tau :rotation) (floor 100 R)))
      ;; :min-allowed-slot = R * max(0, ⌊slot/R⌋ - 1)
      (v2-assert "memo :min-allowed-slot"
        (= (funcall tau :min-allowed-slot)
           (* R (max 0 (1- (floor 100 R))))))
      ;; Memoization: second call returns same value
      (v2-assert "memo :epoch idempotent"
        (= (funcall tau :epoch) (funcall tau :epoch)))
      (v2-assert "memo :min-allowed-slot idempotent"
        (= (funcall tau :min-allowed-slot) (funcall tau :min-allowed-slot))))

    ;; ── 3. Transition ────────────────────────────────────────────
    (let* ((tau (make-tau-state-v2 :slot 100))
           ;; Fake header closure that responds to :slot
           (header (lambda (msg) (case msg (:slot 200))))
           (tau-prime (funcall tau :transition :header header)))
      (v2-assert "transition returns closure"
        (functionp tau-prime))
      (v2-assert "transition :slot = HT"
        (= (funcall tau-prime :slot) 200))
      (v2-assert "transition :epoch computed"
        (= (funcall tau-prime :epoch) (floor 200 (epoch-duration))))
      ;; Original tau unchanged (immutability)
      (v2-assert "original tau unchanged"
        (= (funcall tau :slot) 100))
      ;; Transition assertion: τ' must be > τ
      (v2-assert "transition rejects τ' <= τ"
        (handler-case
            (progn
              (funcall tau :transition
                       :header (lambda (msg) (case msg (:slot 50))))
              nil)  ;; should not reach here
          (error () t))))

    ;; ── 4. Codec ─────────────────────────────────────────────────
    (let* ((tau (make-tau-state-v2 :slot 12345))
           (encoded (funcall tau :encoded)))
      (v2-assert "encoded is byte vector"
        (typep encoded '(vector (unsigned-byte 8))))
      (v2-assert "encoded length = 4"
        (= (length encoded) 4))
      ;; Decode via :decode message
      (multiple-value-bind (decoded consumed)
          (funcall tau :decode encoded 0)
        (v2-assert "decode returns closure"
          (functionp decoded))
        (v2-assert "decode consumed = 4"
          (= consumed 4))
        (v2-assert "decode roundtrip"
          (= (funcall decoded :slot) 12345)))
      ;; Decode via registry
      (v2-assert "decoder registered"
        (not (null (gethash +C11+ *state-decoders*))))
      (multiple-value-bind (decoded consumed)
          (decode-state-segment +C11+ encoded 0)
        (v2-assert "registry decode roundtrip"
          (and (= consumed 4)
               (= (funcall decoded :slot) 12345)))))

    ;; ── 5. State-key / Merkle ────────────────────────────────────
    (let ((tau (make-tau-state-v2 :slot 42)))
      (v2-assert "state-key = C(11)"
        (equalp (funcall tau :state-key) +C11+))
      (let ((mkv (funcall tau :merkle-kv)))
        (v2-assert "merkle-kv is cons"
          (consp mkv))
        (v2-assert "merkle-kv car = state-key"
          (equalp (car mkv) +C11+))
        (v2-assert "merkle-kv cdr = encoded"
          (equalp (cdr mkv) (funcall tau :encoded)))))

    ;; ── 6. Cross-validation with v1 tau-state ────────────────────
    ;; v1 uses :value, v2 uses :slot — same semantics
    (dolist (val '(0 1 100 599 600 601 1199 1200 99999))
      (let ((v1 (make-tau-state :value val))
            (v2 (make-tau-state-v2 :slot val)))
        (v2-assert (format nil "v1=v2 slot=~D :slot" val)
          (= (funcall v1 :value) (funcall v2 :slot)))
        (v2-assert (format nil "v1=v2 slot=~D :epoch" val)
          (= (funcall v1 :epoch) (funcall v2 :epoch)))
        (v2-assert (format nil "v1=v2 slot=~D :phase" val)
          (= (funcall v1 :phase) (funcall v2 :phase)))
        (v2-assert (format nil "v1=v2 slot=~D :rotation" val)
          (= (funcall v1 :rotation) (funcall v2 :rotation)))
        (v2-assert (format nil "v1=v2 slot=~D :encoded" val)
          (equalp (funcall v1 :encoded) (funcall v2 :encoded)))))

    ;; ── 7. Epoch boundary (:epoch-changed? message) ───────────────
    (let ((E (epoch-duration)))
      ;; Same epoch
      (v2-assert "epoch-changed? same epoch → nil"
        (not (funcall (make-tau-state-v2 :slot 0)
                      :epoch-changed?
                      (make-tau-state-v2 :slot 1))))
      ;; Cross epoch boundary
      (v2-assert "epoch-changed? cross → t"
        (funcall (make-tau-state-v2 :slot (1- E))
                 :epoch-changed?
                 (make-tau-state-v2 :slot E)))
      ;; Same slot → same epoch
      (v2-assert "epoch-changed? same slot → nil"
        (not (funcall (make-tau-state-v2 :slot 100)
                      :epoch-changed?
                      (make-tau-state-v2 :slot 100)))))

    ;; ── 8. Transition chaining ───────────────────────────────────
    ;; τ → τ' → τ'' (two transitions)
    (let* ((tau (make-tau-state-v2 :slot 100))
           (h1 (lambda (msg) (case msg (:slot 200))))
           (tau-prime (funcall tau :transition :header h1))
           (h2 (lambda (msg) (case msg (:slot 300))))
           (tau-double-prime (funcall tau-prime :transition :header h2)))
      (v2-assert "chain: τ=100"
        (= (funcall tau :slot) 100))
      (v2-assert "chain: τ'=200"
        (= (funcall tau-prime :slot) 200))
      (v2-assert "chain: τ''=300"
        (= (funcall tau-double-prime :slot) 300)))

    ;; ── 9. Semantic queries for ρ ────────────────────────────────

    ;; :stale? — (11.17) τ' ≥ timeout + U
    ;; tiny: U = +availability-timeout+ = 5
    (let ((tau (make-tau-state-v2 :slot 12)))
      ;; timeout=7, slot=12, 12 >= 7+5=12 → T (stale)
      (v2-assert "stale? timeout=7, slot=12 → t"
        (funcall tau :stale? 7))
      ;; timeout=11, slot=12, 12 >= 11+5=16 → NIL (not stale)
      (v2-assert "stale? timeout=11, slot=12 → nil"
        (not (funcall tau :stale? 11)))
      ;; timeout=0, slot=12, 12 >= 0+5=5 → T
      (v2-assert "stale? timeout=0, slot=12 → t"
        (funcall tau :stale? 0)))

    ;; :slot>= — generic comparison
    (let ((tau (make-tau-state-v2 :slot 100)))
      (v2-assert "slot>= 50 → t"
        (funcall tau :slot>= 50))
      (v2-assert "slot>= 100 → t (equal)"
        (funcall tau :slot>= 100))
      (v2-assert "slot>= 101 → nil"
        (not (funcall tau :slot>= 101))))

    ;; :min-allowed-slot — R·max(0, ⌊slot/R⌋ − 1)
    ;; tiny: R = rotation-period
    (let* ((R (rotation-period))
           (tau-0 (make-tau-state-v2 :slot 0))
           (tau-r (make-tau-state-v2 :slot R))
           (tau-2r (make-tau-state-v2 :slot (* 2 R))))
      ;; slot=0: rotation=0, max(0,-1)=0, result=0
      (v2-assert "min-allowed-slot slot=0 → 0"
        (= (funcall tau-0 :min-allowed-slot) 0))
      ;; slot=R: rotation=1, max(0,0)=0, result=0
      (v2-assert "min-allowed-slot slot=R → 0"
        (= (funcall tau-r :min-allowed-slot) 0))
      ;; slot=2R: rotation=2, max(0,1)=1, result=R
      (v2-assert "min-allowed-slot slot=2R → R"
        (= (funcall tau-2r :min-allowed-slot) R)))

    ;; :lookup-fresh? — (11.26) slot − anchor ≤ L
    (let ((tau (make-tau-state-v2 :slot 20000)))
      ;; anchor=20000 → diff=0 ≤ L → fresh
      (v2-assert "lookup-fresh? same slot → t"
        (funcall tau :lookup-fresh? 20000))
      ;; anchor=19999 → diff=1 ≤ L → fresh
      (v2-assert "lookup-fresh? 1 slot ago → t"
        (funcall tau :lookup-fresh? 19999))
      ;; anchor=0 → diff=20000 > L=14400 → stale
      (v2-assert "lookup-fresh? anchor=0 → nil"
        (not (funcall tau :lookup-fresh? 0)))))

  ;; ── Summary ────────────────────────────────────────────────────
  (let ((total (+ *v2-tau-pass* *v2-tau-fail*)))
    (format t "~%  τ (v2): ~D/~D passed~%" *v2-tau-pass* total)
    (if (zerop *v2-tau-fail*)
        (format t "  ✅ All v2 tau tests passed!~%")
        (format t "  ❌ ~D failures~%" *v2-tau-fail*))))
