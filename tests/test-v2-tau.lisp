;;;; tests/test-v2-tau.lisp — Validate tau-state (define-state-closure)
;;;;
;;;; Tests:
;;;;   1. Field access: :slot
;;;;   2. Memoized accessors: :epoch, :phase, :rotation, :min-allowed-slot
;;;;   3. Transition: :transition :header h  → τ' closure
;;;;   4. Codec: :encoded, :decode
;;;;   5. State-key: :state-key, :merkle-kv
;;;;   6. Sigma decoder registry
;;;;   7. Epoch boundary: :epoch-changed? message
;;;;   8. Transition chaining: τ → τ' → τ''
;;;;   9. Semantic queries: :stale?, :slot>=, :lookup-fresh?

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; TEST INFRASTRUCTURE
;;; ═════════════════════════════════════════════════════════════════

(defvar *tau-pass* 0)
(defvar *tau-fail* 0)

(defmacro tau-assert (name test-form)
  `(if ,test-form
       (progn (incf *tau-pass*)
              (format t "  ✅ ~A~%" ,name))
       (progn (incf *tau-fail*)
              (format t "  ❌ ~A~%" ,name))))

;;; ═════════════════════════════════════════════════════════════════
;;; TESTS
;;; ═════════════════════════════════════════════════════════════════

(defun run-tau-tests ()
  "Run all tau-state tests."
  (setf *tau-pass* 0 *tau-fail* 0)
  (format t "~%═══ τ tau-state tests ═══~%")

  (with-chain :tiny

    ;; ── 1. Field access ──────────────────────────────────────────
    (let ((tau (make-tau-state :slot 100)))
      (tau-assert "field :slot"
        (= (funcall tau :slot) 100))
      (tau-assert "field :type"
        (eq (funcall tau :type) :tau-state))
      (tau-assert "field :as-plist"
        (equal (funcall tau :as-plist) '(:slot 100))))

    ;; ── 2. Memoized accessors ────────────────────────────────────
    (let* ((E (epoch-duration))
           (R (rotation-period))
           (tau (make-tau-state :slot 100)))
      (tau-assert "memo :epoch"
        (= (funcall tau :epoch) (floor 100 E)))
      (tau-assert "memo :phase"
        (= (funcall tau :phase) (mod 100 E)))
      (tau-assert "memo :rotation"
        (= (funcall tau :rotation) (floor 100 R)))
      (tau-assert "memo :min-allowed-slot"
        (= (funcall tau :min-allowed-slot)
           (* R (max 0 (1- (floor 100 R))))))
      (tau-assert "memo :epoch idempotent"
        (= (funcall tau :epoch) (funcall tau :epoch)))
      (tau-assert "memo :min-allowed-slot idempotent"
        (= (funcall tau :min-allowed-slot) (funcall tau :min-allowed-slot))))

    ;; ── 3. Transition ────────────────────────────────────────────
    (let* ((tau (make-tau-state :slot 100))
           (header (lambda (msg) (case msg (:slot 200))))
           (tau-prime (funcall tau :transition :header header)))
      (tau-assert "transition returns closure"
        (functionp tau-prime))
      (tau-assert "transition :slot = HT"
        (= (funcall tau-prime :slot) 200))
      (tau-assert "transition :epoch computed"
        (= (funcall tau-prime :epoch) (floor 200 (epoch-duration))))
      (tau-assert "original tau unchanged"
        (= (funcall tau :slot) 100))
      (tau-assert "transition rejects τ' <= τ"
        (handler-case
            (progn
              (funcall tau :transition
                       :header (lambda (msg) (case msg (:slot 50))))
              nil)
          (error () t))))

    ;; ── 4. Codec ─────────────────────────────────────────────────
    (let* ((tau (make-tau-state :slot 12345))
           (encoded (funcall tau :encoded)))
      (tau-assert "encoded is byte vector"
        (typep encoded '(vector (unsigned-byte 8))))
      (tau-assert "encoded length = 4"
        (= (length encoded) 4))
      (multiple-value-bind (decoded consumed)
          (funcall tau :decode encoded 0)
        (tau-assert "decode returns closure"
          (functionp decoded))
        (tau-assert "decode consumed = 4"
          (= consumed 4))
        (tau-assert "decode roundtrip"
          (= (funcall decoded :slot) 12345)))
      ;; Decode via sigma registry
      (tau-assert "decoder registered"
        (not (null (gethash +C11+ *state-decoders*))))
      (multiple-value-bind (decoded consumed)
          (decode-state-segment +C11+ encoded 0)
        (tau-assert "registry decode roundtrip"
          (and (= consumed 4)
               (= (funcall decoded :slot) 12345)))))

    ;; ── 5. State-key / Merkle ────────────────────────────────────
    (let ((tau (make-tau-state :slot 42)))
      (tau-assert "state-key = C(11)"
        (equalp (funcall tau :state-key) +C11+))
      (let ((mkv (funcall tau :merkle-kv)))
        (tau-assert "merkle-kv is cons"
          (consp mkv))
        (tau-assert "merkle-kv car = state-key"
          (equalp (car mkv) +C11+))
        (tau-assert "merkle-kv cdr = encoded"
          (equalp (cdr mkv) (funcall tau :encoded)))))

    ;; ── 6. Deterministic values across slots ─────────────────────
    (dolist (val '(0 1 100 599 600 601 1199 1200 99999))
      (let* ((E (epoch-duration))
             (R (rotation-period))
             (tau (make-tau-state :slot val)))
        (tau-assert (format nil "slot=~D :epoch=⌊~D/~D⌋" val val E)
          (= (funcall tau :epoch) (floor val E)))
        (tau-assert (format nil "slot=~D :phase=~D mod ~D" val val E)
          (= (funcall tau :phase) (mod val E)))
        (tau-assert (format nil "slot=~D :rotation=⌊~D/~D⌋" val val R)
          (= (funcall tau :rotation) (floor val R)))))

    ;; ── 7. Epoch boundary (:epoch-changed?) ──────────────────────
    (let ((E (epoch-duration)))
      (tau-assert "epoch-changed? same epoch → nil"
        (not (funcall (make-tau-state :slot 0)
                      :epoch-changed?
                      (make-tau-state :slot 1))))
      (tau-assert "epoch-changed? cross → t"
        (funcall (make-tau-state :slot (1- E))
                 :epoch-changed?
                 (make-tau-state :slot E)))
      (tau-assert "epoch-changed? same slot → nil"
        (not (funcall (make-tau-state :slot 100)
                      :epoch-changed?
                      (make-tau-state :slot 100)))))

    ;; ── 8. Transition chaining ───────────────────────────────────
    (let* ((tau (make-tau-state :slot 100))
           (h1 (lambda (msg) (case msg (:slot 200))))
           (tau-prime (funcall tau :transition :header h1))
           (h2 (lambda (msg) (case msg (:slot 300))))
           (tau-double-prime (funcall tau-prime :transition :header h2)))
      (tau-assert "chain: τ=100"
        (= (funcall tau :slot) 100))
      (tau-assert "chain: τ'=200"
        (= (funcall tau-prime :slot) 200))
      (tau-assert "chain: τ''=300"
        (= (funcall tau-double-prime :slot) 300)))

    ;; ── 9. Semantic queries for ρ ────────────────────────────────

    ;; :stale? — (11.17) τ' ≥ timeout + U
    (let ((tau (make-tau-state :slot 12)))
      (tau-assert "stale? timeout=7, slot=12 → t"
        (funcall tau :stale? 7))
      (tau-assert "stale? timeout=11, slot=12 → nil"
        (not (funcall tau :stale? 11)))
      (tau-assert "stale? timeout=0, slot=12 → t"
        (funcall tau :stale? 0)))

    ;; :slot>=
    (let ((tau (make-tau-state :slot 100)))
      (tau-assert "slot>= 50 → t"
        (funcall tau :slot>= 50))
      (tau-assert "slot>= 100 → t (equal)"
        (funcall tau :slot>= 100))
      (tau-assert "slot>= 101 → nil"
        (not (funcall tau :slot>= 101))))

    ;; :min-allowed-slot — R·max(0, ⌊slot/R⌋ − 1)
    (let* ((R (rotation-period))
           (tau-0 (make-tau-state :slot 0))
           (tau-r (make-tau-state :slot R))
           (tau-2r (make-tau-state :slot (* 2 R))))
      (tau-assert "min-allowed-slot slot=0 → 0"
        (= (funcall tau-0 :min-allowed-slot) 0))
      (tau-assert "min-allowed-slot slot=R → 0"
        (= (funcall tau-r :min-allowed-slot) 0))
      (tau-assert "min-allowed-slot slot=2R → R"
        (= (funcall tau-2r :min-allowed-slot) R)))

    ;; :lookup-fresh? — (11.26) slot − anchor ≤ L
    (let ((tau (make-tau-state :slot 20000)))
      (tau-assert "lookup-fresh? same slot → t"
        (funcall tau :lookup-fresh? 20000))
      (tau-assert "lookup-fresh? 1 slot ago → t"
        (funcall tau :lookup-fresh? 19999))
      (tau-assert "lookup-fresh? anchor=0 → nil"
        (not (funcall tau :lookup-fresh? 0)))))

  ;; ── Summary ────────────────────────────────────────────────────
  (let ((total (+ *tau-pass* *tau-fail*)))
    (format t "~%  τ: ~D/~D passed~%" *tau-pass* total)
    (if (zerop *tau-fail*)
        (format t "  ✅ All tau tests passed!~%")
        (format t "  ❌ ~D failures~%" *tau-fail*))))
