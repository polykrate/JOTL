;;;; block/validation.lisp — Structural Block Validation
;;;; Gray Paper §5 — Checks that NO individual STF owns
;;;;
;;;; Called by apply-block (Υ) BEFORE transition-state(σ, B).
;;;; All inputs are closures — no plist dispatch.

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; EXTRINSIC HASH (GP §5.4-5.6)
;;; ═════════════════════════════════════════════════════════════════

(defun validate-extrinsic-hash (header extrinsic)
  "Structural: HX ≡ H(E(H#(a))).
   No STF owns this — it's a commitment to extrinsic data.
   
   Args: header (closure), extrinsic (closure)
   Returns: (values valid-p computed-hx)"
  (let ((header-hx (funcall header :extrinsic-hash))
        (computed-hx (funcall extrinsic :extrinsic-hash)))
    (values (equalp header-hx computed-hx) computed-hx)))

;;; ═════════════════════════════════════════════════════════════════
;;; TIMESLOT NOT IN FUTURE (GP §5.7 clause 2)
;;; ═════════════════════════════════════════════════════════════════

(defun validate-timeslot-not-future (header current-time)
  "Structural: HT · P ≤ T.
   No STF owns wall-clock checks. The τ STF owns τ < τ'.
   
   Args: header (closure), current-time (UNIX timestamp)
   Returns: (values valid-p message)"
  (let* ((ht (funcall header :slot))
         (block-time (* ht (slot-duration))))
    (if (<= block-time current-time)
        (values t (format nil "HT=~D ok" ht))
        (values nil (format nil "HT=~D in future (time ~D > ~D)"
                            ht block-time current-time)))))

;;; ═════════════════════════════════════════════════════════════════
;;; PARENT HASH (GP §5.2)
;;; ═════════════════════════════════════════════════════════════════

(defun validate-parent-hash (header parent-header-encoded)
  "Structural: HP ≡ H(E(P(H))).
   No STF owns this — chain integrity check.
   
   Args: header (closure), parent-header-encoded (byte array)
   Returns: (values valid-p computed-hash)"
  (let ((hp (funcall header :parent-hash))
        (computed (blake2b-256 parent-header-encoded)))
    (values (equalp hp computed) computed)))

;;; ═════════════════════════════════════════════════════════════════
;;; validate-block — all structural checks
;;; ═════════════════════════════════════════════════════════════════

(defun validate-block (sigma block &key current-time parent-header-encoded)
  "Validate block B structurally before Υ(σ, B).
   
   All args are closures. No plist dispatch.
   
   Checks:
     1. HX matches extrinsic data        (§5.4-5.6)
     2. HT not in future                 (§5.7 clause 2)
     3. HP matches parent header hash    (§5.2)
   
   Returns: (values valid-p errors)"
  (declare (ignore sigma))
  (let ((h (funcall block :header))
        (e (funcall block :extrinsic))
        (errors '()))
    
    ;; §5.4-5.6: HX
    (multiple-value-bind (ok computed) (validate-extrinsic-hash h e)
      (declare (ignore computed))
      (unless ok (push (list :hx "HX mismatch") errors)))
    
    ;; §5.7 clause 2: HT · P ≤ T
    (when current-time
      (multiple-value-bind (ok msg) (validate-timeslot-not-future h current-time)
        (declare (ignore msg))
        (unless ok (push (list :ht-future
                               (format nil "HT=~D in future"
                                       (funcall h :slot))) errors))))
    
    ;; §5.2: HP
    (when parent-header-encoded
      (multiple-value-bind (ok computed) (validate-parent-hash h parent-header-encoded)
        (declare (ignore computed))
        (unless ok (push (list :hp "HP mismatch") errors))))
    
    (values (null errors) (nreverse errors))))

;;; Exports managed in package.lisp
