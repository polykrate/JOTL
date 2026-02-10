;;;; bloc/validation.lisp — Block Validation
;;;; Gray Paper §5
;;;;
;;;; Two layers:
;;;;   validate-block(B)  — intrinsic checks (HX). Called by Υ.
;;;;   validate-block-env — environmental checks (wall-clock, parent hash).
;;;;                        Called by import-block (node layer).

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; INTRINSIC VALIDATION — called by Υ (apply-block)
;;; ═════════════════════════════════════════════════════════════════

(defun validate-extrinsic-hash (header block)
  "HX ≡ H(H#(ET) ⌢ H#(EP) ⌢ H#(EG) ⌢ H#(EA) ⌢ H#(ED)) — §5.4-5.6.
   Intrinsic to the block. No external context needed.
   
   Args: header (closure), block (closure — holds raw extrinsic data)
   Returns: (values valid-p computed-hx)"
  (let ((header-hx (funcall header :extrinsic-hash))
        (computed-hx (funcall block :extrinsic-hash)))
    (values (equalp header-hx computed-hx) computed-hx)))

(defun validate-block (block)
  "Intrinsic block validation — called by Υ(σ, B).
   Checks only what can be verified from B alone (no σ, no env).
   
   Checks:
     1. HX matches extrinsic data  (§5.4-5.6)
   
   Returns: (values valid-p errors)"
  (let ((h (funcall block :header))
        (errors '()))
    ;; §5.4-5.6: HX — block knows HX directly (no extrinsic closure)
    (multiple-value-bind (ok computed) (validate-extrinsic-hash h block)
      (declare (ignore computed))
      (unless ok (push (list :hx "HX mismatch") errors)))
    (values (null errors) (nreverse errors))))

;;; ═════════════════════════════════════════════════════════════════
;;; POST-TRANSITION VALIDATION — called by transition-state
;;; ═════════════════════════════════════════════════════════════════
;;; Checks that require results from the full state transition.

(defun compute-offenders-mark (culprits faults)
  "(10.20) HO = [f | (f,...) ∈ EC] ~ [f | (f,...) ∈ EF]
   The offenders marker in the header is the culprit keys
   concatenated with the fault keys, preserving their order
   (both already sorted by f per (10.8)).
   Returns: list of Ed25519 keys (ordered: culprits then faults)."
  (append (mapcar (lambda (c) (getf c :key)) culprits)
          (mapcar (lambda (f) (getf f :key)) faults)))

(defun validate-header-post-transition (header disputes)
  "Validate header fields that depend on post-transition state.
   Called from transition-state after all sub-STFs have run.

   Checks:
     HO — offenders mark must match ED-derived offenders

   Args: header (closure), disputes (ED plist :verdicts :culprits :faults)
   Signals error on mismatch."
  ;; ── HO: offenders mark ──
  (let* ((culprits       (getf disputes :culprits))
         (faults         (getf disputes :faults))
         (expected-ho    (compute-offenders-mark culprits faults))
         (actual-ho      (funcall header :offenders-mark)))
    ;; Both should be lists of Ed25519 keys (or nil)
    (unless (and (= (length actual-ho) (length expected-ho))
                 (every #'equalp actual-ho expected-ho))
      (error "HO mismatch: expected ~D offenders, got ~D"
             (length expected-ho) (length actual-ho)))))

;;; ═════════════════════════════════════════════════════════════════
;;; ENVIRONMENTAL VALIDATION — called by import-block (node layer)
;;; ═════════════════════════════════════════════════════════════════
;;; These need external context (wall-clock, parent header bytes).
;;; They do NOT belong in Υ.

(defun validate-timeslot-not-future (header current-time)
  "HT · P ≤ T — §5.7 clause 2.
   Environmental: requires wall-clock time.
   
   Args: header (closure), current-time (UNIX timestamp)
   Returns: (values valid-p message)"
  (let* ((ht (funcall header :slot))
         (block-time (* ht (slot-duration))))
    (if (<= block-time current-time)
        (values t (format nil "HT=~D ok" ht))
        (values nil (format nil "HT=~D in future (time ~D > ~D)"
                            ht block-time current-time)))))

(defun validate-parent-hash (header parent-header-encoded)
  "HP ≡ H(E(P(H))) — §5.2.
   Environmental: requires parent header bytes from state store.
   
   Args: header (closure), parent-header-encoded (byte array)
   Returns: (values valid-p computed-hash)"
  (let ((hp (funcall header :parent-hash))
        (computed (blake2b-256 parent-header-encoded)))
    (values (equalp hp computed) computed)))

;;; Exports managed in package.lisp
