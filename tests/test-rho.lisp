;;;; test-rho.lisp — Quick validation of rho-state closure
(in-package #:jotl)

(format t "~&═══ Testing rho-state ═══~%")

;;; ── Basic creation and field access ──
(let ((rho (make-rho-state)))
  (assert (eq (funcall rho :type) :rho-state))
  (format t "~&✓ :type = :rho-state~%")
  
  (assert (= (aref (funcall rho :state-key) 0) 10))
  (format t "✓ :state-key = C(10)~%")
  
  (assert (= (funcall rho :core-count) 0))
  (format t "✓ :core-count = 0 (empty)~%")
  
  (assert (null (funcall rho :assignments)))
  (format t "✓ :assignments = nil~%")
  
  (assert (zerop (length (funcall rho :encoded))))
  (format t "✓ :encoded = empty (0 assignments)~%")

  ;; ── With assignments ──
  (let* ((a1 nil)  ;; empty core
         (a2 nil)  ;; empty core
         (rho2 (make-rho-state :assignments (list a1 a2))))
    (assert (= (funcall rho2 :core-count) 2))
    (format t "✓ 2 nil assignments, core-count = 2~%")
    
    ;; Encoded: 2 × [0x00] = 2 bytes
    (let ((enc (funcall rho2 :encoded)))
      (assert (= (length enc) 2))
      (assert (= (aref enc 0) 0))
      (assert (= (aref enc 1) 0))
      (format t "✓ encoded: 2 bytes [0x00, 0x00]~%")
      
      ;; Roundtrip decode
      (multiple-value-bind (decoded consumed)
          (funcall (make-rho-state) :decode enc 0)
        (assert (= consumed 2))
        (assert (= (funcall decoded :core-count) 2))
        (assert (null (first (funcall decoded :assignments))))
        (assert (null (second (funcall decoded :assignments))))
        (format t "✓ decode roundtrip: 2 nil assignments~%"))))

  ;; ── Wave 1: transition-dagger with no v-list ──
  (let ((rho-dag (funcall rho :transition-dagger :v-list nil)))
    (assert (eq rho-dag rho))
    (format t "✓ transition-dagger (no v-list) = self~%"))
  
  ;; ── Wave 2: transition-ddagger with no assurances ──
  (let ((tau (make-tau-state :slot 10))
        (kappa (make-kappa-state :validators nil)))
    (multiple-value-bind (rho-ddag r-star)
        (funcall rho :transition-ddagger
                 :assurances nil
                 :tau-prime tau
                 :parent-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                 :kappa kappa)
      ;; With 0 assignments and 0 assurances → nothing changes
      (assert (eq (funcall rho-ddag :type) :rho-state))
      (assert (null r-star))
      (format t "✓ transition-ddagger (no assurances) → ρ‡ + nil R*~%")))
  
  ;; ── Wave 3: transition with no guarantees ──
  (let ((tau (make-tau-state :slot 10))
        (kappa (make-kappa-state :validators nil))
        (lam (make-lambda-state :validators nil))
        (eta (make-eta-state)))
    (let ((rho-prime (funcall rho :transition
                              :guarantees nil
                              :tau-prime tau
                              :kappa kappa
                              :lambda-prev lam
                              :eta eta
                              :offenders nil
                              :recent-blocks nil
                              :auth-pools nil
                              :accounts nil)))
      (assert (eq rho-prime rho))
      (format t "✓ transition (no guarantees) = self~%"))))

(format t "~&═══ All rho-state tests passed ═══~%")
