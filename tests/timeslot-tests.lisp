;;;; tests/timeslot-tests.lisp - Tests for timeslot

(in-package #:jotl-tests)

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: State Key Format
;;; ═══════════════════════════════════════════════════════════════

(defun test-state-key ()
  "Test that C11 generates correct 32-byte state key"
  
  (format t "~%Testing state key format...~%")
  
  ;; C11 = 11
  (assert (= jotl::+c11+ 11))
  (format t "  ✓ C11 = ~D~%" jotl::+c11+)
  
  ;; State key should be 31 bytes (verified from test vectors!)
  (let ((key (jotl::timeslot-state-key)))
    (assert (= (length key) 31))
    (format t "  ✓ State key length = 31 bytes~%")
    
    ;; First byte should be 0x0b (11 in hex)
    (assert (= (aref key 0) 11))
    (format t "  ✓ First byte = 0x~2,'0x (11 decimal)~%" (aref key 0))
    
    ;; Rest should be zeros
    (assert (every #'zerop (subseq key 1)))
    (format t "  ✓ Remaining 30 bytes = 0~%")
    
    ;; Display full key (should match test vectors)
    (format t "  Full key: 0x~{~2,'0x~}~%" 
            (coerce key 'list))
    (format t "  Expected: 0x0b000000000000000000000000000000000000000000000000000000000000~%")
    (format t "  Length:   64 hex chars (0x + 62 digits)~%~%"))
  
  (format t "✓ State key test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Euclidean Division (Gray Paper §6.2)
;;; ═══════════════════════════════════════════════════════════════

(defun test-euclidean-division ()
  "Test τ/E = e ℛ m for tiny chain (E=12)"
  
  (format t "~%Testing euclidean division (tiny chain, E=12)...~%")
  
  (jotl:with-chain :tiny
    ;; τ=0 : 0/12 = 0 ℛ 0
    (multiple-value-bind (e m) (jotl::timeslot-to-epoch-and-phase 0)
      (assert (and (= e 0) (= m 0)))
      (format t "  τ=0  : 0/12  = ~D ℛ ~D ✓~%" e m))
    
    ;; τ=11 : 11/12 = 0 ℛ 11
    (multiple-value-bind (e m) (jotl::timeslot-to-epoch-and-phase 11)
      (assert (and (= e 0) (= m 11)))
      (format t "  τ=11 : 11/12 = ~D ℛ ~D ✓~%" e m))
    
    ;; τ=12 : 12/12 = 1 ℛ 0
    (multiple-value-bind (e m) (jotl::timeslot-to-epoch-and-phase 12)
      (assert (and (= e 1) (= m 0)))
      (format t "  τ=12 : 12/12 = ~D ℛ ~D ✓~%" e m))
    
    ;; τ=25 : 25/12 = 2 ℛ 1
    (multiple-value-bind (e m) (jotl::timeslot-to-epoch-and-phase 25)
      (assert (and (= e 2) (= m 1)))
      (format t "  τ=25 : 25/12 = ~D ℛ ~D ✓~%" e m)))
  
  (format t "✓ Euclidean division test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Inverse Operation
;;; ═══════════════════════════════════════════════════════════════

(defun test-inverse-operation ()
  "Test (e, m) → τ for tiny chain"
  
  (format t "~%Testing inverse operation (e×E + m = τ)...~%")
  
  (jotl:with-chain :tiny
    ;; e=0, m=0 → τ=0
    (assert (= (jotl::epoch-phase-to-timeslot 0 0) 0))
    (format t "  e=0, m=0  → τ=~D ✓~%" (jotl::epoch-phase-to-timeslot 0 0))
    
    ;; e=0, m=11 → τ=11
    (assert (= (jotl::epoch-phase-to-timeslot 0 11) 11))
    (format t "  e=0, m=11 → τ=~D ✓~%" (jotl::epoch-phase-to-timeslot 0 11))
    
    ;; e=1, m=0 → τ=12
    (assert (= (jotl::epoch-phase-to-timeslot 1 0) 12))
    (format t "  e=1, m=0  → τ=~D ✓~%" (jotl::epoch-phase-to-timeslot 1 0))
    
    ;; e=2, m=1 → τ=25
    (assert (= (jotl::epoch-phase-to-timeslot 2 1) 25))
    (format t "  e=2, m=1  → τ=~D ✓~%" (jotl::epoch-phase-to-timeslot 2 1)))
  
  (format t "✓ Inverse operation test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Epoch Transition
;;; ═══════════════════════════════════════════════════════════════

(defun test-epoch-transition ()
  "Test new-epoch-p function"
  
  (format t "~%Testing epoch transitions (tiny chain, E=12)...~%")
  
  (jotl:with-chain :tiny
    ;; Within same epoch
    (assert (not (jotl::new-epoch-p 10 11)))
    (format t "  τ=10 → τ=11 : same epoch ✓~%")
    
    ;; Cross epoch boundary
    (assert (jotl::new-epoch-p 11 12))
    (format t "  τ=11 → τ=12 : NEW EPOCH ✓~%")
    
    ;; Another transition
    (assert (jotl::new-epoch-p 23 24))
    (format t "  τ=23 → τ=24 : NEW EPOCH ✓~%")
    
    ;; Large jump
    (assert (jotl::new-epoch-p 0 25))
    (format t "  τ=0  → τ=25 : NEW EPOCH ✓~%"))
  
  (format t "✓ Epoch transition test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Chain Switching
;;; ═══════════════════════════════════════════════════════════════

(defun test-chain-switching ()
  "Test behavior with different chains"
  
  (format t "~%Testing chain switching...~%")
  
  ;; Tiny chain (E=12)
  (jotl:with-chain :tiny
    (multiple-value-bind (e m) (jotl::timeslot-to-epoch-and-phase 25)
      (format t "  TINY: τ=25 → e=~D, m=~D (E=~D)~%" e m (jotl:epoch-duration))
      (assert (and (= e 2) (= m 1)))))
  
  ;; Full chain (E=600)
  (jotl:with-chain :full
    (multiple-value-bind (e m) (jotl::timeslot-to-epoch-and-phase 25)
      (format t "  FULL: τ=25 → e=~D, m=~D (E=~D)~%" e m (jotl:epoch-duration))
      (assert (and (= e 0) (= m 25)))))
  
  (format t "✓ Chain switching test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ALL TESTS
;;; ═══════════════════════════════════════════════════════════════

(defun run-all-timeslot-tests ()
  "Run all timeslot tests"
  
  (format t "~%╔═══════════════════════════════════════════════╗~%")
  (format t "║  TIMESLOT TESTS (Gray Paper §6.1-6.2)       ║~%")
  (format t "╚═══════════════════════════════════════════════╝~%")
  
  (test-state-key)
  (test-euclidean-division)
  (test-inverse-operation)
  (test-epoch-transition)
  (test-chain-switching)
  
  (format t "~%╔═══════════════════════════════════════════════╗~%")
  (format t "║  ALL TESTS PASSED ✓                          ║~%")
  (format t "╚═══════════════════════════════════════════════╝~%~%"))

;;; Pour lancer les tests :
;;; (asdf:load-system :jotl)
;;; (jotl-tests::run-all-timeslot-tests)
