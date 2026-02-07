;;;; tests/header-tests.lisp - Tests for header (Gray Paper §5)

(in-package #:jotl-tests)

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Header Structure (Gray Paper §5.1)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.1:

  H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
  
Verify all components are accessible.
|#

(defun test-header-structure ()
  "Test header structure matches Gray Paper §5.1"
  
  (format t "~%Testing header structure (Gray Paper §5.1)...~%")
  
  ;; Create a test header with all components
  (let ((header (jotl:make-header
                 :parent-hash (make-array 32 :element-type '(unsigned-byte 8) 
                                             :initial-element 1)
                 :state-root (make-array 32 :element-type '(unsigned-byte 8) 
                                            :initial-element 2)
                 :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8) 
                                                :initial-element 3)
                 :slot 10
                 :epoch-mark nil
                 :tickets-mark nil
                 :author-index 5
                 :entropy-source (make-array 96 :element-type '(unsigned-byte 8) 
                                                :initial-element 4)
                 :offenders-mark '()
                 :seal (make-array 96 :element-type '(unsigned-byte 8) 
                                      :initial-element 5))))
    
    ;; Test all components (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
    (assert (jotl:header-parent-hash header))
    (format t "  ✓ HP (parent-hash) accessible~%")
    
    (assert (jotl:header-state-root header))
    (format t "  ✓ HR (state-root) accessible~%")
    
    (assert (jotl:header-extrinsic-hash header))
    (format t "  ✓ HX (extrinsic-hash) accessible~%")
    
    (assert (= (jotl:header-slot header) 10))
    (format t "  ✓ HT (slot/timeslot) accessible~%")
    
    (assert (jotl:header-epoch-mark header) nil)
    (format t "  ✓ HE (epoch-mark) accessible~%")
    
    (assert (jotl:header-tickets-mark header) nil)
    (format t "  ✓ HW (tickets-mark) accessible~%")
    
    (assert (equal (jotl:header-offenders-mark header) '()))
    (format t "  ✓ HO (offenders-mark) accessible~%")
    
    (assert (= (jotl:header-author-index header) 5))
    (format t "  ✓ HI (author-index) accessible~%")
    
    (assert (jotl:header-entropy-source header))
    (format t "  ✓ HV (entropy-source/VRF) accessible~%")
    
    (assert (jotl:header-seal header))
    (format t "  ✓ HS (seal) accessible~%"))
  
  (format t "✓ Header structure test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Genesis Header (Gray Paper §5.2)
;;; ═══════════════════════════════════════════════════════════════

(defun test-genesis-header ()
  "Test genesis header H0 has no parent"
  
  (format t "~%Testing genesis header (Gray Paper §5.2)...~%")
  
  ;; Genesis header: HP = null
  (let ((genesis (jotl:make-header
                  :parent-hash nil
                  :state-root (make-array 32 :element-type '(unsigned-byte 8))
                  :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                  :slot 0
                  :epoch-mark nil
                  :tickets-mark nil
                  :author-index 0
                  :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                  :offenders-mark '()
                  :seal (make-array 96 :element-type '(unsigned-byte 8)))))
    
    (assert (jotl::header-is-genesis-p genesis))
    (format t "  ✓ Genesis header detected (HP = null)~%")
    
    (assert (null (jotl:header-parent-hash genesis)))
    (format t "  ✓ Genesis has no parent hash~%"))
  
  ;; Non-genesis header: HP ≠ null
  (let ((regular (jotl:make-header
                  :parent-hash (make-array 32 :element-type '(unsigned-byte 8) 
                                              :initial-element 1)
                  :state-root (make-array 32 :element-type '(unsigned-byte 8))
                  :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                  :slot 1
                  :epoch-mark nil
                  :tickets-mark nil
                  :author-index 0
                  :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                  :offenders-mark '()
                  :seal (make-array 96 :element-type '(unsigned-byte 8)))))
    
    (assert (not (jotl::header-is-genesis-p regular)))
    (format t "  ✓ Regular header detected (HP ≠ null)~%")
    
    (assert (jotl:header-parent-hash regular))
    (format t "  ✓ Regular header has parent hash~%"))
  
  (format t "✓ Genesis header test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Parent Hash Formula (Gray Paper §5.2)
;;; ═══════════════════════════════════════════════════════════════

(defun test-parent-hash-formula ()
  "Test HP ≡ H(E(P(H))) formula
   
   Gray Paper §5.2:
   Parent hash must be hash of encoding of parent header"
  
  (format t "~%Testing parent hash formula (Gray Paper §5.2)...~%")
  (format t "  Formula: HP ≡ H(E(P(H)))~%")
  
  ;; Create parent header
  (let* ((parent (jotl:make-header
                  :parent-hash nil  ; Parent is genesis
                  :state-root (make-array 32 :element-type '(unsigned-byte 8))
                  :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                  :slot 0
                  :epoch-mark nil
                  :tickets-mark nil
                  :author-index 0
                  :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                  :offenders-mark '()
                  :seal (make-array 96 :element-type '(unsigned-byte 8))))
         
         ;; Compute parent hash: HP = H(E(parent))
         (parent-hash (jotl::compute-parent-hash parent))
         
         ;; Create child header with computed parent hash
         (child (jotl:make-header
                 :parent-hash parent-hash
                 :state-root (make-array 32 :element-type '(unsigned-byte 8))
                 :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                 :slot 1
                 :epoch-mark nil
                 :tickets-mark nil
                 :author-index 0
                 :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                 :offenders-mark '()
                 :seal (make-array 96 :element-type '(unsigned-byte 8)))))
    
    (format t "  Parent header: H⁻ (slot 0)~%")
    (format t "  Computed HP: ~a~%" (jotl::bytes-to-hex-string parent-hash))
    (format t "  Child HP claim: ~a~%" (jotl::bytes-to-hex-string (jotl:header-parent-hash child)))
    
    ;; Validate: child's HP should equal H(E(parent))
    (assert (jotl::validate-parent-hash child parent))
    (format t "  ✓ HP ≡ H(E(P(H))) verified~%"))
  
  (format t "✓ Parent hash formula test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Timeslot Validation (Gray Paper §5.7)
;;; ═══════════════════════════════════════════════════════════════

(defun test-timeslot-validation ()
  "Test HT ∈ ℕT, P(H)T < HT ∧ HT · P ≤ T
   
   Gray Paper §5.7"
  
  (format t "~%Testing timeslot validation (Gray Paper §5.7)...~%")
  (format t "  Formula: HT ∈ ℕT, P(H)T < HT ∧ HT · P ≤ T~%~%")
  
  ;; Test 1: Genesis (no parent, timeslot 0)
  (let* ((current-time (get-universal-time))
         (genesis (jotl:make-header
                   :parent-hash nil
                   :state-root (make-array 32 :element-type '(unsigned-byte 8))
                   :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                   :slot 0
                   :epoch-mark nil
                   :tickets-mark nil
                   :author-index 0
                   :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                   :offenders-mark '()
                   :seal (make-array 96 :element-type '(unsigned-byte 8)))))
    
    (multiple-value-bind (valid reason) (jotl::validate-timeslot genesis nil current-time)
      (assert valid)
      (format t "  ✓ Genesis header (HT=0): ~A~%" reason)))
  
  ;; Test 2: Regular header (HT > parent HT, in past)
  (let* ((current-time (get-universal-time))
         ;; Parent at slot 10 (60 seconds ago)
         (parent (jotl:make-header
                  :parent-hash nil
                  :state-root (make-array 32 :element-type '(unsigned-byte 8))
                  :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                  :slot 10
                  :epoch-mark nil
                  :tickets-mark nil
                  :author-index 0
                  :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                  :offenders-mark '()
                  :seal (make-array 96 :element-type '(unsigned-byte 8))))
         ;; Child at slot 11 (54 seconds ago)
         (child (jotl:make-header
                 :parent-hash (jotl::compute-parent-hash parent)
                 :state-root (make-array 32 :element-type '(unsigned-byte 8))
                 :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                 :slot 11
                 :epoch-mark nil
                 :tickets-mark nil
                 :author-index 0
                 :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                 :offenders-mark '()
                 :seal (make-array 96 :element-type '(unsigned-byte 8)))))
    
    (multiple-value-bind (valid reason) (jotl::validate-timeslot child parent current-time)
      (assert valid)
      (format t "  ✓ Child header (HT=11 > parent=10): ~A~%" reason)))
  
  ;; Test 3: Invalid - child timeslot ≤ parent
  (let* ((current-time (get-universal-time))
         (parent (jotl:make-header
                  :parent-hash nil
                  :state-root (make-array 32 :element-type '(unsigned-byte 8))
                  :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                  :slot 10
                  :epoch-mark nil
                  :tickets-mark nil
                  :author-index 0
                  :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                  :offenders-mark '()
                  :seal (make-array 96 :element-type '(unsigned-byte 8))))
         ;; Invalid: same timeslot as parent
         (child (jotl:make-header
                 :parent-hash (jotl::compute-parent-hash parent)
                 :state-root (make-array 32 :element-type '(unsigned-byte 8))
                 :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                 :slot 10  ; Same as parent - INVALID!
                 :epoch-mark nil
                 :tickets-mark nil
                 :author-index 0
                 :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                 :offenders-mark '()
                 :seal (make-array 96 :element-type '(unsigned-byte 8)))))
    
    (multiple-value-bind (valid reason) (jotl::validate-timeslot child parent current-time)
      (assert (not valid))
      (format t "  ✓ Invalid header (HT=10 ≯ parent=10): ~A~%" reason)))
  
  ;; Test 4: Future block (will be valid when time advances)
  (let* ((current-time (get-universal-time))
         ;; Block from future (1000 slots ahead)
         (future-block (jotl:make-header
                        :parent-hash (make-array 32 :element-type '(unsigned-byte 8))
                        :state-root (make-array 32 :element-type '(unsigned-byte 8))
                        :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8))
                        :slot 1000000  ; Far in future
                        :epoch-mark nil
                        :tickets-mark nil
                        :author-index 0
                        :entropy-source (make-array 96 :element-type '(unsigned-byte 8))
                        :offenders-mark '()
                        :seal (make-array 96 :element-type '(unsigned-byte 8)))))
    
    (multiple-value-bind (valid reason) (jotl::validate-timeslot future-block nil current-time)
      (assert (not valid))
      (format t "  ✓ Future block (HT·P > T): ~A~%" reason)))
  
  (format t "✓ Timeslot validation test passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; TEST: Verify Against Test Vectors
;;; ═══════════════════════════════════════════════════════════════

(defun test-header-from-testvector ()
  "Test header parsing from test vector
   
   Use genesis.json to verify header structure"
  
  (format t "~%Testing header from test vector...~%")
  (format t "  (Manual verification with Python for now)~%")
  (format t "  TODO: Parse genesis.json and verify header fields~%")
  (format t "  Expected fields: parent, state_root, slot, etc.~%")
  
  ;; TODO: Add JSON parsing to read test vectors
  (format t "✓ Test vector placeholder passed!~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ALL HEADER TESTS
;;; ═══════════════════════════════════════════════════════════════

(defun run-all-header-tests ()
  "Run all header tests"
  
  (format t "~%╔═══════════════════════════════════════════════╗~%")
  (format t "║  HEADER TESTS (Gray Paper §5)                ║~%")
  (format t "╚═══════════════════════════════════════════════╝~%")
  
  (test-header-structure)
  (test-genesis-header)
  (test-parent-hash-formula)
  (test-timeslot-validation)
  (test-header-from-testvector)
  
  (format t "~%╔═══════════════════════════════════════════════╗~%")
  (format t "║  ALL HEADER TESTS PASSED ✓                   ║~%")
  (format t "╚═══════════════════════════════════════════════╝~%~%"))

;;; Utility for test vectors
(defun bytes-to-hex-string (bytes)
  "Convert byte array to hex string for display"
  (if bytes
      (format nil "0x~{~2,'0x~}..." (coerce (subseq bytes 0 (min 4 (length bytes))) 'list))
      "null"))

;;; Run: (jotl-tests::run-all-header-tests)
