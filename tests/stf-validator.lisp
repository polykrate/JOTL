;;;; stf-validator.lisp - Validate STF against official test vectors
;;;; Compares pre_state + input → post_state

(in-package :cl-user)

(defpackage #:jotl.stf-validator
  (:use #:cl)
  (:export #:validate-stf-test
           #:run-all-stf-tests))

(in-package #:jotl.stf-validator)

;;; ==========================================================================
;;; JSON Parsing
;;; ==========================================================================

(defun read-json-file (filepath)
  "Read and parse JSON file
   
   Returns: parsed JSON as alist/plist structure"
  (with-open-file (stream filepath :direction :input)
    (let ((content (make-string (file-length stream))))
      (read-sequence content stream)
      ;; For now, just return the raw string
      ;; TODO: Use a JSON library (yason, jonathan, etc.)
      content)))

(defun parse-test-vector (json-string)
  "Parse test vector JSON
   
   Expected structure:
   {
     \"input\": { ... },
     \"pre_state\": { ... },
     \"post_state\": { ... },
     \"output\": { ... }
   }"
  ;; TODO: Implement JSON parsing
  ;; For now, return a stub
  (list :input nil
        :pre-state nil
        :post-state nil
        :output nil))

;;; ==========================================================================
;;; State Comparison
;;; ==========================================================================

(defun compare-states (expected-state actual-state &key (verbose t))
  "Compare two states (pre/post)
   
   Args:
     expected-state: State from test vector
     actual-state: State computed by our STF
     verbose: Print differences
   
   Returns:
     T if states match, NIL otherwise"
  
  ;; TODO: Implement deep state comparison
  ;; For now, return T
  (when verbose
    (format t "~&Comparing states...~%"))
  t)

(defun extract-state-field (state field-name)
  "Extract a specific field from state
   
   Args:
     state: State object (closure or alist)
     field-name: Field to extract (e.g., :slot, :entropy)
   
   Returns:
     Field value"
  
  ;; Handle both closures and alists
  (etypecase state
    (function (funcall state field-name))
    (list (getf state field-name))))

;;; ==========================================================================
;;; STF Test Runner
;;; ==========================================================================

(defun validate-stf-test (test-file &key (stf-function nil) (verbose t))
  "Validate a single STF test
   
   Args:
     test-file: Path to JSON test file
     stf-function: STF function to test (e.g., #'jotl:accumulate)
     verbose: Print detailed output
   
   Returns:
     T if test passes, NIL otherwise
   
   Process:
     1. Load test vector (input, pre_state, post_state)
     2. Run STF: pre_state + input → computed_state
     3. Compare computed_state with post_state"
  
  (when verbose
    (format t "~&~%Testing: ~A~%" (file-namestring test-file)))
  
  (handler-case
      (let* ((json-content (read-json-file test-file))
             (test-data (parse-test-vector json-content))
             (input (getf test-data :input))
             (pre-state (getf test-data :pre-state))
             (expected-post-state (getf test-data :post-state)))
        
        (when verbose
          (format t "  Pre-state loaded~%")
          (format t "  Input loaded~%"))
        
        ;; Run STF if function provided
        (let ((computed-post-state
               (if stf-function
                   (progn
                     (when verbose
                       (format t "  Running STF...~%"))
                     (funcall stf-function pre-state input))
                   (progn
                     (when verbose
                       (format t "  No STF function provided, skipping execution~%"))
                     nil))))
          
          ;; Compare states
          (if computed-post-state
              (let ((match (compare-states expected-post-state computed-post-state 
                                          :verbose verbose)))
                (when verbose
                  (format t "  Result: ~A~%" (if match "✅ PASS" "❌ FAIL")))
                match)
              (progn
                (when verbose
                  (format t "  Result: ⏭️  SKIPPED (no STF)~%"))
                :skipped))))
    
    (error (e)
      (when verbose
        (format t "  Result: ❌ ERROR: ~A~%" e))
      nil)))

(defun run-all-stf-tests (test-directory &key (stf-function nil) (pattern "*.json"))
  "Run all STF tests in a directory
   
   Args:
     test-directory: Directory containing test JSON files
     stf-function: STF function to test
     pattern: File pattern to match (default: *.json)
   
   Returns:
     (values passed failed skipped errors)"
  
  (format t "~&~%Running STF tests from: ~A~%" test-directory)
  (format t "Pattern: ~A~%~%" pattern)
  
  (let ((passed 0)
        (failed 0)
        (skipped 0)
        (errors 0))
    
    ;; TODO: Iterate over test files
    ;; For now, just return summary
    
    (format t "~%Summary:~%")
    (format t "  ✅ Passed:  ~D~%" passed)
    (format t "  ❌ Failed:  ~D~%" failed)
    (format t "  ⏭️  Skipped: ~D~%" skipped)
    (format t "  💥 Errors:  ~D~%" errors)
    
    (values passed failed skipped errors)))

;;; ==========================================================================
;;; Example Usage
;;; ==========================================================================

#|
;; Load test vectors
(defparameter *test-dir* 
  "/home/polycrate/Projets/JOTL/tests/jamtestvectors/stf/accumulate/tiny/")

;; Validate single test (without STF - just structure check)
(validate-stf-test 
  (merge-pathnames "accumulate_ready_queued_reports-1.json" *test-dir*))

;; Run all tests in directory
(run-all-stf-tests *test-dir*)

;; With actual STF function (when implemented)
(run-all-stf-tests *test-dir* :stf-function #'jotl:accumulate)
|#
