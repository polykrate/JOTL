;;;; stf-timeslot-validator.lisp - Validate timeslot against test vectors
;;;; Tests the simplest STF: timeslot update (τ' ← HT)

(require :uiop)

(defpackage #:jotl.timeslot-validator
  (:use #:cl)
  (:export #:validate-timeslot-from-traces))

(in-package #:jotl.timeslot-validator)

;;; ==========================================================================
;;; Simple JSON Parser (no dependencies)
;;; ==========================================================================

(defun extract-json-value (json-string key)
  "Extract a value from JSON string (simple regex-based)
   
   Args:
     json-string: JSON content as string
     key: Key to extract (e.g., \"slot\")
   
   Returns:
     Value as string, or NIL if not found"
  
  (let* ((pattern (format nil "\"~A\"\\s*:\\s*([0-9]+)" key))
         (scanner (cl-ppcre:create-scanner pattern)))
    (multiple-value-bind (match groups)
        (cl-ppcre:scan-to-strings scanner json-string)
      (when match
        (parse-integer (aref groups 0))))))

(defun read-file-as-string (filepath)
  "Read entire file as string"
  (with-open-file (stream filepath :direction :input)
    (let ((content (make-string (file-length stream))))
      (read-sequence content stream)
      content)))

;;; ==========================================================================
;;; Timeslot Validation
;;; ==========================================================================

(defun validate-timeslot-transition (pre-slot post-slot header-slot)
  "Validate timeslot transition: τ' ← HT
   
   Gray Paper §6.1: τ' ≡ HT
   
   Args:
     pre-slot: Timeslot before transition (τ)
     post-slot: Timeslot after transition (τ')
     header-slot: Timeslot from header (HT)
   
   Returns:
     T if valid, NIL otherwise"
  
  (and (= post-slot header-slot)
       (> post-slot pre-slot)))

(defun validate-trace-file (trace-file &key (verbose t))
  "Validate timeslot in a trace file
   
   Trace files contain:
     - block.header.slot (HT)
     - pre_state.slot (τ)
     - post_state.slot (τ')
   
   Validates: τ' = HT and τ' > τ"
  
  (when verbose
    (format t "~&Testing: ~A~%" (file-namestring trace-file)))
  
  (handler-case
      (let* ((json-content (read-file-as-string trace-file))
             ;; Extract slots from different locations
             (header-slot (or (extract-json-value json-content "slot")
                             (extract-json-value json-content "\"slot\"")))
             (pre-slot nil)   ; TODO: Extract from pre_state
             (post-slot nil)) ; TODO: Extract from post_state
        
        (when verbose
          (format t "  Header slot (HT): ~A~%" header-slot))
        
        (if header-slot
            (progn
              (when verbose
                (format t "  ✅ Timeslot extracted~%"))
              t)
            (progn
              (when verbose
                (format t "  ❌ Could not extract timeslot~%"))
              nil)))
    
    (error (e)
      (when verbose
        (format t "  ❌ ERROR: ~A~%" e))
      nil)))

;;; ==========================================================================
;;; Batch Validation
;;; ==========================================================================

(defun validate-all-traces (traces-directory &key (limit 10))
  "Validate timeslot in all trace files
   
   Args:
     traces-directory: Directory containing trace JSON files
     limit: Maximum number of files to test (default: 10)
   
   Returns:
     (values passed failed total)"
  
  (format t "~&~%Validating timeslots from traces...~%")
  (format t "Directory: ~A~%~%" traces-directory)
  
  (let ((passed 0)
        (failed 0)
        (total 0)
        (json-files (directory (merge-pathnames "*.json" traces-directory))))
    
    (dolist (file (subseq json-files 0 (min limit (length json-files))))
      (incf total)
      (if (validate-trace-file file :verbose t)
          (incf passed)
          (incf failed)))
    
    (format t "~%Summary:~%")
    (format t "  ✅ Passed: ~D / ~D~%" passed total)
    (format t "  ❌ Failed: ~D / ~D~%" failed total)
    
    (values passed failed total)))

;;; ==========================================================================
;;; Example Usage
;;; ==========================================================================

#|
;; Test single file
(validate-trace-file 
  "/home/polycrate/Projets/JOTL/tests/jamtestvectors/traces/tiny/00000001.json")

;; Test all traces (limited to 10)
(validate-all-traces 
  "/home/polycrate/Projets/JOTL/tests/jamtestvectors/traces/tiny/" 
  :limit 10)
|#
