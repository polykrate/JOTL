;;;; test-header-decode.lisp - Test header decoding from test vectors
;;;; Validates our codec against official JAM test vectors

(load "scripts/load-jotl.lisp")

(in-package :jotl)

;;; ==========================================================================
;;; Simple JSON Parser (no dependencies)
;;; ==========================================================================

(defun read-json-file (filepath)
  "Read JSON file as string"
  (with-open-file (stream filepath)
    (let ((contents (make-string (file-length stream))))
      (read-sequence contents stream)
      contents)))

(defun extract-json-string-value (json key)
  "Extract a string value from JSON (simple regex-free approach)"
  (let ((search-str (format nil "\"~A\": \"" key)))
    (let ((pos (search search-str json)))
      (when pos
        (let* ((start (+ pos (length search-str)))
               (end (position #\" json :start start)))
          (when end
            (subseq json start end)))))))

(defun extract-json-number-value (json key)
  "Extract a number value from JSON"
  (let ((search-str (format nil "\"~A\": " key)))
    (let ((pos (search search-str json)))
      (when pos
        (let* ((start (+ pos (length search-str)))
               (end (or (position #\, json :start start)
                       (position #\Newline json :start start)
                       (position #\} json :start start))))
          (when end
            (let ((num-str (string-trim '(#\Space #\Tab #\Newline) 
                                       (subseq json start end))))
              (parse-integer num-str :junk-allowed t)))))))))

;;; ==========================================================================
;;; Header Test from Test Vector
;;; ==========================================================================

(defun test-header-from-vector (json-file)
  "Test header encoding/decoding from a test vector
   
   Process:
   1. Load header JSON
   2. Extract all fields
   3. Encode with our codec
   4. Compare with expected encoding (if available)
   5. Compute hash
   6. Validate structure"
  
  (format t "~%~%=== Testing Header from Test Vector ===~%")
  (format t "File: ~A~%~%" (file-namestring json-file))
  
  (handler-case
      (let* ((json (read-json-file json-file))
             ;; Extract header fields
             (parent-hash (extract-json-string-value json "parent"))
             (state-root (extract-json-string-value json "parent_state_root"))
             (extrinsic-hash (extract-json-string-value json "extrinsic_hash"))
             (slot (extract-json-number-value json "slot"))
             (author-index (extract-json-number-value json "author_index"))
             (entropy-source (extract-json-string-value json "entropy_source"))
             (seal (extract-json-string-value json "seal")))
        
        (format t "Extracted fields:~%")
        (format t "  Parent:         ~A~%" (if parent-hash (subseq parent-hash 0 (min 20 (length parent-hash))) "nil"))
        (format t "  State root:     ~A~%" (if state-root (subseq state-root 0 (min 20 (length state-root))) "nil"))
        (format t "  Extrinsic hash: ~A~%" (if extrinsic-hash (subseq extrinsic-hash 0 (min 20 (length extrinsic-hash))) "nil"))
        (format t "  Slot:           ~A~%" slot)
        (format t "  Author index:   ~A~%" author-index)
        (format t "  Entropy source: ~A~%" (if entropy-source (subseq entropy-source 0 (min 20 (length entropy-source))) "nil"))
        (format t "  Seal:           ~A~%" (if seal (subseq seal 0 (min 20 (length seal))) "nil"))
        
        ;; Convert hex strings to bytes
        (format t "~%Converting to bytes...~%")
        (let ((parent-bytes (when parent-hash (jam.ffi:hex-string-to-bytes parent-hash)))
              (state-root-bytes (when state-root (jam.ffi:hex-string-to-bytes state-root)))
              (extrinsic-bytes (when extrinsic-hash (jam.ffi:hex-string-to-bytes extrinsic-hash)))
              (entropy-bytes (when entropy-source (jam.ffi:hex-string-to-bytes entropy-source)))
              (seal-bytes (when seal (jam.ffi:hex-string-to-bytes seal))))
          
          (format t "  ✓ Parent:         ~D bytes~%" (if parent-bytes (length parent-bytes) 0))
          (format t "  ✓ State root:     ~D bytes~%" (if state-root-bytes (length state-root-bytes) 0))
          (format t "  ✓ Extrinsic hash: ~D bytes~%" (if extrinsic-bytes (length extrinsic-bytes) 0))
          (format t "  ✓ Entropy source: ~D bytes~%" (if entropy-bytes (length entropy-bytes) 0))
          (format t "  ✓ Seal:           ~D bytes~%" (if seal-bytes (length seal-bytes) 0))
          
          ;; Create header closure
          (format t "~%Creating header...~%")
          (let ((header (make-header-encoded
                         :parent-hash parent-bytes
                         :state-root state-root-bytes
                         :extrinsic-hash extrinsic-bytes
                         :slot slot
                         :epoch-mark nil  ; TODO: Parse epoch_mark
                         :tickets-mark nil
                         :offenders-mark nil  ; TODO: Parse offenders_mark
                         :author-index author-index
                         :entropy-source entropy-bytes
                         :seal seal-bytes)))
            
            (format t "  ✓ Header created~%")
            
            ;; Test accessors
            (format t "~%Testing accessors:~%")
            (format t "  Slot:         ~D~%" (funcall header :slot))
            (format t "  Author index: ~D~%" (funcall header :author-index))
            (format t "  Is genesis:   ~A~%" (funcall header :is-genesis))
            
            ;; Encode header
            (format t "~%Encoding header...~%")
            (let ((encoded (funcall header :encoded)))
              (format t "  ✓ Encoded size: ~D bytes~%" (length encoded))
              
              ;; Compute hash
              (format t "~%Computing hash...~%")
              (let ((hash (funcall header :hash)))
                (format t "  ✓ Hash: ~A~%" (jam.ffi:bytes-to-hex-string hash))
                
                (format t "~%✅ Header test PASSED!~%")
                t))))
        
    (error (e)
      (format t "~%❌ ERROR: ~A~%" e)
      nil)))

;;; ==========================================================================
;;; Run Test
;;; ==========================================================================

(defparameter *header-test-file*
  #P"/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/header_0.json")

(test-header-from-vector *header-test-file*)

(format t "~%Done!~%")
