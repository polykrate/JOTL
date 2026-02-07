#!/bin/bash
# test-extrinsic-et-ep.sh
# Test ET (Tickets) and EP (Preimages) encoding/decoding

cd /home/polycrate/Projets/JOTL

cat <<'LISP' | sbcl --noinform --disable-debugger
(require :asdf)
(push #P"/home/polycrate/Projets/JOTL/" asdf:*central-registry*)
(push #P"/home/polycrate/Projets/JOTL/crypto/" asdf:*central-registry*)

(ql:quickload :cffi :silent t)
(ql:quickload :alexandria :silent t)
(ql:quickload :cl-json :silent t)

(asdf:load-system :jam-crypto)
(asdf:load-system :jotl)

(defun get-json-field (alist field-name)
  "Get a field from a cl-json alist, handling underscore conversion."
  (let ((key (intern (string-upcase (substitute #\- #\_ field-name)) :keyword)))
    (cdr (assoc key alist))))

(defun test-tickets-encoding ()
  "Test ticket encoding/decoding with test vectors."
  (format t "~%========================================~%")
  (format t "Testing ET (Tickets) Encoding/Decoding~%")
  (format t "========================================~%~%")
  
  ;; Load test vectors
  (let* ((json-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/extrinsic.json")
         (json-data (with-open-file (stream json-path)
                      (cl-json:decode-json stream)))
         (tickets-json (get-json-field json-data "tickets")))
    
    (format t "Found ~a tickets in test vectors~%" (length tickets-json))
    
    ;; Test first ticket only (others are identical in structure)
    (let* ((ticket-json (first tickets-json))
           (attempt (get-json-field ticket-json "attempt"))
           (signature-hex (get-json-field ticket-json "signature"))
           (signature-bytes (jam.ffi:hex-string-to-bytes signature-hex)))
      
      (format t "~%Ticket 0:~%")
      (format t "  attempt: ~a~%" attempt)
      (format t "  signature length: ~a bytes~%" (length signature-bytes))
      
      ;; Test encoding
      (let* ((ticket-plist (list :attempt attempt :signature signature-bytes))
             (encoded (jotl:encode-ticket ticket-plist)))
        
        (format t "  ✓ Encoded: ~a bytes~%" (length encoded))
        
        ;; Test decoding
        (multiple-value-bind (decoded bytes-consumed)
            (jotl:decode-ticket encoded 0)
          
          (format t "  ✓ Decoded: ~a bytes consumed~%" bytes-consumed)
          
          ;; Verify round-trip
          (let ((decoded-attempt (getf decoded :attempt))
                (decoded-signature (getf decoded :signature)))
            
            (assert (= decoded-attempt attempt) ()
                    "Attempt mismatch: ~a != ~a" decoded-attempt attempt)
            
            (assert (equalp decoded-signature signature-bytes) ()
                    "Signature mismatch")
            
            (format t "  ✅ Round-trip OK!~%")))))
    
    ;; Test sequence encoding
    (format t "~%Testing tickets sequence encoding...~%")
    (let* ((tickets-plist (mapcar (lambda (ticket-json)
                                    (list :attempt (get-json-field ticket-json "attempt")
                                          :signature (jam.ffi:hex-string-to-bytes 
                                                      (get-json-field ticket-json "signature"))))
                                  tickets-json))
           (encoded-seq (jotl:encode-tickets-extrinsic tickets-plist)))
      
      (format t "  Encoded sequence: ~a bytes~%" (length encoded-seq))
      
      ;; Decode sequence
      (multiple-value-bind (decoded-tickets bytes-consumed)
          (jotl:decode-tickets-extrinsic encoded-seq 0)
        
        (format t "  Decoded sequence: ~a tickets, ~a bytes~%" 
                (length decoded-tickets) bytes-consumed)
        
        (assert (= (length decoded-tickets) (length tickets-plist)) ()
                "Ticket count mismatch")
        
        (format t "  ✅ Sequence encoding/decoding OK!~%")))))

(defun test-preimages-encoding ()
  "Test preimage encoding/decoding with test vectors."
  (format t "~%========================================~%")
  (format t "Testing EP (Preimages) Encoding/Decoding~%")
  (format t "========================================~%~%")
  
  ;; Load test vectors
  (let* ((json-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/extrinsic.json")
         (json-data (with-open-file (stream json-path)
                      (cl-json:decode-json stream)))
         (preimages-json (get-json-field json-data "preimages")))
    
    (format t "Found ~a preimages in test vectors~%" (length preimages-json))
    
    ;; Test first preimage
    (let* ((preimage-json (first preimages-json))
           (requester (get-json-field preimage-json "requester"))
           (blob-hex (get-json-field preimage-json "blob"))
           (blob-bytes (jam.ffi:hex-string-to-bytes blob-hex)))
      
      (format t "~%Preimage 0:~%")
      (format t "  requester: ~a~%" requester)
      (format t "  blob length: ~a bytes~%" (length blob-bytes))
      
      ;; Test encoding
      (let* ((preimage-plist (list :requester requester :blob blob-bytes))
             (encoded (jotl:encode-preimage preimage-plist)))
        
        (format t "  ✓ Encoded: ~a bytes~%" (length encoded))
        
        ;; Test decoding
        (multiple-value-bind (decoded bytes-consumed)
            (jotl:decode-preimage encoded 0)
          
          (format t "  ✓ Decoded: ~a bytes consumed~%" bytes-consumed)
          
          ;; Verify round-trip
          (let ((decoded-requester (getf decoded :requester))
                (decoded-blob (getf decoded :blob)))
            
            (assert (= decoded-requester requester) ()
                    "Requester mismatch: ~a != ~a" decoded-requester requester)
            
            (assert (equalp decoded-blob blob-bytes) ()
                    "Blob mismatch")
            
            (format t "  ✅ Round-trip OK!~%")))))
    
    ;; Test sequence encoding
    (format t "~%Testing preimages sequence encoding...~%")
    (let* ((preimages-plist (mapcar (lambda (preimage-json)
                                      (list :requester (get-json-field preimage-json "requester")
                                            :blob (jam.ffi:hex-string-to-bytes 
                                                   (get-json-field preimage-json "blob"))))
                                    preimages-json))
           (encoded-seq (jotl:encode-preimages-extrinsic preimages-plist)))
      
      (format t "  Encoded sequence: ~a bytes~%" (length encoded-seq))
      
      ;; Decode sequence
      (multiple-value-bind (decoded-preimages bytes-consumed)
          (jotl:decode-preimages-extrinsic encoded-seq 0)
        
        (format t "  Decoded sequence: ~a preimages, ~a bytes~%" 
                (length decoded-preimages) bytes-consumed)
        
        (assert (= (length decoded-preimages) (length preimages-plist)) ()
                "Preimage count mismatch")
        
        (format t "  ✅ Sequence encoding/decoding OK!~%")))))

(format t "~%╔════════════════════════════════════════════════════════╗~%")
(format t "║  JOTL - Extrinsic ET/EP Test Suite                    ║~%")
(format t "║  Testing with jamtestvectors/codec/tiny/extrinsic.json ║~%")
(format t "╚════════════════════════════════════════════════════════╝~%")

(handler-case
    (progn
      (test-tickets-encoding)
      (test-preimages-encoding)
      
      (format t "~%╔════════════════════════════════════════════════════════╗~%")
      (format t "║  ✅ ALL TESTS PASSED!                                  ║~%")
      (format t "║  ET (Tickets) ✅  EP (Preimages) ✅                    ║~%")
      (format t "║  Extrinsic encoding/decoding working!                  ║~%")
      (format t "╚════════════════════════════════════════════════════════╝~%")
      (sb-ext:exit :code 0))
  (error (e)
    (format t "~%❌ TEST FAILED: ~a~%" e)
    (sb-ext:exit :code 1)))
LISP
