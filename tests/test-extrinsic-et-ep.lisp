#!/usr/bin/env sbcl --script
;;;; test-extrinsic-et-ep.lisp
;;;; Test ET (Tickets) and EP (Preimages) encoding/decoding
;;;; Using jamtestvectors/codec/tiny/extrinsic.json

(require :asdf)
(ql:quickload :cffi :silent t)
(ql:quickload :alexandria :silent t)
(ql:quickload :cl-json :silent t)

(load "jam-crypto.asd")
(load "jotl.asd")
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
    
    ;; Test each ticket
    (loop for ticket-json in tickets-json
          for i from 0
          do (let* ((attempt (get-json-field ticket-json "attempt"))
                    (signature-hex (get-json-field ticket-json "signature"))
                    (signature-bytes (jam.ffi:hex-string-to-bytes signature-hex)))
               
               (format t "~%Ticket ~a:~%" i)
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
                     
                     (format t "  ✅ Round-trip OK!~%"))))))
    
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
    
    ;; Test each preimage
    (loop for preimage-json in preimages-json
          for i from 0
          do (let* ((requester (get-json-field preimage-json "requester"))
                    (blob-hex (get-json-field preimage-json "blob"))
                    (blob-bytes (jam.ffi:hex-string-to-bytes blob-hex)))
               
               (format t "~%Preimage ~a:~%" i)
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
                     
                     (format t "  ✅ Round-trip OK!~%"))))))
    
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

(defun test-partial-extrinsic ()
  "Test partial extrinsic with ET and EP only (ED, EA, EG empty)."
  (format t "~%========================================~%")
  (format t "Testing Partial Extrinsic E ≡ (ET, ED, EP, EA, EG)~%")
  (format t "  ET ✅, EP ✅, ED/EA/EG = empty~%")
  (format t "========================================~%~%")
  
  ;; Load test vectors
  (let* ((json-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/extrinsic.json")
         (json-data (with-open-file (stream json-path)
                      (cl-json:decode-json stream)))
         (tickets-json (get-json-field json-data "tickets"))
         (preimages-json (get-json-field json-data "preimages"))
         
         ;; Convert to plists
         (tickets (mapcar (lambda (t-json)
                            (list :attempt (get-json-field t-json "attempt")
                                  :signature (jam.ffi:hex-string-to-bytes 
                                              (get-json-field t-json "signature"))))
                          tickets-json))
         (preimages (mapcar (lambda (p-json)
                              (list :requester (get-json-field p-json "requester")
                                    :blob (jam.ffi:hex-string-to-bytes 
                                           (get-json-field p-json "blob"))))
                            preimages-json)))
    
    (format t "Encoding partial extrinsic...~%")
    (format t "  Tickets: ~a~%" (length tickets))
    (format t "  Preimages: ~a~%" (length preimages))
    
    ;; Encode with empty ED, EA, EG
    (let ((encoded (jotl:encode-extrinsic tickets nil preimages nil nil)))
      
      (format t "  ✓ Encoded: ~a bytes~%~%" (length encoded))
      
      ;; Decode
      (multiple-value-bind (decoded bytes-consumed)
          (jotl:decode-extrinsic encoded 0)
        
        (format t "  ✓ Decoded: ~a bytes consumed~%" bytes-consumed)
        (format t "    Tickets: ~a~%" (length (getf decoded :tickets)))
        (format t "    Preimages: ~a~%" (length (getf decoded :preimages)))
        (format t "    Disputes: ~a (stub)~%" (length (getf decoded :disputes)))
        (format t "    Assurances: ~a (stub)~%" (length (getf decoded :assurances)))
        (format t "    Guarantees: ~a (stub)~%~%" (length (getf decoded :guarantees)))
        
        ;; Verify
        (assert (= (length (getf decoded :tickets)) (length tickets)) ()
                "Tickets count mismatch")
        (assert (= (length (getf decoded :preimages)) (length preimages)) ()
                "Preimages count mismatch")
        
        (format t "  ✅ Partial extrinsic OK!~%")))))

(defun main ()
  (format t "~%╔════════════════════════════════════════════════════════╗~%")
  (format t "║  JOTL - Extrinsic ET/EP Test Suite                    ║~%")
  (format t "║  Testing with jamtestvectors/codec/tiny/extrinsic.json ║~%")
  (format t "╚════════════════════════════════════════════════════════╝~%")
  
  (handler-case
      (progn
        (test-tickets-encoding)
        (test-preimages-encoding)
        (test-partial-extrinsic)
        
        (format t "~%╔════════════════════════════════════════════════════════╗~%")
        (format t "║  ✅ ALL TESTS PASSED!                                  ║~%")
        (format t "║  ET (Tickets) ✅  EP (Preimages) ✅                    ║~%")
        (format t "║  Partial Extrinsic encoding/decoding working!          ║~%")
        (format t "╚════════════════════════════════════════════════════════╝~%")
        (sb-ext:exit :code 0))
    (error (e)
      (format t "~%❌ TEST FAILED: ~a~%" e)
      (sb-ext:exit :code 1))))

(main)
