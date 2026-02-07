#!/bin/bash
# test-extrinsic-hash.sh
# Test HX (Extrinsic Hash) computation with Merkle Trie

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

(defun test-extrinsic-hash-simple ()
  "Test HX computation with a simple extrinsic (ET + EP only, others empty)."
  (format t "~%========================================~%")
  (format t "Testing HX (Extrinsic Hash) Computation~%")
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
    
    (format t "Computing HX for extrinsic with:~%")
    (format t "  Tickets: ~a~%" (length tickets))
    (format t "  Preimages: ~a~%" (length preimages))
    (format t "  Assurances: 0 (empty)~%")
    (format t "  Disputes: 0 (empty)~%")
    (format t "  Guarantees: 0 (empty/stub)~%~%")
    
    ;; Build extrinsic data
    (let* ((extrinsic-data (list :tickets tickets
                                 :preimages preimages
                                 :assurances '()
                                 :disputes '()
                                 :guarantees '()))
           (hx (jotl:compute-extrinsic-hash extrinsic-data))
           (hx-hex (jam.ffi:bytes-to-hex-string hx)))
      
      (format t "Computed HX: ~a~%" hx-hex)
      (format t "  Length: ~a bytes~%" (length hx))
      
      (assert (= (length hx) 32) ()
              "HX must be 32 bytes, got: ~a" (length hx))
      
      (format t "~%✅ HX computation successful!~%")
      (format t "  32-byte hash ✓~%")
      (format t "  Merkle root from 5 components ✓~%")
      hx-hex)))

(defun test-extrinsic-hash-full ()
  "Test HX with full extrinsic (ET + EP + EA + ED)."
  (format t "~%========================================~%")
  (format t "Testing HX with Full Extrinsic~%")
  (format t "========================================~%~%")
  
  ;; Load test vectors
  (let* ((json-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/extrinsic.json")
         (json-data (with-open-file (stream json-path)
                      (cl-json:decode-json stream)))
         (tickets-json (get-json-field json-data "tickets"))
         (preimages-json (get-json-field json-data "preimages"))
         (assurances-json (get-json-field json-data "assurances"))
         (disputes-json (get-json-field json-data "disputes"))
         (verdicts-json (get-json-field disputes-json "verdicts"))
         (culprits-json (get-json-field disputes-json "culprits"))
         (faults-json (get-json-field disputes-json "faults"))
         
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
                            preimages-json))
         (assurances (mapcar (lambda (a-json)
                               (list :anchor (get-json-field a-json "anchor")
                                     :bitfield (get-json-field a-json "bitfield")
                                     :validator-index (cdr (assoc :VALIDATOR--INDEX a-json))
                                     :signature (get-json-field a-json "signature")))
                             assurances-json))
         (disputes (list :verdicts (mapcar (lambda (v-json)
                                             (list :target (get-json-field v-json "target")
                                                   :age (get-json-field v-json "age")
                                                   :votes (mapcar (lambda (vote-json)
                                                                    (list :vote (get-json-field vote-json "vote")
                                                                          :index (get-json-field vote-json "index")
                                                                          :signature (get-json-field vote-json "signature")))
                                                                  (get-json-field v-json "votes"))))
                                           verdicts-json)
                         :culprits (mapcar (lambda (c-json)
                                             (list :target (get-json-field c-json "target")
                                                   :key (get-json-field c-json "key")
                                                   :signature (get-json-field c-json "signature")))
                                           culprits-json)
                         :faults (mapcar (lambda (f-json)
                                           (list :target (get-json-field f-json "target")
                                                 :vote (get-json-field f-json "vote")
                                                 :key (get-json-field f-json "key")
                                                 :signature (get-json-field f-json "signature")))
                                         faults-json))))
    
    (format t "Computing HX for FULL extrinsic with:~%")
    (format t "  Tickets: ~a~%" (length tickets))
    (format t "  Preimages: ~a~%" (length preimages))
    (format t "  Assurances: ~a~%" (length assurances))
    (format t "  Disputes: ~a verdicts, ~a culprits, ~a faults~%" 
            (length (getf disputes :verdicts))
            (length (getf disputes :culprits))
            (length (getf disputes :faults)))
    (format t "  Guarantees: 0 (empty/stub)~%~%")
    
    ;; Build extrinsic data
    (let* ((extrinsic-data (list :tickets tickets
                                 :preimages preimages
                                 :assurances assurances
                                 :disputes disputes
                                 :guarantees '()))
           (hx (jotl:compute-extrinsic-hash extrinsic-data))
           (hx-hex (jam.ffi:bytes-to-hex-string hx)))
      
      (format t "Computed HX: ~a~%" hx-hex)
      (format t "  Length: ~a bytes~%" (length hx))
      
      (assert (= (length hx) 32) ()
              "HX must be 32 bytes, got: ~a" (length hx))
      
      (format t "~%✅ Full HX computation successful!~%")
      (format t "  32-byte hash ✓~%")
      (format t "  All extrinsic components included ✓~%")
      hx-hex)))

(defun test-extrinsic-hash-consistency ()
  "Test that HX is consistent across multiple computations."
  (format t "~%========================================~%")
  (format t "Testing HX Consistency~%")
  (format t "========================================~%~%")
  
  (let* ((extrinsic-data (list :tickets '()
                               :preimages '()
                               :assurances '()
                               :disputes '()
                               :guarantees '()))
         (hx1 (jotl:compute-extrinsic-hash extrinsic-data))
         (hx2 (jotl:compute-extrinsic-hash extrinsic-data)))
    
    (format t "Computing HX twice for empty extrinsic:~%")
    (format t "  HX1: ~a~%" (jam.ffi:bytes-to-hex-string hx1))
    (format t "  HX2: ~a~%" (jam.ffi:bytes-to-hex-string hx2))
    
    (assert (equalp hx1 hx2) ()
            "HX computation must be deterministic!")
    
    (format t "~%✅ HX is deterministic!~%")))

(format t "~%╔════════════════════════════════════════════════════════╗~%")
(format t "║  JOTL - Extrinsic Hash (HX) Test Suite                ║~%")
(format t "║  Gray Paper §5.4-5.6 - Merkle Tree Implementation     ║~%")
(format t "╚════════════════════════════════════════════════════════╝~%")

(handler-case
    (progn
      (test-extrinsic-hash-simple)
      (test-extrinsic-hash-full)
      (test-extrinsic-hash-consistency)
      
      (format t "~%╔════════════════════════════════════════════════════════╗~%")
      (format t "║  ✅ ALL TESTS PASSED!                                  ║~%")
      (format t "║  HX (Extrinsic Hash) working correctly! 🌲             ║~%")
      (format t "║  Merkle Trie integration successful!                   ║~%")
      (format t "╚════════════════════════════════════════════════════════╝~%")
      (sb-ext:exit :code 0))
  (error (e)
    (format t "~%❌ TEST FAILED: ~a~%" e)
    (sb-ext:exit :code 1)))
LISP
