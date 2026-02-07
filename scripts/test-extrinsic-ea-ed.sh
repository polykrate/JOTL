#!/bin/bash
# test-extrinsic-ea-ed.sh
# Test EA (Assurances) and ED (Disputes) encoding/decoding

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

(defun test-assurances-encoding ()
  "Test assurance encoding/decoding with test vectors."
  (format t "~%========================================~%")
  (format t "Testing EA (Assurances) Encoding/Decoding~%")
  (format t "========================================~%~%")
  
  ;; Load test vectors
  (let* ((json-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/extrinsic.json")
         (json-data (with-open-file (stream json-path)
                      (cl-json:decode-json stream)))
         (assurances-json (get-json-field json-data "assurances")))
    
    (format t "Found ~a assurances in test vectors~%" (length assurances-json))
    
    ;; Test first assurance
    (let* ((assurance-json (first assurances-json))
           (anchor (get-json-field assurance-json "anchor"))
           (bitfield (get-json-field assurance-json "bitfield"))
           (validator-index (cdr (assoc :VALIDATOR--INDEX assurance-json)))  ; cl-json double-dash
           (signature (get-json-field assurance-json "signature")))
      
      (format t "~%Assurance 0:~%")
      (format t "  anchor: ~a~%" anchor)
      (format t "  bitfield: ~a~%" bitfield)
      (format t "  validator-index: ~a~%" validator-index)
      
      ;; Test encoding
      (let* ((assurance-plist (list :anchor anchor
                                    :bitfield bitfield
                                    :validator-index (or validator-index 0)
                                    :signature signature))
             (encoded (jotl:encode-assurance assurance-plist)))
        
        (format t "  ✓ Encoded: ~a bytes~%" (length encoded))
        
        ;; Test decoding
        (multiple-value-bind (decoded bytes-consumed)
            (jotl:decode-assurance encoded 0)
          
          (format t "  ✓ Decoded: ~a bytes consumed~%" bytes-consumed)
          
          ;; Verify round-trip
          (assert (= (getf decoded :validator-index) validator-index))
          (format t "  ✅ Round-trip OK!~%"))))
    
    ;; Test sequence encoding
    (format t "~%Testing assurances sequence encoding...~%")
    (let* ((assurances-plist (mapcar (lambda (a-json)
                                       (list :anchor (get-json-field a-json "anchor")
                                             :bitfield (get-json-field a-json "bitfield")
                                             :validator-index (cdr (assoc :VALIDATOR--INDEX a-json))
                                             :signature (get-json-field a-json "signature")))
                                     assurances-json))
           (encoded-seq (jotl:encode-assurances-extrinsic assurances-plist)))
      
      (format t "  Encoded sequence: ~a bytes~%" (length encoded-seq))
      
      ;; Decode sequence
      (multiple-value-bind (decoded-assurances bytes-consumed)
          (jotl:decode-assurances-extrinsic encoded-seq 0)
        
        (format t "  Decoded sequence: ~a assurances, ~a bytes~%" 
                (length decoded-assurances) bytes-consumed)
        
        (assert (= (length decoded-assurances) (length assurances-plist)))
        
        (format t "  ✅ Sequence encoding/decoding OK!~%")))))

(defun test-disputes-encoding ()
  "Test dispute encoding/decoding with test vectors."
  (format t "~%========================================~%")
  (format t "Testing ED (Disputes) Encoding/Decoding~%")
  (format t "========================================~%~%")
  
  ;; Load test vectors
  (let* ((json-path "/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/extrinsic.json")
         (json-data (with-open-file (stream json-path)
                      (cl-json:decode-json stream)))
         (disputes-json (get-json-field json-data "disputes"))
         (verdicts-json (get-json-field disputes-json "verdicts"))
         (culprits-json (get-json-field disputes-json "culprits"))
         (faults-json (get-json-field disputes-json "faults")))
    
    (format t "Found disputes in test vectors:~%")
    (format t "  Verdicts: ~a~%" (length verdicts-json))
    (format t "  Culprits: ~a~%" (length culprits-json))
    (format t "  Faults: ~a~%~%" (length faults-json))
    
    ;; Test verdict encoding
    (let* ((verdict-json (first verdicts-json))
           (target (get-json-field verdict-json "target"))
           (age (get-json-field verdict-json "age"))
           (votes-json (get-json-field verdict-json "votes"))
           (votes (mapcar (lambda (v-json)
                            (list :vote (get-json-field v-json "vote")
                                  :index (get-json-field v-json "index")
                                  :signature (get-json-field v-json "signature")))
                          votes-json)))
      
      (format t "Verdict 0:~%")
      (format t "  target: ~a~%" target)
      (format t "  age: ~a~%" age)
      (format t "  votes: ~a~%" (length votes))
      
      (let* ((verdict-plist (list :target target :age age :votes votes))
             (encoded (jotl:encode-verdict verdict-plist)))
        
        (format t "  ✓ Encoded: ~a bytes~%" (length encoded))
        
        (multiple-value-bind (decoded bytes-consumed)
            (jotl:decode-verdict encoded 0)
          
          (format t "  ✓ Decoded: ~a bytes consumed~%" bytes-consumed)
          (assert (= (getf decoded :age) age))
          (format t "  ✅ Verdict round-trip OK!~%"))))
    
    ;; Test complete disputes encoding
    (format t "~%Testing complete disputes encoding...~%")
    (let* ((disputes-plist (list :verdicts (mapcar (lambda (v-json)
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
                                                 faults-json)))
           (encoded-disputes (jotl:encode-disputes-extrinsic disputes-plist)))
      
      (format t "  Encoded disputes: ~a bytes~%" (length encoded-disputes))
      
      (multiple-value-bind (decoded-disputes bytes-consumed)
          (jotl:decode-disputes-extrinsic encoded-disputes 0)
        
        (format t "  Decoded disputes: ~a bytes~%" bytes-consumed)
        (format t "    Verdicts: ~a~%" (length (getf decoded-disputes :verdicts)))
        (format t "    Culprits: ~a~%" (length (getf decoded-disputes :culprits)))
        (format t "    Faults: ~a~%~%" (length (getf decoded-disputes :faults)))
        
        (assert (= (length (getf decoded-disputes :verdicts)) (length verdicts-json)))
        (assert (= (length (getf decoded-disputes :culprits)) (length culprits-json)))
        (assert (= (length (getf decoded-disputes :faults)) (length faults-json)))
        
        (format t "  ✅ Disputes encoding/decoding OK!~%")))))

(format t "~%╔════════════════════════════════════════════════════════╗~%")
(format t "║  JOTL - Extrinsic EA/ED Test Suite                    ║~%")
(format t "║  Testing with jamtestvectors/codec/tiny/extrinsic.json ║~%")
(format t "╚════════════════════════════════════════════════════════╝~%")

(handler-case
    (progn
      (test-assurances-encoding)
      (test-disputes-encoding)
      
      (format t "~%╔════════════════════════════════════════════════════════╗~%")
      (format t "║  ✅ ALL TESTS PASSED!                                  ║~%")
      (format t "║  EA (Assurances) ✅  ED (Disputes) ✅                  ║~%")
      (format t "║  Extrinsic EA/ED encoding/decoding working!            ║~%")
      (format t "╚════════════════════════════════════════════════════════╝~%")
      (sb-ext:exit :code 0))
  (error (e)
    (format t "~%❌ TEST FAILED: ~a~%" e)
    (sb-ext:exit :code 1)))
LISP
