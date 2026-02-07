;;;; test-header-roundtrip.lisp - Header round-trip and hash test
;;;; Validates:
;;;;   1. decode(header.bin) → encode → bytes = original
;;;;   2. H(E(H)) = blake2b(sealed header bytes)

(in-package :jotl)

(defun run-header-roundtrip-tests ()
  (let* ((header-bin (alexandria:read-file-into-byte-vector
                      "tests/jamtestvectors/codec/tiny/header_0.bin"))
         (total-size (length header-bin)))
    
    (format t "~%=== Header Round-Trip Test ===~%")
    (format t "Header binary size: ~A bytes~%" total-size)
    
    ;; 1. Decode
    (format t "~%--- Step 1: Decode ---~%")
    (multiple-value-bind (decoded consumed)
        (decode-header header-bin 0)
      (format t "Decoded ~A bytes of ~A~%" consumed total-size)
      (format t "HP: ~A~%" (jam.ffi:bytes-to-hex-string (getf decoded :parent-hash)))
      (format t "HR: ~A~%" (jam.ffi:bytes-to-hex-string (getf decoded :state-root)))
      (format t "HX: ~A~%" (jam.ffi:bytes-to-hex-string (getf decoded :extrinsic-hash)))
      (format t "HT: ~A~%" (getf decoded :slot))
      (format t "HE: ~A~%" (if (getf decoded :epoch-mark) "Some" "None"))
      (format t "HW: ~A~%" (if (getf decoded :tickets-mark) "Some" "None"))
      (format t "HI: ~A~%" (getf decoded :author-index))
      (format t "HV: ~A bytes~%" (length (getf decoded :entropy-source)))
      (format t "HO: ~A offenders~%" (length (getf decoded :offenders-mark)))
      (format t "HS: ~A~%" (if (getf decoded :seal) 
                                (format nil "~A bytes" (length (getf decoded :seal)))
                                "MISSING!"))
      
      (unless (= consumed total-size)
        (format t "~%⚠️  Consumed ~A bytes but header is ~A bytes!~%" consumed total-size))
      
      ;; 2. Re-encode unsealed
      (format t "~%--- Step 2: Re-encode Unsealed EU(H) ---~%")
      (let ((re-encoded-unsealed (encode-header-unsealed
                                  (getf decoded :parent-hash)
                                  (getf decoded :state-root)
                                  (getf decoded :extrinsic-hash)
                                  (getf decoded :slot)
                                  (getf decoded :epoch-mark)
                                  (getf decoded :tickets-mark)
                                  (getf decoded :offenders-mark)
                                  (getf decoded :author-index)
                                  (getf decoded :entropy-source))))
        (format t "EU(H) size: ~A bytes~%" (length re-encoded-unsealed))
        (let ((expected-unsealed-size (- total-size 96)))  ; total - seal
          (format t "Expected EU(H) size: ~A bytes (total ~A - seal 96)~%" 
                  expected-unsealed-size total-size)
          
          ;; Compare unsealed bytes
          (let ((original-unsealed (subseq header-bin 0 expected-unsealed-size)))
            (if (equalp re-encoded-unsealed original-unsealed)
                (format t "✅ EU(H) round-trip: MATCH~%")
                (progn
                  (format t "❌ EU(H) round-trip: MISMATCH~%")
                  ;; Find first difference
                  (loop for i from 0 below (min (length re-encoded-unsealed) 
                                                (length original-unsealed))
                        when (not (= (aref re-encoded-unsealed i) (aref original-unsealed i)))
                        do (format t "   First diff at byte ~A: got 0x~2,'0X, expected 0x~2,'0X~%" 
                                   i (aref re-encoded-unsealed i) (aref original-unsealed i))
                           (return)))))))
      
      ;; 3. Re-encode sealed (full header)
      (format t "~%--- Step 3: Re-encode Sealed E(H) ---~%")
      (let ((re-encoded-sealed (encode-header
                                (getf decoded :parent-hash)
                                (getf decoded :state-root)
                                (getf decoded :extrinsic-hash)
                                (getf decoded :slot)
                                (getf decoded :epoch-mark)
                                (getf decoded :tickets-mark)
                                (getf decoded :offenders-mark)
                                (getf decoded :author-index)
                                (getf decoded :entropy-source)
                                (getf decoded :seal))))
        (format t "E(H) size: ~A bytes~%" (length re-encoded-sealed))
        
        (if (equalp re-encoded-sealed header-bin)
            (format t "✅ E(H) round-trip: MATCH~%")
            (progn
              (format t "❌ E(H) round-trip: MISMATCH~%")
              (loop for i from 0 below (min (length re-encoded-sealed) (length header-bin))
                    when (not (= (aref re-encoded-sealed i) (aref header-bin i)))
                    do (format t "   First diff at byte ~A: got 0x~2,'0X, expected 0x~2,'0X~%" 
                               i (aref re-encoded-sealed i) (aref header-bin i))
                       (return)))))
      
      ;; 4. Compute header hash H(E(H))
      (format t "~%--- Step 4: Header Hash H(E(H)) ---~%")
      (let ((header-hash (compute-header-hash-from-decoded decoded)))
        (format t "H(E(H)) = ~A~%" (jam.ffi:bytes-to-hex-string header-hash))
        (format t "~%This hash would appear as HP in a child block.~%"))
      
      ;; 5. Also compute H(raw_bytes) directly for verification
      (format t "~%--- Step 5: Direct hash of raw bytes ---~%")
      (let ((direct-hash (jam.ffi:blake2b-256 header-bin)))
        (format t "H(header_0.bin) = ~A~%" (jam.ffi:bytes-to-hex-string direct-hash))
        
        ;; They should match if round-trip is correct
        (let ((hash-from-decoded (compute-header-hash-from-decoded decoded)))
          (if (equalp direct-hash hash-from-decoded)
              (format t "✅ Hash consistency: decoded encode hash = raw bytes hash~%")
              (format t "❌ Hash inconsistency! Re-encoding changed the bytes.~%")))))))
