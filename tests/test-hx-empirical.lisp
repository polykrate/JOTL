;;;; Empirical test for HX = H(E(H#(a)))  — Gray Paper §5.4-5.6
;;;;
;;;; FROM STRAWBERRY (Go reference implementation):
;;;; 1. Hash each encoded component: H(ET_bytes), H(EP_bytes), H(g_bytes), H(EA_bytes), H(ED_bytes)
;;;; 2. g = jam.Marshal([(H(r), timeslot, credentials) for each guarantee])
;;;; 3. E(H#(a)) = concat of 5 hashes (160 bytes)
;;;; 4. HX = H(E(H#(a))) = blake2b(160 bytes)
(in-package :jotl)

(defun load-bin (name)
  (alexandria:read-file-into-byte-vector
   (merge-pathnames name "tests/jamtestvectors/codec/tiny/")))

(defun cat (&rest arrays)
  (apply #'concatenate '(vector (unsigned-byte 8)) arrays))

;;; ====================================================================
;;; Compute g from guarantees (§5.6) using raw bytes
;;; g = E(↕[(H(r), E4(t), ↕a) | (r, t, a) ← EG])
;;; ====================================================================

(defun compute-g-raw (eg-bin)
  "Compute g using raw work report bytes (no re-encoding).
   Returns: byte array of the encoded g."
  (multiple-value-bind (guarantees consumed)
      (decode-guarantees-extrinsic eg-bin 0)
    (declare (ignore consumed))
    (if (null guarantees)
        (encode-compact 0)
        (let ((items nil))
          (dolist (g guarantees)
            (let* (;; Use raw bytes from the binary for H(r)
                   (raw-report (getf g :report-raw-bytes))
                   (h-r (blake2b-256 raw-report))
                   ;; E4(t) = timeslot as u32
                   (t-bytes (encode-u32 (getf g :slot)))
                   ;; ↕a = credentials
                   (sigs (getf g :signatures))
                   (sigs-encoded
                     (apply #'cat
                            (encode-compact (length sigs))
                            (mapcar (lambda (s)
                                      (cat (encode-u16 (getf s :validator-index))
                                           (getf s :signature)))
                                    sigs))))
              (push (cat h-r t-bytes sigs-encoded) items)))
          (apply #'cat
                 (encode-compact (length guarantees))
                 (nreverse items))))))

(defun compute-g-reencoded (eg-bin)
  "Compute g using re-encoded work report (to verify round-trip).
   Returns: byte array of the encoded g."
  (multiple-value-bind (guarantees consumed)
      (decode-guarantees-extrinsic eg-bin 0)
    (declare (ignore consumed))
    (if (null guarantees)
        (encode-compact 0)
        (let ((items nil))
          (dolist (g guarantees)
            (let* ((report (getf g :report))
                   (report-bytes (encode-work-report report))
                   (h-r (blake2b-256 report-bytes))
                   (t-bytes (encode-u32 (getf g :slot)))
                   (sigs (getf g :signatures))
                   (sigs-encoded
                     (apply #'cat
                            (encode-compact (length sigs))
                            (mapcar (lambda (s)
                                      (cat (encode-u16 (getf s :validator-index))
                                           (getf s :signature)))
                                    sigs))))
              (push (cat h-r t-bytes sigs-encoded) items)))
          (apply #'cat
                 (encode-compact (length guarantees))
                 (nreverse items))))))

;;; ====================================================================
;;; MAIN TEST
;;; ====================================================================

(defun hx-tests ()
  (let* ((header-bin (load-bin "header_0.bin"))
         (et-bin (load-bin "tickets_extrinsic.bin"))
         (ep-bin (load-bin "preimages_extrinsic.bin"))
         (eg-bin (load-bin "guarantees_extrinsic.bin"))
         (ea-bin (load-bin "assurances_extrinsic.bin"))
         (ed-bin (load-bin "disputes_extrinsic.bin"))
         ;; HX is at offset 64 in the header (after HP=32 + HR=32)
         (expected-hx (subseq header-bin 64 96)))
    
    (format t "~%Expected HX: ~a~%" (bytes-to-hex-string expected-hx))
    
    ;; First, verify raw vs re-encoded work report hashes match
    (multiple-value-bind (guarantees consumed)
        (decode-guarantees-extrinsic eg-bin 0)
      (declare (ignore consumed))
      (format t "~%--- Verifying WorkReport bytes (raw vs re-encoded) ---~%")
      (dolist (g guarantees)
        (let* ((raw (getf g :report-raw-bytes))
               (reencoded (encode-work-report (getf g :report))))
          (format t "  Raw:       ~d bytes -> H = ~a~%" (length raw) 
                  (bytes-to-hex-string (blake2b-256 raw)))
          (format t "  Reencoded: ~d bytes -> H = ~a~%" (length reencoded)
                  (bytes-to-hex-string (blake2b-256 reencoded)))
          (format t "  Match: ~a~%" (if (equalp raw reencoded) "✅ YES" "❌ NO")))))
    
    ;; Compute g both ways
    (let* ((g-raw (compute-g-raw eg-bin))
           (g-reenc (compute-g-reencoded eg-bin)))
      
      (format t "~%g raw:       ~d bytes~%" (length g-raw))
      (format t "g reencoded: ~d bytes~%" (length g-reenc))
      (format t "g match:     ~a~%" (if (equalp g-raw g-reenc) "✅ YES" "❌ NO"))
      
      ;; Hash each component  
      (let* ((h-et (blake2b-256 et-bin))
             (h-ep (blake2b-256 ep-bin))
             (h-g  (blake2b-256 g-raw))
             (h-ea (blake2b-256 ea-bin))
             (h-ed (blake2b-256 ed-bin)))
        
        (format t "~%Component hashes:~%")
        (format t "  H(ET): ~a~%" (bytes-to-hex-string h-et))
        (format t "  H(EP): ~a~%" (bytes-to-hex-string h-ep))
        (format t "  H(g):  ~a~%" (bytes-to-hex-string h-g))
        (format t "  H(EA): ~a~%" (bytes-to-hex-string h-ea))
        (format t "  H(ED): ~a~%" (bytes-to-hex-string h-ed))
        
        ;; ======================================================
        ;; Test 1: HX = H(H(ET) || H(EP) || H(g) || H(EA) || H(ED))
        ;; ======================================================
        (format t "~%--- Test 1: H(H(ET)||H(EP)||H(g)||H(EA)||H(ED)) ---~%")
        (let* ((concat-hashes (cat h-et h-ep h-g h-ea h-ed))
               (hx (blake2b-256 concat-hashes)))
          (format t "  HX = ~a  ~a~%" (bytes-to-hex-string hx)
                  (if (equalp hx expected-hx) "✅ MATCH!" "❌")))
        
        ;; ======================================================
        ;; Test 2: With raw EG (no g transformation)
        ;; ======================================================
        (format t "~%--- Test 2: H(H(ET)||H(EP)||H(EG_raw)||H(EA)||H(ED)) ---~%")
        (let* ((h-eg (blake2b-256 eg-bin))
               (concat-hashes (cat h-et h-ep h-eg h-ea h-ed))
               (hx (blake2b-256 concat-hashes)))
          (format t "  HX = ~a  ~a~%" (bytes-to-hex-string hx)
                  (if (equalp hx expected-hx) "✅ MATCH!" "❌")))

        ;; ======================================================
        ;; Test 3: GP §4.3 order: ET, ED, EP, EA, g
        ;; ======================================================
        (format t "~%--- Test 3: GP §4.3 order ---~%")
        (let* ((concat-hashes (cat h-et h-ed h-ep h-ea h-g))
               (hx (blake2b-256 concat-hashes)))
          (format t "  HX = ~a  ~a~%" (bytes-to-hex-string hx)
                  (if (equalp hx expected-hx) "✅ MATCH!" "❌")))
        
        ;; ======================================================
        ;; Test 4: Decode full extrinsic.bin, encode each, hash
        ;; This ensures we're using the exact same bytes
        ;; ======================================================
        (format t "~%--- Test 4: From extrinsic.bin decode/re-encode ---~%")
        (let* ((ext-bin (load-bin "extrinsic.bin"))
               (decoded (decode-extrinsic ext-bin 0))
               (re-et (encode-tickets-extrinsic (getf decoded :tickets)))
               (re-ep (encode-preimages-extrinsic (getf decoded :preimages)))
               (re-ea (encode-assurances-extrinsic (getf decoded :assurances)))
               (re-ed (encode-disputes-extrinsic (getf decoded :disputes)))
               (re-g  (compute-g-raw eg-bin)))
          (format t "  ET match bin: ~a~%" (equalp re-et et-bin))
          (format t "  EP match bin: ~a~%" (equalp re-ep ep-bin))
          (format t "  EA match bin: ~a~%" (equalp re-ea ea-bin))
          (format t "  ED match bin: ~a~%" (equalp re-ed ed-bin))
          (let* ((h-re-et (blake2b-256 re-et))
                 (h-re-ep (blake2b-256 re-ep))
                 (h-re-g  (blake2b-256 re-g))
                 (h-re-ea (blake2b-256 re-ea))
                 (h-re-ed (blake2b-256 re-ed))
                 (concat-hashes (cat h-re-et h-re-ep h-re-g h-re-ea h-re-ed))
                 (hx (blake2b-256 concat-hashes)))
            (format t "  HX = ~a  ~a~%" (bytes-to-hex-string hx)
                    (if (equalp hx expected-hx) "✅ MATCH!" "❌"))))
        
        ;; ======================================================
        ;; Test 5: Dump g bytes for comparison
        ;; ======================================================
        (format t "~%--- g bytes (first 100) ---~%")
        (format t "  ~a~%" (bytes-to-hex-string (subseq g-raw 0 (min 100 (length g-raw)))))
        ))))

(hx-tests)
