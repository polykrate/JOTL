(in-package #:jotl)

;;; Diagnose epoch cascade failures — focus: guarantee BAD-SIGNATURE

(defun de-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun de-run (trace-id step)
  (format t "~%=== EPOCH DIAG: ~A / ~A ===~%" trace-id step)
  (let* ((dir (de-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Block info
      (let ((header (funcall block-cl :header)))
        (format t "Block timeslot: ~D~%" (funcall header :slot))
        (format t "Author: ~D~%" (funcall header :author-index)))

      (let* ((tau-prime-val (funcall (funcall block-cl :header) :slot))
             (block-epoch (floor tau-prime-val 600))
             (kappa (funcall pre-sigma :load :kappa))
             (lambda-prev (funcall pre-sigma :load :lambda))
             (guarantees (funcall block-cl :guarantees)))

        (format t "Guarantees: ~D~%" (length guarantees))

        (dolist (g guarantees)
          (let* ((report (getf g :report))
                 (raw-bytes (getf g :report-raw-bytes))
                 (guarantee-slot (getf g :slot))
                 (signatures (getf g :signatures))
                 (core-index (getf report :core-index))
                 ;; Hash from re-encoding
                 (reencoded (encode-work-report report))
                 (hash-reenc (blake2b-256 reencoded))
                 ;; Hash from raw bytes
                 (hash-raw (when raw-bytes (blake2b-256 raw-bytes))))
            (format t "~%  Guarantee: core=~D slot=~D~%" core-index guarantee-slot)
            (format t "    raw-bytes: ~A (~D bytes)~%"
                    (if raw-bytes "YES" "NO")
                    (if raw-bytes (length raw-bytes) 0))
            (format t "    reencoded: ~D bytes~%" (length reencoded))
            (format t "    raw=reenc? ~A~%"
                    (if raw-bytes (equalp raw-bytes reencoded) "N/A"))
            (when (and raw-bytes (not (equalp raw-bytes reencoded)))
              ;; Find first diff
              (let ((min-len (min (length raw-bytes) (length reencoded))))
                (dotimes (i min-len)
                  (when (/= (aref raw-bytes i) (aref reencoded i))
                    (format t "    FIRST DIFF at byte ~D: raw=0x~2,'0X reenc=0x~2,'0X~%"
                            i (aref raw-bytes i) (aref reencoded i))
                    (return)))))

            (format t "    hash-reenc: ~A~%"
                    (subseq (bytes-to-hex-string hash-reenc) 0 16))
            (when hash-raw
              (format t "    hash-raw:   ~A~%"
                      (subseq (bytes-to-hex-string hash-raw) 0 16)))

            (dolist (sig signatures)
              (let* ((idx (getf sig :validator-index))
                     (sig-bytes (ensure-bytes (getf sig :signature)))
                     (guarantee-epoch (floor guarantee-slot 600))
                     (keyset (if (/= block-epoch guarantee-epoch) lambda-prev kappa))
                     (ed-key (ensure-bytes (funcall keyset :ed25519-key idx)))
                     ;; Verify with re-encoded hash
                     (msg-reenc (guarantee-signing-payload hash-reenc))
                     (ok-reenc (jam.ffi:ed25519-verify ed-key msg-reenc sig-bytes)))
                (format t "    sig idx=~D: reenc-verify=~A" idx ok-reenc)
                ;; Also verify with raw hash
                (when hash-raw
                  (let* ((msg-raw (guarantee-signing-payload hash-raw))
                         (ok-raw (jam.ffi:ed25519-verify ed-key msg-raw sig-bytes)))
                    (format t " raw-verify=~A" ok-raw)))
                (format t "~%")))))))))

;; Run on 1766243493_9922 step 31
(de-run "1766243493_9922" "00000031")
