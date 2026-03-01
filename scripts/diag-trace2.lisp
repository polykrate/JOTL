;;; diag-trace2.lisp — Deep investigation of trace 1767871405_1375 step 34
;;; The reference rejects this block (pre_root == post_root) but JOTL accepts it.
;;; H_r matches. We need to find the missing validation.

(in-package #:jotl)

(let* ((base (asdf:system-source-directory :jotl))
       (trace-dir (merge-pathnames
                   "../jam-conformance/fuzz-reports/0.7.2/traces/1767871405_1375/"
                   base))
       (step-path (merge-pathnames "00000034.bin" trace-dir)))

  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore post-sigma))

    (format t "~&═══ TRACE 2 DEEP DIAGNOSTIC ═══~%")
    (format t "  Pre root:  ~A~%" (bytes-to-hex-string pre-root))
    (format t "  Post root: ~A~%" (bytes-to-hex-string post-root))
    (format t "  Rejected by ref? ~A~%" (equalp pre-root post-root))

    (let* ((h   (funcall block-cl :header))
           (e-p (funcall block-cl :preimages))
           (e-a (funcall block-cl :assurances))
           (e-g (funcall block-cl :guarantees)))

      ;; ── EP preimage details ──
      (format t "~%  === EP PREIMAGE DETAILS ===~%")
      (dolist (p e-p)
        (let* ((sid (getf p :requester))
               (blob (ensure-bytes (getf p :blob)))
               (hash (jam.ffi:blake2b-256 blob))
               (len (length blob)))
          (format t "  EP: sid=~D hash=~A len=~D~%"
                  sid (subseq (bytes-to-hex-string hash) 0 16) len)
          ;; Check if this preimage already exists in the pre-state
          (let* ((delta (funcall pre-sigma :load :delta))
                 (raw-kvs (funcall delta :raw-kvs))
                 (meta-key (make-service-metadata-key sid))
                 (lookup-key (interleave-sub-key sid (lookup-trie-h hash len)))
                 (blob-key (interleave-sub-key sid (preimage-trie-h hash))))
            ;; Check service exists
            (let ((meta (find meta-key raw-kvs :key #'car :test #'equalp)))
              (format t "    service ~D exists? ~A~%" sid (not (null meta))))
            ;; Check lookup entry
            (let ((lookup (find lookup-key raw-kvs :key #'car :test #'equalp)))
              (format t "    lookup entry? ~A~%" (not (null lookup)))
              (when lookup
                (let ((statuses (load-lookup-value (cdr lookup))))
                  (format t "    statuses: ~A (count=~D, even?=~A)~%"
                          statuses (length statuses) (evenp (length statuses))))))
            ;; Check if blob already exists  
            (let ((existing-blob (find blob-key raw-kvs :key #'car :test #'equalp)))
              (format t "    blob already stored? ~A~%" (not (null existing-blob)))))))

      ;; ── Check if both preimages refer to same data ──
      (when (= (length e-p) 2)
        (let* ((p1 (first e-p))
               (p2 (second e-p))
               (b1 (ensure-bytes (getf p1 :blob)))
               (b2 (ensure-bytes (getf p2 :blob)))
               (h1 (jam.ffi:blake2b-256 b1))
               (h2 (jam.ffi:blake2b-256 b2)))
          (format t "~%  Same blob? ~A~%" (equalp b1 b2))
          (format t "  Same hash? ~A~%" (equalp h1 h2))
          (format t "  Same requester? ~A~%"
                  (= (getf p1 :requester) (getf p2 :requester)))))

      ;; ── Check duplicate preimage provision ──
      ;; GP rule: same (service, hash, length) pair must not appear twice in EP
      (format t "~%  === DUPLICATE CHECK ===~%")
      (let ((seen (make-hash-table :test 'equal)))
        (dolist (p e-p)
          (let* ((sid (getf p :requester))
                 (blob (ensure-bytes (getf p :blob)))
                 (hash (jam.ffi:blake2b-256 blob))
                 (len (length blob))
                 (key (list sid (bytes-to-hex-string hash) len)))
            (if (gethash key seen)
                (format t "  DUPLICATE: sid=~D hash=~A len=~D~%"
                        sid (subseq (bytes-to-hex-string hash) 0 16) len)
                (progn
                  (setf (gethash key seen) t)
                  (format t "  unique: sid=~D hash=~A len=~D~%"
                          sid (subseq (bytes-to-hex-string hash) 0 16) len))))))

      ;; ── Check assurances more closely ──
      (format t "~%  === ASSURANCE DETAILS ===~%")
      (format t "  Count: ~D~%" (length e-a))
      (dolist (a e-a)
        (format t "  A: validator=~D anchor=~A~%"
                (getf a :validator-index)
                (subseq (bytes-to-hex-string (getf a :anchor)) 0 16)))

      ;; ── Check guarantees ──
      (format t "~%  === GUARANTEE DETAILS ===~%")
      (format t "  Count: ~D~%" (length e-g))
      (dolist (g e-g)
        (let ((report (getf g :report)))
          (format t "  G: core=~D slot=~D sigs=~D results=~D~%"
                  (getf report :core-index)
                  (getf g :slot)
                  (length (getf g :signatures))
                  (length (getf report :results)))
          (let ((ctx (getf report :context)))
            (format t "    anchor: ~A~%"
                    (subseq (bytes-to-hex-string (getf ctx :anchor)) 0 16))
            (format t "    state-root: ~A~%"
                    (subseq (bytes-to-hex-string (getf ctx :state-root)) 0 16))
            (format t "    lookup-anchor: ~A slot=~D~%"
                    (subseq (bytes-to-hex-string (getf ctx :lookup-anchor)) 0 16)
                    (getf ctx :lookup-anchor-slot))
            ;; Check prerequisites
            (format t "    prerequisites: ~A~%"
                    (getf report :prerequisites)))))

      ;; ── Try running apply-block step by step with tracing ──
      (format t "~%  === RUNNING APPLY-BLOCK WITH TRACING ===~%")
      (handler-case
          (let ((result (apply-block pre-sigma block-cl)))
            (declare (ignore result))
            (format t "  apply-block: SUCCEEDED (block was ACCEPTED)~%")
            (format t "  → This is WRONG — ref rejects this block!~%"))
        (preimages-error (e)
          (format t "  apply-block: preimages-error → ~A~%" e))
        (guarantee-error (e)
          (format t "  apply-block: guarantee-error → ~A~%" e))
        (assurance-error (e)
          (format t "  apply-block: assurance-error → ~A~%" e))
        (disputes-error (e)
          (format t "  apply-block: disputes-error → ~A~%" e))
        (safrole-error (e)
          (format t "  apply-block: safrole-error → ~A~%" e))
        (error (e)
          (format t "  apply-block: general error → ~A~%" e))))))
