;;;; debug-failing-steps.lisp — Verify anchor data against beta for trace 2
(in-package #:jotl)

(defun debug-trace2-anchor-match (step-path)
  (let* ((bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma post-root pre-root))
      (let* ((*chain-log-level* nil)
             (h (funcall block-cl :header))
             (e-g (funcall block-cl :guarantees))
             (g (first e-g))
             (report (getf g :report))
             (ctx (getf report :context))
             ;; Context fields
             (ctx-anchor (ensure-bytes (getf ctx :anchor)))
             (ctx-state-root (ensure-bytes (getf ctx :state-root)))
             (ctx-beefy-root (ensure-bytes (getf ctx :beefy-root)))
             (ctx-lookup-anchor (ensure-bytes (getf ctx :lookup-anchor)))
             (ctx-lookup-slot (getf ctx :lookup-anchor-slot))
             ;; Beta dagger
             (beta (funcall pre-sigma :decode-segment :beta))
             (beta-dagger (funcall beta :transition-dagger :header h)))

        (format t "~%Context anchor:       ~A~%" (bytes-to-hex-string ctx-anchor))
        (format t "Context lookup-anchor: ~A~%" (bytes-to-hex-string ctx-lookup-anchor))
        (format t "Same hash? ~A~%" (equalp ctx-anchor ctx-lookup-anchor))
        (format t "Context state-root:   ~A~%" (bytes-to-hex-string ctx-state-root))
        (format t "Context beefy-root:   ~A~%" (bytes-to-hex-string ctx-beefy-root))
        (format t "Context lookup-slot:  ~D~%" ctx-lookup-slot)

        ;; Search beta for the anchor
        (format t "~%── β† search for anchor ──~%")
        (let* ((find-record (lambda (hash)
                              (funcall beta-dagger :find-record hash)))
               (record (funcall find-record ctx-anchor)))
          (if record
              (progn
                (format t "  FOUND in β†!~%")
                (format t "  Record state-root: ~A~%"
                        (bytes-to-hex-string (ensure-bytes (getf record :state-root))))
                (format t "  Record beefy-root: ~A~%"
                        (bytes-to-hex-string (ensure-bytes (getf record :beefy-root))))
                (format t "  State-root match? ~A~%"
                        (equalp (ensure-bytes (getf record :state-root)) ctx-state-root))
                (format t "  Beefy-root match? ~A~%"
                        (equalp (ensure-bytes (getf record :beefy-root)) ctx-beefy-root)))
              (format t "  NOT FOUND in β†! *** Should reject ***~%")))

        ;; List all records in beta for context
        (format t "~%── β† all records ──~%")
        (let ((records (funcall beta-dagger :recent-records)))
          (format t "  Count: ~D~%" (length records))
          (dolist (r records)
            (format t "  hash=~A... slot=~A~%"
                    (subseq (bytes-to-hex-string (ensure-bytes (getf r :hash))) 0 16)
                    (getf r :slot))))))))

(let* ((traces-dir (or (uiop:getenv "TRACES_DIR")
                       (namestring (merge-pathnames "../jam-conformance/fuzz-reports/0.7.2/traces/"
                                                    (asdf:system-source-directory :jotl))))))
  (format t "~%════════════════════════════════════════~%")
  (format t "TRACE 2: 1767896003_2541 step 00013906~%")
  (format t "════════════════════════════════════════~%")
  (debug-trace2-anchor-match (concatenate 'string traces-dir "1767896003_2541/00013906.bin")))

(sb-ext:exit :code 0)
