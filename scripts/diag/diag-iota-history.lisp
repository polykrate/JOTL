;;; diag-iota-history.lisp — Track IOTA changes across trace steps
;;; Check if IOTA changed between steps and if assurances use the right validator set
(in-package #:jotl)

(defun dih-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dih-run (trace-id)
  (format t "~%=== IOTA HISTORY: ~A ===~%" trace-id)
  (let ((dir (dih-trace-dir trace-id))
        (prev-iota-bytes nil)
        (prev-kappa-bytes nil))
    (dolist (step '("00000014" "00000015" "00000016" "00000017" "00000018"))
      (let* ((step-path (merge-pathnames (format nil "~A.bin" step) dir)))
        (when (probe-file step-path)
          (let ((bytes (alexandria:read-file-into-byte-vector step-path)))
            (multiple-value-bind (pre-sigma block-cl post-sigma)
                (decode-trace-step-bin bytes)
              (declare (ignore post-sigma))
              (let* ((header (funcall block-cl :header))
                     (slot (funcall header :slot))
                     (pre-iota (funcall pre-sigma :load :iota))
                     (pre-kappa (funcall pre-sigma :load :kappa))
                     (iota-bytes (funcall pre-iota :save))
                     (kappa-bytes (funcall pre-kappa :save))
                     (iota-changed (and prev-iota-bytes (not (equalp iota-bytes prev-iota-bytes))))
                     (kappa-changed (and prev-kappa-bytes (not (equalp kappa-bytes prev-kappa-bytes))))
                     (guarantees (funcall block-cl :guarantees))
                     (assurances (funcall block-cl :assurances))
                     ;; Check rho
                     (rho (funcall pre-sigma :load :rho))
                     (assignments (funcall rho :assignments))
                     (n-assigned (count-if #'identity assignments)))
                (format t "~%[~A] slot=~D guar=~D assur=~D cores-assigned=~D"
                        step slot (length guarantees) (length assurances) n-assigned)
                (when iota-changed (format t " *** IOTA CHANGED ***"))
                (when kappa-changed (format t " *** KAPPA CHANGED ***"))
                (format t "~%")
                ;; Show first few bytes of iota for comparison
                (format t "  iota[0..8]: ~{~2,'0X~}~%"
                        (coerce (subseq iota-bytes 0 (min 8 (length iota-bytes))) 'list))
                (format t "  kappa[0..8]: ~{~2,'0X~}~%"
                        (coerce (subseq kappa-bytes 0 (min 8 (length kappa-bytes))) 'list))
                ;; Show which cores have assignments and their timeouts
                (loop for a in assignments for i from 0 do
                  (when a
                    (let* ((report (getf a :report))
                           (timeout (getf a :timeout))
                           (pkg-hash (getf (getf report :package-spec) :hash)))
                      (format t "  core[~D] pkg=~{~2,'0X~} timeout=~D~%"
                              i (coerce (subseq pkg-hash 0 8) 'list) timeout))))
                (setf prev-iota-bytes iota-bytes
                      prev-kappa-bytes kappa-bytes)))))))))

(dih-run "1766479507_7943")
(sb-ext:exit :code 0)
