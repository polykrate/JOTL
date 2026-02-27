;;;; diag/diag-pi2b.lisp — Show byte diff in trace 2 PI

(in-package :jotl)

(defun dp-decode-pi-sections (bytes)
  "Decode PI binary into (values pi_V-bytes pi_L-bytes pi_C-bytes pi_S-bytes svc-count)."
  (let* ((v (num-validators))
         (rec-size (* 6 4))
         (pv-size (* v rec-size))
         (pl-start pv-size)
         (pl-end (+ pl-start pv-size))
         (pos pl-end))
    (dotimes (ci (num-cores))
      (dotimes (fi 8)
        (multiple-value-bind (_v consumed) (decode-compact bytes pos)
          (declare (ignore _v))
          (incf pos consumed))))
    (let ((pc-end pos))
      (multiple-value-bind (svc-count svc-len-consumed) (decode-compact bytes pos)
        (let ((ps-start pos))
          (incf pos svc-len-consumed)
          (dotimes (si svc-count)
            (incf pos 4)
            (dotimes (fi 10)
              (multiple-value-bind (_v consumed) (decode-compact bytes pos)
                (declare (ignore _v))
                (incf pos consumed))))
          (values (subseq bytes 0 pv-size)
                  (subseq bytes pl-start pl-end)
                  (subseq bytes pl-end pc-end)
                  (subseq bytes ps-start pos)
                  svc-count))))))

(defun dp-decode-services-section (bytes)
  "Decode π_S section into list of (sid . (field-values))."
  (let ((pos 0) (result nil))
    (multiple-value-bind (svc-count consumed) (decode-compact bytes pos)
      (incf pos consumed)
      (dotimes (si svc-count)
        (let ((sid (logior (aref bytes pos)
                           (ash (aref bytes (+ pos 1)) 8)
                           (ash (aref bytes (+ pos 2)) 16)
                           (ash (aref bytes (+ pos 3)) 24))))
          (incf pos 4)
          (let ((fields nil))
            (dotimes (fi 10)
              (multiple-value-bind (val consumed) (decode-compact bytes pos)
                (push val fields)
                (incf pos consumed)))
            (push (cons sid (nreverse fields)) result)))))
    (nreverse result)))

(defun dp2b-run ()
  (let* ((trace-id "1767896003_7770") (step "00000033")
         (dir (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
                              (truename (asdf:system-source-directory :jotl))))
         (bytes (alexandria:read-file-into-byte-vector (merge-pathnames (format nil "~A.bin" step) dir))))
    (multiple-value-bind (pre-sigma block-cl post-sigma) (decode-trace-step-bin bytes)
      (let* ((epi (funcall post-sigma :segment :pi))
             (*chain-log-level* nil) (*debug-pvm-trace* nil)
             (sp (import-block pre-sigma block-cl))
             (cpi (funcall sp :segment :pi)))

        ;; Decode sections
        (multiple-value-bind (c-pv c-pl c-pc c-ps c-svc) (dp-decode-pi-sections cpi)
          (multiple-value-bind (e-pv e-pl e-pc e-ps e-svc) (dp-decode-pi-sections epi)
            (format t "pi_V: ~A~%" (if (equalp c-pv e-pv) "OK" "DIFF"))
            (format t "pi_L: ~A~%" (if (equalp c-pl e-pl) "OK" "DIFF"))
            (format t "pi_C: ~A~%" (if (equalp c-pc e-pc) "OK" "DIFF"))
            (format t "pi_S: ~A (c-svcs=~D e-svcs=~D)~%" (if (equalp c-ps e-ps) "OK" "DIFF") c-svc e-svc)

            (when (not (equalp c-ps e-ps))
              (let ((c-svcs (dp-decode-services-section c-ps))
                    (e-svcs (dp-decode-services-section e-ps)))
                (let ((fields '(:prov-count :prov-size :refine-count :refine-gas
                                :imports :ext-count :ext-size :exports
                                :accum-count :accum-gas)))
                  (let ((all-sids (remove-duplicates
                                   (append (mapcar #'car c-svcs) (mapcar #'car e-svcs)))))
                    (dolist (sid (sort all-sids #'<))
                      (let ((c-entry (assoc sid c-svcs))
                            (e-entry (assoc sid e-svcs)))
                        (cond
                          ((and c-entry e-entry (equal (cdr c-entry) (cdr e-entry)))
                           nil)
                          ((and c-entry e-entry)
                           (loop for cf in (cdr c-entry)
                                 for ef in (cdr e-entry)
                                 for fn in fields
                                 unless (= cf ef)
                                 do (format t "  sid ~D ~A: c=~D e=~D (Δ=~D)~%"
                                            sid fn cf ef (- cf ef))))
                          (c-entry
                           (format t "  sid ~D: EXTRA~%" sid))
                          (e-entry
                           (format t "  sid ~D: MISSING~%" sid)))))))))))))))



(dp2b-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
