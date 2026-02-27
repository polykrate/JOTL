;;;; diag/diag-pi2.lisp — Compare PI for trace 2

(in-package :jotl)

(defun dp2-run ()
  (let* ((trace-id "1767896003_7770") (step "00000033")
         (dir (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
                              (truename (asdf:system-source-directory :jotl))))
         (bytes (alexandria:read-file-into-byte-vector (merge-pathnames (format nil "~A.bin" step) dir))))
    (multiple-value-bind (pre-sigma block-cl post-sigma) (decode-trace-step-bin bytes)
      (let* ((epi (funcall post-sigma :segment :pi))
             (*chain-log-level* nil)
             (*debug-pvm-trace* t)
             (*debug-pvm-traces* nil)
             (sp (import-block pre-sigma block-cl))
             (cpi (funcall sp :segment :pi)))
        (format t "len: c=~D e=~D~%" (length cpi) (length epi))

        ;; Find first diff byte
        (let ((first-diff nil))
          (dotimes (i (min (length cpi) (length epi)))
            (unless (= (aref cpi i) (aref epi i))
              (setf first-diff i)
              (return)))
          (when first-diff
            (format t "First diff at byte ~D~%" first-diff)
            (format t "  c[~D..~D]: " (max 0 (- first-diff 4)) (min (length cpi) (+ first-diff 12)))
            (loop for i from (max 0 (- first-diff 4)) below (min (length cpi) (+ first-diff 12))
                  do (format t "~2,'0X " (aref cpi i)))
            (format t "~%  e[~D..~D]: " (max 0 (- first-diff 4)) (min (length epi) (+ first-diff 12)))
            (loop for i from (max 0 (- first-diff 4)) below (min (length epi) (+ first-diff 12))
                  do (format t "~2,'0X " (aref epi i)))
            (terpri))

          ;; Count total diffs
          (let ((diff-count 0))
            (dotimes (i (min (length cpi) (length epi)))
              (unless (= (aref cpi i) (aref epi i))
                (incf diff-count)))
            (format t "Total diff bytes: ~D~%" diff-count))

          ;; Decode PI sections
          (multiple-value-bind (c-pv c-pl c-pc c-ps c-svc-count)
              (dp-decode-pi-sections cpi)
            (multiple-value-bind (e-pv e-pl e-pc e-ps e-svc-count)
                (dp-decode-pi-sections epi)
              (format t "~%PI sections:~%")
              (format t "  pi_V: ~A (c=~D e=~D)~%"
                      (if (equalp c-pv e-pv) "OK" "DIFF")
                      (length c-pv) (length e-pv))
              (format t "  pi_L: ~A (c=~D e=~D)~%"
                      (if (equalp c-pl e-pl) "OK" "DIFF")
                      (length c-pl) (length e-pl))
              (format t "  pi_C: ~A (c=~D e=~D)~%"
                      (if (equalp c-pc e-pc) "OK" "DIFF")
                      (length c-pc) (length e-pc))
              (format t "  pi_S: ~A (c=~D e=~D svcs c=~D e=~D)~%"
                      (if (equalp c-ps e-ps) "OK" "DIFF")
                      (length c-ps) (length e-ps) c-svc-count e-svc-count)

              ;; Detail service stats
              (when (not (equalp c-ps e-ps))
                (let ((c-svcs (dp-decode-services-section c-ps))
                      (e-svcs (dp-decode-services-section e-ps)))
                  (let ((all-sids (remove-duplicates
                                   (append (mapcar #'car c-svcs)
                                           (mapcar #'car e-svcs)))))
                    (dolist (sid (sort all-sids #'<))
                      (let ((c-entry (assoc sid c-svcs))
                            (e-entry (assoc sid e-svcs)))
                        (cond
                          ((and c-entry e-entry (equal (cdr c-entry) (cdr e-entry)))
                           nil)
                          ((and c-entry e-entry)
                           (let ((fields '(:provided-count :provided-size
                                           :refinement-count :refinement-gas
                                           :imports :extrinsic-count
                                           :extrinsic-size :exports
                                           :accumulate-count :accumulate-gas)))
                             (loop for cf in (cdr c-entry)
                                   for ef in (cdr e-entry)
                                   for fn in fields
                                   unless (= cf ef)
                                   do (format t "    sid ~D ~A: c=~D e=~D (delta=~D)~%"
                                              sid fn cf ef (- cf ef)))))
                          (c-entry
                           (format t "    sid ~D: EXTRA in computed~%" sid))
                          (e-entry
                           (format t "    sid ~D: MISSING in computed~%" sid)))))))))

          ;; Show HC traces
          (format t "~%HC traces per service:~%")
          (dolist (trace (reverse *debug-pvm-traces*))
            (format t "  sid=~D gas-limit=~D gas-used=~D HCs=~D~%"
                    (getf trace :sid) (getf trace :gas-limit)
                    (getf trace :gas-used) (length (getf trace :host-call-log))))))))))

(dp2-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
