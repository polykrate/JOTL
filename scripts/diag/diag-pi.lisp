;;;; diag/diag-pi.lisp — Diagnose PI-only divergence in polkajam traces
;;;;
;;;; Usage: sbcl --load scripts/load-jotl.lisp --load scripts/diag/diag-pi.lisp
;;;;
;;;; Replays a specific trace step and compares PI sub-fields:
;;;;   π_V (validator stats), π_L (last epoch stats),
;;;;   π_C (core stats), π_S (service stats)

(in-package :jotl)

(defvar *dp-trace-id* "1767895984_7922")
(defvar *dp-step* "00000061")

(defun dp-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dp-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dp-hex (bytes &optional (n 16))
  (with-output-to-string (s)
    (dotimes (i (min n (length bytes)))
      (format s "~2,'0X " (aref bytes i)))))

(defun dp-decode-pi-sections (bytes)
  "Decode PI binary into (values pi_V-bytes pi_L-bytes pi_C-bytes pi_S-bytes).
   π_V and π_L are V × 6 × u32 = V × 24 bytes each.
   π_C is C × 8 compact fields.  π_S is compact-prefixed."
  (let* ((v (num-validators))
         (rec-size (* 6 4))  ; 6 × u32
         (pv-size (* v rec-size))
         (pl-start pv-size)
         (pl-end (+ pl-start pv-size))
         (pos pl-end))
    ;; Skip π_C: C records × 8 compact fields
    (dotimes (ci (num-cores))
      (dotimes (fi 8)
        (multiple-value-bind (_v consumed) (decode-compact bytes pos)
          (declare (ignore _v))
          (incf pos consumed))))
    (let ((pc-end pos))
      ;; π_S starts here
      (multiple-value-bind (svc-count svc-len-consumed) (decode-compact bytes pos)
        (let ((ps-start pos))
          (incf pos svc-len-consumed)
          ;; Skip service entries: sid(4) + 10 compact fields each
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

(defun dp-decode-validator-record (bytes offset)
  "Decode one validator record (6 × u32) from BYTES at OFFSET."
  (list :blocks         (decode-u32 bytes offset)
        :tickets        (decode-u32 bytes (+ offset 4))
        :preimages      (decode-u32 bytes (+ offset 8))
        :preimages-size (decode-u32 bytes (+ offset 12))
        :guarantees     (decode-u32 bytes (+ offset 16))
        :assurances     (decode-u32 bytes (+ offset 20))))

(defun dp-decode-services-section (bytes)
  "Decode π_S section: compact-count + entries (sid + 10 compact fields)."
  (let ((pos 0))
    (multiple-value-bind (svc-count consumed) (decode-compact bytes pos)
      (incf pos consumed)
      (let ((services '()))
        (dotimes (si svc-count)
          (let ((sid (decode-u32 bytes pos)))
            (incf pos 4)
            (let ((fields '()))
              (dotimes (fi 10)
                (multiple-value-bind (val consumed) (decode-compact bytes pos)
                  (push val fields)
                  (incf pos consumed)))
              (push (cons sid (nreverse fields)) services))))
        (nreverse services)))))

(defun dp-run ()
  "Run PI diagnostic on the configured trace step."
  (format t "~%=== PI DIAGNOSTIC ===~%")
  (format t "Trace: ~A  Step: ~A~%" *dp-trace-id* *dp-step*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dp-step*)
                                     (dp-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root post-root))

      (let ((expected-pi (funcall post-sigma :segment :pi)))
        (format t "Expected PI: ~D bytes~%" (length expected-pi))

        ;; Apply block
        (let* ((ts (funcall (funcall block-cl :header) :timeslot))
               (ep-dur (epoch-duration)))
          (format t "Block timeslot: ~D (epoch ~D, phase ~D)~%"
                  ts (floor ts ep-dur) (mod ts ep-dur))
          (format t "Author: ~D~%" (funcall (funcall block-cl :header) :author-index)))

        (handler-case
            (let* ((*chain-log-level* nil)
                   (sigma-prime (import-block pre-sigma block-cl))
                   (computed-pi (funcall sigma-prime :segment :pi)))
              (format t "Computed PI: ~D bytes~%" (length computed-pi))

              (if (equalp computed-pi expected-pi)
                  (format t "~%RESULT: PI MATCH~%")
                  (progn
                    (format t "~%RESULT: PI MISMATCH~%")

                    ;; Decode sections
                    (multiple-value-bind (c-pv c-pl c-pc c-ps c-svc-count)
                        (dp-decode-pi-sections computed-pi)
                      (multiple-value-bind (e-pv e-pl e-pc e-ps e-svc-count)
                          (dp-decode-pi-sections expected-pi)

                        ;; ── π_V ──
                        (if (equalp c-pv e-pv)
                            (format t "  π_V: OK~%")
                            (progn
                              (format t "  π_V: DIVERGE~%")
                              (dotimes (vi (num-validators))
                                (let* ((off (* vi 24))
                                       (c-rec (dp-decode-validator-record c-pv off))
                                       (e-rec (dp-decode-validator-record e-pv off)))
                                  (unless (equal c-rec e-rec)
                                    (format t "    v~D: computed=~S~%" vi c-rec)
                                    (format t "    v~D: expected=~S~%" vi e-rec))))))

                        ;; ── π_L ──
                        (if (equalp c-pl e-pl)
                            (format t "  π_L: OK~%")
                            (progn
                              (format t "  π_L: DIVERGE~%")
                              (dotimes (vi (num-validators))
                                (let* ((off (* vi 24))
                                       (c-rec (dp-decode-validator-record c-pl off))
                                       (e-rec (dp-decode-validator-record e-pl off)))
                                  (unless (equal c-rec e-rec)
                                    (format t "    v~D: computed=~S~%" vi c-rec)
                                    (format t "    v~D: expected=~S~%" vi e-rec))))))

                        ;; ── π_C ──
                        (if (equalp c-pc e-pc)
                            (format t "  π_C: OK~%")
                            (format t "  π_C: DIVERGE (c=~D bytes e=~D bytes)~%"
                                    (length c-pc) (length e-pc)))

                        ;; ── π_S ──
                        (if (equalp c-ps e-ps)
                            (format t "  π_S: OK~%")
                            (progn
                              (format t "  π_S: DIVERGE (c-count=~D e-count=~D)~%"
                                      c-svc-count e-svc-count)
                              ;; Decode and compare service entries
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
                                         nil) ;; same
                                        ((and c-entry e-entry)
                                         (format t "    sid ~D: computed=~S~%"
                                                 sid (cdr c-entry))
                                         (format t "    sid ~D: expected=~S~%"
                                                 sid (cdr e-entry))
                                         ;; Show field names
                                         (let ((fields '(:provided-count :provided-size
                                                         :refinement-count :refinement-gas
                                                         :imports :extrinsic-count
                                                         :extrinsic-size :exports
                                                         :accumulate-count :accumulate-gas)))
                                           (loop for cf in (cdr c-entry)
                                                 for ef in (cdr e-entry)
                                                 for fn in fields
                                                 unless (= cf ef)
                                                 do (format t "      ~A: c=~D e=~D (Δ=~D)~%"
                                                            fn cf ef (- cf ef)))))
                                        (c-entry
                                         (format t "    sid ~D: EXTRA in computed~%" sid))
                                        (e-entry
                                         (format t "    sid ~D: MISSING in computed~%" sid)))))))))))))
              (error (err) (format t "~%ERROR: ~A~%" err)))))))

  (format t "~%=== END PI DIAGNOSTIC ===~%"))

;; Run on both traces
(dp-run)

(setf *dp-trace-id* "1767896003_7770"
      *dp-step* "00000033")
(dp-run)
