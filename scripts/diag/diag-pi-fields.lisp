;;;; diag/diag-pi-fields.lisp — Count fields per service in expected PI

(in-package :jotl)

(defvar *dpf-trace-id* "1767895984_7922")
(defvar *dpf-step* "00000061")

(defun dpf-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dpf-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dpf-run ()
  (format t "~%=== PI FIELDS DIAGNOSTIC ===~%")
  (format t "Trace: ~A  Step: ~A~%" *dpf-trace-id* *dpf-step*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dpf-step*)
                                     (dpf-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-sigma block-cl pre-root post-root))

      ;; Get expected PI from post-state
      (let ((pi-bytes (funcall post-sigma :segment :pi)))
        (format t "Total PI bytes: ~D~%" (length pi-bytes))

        ;; Skip π_V (V × 24 bytes) and π_L (V × 24 bytes)
        (let* ((v (num-validators))
               (rec-size (* 6 4))
               (pos (* 2 v rec-size)))
          (format t "After π_V + π_L: pos=~D~%" pos)

          ;; Skip π_C: C records × 8 compact fields each
          (dotimes (ci (num-cores))
            (dotimes (fi 8)
              (multiple-value-bind (_v consumed) (decode-compact pi-bytes pos)
                (declare (ignore _v))
                (incf pos consumed))))
          (format t "After π_C: pos=~D~%" pos)

          ;; Now decode π_S carefully
          ;; Read service count
          (multiple-value-bind (svc-count svc-len-consumed) (decode-compact pi-bytes pos)
            (format t "~%π_S starts at pos=~D, service-count=~D (consumed ~D bytes)~%"
                    pos svc-count svc-len-consumed)
            (incf pos svc-len-consumed)

            ;; For each service, read sid(4) + N compact fields
            ;; Don't assume 10 fields — count them by seeing how many
            ;; compacts fit before the next SID or end
            (dotimes (si svc-count)
              (let ((sid (decode-u32 pi-bytes pos))
                    (fields '())
                    (field-start (+ pos 4)))
                (incf pos 4)
                ;; Try reading fields — we'll read as many as possible
                ;; up to a reasonable limit (20)
                ;; Actually, let's just try reading exactly 10 and 12
                ;; fields and see which gets us to the right position
                (let ((pos-10 pos)
                      (pos-12 pos)
                      (fields-10 '())
                      (fields-12 '()))
                  ;; Read 10 fields
                  (dotimes (fi 10)
                    (multiple-value-bind (val consumed) (decode-compact pi-bytes pos-10)
                      (push val fields-10)
                      (incf pos-10 consumed)))
                  ;; Read 12 fields from same start
                  (let ((p12 (- pos-10 0)))
                    (setf pos-12 pos)
                    (dotimes (fi 12)
                      (when (< pos-12 (length pi-bytes))
                        (multiple-value-bind (val consumed) (decode-compact pi-bytes pos-12)
                          (push val fields-12)
                          (incf pos-12 consumed)))))

                  ;; Check: after 10 fields, does the next 4 bytes look like a SID?
                  (let ((next-sid-10 (when (< (+ pos-10 3) (length pi-bytes))
                                       (decode-u32 pi-bytes pos-10)))
                        (next-sid-12 (when (< (+ pos-12 3) (length pi-bytes))
                                       (decode-u32 pi-bytes pos-12))))
                    (format t "~%  sid[~D]=~D (~D)~%" si sid sid)
                    (format t "    10 fields: ~S~%" (nreverse fields-10))
                    (format t "    12 fields: ~S~%" (nreverse fields-12))
                    (format t "    pos-after-10=~D (next4=~D)  pos-after-12=~D (next4=~D)~%"
                            pos-10 next-sid-10 pos-12 next-sid-12)
                    (format t "    end-of-pi=~D~%" (length pi-bytes)))

                  ;; Advance with 10 fields (our current assumption)
                  (setf pos pos-10))))))))))

(dpf-run)
(sb-ext:exit :code 0)
