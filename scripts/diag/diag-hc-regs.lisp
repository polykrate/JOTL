;;;; diag/diag-hc-regs.lisp — Dump complete register state after each host call

(in-package :jotl)

(defvar *dhr-trace-id* "1767895984_7922")
(defvar *dhr-step* "00000061")
(defvar *dhr-target-sid* 3101749195)

(defun dhr-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dhr-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dhr-run ()
  (format t "~%=== HC REGISTER DIAGNOSTIC ===~%")

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dhr-step*)
                                     (dhr-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma pre-root post-root))

      ;; Enable debug trace and capture
      (let ((*debug-pvm-trace* t)
            (*debug-pvm-traces* nil)
            (*chain-log-level* nil))

        ;; Run the block
        (import-block pre-sigma block-cl)

        ;; Extract trace for target
        (dolist (trace (reverse *debug-pvm-traces*))
          (when (= (getf trace :sid) *dhr-target-sid*)
            (format t "~%=== Service ~D ===~%" *dhr-target-sid*)
            (format t "gas-limit=~D gas-used=~D~%"
                    (getf trace :gas-limit) (getf trace :gas-used))

            (let ((log (getf trace :host-call-log))
                  (prev-gas nil)
                  (hc-num 0))
              (dolist (entry log)
                (incf hc-num)
                (let ((id (getf entry :id))
                      (gb (getf entry :gas-before))
                      (ga (getf entry :gas-after))
                      (a0b (getf entry :a0-before))
                      (a1b (getf entry :a1-before))
                      (a2b (getf entry :a2-before))
                      (a3b (getf entry :a3-before))
                      (a4b (getf entry :a4-before))
                      (a5b (getf entry :a5-before))
                      (a0a (getf entry :a0-after))
                      (a1a (getf entry :a1-after))
                      (res (getf entry :result)))
                  (when prev-gas
                    (format t "  [~D instr gap]~%" (- prev-gas gb)))
                  (format t "HC#~2D id=~3D gas=~D→~D "
                          hc-num id gb ga)
                  (format t "A0=~D A1=~D A2=~D A3=~D A4=~D A5=~D → A0=~D A1=~D ~A~%"
                          a0b a1b a2b a3b a4b a5b a0a a1a res)
                  (setf prev-gas ga))))))))))

(dhr-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
