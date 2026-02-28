;;; diag-missing-checkpoint.lisp — Trace PVM instructions between HC[18] and HC[19]
;;; Looking for a missing ecalli 17 (checkpoint) that JOTL skips
(in-package #:jotl)

(defvar *target-sid* 0)
(defvar *hc-counter* 0)
(defvar *trace-between* nil)
(defvar *inst-log* nil)

(defun dmc-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dmc-run (trace-id step)
  (format t "~%=== MISSING CHECKPOINT: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dmc-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (raw (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin raw)
      (declare (ignore post-sigma))
      (setf *hc-counter* 0
            *trace-between* nil
            *inst-log* nil)
      (let ((orig-step (fdefinition 'jamvm:vm-step))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch)))
        (unwind-protect
             (progn
               ;; Intercept vm-step to log instructions between HC18 and HC19
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (when *trace-between*
                         (let ((pc (jamvm:pvm-pc vm)))
                           (multiple-value-bind (info skip args)
                               (jamvm:decode-instruction vm pc)
                             (let ((name (if info (jamvm::opi-name info) :unknown))
                                   (imm (when args (jamvm::arg-imm args))))
                               (push (list pc name skip imm
                                          (jamvm:pvm-gas vm)
                                          (jamvm:reg vm jamvm:+a0+)
                                          (jamvm:reg vm jamvm:+a1+))
                                     *inst-log*)))))
                       (funcall orig-step vm)))
               ;; Intercept host-dispatch to track HC calls for svc 0
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (when (= sid *target-sid*)
                           (incf *hc-counter*)
                           ;; After HC[18], start tracing
                           (when (= *hc-counter* 18)
                             (format t "~%[HC ~D] = HC~D → start tracing PVM~%"
                                     *hc-counter* id)
                             (setf *trace-between* t
                                   *inst-log* nil))
                           ;; At HC[19], stop tracing and dump
                           (when (= *hc-counter* 19)
                             (setf *trace-between* nil)
                             (format t "[HC ~D] = HC~D~%" *hc-counter* id)
                             (let ((log (nreverse *inst-log*)))
                               (format t "~%Instructions between HC18 and HC19: ~D~%" (length log))
                               (dolist (entry log)
                                 (destructuring-bind (pc name skip imm gas a0 a1) entry
                                   (format t "  pc=~6D ~12A skip=~D imm=~A gas=~D a0=~D a1=~D~%"
                                           pc name skip imm gas a0 a1)))
                               ;; Check if any ecalli 17 (checkpoint)
                               (let ((has-cp (find-if (lambda (e)
                                                        (and (eq (second e) :ecalli)
                                                             (eql (fourth e) 17)))
                                                      log)))
                                 (if has-cp
                                     (format t "~%*** FOUND ecalli 17 (checkpoint) at pc=~D ***~%"
                                             (first has-cp))
                                     (format t "~%*** NO ecalli 17 (checkpoint) found ***~%"))))))
                         (funcall orig-dispatch vm ctx id))))
               (let ((*chain-log-level* nil) (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))
          (setf (fdefinition 'jamvm:vm-step) orig-step
                (fdefinition 'jam-host::host-dispatch) orig-dispatch))))))

(dmc-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
