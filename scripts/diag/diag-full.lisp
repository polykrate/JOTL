;;; diag-full.lisp — Why does HC4 return FULL?
;;; Trace the threshold computation for sid=3953987607

(in-package #:jotl)

(defvar *dt-target* 3953987607)

(defun dt-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dt-run (trace-id step)
  (format t "~%=== FULL-CHECK DIAG: ~A / ~A sid=~D ===~%" trace-id step *dt-target*)
  (let* ((dir (dt-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Wrap host-dispatch to log all HC3/HC4/HC5/HC23 for target
      (let ((orig-dispatch (fdefinition 'jam-host::host-dispatch))
            (hc-count 0))

        (unwind-protect
             (progn
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (if (= sid *dt-target*)
                             (progn
                               (incf hc-count)
                               ;; Log state before HC
                               (when (member id '(3 4 5 23))
                                 (format t "~%[HC~D #~D] items=~D footprint=~D threshold(a_f)=~D balance=~D~%"
                                         id hc-count
                                         (jam-host::hctx-items-count ctx)
                                         (jam-host::hctx-footprint ctx)
                                         (jam-host::hctx-threshold ctx)
                                         (jam-host::hctx-balance ctx))
                                 (let ((a-t (jam-host::compute-threshold
                                             (jam-host::hctx-items-count ctx)
                                             (jam-host::hctx-footprint ctx)
                                             (jam-host::hctx-threshold ctx))))
                                   (format t "  a_t=~D (B_S=100 + B_I*~D + B_L*~D - a_f=~D)~%"
                                           a-t
                                           (jam-host::hctx-items-count ctx)
                                           (jam-host::hctx-footprint ctx)
                                           (jam-host::hctx-threshold ctx)))
                                 (format t "  regs: a0=~D a1=~D a2=~D a3=~D a4=~D a5=~D~%"
                                         (jamvm:reg vm jamvm:+a0+) (jamvm:reg vm jamvm:+a1+)
                                         (jamvm:reg vm jamvm:+a2+) (jamvm:reg vm jamvm:+a3+)
                                         (jamvm:reg vm jamvm:+a4+) (jamvm:reg vm jamvm:+a5+)))
                               ;; Call original
                               (let ((result (funcall orig-dispatch vm ctx id)))
                                 ;; Log state after HC
                                 (when (member id '(3 4 5 23))
                                   (format t "  → a0=~D items=~D footprint=~D result=~A~%"
                                           (jamvm:reg vm jamvm:+a0+)
                                           (jam-host::hctx-items-count ctx)
                                           (jam-host::hctx-footprint ctx)
                                           result)
                                   ;; For HC4, also log the key
                                   (when (= id 4)
                                     (let ((a0-val (jamvm:reg vm jamvm:+a0+)))
                                       (when (= a0-val (ldb (byte 64 0) -5))
                                         (format t "  ** FULL! threshold exceeded **~%")))))
                                 result))
                             (funcall orig-dispatch vm ctx id)))))

               ;; Run
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))

          ;; Restore
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch))))))

(dt-run "1768066437_3920" "00000012")
(sb-ext:exit :code 0)
