;;; diag-pvm-trap-trace.lisp — Trace last 50 PVM instructions before trap
;;; Focus on branching decisions and register values near PC=97133
(in-package #:jotl)

(defvar *ring-buf* nil)
(defvar *ring-idx* 0)
(defvar *ring-size* 2000)
(defvar *target-sid* 0)

(defun dtt-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dtt-run (trace-id step)
  (format t "~%=== PVM TRAP TRACE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dtt-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :slot)))

      (let ((orig-vm-step (fdefinition 'jamvm:vm-step))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch))
            (orig-accum-svc (fdefinition 'accumulate-service)))

        (unwind-protect
             (progn
               ;; Intercept vm-step to record instructions
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (when *ring-buf*
                         (let ((pc (jamvm:pvm-pc vm)))
                           (setf jamvm:*vm-last-step-pc* pc)
                           (handler-case
                               (multiple-value-bind (info skip args)
                                   (jamvm:decode-instruction vm pc)
                                 (declare (ignore args))
                                 (let ((entry (vector
                                               pc
                                               (jamvm:pvm-gas vm)
                                               (if info (jamvm::opi-name info) :unknown)
                                               skip
                                               ;; All 13 registers
                                               (jamvm:reg vm 0)   ;; ra
                                               (jamvm:reg vm 1)   ;; sp
                                               (jamvm:reg vm 2)   ;; t0
                                               (jamvm:reg vm 3)   ;; t1
                                               (jamvm:reg vm 4)   ;; t2
                                               (jamvm:reg vm 5)   ;; s0
                                               (jamvm:reg vm 6)   ;; s1
                                               (jamvm:reg vm 7)   ;; a0
                                               (jamvm:reg vm 8)   ;; a1
                                               (jamvm:reg vm 9)   ;; a2
                                               (jamvm:reg vm 10)  ;; a3
                                               (jamvm:reg vm 11)  ;; a4
                                               (jamvm:reg vm 12)  ;; a5
                                               )))
                                   (setf (aref *ring-buf* (mod *ring-idx* *ring-size*)) entry)
                                   (incf *ring-idx*)))
                             (error () nil))))
                       (funcall orig-vm-step vm)))

               ;; Intercept host-dispatch for HC logging
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (when (and *ring-buf* (= sid *target-sid*))
                           (let ((entry (vector
                                         (or jamvm:*vm-last-step-pc* 0)
                                         (jamvm:pvm-gas vm)
                                         (format nil "HC~D" id)
                                         0
                                         (jamvm:reg vm 0) (jamvm:reg vm 1)
                                         (jamvm:reg vm 2) (jamvm:reg vm 3)
                                         (jamvm:reg vm 4) (jamvm:reg vm 5)
                                         (jamvm:reg vm 6) (jamvm:reg vm 7)
                                         (jamvm:reg vm 8) (jamvm:reg vm 9)
                                         (jamvm:reg vm 10) (jamvm:reg vm 11)
                                         (jamvm:reg vm 12))))
                             (setf (aref *ring-buf* (mod *ring-idx* *ring-size*)) entry)
                             (incf *ring-idx*)))
                         (funcall orig-dispatch vm ctx id))))

               ;; Wrap accumulate-service
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (if (= sid *target-sid*)
                           (progn
                             (setf *ring-buf* (make-array *ring-size* :initial-element nil)
                                   *ring-idx* 0)
                             (multiple-value-bind (effects gas-used)
                                 (funcall orig-accum-svc sid items gas-limit state
                                          :transfer-balance transfer-balance
                                          :svc-transfers svc-transfers)

                               ;; Print last 50 instructions before trap
                               (format t "~%--- RESULT: outcome=~A gas-used=~D last-pc=~A ---~%"
                                       (when effects (getf effects :outcome))
                                       gas-used jamvm:*vm-last-step-pc*)
                               (format t "Total instructions: ~D~%" *ring-idx*)

                               ;; Print instructions around HC19 (last "boot") through trap
                               ;; Look for instructions near PC 97028..97133
                               (let ((show-start (max 0 (- *ring-idx* 50))))
                                 (format t "~%Last 50 instructions:~%")
                                 (loop for abs-i from show-start below *ring-idx*
                                       do (let ((e (aref *ring-buf* (mod abs-i *ring-size*))))
                                            (when e
                                              (format t "[~6D] pc=~6D gas=~8D ~15A ra=~D sp=~D t0=~D t1=~D t2=~D s0=~D s1=~D a0=~D a1=~D a2=~D a3=~D a4=~D a5=~D~%"
                                                      abs-i
                                                      (aref e 0) (aref e 1) (aref e 2)
                                                      (aref e 4) (aref e 5)
                                                      (aref e 6) (aref e 7) (aref e 8)
                                                      (aref e 9) (aref e 10)
                                                      (aref e 11) (aref e 12) (aref e 13)
                                                      (aref e 14) (aref e 15) (aref e 16))))))

                               ;; Also print instructions around the last HC19 (search backward for HC100)
                               (format t "~%Instructions around last HC calls:~%")
                               (let* ((hc-positions nil))
                                 ;; Find all HC positions
                                 (let ((scan-start (max 0 (- *ring-idx* *ring-size*))))
                                   (loop for abs-i from scan-start below *ring-idx*
                                         do (let ((e (aref *ring-buf* (mod abs-i *ring-size*))))
                                              (when (and e (stringp (aref e 2))
                                                         (search "HC" (aref e 2)))
                                                (push abs-i hc-positions)))))
                                 (setf hc-positions (nreverse hc-positions))
                                 (format t "HC call positions: ~{~D~^ ~}~%" hc-positions)
                                 ;; Show instructions around last 3 HC calls
                                 (when (>= (length hc-positions) 3)
                                   (let ((start-pos (nth (- (length hc-positions) 3) hc-positions)))
                                     (format t "~%From HC call at position ~D:~%" start-pos)
                                     (loop for abs-i from (max 0 (- start-pos 5)) below *ring-idx*
                                           do (let ((e (aref *ring-buf* (mod abs-i *ring-size*))))
                                                (when e
                                                  (format t "[~6D] pc=~6D gas=~8D ~15A a0=~D a1=~D a2=~D s0=~D s1=~D t0=~D~%"
                                                          abs-i
                                                          (aref e 0) (aref e 1) (aref e 2)
                                                          (aref e 11) (aref e 12) (aref e 13)
                                                          (aref e 9) (aref e 10)
                                                          (aref e 6))))))))

                               (setf *ring-buf* nil)
                               (values effects gas-used)))
                           (funcall orig-accum-svc sid items gas-limit state
                                    :transfer-balance transfer-balance
                                    :svc-transfers svc-transfers))))

               ;; Run
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))

          ;; Restore
          (setf (fdefinition 'jamvm:vm-step) orig-vm-step)
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch)
          (setf (fdefinition 'accumulate-service) orig-accum-svc))))))

(dtt-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
