;;; diag-pvm-panic.lisp — Trace PVM execution near panic point
;;; Captures last N instructions with ALL registers before panic.

(in-package #:jotl)

(defvar *ring-buf* nil)
(defvar *ring-idx* 0)
(defvar *ring-size* 100)
(defvar *hc-log* nil "Host call log: list of (hc-id gas-before gas-after regs-before regs-after)")

(defun ring-push (entry)
  (setf (aref *ring-buf* (mod *ring-idx* *ring-size*)) entry)
  (incf *ring-idx*))

(defun ring-dump (&optional (n *ring-size*))
  (let ((start (max 0 (- *ring-idx* n)))
        (end *ring-idx*))
    (loop for i from start below end
          for entry = (aref *ring-buf* (mod i *ring-size*))
          do (format t "  ~A~%" entry))))

(defun dp-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dp-run (trace-id step target-sid)
  (format t "~%=== PVM PANIC TRACE: ~A / ~A (sid=~D) ===~%" trace-id step target-sid)
  (let* ((dir (dp-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      (let ((orig-accum-svc (fdefinition 'accumulate-service))
            (orig-vm-step   (fdefinition 'jamvm:vm-step))
            (orig-dispatch  (fdefinition 'jam-host::host-dispatch)))
        (unwind-protect
             (progn
               ;; Wrap vm-step: ring buffer with ALL regs
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (when *ring-buf*
                         (let* ((pc (jamvm:pvm-pc vm))
                                (gas (jamvm:pvm-gas vm))
                                (code (jamvm:pvm-code vm))
                                (raw (if (< pc (length code)) (aref code pc) 255))
                                (regs (copy-seq (jamvm:pvm-regs vm))))
                           (ring-push (list pc raw gas regs))))
                       (funcall orig-vm-step vm)))

               ;; Wrap host-dispatch: log HC details
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (if *ring-buf*
                           (let ((gas-before (jamvm:pvm-gas vm))
                                 (regs-before (copy-seq (jamvm:pvm-regs vm))))
                             (let ((result (funcall orig-dispatch vm ctx id)))
                               (push (list :hc id
                                           :gas-before gas-before
                                           :gas-after (jamvm:pvm-gas vm)
                                           :regs-before regs-before
                                           :regs-after (copy-seq (jamvm:pvm-regs vm)))
                                     *hc-log*)
                               result))
                           (funcall orig-dispatch vm ctx id))))

               ;; Wrap accumulate-service for target
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (if (= sid target-sid)
                           (progn
                             (format t "~%[TARGET] sid=~D gas=~D items=~D~%" sid gas-limit (length items))
                             (setf *ring-buf* (make-array *ring-size* :initial-element nil)
                                   *ring-idx* 0
                                   *hc-log* nil)
                             (multiple-value-bind (effects gas-used)
                                 (funcall orig-accum-svc sid items gas-limit state
                                          :transfer-balance transfer-balance
                                          :svc-transfers svc-transfers)
                               (format t "  outcome=~D gas-used=~D last-pc=~A~%"
                                       (if effects (getf effects :outcome) -1)
                                       gas-used
                                       jamvm:*vm-last-step-pc*)

                               ;; Dump host calls
                               (format t "~%  Host calls (~D total):~%" (length *hc-log*))
                               (dolist (hc (reverse *hc-log*))
                                 (let ((id (getf hc :hc))
                                       (gb (getf hc :gas-before))
                                       (ga (getf hc :gas-after))
                                       (rb (getf hc :regs-before))
                                       (ra (getf hc :regs-after)))
                                   (format t "    HC~D gas:~D→~D a0:~D→~D a1:~D→~D a2:~D→~D~%"
                                           id gb ga
                                           (aref rb 7) (aref ra 7)   ;; a0
                                           (aref rb 8) (aref ra 8)   ;; a1
                                           (aref rb 9) (aref ra 9))))  ;; a2

                               ;; Dump last instructions
                               (format t "~%  Last ~D instructions:~%"
                                       (min *ring-idx* *ring-size*))
                               (let ((start (max 0 (- *ring-idx* 40)))
                                     (end *ring-idx*))
                                 (loop for i from start below end
                                       for entry = (aref *ring-buf* (mod i *ring-size*))
                                       when entry do
                                       (destructuring-bind (pc raw gas regs) entry
                                         (format t "  pc=~6D op=~3D gas=~D regs=[~{~D~^ ~}]~%"
                                                 pc raw gas (coerce regs 'list)))))

                               (setf *ring-buf* nil)
                               (values effects gas-used)))
                           (funcall orig-accum-svc sid items gas-limit state
                                    :transfer-balance transfer-balance
                                    :svc-transfers svc-transfers))))

               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))

          (setf (fdefinition 'accumulate-service) orig-accum-svc
                (fdefinition 'jamvm:vm-step) orig-vm-step
                (fdefinition 'jam-host::host-dispatch) orig-dispatch))))))

;; Trace sid=3953987607
(dp-run "1768066437_3920" "00000012" 3953987607)

(sb-ext:exit :code 0)
