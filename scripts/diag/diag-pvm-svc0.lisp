;;; diag-pvm-svc0.lisp — Deep PVM trace for privileged service 0
;;; Goal: find WHY the PVM panics (trap@97133) instead of halting
;;; Strategy: log all HC calls with full regs + ring buffer of last N instructions
;;; Also dump the code bytes around the trap instruction

(in-package #:jotl)

(defvar *ring-buf* nil)
(defvar *ring-idx* 0)
(defvar *ring-size* 500)
(defvar *target-sid* 0)
(defvar *hc-log* nil)

(defun svc0-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun svc0-run (trace-id step)
  (format t "~%=== PVM SVC0 TRACE: ~A / ~A ===~%" trace-id step)
  (let* ((dir (svc0-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Block info
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D  Author: ~D~%"
                (funcall header :slot) (funcall header :author-index)))

      ;; Pre-state chi
      (let ((chi (funcall pre-sigma :load :chi)))
        (format t "χ: manager=~D designate=~D always-accum=~A~%"
                (funcall chi :manager)
                (funcall chi :designate)
                (funcall chi :always-accum)))

      ;; Wrap host-dispatch to log HC calls for service 0
      (let ((orig-dispatch (fdefinition 'jam-host::host-dispatch))
            (orig-vm-step  (fdefinition 'jamvm:vm-step)))

        (unwind-protect
             (progn
               ;; Intercept host-dispatch
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (if (= sid *target-sid*)
                             (let* ((gas-before (jamvm:pvm-gas vm))
                                    (pc-before jamvm:*vm-last-step-pc*)
                                    ;; Read a0-a5 (register indices 7-12)
                                    (regs-before (list (jamvm:reg vm jamvm:+a0+)
                                                       (jamvm:reg vm jamvm:+a1+)
                                                       (jamvm:reg vm jamvm:+a2+)
                                                       (jamvm:reg vm jamvm:+a3+)
                                                       (jamvm:reg vm jamvm:+a4+)
                                                       (jamvm:reg vm jamvm:+a5+)))
                                    (result (funcall orig-dispatch vm ctx id))
                                    (gas-after (jamvm:pvm-gas vm))
                                    (regs-after (list (jamvm:reg vm jamvm:+a0+)
                                                       (jamvm:reg vm jamvm:+a1+)
                                                       (jamvm:reg vm jamvm:+a2+)
                                                       (jamvm:reg vm jamvm:+a3+)
                                                       (jamvm:reg vm jamvm:+a4+)
                                                       (jamvm:reg vm jamvm:+a5+))))
                               (push (list :hc id :pc pc-before
                                           :gas-before gas-before :gas-after gas-after
                                           :regs-before regs-before
                                           :regs-after regs-after
                                           :result result)
                                     *hc-log*)
                               result)
                             (funcall orig-dispatch vm ctx id)))))

               ;; Intercept vm-step to record ring buffer for service 0
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (when *ring-buf*
                         (let ((entry (vector (jamvm:pvm-pc vm)
                                             (jamvm:pvm-gas vm)
                                             (jamvm:reg vm jamvm:+a0+)
                                             (jamvm:reg vm jamvm:+a1+)
                                             (jamvm:reg vm jamvm:+a2+))))
                           (setf (aref *ring-buf* (mod *ring-idx* *ring-size*)) entry)
                           (incf *ring-idx*)))
                       (setf jamvm:*vm-last-step-pc* (jamvm:pvm-pc vm))
                       (funcall orig-vm-step vm)))

               ;; Wrap accumulate-service for service 0
               (let ((orig-accum-svc (fdefinition 'accumulate-service)))
                 (unwind-protect
                      (progn
                        (setf (fdefinition 'accumulate-service)
                              (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                                (if (= sid *target-sid*)
                                    (progn
                                      (setf *ring-buf* (make-array *ring-size* :initial-element nil)
                                            *ring-idx* 0
                                            *hc-log* nil)
                                      (format t "~%[ACCUM-SVC] sid=~D items=~D gas=~D xfer-bal=~D~%"
                                              sid (length items) gas-limit transfer-balance)
                                      (multiple-value-bind (effects gas-used)
                                          (funcall orig-accum-svc sid items gas-limit state
                                                   :transfer-balance transfer-balance
                                                   :svc-transfers svc-transfers)
                                        ;; Report outcome
                                        (format t "~%--- RESULT: outcome=~A gas-used=~D last-pc=~A ---~%"
                                                (when effects (getf effects :outcome))
                                                gas-used jamvm:*vm-last-step-pc*)

                                        ;; HC log (chronological)
                                        (let ((hcs (reverse *hc-log*)))
                                          (format t "~%  Host calls (~D):~%" (length hcs))
                                          (loop for hc in hcs
                                                for n from 1
                                                do (format t "  [~2D] HC~D @pc=~D  gas:~D→~D (Δ=~D)~%"
                                                           n (getf hc :hc) (getf hc :pc)
                                                           (getf hc :gas-before) (getf hc :gas-after)
                                                           (- (getf hc :gas-before) (getf hc :gas-after)))
                                                   (format t "        IN:  a0=~D a1=~D a2=~D a3=~D a4=~D a5=~D~%"
                                                           (nth 0 (getf hc :regs-before))
                                                           (nth 1 (getf hc :regs-before))
                                                           (nth 2 (getf hc :regs-before))
                                                           (nth 3 (getf hc :regs-before))
                                                           (nth 4 (getf hc :regs-before))
                                                           (nth 5 (getf hc :regs-before)))
                                                   (format t "        OUT: a0=~D a1=~D a2=~D a3=~D a4=~D a5=~D~%"
                                                           (nth 0 (getf hc :regs-after))
                                                           (nth 1 (getf hc :regs-after))
                                                           (nth 2 (getf hc :regs-after))
                                                           (nth 3 (getf hc :regs-after))
                                                           (nth 4 (getf hc :regs-after))
                                                           (nth 5 (getf hc :regs-after)))))

                                        ;; Ring buffer: last instructions before end
                                        (let ((total (min *ring-idx* *ring-size*))
                                              (start (max 0 (- *ring-idx* *ring-size*))))
                                          (format t "~%  Total instructions: ~D~%" *ring-idx*)
                                          ;; Show last 50 instructions
                                          (let ((show-start (max start (- *ring-idx* 50))))
                                            (format t "  Last ~D instructions:~%" (- *ring-idx* show-start))
                                            (loop for abs-i from show-start below *ring-idx*
                                                  do (let ((entry (aref *ring-buf* (mod abs-i *ring-size*))))
                                                       (when entry
                                                         (format t "    [~6D] pc=~6D gas=~8D a0=~D a1=~D a2=~D~%"
                                                                 abs-i
                                                                 (aref entry 0) (aref entry 1)
                                                                 (aref entry 2) (aref entry 3) (aref entry 4)))))))

                                        (setf *ring-buf* nil)
                                        (values effects gas-used)))
                                    (funcall orig-accum-svc sid items gas-limit state
                                             :transfer-balance transfer-balance
                                             :svc-transfers svc-transfers))))

                        ;; Run
                        (let ((*chain-log-level* nil)
                              (*debug-pvm-trace* nil))
                          (import-block pre-sigma block-cl)))

                   ;; Restore accumulate-service
                   (setf (fdefinition 'accumulate-service) orig-accum-svc))))

          ;; Restore host-dispatch + vm-step
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch)
          (setf (fdefinition 'jamvm:vm-step) orig-vm-step))))))

;; Run on IOTA+PI+DELTA-KVS trace
(svc0-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
