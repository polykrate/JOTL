;;; diag-flow-detail.lisp — Trace instructions between HC100@41213 and HC3@95085
;;; to find the branch that skips HC17@41816
(in-package #:jotl)

(defvar *target-sid* 0)
;; We want to log instructions 99200..99450 (around the gap)
(defvar *log-start* 99200)
(defvar *log-end*   99450)
;; Also log instructions around the second HC100 (items loop)
;; And instructions 6250..6350 (around the items fetch)
(defvar *log-start2* 103380)
(defvar *log-end2*   103430)

(defun dfd-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun dfd-run (trace-id step)
  (format t "~%=== FLOW DETAIL: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dfd-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      (let ((orig-vm-step (fdefinition 'jamvm:vm-step))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch))
            (orig-accum-svc (fdefinition 'accumulate-service))
            (instruction-count 0)
            (logged-instrs nil))

        (unwind-protect
             (progn
               (setf (fdefinition 'jamvm:vm-step)
                     (lambda (vm)
                       (let ((pc (jamvm:pvm-pc vm)))
                         (setf jamvm:*vm-last-step-pc* pc)
                         (incf instruction-count)
                         (when (or (and (>= instruction-count *log-start*)
                                       (<= instruction-count *log-end*))
                                   (and (>= instruction-count *log-start2*)
                                        (<= instruction-count *log-end2*)))
                           (handler-case
                               (multiple-value-bind (info skip args)
                                   (jamvm:decode-instruction vm pc)
                                 (push (list instruction-count pc
                                             (if info (jamvm::opi-name info) :unknown)
                                             skip
                                             (jamvm:pvm-gas vm)
                                             ;; All registers for branch analysis
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
                                             ;; Immediate arg if relevant
                                             (when (and info (member (jamvm::opi-args info) '(:imm :imm-imm :offset :reg-imm)))
                                               (jamvm::arg-imm args)))
                                       logged-instrs))
                             (error () nil))))
                       (funcall orig-vm-step vm)))

               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let ((sid (jam-host::hctx-service-id ctx)))
                         (when (and (= sid *target-sid*)
                                    (or (and (>= instruction-count *log-start*)
                                             (<= instruction-count *log-end*))
                                        (and (>= instruction-count *log-start2*)
                                             (<= instruction-count *log-end2*))))
                           (push (list instruction-count
                                       (or jamvm:*vm-last-step-pc* 0)
                                       (format nil ">>>HC~D<<<" id)
                                       0 (jamvm:pvm-gas vm)
                                       (jamvm:reg vm 0) (jamvm:reg vm 1)
                                       (jamvm:reg vm 2) (jamvm:reg vm 3)
                                       (jamvm:reg vm 4) (jamvm:reg vm 5)
                                       (jamvm:reg vm 6) (jamvm:reg vm 7)
                                       (jamvm:reg vm 8) (jamvm:reg vm 9)
                                       (jamvm:reg vm 10) (jamvm:reg vm 11)
                                       (jamvm:reg vm 12) nil)
                                 logged-instrs)))
                       (funcall orig-dispatch vm ctx id)))

               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (if (= sid *target-sid*)
                           (progn
                             (setf instruction-count 0 logged-instrs nil)
                             (multiple-value-bind (effects gas-used)
                                 (funcall orig-accum-svc sid items gas-limit state
                                          :transfer-balance transfer-balance
                                          :svc-transfers svc-transfers)
                               (format t "~%--- Instructions ~D..~D and ~D..~D ---~%"
                                       *log-start* *log-end* *log-start2* *log-end2*)
                               (dolist (instr (nreverse logged-instrs))
                                 (format t "[~6D] pc=~6D ~18A skip=~D gas=~8D ra=~D sp=~D t0=~D t1=~D t2=~D s0=~D s1=~D a0=~D a1=~D a2=~D a3=~D a4=~D a5=~D~@[ imm=~D~]~%"
                                         (first instr) (second instr) (third instr)
                                         (fourth instr) (fifth instr)
                                         (nth 5 instr) (nth 6 instr)
                                         (nth 7 instr) (nth 8 instr) (nth 9 instr)
                                         (nth 10 instr) (nth 11 instr)
                                         (nth 12 instr) (nth 13 instr) (nth 14 instr)
                                         (nth 15 instr) (nth 16 instr) (nth 17 instr)
                                         (nth 18 instr)))
                               (values effects gas-used)))
                           (funcall orig-accum-svc sid items gas-limit state
                                    :transfer-balance transfer-balance
                                    :svc-transfers svc-transfers))))

               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (import-block pre-sigma block-cl)))

          (setf (fdefinition 'jamvm:vm-step) orig-vm-step
                (fdefinition 'jam-host::host-dispatch) orig-dispatch
                (fdefinition 'accumulate-service) orig-accum-svc))))))

(dfd-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
