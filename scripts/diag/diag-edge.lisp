;;;; diag/diag-edge.lisp — Deep dive into service 3101749195 edge case

(in-package :jotl)

(defvar *de-trace-id* "1767895984_7922")
(defvar *de-step* "00000061")
(defvar *de-target-sid* 3101749195)

(defun de-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *de-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun de-run ()
  (format t "~%=== EDGE CASE DIAGNOSTIC for sid ~D ===~%" *de-target-sid*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *de-step*)
                                     (de-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma pre-root post-root))

      ;; 1. Show block info
      (let* ((header (funcall block-cl :header))
             (ts (funcall header :timeslot)))
        (format t "Timeslot: ~D~%" ts)
        (format t "Author: ~D~%" (funcall header :author-index)))

      ;; 2. Show service pre-state
      (let* ((delta (funcall pre-sigma :load :delta))
             (svc-data (when delta (funcall delta :service-data *de-target-sid*))))
        (format t "~%Service pre-state:~%")
        (if svc-data
            (progn
              (format t "  code-blob: ~D bytes~%"
                      (length (or (getf svc-data :code-blob) #())))
              (let ((meta (getf svc-data :metadata)))
                (when meta
                  (format t "  balance=~D items=~D footprint=~D~%"
                          (getf meta :balance) (getf meta :items-count)
                          (getf meta :footprint))
                  (format t "  min-accum-gas=~D min-memo-gas=~D~%"
                          (getf meta :min-accum-gas) (getf meta :min-memo-gas))))
              (format t "  storage: ~D entries~%"
                      (if (hash-table-p (getf svc-data :storage))
                          (hash-table-count (getf svc-data :storage)) 0)))
            (format t "  (no delta loaded)~%")))

      ;; 3. Run with full PVM instruction trace for the target service
      (format t "~%=== Running with PVM instruction trace ===~%")
      (let ((*debug-pvm-trace* t)
            (*debug-pvm-traces* nil)
            (*chain-log-level* nil))

        ;; Wrap lisp-pvm-run-accumulate to trace VM state
        (let ((orig-fn (fdefinition 'jam-host:lisp-pvm-run-accumulate)))
          (unwind-protect
               (progn
                 (setf (fdefinition 'jam-host:lisp-pvm-run-accumulate)
                       (lambda (code-blob service-id balance timeslot &rest keys)
                         (when (= service-id *de-target-sid*)
                           (format t "~%[PVM-ACCUM] sid=~D balance=~D ts=~D~%"
                                   service-id balance timeslot)
                           (format t "  gas=~D~%" (getf keys :gas))
                           (format t "  items-count=~D footprint=~D~%"
                                   (getf keys :items-count) (getf keys :footprint))
                           ;; Enable instruction counting
                           (setf jamvm:*vm-opcode-counts*
                                 (make-array 256 :initial-element 0)))
                         (multiple-value-bind (effects gas-used)
                             (apply orig-fn code-blob service-id balance timeslot keys)
                           (when (= service-id *de-target-sid*)
                             (format t "~%[PVM-RESULT] gas-used=~D outcome=~D~%"
                                     gas-used (and effects (getf effects :outcome)))
                             ;; Show instruction counts
                             (when jamvm:*vm-opcode-counts*
                               (format t "  Instruction counts:~%")
                               (let ((total 0))
                                 (dotimes (i 256)
                                   (let ((cnt (aref jamvm:*vm-opcode-counts* i)))
                                     (when (plusp cnt)
                                       (format t "    opcode ~3D: ~D~%" i cnt)
                                       (incf total cnt))))
                                 (format t "  Total instructions: ~D~%" total)))
                             (setf jamvm:*vm-opcode-counts* nil))
                           (values effects gas-used))))
                 (import-block pre-sigma block-cl))
            (setf (fdefinition 'jam-host:lisp-pvm-run-accumulate) orig-fn)))

        ;; Show HC trace for target
        (dolist (trace (reverse *debug-pvm-traces*))
          (when (= (getf trace :sid) *de-target-sid*)
            (format t "~%=== HC trace for sid ~D ===~%" *de-target-sid*)
            (format t "  gas-limit=~D gas-used=~D gas-remaining=~D~%"
                    (getf trace :gas-limit) (getf trace :gas-used)
                    (- (getf trace :gas-limit) (getf trace :gas-used)))
            (let ((log (getf trace :host-call-log))
                  (prev-gas nil))
              (format t "  ~D host calls:~%" (length log))
              (dolist (entry log)
                (let ((id (getf entry :id))
                      (gb (getf entry :gas-before))
                      (ga (getf entry :gas-after))
                      (res (getf entry :result)))
                  (when prev-gas
                    (let ((instr-gap (- prev-gas gb)))
                      (format t "    [~D gas in instructions]~%" instr-gap)))
                  (format t "    HC~D: gas ~D→~D (Δ=~D) result=~A~%"
                          id gb ga (- gb ga) res)
                  (setf prev-gas ga))))))))))

(de-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
