;;; diag-beta.lisp — Diagnose BETA+PI+THETA+DELTA-KVS divergences
;;; Focus: why is THETA empty (no commitments)?

(in-package #:jotl)

(defun db-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun db-u32-le (bytes offset)
  (+ (aref bytes offset)
     (ash (aref bytes (+ offset 1)) 8)
     (ash (aref bytes (+ offset 2)) 16)
     (ash (aref bytes (+ offset 3)) 24)))

(defun db-decode-theta (bytes)
  "Decode θ segment into list of (service-id . yield-hash) pairs."
  (when (and bytes (plusp (length bytes)))
    (let ((offset 0) (result nil))
      (multiple-value-bind (count consumed)
          (decode-compact bytes offset)
        (incf offset consumed)
        (dotimes (i count)
          (let ((sid (db-u32-le bytes offset))
                (hash (subseq bytes (+ offset 4) (+ offset 4 32))))
            (push (cons sid hash) result)
            (incf offset 36))))
      (nreverse result))))

(defun db-run (trace-id step)
  (format t "~%=== BETA+THETA DIAG: ~A / ~A ===~%" trace-id step)
  (let* ((dir (db-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)

      ;; Block info
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :timeslot))
        (format t "Author: ~D~%" (funcall header :author-index)))

      ;; Guarantees count
      (let ((guarantees (handler-case (funcall block-cl :guarantees) (error () nil))))
        (format t "Guarantees: ~A~%"
                (if (and guarantees (getf guarantees :guarantees))
                    (length (getf guarantees :guarantees))
                    0)))

      ;; Assurances count
      (let ((assurances (handler-case (funcall block-cl :assurances) (error () nil))))
        (format t "Assurances: ~A~%"
                (if assurances (length assurances) 0)))

      ;; Pre-state ρ
      (let ((pre-rho (funcall pre-sigma :load :rho)))
        (when pre-rho
          (let ((assignments (funcall pre-rho :assignments))
                (count 0) (report-cores '()))
            (loop for a in assignments for ci from 0 do
              (when a
                (incf count)
                (push ci report-cores)
                (let ((report (getf a :report)))
                  (when report
                    (let ((sid (getf report :service-id)))
                      (format t "  ρ[~D]: sid=~A timeout=~A~%"
                              ci sid (getf a :timeout)))))))
            (format t "Pre ρ pending: ~D on cores ~A~%" count (nreverse report-cores)))))

      ;; Pre-state ω (accumulation queues)
      (let ((pre-omega (funcall pre-sigma :load :omega)))
        (when pre-omega
          (format t "Pre ω total queued: ~D~%" (funcall pre-omega :total-queued))))

      ;; Expected θ
      (let ((exp-theta-bytes (funcall post-sigma :segment :theta)))
        (format t "~%Expected θ: ~D bytes~%" (length exp-theta-bytes))
        (let ((exp-pairs (db-decode-theta exp-theta-bytes)))
          (format t "  Expected commitments: ~D~%" (length exp-pairs))
          (dolist (p exp-pairs)
            (format t "    sid=~D hash=~A~%" (car p)
                    (subseq (bytes-to-hex-string (cdr p)) 0 16)))))

      ;; Wrap accumulate-star + accumulate-service to trace R*
      (let ((orig-accum-star (fdefinition 'accumulate-star))
            (orig-accum-svc  (fdefinition 'accumulate-service)))

        (unwind-protect
             (progn
               ;; Trace accumulate-service
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (format t "  [ACCUM-SVC] sid=~D items=~D gas=~D xfer-bal=~D~%"
                               sid (length items) gas-limit transfer-balance)
                       (let ((jamvm:*vm-last-step-pc* nil))
                         (multiple-value-bind (effects gas-used)
                             (funcall orig-accum-svc sid items gas-limit state
                                      :transfer-balance transfer-balance
                                      :svc-transfers svc-transfers)
                           (when effects
                             (format t "    outcome=~D gas-used=~D yield=~A xfers=~D last-pc=~A~%"
                                     (getf effects :outcome) gas-used
                                     (if (getf effects :yield-output) "YES" "no")
                                     (length (getf effects :transfers))
                                     jamvm:*vm-last-step-pc*))
                           (values effects gas-used)))))

               ;; Trace accumulate-star
               (setf (fdefinition 'accumulate-star)
                     (lambda (state transfers reports free-accum)
                       (format t "~%[ACCUM*] transfers=~D reports=~D free-accum=~D~%"
                               (length transfers) (length reports) (length free-accum))
                       ;; Show R* report details
                       (dolist (r reports)
                         (let ((results (getf r :results)))
                           (format t "  R* report: ~D results~%" (length results))
                           (dolist (res results)
                             (format t "    result: sid=~D gas=~D~%"
                                     (getf res :service-id)
                                     (getf res :accumulate-gas)))))
                       (multiple-value-bind (state* new-xfers commits gas-u)
                           (funcall orig-accum-star state transfers reports free-accum)
                         (format t "  ACCUM* → commits=~D new-xfers=~D~%"
                                 (length commits) (length new-xfers))
                         (dolist (c commits)
                           (format t "    commit: sid=~D~%" (car c)))
                         (values state* new-xfers commits gas-u))))

               ;; Run import-block
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (multiple-value-bind (sigma-prime computed-root)
                     (import-block pre-sigma block-cl)
                   (declare (ignore computed-root))

                   ;; Compare THETA
                   (let ((comp-theta-bytes (funcall (funcall sigma-prime :load :theta) :save))
                         (exp-theta-bytes  (funcall post-sigma :segment :theta)))
                     (format t "~%THETA: comp=~D bytes, exp=~D bytes~%"
                             (length comp-theta-bytes) (length exp-theta-bytes))
                     (if (equalp comp-theta-bytes exp-theta-bytes)
                         (format t "  THETA: MATCH~%")
                         (progn
                           (format t "  THETA: MISMATCH~%")
                           (let ((comp-pairs (db-decode-theta comp-theta-bytes))
                                 (exp-pairs  (db-decode-theta exp-theta-bytes)))
                             (format t "  comp: ~D commitments, exp: ~D commitments~%"
                                     (length comp-pairs) (length exp-pairs))))))

                   ;; Show DELTA-KVS diff count
                   (let ((computed-ht (make-hash-table :test 'equalp))
                         (expected-ht (make-hash-table :test 'equalp))
                         (diffs 0))
                     (dolist (kv (funcall sigma-prime :merkle-kvs))
                       (setf (gethash (car kv) computed-ht) (cdr kv)))
                     (dolist (kv (funcall post-sigma :merkle-kvs))
                       (setf (gethash (car kv) expected-ht) (cdr kv)))
                     (maphash (lambda (k v)
                                (unless (segment-key-p k)
                                  (let ((cv (gethash k computed-ht)))
                                    (when (not (equalp cv v))
                                      (incf diffs)))))
                              expected-ht)
                     (maphash (lambda (k v)
                                (declare (ignore v))
                                (unless (segment-key-p k)
                                  (unless (gethash k expected-ht)
                                    (incf diffs))))
                              computed-ht)
                     (format t "DELTA-KVS diffs: ~D~%" diffs)))))

          ;; Restore
          (setf (fdefinition 'accumulate-star) orig-accum-star
                (fdefinition 'accumulate-service) orig-accum-svc))))))

;; Run on all 6 traces
(dolist (spec '(("1768066437_3920" "00000012")
               ("1768066437_6431" "00000012")
               ("1768067197_6472" "00000012")
               ("1767872928_2891" "00000092")
               ("1767889897_5940" "00000355")
               ("1767871405_3616" "00000389")))
  (handler-case
      (db-run (first spec) (second spec))
    (error (e) (format t "~%ERROR on ~A/~A: ~A~%" (first spec) (second spec) e))))

(sb-ext:exit :code 0)
