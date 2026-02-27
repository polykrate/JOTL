;;;; diag-dkvs.lisp — Diagnose DELTA-KVS only divergences
(in-package #:jotl)

(defun dd-trace-dir (trace-id)
  (merge-pathnames (format nil "traces/~A/" trace-id)
                   #P"/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/"))

(defun dd-run (trace-id step)
  (format t "~%=== DELTA-KVS DIAG: ~A / ~A ===~%" trace-id step)
  (let* ((dir (dd-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)

      ;; Show block info
      (let ((header (funcall block-cl :header)))
        (format t "Block slot: ~D~%" (funcall header :timeslot))
        (format t "Author: ~D~%" (funcall header :author-index)))

      ;; Show guarantees
      (let ((guarantees (handler-case (funcall block-cl :guarantees) (error () nil))))
        (format t "Guarantees: ~A~%" (if (and guarantees (getf guarantees :guarantees))
                                         (length (getf guarantees :guarantees))
                                         0)))

      ;; Show chi / always-accum
      (let ((pre-chi (funcall pre-sigma :load :chi)))
        (format t "χ_Z (always-accum): ~A~%" (when pre-chi (funcall pre-chi :always-accum))))

      ;; Save all original functions
      (let ((orig-accum-star (fdefinition 'accumulate-star))
            (orig-accum-svc (fdefinition 'accumulate-service))
            (orig-dispatch (fdefinition 'jam-host::host-dispatch)))
        (unwind-protect
             (progn
               ;; Trace accumulate-star
               (setf (fdefinition 'accumulate-star)
                     (lambda (state transfers reports free-accum)
                       (format t "~%[ACCUM*] transfers=~D reports=~D free-accum=~D~%"
                               (length transfers) (length reports) (length free-accum))
                       (when transfers
                         (dolist (x transfers)
                           (format t "  xfer: sender=~D dest=~D amount=~D gas=~D~%"
                                   (getf x :sender) (getf x :destination)
                                   (getf x :amount) (getf x :gas-limit))))
                       (funcall orig-accum-star state transfers reports free-accum)))

               ;; Trace host calls
               (setf (fdefinition 'jam-host::host-dispatch)
                     (lambda (vm ctx id)
                       (let* ((sid (jam-host::hctx-service-id ctx))
                              (gas-before (jamvm:pvm-gas vm))
                              (result (funcall orig-dispatch vm ctx id))
                              (gas-after (jamvm:pvm-gas vm)))
                         (when (= sid 2770249356)
                           (format t "    [HC~D] sid=~D gas:~D→~D a0=~D~%"
                                   id sid gas-before gas-after
                                   (jamvm:reg vm jamvm:+a0+)))
                         result)))

               ;; Trace accumulate-service
               (setf (fdefinition 'accumulate-service)
                     (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                       (format t "  [ACCUM-SVC] sid=~D items=~D gas=~D xfer-bal=~D svc-xfers=~D~%"
                               sid (length items) gas-limit transfer-balance (length svc-transfers))
                       (multiple-value-bind (effects gas-used)
                           (funcall orig-accum-svc sid items gas-limit state
                                    :transfer-balance transfer-balance
                                    :svc-transfers svc-transfers)
                         (when effects
                           (format t "    outcome=~D gas-used=~D transfers=~D~%"
                                   (getf effects :outcome) gas-used
                                   (length (getf effects :transfers)))
                           (dolist (x (getf effects :transfers))
                             (format t "      xfer-to=~D amount=~D gas=~D~%"
                                     (getf x :to) (getf x :amount) (getf x :gas-limit))))
                         (values effects gas-used))))

               ;; Run
               (let ((*chain-log-level* nil)
                     (*debug-pvm-trace* nil))
                 (multiple-value-bind (sigma-prime computed-root)
                     (import-block pre-sigma block-cl)
                   (declare (ignore computed-root))

                   ;; Compare delta-kvs
                   (let ((computed-ht (make-hash-table :test 'equalp))
                         (expected-ht (make-hash-table :test 'equalp)))
                     (dolist (kv (funcall sigma-prime :merkle-kvs))
                       (setf (gethash (car kv) computed-ht) (cdr kv)))
                     (dolist (kv (funcall post-sigma :merkle-kvs))
                       (setf (gethash (car kv) expected-ht) (cdr kv)))

                     (let ((diffs 0))
                       (maphash (lambda (k v)
                                  (unless (segment-key-p k)
                                    (let ((cv (gethash k computed-ht)))
                                      (when (not (equalp cv v))
                                        (incf diffs)
                                        (format t "~%  DIFF key=~A~%" (bytes-to-hex-string k))
                                        (format t "    exp-len=~D comp-len=~A~%"
                                                (length v) (if cv (length cv) "MISSING"))))))
                                expected-ht)
                       (maphash (lambda (k v)
                                  (declare (ignore v))
                                  (unless (segment-key-p k)
                                    (unless (gethash k expected-ht)
                                      (incf diffs)
                                      (format t "~%  EXTRA key=~A~%" (bytes-to-hex-string k)))))
                                computed-ht)
                       (format t "~%Total delta-kvs diffs: ~D~%" diffs))))))

          ;; Restore
          (setf (fdefinition 'jam-host::host-dispatch) orig-dispatch
                (fdefinition 'accumulate-star) orig-accum-star
                (fdefinition 'accumulate-service) orig-accum-svc))))))

;; Run
(dd-run "1766243315_9206" "00001065")

(sb-ext:exit :code 0)
