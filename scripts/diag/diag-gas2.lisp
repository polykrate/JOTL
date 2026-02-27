;;;; diag/diag-gas2.lisp — Detailed gas/transfer diagnostic

(in-package :jotl)

(defvar *dg2-trace-id* "1767895984_7922")
(defvar *dg2-step* "00000061")

(defun dg2-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dg2-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

;;; Intercept accumulate-star to log what's happening
(defun dg2-run ()
  (format t "~%=== GAS2 DIAGNOSTIC ===~%")
  (format t "Trace: ~A  Step: ~A~%" *dg2-trace-id* *dg2-step*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dg2-step*)
                                     (dg2-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root post-root))

      ;; Show block info
      (let* ((header (funcall block-cl :header))
             (ts (funcall header :timeslot)))
        (format t "Block timeslot: ~D~%" ts))

      ;; Wrap accumulate-service to log transfers vs items
      (let ((*chain-log-level* nil)
            (orig-fn #'accumulate-service))
        (flet ((wrapped-accumulate-service (service-id items gas-limit state
                                           &key (transfer-balance 0) (svc-transfers nil))
                 (format t "~%--- accumulate-service ---~%")
                 (format t "  sid=~D~%" service-id)
                 (format t "  items=~D~%" (length (or items nil)))
                 (format t "  svc-transfers=~D~%" (length (or svc-transfers nil)))
                 (format t "  gas-limit=~D~%" gas-limit)
                 (format t "  transfer-balance=~D~%" transfer-balance)
                 (when svc-transfers
                   (dolist (x svc-transfers)
                     (format t "    xfer: sender=~D dest=~D amount=~D gas-limit=~D~%"
                             (getf x :sender) (getf x :destination)
                             (getf x :amount) (getf x :gas-limit))))
                 (when items
                   (dolist (u items)
                     (format t "    item: gas=~D~%"
                             (or (getf u :gas) 0))))
                 ;; Show what encode-accumulate-items would produce
                 (let ((enc (encode-accumulate-items items svc-transfers)))
                   (format t "  encoded-items-count=~D (transfers+work)~%"
                           (length enc)))
                 ;; Call original
                 (multiple-value-bind (effects gas-used)
                     (funcall orig-fn service-id items gas-limit state
                              :transfer-balance transfer-balance
                              :svc-transfers svc-transfers)
                   (format t "  → gas-used=~D outcome=~A~%"
                           gas-used
                           (when effects (getf effects :outcome)))
                   (values effects gas-used))))

          ;; Temporarily shadow (will use handler for now - simpler approach)
          ;; Instead, just look at what the block contains
          (handler-case
              (let ((sigma-prime (import-block pre-sigma block-cl)))
                (declare (ignore sigma-prime))
                (format t "~%Block processed.~%"))
            (error (e)
              (format t "~%ERROR: ~A~%" e))))

        ;; Instead of wrapping, let me use a more direct approach:
        ;; Decode the pre-state and check what transfers exist
        (let* ((pre-delta (funcall pre-sigma :closure :delta)))
          (format t "~%Pre-state services present:~%")
          (let ((sids (funcall pre-delta :all-service-ids)))
            (format t "  Service IDs: ~{~D~^ ~}~%" sids)
            (format t "  Count: ~D~%" (length sids))))

        ;; Check pending transfers in the block
        (let ((extrinsic (funcall block-cl :extrinsic)))
          (format t "~%Block extrinsic keys:~%")
          ;; Try to find transfers
          (handler-case
              (let ((tickets (funcall extrinsic :tickets))
                    (preimages (funcall extrinsic :preimages))
                    (guarantees (funcall extrinsic :guarantees))
                    (assurances (funcall extrinsic :assurances)))
                (format t "  tickets=~D preimages=~D guarantees=~D assurances=~D~%"
                        (length tickets) (length preimages)
                        (length guarantees) (length assurances)))
            (error (e)
              (format t "  Error reading extrinsic: ~A~%" e))))))))

(dg2-run)
(sb-ext:exit :code 0)
