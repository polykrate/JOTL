;;;; diag/diag-gas5.lisp — Log accumulate item counts and transfers per service

(in-package :jotl)

;; Wrap accumulate-service to log what's passed
(let ((orig (fdefinition 'accumulate-service)))
  (setf (fdefinition 'accumulate-service)
        (lambda (service-id items gas-limit state
                 &key (transfer-balance 0) (svc-transfers nil))
          (format *error-output*
                  "~&[ACCUM-SVC] sid=~D items=~D xfers=~D gas-limit=~D xfer-balance=~D~%"
                  service-id (length (or items nil)) (length (or svc-transfers nil))
                  gas-limit transfer-balance)
          (when svc-transfers
            (dolist (x svc-transfers)
              (format *error-output*
                      "~&  xfer: sender=~D dest=~D amount=~D gas=~D~%"
                      (getf x :sender) (getf x :destination)
                      (getf x :amount) (getf x :gas-limit))))
          (let ((enc-items (encode-accumulate-items items svc-transfers)))
            (format *error-output*
                    "~&[ACCUM-SVC] total-encoded-items=~D (xfer+work)~%"
                    (length enc-items)))
          (funcall orig service-id items gas-limit state
                   :transfer-balance transfer-balance
                   :svc-transfers svc-transfers))))

(defvar *dg5-trace-id* "1767895984_7922")
(defvar *dg5-step* "00000061")

(defun dg5-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dg5-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dg5-run ()
  (format t "~%=== GAS5 DIAGNOSTIC ===~%")
  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dg5-step*)
                                     (dg5-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma pre-root post-root))
      (let ((*chain-log-level* nil))
        (handler-case
            (let ((sigma-prime (import-block pre-sigma block-cl)))
              (declare (ignore sigma-prime))
              (format t "Done.~%"))
          (error (e) (format t "ERROR: ~A~%" e)))))))

(dg5-run)
(sb-ext:exit :code 0)
