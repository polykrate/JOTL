;;;; diag/diag-gas3.lisp — Check what transfers exist for the divergent service

(in-package :jotl)

(defvar *dg3-trace-id* "1767895984_7922")
(defvar *dg3-step* "00000061")

(defun dg3-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dg3-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dg3-run ()
  (format t "~%=== GAS3 DIAGNOSTIC ===~%")
  (format t "Trace: ~A  Step: ~A~%" *dg3-trace-id* *dg3-step*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dg3-step*)
                                     (dg3-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma pre-root post-root))

      ;; Get block header info
      (let* ((header (funcall block-cl :header))
             (ts (funcall header :timeslot)))
        (format t "Block timeslot: ~D  Author: ~D~%"
                ts (funcall header :author-index)))

      ;; Get pre-state closures
      (let* ((chi (funcall pre-sigma :closure :chi))
             (delta (funcall pre-sigma :closure :delta))
             (omega (funcall pre-sigma :closure :omega))
             (xi (funcall pre-sigma :closure :xi)))

        ;; Show always-accum (free accumulation services)
        (format t "~%Always-accum (χ_Z):~%")
        (let ((free-accum (funcall chi :always-accum)))
          (dolist (fa free-accum)
            (format t "  sid=~D gas=~D~%" (car fa) (cdr fa))))

        ;; Show pending transfers from prior blocks
        ;; These would come from the omega/xi state
        ;; Actually in GP, deferred transfers come from prior accumulations
        ;; stored somewhere. Let me check xi.
        (format t "~%Xi (accumulated history):~%")
        (handler-case
            (let ((xi-flat (funcall xi :flattened)))
              (format t "  flattened entries: ~D~%" (length xi-flat)))
          (error (e) (format t "  Error: ~A~%" e)))

        ;; Try to get pending transfers from omega
        (format t "~%Omega state:~%")
        (handler-case
            (progn
              (format t "  omega keys: ~S~%" (funcall omega :keys)))
          (error (e)
            (format t "  Error: ~A~%" e)))

        ;; Look at the extrinsic
        (format t "~%Block extrinsic:~%")
        (let ((extrinsic (funcall block-cl :extrinsic)))
          (handler-case
              (let ((guarantees (funcall extrinsic :guarantees)))
                (format t "  Guarantees: ~D~%" (length guarantees))
                ;; Show which services are in the work results
                (dolist (g guarantees)
                  (let ((report (getf g :report)))
                    (format t "    report context=~D items=~D~%"
                            (getf report :context-service-id)
                            (length (getf report :results)))
                    (dolist (r (getf report :results))
                      (format t "      sid=~D gas=~D~%"
                              (getf r :service-id)
                              (or (getf (getf r :refine-load) :gas-used) 0))))))
            (error (e) (format t "  Guarantees error: ~A~%" e))))

        ;; Now check what prior deferred transfers exist.
        ;; In the GP, deferred transfers t come from the previous block's
        ;; accumulate results. They're stored in the state.
        ;; Let me check if there's a :pending-transfers or :deferred-transfers field
        ;; in the omega or other state.
        (format t "~%Checking for deferred transfers in state...~%")
        ;; The deferred transfers would be encoded in the xi or omega state.
        ;; Actually, in GP 12.18, t (deferred transfers) comes from the previous
        ;; accumulation round's output.
        ;; Let me check what omega gives us
        (handler-case
            (let* ((r-star-input (funcall (funcall block-cl :extrinsic) :guarantees))
                   (omega-prime (funcall omega :transition
                                         :reports r-star-input
                                         :xi-flattened (funcall xi :flattened)
                                         :timeslot ts
                                         :prev-timeslot (1- ts)))
                   (r-star (funcall omega-prime :r-star)))
              (format t "  R* (available reports): ~D~%" (length r-star))
              ;; Check for deferred transfers
              (format t "  Checking for pending-transfers field...~%")
              (handler-case
                  (let ((xfers (funcall omega-prime :pending-transfers)))
                    (format t "  Pending transfers: ~D~%" (length xfers))
                    (dolist (x xfers)
                      (format t "    sender=~D dest=~D amount=~D gas=~D~%"
                              (getf x :sender) (getf x :destination)
                              (getf x :amount) (getf x :gas-limit))))
                (error (e) (format t "  No pending-transfers: ~A~%" e))))
          (error (e) (format t "  Error computing omega: ~A~%" e)))))))

(dg3-run)
(sb-ext:exit :code 0)
