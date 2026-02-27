;;;; diag/diag-xfers.lisp — Show all transfers and multi-round accumulation

(in-package :jotl)

(defvar *dx-trace-id* "1767896003_7770")
(defvar *dx-step* "00000033")

(defun dx-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dx-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dx-run ()
  (format t "~%=== TRANSFER/MULTI-ROUND DIAGNOSTIC ===~%")

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dx-step*)
                                     (dx-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Wrap accumulate-star to trace each round
      (let ((orig-star (fdefinition 'accumulate-star))
            (round-num 0))

        (unwind-protect
            (progn
              (setf (fdefinition 'accumulate-star)
                    (lambda (state transfers reports free-accum)
                      (incf round-num)
                      (format t "~%[ROUND ~D] transfers=~D reports=~D free-accum=~D~%"
                              round-num (length transfers)
                              (length (or reports nil))
                              (length (or free-accum nil)))
                      (when transfers
                        (dolist (x transfers)
                          (format t "  xfer: ~D→~D amount=~D gas=~D~%"
                                  (getf x :sender)
                                  (getf x :destination)
                                  (getf x :amount)
                                  (getf x :gas-limit))))
                      (multiple-value-bind (state* new-xfers commits gas-usage)
                          (funcall orig-star state transfers reports free-accum)
                        (format t "  new-xfers=~D gas-usage:~%"
                                (length new-xfers))
                        (when new-xfers
                          (dolist (x new-xfers)
                            (format t "    new: ~D→~D amount=~D gas=~D~%"
                                    (getf x :sender)
                                    (getf x :destination)
                                    (getf x :amount)
                                    (getf x :gas-limit))))
                        (dolist (gu gas-usage)
                          (format t "    sid=~D items=~D gas=~D~%"
                                  (first gu) (second gu) (third gu)))
                        (values state* new-xfers commits gas-usage))))

              ;; Run
              (let ((*chain-log-level* nil)
                    (*debug-pvm-trace* nil))
                (import-block pre-sigma block-cl)))

          ;; Restore
          (setf (fdefinition 'accumulate-star) orig-star))))))

(dx-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
