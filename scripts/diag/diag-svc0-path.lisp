;;; diag-svc0-path.lisp — How does service 0 get accumulated?
(in-package #:jotl)

(let* ((trace-id "1766479507_7943")
       (step "00000018")
       (base (asdf:system-source-directory :jotl))
       (dir (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id) base))
       (step-path (merge-pathnames (format nil "~A.bin" step) dir))
       (bytes (alexandria:read-file-into-byte-vector step-path)))
  (multiple-value-bind (pre-sigma block-cl post-sigma)
      (decode-trace-step-bin bytes)
    (declare (ignore post-sigma))
    
    (let ((header (funcall block-cl :header)))
      (format t "Block slot: ~D~%" (funcall header :slot)))
    
    ;; Chi state
    (let ((chi (funcall pre-sigma :load :chi)))
      (format t "χ_M (manager): ~D~%" (funcall chi :manager))
      (format t "χ_V (designate): ~D~%" (funcall chi :designate))
      (format t "χ_Z (always-accum): ~A~%" (funcall chi :always-accum))
      (format t "χ_A (authorizers): ~A~%" (handler-case (funcall chi :authorizers) (error () "N/A"))))
    
    ;; Guarantees
    (let ((guarantees (handler-case (funcall block-cl :guarantees) (error () nil))))
      (format t "~%Guarantees: ~D~%" (length guarantees))
      (when guarantees
        (dolist (g guarantees)
          (let* ((report (getf g :report))
                 (core (getf report :core-index))
                 (items (getf report :work-items)))
            (format t "  Core ~D: ~D items~%" core (length items))
            (dolist (item items)
              (format t "    service=~D~%" (getf item :service-id)))))))
    
    ;; Wrap accumulate-star to see services
    (let ((orig-accum-star (fdefinition 'accumulate-star))
          (orig-accum-svc (fdefinition 'accumulate-service)))
      (unwind-protect
           (progn
             (setf (fdefinition 'accumulate-star)
                   (lambda (state transfers reports free-accum)
                     (format t "~%[ACCUM*] transfers=~D reports=~D free-accum=~D~%"
                             (length transfers) (length reports) (length free-accum))
                     ;; Show services in reports
                     (dolist (r reports)
                       (let ((items (getf r :work-items)))
                         (format t "  report services: ~{~D~^, ~}~%"
                                 (mapcar (lambda (i) (getf i :service-id)) items))))
                     ;; Show free-accum
                     (dolist (fa free-accum)
                       (format t "  free-accum: sid=~D gas=~D~%" (car fa) (cdr fa)))
                     (funcall orig-accum-star state transfers reports free-accum)))
             
             (setf (fdefinition 'accumulate-service)
                   (lambda (sid items gas-limit state &key (transfer-balance 0) (svc-transfers nil))
                     (format t "  [ACCUM-SVC] sid=~D items=~D gas=~D xfer-bal=~D~%"
                             sid (length items) gas-limit transfer-balance)
                     (multiple-value-bind (effects gas-used)
                         (funcall orig-accum-svc sid items gas-limit state
                                  :transfer-balance transfer-balance
                                  :svc-transfers svc-transfers)
                       (format t "    → outcome=~A gas-used=~D~%"
                               (when effects (getf effects :outcome)) gas-used)
                       (values effects gas-used))))
             
             (let ((*chain-log-level* nil)
                   (*debug-pvm-trace* nil))
               (import-block pre-sigma block-cl)))
        
        (setf (fdefinition 'accumulate-star) orig-accum-star)
        (setf (fdefinition 'accumulate-service) orig-accum-svc)))))

(sb-ext:exit :code 0)
