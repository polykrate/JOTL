;;; diag-expected-svc0.lisp — Compare expected vs actual service 0 state
(in-package #:jotl)

(defun des-trace-dir (trace-id)
  (let ((base (asdf:system-source-directory :jotl)))
    (merge-pathnames
     (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/" trace-id)
     base)))

(defun des-run (trace-id step)
  (format t "~%=== EXPECTED vs ACTUAL SVC 0: ~A / ~A ===~%" trace-id step)
  (let* ((dir (des-trace-dir trace-id))
         (step-path (merge-pathnames (format nil "~A.bin" step) dir))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      
      ;; Expected post-state service 0
      (format t "~%--- EXPECTED POST-STATE (svc 0) ---~%")
      (let* ((exp-delta (funcall post-sigma :load :delta))
             (exp-svc (funcall exp-delta :service-data 0))
             (exp-meta (getf exp-svc :metadata)))
        (if exp-meta
            (progn
              (format t "  balance:      ~D~%" (getf exp-meta :balance))
              (format t "  min-accum-gas:~D~%" (getf exp-meta :min-accum-gas))
              (format t "  items-count:  ~D~%" (getf exp-meta :items-count))
              (format t "  footprint:    ~D~%" (getf exp-meta :footprint))
              (format t "  last-accum:   ~D~%" (getf exp-meta :last-accum-slot))
              ;; Check storage count
              (let ((exp-storage (getf exp-svc :storage)))
                (format t "  storage keys: ~D~%" (hash-table-count exp-storage))))
            (format t "  Service 0 NOT FOUND in expected post-state~%")))
      
      ;; Pre-state service 0
      (format t "~%--- PRE-STATE (svc 0) ---~%")
      (let* ((pre-delta (funcall pre-sigma :load :delta))
             (pre-svc (funcall pre-delta :service-data 0))
             (pre-meta (getf pre-svc :metadata)))
        (if pre-meta
            (progn
              (format t "  balance:      ~D~%" (getf pre-meta :balance))
              (format t "  min-accum-gas:~D~%" (getf pre-meta :min-accum-gas))
              (format t "  items-count:  ~D~%" (getf pre-meta :items-count))
              (format t "  footprint:    ~D~%" (getf pre-meta :footprint))
              (format t "  last-accum:   ~D~%" (getf pre-meta :last-accum-slot))
              (let ((pre-storage (getf pre-svc :storage)))
                (format t "  storage keys: ~D~%" (hash-table-count pre-storage))))
            (format t "  Service 0 NOT FOUND in pre-state~%")))
      
      ;; Compare storage changes
      (format t "~%--- STORAGE DIFF (svc 0) ---~%")
      (let* ((pre-delta (funcall pre-sigma :load :delta))
             (exp-delta (funcall post-sigma :load :delta))
             (pre-svc (funcall pre-delta :service-data 0))
             (exp-svc (funcall exp-delta :service-data 0))
             (pre-storage (getf pre-svc :storage))
             (exp-storage (getf exp-svc :storage))
             (added 0) (removed 0) (changed 0))
        ;; Find added/changed
        (maphash (lambda (k v)
                   (let ((old (gethash k pre-storage)))
                     (cond
                       ((null old) (incf added))
                       ((not (equalp v old)) (incf changed)))))
                 exp-storage)
        ;; Find removed
        (maphash (lambda (k v)
                   (declare (ignore v))
                   (unless (gethash k exp-storage)
                     (incf removed)))
                 pre-storage)
        (format t "  Added:   ~D~%" added)
        (format t "  Removed: ~D~%" removed)
        (format t "  Changed: ~D~%" changed))
      
      ;; Compare IOTA
      (format t "~%--- IOTA COMPARISON ---~%")
      (let* ((pre-iota (funcall pre-sigma :load :iota))
             (exp-iota (funcall post-sigma :load :iota))
             (pre-iota-bytes (funcall pre-iota :save))
             (exp-iota-bytes (funcall exp-iota :save)))
        (if (equalp pre-iota-bytes exp-iota-bytes)
            (format t "  IOTA: UNCHANGED (pre == expected)~%")
            (format t "  IOTA: CHANGED (pre != expected) → designate was applied~%")))

      ;; Expected PI gas stats for service 0  
      (format t "~%--- EXPECTED PI (gas stats) ---~%")
      (let* ((exp-pi (funcall post-sigma :load :pi))
             (pre-pi (funcall pre-sigma :load :pi)))
        (handler-case
            (let* ((exp-pi-bytes (funcall exp-pi :save))
                   (pre-pi-bytes (funcall pre-pi :save)))
              (format t "  expected PI: ~D bytes~%" (length exp-pi-bytes))
              (format t "  pre PI: ~D bytes~%" (length pre-pi-bytes))
              (if (equalp exp-pi-bytes pre-pi-bytes)
                  (format t "  PI: UNCHANGED~%")
                  (format t "  PI: CHANGED~%")))
          (error (e) (format t "  Error: ~A~%" e)))))))

(des-run "1766479507_7943" "00000018")
(sb-ext:exit :code 0)
