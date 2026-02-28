;;;; diag-pi-deep.lisp — Deep investigation of PI-only divergence
;;;; Trace: 1766243493_6113 step 00000035
(in-package #:jotl)

(defvar *trace-dir*
  (merge-pathnames "../jam-conformance/fuzz-reports/0.7.2/traces/1767896003_7770/"
                   (asdf:system-source-directory :jotl)))

(defvar *step-file*
  (merge-pathnames "00000033.bin" *trace-dir*))

(format t "~%=== PI-DEEP DIAGNOSTIC ===~%")
(format t "Step file: ~A~%" *step-file*)

(let* ((bytes (alexandria:read-file-into-byte-vector *step-file*))
       (vals (multiple-value-list (decode-trace-step-bin bytes)))
       (pre-sigma  (first vals))
       (block-cl   (second vals))
       (post-sigma (third vals))
       (pre-root   (fourth vals))
       (post-root  (fifth vals)))

  (format t "Pre-root:  ~A~%" (bytes-to-hex-string pre-root))
  (format t "Post-root: ~A~%" (bytes-to-hex-string post-root))
  
  ;; Show block header info
  (let ((header (funcall block-cl :header)))
    (format t "~%Block slot: ~D~%" (funcall header :slot))
    (format t "Author index: ~D~%" (funcall header :author-index)))
  
  ;; Show guarantees
  (let ((guarantees (funcall block-cl :guarantees)))
    (format t "~%Guarantees: ~D~%" (length guarantees))
    (dolist (g guarantees)
      (let* ((report (getf g :report))
             (results (getf report :results)))
        (format t "  Report: ~D results~%" (length results))
        (dolist (r results)
          (let* ((sid (getf r :service-id))
                 (result-entry (getf r :result))
                 (kind (work-exec-result-kind result-entry)))
            (format t "    sid=~D kind=~D (~A)~%"
                    sid kind
                    (cond ((= kind 0) "OK")
                          ((= kind 1) "OOG")
                          ((= kind 2) "Panic")
                          (t "Other"))))))))
  
  ;; Run import
  (format t "~%--- Running import-block ---~%")
  (let ((*chain-log-level* nil))
    (handler-case
        (multiple-value-bind (sigma-prime computed-root)
            (import-block pre-sigma block-cl)
          (format t "Computed root: ~A~%" (bytes-to-hex-string computed-root))
          (format t "Root match: ~A~%" (equalp computed-root post-root))
          
          ;; Compare PI component
          (let ((pi-key (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0)))
            (setf (aref pi-key 0) 1)  ;; PI segment = C(1)
            
            (let ((computed-ht (make-hash-table :test 'equalp))
                  (expected-ht (make-hash-table :test 'equalp)))
              (dolist (kv (funcall sigma-prime :merkle-kvs))
                (setf (gethash (car kv) computed-ht) (cdr kv)))
              (dolist (kv (funcall post-sigma :merkle-kvs))
                (setf (gethash (car kv) expected-ht) (cdr kv)))
              
              ;; Check all segments
              (dolist (entry +sigma-segment-order+)
                (let* ((kw (car entry))
                       (cn (cdr entry))
                       (key (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref key 0) cn)
                  (let ((exp (gethash key expected-ht))
                        (got (gethash key computed-ht)))
                    (cond
                      ((and exp got (equalp exp got))
                       nil) ;; match
                      ((and exp got)
                       (format t "  ~A: DIFF exp=~D bytes, got=~D bytes~%"
                               kw (length exp) (length got))
                       ;; Find first differing byte
                       (let ((min-len (min (length exp) (length got))))
                         (loop for i below min-len
                               when (/= (aref exp i) (aref got i))
                               do (format t "    First diff at byte ~D: exp=0x~2,'0X got=0x~2,'0X~%"
                                          i (aref exp i) (aref got i))
                                  (return))
                         (when (/= (length exp) (length got))
                           (format t "    Length diff: exp=~D got=~D~%"
                                   (length exp) (length got)))))
                      ((and exp (null got))
                       (format t "  ~A: MISSING (expected ~D bytes)~%" kw (length exp)))
                      ((and (null exp) got)
                       (format t "  ~A: EXTRA (~D bytes)~%" kw (length got)))))))
              
              ;; Now deep-dive into PI
              (let ((pi-exp (gethash pi-key expected-ht))
                    (pi-got (gethash pi-key computed-ht)))
                (when (and pi-exp pi-got (not (equalp pi-exp pi-got)))
                  (format t "~%=== PI DEEP DIVE ===~%")
                  (format t "PI exp len: ~D~%" (length pi-exp))
                  (format t "PI got len: ~D~%" (length pi-got))
                  
                  ;; PI state is a list of service accumulation results
                  ;; Let's decode both and compare
                  (let ((exp-pi-state (funcall post-sigma :load :pi))
                        (got-pi-state (funcall sigma-prime :load :pi)))
                    
                    ;; Compare service-by-service
                    (format t "~%Expected PI services: ")
                    (let ((exp-services nil))
                      (funcall exp-pi-state :for-each-entry
                               (lambda (sid gas result)
                                 (push (list sid gas result) exp-services)))
                      (setf exp-services (sort exp-services #'< :key #'first))
                      (format t "~D entries~%" (length exp-services))
                      (dolist (e exp-services)
                        (format t "  sid=~D gas=~D result=~D~%"
                                (first e) (second e) (third e))))
                    
                    (format t "~%Got PI services: ")
                    (let ((got-services nil))
                      (funcall got-pi-state :for-each-entry
                               (lambda (sid gas result)
                                 (push (list sid gas result) got-services)))
                      (setf got-services (sort got-services #'< :key #'first))
                      (format t "~D entries~%" (length got-services))
                      (dolist (e got-services)
                        (format t "  sid=~D gas=~D result=~D~%"
                                (first e) (second e) (third e))))))))))
      (error (e)
        (format t "ERROR: ~A~%" e)))))

(format t "~%=== DONE ===~%")
(sb-ext:exit :code 0)
