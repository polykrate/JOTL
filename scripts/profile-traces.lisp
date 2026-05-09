(setf jotl::*chain-log-level* nil)

(dolist (trace-name '("safrole" "fallback" "storage" "storage_light"))
  (let ((jotl:*prof* (make-hash-table :test 'eq)))
    (jotl/test:run-trace
     (namestring (merge-pathnames (format nil "~A/" trace-name)
                                  jotl/test::*trace-base-dir*)))
    (format t "~%=== ~A profiling ===~%" trace-name)
    (let ((pairs nil))
      (maphash (lambda (k v) (push (cons k v) pairs)) jotl:*prof*)
      (setf pairs (sort pairs #'> :key #'cdr))
      (dolist (p pairs)
        (format t "  ~16A: ~,3F s~%" (car p)
                (/ (cdr p) (float internal-time-units-per-second)))))))

(sb-ext:exit)
