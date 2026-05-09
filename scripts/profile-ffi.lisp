(load (merge-pathnames "tests/conformance.lisp"
                       (make-pathname :directory
                                      (butlast (pathname-directory
                                                (or *load-truename* *default-pathname-defaults*))))))
(setf jotl::*chain-log-level* nil)

;;; Wrap FFI functions to measure their cumulative time
(defvar *ffi-timings* (make-hash-table :test 'eq))

(defmacro wrap-ffi (pkg-sym key)
  "Replace PKG-SYM with a wrapper that accumulates wall-clock time under KEY."
  (let ((orig (gensym "ORIG")))
    `(let ((,orig (symbol-function ',pkg-sym)))
       (setf (symbol-function ',pkg-sym)
             (lambda (&rest args)
               (let ((t0 (get-internal-real-time)))
                 (multiple-value-prog1 (apply ,orig args)
                   (let ((dt (- (get-internal-real-time) t0)))
                     (if (gethash ,key *ffi-timings*)
                         (incf (the integer (gethash ,key *ffi-timings*)) dt)
                         (setf (gethash ,key *ffi-timings*) dt))))))))))

(wrap-ffi jam.ffi:blake2b-256                :blake2b)
(wrap-ffi jam.ffi:keccak-256                 :keccak)
(wrap-ffi jam.ffi:ed25519-verify             :ed25519)
(wrap-ffi jam.ffi:bandersnatch-verify-vrf    :bander-vrf)
(wrap-ffi jam.ffi:bandersnatch-verify-ring-vrf :bander-ring-vrf)
(wrap-ffi jam.ffi:bandersnatch-compute-ring-commitment :bander-ring-commit)
(wrap-ffi jam.ffi:Y                          :bander-Y)
(wrap-ffi jam.ffi:deterministic-shuffle      :shuffle)

;;; Also wrap the Lisp PVM entry point
(wrap-ffi jam-host:lisp-pvm-run-accumulate   :pvm-lisp)

;;; Count PVM instructions executed
(defvar *pvm-instr-count* 0)
(let ((orig (symbol-function 'jamvm:vm-step)))
  (setf (symbol-function 'jamvm:vm-step)
        (lambda (vm)
          (incf *pvm-instr-count*)
          (funcall orig vm))))

(defun print-timings (label)
  (format t "~%=== ~A — FFI + PVM breakdown ===~%" label)
  (let ((pairs nil))
    (maphash (lambda (k v) (push (cons k v) pairs)) *ffi-timings*)
    (setf pairs (sort pairs #'> :key #'cdr))
    (let ((total 0))
      (dolist (p pairs)
        (let ((secs (/ (cdr p) (float internal-time-units-per-second))))
          (incf total secs)
          (format t "  ~22A: ~,3F s~%" (car p) secs)))
      (format t "  ~22A: ~,3F s~%" "--- total-measured ---" total)))
  ;; Also print the prof timings
  (when jotl:*prof*
    (format t "~%  Phase timings:~%")
    (let ((pairs nil))
      (maphash (lambda (k v) (push (cons k v) pairs)) jotl:*prof*)
      (setf pairs (sort pairs #'> :key #'cdr))
      (dolist (p pairs)
        (format t "  ~22A: ~,3F s~%" (car p)
                (/ (cdr p) (float internal-time-units-per-second)))))))

(dolist (trace-name '("safrole" "fallback" "storage" "storage_light"))
  (setf *ffi-timings* (make-hash-table :test 'eq))
  (setf *pvm-instr-count* 0)
  (let ((jotl:*prof* (make-hash-table :test 'eq)))
    (jotl/test:run-trace
     (namestring (merge-pathnames (format nil "~A/" trace-name)
                                  jotl/test::*trace-base-dir*)))
    (print-timings trace-name)
    (let ((pvm-secs (/ (or (gethash :pvm-lisp *ffi-timings*) 0)
                       (float internal-time-units-per-second))))
      (format t "~%  PVM instructions: ~:D (~,1F M inst/s)~%"
              *pvm-instr-count*
              (if (> pvm-secs 0.001)
                  (/ *pvm-instr-count* pvm-secs 1e6)
                  0.0)))))

(sb-ext:exit)
