;;;; load-jotl.lisp - Load JOTL system with crypto FFI
;;;;
;;;; Quiet loader: suppresses compilation noise (notes, style-warnings).
;;;; Only genuine errors reach the terminal.

(in-package :cl-user)

;; Locate project root from this script's path
(let* ((jotl-root (make-pathname :directory
                                 (butlast (pathname-directory
                                           (or *load-truename* *default-pathname-defaults*)))))
       (jam-crypto-asd (merge-pathnames "jam-crypto.asd" jotl-root))
       (jamvm-asd (merge-pathnames "jamvm.asd" jotl-root))
       (jotl-asd (merge-pathnames "jotl.asd" jotl-root)))
  ;; Register system definitions
  (load jam-crypto-asd)
  (load jamvm-asd)
  (load jotl-asd)

  ;; Load systems — suppress all compilation noise
  ;; (style-warnings, compiler notes, "compiling file" messages)
  ;; Only genuine errors and our own prints (via *error-output*) pass through.
  (let ((sink (make-broadcast-stream)))
    (handler-bind ((style-warning #'muffle-warning)
                   #+sbcl (sb-ext:compiler-note #'muffle-warning))
      (let ((*standard-output* sink)
            (*trace-output* sink)
            (*compile-verbose* nil)
            (*compile-print* nil)
            (asdf:*asdf-verbose* nil))
        (asdf:load-system :jam-crypto)
        (asdf:load-system :jamvm)
        (asdf:load-system :jotl)))))

;; Hint for REPL use (only visible interactively, not in test scripts)
(when (interactive-stream-p *standard-input*)
  (format *error-output* "~%Try: (in-package :jotl)~%~%"))
