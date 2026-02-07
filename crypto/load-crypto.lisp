;;;; JAM Crypto FFI Loader
;;;; Loads the Rust FFI library and bindings
;;;; Based on the working version from the old project

(in-package :cl-user)

(format t "~%Loading JAM Crypto FFI...~%")

;;; Load CFFI if available
(eval-when (:compile-toplevel :load-toplevel :execute)
  (handler-case
      (progn
        (require :cffi)
        (format t "  ✓ CFFI loaded~%"))
    (error (e)
      (warn "CFFI not available: ~A~%FFI functions will not work." e))))

;;; Define package
(load (merge-pathnames "package.lisp" *load-pathname*))

;;; Load utilities
(load (merge-pathnames "utils.lisp" *load-pathname*))

;;; Load crypto bindings (with FFI)
(handler-case
    (progn
      (load (merge-pathnames "bindings-old.lisp" *load-pathname*))
      (setf jam.ffi:*ffi-loaded* t)
      (format t "  ✓ FFI bindings loaded~%"))
  (error (e)
    (warn "FFI load failed: ~A" e)
    (setf jam.ffi:*ffi-loaded* nil)))

;;; Load high-level primitives
(load (merge-pathnames "primitives.lisp" *load-pathname*))
(load (merge-pathnames "shuffle.lisp" *load-pathname*))

(format t "~%✅ JAM Crypto ready (FFI: ~A)~%~%" jam.ffi:*ffi-loaded*)
