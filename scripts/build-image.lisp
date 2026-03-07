;;;; build-image.lisp — Build a standalone JOTL binary (SBCL core image)
;;;;
;;;; Called by scripts/build.sh.  Expects JOTL to already be loaded.
;;;;
;;;; The resulting binary provides a CLI:
;;;;   ./jotl fuzz [SOCKET]                        Fuzz-v1 target server
;;;;   ./jotl test [-v] [--vectors PATH] [TRACES]  Conformance tests
;;;;   ./jotl version                              Show version

(in-package #:cl-user)

;; Load test runner if not already loaded
(unless (find-package :jotl/test)
  (load (merge-pathnames "tests/conformance.lisp"
                         (asdf:system-source-directory :jotl))))

(defun jotl-main ()
  "CLI entry point for the standalone JOTL binary."
  (let ((args (rest sb-ext:*posix-argv*)))  ;; skip argv[0]
    (cond
      ;; No args → help
      ((or (null args)
           (find "--help" args :test #'string=)
           (find "-h" args :test #'string=))
       (format t "~%JOTL — JAM On The Lisp~%~%")
       (format t "Usage:~%")
       (format t "  jotl fuzz [SOCKET]                        Fuzz-v1 target server~%")
       (format t "  jotl test [-v] [--vectors PATH] [TRACES]  Conformance tests~%")
       (format t "  jotl version                              Show version~%")
       (format t "~%Options:~%")
       (format t "  -v, --verbose     Per-block detail + component diff on failures~%")
       (format t "  --vectors PATH    Path to jamtestvectors/traces/ directory~%")
       (format t "~%Environment:~%")
       (format t "  JAM_TEST_VECTORS  Path to test vectors (alternative to --vectors)~%")
       (terpri)
       (sb-ext:exit :code 0))

      ;; fuzz <socket>
      ((string= (first args) "fuzz")
       (let ((socket (or (second args) "/tmp/jam_target.sock")))
         (format *error-output* "[jotl] Starting fuzz target on ~A~%" socket)
         (jotl:run-fuzz-target :socket socket))
       (sb-ext:exit :code 0))

      ;; test [-v] [--vectors PATH] [traces...]
      ((string= (first args) "test")
       (let ((verbose nil)
             (traces nil)
             (rest-args (rest args)))
         (loop while rest-args do
           (let ((arg (pop rest-args)))
             (cond
               ((or (string= arg "-v") (string= arg "--verbose"))
                (setf verbose t))
               ((string= arg "--vectors")
                (let ((path (pop rest-args)))
                  (when path
                    (setf jotl/test::*trace-base-dir*
                          (if (and (plusp (length path))
                                   (char= (char path (1- (length path))) #\/))
                              path
                              (concatenate 'string path "/"))))))
               (t (push arg traces)))))
         (setf traces (nreverse traces))
         (setf jotl::*chain-log-level* nil)
         (let ((result (jotl/test:run-all
                        :verbose verbose
                        :traces (or traces nil))))
           (sb-ext:exit :code (if (zerop (getf result :step-fail 0)) 0 1)))))

      ;; version
      ((string= (first args) "version")
       (format t "JOTL ~A~%"
               (if (boundp 'jotl::*jotl-version*)
                   (symbol-value 'jotl::*jotl-version*)
                   "dev"))
       (sb-ext:exit :code 0))

      (t
       (format *error-output* "Unknown command: ~A~%Try: jotl --help~%" (first args))
       (sb-ext:exit :code 1)))))

;; ── Save the image ──────────────────────────────────────────────
(let ((output (or (uiop:getenv "JOTL_BUILD_OUTPUT") "./jotl")))
  (format *error-output* "[build] Saving JOTL binary → ~A~%" output)
  (sb-ext:save-lisp-and-die output
    :toplevel #'jotl-main
    :executable t
    :compression t
    :save-runtime-options t))
