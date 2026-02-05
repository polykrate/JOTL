;;;; suite.lisp
;;;; JOTL Test Suite - Main test runner
;;;;
;;;; Usage:
;;;;   sbcl --load test/suite.lisp --quit
;;;;   or: make test (if Makefile exists)

(require :asdf)
(push #P"/home/polycrate/Projets/JOTL/" asdf:*central-registry*)
(asdf:load-system :jotl :verbose nil)

(defparameter *test-root* 
  (make-pathname :directory 
                 (pathname-directory *load-truename*))
  "Root directory for tests")

(defun run-test-file (file-path description)
  "Run a single test file and report results"
  (format t "~%╔══════════════════════════════════════════════════════════════╗~%")
  (format t "║  Running: ~A~%" description)
  (format t "╚══════════════════════════════════════════════════════════════╝~%")
  (handler-case
      (progn
        (load (merge-pathnames file-path *test-root*) :verbose nil)
        (format t "~%✅ ~A: PASSED~%" description)
        t)
    (error (e)
      (format t "~%❌ ~A: FAILED~%" description)
      (format t "   Error: ~A~%" e)
      nil)))

(defun run-all-tests ()
  "Run all JOTL test suites"
  (format t "~%╔══════════════════════════════════════════════════════════════╗~%")
  (format t "║                                                              ║~%")
  (format t "║                    JOTL TEST SUITE                           ║~%")
  (format t "║                                                              ║~%")
  (format t "║  JAM (Join-Accumulate Machine) - Common Lisp Implementation  ║~%")
  (format t "║                                                              ║~%")
  (format t "╚══════════════════════════════════════════════════════════════╝~%")
  
  (let ((results '()))
    ;; Codec tests
    (push (run-test-file "codec/test-block.lisp" "Block Codec (tiny + full)")
          results)
    
    ;; Summary
    (let ((passed (count t results))
          (total (length results)))
      (format t "~%╔══════════════════════════════════════════════════════════════╗~%")
      (format t "║                                                              ║~%")
      (if (= passed total)
          (format t "║            ✅ ALL TESTS PASSED (~D/~D) ✅                    ║~%" passed total)
          (format t "║            ⚠️  SOME TESTS FAILED (~D/~D) ⚠️                  ║~%" passed total))
      (format t "║                                                              ║~%")
      (format t "╚══════════════════════════════════════════════════════════════╝~%")
      
      ;; Exit with appropriate code
      (if (= passed total)
          (sb-ext:exit :code 0)
          (sb-ext:exit :code 1)))))

;; Run all tests
(run-all-tests)
