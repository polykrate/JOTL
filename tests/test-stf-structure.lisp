;;;; Quick test to check JSON structure

(load "tests/stf-validator.lisp")

(in-package :jotl.stf-validator)

(defparameter *test-file* 
  "/home/polycrate/Projets/JOTL/tests/jamtestvectors/stf/accumulate/tiny/accumulate_ready_queued_reports-1.json")

(format t "~%Testing STF validator structure...~%")
(validate-stf-test *test-file* :verbose t)
(format t "~%Done!~%")
