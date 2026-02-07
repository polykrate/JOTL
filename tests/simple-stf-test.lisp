;;;; simple-stf-test.lisp - Simple STF test without external dependencies
;;;; Tests timeslot extraction from trace files

(defun read-file-string (filepath)
  "Read file as string"
  (with-open-file (stream filepath)
    (let ((contents (make-string (file-length stream))))
      (read-sequence contents stream)
      contents)))

(defun find-slot-in-json (json-string)
  "Extract 'slot' value from JSON (simple string search)
   
   Looks for: \"slot\": 42"
  (let ((pos (search "\"slot\"" json-string)))
    (when pos
      (let* ((colon-pos (position #\: json-string :start pos))
             (after-colon (subseq json-string (1+ colon-pos)))
             (comma-or-newline (or (position #\, after-colon)
                                   (position #\Newline after-colon)
                                   (length after-colon)))
             (number-string (string-trim '(#\Space #\Tab #\Newline) 
                                        (subseq after-colon 0 comma-or-newline))))
        (parse-integer number-string :junk-allowed t)))))

(defun test-trace-file (filepath)
  "Test a single trace file"
  (format t "~&Testing: ~A~%" (file-namestring filepath))
  (handler-case
      (let* ((json (read-file-string filepath))
             (slot (find-slot-in-json json)))
        (if slot
            (progn
              (format t "  ✅ Slot found: ~D~%" slot)
              t)
            (progn
              (format t "  ❌ Slot not found~%")
              nil)))
    (error (e)
      (format t "  ❌ ERROR: ~A~%" e)
      nil)))

(defun test-all-traces (directory &key (limit 5))
  "Test multiple trace files"
  (format t "~%Testing trace files from: ~A~%~%" directory)
  (let ((files (directory (merge-pathnames "*.json" directory)))
        (passed 0)
        (failed 0))
    
    (dolist (file (subseq files 0 (min limit (length files))))
      (if (test-trace-file file)
          (incf passed)
          (incf failed)))
    
    (format t "~%Summary: ~D passed, ~D failed~%" passed failed)
    (values passed failed)))

;;; Run tests
(format t "~%=== Simple STF Test ===~%")

(defparameter *traces-dir* 
  #P"/home/polycrate/Projets/JOTL/tests/jamtestvectors/traces/tiny/")

(test-all-traces *traces-dir* :limit 5)

(format t "~%Done!~%")
