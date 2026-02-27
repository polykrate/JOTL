;;;; diag/diag-sbrk.lisp — Count sbrk pages for service 0

(in-package :jotl)

(defvar *ds-trace-id* "1767896003_7770")
(defvar *ds-step* "00000033")
(defvar *ds-target-sid* 0)
(defvar *ds-sbrk-pages* 0)
(defvar *ds-sbrk-calls* 0)
(defvar *ds-tracking* nil)

(defun ds-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *ds-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun ds-run ()
  (format t "~%=== SBRK DIAGNOSTIC for sid ~D ===~%" *ds-target-sid*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *ds-step*)
                                     (ds-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma))

      ;; Wrap sbrk to count pages
      (let ((orig-sbrk (gethash :sbrk jamvm::*instruction-handlers*))
            (orig-pvm (fdefinition 'jam-host:lisp-pvm-run-accumulate)))

        (unwind-protect
            (progn
              ;; Wrap sbrk instruction
              (setf (gethash :sbrk jamvm::*instruction-handlers*)
                    (lambda (vm args)
                      (let ((old-top (jamvm::mem-heap-top (jamvm:pvm-memory vm)))
                            (size-raw (jamvm:reg vm (jamvm::arg-rb args))))
                        (let ((result (funcall orig-sbrk vm args)))
                          (when *ds-tracking*
                            (let* ((new-top (jamvm::mem-heap-top (jamvm:pvm-memory vm)))
                                   (old-page (if (zerop old-top) 0
                                                 (jamvm::page-index (1- old-top))))
                                   (new-page (if (= old-top new-top) old-page
                                                 (jamvm::page-index (1- new-top))))
                                   (pages (if (= old-top new-top) 0
                                              (- new-page old-page))))
                              (incf *ds-sbrk-calls*)
                              (when (plusp pages)
                                (format t "  [SBRK] size=~D old=~D new=~D pages=~D gas=~D~%"
                                        size-raw old-top new-top pages (jamvm:pvm-gas vm))
                                (incf *ds-sbrk-pages* pages))))
                          result))))

              ;; Also link the new handler into opcode table
              (let ((handler (gethash :sbrk jamvm::*instruction-handlers*)))
                (dotimes (i 256)
                  (let ((info (aref jamvm::*opcode-table* i)))
                    (when (and info (eq (jamvm::opi-name info) :sbrk))
                      (setf (jamvm::opi-handler info) handler)))))

              ;; Wrap lisp-pvm-run-accumulate to track target service
              (setf (fdefinition 'jam-host:lisp-pvm-run-accumulate)
                    (lambda (code-blob service-id balance timeslot &rest keys)
                      (when (= service-id *ds-target-sid*)
                        (setf *ds-sbrk-pages* 0
                              *ds-sbrk-calls* 0
                              *ds-tracking* t))
                      (multiple-value-bind (effects gas-used)
                          (apply orig-pvm code-blob service-id balance timeslot keys)
                        (when (= service-id *ds-target-sid*)
                          (setf *ds-tracking* nil)
                          (format t "~%  sid ~D: sbrk-calls=~D sbrk-pages=~D gas-used=~D~%"
                                  service-id *ds-sbrk-calls* *ds-sbrk-pages* gas-used)
                          (format t "  page-gas (if charged): ~D~%"
                                  (* *ds-sbrk-pages* jamvm:+gas-per-page+)))
                        (values effects gas-used))))

              ;; Run
              (let ((*chain-log-level* nil)
                    (*debug-pvm-trace* nil))
                (import-block pre-sigma block-cl)))

          ;; Restore
          (setf (gethash :sbrk jamvm::*instruction-handlers*) orig-sbrk)
          ;; Re-link original handler
          (dotimes (i 256)
            (let ((info (aref jamvm::*opcode-table* i)))
              (when (and info (eq (jamvm::opi-name info) :sbrk))
                (setf (jamvm::opi-handler info) orig-sbrk))))
          (setf (fdefinition 'jam-host:lisp-pvm-run-accumulate) orig-pvm))))))

(ds-run)
(format t "~%Done.~%")
(sb-ext:exit :code 0)
