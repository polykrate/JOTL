;;;; Quick test: run transition-psi against disputes test vectors
(in-package :jotl)

(ql:quickload :cl-json :silent t)

;;; Helper: extract ed25519 key accounting for cl-json renaming
(defun json-ed25519 (validator-alist)
  "Get ed25519 key from a validator alist (cl-json renames ed25519 → ed-25519)."
  (or (cdr (assoc :ed25519 validator-alist))
      (cdr (assoc :ed-25519 validator-alist))))

;;; Helper: convert JSON validator list to our plist format
(defun json-validators-to-plists (validators-json)
  "Convert cl-json validator alists to plists with :ed25519 key."
  (mapcar (lambda (v)
            (list :ed25519 (let ((hex (json-ed25519 v)))
                             (when hex (hex-string-to-bytes hex)))
                  :bandersnatch (let ((hex (cdr (assoc :bandersnatch v))))
                                  (when hex (hex-string-to-bytes hex)))))
          validators-json))

;;; Helper: convert JSON hash list to byte-vector list
(defun json-hashes-to-bytes (hash-list)
  (mapcar #'hex-string-to-bytes hash-list))

;;; Helper: convert JSON disputes to our plist format
(defun json-disputes-to-plist (disputes-json)
  (let ((verdicts (cdr (assoc :verdicts disputes-json)))
        (culprits (cdr (assoc :culprits disputes-json)))
        (faults (cdr (assoc :faults disputes-json))))
    (list
     :verdicts (mapcar (lambda (v)
                         (list :target (hex-string-to-bytes (cdr (assoc :target v)))
                               :age (cdr (assoc :age v))
                               :votes (mapcar (lambda (vote)
                                                (list :vote (cdr (assoc :vote vote))
                                                      :index (cdr (assoc :index vote))
                                                      :signature (hex-string-to-bytes
                                                                  (cdr (assoc :signature vote)))))
                                              (cdr (assoc :votes v)))))
                       verdicts)
     :culprits (mapcar (lambda (c)
                         (list :target (hex-string-to-bytes (cdr (assoc :target c)))
                               :key (hex-string-to-bytes (cdr (assoc :key c)))
                               :signature (hex-string-to-bytes (cdr (assoc :signature c)))))
                       culprits)
     :faults (mapcar (lambda (f)
                       (list :target (hex-string-to-bytes (cdr (assoc :target f)))
                             :vote (cdr (assoc :vote f))
                             :key (hex-string-to-bytes (cdr (assoc :key f)))
                             :signature (hex-string-to-bytes (cdr (assoc :signature f)))))
                     faults))))

;;; Helper: convert JSON psi state to our plist format
(defun json-psi-to-plist (psi-json)
  (list :good (json-hashes-to-bytes (cdr (assoc :good psi-json)))
        :bad (json-hashes-to-bytes (cdr (assoc :bad psi-json)))
        :wonky (json-hashes-to-bytes (cdr (assoc :wonky psi-json)))
        :offenders (json-hashes-to-bytes (cdr (assoc :offenders psi-json)))))

;;; Run test
(defun run-disputes-test (path spec)
  (let* ((json (cl-json:decode-json-from-string (uiop:read-file-string path)))
         (input (cdr (assoc :input json)))
         (pre (or (cdr (assoc :pre-state json))
                  (cdr (assoc :pre--state json))))
         (output (cdr (assoc :output json)))
         (post (or (cdr (assoc :post-state json))
                   (cdr (assoc :post--state json))))
         ;; Parse input
         (disputes (json-disputes-to-plist (cdr (assoc :disputes input))))
         ;; Parse pre-state
         (tau (cdr (assoc :tau pre)))
         (psi (json-psi-to-plist (cdr (assoc :psi pre))))
         (kappa (json-validators-to-plists (cdr (assoc :kappa pre))))
         (lambda-prev (json-validators-to-plists (cdr (assoc :lambda pre))))
         ;; Expected output
         (expected-ok (assoc :ok output))
         (expected-err (cdr (assoc :err output)))
         ;; File name for display
         (fname (file-namestring path)))
    (let ((*chain* (case spec
                    (:tiny +tiny-chainspec+)
                    (:full +full-chainspec+)
                    (otherwise (error "Unknown chain: ~A" spec)))))
      (handler-case
          (let ((psi-prime (transition-psi disputes psi tau kappa lambda-prev)))
            (if expected-ok
                ;; Expected success — compare post-state psi
                (let* ((post-psi (json-psi-to-plist (cdr (assoc :psi post))))
                       (good-match (= (length (getf psi-prime :good))
                                      (length (getf post-psi :good))))
                       (bad-match (= (length (getf psi-prime :bad))
                                     (length (getf post-psi :bad))))
                       (wonky-match (= (length (getf psi-prime :wonky))
                                       (length (getf post-psi :wonky))))
                       (offenders-match (= (length (getf psi-prime :offenders))
                                           (length (getf post-psi :offenders)))))
                  (if (and good-match bad-match wonky-match offenders-match)
                      (format t "  ✅ ~A~%" fname)
                      (format t "  ❌ ~A — state mismatch: good=~A/~A bad=~A/~A wonky=~A/~A off=~A/~A~%"
                              fname
                              (length (getf psi-prime :good)) (length (getf post-psi :good))
                              (length (getf psi-prime :bad)) (length (getf post-psi :bad))
                              (length (getf psi-prime :wonky)) (length (getf post-psi :wonky))
                              (length (getf psi-prime :offenders)) (length (getf post-psi :offenders)))))
                ;; Expected error — got success instead
                (format t "  ❌ ~A — expected error '~A' but got OK~%" fname expected-err)))
        (disputes-error (e)
          (if expected-err
              ;; Expected error — check code
              (format t "  ✅ ~A (err: ~A)~%" fname (disputes-error-code e))
              ;; Expected success — got error
              (format t "  ❌ ~A — unexpected error: ~A~%" fname e)))
        (error (e)
          (format t "  💥 ~A — ~A~%" fname e))))))

;;; Run all tests
(dolist (spec '(:tiny :full))
  (format t "~%=== Disputes STF Tests (~(~A~)) ===~%" spec)
  (let ((dir (format nil "tests/jamtestvectors/stf/disputes/~(~A~)/" spec)))
    (dolist (path (sort (directory (merge-pathnames "*.json" dir)) #'string<
                        :key #'namestring))
      (run-disputes-test (namestring path) spec))))
