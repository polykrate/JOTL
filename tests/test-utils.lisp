;;;; tests/test-utils.lisp — Shared test utilities
;;;;
;;;; Loaded by all test files. Provides:
;;;;   hex-to-bytes, bytes=, hex=, load-json, load-bin
;;;;   json-validators, json-hashes-to-bytes, json-work-report, json-disputes
;;;;   compare-bytes, compare-hash-sets, compare-eta, compare-validator-list

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; BASIC HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun hex-to-bytes (hex-str)
  "Convert hex string to byte vector.
   Handles nil, empty strings, and 0x prefix."
  (cond
    ((null hex-str) (make-array 0 :element-type '(unsigned-byte 8)))
    ((and (stringp hex-str) (or (string= hex-str "") (string= hex-str "0x")))
     (make-array 0 :element-type '(unsigned-byte 8)))
    (t (jam.ffi:hex-string-to-bytes hex-str))))

(defun bytes= (a b)
  "Compare two byte vectors for equality."
  (equalp a b))

(defun hex= (bytes hex-string)
  "Compare byte vector against a 0x-prefixed hex string."
  (bytes= bytes (hex-to-bytes hex-string)))

(defun load-json (path)
  "Load a JSON file and return parsed alist."
  (cl-json:decode-json-from-string (uiop:read-file-string path)))

(defun load-bin (path)
  "Load a binary file into a byte vector."
  (alexandria:read-file-into-byte-vector path))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON→LISP PARSERS — shared across test files
;;; ═══════════════════════════════════════════════════════════════

(defun json-validators (validators-json)
  "Parse JSON validator list → list of plists with all 4 key types.
   Handles cl-json renaming ed25519 → ed-25519."
  (mapcar (lambda (v)
            (list :bandersnatch (hex-to-bytes (cdr (assoc :bandersnatch v)))
                  :ed25519      (hex-to-bytes (or (cdr (assoc :ed25519 v))
                                                   (cdr (assoc :ed-25519 v))))
                  :bls          (hex-to-bytes (cdr (assoc :bls v)))
                  :metadata     (hex-to-bytes (cdr (assoc :metadata v)))))
          validators-json))

(defun json-hashes-to-bytes (hash-list)
  "Convert a list of hex strings to a list of byte vectors."
  (mapcar #'hex-to-bytes hash-list))

(defun json-work-report (wr-json)
  "Parse a JSON WorkReport → plist (same format as our internal representation).
   Returns nil if wr-json is nil."
  (when (null wr-json) (return-from json-work-report nil))
  (let* ((pkg-json (cdr (assoc :package--spec wr-json)))
         (ctx-json (cdr (assoc :context wr-json)))
         (results-json (cdr (assoc :results wr-json)))
         ;; WorkPackageSpec
         (package-spec (list :hash (hex-to-bytes (cdr (assoc :hash pkg-json)))
                             :length (cdr (assoc :length pkg-json))
                             :erasure-root (hex-to-bytes (cdr (assoc :erasure--root pkg-json)))
                             :exports-root (hex-to-bytes (cdr (assoc :exports--root pkg-json)))
                             :exports-count (cdr (assoc :exports--count pkg-json))))
         ;; RefineContext
         (prereqs-json (cdr (assoc :prerequisites ctx-json)))
         (context (list :anchor (hex-to-bytes (cdr (assoc :anchor ctx-json)))
                        :state-root (hex-to-bytes (cdr (assoc :state--root ctx-json)))
                        :beefy-root (hex-to-bytes (cdr (assoc :beefy--root ctx-json)))
                        :lookup-anchor (hex-to-bytes (cdr (assoc :lookup--anchor ctx-json)))
                        :lookup-anchor-slot (cdr (assoc :lookup--anchor--slot ctx-json))
                        :prerequisites (mapcar #'hex-to-bytes (or prereqs-json '()))))
         ;; WorkResults
         (results (mapcar (lambda (r-json)
                            (let* ((result-val-json (cdr (assoc :result r-json)))
                                   (result-val
                                     (cond
                                       ((assoc :ok result-val-json)
                                        (list :ok (hex-to-bytes
                                                   (cdr (assoc :ok result-val-json)))))
                                       ((assoc :out--of--gas result-val-json)
                                        (list :out-of-gas t))
                                       ((assoc :panic result-val-json)
                                        (list :panic t))
                                       ((assoc :bad--exports result-val-json)
                                        (list :bad-exports t))
                                       ((assoc :output--oversize result-val-json)
                                        (list :output-oversize t))
                                       ((assoc :bad--code result-val-json)
                                        (list :bad-code t))
                                       ((assoc :code--oversize result-val-json)
                                        (list :code-oversize t))
                                       (t (error "Unknown result variant: ~A"
                                                  result-val-json))))
                                   (rl-json (cdr (assoc :refine--load r-json)))
                                   (refine-load
                                     (list :gas-used (cdr (assoc :gas--used rl-json))
                                           :imports (cdr (assoc :imports rl-json))
                                           :extrinsic-count (cdr (assoc :extrinsic--count rl-json))
                                           :extrinsic-size (cdr (assoc :extrinsic--size rl-json))
                                           :exports (cdr (assoc :exports rl-json)))))
                              (list :service-id (cdr (assoc :service--id r-json))
                                    :code-hash (hex-to-bytes
                                                (cdr (assoc :code--hash r-json)))
                                    :payload-hash (hex-to-bytes
                                                   (cdr (assoc :payload--hash r-json)))
                                    :accumulate-gas (cdr (assoc :accumulate--gas r-json))
                                    :result result-val
                                    :refine-load refine-load)))
                          results-json)))
    (list :package-spec package-spec
          :context context
          :core-index (cdr (assoc :core--index wr-json))
          :authorizer-hash (hex-to-bytes (cdr (assoc :authorizer--hash wr-json)))
          :auth-gas-used (cdr (assoc :auth--gas--used wr-json))
          :auth-output (hex-to-bytes (cdr (assoc :auth--output wr-json)))
          :segment-root-lookup (mapcar (lambda (item)
                                         (list :work-package-hash
                                               (hex-to-bytes
                                                (cdr (assoc :work--package--hash item)))
                                               :segment-tree-root
                                               (hex-to-bytes
                                                (cdr (assoc :segment--tree--root item)))))
                                       (or (cdr (assoc :segment--root--lookup wr-json)) '()))
          :results results)))

(defun json-disputes (disputes-json)
  "Parse JSON disputes extrinsic → plist (:verdicts :culprits :faults).
   Each sub-list contains plists with byte-vector fields."
  (let ((verdicts-json (cdr (assoc :verdicts disputes-json)))
        (culprits-json (cdr (assoc :culprits disputes-json)))
        (faults-json (cdr (assoc :faults disputes-json))))
    (list
     :verdicts (mapcar (lambda (v)
                         (list :target (hex-to-bytes (cdr (assoc :target v)))
                               :age (cdr (assoc :age v))
                               :votes (mapcar (lambda (vote)
                                                (list :vote (cdr (assoc :vote vote))
                                                      :index (cdr (assoc :index vote))
                                                      :signature (hex-to-bytes
                                                                  (cdr (assoc :signature vote)))))
                                              (cdr (assoc :votes v)))))
                       (or verdicts-json '()))
     :culprits (mapcar (lambda (c)
                         (list :target (hex-to-bytes (cdr (assoc :target c)))
                               :key (hex-to-bytes (cdr (assoc :key c)))
                               :signature (hex-to-bytes (cdr (assoc :signature c)))))
                       (or culprits-json '()))
     :faults (mapcar (lambda (f)
                       (list :target (hex-to-bytes (cdr (assoc :target f)))
                             :vote (cdr (assoc :vote f))
                             :key (hex-to-bytes (cdr (assoc :key f)))
                             :signature (hex-to-bytes (cdr (assoc :signature f)))))
                     (or faults-json '())))))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARISON HELPERS — labeled deep comparisons
;;; ═══════════════════════════════════════════════════════════════

(defun compare-bytes (label actual expected)
  "Compare two byte vectors. Returns T if equal, prints diff on mismatch."
  (if (equalp actual expected)
      t
      (progn
        (format t "    ✗ ~A: bytes mismatch~%" label)
        (when (and actual expected)
          (format t "      got-len: ~D  want-len: ~D~%" (length actual) (length expected))
          (when (and (<= (length actual) 64) (<= (length expected) 64))
            (format t "      got:  ~A~%      want: ~A~%"
                    (jam.ffi:bytes-to-hex-string actual)
                    (jam.ffi:bytes-to-hex-string expected))))
        nil)))

(defun compare-hash-sets (label actual expected)
  "Compare two lists of 32-byte hashes. Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label (length actual) (length expected))
      (return-from compare-hash-sets nil))
    (loop for a in actual for e in expected for i from 0
          unless (equalp a e)
            do (format t "    ✗ ~A[~D]: ~A ≠ ~A~%"
                       label i
                       (jam.ffi:bytes-to-hex-string a)
                       (jam.ffi:bytes-to-hex-string e))
               (setf ok nil))
    ok))

(defun compare-eta (label actual expected)
  "Compare two η (list of 4 hashes). Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: η length ~D ≠ ~D~%" label (length actual) (length expected))
      (return-from compare-eta nil))
    (loop for a in actual for e in expected for i from 0
          unless (equalp a e)
          do (format t "    ✗ ~A: η[~D]~%      got:  ~A~%      want: ~A~%"
                     label i
                     (jam.ffi:bytes-to-hex-string a)
                     (jam.ffi:bytes-to-hex-string e))
             (setf ok nil))
    ok))

(defun compare-validator-list (label actual expected)
  "Compare two lists of full validators (K plists). Returns T if all match."
  (let ((ok t))
    (unless (= (length actual) (length expected))
      (format t "    ✗ ~A: length ~D ≠ ~D~%" label (length actual) (length expected))
      (return-from compare-validator-list nil))
    (loop for a in actual for e in expected for i from 0
          do (unless (and (equalp (getf a :bandersnatch) (getf e :bandersnatch))
                          (equalp (getf a :ed25519)      (getf e :ed25519))
                          (equalp (getf a :bls)           (getf e :bls))
                          (equalp (getf a :metadata)      (getf e :metadata)))
               (format t "    ✗ ~A[~D]: validator mismatch~%" label i)
               (unless (equalp (getf a :bandersnatch) (getf e :bandersnatch))
                 (format t "      band got:  ~A~%      band want: ~A~%"
                         (jam.ffi:bytes-to-hex-string (getf a :bandersnatch))
                         (jam.ffi:bytes-to-hex-string (getf e :bandersnatch))))
               (unless (equalp (getf a :ed25519) (getf e :ed25519))
                 (format t "      ed25 got:  ~A~%      ed25 want: ~A~%"
                         (jam.ffi:bytes-to-hex-string (getf a :ed25519))
                         (jam.ffi:bytes-to-hex-string (getf e :ed25519))))
               (setf ok nil)))
    ok))
