;;;; tests/test-pi.lisp — π Validator Statistics test suite
;;;;
;;;; Tests against jamtestvectors/stf/statistics/{tiny,full}/
;;;;
;;;; Test vectors format:
;;;;   Input:     {slot, author_index, extrinsic}
;;;;   PreState:  {vals_curr_stats, vals_last_stats, slot, curr_validators}
;;;;   Output:    NULL
;;;;   PostState: {vals_curr_stats, vals_last_stats, slot, curr_validators}

(in-package #:jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; JSON → LISP PARSERS
;;; ═══════════════════════════════════════════════════════════════

(defun json-validator-activity (json-obj)
  "Parse a ValidatorActivityRecord from JSON alist."
  (list :blocks         (cdr (assoc :blocks json-obj))
        :tickets        (cdr (assoc :tickets json-obj))
        :preimages      (cdr (assoc :pre--images json-obj))
        :preimages-size (cdr (assoc :pre--images--size json-obj))
        :guarantees     (cdr (assoc :guarantees json-obj))
        :assurances     (cdr (assoc :assurances json-obj))))

(defun json-validators-statistics (json-array)
  "Parse an array of ValidatorActivityRecords from JSON."
  (mapcar #'json-validator-activity json-array))

(defun json-guarantee-signatures (guarantee-json)
  "Extract guarantor signatures from a JSON guarantee.
   Returns list of (:validator-index idx :signature bytes)."
  (let ((sigs-json (cdr (assoc :signatures guarantee-json))))
    (mapcar (lambda (s)
              (list :validator-index (cdr (assoc :validator--index s))
                    :signature (hex-to-bytes (cdr (assoc :signature s)))))
            sigs-json)))

(defun json-assurances-for-stats (assurances-json)
  "Parse assurances for statistics: extract validator-index per assurance."
  (mapcar (lambda (a)
            (list :validator-index (cdr (assoc :validator--index a))))
          assurances-json))

(defun json-preimages-for-stats (preimages-json)
  "Parse preimages for statistics: extract blob sizes."
  (mapcar (lambda (p)
            (list :blob (hex-to-bytes (cdr (assoc :blob p)))))
          preimages-json))

;;; ═══════════════════════════════════════════════════════════════
;;; BINARY PARSER — decode State from binary test vector
;;; ═══════════════════════════════════════════════════════════════

(defun decode-pi-test-state (bytes offset)
  "Decode the test vector State:
     π_V (V×24), π_L (V×24), τ (u32), validators (V×336).
   Returns: (values vals-curr vals-last slot consumed)."
  (let ((pos offset))
    ;; π_V
    (multiple-value-bind (vc vc-consumed) (decode-validators-statistics bytes pos)
      (incf pos vc-consumed)
      ;; π_L
      (multiple-value-bind (vl vl-consumed) (decode-validators-statistics bytes pos)
        (incf pos vl-consumed)
        ;; τ
        (multiple-value-bind (slot slot-consumed) (decode-u32 bytes pos)
          (incf pos slot-consumed)
          ;; validators (V×336) — skip, not needed for transition test
          (let ((validators-consumed (* (num-validators) +validator-key-size+)))
            (incf pos validators-consumed)
            (values vc vl slot (- pos offset))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; COMPARE HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defvar *pi-errors* 0)

(defun pi-check (label test &optional detail)
  (if test
      (format t "    ✓ ~A~%" label)
      (progn (incf *pi-errors*)
             (format t "    ✗ ~A~@[ — ~A~]~%" label detail))))

(defun compare-validator-stats (label actual expected)
  "Compare two lists of V validator activity records."
  (loop for vi from 0 below (length expected)
        for a-rec = (nth vi actual)
        for e-rec = (nth vi expected)
        do (dolist (key '(:blocks :tickets :preimages :preimages-size
                          :guarantees :assurances))
             (let ((av (getf a-rec key))
                   (ev (getf e-rec key)))
               (unless (eql av ev)
                 (incf *pi-errors*)
                 (format t "    ✗ ~A v[~D].~A: got ~D, expected ~D~%"
                         label vi key av ev))))))

;;; ═══════════════════════════════════════════════════════════════
;;; MAIN TEST — JSON-based (for debugging)
;;; ═══════════════════════════════════════════════════════════════

(defun test-pi-json (label json-path)
  "Run a single π statistics test from a JSON test vector."
  (format t "~%── ~A ──~%" label)
  (let* ((*pi-errors* 0)
         (json (load-json json-path))
         ;; Input
         (input (cdr (assoc :input json)))
         (slot-new (cdr (assoc :slot input)))
         (author (cdr (assoc :author--index input)))
         (extrinsic (cdr (assoc :extrinsic input)))
         ;; Pre-state
         (pre (cdr (assoc :pre--state json)))
         (pre-curr (json-validators-statistics (cdr (assoc :vals--curr--stats pre))))
         (pre-last (json-validators-statistics (cdr (assoc :vals--last--stats pre))))
         (pre-slot (cdr (assoc :slot pre)))
         ;; Post-state (expected)
         (post (cdr (assoc :post--state json)))
         (exp-curr (json-validators-statistics (cdr (assoc :vals--curr--stats post))))
         (exp-last (json-validators-statistics (cdr (assoc :vals--last--stats post)))))
    ;; Build π closure from pre-state
    (let* ((pi-cl (make-pi-state :vals-curr pre-curr :vals-last pre-last))
           ;; Build minimal τ and τ'
           (tau (make-tau-state :slot pre-slot))
           (tau-prime (make-tau-state :slot slot-new))
           ;; Build minimal header
           (header (lambda (msg &rest args)
                     (declare (ignore args))
                     (case msg
                       (:slot slot-new)
                       (:author-index author)
                       (otherwise nil))))
           ;; Parse extrinsic components
           (tickets (cdr (assoc :tickets extrinsic)))
           (preimages-json (cdr (assoc :preimages extrinsic)))
           (guarantees-json (cdr (assoc :guarantees extrinsic)))
           (assurances-json (cdr (assoc :assurances extrinsic)))
           ;; Parse for the transition
           (preimages (json-preimages-for-stats preimages-json))
           (assurances (json-assurances-for-stats assurances-json))
           (guarantees (mapcar (lambda (g)
                                 (list :signatures (json-guarantee-signatures g)))
                               guarantees-json))
           ;; Run transition
           (pi-prime (funcall pi-cl :transition
                              :header header
                              :tau tau :tau-prime tau-prime
                              :tickets tickets :preimages preimages
                              :assurances assurances :guarantees guarantees
                              :kappa-prime nil)))
      ;; Compare
      (let ((act-curr (funcall pi-prime :vals-curr))
            (act-last (funcall pi-prime :vals-last)))
        (format t "  Comparing π'_V (current):~%")
        (compare-validator-stats "π_V" act-curr exp-curr)
        (format t "  Comparing π'_L (last):~%")
        (compare-validator-stats "π_L" act-last exp-last))
      (if (zerop *pi-errors*)
          (progn (format t "  ✅ PASS~%") t)
          (progn (format t "  ❌ FAIL (~D errors)~%" *pi-errors*) nil)))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUNNER
;;; ═══════════════════════════════════════════════════════════════

(defun run-pi-tests (&key (spec :tiny))
  "Run all π statistics test vectors."
  (let* ((dir (format nil "tests/jamtestvectors/stf/statistics/~(~A~)/" spec))
         (pass 0) (fail 0))
    (format t "~%═══════════════════════════════════════════════════~%")
    (format t "  π Statistics Tests — ~A~%" spec)
    (format t "═══════════════════════════════════════════════════~%")
    (dolist (file (sort (directory (merge-pathnames "*.json" dir))
                        #'string< :key #'namestring))
      (handler-case
          (if (test-pi-json (pathname-name file) (namestring file))
              (incf pass)
              (incf fail))
        (error (e)
          (format t "~%ERROR in ~A: ~A~%" (pathname-name file) e)
          (incf fail))))
    (format t "~%═══════════════════════════════════════════════════~%")
    (format t "  Results: ~D passed, ~D failed~%" pass fail)
    (format t "═══════════════════════════════════════════════════~%")
    (zerop fail)))
