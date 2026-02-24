;;;; lib/macros.lisp — define-state-closure: the single macro for JOTL
;;;;
;;;; Every closure in JOTL (state components, block structures, sub-objects)
;;;; is built with define-state-closure.
;;;;
;;;; A closure is a deterministic, immutable, message-dispatching object:
;;;;   - Holds immutable data (fields)
;;;;   - Derives lazy/memoized computed properties
;;;;   - Saves itself to bytes (:save)
;;;;   - Loads from bytes via top-level load-NAME function
;;;;   - Answers semantic queries via method messages
;;;;   - Optionally transforms itself into its prime via :transition
;;;;
;;;; Merkle position (state key C(n)) is NOT the component's concern.
;;;; σ (sigma) owns the mapping C(n) → component AND the load dispatch.
;;;; Components just know their codec; σ knows where they live.
;;;;
;;;; Uniform access principle: all messages use (funcall obj :msg &rest args).

(in-package #:jotl)

(defmacro define-state-closure (name (&rest field-specs) &body extra-clauses)
  "Define a self-transforming state closure.

   Generates:
     (make-NAME &key field1 field2 ...) → closure   [internal constructor]
     (load-NAME bytes offset)           → (values closure consumed)  [when :decode present]

   FIELD-SPECS: (PARAM DEFAULT) or (PARAM DEFAULT :key MSG-KEY)
   EXTRA-CLAUSES:
     (:key BODY)                    — computed on every access
     (:key :memo BODY)              — lazy-cached
     (:decode (BYTES OFFSET) BODY)  — loader (generates top-level load-NAME)
     (:key (PARAMS) BODY)           — method with positional args
     (:transition (&key ...) BODY)  — STF: (funcall obj :transition :k v ...)
     (:transition-NAME (&key ...) BODY) — multi-stage STF"
  (let ((fields '())
        (memo-clauses '())
        (regular-clauses '())
        (method-clauses '())
        (transition-clauses '())
        (decode-clause nil))
    ;; ── Parse field specs ──
    (dolist (spec field-specs)
      (destructuring-bind (param default &key key) spec
        (let* ((param-str (symbol-name param))
               (clean-str (if (and (> (length param-str) 0)
                                   (char= (char param-str (1- (length param-str))) #\*))
                              (subseq param-str 0 (1- (length param-str)))
                              param-str))
               (msg-key (or key (intern clean-str :keyword))))
          (push (list :param param :default default
                      :key msg-key :clean clean-str)
                fields))))
    (setf fields (nreverse fields))
    ;; ── Parse extra clauses ──
    (dolist (clause extra-clauses)
      (destructuring-bind (key &rest body) clause
        (let ((key-name (symbol-name key)))
          (cond
            ((eq key :decode)
             (setf decode-clause (list :params (first body)
                                       :body (if (= (length (rest body)) 1)
                                                 (second body)
                                                 `(progn ,@(rest body))))))
            ((or (eq key :transition)
                 (and (> (length key-name) 11)
                      (string= key-name "TRANSITION-" :end1 11)))
             (push (list :key key
                         :lambda-list (first body)
                         :body-forms (rest body))
                   transition-clauses))
            ((and (>= (length body) 2)
                  (eq (first body) :memo))
             (push (list :key key :body (if (= (length (rest body)) 1)
                                            (second body)
                                            `(progn ,@(rest body))))
                   memo-clauses))
            ((and (>= (length body) 2)
                  (listp (first body))
                  (every #'symbolp (first body)))
             (push (list :key key
                         :lambda-list (first body)
                         :body-forms (rest body))
                   method-clauses))
            (t (push clause regular-clauses))))))
    (setf memo-clauses (nreverse memo-clauses))
    (setf regular-clauses (nreverse regular-clauses))
    (setf method-clauses (nreverse method-clauses))
    (setf transition-clauses (nreverse transition-clauses))
    ;; ── Generate ──
    (let ((constructor (intern (format nil "MAKE-~A" name)))
          (loader-fn (when decode-clause (intern (format nil "LOAD-~A" name))))
          (memo-vars (loop for mc in memo-clauses
                           collect (gensym (format nil "MEMO-~A-" (getf mc :key))))))
      `(progn
         (defun ,constructor
             (&key ,@(loop for f in fields
                           collect (list (getf f :param) (getf f :default))))
           ,(format nil "Creates ~A state closure (immutable, self-transforming)." name)
           (let (,@(loop for mv in memo-vars collect `(,mv nil)))
             (labels ((self (&rest args)
                        (declare (dynamic-extent args))
                        (let ((msg (car args)))
                          (case msg
                            ,@(loop for f in fields
                                    collect `(,(getf f :key) ,(getf f :param)))
                            ,@(loop for mc in memo-clauses
                                    for mv in memo-vars
                                    collect `(,(getf mc :key)
                                              (or ,mv (setf ,mv ,(getf mc :body)))))
                            ,@regular-clauses
                            ,@(loop for mc in method-clauses
                                    collect `(,(getf mc :key)
                                              (destructuring-bind ,(getf mc :lambda-list) (cdr args)
                                                ,@(getf mc :body-forms))))
                            ,@(loop for tc in transition-clauses
                                    collect `(,(getf tc :key)
                                              (destructuring-bind ,(getf tc :lambda-list) (cdr args)
                                                ,@(getf tc :body-forms))))
                            (otherwise
                             (error ,(format nil "Unknown ~A message: ~~a" name) msg))))))
               #'self)))
         ,@(when decode-clause
             `((defun ,loader-fn ,(getf decode-clause :params)
                 ,(format nil "Load ~A from bytes. Public standalone loader." name)
                 ,(getf decode-clause :body))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; PROF — lightweight phase profiler
;;; ═══════════════════════════════════════════════════════════════
;;; When *prof* is bound to a hash-table, (prof :phase body) accumulates
;;; wall-clock time under the given key.  Zero overhead when *prof* is NIL.

(defvar *prof* nil
  "When bound to a hash-table, (prof :key body) accumulates timing.
   Keys → internal-time-units (use prof-seconds to convert).")

(defmacro prof (phase &body body)
  "Accumulate wall-clock time for PHASE when *prof* is active."
  (let ((t0 (gensym "T0")))
    `(if *prof*
         (let ((,t0 (get-internal-real-time)))
           (multiple-value-prog1 (progn ,@body)
             (let ((elapsed (- (get-internal-real-time) ,t0)))
               (if (gethash ,phase *prof*)
                   (incf (the integer (gethash ,phase *prof*)) elapsed)
                   (setf (gethash ,phase *prof*) elapsed)))))
         (progn ,@body))))

(defun prof-seconds (phase)
  "Return accumulated seconds for PHASE, or 0."
  (if *prof*
      (/ (gethash phase *prof* 0)
         (float internal-time-units-per-second))
      0.0))
