;;;; lib/macros.lisp — define-state-closure: the single macro for JOTL
;;;;
;;;; Every closure in JOTL (state components, block structures, sub-objects)
;;;; is built with define-state-closure.
;;;;
;;;; A closure is a deterministic, immutable, message-dispatching object:
;;;;   - Holds immutable data (fields)
;;;;   - Derives lazy/memoized computed properties
;;;;   - Encodes itself to bytes (:encoded)
;;;;   - Decodes from bytes (:decode message + top-level decode-NAME fn)
;;;;   - Answers semantic queries via method messages
;;;;   - Optionally transforms itself into its prime via :transition
;;;;
;;;; Merkle position (state key C(n)) is NOT the component's concern.
;;;; σ (sigma) owns the mapping C(n) → component AND the decode dispatch.
;;;; Components just know their codec; σ knows where they live.
;;;;
;;;; Uniform access principle: all messages use (funcall obj :msg &rest args).

(in-package #:jotl)

(defmacro define-state-closure (name (&rest field-specs) &body extra-clauses)
  "Define a self-transforming state closure.

   Generates:
     (make-NAME &key field1 field2 ...) → closure
     (NAME-field1 obj)                  → value  (accessor per field)
     (decode-NAME bytes offset)         → (values closure consumed)  [when :decode present]

   FIELD-SPECS: (PARAM DEFAULT) or (PARAM DEFAULT :key MSG-KEY)
   EXTRA-CLAUSES:
     (:key BODY)                    — computed on every access
     (:key :memo BODY)              — lazy-cached
     (:decode (BYTES OFFSET) BODY)  — decoder (also generates top-level decode-NAME)
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
                         :body (if (= (length (rest body)) 1)
                                   (second body)
                                   `(progn ,@(rest body))))
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
                         :body (if (= (length (rest body)) 1)
                                   (second body)
                                   `(progn ,@(rest body))))
                   method-clauses))
            (t (push clause regular-clauses))))))
    (setf memo-clauses (nreverse memo-clauses))
    (setf regular-clauses (nreverse regular-clauses))
    (setf method-clauses (nreverse method-clauses))
    (setf transition-clauses (nreverse transition-clauses))
    ;; ── Generate ──
    (let ((constructor (intern (format nil "MAKE-~A" name)))
          (decoder-fn (when decode-clause (intern (format nil "DECODE-~A" name))))
          (type-kw (intern (symbol-name name) :keyword))
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
                                                ,(getf mc :body))))
                            ,@(loop for tc in transition-clauses
                                    collect `(,(getf tc :key)
                                              (destructuring-bind ,(getf tc :lambda-list) (cdr args)
                                                ,(getf tc :body))))
                            ,@(when decode-clause
                                `((:decode
                                   (destructuring-bind ,(getf decode-clause :params) (cdr args)
                                     ,(getf decode-clause :body)))))
                            (:as-plist
                             (list ,@(loop for f in fields
                                           append (list (getf f :key)
                                                        (getf f :param)))))
                            (:type ,type-kw)
                            (otherwise
                             (error ,(format nil "Unknown ~A message: ~~a" name) msg))))))
               #'self)))
         ,@(loop for f in fields
                 for acc-name = (intern (format nil "~A-~A" name (getf f :clean)))
                 collect `(defun ,acc-name (obj)
                            ,(format nil "Access ~A from ~A." (getf f :key) name)
                            (funcall obj ,(getf f :key))))
         ,@(when decode-clause
             `((defun ,decoder-fn ,(getf decode-clause :params)
                 ,(format nil "Decode ~A from bytes.  Top-level standalone decoder." name)
                 ,(getf decode-clause :body))))))))
