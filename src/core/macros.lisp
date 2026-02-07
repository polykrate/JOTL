;;;; core/macros.lisp — Infrastructure macros for Pure FP value objects
;;;;
;;;; define-value-object: eliminates the closure + accessor boilerplate.
;;;; Used by sigma.lisp, beta.lisp, header.lisp, extrinsic.lisp, block.lisp.

(in-package #:jotl)

(defmacro define-value-object (name (&rest field-specs) &body extra-clauses)
  "Define an immutable value object as a message-dispatching closure.

   Generates:
     (make-NAME &key field1 field2 ...) → closure
     (NAME-field1 obj)                  → value  (accessor per field)
     Closure auto-responds to :as-plist, :type, and field keys.

   FIELD-SPECS: list of (PARAM DEFAULT) or (PARAM DEFAULT :key MSG-KEY)
     PARAM   — keyword parameter name in constructor
     DEFAULT — default value
     MSG-KEY — override message keyword (default: derived from PARAM)
               Trailing * is stripped: lambda* → :lambda, pi* → :pi

   EXTRA-CLAUSES: additional case clauses for computed messages.
     Three forms:
       (:key BODY)              — computed on every access
       (:key :memo BODY)        — lazy-cached (computed once, memoized)
       (:key :alias FIELD-REF)  — simple alias for another field/expression

   `self` is available in all extra-clause bodies to send messages to the
   closure itself (e.g. (:hash :memo (blake2b-256 (self :encoded)))).

   Example:
     (define-value-object header
       ((parent-hash nil) (slot nil) (seal nil))
       (:timeslot slot)
       (:encoded :memo (encode-header parent-hash slot seal))
       (:hash :memo (blake2b-256 (self :encoded))))"
  (let ((fields '())
        (memo-clauses '())
        (regular-clauses '()))
    ;; ── Parse field specs ──
    (dolist (spec field-specs)
      (destructuring-bind (param default &key key) spec
        (let* ((param-str (symbol-name param))
               ;; Strip trailing * (for CL reserved: lambda*, pi*)
               (clean-str (if (and (> (length param-str) 0)
                                   (char= (char param-str (1- (length param-str))) #\*))
                              (subseq param-str 0 (1- (length param-str)))
                              param-str))
               (msg-key (or key (intern clean-str :keyword))))
          (push (list :param param :default default
                      :key msg-key :clean clean-str)
                fields))))
    (setf fields (nreverse fields))
    ;; ── Parse extra clauses: separate :memo from regular ──
    (dolist (clause extra-clauses)
      (destructuring-bind (key &rest body) clause
        (if (and (>= (length body) 2)
                 (eq (first body) :memo))
            ;; (:key :memo body...) → memoized
            (push (list :key key :body (if (= (length (rest body)) 1)
                                           (second body)
                                           `(progn ,@(rest body))))
                  memo-clauses)
            ;; (:key body) → regular (including :alias)
            (push clause regular-clauses))))
    (setf memo-clauses (nreverse memo-clauses))
    (setf regular-clauses (nreverse regular-clauses))
    ;; ── Generate ──
    (let ((constructor (intern (format nil "MAKE-~A" name)))
          (type-kw (intern (symbol-name name) :keyword))
          (memo-vars (loop for mc in memo-clauses
                           collect (gensym (format nil "MEMO-~A-" (getf mc :key))))))
      `(progn
         ;; Constructor
         (defun ,constructor
             (&key ,@(loop for f in fields
                           collect (list (getf f :param) (getf f :default))))
           ,(format nil "Creates ~A value object (immutable closure)." name)
           ;; Memo cache variables (nil = not yet computed)
           (let (,@(loop for mv in memo-vars collect `(,mv nil)))
             ;; labels gives the closure a name 'self' for self-reference
             (labels ((self (msg)
                        (case msg
                          ;; Field access
                          ,@(loop for f in fields
                                  collect `(,(getf f :key) ,(getf f :param)))
                          ;; Memoized computed messages
                          ,@(loop for mc in memo-clauses
                                  for mv in memo-vars
                                  collect `(,(getf mc :key)
                                            (or ,mv (setf ,mv ,(getf mc :body)))))
                          ;; Regular extra clauses
                          ,@regular-clauses
                          ;; Auto-generated
                          (:as-plist
                           (list ,@(loop for f in fields
                                         append (list (getf f :key)
                                                      (getf f :param)))))
                          (:type ,type-kw)
                          (otherwise
                           (error ,(format nil "Unknown ~A message: ~~a" name) msg)))))
               #'self)))
         ;; Accessors
         ,@(loop for f in fields
                 for acc-name = (intern (format nil "~A-~A" name (getf f :clean)))
                 collect `(defun ,acc-name (obj)
                            ,(format nil "Access ~A from ~A." (getf f :key) name)
                            (funcall obj ,(getf f :key))))))))
