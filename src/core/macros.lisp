;;;; core/macros.lisp — Infrastructure macros for Pure FP value objects
;;;;
;;;; define-value-object: eliminates the closure + accessor boilerplate.
;;;; Used by sigma.lisp, beta.lisp, and all future STF state segments.

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

   EXTRA-CLAUSES: additional (MSG-KEY BODY) case clauses for computed messages.

   Example:
     (define-value-object beta
       ((history '()) (mmr-peaks #()))
       (:length (length history))
       (:full-p (>= (length history) +history-size+)))"
  (let ((fields '()))
    ;; Parse field specs
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
    (let ((constructor (intern (format nil "MAKE-~A" name)))
          (type-kw (intern (symbol-name name) :keyword)))
      `(progn
         ;; Constructor
         (defun ,constructor
             (&key ,@(loop for f in fields
                           collect (list (getf f :param) (getf f :default))))
           ,(format nil "Creates ~A value object (immutable closure)." name)
           (lambda (msg)
             (case msg
               ;; Field access
               ,@(loop for f in fields
                       collect `(,(getf f :key) ,(getf f :param)))
               ;; Extra computed messages
               ,@extra-clauses
               ;; Auto-generated
               (:as-plist
                (list ,@(loop for f in fields
                              append (list (getf f :key) (getf f :param)))))
               (:type ,type-kw)
               (otherwise
                (error ,(format nil "Unknown ~A message: ~~a" name) msg)))))
         ;; Accessors
         ,@(loop for f in fields
                 for acc-name = (intern (format nil "~A-~A" name (getf f :clean)))
                 collect `(defun ,acc-name (obj)
                            ,(format nil "Access ~A from ~A." (getf f :key) name)
                            (funcall obj ,(getf f :key))))))))
