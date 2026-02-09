;;;; v2/macros.lisp — define-state-closure: self-transforming state closures
;;;;
;;;; A state closure is a deterministic actor:
;;;;   - Holds immutable data (fields)
;;;;   - Derives lazy/memoized computed properties
;;;;   - Encodes itself to bytes
;;;;   - Knows its Merkle position (state-key)
;;;;   - Transforms itself into its prime via :transition
;;;;   - Answers semantic queries via method messages
;;;;
;;;; Protocol: variadic dispatch (funcall obj :msg &rest args)
;;;;   (funcall tau :slot)                → field access
;;;;   (funcall tau :epoch)               → memoized derived property
;;;;   (funcall tau :encoded)             → serialized bytes
;;;;   (funcall tau :stale? timeout)      → query with argument
;;;;   (funcall tau :transition :header h) → τ' closure
;;;;
;;;; See DESIGN.md §3 for full specification.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; STATE DECODER REGISTRY — used by sigma decode dispatch
;;; ═══════════════════════════════════════════════════════════════

(defvar *state-decoders* (make-hash-table :test 'equalp)
  "Maps C(n) byte-vector → (lambda (bytes offset) → (values closure consumed)).
   Populated by define-state-closure expansions.")

(defun register-state-decoder (state-key decoder-fn)
  "Register a state component decoder. Called by define-state-closure expansion."
  (setf (gethash state-key *state-decoders*) decoder-fn))

(defun decode-state-segment (state-key bytes offset)
  "Decode a state segment given its Merkle key and raw bytes.
   Dispatches to the decoder registered by define-state-closure."
  (let ((decoder (gethash state-key *state-decoders*)))
    (unless decoder
      (error "No decoder registered for state-key ~A" state-key))
    (funcall decoder bytes offset)))

;;; ═══════════════════════════════════════════════════════════════
;;; MACRO — define-state-closure
;;; ═══════════════════════════════════════════════════════════════

(defmacro define-state-closure (name (&rest field-specs) &body extra-clauses)
  "Define a self-transforming state closure (v2 protocol).

   Generates:
     (make-NAME &key field1 field2 ...) → closure
     (NAME-field1 obj)                  → value  (accessor per field)
     Closure responds to :as-plist, :type, field keys, memos, methods,
     and :transition.

   FIELD-SPECS: list of (PARAM DEFAULT) or (PARAM DEFAULT :key MSG-KEY)
     PARAM   — keyword parameter name in constructor
     DEFAULT — default value
     MSG-KEY — override message keyword (default: derived from PARAM)
               Trailing * is stripped: lambda* → :lambda, pi* → :pi

   EXTRA-CLAUSES:
     (:key BODY)              — computed on every access
     (:key :memo BODY)        — lazy-cached (computed once, memoized)
     (:key :alias FIELD-REF)  — simple alias
     (:state-key EXPR)        — Merkle key C(n), auto-generates :state-key/:merkle-kv
     (:decode (BYTES OFFSET) BODY)
                               — decoder function, registered in *state-decoders*
     (:key (PARAMS) BODY)     — method: message with arguments
                                 (funcall obj :key arg1 arg2 ...)
                                 PARAMS is a list of symbols (positional args)
     (:transition (LAMBDA-LIST) BODY)
                               — STF with keyword args: (funcall obj :transition :k v ...)
     (:transition-NAME (LAMBDA-LIST) BODY)
                               — multi-stage STF (e.g. :transition-dagger)

   `self` is available in all clause bodies (variadic: (self :msg ...)).

   Example:
     (define-state-closure tau-state
       ((slot 0))
       (:state-key +C11+)
       (:encoded :memo (E4 slot))
       (:epoch :memo (floor slot (epoch-duration)))
       (:stale? (timeout) (>= slot (+ timeout 5)))
       (:transition (&key header)
         (make-tau-state :slot (funcall header :slot))))"
  (let ((fields '())
        (memo-clauses '())
        (regular-clauses '())
        (method-clauses '())
        (transition-clauses '())
        (decode-clause nil)
        (state-key-expr nil))
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
    ;; ── Parse extra clauses ──
    (dolist (clause extra-clauses)
      (destructuring-bind (key &rest body) clause
        (let ((key-name (symbol-name key)))
          (cond
            ;; (:state-key EXPR)
            ((eq key :state-key)
             (setf state-key-expr (first body)))
            ;; (:decode (bytes offset) BODY)
            ((eq key :decode)
             (setf decode-clause (list :params (first body)
                                       :body (if (= (length (rest body)) 1)
                                                 (second body)
                                                 `(progn ,@(rest body))))))
            ;; (:transition LAMBDA-LIST BODY) or (:transition-xxx LAMBDA-LIST BODY)
            ((or (eq key :transition)
                 (and (> (length key-name) 11)
                      (string= key-name "TRANSITION-" :end1 11)))
             (push (list :key key
                         :lambda-list (first body)
                         :body (if (= (length (rest body)) 1)
                                   (second body)
                                   `(progn ,@(rest body))))
                   transition-clauses))
            ;; (:key :memo body...) → memoized
            ((and (>= (length body) 2)
                  (eq (first body) :memo))
             (push (list :key key :body (if (= (length (rest body)) 1)
                                            (second body)
                                            `(progn ,@(rest body))))
                   memo-clauses))
            ;; (:key (params) body...) → method with positional args
            ;; Detected: >= 2 body forms, first is a list of only symbols
            ((and (>= (length body) 2)
                  (listp (first body))
                  (every #'symbolp (first body)))
             (push (list :key key
                         :lambda-list (first body)
                         :body (if (= (length (rest body)) 1)
                                   (second body)
                                   `(progn ,@(rest body))))
                   method-clauses))
            ;; (:key body) → regular (computed every access)
            (t (push clause regular-clauses))))))
    (setf memo-clauses (nreverse memo-clauses))
    (setf regular-clauses (nreverse regular-clauses))
    (setf method-clauses (nreverse method-clauses))
    (setf transition-clauses (nreverse transition-clauses))
    ;; ── Generate ──
    (let ((constructor (intern (format nil "MAKE-~A" name)))
          (type-kw (intern (symbol-name name) :keyword))
          (memo-vars (loop for mc in memo-clauses
                           collect (gensym (format nil "MEMO-~A-" (getf mc :key))))))
      `(progn
         ;; ── Constructor ──
         (defun ,constructor
             (&key ,@(loop for f in fields
                           collect (list (getf f :param) (getf f :default))))
           ,(format nil "Creates ~A state closure (immutable, self-transforming)." name)
           ;; Memo cache variables (nil = not yet computed)
           (let (,@(loop for mv in memo-vars collect `(,mv nil)))
             ;; labels: self is variadic for :transition / method support
             (labels ((self (&rest args)
                        (declare (dynamic-extent args))
                        (let ((msg (car args)))
                          (case msg
                            ;; ── Field access ──
                            ,@(loop for f in fields
                                    collect `(,(getf f :key) ,(getf f :param)))
                            ;; ── Memoized computed messages ──
                            ,@(loop for mc in memo-clauses
                                    for mv in memo-vars
                                    collect `(,(getf mc :key)
                                              (or ,mv (setf ,mv ,(getf mc :body)))))
                            ;; ── Regular extra clauses ──
                            ,@regular-clauses
                            ;; ── Method clauses (queries with positional args) ──
                            ,@(loop for mc in method-clauses
                                    collect `(,(getf mc :key)
                                              (destructuring-bind ,(getf mc :lambda-list) (cdr args)
                                                ,(getf mc :body))))
                            ;; ── Transition clauses (STF with keyword args) ──
                            ,@(loop for tc in transition-clauses
                                    collect `(,(getf tc :key)
                                              (destructuring-bind ,(getf tc :lambda-list) (cdr args)
                                                ,(getf tc :body))))
                            ;; ── Decode (dispatched from instance) ──
                            ,@(when decode-clause
                                `((:decode
                                   (destructuring-bind ,(getf decode-clause :params) (cdr args)
                                     ,(getf decode-clause :body)))))
                            ;; ── State-key auto-generated messages ──
                            ,@(when state-key-expr
                                `((:state-key ,state-key-expr)
                                  (:merkle-kv (cons (self :state-key)
                                                    (self :encoded)))))
                            ;; ── Auto-generated ──
                            (:as-plist
                             (list ,@(loop for f in fields
                                           append (list (getf f :key)
                                                        (getf f :param)))))
                            (:type ,type-kw)
                            (otherwise
                             (error ,(format nil "Unknown ~A message: ~~a" name) msg))))))
               #'self)))
         ;; ── Accessors ──
         ,@(loop for f in fields
                 for acc-name = (intern (format nil "~A-~A" name (getf f :clean)))
                 collect `(defun ,acc-name (obj)
                            ,(format nil "Access ~A from ~A." (getf f :key) name)
                            (funcall obj ,(getf f :key))))
         ;; ── Register decoder in sigma dispatch table ──
         ,@(when (and state-key-expr decode-clause)
             `((register-state-decoder
                ,state-key-expr
                (lambda ,(getf decode-clause :params)
                  ,(getf decode-clause :body)))))))))
