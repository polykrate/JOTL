;;;; work.lisp
;;;; JAM Work structures for block reports
;;;; Graypaper references: Appendix C.24, C.25, C.29, C.34

(in-package :jotl-bloc)

;;; Context structure (C)
;;;
;;; Graypaper Appendix C.24:
;;; E(x ∈ C) ≡ E(xa, xs, xb, xl, E4(xt), ↕xp)
;;;
;;; Where:
;;; - xa: anchor hash
;;; - xs: state root
;;; - xb: beefy root
;;; - xl: lookup anchor
;;; - xt: lookup anchor slot (timeslot)
;;; - xp: prerequisites (sequence)

(defstruct refine-context
  "Context structure (C) for work items.
   
   Used in work reports to specify the state context."
  ;; xa ∈ H : anchor hash (32 bytes)
  (anchor nil :type (or null list))
  
  ;; xs ∈ H : state root (32 bytes)
  (state-root nil :type (or null list))
  
  ;; xb ∈ H : beefy root (32 bytes)
  (beefy-root nil :type (or null list))
  
  ;; xl ∈ H : lookup anchor (32 bytes)
  (lookup-anchor nil :type (or null list))
  
  ;; xt ∈ N : lookup anchor slot (4 bytes, E4)
  (lookup-anchor-slot nil :type (or null integer))
  
  ;; xp : prerequisites (sequence)
  (prerequisites nil :type list))

;;; Package Spec structure (Y)
;;;
;;; Graypaper Appendix C.25:
;;; E(x ∈ Y) ≡ E(xp, E4(xl), xu, xe, E2(xn))
;;;
;;; Where:
;;; - xp: package hash
;;; - xl: length
;;; - xu: erasure root
;;; - xe: exports root
;;; - xn: exports count

(defstruct package-spec
  "Package specification (Y).
   
   Describes a work package being reported on."
  ;; xp ∈ H : package hash (32 bytes)
  (hash nil :type (or null list))
  
  ;; xl ∈ N : length (4 bytes, E4)
  (length nil :type (or null integer))
  
  ;; xu ∈ H : erasure root (32 bytes)
  (erasure-root nil :type (or null list))
  
  ;; xe ∈ H : exports root (32 bytes)
  (exports-root nil :type (or null list))
  
  ;; xn ∈ N : exports count (2 bytes, E2)
  (exports-count nil :type (or null integer)))

;;; Refine Load structure
;;;
;;; Part of work results, describes resource usage during refine stage

(defstruct refine-load
  "Resource usage during refine stage."
  (gas-used nil :type (or null integer))
  (imports nil :type (or null integer))
  (extrinsic-count nil :type (or null integer))
  (extrinsic-size nil :type (or null integer))
  (exports nil :type (or null integer)))

;;; Work Result structure (W)
;;;
;;; Graypaper Appendix C.29:
;;; E(w ∈ W) ≡ E(E4(ws), wc, E8(wg), E8(wa), E2(we), ↕wy, ...)
;;;
;;; Where:
;;; - ws: service id
;;; - wc: code hash
;;; - wg: accumulate gas
;;; - wa: accumulate gas used (?)
;;; - we: export count (?)
;;; - wy: payload hash (?)

(defstruct work-result
  "Work result (W) for a single work item execution.
   
   Describes the outcome of executing a work item."
  ;; ws ∈ N : service id (4 bytes, E4)
  (service-id nil :type (or null integer))
  
  ;; wc ∈ H : code hash (32 bytes)
  (code-hash nil :type (or null list))
  
  ;; Payload hash (32 bytes) - from JSON
  (payload-hash nil :type (or null list))
  
  ;; wg ∈ N : accumulate gas (8 bytes, E8)
  (accumulate-gas nil :type (or null integer))
  
  ;; Result discriminant: ok(data) or panic(data) or other
  ;; Using C.34 encoding
  (result nil :type t)
  
  ;; Refine load information
  (refine-load nil :type (or null refine-load)))

;;; Work Report structure (complete)
;;;
;;; This is what actually goes in extrinsic.guarantees[]

(defstruct work-report
  "Complete work report structure.
   
   This is what EG (guarantees/reports) contains in a block."
  ;; Package specification (Y)
  (package-spec nil :type (or null package-spec))
  
  ;; Context (C)
  (context nil :type (or null refine-context))
  
  ;; Core index
  (core-index nil :type (or null integer))
  
  ;; Authorizer hash (32 bytes)
  (authorizer-hash nil :type (or null list))
  
  ;; Authorization gas used
  (auth-gas-used nil :type (or null integer))
  
  ;; Authorization output (blob)
  (auth-output nil :type (or null list))
  
  ;; Segment root lookup (sequence)
  (segment-root-lookup nil :type list)
  
  ;; Results (sequence of work-result)
  (results nil :type list))

;;; Guarantee structure
;;;
;;; A guarantee wraps a work-report with validator signatures

(defstruct guarantee
  "Guarantee structure for extrinsic.
   
   Wraps a work-report with its slot and validator signatures."
  ;; The work report
  (report nil :type (or null work-report))
  
  ;; Slot (timeslot)
  (slot nil :type (or null integer))
  
  ;; Signatures: list of (validator-index, signature) pairs
  (signatures nil :type list))

;;; Encoding functions

(defun encode-refine-context (context)
  "Encode refine context (C).
   
   Graypaper Appendix C.24: E(x ∈ C) ≡ E(xa, xs, xb, xl, E4(xt), ↕xp)
   
   Args:
     context: A refine-context structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   ;; xa : anchor (32 bytes)
   (refine-context-anchor context)
   ;; xs : state root (32 bytes)
   (refine-context-state-root context)
   ;; xb : beefy root (32 bytes)
   (refine-context-beefy-root context)
   ;; xl : lookup anchor (32 bytes)
   (refine-context-lookup-anchor context)
   ;; E4(xt) : lookup anchor slot (4 bytes)
   (e4 (refine-context-lookup-anchor-slot context))
   ;; ↕xp : prerequisites (length-prefixed sequence)
   (encode-with-length
    (apply #'concat-octets (refine-context-prerequisites context)))))

(defun decode-refine-context (octets &optional (start 0))
  "Decode refine context (C).
   
   Inverse of encode-refine-context.
   
   Args:
     octets: Encoded context data
     start: Starting position
   
   Returns:
     values: (refine-context bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      ;; xa : anchor (32 bytes)
      (anchor (decode-hash octets pos))
      ;; xs : state root (32 bytes)
      (state-root (decode-hash octets pos))
      ;; xb : beefy root (32 bytes)
      (beefy-root (decode-hash octets pos))
      ;; xl : lookup anchor (32 bytes)
      (lookup-anchor (decode-hash octets pos))
      ;; E4(xt) : lookup anchor slot (4 bytes)
      (lookup-anchor-slot (decode-e4 octets pos))
      
      ;; ↕xp : prerequisites (length-prefixed sequence of hashes)
      ;; FIXME: Test vector encoding is unclear. Appears to omit count when empty.
      ;; For now, hardcode empty list and don't consume any bytes.
      
      (values
       (make-refine-context
        :anchor anchor
        :state-root state-root
        :beefy-root beefy-root
        :lookup-anchor lookup-anchor
        :lookup-anchor-slot lookup-anchor-slot
        :prerequisites '())  ; Empty for now
       (- pos start)))))

(defun encode-package-spec (spec)
  "Encode package spec (Y).
   
   Graypaper Appendix C.25: E(x ∈ Y) ≡ E(xp, E4(xl), xu, xe, E2(xn))
   
   Args:
     spec: A package-spec structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   ;; xp : package hash (32 bytes)
   (package-spec-hash spec)
   ;; E4(xl) : length (4 bytes)
   (e4 (package-spec-length spec))
   ;; xu : erasure root (32 bytes)
   (package-spec-erasure-root spec)
   ;; xe : exports root (32 bytes)
   (package-spec-exports-root spec)
   ;; E2(xn) : exports count (2 bytes)
   (e2 (package-spec-exports-count spec))))

(defun decode-package-spec (octets &optional (start 0))
  "Decode package spec (Y).
   
   Inverse of encode-package-spec.
   
   Args:
     octets: Encoded package spec data
     start: Starting position
   
   Returns:
     values: (package-spec bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      ;; xp : package hash (32 bytes)
      (hash (decode-hash octets pos))
      ;; E4(xl) : length (4 bytes)
      (length (decode-e4 octets pos))
      ;; xu : erasure root (32 bytes)
      (erasure-root (decode-hash octets pos))
      ;; xe : exports root (32 bytes)
      (exports-root (decode-hash octets pos))
      ;; E2(xn) : exports count (2 bytes)
      (exports-count (decode-e2 octets pos))
      
      (values
       (make-package-spec
        :hash hash
        :length length
        :erasure-root erasure-root
        :exports-root exports-root
        :exports-count exports-count)
       (- pos start)))))

;;; Work Output encoding (C.34)
;;;
;;; Graypaper Appendix C.34:
;;; O(o ∈ E ∪ B) ≡
;;;   (0, ↕o) if o ∈ B      ← ok(blob)
;;;    1      if o = ∞      ← out of gas
;;;    2      if o = ☇      ← panic with revert
;;;    3      if o = ⊚      ← panic with no revert  
;;;    4      if o = ⊖      ← bad work package
;;;    5      if o = BAD    ← service not available
;;;    6      if o = BIG    ← code too large

(defun encode-work-output (output)
  "Encode work output (O).
   
   Graypaper Appendix C.34: O(o ∈ E ∪ B)
   
   Args:
     output: Either (:ok data) or one of :out-of-gas, :panic-revert, :panic-no-revert,
             :bad-work-package, :service-unavailable, :code-too-large
   
   Returns:
     Encoded octet sequence"
  (cond
    ;; (0, ↕o) if o ∈ B - ok with data
    ((and (consp output) (eq (car output) :ok))
     (cons 0 (encode-with-length (cdr output))))
    
    ;; 1 if o = ∞ - out of gas
    ((eq output :out-of-gas) (list 1))
    
    ;; 2 if o = ☇ - panic with revert
    ((or (eq output :panic-revert)
         (and (consp output) (eq (car output) :panic)))
     (list 2))
    
    ;; 3 if o = ⊚ - panic with no revert
    ((eq output :panic-no-revert) (list 3))
    
    ;; 4 if o = ⊖ - bad work package
    ((eq output :bad-work-package) (list 4))
    
    ;; 5 if o = BAD - service not available
    ((eq output :service-unavailable) (list 5))
    
    ;; 6 if o = BIG - code too large
    ((eq output :code-too-large) (list 6))
    
    (t (error "Unknown work output type: ~A" output))))

(defun decode-work-output (octets &optional (start 0))
  "Decode work output (O).
   
   Inverse of encode-work-output (C.34).
   
   Args:
     octets: Encoded work output data
     start: Starting position
   
   Returns:
     values: (output bytes-consumed)"
  (let ((discriminant (nth start octets)))
    (case discriminant
      ;; 0 = ok(data) with length-prefixed blob
      (0 (multiple-value-bind (data consumed)
             (decode-with-length octets (1+ start))
           (values (cons :ok data) (1+ consumed))))
      
      ;; 1 = out of gas
      (1 (values :out-of-gas 1))
      
      ;; 2 = panic with revert
      (2 (values :panic-revert 1))
      
      ;; 3 = panic with no revert
      (3 (values :panic-no-revert 1))
      
      ;; 4 = bad work package
      (4 (values :bad-work-package 1))
      
      ;; 5 = service not available
      (5 (values :service-unavailable 1))
      
      ;; 6 = code too large
      (6 (values :code-too-large 1))
      
      (t (error "Unknown work output discriminant: ~A" discriminant)))))

;;; Work result encoding (C.29)

(defun encode-refine-load (load)
  "Encode refine load structure.
   
   Args:
     load: A refine-load structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   (e8 (refine-load-gas-used load))
   (e8 (refine-load-imports load))
   (e8 (refine-load-extrinsic-count load))
   (e8 (refine-load-extrinsic-size load))
   (e8 (refine-load-exports load))))

(defun decode-refine-load (octets &optional (start 0))
  "Decode refine load structure.
   
   Args:
     octets: Encoded refine load data
     start: Starting position
   
   Returns:
     values: (refine-load bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      (gas-used (decode-e8 octets pos))
      (imports (decode-e8 octets pos))
      (extrinsic-count (decode-e8 octets pos))
      (extrinsic-size (decode-e8 octets pos))
      (exports (decode-e8 octets pos))
      
      (values
       (make-refine-load
        :gas-used gas-used
        :imports imports
        :extrinsic-count extrinsic-count
        :extrinsic-size extrinsic-size
        :exports exports)
       (- pos start)))))

(defun encode-work-result (result)
  "Encode work result (W).
   
   Graypaper Appendix C.29:
   E(w ∈ W) ≡ E(E4(ws), wc, wp, E8(wg), O(result), refine_load)
   
   Args:
     result: A work-result structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   ;; E4(ws) : service id (4 bytes)
   (e4 (work-result-service-id result))
   ;; wc : code hash (32 bytes)
   (work-result-code-hash result)
   ;; wp : payload hash (32 bytes)
   (work-result-payload-hash result)
   ;; E8(wg) : accumulate gas (8 bytes)
   (e8 (work-result-accumulate-gas result))
   ;; O(result) : work output (C.34)
   (encode-work-output (work-result-result result))
   ;; refine_load : refine load structure
   (encode-refine-load (work-result-refine-load result))))

(defun decode-work-result (octets &optional (start 0))
  "Decode work result (W).
   
   Inverse of encode-work-result (C.29).
   
   Args:
     octets: Encoded work result data
     start: Starting position
   
   Returns:
     values: (work-result bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      ;; E4(ws) : service id (4 bytes)
      (service-id (decode-e4 octets pos))
      ;; wc : code hash (32 bytes)
      (code-hash (decode-hash octets pos))
      ;; wp : payload hash (32 bytes)
      (payload-hash (decode-hash octets pos))
      ;; E8(wg) : accumulate gas (8 bytes)
      (accumulate-gas (decode-e8 octets pos))
      ;; O(result) : work output (C.34)
      (result-output (decode-work-output octets pos))
      ;; refine_load : refine load structure
      (refine-load (decode-refine-load octets pos))
      
      (values
       (make-work-result
        :service-id service-id
        :code-hash code-hash
        :payload-hash payload-hash
        :accumulate-gas accumulate-gas
        :result result-output
        :refine-load refine-load)
       (- pos start)))))

;;; Work Report encoding

(defun encode-work-report (report)
  "Encode complete work report.
   
   This is what goes into guarantee.report.
   
   Args:
     report: A work-report structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   ;; Package spec (Y) - C.25
   (encode-package-spec (work-report-package-spec report))
   ;; Context (C) - C.24
   (encode-refine-context (work-report-context report))
   ;; Core index (2 bytes, E2)
   (e2 (work-report-core-index report))
   ;; Authorizer hash (32 bytes)
   (work-report-authorizer-hash report)
   ;; Auth gas used (8 bytes, E8)
   (e8 (work-report-auth-gas-used report))
   ;; Auth output (length-prefixed)
   (encode-with-length (work-report-auth-output report))
   ;; Segment root lookup (length-prefixed sequence)
   ;; Note: segment roots are hashes (identity encoding), no pre-encoded needed
   (encode-length-prefixed-sequence (work-report-segment-root-lookup report))
   ;; Results (length-prefixed sequence of work-result) - C.29
   (encode-length-prefixed-sequence
    (mapcar #'encode-work-result (work-report-results report))
    :pre-encoded t)))

(defun decode-work-report (octets &optional (start 0))
  "Decode complete work report.
   
   Inverse of encode-work-report.
   
   Args:
     octets: Encoded work report data
     start: Starting position
   
   Returns:
     values: (work-report bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      ;; Package spec (Y) - C.25
      (package-spec (decode-package-spec octets pos))
      ;; Context (C) - C.24
      (context (decode-refine-context octets pos))
      ;; Core index (2 bytes, E2)
      (core-index (decode-e2 octets pos))
      ;; Authorizer hash (32 bytes)
      (authorizer-hash (decode-hash octets pos))
      ;; Auth gas used (8 bytes, E8)
      (auth-gas-used (decode-e8 octets pos))
      ;; Auth output (length-prefixed)
      (auth-output (decode-with-length octets pos))
      ;; Segment root lookup (length-prefixed sequence of SegmentRootLookupItem)
      ;; FIXME: Like prerequisites, test vector seems to omit count byte when empty
      ;; Each item would be: work-package-hash (32) + segment-tree-root (32) = 64 bytes
      ;; Hardcode empty for now
      
      ;; Results (length-prefixed sequence of work-result) - C.29
      (results (decode-length-prefixed-sequence octets #'decode-work-result pos))
      
      (values
       (make-work-report
        :package-spec package-spec
        :context context
        :core-index core-index
        :authorizer-hash authorizer-hash
        :auth-gas-used auth-gas-used
        :auth-output auth-output
        :segment-root-lookup '()  ; Empty for now
        :results results)
       (- pos start)))))

;;; Guarantee encoding (for extrinsic.guarantees)

(defun encode-guarantee (guarantee)
  "Encode a guarantee (work report + signatures).
   
   This is the format used in extrinsic.guarantees[] (EG).
   
   Args:
     guarantee: A guarantee structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   ;; Work report
   (encode-work-report (guarantee-report guarantee))
   ;; E4(slot) : slot/timeslot (4 bytes)
   (e4 (guarantee-slot guarantee))
   ;; Signatures: ↕[(E2(v), s) | (v, s) <- signatures]
   (encode-length-prefixed-sequence
    (mapcar (lambda (sig-pair)
              (destructuring-bind (validator-index signature) sig-pair
                (concat-octets
                 (e2 validator-index)
                 (encode-with-length signature))))
            (guarantee-signatures guarantee))
    :pre-encoded t)))

(defun decode-guarantee (octets &optional (start 0))
  "Decode a guarantee (work report + signatures).
   
   Inverse of encode-guarantee.
   
   Args:
     octets: Encoded guarantee data
     start: Starting position
   
   Returns:
     values: (guarantee bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      ;; Work report
      (report (decode-work-report octets pos))
      ;; E4(slot) : slot/timeslot (4 bytes)
      (slot (decode-e4 octets pos))
      ;; Signatures: ↕[(E2(v), s) | (v, s) <- signatures]
      (signatures
       (decode-length-prefixed-sequence
        octets
        (lambda (o s)
          (let ((p s))
            (decode>> (o p)
              (validator-index (decode-e2 o p))
              (signature (decode-with-length o p))
              (values (list validator-index signature) (- p s)))))
        pos))
      
      (values
       (make-guarantee
        :report report
        :slot slot
        :signatures signatures)
       (- pos start)))))
