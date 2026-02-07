;;;; work-report.lisp - WorkReport Structure Encoding/Decoding
;;;; Gray Paper §11-12 - Work Reports
;;;;
;;;; jam-types-py reference (from davxy/jam-types-py):
;;;;   WorkReport = (package_spec, context, core_index, authorizer_hash,
;;;;                 auth_gas_used, auth_output, segment_root_lookup, results)

(in-package :jotl)

;;; ==========================================================================
;;; WorkPackageSpec
;;; ==========================================================================
;;;
;;; Fields:
;;;   hash:           WorkPackageHash (32 bytes)
;;;   length:         U32
;;;   erasure_root:   OpaqueHash (32 bytes)
;;;   exports_root:   OpaqueHash (32 bytes)
;;;   exports_count:  U16
;;;
;;; Total fixed: 32 + 4 + 32 + 32 + 2 = 102 bytes

(defun decode-work-package-spec (bytes offset)
  "Decode WorkPackageSpec.
   Returns: (values spec-plist bytes-consumed)"
  (let ((pos offset))
    (let ((hash (subseq bytes pos (+ pos 32))))
      (incf pos 32)
      (multiple-value-bind (pkg-length length-bytes)
          (decode-u32 bytes pos)
        (incf pos length-bytes)
        (let ((erasure-root (subseq bytes pos (+ pos 32))))
          (incf pos 32)
          (let ((exports-root (subseq bytes pos (+ pos 32))))
            (incf pos 32)
            (multiple-value-bind (exports-count exports-bytes)
                (decode-u16 bytes pos)
              (incf pos exports-bytes)
              (values (list :hash hash
                            :length pkg-length
                            :erasure-root erasure-root
                            :exports-root exports-root
                            :exports-count exports-count)
                      (- pos offset)))))))))

(defun encode-work-package-spec (spec)
  "Encode WorkPackageSpec.
   Returns: byte array"
  (concatenate '(vector (unsigned-byte 8))
               (getf spec :hash)
               (encode-u32 (getf spec :length))
               (getf spec :erasure-root)
               (getf spec :exports-root)
               (encode-u16 (getf spec :exports-count))))

;;; ==========================================================================
;;; RefineContext
;;; ==========================================================================
;;;
;;; Fields:
;;;   anchor:              HeaderHash (32 bytes)
;;;   state_root:          OpaqueHash (32 bytes)
;;;   beefy_root:          OpaqueHash (32 bytes)
;;;   lookup_anchor:       HeaderHash (32 bytes)
;;;   lookup_anchor_slot:  TimeSlot (u32)
;;;   prerequisites:       Vec<OpaqueHash>

(defun decode-refine-context (bytes offset)
  "Decode RefineContext.
   Returns: (values context-plist bytes-consumed)"
  (let ((pos offset))
    (let ((anchor (subseq bytes pos (+ pos 32))))
      (incf pos 32)
      (let ((state-root (subseq bytes pos (+ pos 32))))
        (incf pos 32)
        (let ((beefy-root (subseq bytes pos (+ pos 32))))
          (incf pos 32)
          (let ((lookup-anchor (subseq bytes pos (+ pos 32))))
            (incf pos 32)
            (multiple-value-bind (lookup-slot slot-bytes)
                (decode-u32 bytes pos)
              (incf pos slot-bytes)
              ;; prerequisites: Vec<OpaqueHash> (compact-prefixed sequence of 32-byte hashes)
              (multiple-value-bind (prerequisites prereq-bytes)
                  (decode-sequence bytes
                                   (lambda (b o)
                                     (values (subseq b o (+ o 32)) 32))
                                   pos)
                (incf pos prereq-bytes)
                (values (list :anchor anchor
                              :state-root state-root
                              :beefy-root beefy-root
                              :lookup-anchor lookup-anchor
                              :lookup-anchor-slot lookup-slot
                              :prerequisites prerequisites)
                        (- pos offset))))))))))

(defun encode-refine-context (ctx)
  "Encode RefineContext.
   Returns: byte array"
  (concatenate '(vector (unsigned-byte 8))
               (getf ctx :anchor)
               (getf ctx :state-root)
               (getf ctx :beefy-root)
               (getf ctx :lookup-anchor)
               (encode-u32 (getf ctx :lookup-anchor-slot))
               (encode-sequence (or (getf ctx :prerequisites) '())
                                (lambda (hash) hash))))

;;; ==========================================================================
;;; SegmentRootLookupItem
;;; ==========================================================================
;;;
;;; Fields:
;;;   work_package_hash:  WorkPackageHash (32 bytes)
;;;   segment_tree_root:  SegmentTreeRoot (32 bytes)
;;;
;;; Total fixed: 64 bytes

(defun decode-segment-root-lookup-item (bytes offset)
  "Decode SegmentRootLookupItem.
   Returns: (values item-plist bytes-consumed)"
  (let ((pos offset))
    (let ((wp-hash (subseq bytes pos (+ pos 32))))
      (incf pos 32)
      (let ((seg-root (subseq bytes pos (+ pos 32))))
        (incf pos 32)
        (values (list :work-package-hash wp-hash
                      :segment-tree-root seg-root)
                (- pos offset))))))

;;; ==========================================================================
;;; RefineLoad
;;; ==========================================================================
;;;
;;; All fields compact-encoded:
;;;   gas_used:           Compact<Gas>
;;;   imported_segments:  Compact
;;;   extrinsic_count:    Compact
;;;   extrinsic_size:     Compact
;;;   exported_segments:  Compact

(defun decode-refine-load (bytes offset)
  "Decode RefineLoad (all compact-encoded fields).
   Returns: (values load-plist bytes-consumed)"
  (let ((pos offset))
    (multiple-value-bind (gas-used gas-bytes)
        (decode-compact bytes pos)
      (incf pos gas-bytes)
      (multiple-value-bind (imports imports-bytes)
          (decode-compact bytes pos)
        (incf pos imports-bytes)
        (multiple-value-bind (ext-count ext-count-bytes)
            (decode-compact bytes pos)
          (incf pos ext-count-bytes)
          (multiple-value-bind (ext-size ext-size-bytes)
              (decode-compact bytes pos)
            (incf pos ext-size-bytes)
            (multiple-value-bind (exports exports-bytes)
                (decode-compact bytes pos)
              (incf pos exports-bytes)
              (values (list :gas-used gas-used
                            :imports imports
                            :extrinsic-count ext-count
                            :extrinsic-size ext-size
                            :exports exports)
                      (- pos offset)))))))))

;;; ==========================================================================
;;; WorkExecResult (Enum)
;;; ==========================================================================
;;;
;;; Variant 0: Ok(ByteSequence)   - successful execution with output
;;; Variant 1: Panic              - execution panicked (no payload)
;;; Variant 2+: Error codes

(defun decode-work-exec-result (bytes offset)
  "Decode WorkExecResult (Enum).
   Returns: (values result-plist bytes-consumed)"
  (let ((pos offset)
        (variant (aref bytes offset)))
    (incf pos 1)
    (case variant
      (0 ;; Ok(ByteSequence)
       (multiple-value-bind (blob-len len-bytes)
           (decode-compact bytes pos)
         (incf pos len-bytes)
         (let ((blob (subseq bytes pos (+ pos blob-len))))
           (incf pos blob-len)
           (values (list :ok blob) (- pos offset)))))
      (1 ;; Panic (no payload)
       (values (list :panic nil) 1))
      (otherwise
       ;; Other error variants - record the code
       (values (list :error variant) 1)))))

;;; ==========================================================================
;;; WorkResult
;;; ==========================================================================
;;;
;;; Fields:
;;;   service_id:      ServiceId (U32)
;;;   code_hash:       OpaqueHash (32 bytes)
;;;   payload_hash:    OpaqueHash (32 bytes)
;;;   accumulate_gas:  Gas (U64, fixed 8 bytes)
;;;   result:          WorkExecResult (Enum)
;;;   refine_load:     RefineLoad

(defun decode-work-result (bytes offset)
  "Decode WorkResult.
   Returns: (values result-plist bytes-consumed)"
  (let ((pos offset))
    ;; service_id (u32)
    (multiple-value-bind (service-id sid-bytes)
        (decode-u32 bytes pos)
      (incf pos sid-bytes)
      ;; code_hash (32 bytes)
      (let ((code-hash (subseq bytes pos (+ pos 32))))
        (incf pos 32)
        ;; payload_hash (32 bytes)
        (let ((payload-hash (subseq bytes pos (+ pos 32))))
          (incf pos 32)
          ;; accumulate_gas (u64, fixed 8 bytes - NOT compact!)
          (multiple-value-bind (acc-gas gas-bytes)
              (decode-u64 bytes pos)
            (incf pos gas-bytes)
            ;; result (WorkExecResult enum)
            (multiple-value-bind (exec-result result-bytes)
                (decode-work-exec-result bytes pos)
              (incf pos result-bytes)
              ;; refine_load
              (multiple-value-bind (refine-load load-bytes)
                  (decode-refine-load bytes pos)
                (incf pos load-bytes)
                (values (list :service-id service-id
                              :code-hash code-hash
                              :payload-hash payload-hash
                              :accumulate-gas acc-gas
                              :result exec-result
                              :refine-load refine-load)
                        (- pos offset))))))))))

;;; ==========================================================================
;;; Complete WorkReport Encoding/Decoding
;;; ==========================================================================
;;;
;;; WorkReport structure (jam-types-py):
;;;   package_spec:         WorkPackageSpec
;;;   context:              RefineContext
;;;   core_index:           Compact<CoreIndex>
;;;   authorizer_hash:      OpaqueHash (32 bytes)
;;;   auth_gas_used:        Compact<U64>
;;;   auth_output:          AuthorizerOutput (ByteSequence: compact-len + data)
;;;   segment_root_lookup:  Vec<SegmentRootLookupItem>
;;;   results:              Vec<WorkResult>

(defun decode-work-report (bytes offset)
  "Decode complete WorkReport.
   
   Gray Paper §11-12. Structure from jam-types-py.
   
   Returns: (values work-report-plist bytes-consumed)"
  (let ((pos offset))
    ;; package_spec
    (multiple-value-bind (package-spec spec-bytes)
        (decode-work-package-spec bytes pos)
      (incf pos spec-bytes)
      
      ;; context
      (multiple-value-bind (context ctx-bytes)
          (decode-refine-context bytes pos)
        (incf pos ctx-bytes)
        
        ;; core_index (Compact)
        (multiple-value-bind (core-index core-bytes)
            (decode-compact bytes pos)
          (incf pos core-bytes)
          
          ;; authorizer_hash (32 bytes)
          (let ((authorizer-hash (subseq bytes pos (+ pos 32))))
            (incf pos 32)
            
            ;; auth_gas_used (Compact<U64>)
            (multiple-value-bind (auth-gas auth-gas-bytes)
                (decode-compact bytes pos)
              (incf pos auth-gas-bytes)
              
              ;; auth_output (ByteSequence: compact-length + data)
              (multiple-value-bind (output-len output-len-bytes)
                  (decode-compact bytes pos)
                (incf pos output-len-bytes)
                (let ((auth-output (subseq bytes pos (+ pos output-len))))
                  (incf pos output-len)
                  
                  ;; segment_root_lookup (Vec<SegmentRootLookupItem>)
                  (multiple-value-bind (seg-lookup seg-bytes)
                      (decode-sequence bytes #'decode-segment-root-lookup-item pos)
                    (incf pos seg-bytes)
                    
                    ;; results (Vec<WorkResult>)
                    (multiple-value-bind (results results-bytes)
                        (decode-sequence bytes #'decode-work-result pos)
                      (incf pos results-bytes)
                      
                      (values (list :package-spec package-spec
                                    :context context
                                    :core-index core-index
                                    :authorizer-hash authorizer-hash
                                    :auth-gas-used auth-gas
                                    :auth-output auth-output
                                    :segment-root-lookup seg-lookup
                                    :results results)
                              (- pos offset)))))))))))))

(defun encode-work-report (report)
  "Encode complete WorkReport.
   
   Accepts either raw bytes or a structured plist.
   
   Returns: byte array"
  (etypecase report
    ;; Raw bytes passthrough
    ((simple-array (unsigned-byte 8) (*)) report)
    (vector (coerce report '(simple-array (unsigned-byte 8) (*))))
    ;; Structured plist encoding
    (list
     (concatenate '(vector (unsigned-byte 8))
                  (encode-work-package-spec (getf report :package-spec))
                  (encode-refine-context (getf report :context))
                  (encode-compact (getf report :core-index))
                  (getf report :authorizer-hash)
                  (encode-compact (getf report :auth-gas-used))
                  (let ((output (getf report :auth-output)))
                    (concatenate '(vector (unsigned-byte 8))
                                 (encode-compact (length output))
                                 output))
                  (encode-sequence (or (getf report :segment-root-lookup) '())
                                   (lambda (item)
                                     (concatenate '(vector (unsigned-byte 8))
                                                  (getf item :work-package-hash)
                                                  (getf item :segment-tree-root))))
                  ;; TODO: encode-work-result for full results encoding
                  (encode-compact (length (or (getf report :results) '())))))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(decode-work-package-spec encode-work-package-spec
          decode-refine-context encode-refine-context
          decode-segment-root-lookup-item
          decode-refine-load
          decode-work-exec-result
          decode-work-result
          decode-work-report encode-work-report))
