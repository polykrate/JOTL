;;;; block.lisp - JAM Block Encoding/Decoding
;;;; Gray Paper §4.2 - Complete block encoding
;;;; Orchestrates header and extrinsic encoding

(in-package :jotl)

;;; ==========================================================================
;;; Block Structure (Gray Paper §4.2)
;;; ==========================================================================
;;;
;;; B ≡ (H, E)
;;;
;;; Where:
;;;   H : Header (Gray Paper §5)
;;;   E : Extrinsic (Gray Paper §4.3)
;;;
;;; A block is simply the concatenation of encoded header and extrinsic:
;;;   E(B) = E(H) || E(E)

;;; ==========================================================================
;;; Block Encoding
;;; ==========================================================================

(defun encode-block (header extrinsic)
  "Encode a complete block B ≡ (H, E).
   
   Gray Paper §4.2:
   E(B) = E(H) || E(E)
   
   Args:
     header: Either:
       - Header closure (from make-header-encoded)
       - Plist with header fields
     extrinsic: Either:
       - Extrinsic closure (from make-extrinsic-encoded)
       - Plist with extrinsic fields
   
   Returns:
     byte array (encoded block)"
  (let ((header-bytes
         (if (functionp header)
             ;; Header is a closure - call :encoded
             (funcall header :encoded)
             ;; Header is a plist - encode it
             (encode-header
              (getf header :parent-hash)
              (getf header :state-root)
              (getf header :extrinsic-hash)
              (getf header :slot)
              (getf header :epoch-mark)
              (getf header :tickets-mark)
              (getf header :offenders-mark)
              (getf header :author-index)
              (getf header :entropy-source)
              (getf header :seal))))
        (extrinsic-bytes
         (if (functionp extrinsic)
             ;; Extrinsic is a closure - call :encoded
             (funcall extrinsic :encoded)
             ;; Extrinsic is a plist - encode it
             ;; TODO: Implement when extrinsic encoding is ready
             (error "Direct extrinsic encoding not yet implemented. Use closure."))))
    
    (concatenate '(vector (unsigned-byte 8))
                 header-bytes
                 extrinsic-bytes)))

;;; ==========================================================================
;;; Block Decoding
;;; ==========================================================================

(defun decode-block (bytes &optional (offset 0))
  "Decode a complete block from bytes.
   
   Gray Paper §4.2:
   Decode E(B) = E(H) || E(E)
   
   Args:
     bytes: byte array containing encoded block
     offset: starting position (default 0)
   
   Returns:
     (values block-plist total-bytes-consumed)
     
   block-plist format:
     (:header header-plist :extrinsic extrinsic-plist)"
  
  ;; Step 1: Decode header
  ;; We need to know the header structure to decode it properly
  ;; For now, we'll decode the fixed-size parts and handle variable parts
  
  (let ((pos offset)
        (header-fields '())
        (extrinsic-fields '()))
    
    ;; Decode header fixed parts (HP, HR, HX, HT)
    (let ((parent-hash (decode-hash-32 bytes pos)))
      (push (cons :parent-hash parent-hash) header-fields)
      (incf pos 32))
    
    (let ((state-root (decode-hash-32 bytes pos)))
      (push (cons :state-root state-root) header-fields)
      (incf pos 32))
    
    (let ((extrinsic-hash (decode-hash-32 bytes pos)))
      (push (cons :extrinsic-hash extrinsic-hash) header-fields)
      (incf pos 32))
    
    (let ((slot (decode-fixed-le (subseq bytes pos (+ pos 4)))))
      (push (cons :slot slot) header-fields)
      (incf pos 4))
    
    ;; Decode header variable parts (HE, HW, HI, HV, HO, HS)
    ;; TODO: Complete implementation based on header structure
    
    ;; For now, return what we have
    (values
     (list :header (nreverse header-fields)
           :extrinsic extrinsic-fields)
     (- pos offset))))

(defun decode-block-complete (bytes &optional (offset 0))
  "Decode a complete block with ALL fields.
   
   This is the full implementation that handles all variable-length fields.
   
   TODO: Implement complete decoding when needed
   
   Args:
     bytes: byte array
     offset: starting position
   
   Returns:
     (values block-plist total-bytes-consumed)"
  (declare (ignore bytes offset))
  (error "Complete block decoding not yet implemented. Use decode-block for basic fields."))

;;; ==========================================================================
;;; Block Hashing
;;; ==========================================================================

(defun compute-block-hash (header extrinsic)
  "Compute the hash of a block.
   
   The block hash is simply the header hash H(E(H))
   (the extrinsic doesn't contribute to the block hash).
   
   Gray Paper §5.2: Block is identified by its header hash
   
   Args:
     header: header closure or plist
     extrinsic: extrinsic closure or plist (ignored for hash)
   
   Returns:
     32-byte hash"
  (declare (ignore extrinsic))  ; Extrinsic doesn't affect block hash
  
  (if (functionp header)
      ;; Header is a closure - call :hash
      (funcall header :hash)
      ;; Header is a plist - compute hash
      (compute-header-hash
       (getf header :parent-hash)
       (getf header :state-root)
       (getf header :extrinsic-hash)
       (getf header :slot)
       (getf header :epoch-mark)
       (getf header :tickets-mark)
       (getf header :offenders-mark)
       (getf header :author-index)
       (getf header :entropy-source)
       (getf header :seal))))

;;; ==========================================================================
;;; Block Closure (Pure FP Integration)
;;; ==========================================================================

(defun make-block-encoded (&key header extrinsic)
  "Create a block closure with encoding support.
   
   Pure FP approach: B ≡ (H, E) as a closure
   
   Args:
     header: Header closure (from make-header-encoded)
     extrinsic: Extrinsic closure (from make-extrinsic-encoded)
   
   Returns:
     Block closure with interface:
       (:header) → header closure
       (:extrinsic) → extrinsic closure
       (:encoded) → byte array (lazy)
       (:hash) → 32-byte hash (lazy)
       (:parent-hash) → parent hash from header
       (:slot) → slot from header
       (:is-genesis) → boolean
       (:type) → :block"
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      ;; Core components
      (:header header)
      (:extrinsic extrinsic)
      
      ;; Encoding (lazy evaluation)
      (:encoded
       (encode-block header extrinsic))
      
      ;; Hash (block hash = header hash)
      (:hash
       (if (functionp header)
           (funcall header :hash)
           (compute-header-hash
            (getf header :parent-hash)
            (getf header :state-root)
            (getf header :extrinsic-hash)
            (getf header :slot)
            (getf header :epoch-mark)
            (getf header :tickets-mark)
            (getf header :offenders-mark)
            (getf header :author-index)
            (getf header :entropy-source)
            (getf header :seal))))
      
      ;; Convenience accessors (delegate to header)
      (:parent-hash
       (if (functionp header)
           (funcall header :parent-hash)
           (getf header :parent-hash)))
      
      (:slot
       (if (functionp header)
           (funcall header :slot)
           (getf header :slot)))
      
      (:timeslot
       (if (functionp header)
           (funcall header :timeslot)
           (getf header :slot)))
      
      (:is-genesis
       (if (functionp header)
           (funcall header :is-genesis)
           (null (getf header :parent-hash))))
      
      ;; Extrinsic accessors (delegate to extrinsic)
      (:tickets
       (when extrinsic
         (funcall extrinsic :tickets)))
      
      (:disputes
       (when extrinsic
         (funcall extrinsic :disputes)))
      
      (:preimages
       (when extrinsic
         (funcall extrinsic :preimages)))
      
      (:assurances
       (when extrinsic
         (funcall extrinsic :assurances)))
      
      (:guarantees
       (when extrinsic
         (funcall extrinsic :guarantees)))
      
      ;; Type identification
      (:type :block)
      
      (otherwise
       (error "Unknown block message: ~a" msg)))))

;;; ==========================================================================
;;; Block Validation Helpers
;;; ==========================================================================

(defun validate-block-structure (block)
  "Validate that a block has the correct structure.
   
   Checks:
     - Header is present
     - Extrinsic is present
     - Header has required fields
   
   Args:
     block: Block closure or plist
   
   Returns:
     t if valid, signals error otherwise"
  (let ((header (if (functionp block)
                    (funcall block :header)
                    (getf block :header)))
        (extrinsic (if (functionp block)
                       (funcall block :extrinsic)
                       (getf block :extrinsic))))
    
    (assert header () "Block must have a header")
    (assert extrinsic () "Block must have an extrinsic")
    
    ;; Validate header has required fields
    (when (functionp header)
      (assert (funcall header :parent-hash) () "Header must have parent-hash")
      (assert (funcall header :state-root) () "Header must have state-root")
      (assert (funcall header :slot) () "Header must have slot"))
    
    t))

(defun block-size (block)
  "Compute the size of an encoded block in bytes.
   
   Args:
     block: Block closure or plist
   
   Returns:
     Number of bytes"
  (length (if (functionp block)
              (funcall block :encoded)
              (encode-block (getf block :header) (getf block :extrinsic)))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(;; Encoding
          encode-block
          
          ;; Decoding
          decode-block
          decode-block-complete
          
          ;; Hashing
          compute-block-hash
          
          ;; Closure
          make-block-encoded
          
          ;; Helpers
          validate-block-structure
          block-size))
