;;;; validation.lisp - Block Validation Functions
;;;; Gray Paper §5 - Block Structure Validation
;;;;
;;;; Pure functions (not closures) for validating blocks, headers, and extrinsics.

(in-package :jotl)

;;; ==========================================================================
;;; Extrinsic Hash Validation (Gray Paper §5.4-5.6)
;;; ==========================================================================

(defun validate-extrinsic-hash (header-hx extrinsic-data)
  "Validate that the extrinsic hash in the header matches the computed hash.
   
   Gray Paper §5.4: HX ≡ H_MMR(a)
   
   Args:
     header-hx: The HX field from the header (32 bytes)
     extrinsic-data: Extrinsic plist or closure with :tickets :preimages etc.
   
   Returns:
     (values is-valid computed-hx)
     - is-valid: T if HX matches, NIL otherwise
     - computed-hx: The computed hash (32 bytes) for debugging"
  (let ((computed-hx (compute-extrinsic-hash extrinsic-data)))
    (values (equalp header-hx computed-hx)
            computed-hx)))

;;; ==========================================================================
;;; Timeslot Validation (Gray Paper §5.7)
;;; ==========================================================================

(defun validate-timeslot (header-ht current-time)
  "Validate that the header timeslot is valid.
   
   Gray Paper §5.7: HT · P ≤ T (block time must be in the past)
   
   Args:
     header-ht: The HT field from header (timeslot index)
     current-time: Current UNIX timestamp
   
   Returns:
     (values is-valid message)
     - is-valid: T if timeslot is valid, NIL otherwise
     - message: Human-readable validation result"
  (let* ((slot-duration (jotl:slot-duration))  ; P from chainspec
         (block-time (* header-ht slot-duration)))
    (if (<= block-time current-time)
        (values t (format nil "Timeslot ~a is valid (block time ~a <= current ~a)"
                          header-ht block-time current-time))
        (values nil (format nil "Timeslot ~a is invalid (block time ~a > current ~a)"
                            header-ht block-time current-time)))))

;;; ==========================================================================
;;; Parent Hash Validation (Gray Paper §5.2)
;;; ==========================================================================

(defun validate-parent-hash (header-hp parent-header)
  "Validate that the parent hash in the header matches the parent.
   
   Gray Paper §5.2: HP ≡ H(E(P(H)))
   
   Args:
     header-hp: The HP field from header (32 bytes)
     parent-header: The parent header (plist or closure)
   
   Returns:
     (values is-valid computed-hash)
     - is-valid: T if HP matches, NIL otherwise
     - computed-hash: The computed parent hash for debugging"
  ;; TODO: Implement when we have header encoding
  ;; For now, assume parent-header is already encoded or we have its hash
  (let ((parent-hash (if (functionp parent-header)
                         (funcall parent-header :hash)
                         (getf parent-header :hash))))
    (if parent-hash
        (values (equalp header-hp parent-hash) parent-hash)
        (values nil nil))))

;;; ==========================================================================
;;; Header Validation
;;; ==========================================================================

(defun validate-header (header &key parent-header current-time)
  "Validate a complete header.
   
   Validates:
     - Timeslot (if current-time provided)
     - Parent hash (if parent-header provided)
     - TODO: Epoch mark, tickets mark, offenders mark
   
   Args:
     header: Header plist or closure
     parent-header: (optional) Parent header for HP validation
     current-time: (optional) Current UNIX timestamp for HT validation
   
   Returns:
     (values is-valid validation-results)
     - is-valid: T if all validations pass, NIL otherwise
     - validation-results: Plist with detailed results"
  (let ((results '())
        (all-valid t))
    
    ;; Extract header fields
    (let ((ht (if (functionp header)
                  (funcall header :slot)
                  (getf header :slot)))
          (hp (if (functionp header)
                  (funcall header :parent-hash)
                  (getf header :parent-hash))))
      
      ;; Validate timeslot (if current-time provided)
      (when current-time
        (multiple-value-bind (is-valid message)
            (validate-timeslot ht current-time)
          (setf results (append results (list :timeslot is-valid
                                               :timeslot-message message)))
          (unless is-valid (setf all-valid nil))))
      
      ;; Validate parent hash (if parent-header provided)
      (when parent-header
        (multiple-value-bind (is-valid computed-hash)
            (validate-parent-hash hp parent-header)
          (setf results (append results (list :parent-hash is-valid
                                               :computed-parent-hash computed-hash)))
          (unless is-valid (setf all-valid nil)))))
    
    (values all-valid results)))

;;; ==========================================================================
;;; Block Validation
;;; ==========================================================================

(defun validate-block (header extrinsic-data &key parent-header current-time)
  "Validate a complete block (header + extrinsic).
   
   Gray Paper §5: Validates the full block structure
   
   Validates:
     - Extrinsic hash (HX) matches computed hash from extrinsic data
     - Header validity (timeslot, parent hash, etc.)
     - TODO: State root (HR)
   
   Args:
     header: Header plist or closure
     extrinsic-data: Extrinsic plist or closure
     parent-header: (optional) Parent header
     current-time: (optional) Current UNIX timestamp
   
   Returns:
     (values is-valid validation-results)
     - is-valid: T if all validations pass, NIL otherwise
     - validation-results: Plist with detailed results for each validation"
  (let ((results '())
        (all-valid t))
    
    ;; Extract HX from header
    (let ((header-hx (if (functionp header)
                         (funcall header :extrinsic-hash)
                         (getf header :extrinsic-hash))))
      
      ;; Validate extrinsic hash
      (multiple-value-bind (hx-valid computed-hx)
          (validate-extrinsic-hash header-hx extrinsic-data)
        (setf results (append results (list :extrinsic-hash hx-valid
                                             :computed-hx computed-hx
                                             :header-hx header-hx)))
        (unless hx-valid (setf all-valid nil)))
      
      ;; Validate header
      (multiple-value-bind (header-valid header-results)
          (validate-header header
                           :parent-header parent-header
                           :current-time current-time)
        (setf results (append results header-results))
        (unless header-valid (setf all-valid nil))))
    
    (values all-valid results)))

;;; ==========================================================================
;;; Convenience Functions
;;; ==========================================================================

(defun validate-block-from-binary (header-bytes extrinsic-bytes &key current-time)
  "Validate a block from binary-encoded header and extrinsic.
   
   Convenience function that decodes and validates.
   
   Args:
     header-bytes: Encoded header (byte array)
     extrinsic-bytes: Encoded extrinsic (byte array)
     current-time: (optional) Current UNIX timestamp
   
   Returns:
     (values is-valid validation-results decoded-header decoded-extrinsic)"
  ;; Decode header and extrinsic
  (let ((decoded-header (decode-header header-bytes 0))
        (decoded-extrinsic (decode-extrinsic extrinsic-bytes 0)))
    
    ;; Validate
    (multiple-value-bind (is-valid results)
        (validate-block decoded-header decoded-extrinsic
                        :current-time current-time)
      (values is-valid results decoded-header decoded-extrinsic))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(validate-extrinsic-hash
          validate-timeslot
          validate-parent-hash
          validate-header
          validate-block
          validate-block-from-binary))
