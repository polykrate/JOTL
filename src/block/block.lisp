;;;; block/block.lisp — JAM Block B ≡ (H, E)
;;;; Gray Paper §4.1-4.2
;;;;
;;;; Single source of truth: closure + encode/decode + hash.
;;;; decode-block returns closures — ONE representation everywhere.

(in-package :jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; BLOCK CLOSURE — make-block
;;; ═════════════════════════════════════════════════════════════════

(defun make-block (header extrinsic)
  "Creates block closure B ≡ (H, E).
   
   Gray Paper §4.2. Immutable. Both H and E are closures."
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      ;; Core components
      (:header header)
      (:extrinsic extrinsic)
      
      ;; Extrinsic passthrough
      (:tickets    (funcall extrinsic :tickets))
      (:disputes   (funcall extrinsic :disputes))
      (:preimages  (funcall extrinsic :preimages))
      (:assurances (funcall extrinsic :assurances))
      (:guarantees (funcall extrinsic :guarantees))
      
      ;; Header passthrough
      (:slot         (funcall header :slot))
      (:timeslot     (funcall header :slot))
      (:parent-hash  (funcall header :parent-hash))
      (:state-root   (funcall header :state-root))
      
      ;; Hash (block hash = header hash)
      (:hash (funcall header :hash))
      
      ;; Encoding (lazy)
      (:encoded
       (concatenate '(vector (unsigned-byte 8))
                    (funcall header :encoded)
                    (funcall extrinsic :encoded)))
      
      ;; Convenience
      (:is-genesis (funcall header :is-genesis))
      (:type :block)
      
      (otherwise (error "Unknown block message: ~a" msg)))))

;;; ═════════════════════════════════════════════════════════════════
;;; BLOCK ACCESSORS
;;; ═════════════════════════════════════════════════════════════════

(defun block-header (b) (funcall b :header))
(defun block-extrinsic (b) (funcall b :extrinsic))
(defun block-tickets (b) (funcall b :tickets))
(defun block-disputes (b) (funcall b :disputes))
(defun block-preimages (b) (funcall b :preimages))
(defun block-assurances (b) (funcall b :assurances))
(defun block-guarantees (b) (funcall b :guarantees))
(defun block-slot (b) (funcall b :slot))

;;; ═════════════════════════════════════════════════════════════════
;;; BLOCK ENCODING
;;; ═════════════════════════════════════════════════════════════════

(defun encode-block (header extrinsic)
  "Encode block B ≡ (H, E). Accepts closures."
  (concatenate '(vector (unsigned-byte 8))
               (funcall header :encoded)
               (funcall extrinsic :encoded)))

;;; ═════════════════════════════════════════════════════════════════
;;; BLOCK DECODING — returns closures
;;; ═════════════════════════════════════════════════════════════════

(defun decode-block (bytes &optional (offset 0))
  "Decode block B ≡ (H, E) from binary.
   
   Returns CLOSURES — not plists. This is the single entry point.
   
   Returns: (values block-closure total-bytes-consumed)"
  (let ((pos offset))
    ;; 1. Decode header → plist
    (multiple-value-bind (h-plist header-bytes)
        (decode-header bytes pos)
      (incf pos header-bytes)
      ;; 2. Decode extrinsic → plist
      (multiple-value-bind (e-plist extrinsic-bytes)
          (decode-extrinsic bytes pos)
        (incf pos extrinsic-bytes)
        ;; 3. Wrap in closures
        (let* ((header (apply #'make-header
                              ;; Flatten plist into keyword args
                              h-plist))
               (extrinsic (make-extrinsic
                           :tickets    (getf e-plist :tickets)
                           :disputes   (getf e-plist :disputes)
                           :preimages  (getf e-plist :preimages)
                           :assurances (getf e-plist :assurances)
                           :guarantees (getf e-plist :guarantees)))
               (block (make-block header extrinsic)))
          (values block (- pos offset)))))))

;;; ═════════════════════════════════════════════════════════════════
;;; BLOCK HASHING
;;; ═════════════════════════════════════════════════════════════════

(defun compute-block-hash (block)
  "Block hash = header hash H(E(H))."
  (funcall (funcall block :header) :hash))

;;; ═════════════════════════════════════════════════════════════════
;;; HELPERS
;;; ═════════════════════════════════════════════════════════════════

(defun validate-block-structure (block)
  "Basic structural check: header and extrinsic present."
  (assert (funcall block :header) () "Block must have a header")
  (assert (funcall block :extrinsic) () "Block must have an extrinsic")
  t)

(defun block-size (block)
  "Size of encoded block in bytes."
  (length (funcall block :encoded)))

;;; ═════════════════════════════════════════════════════════════════
;;; BLOCK-CONTEXT TERMS (GP §I.4.1) — for reference
;;; ═════════════════════════════════════════════════════════════════
;;; A: Ancestor set | B: Block | E: Extrinsic | H: Header
;;; S: Accumulated work-reports | R: Ready work-reports
;;; T: Ticketed condition | U: Audit condition

(export '(;; Closure
          make-block
          ;; Accessors
          block-header block-extrinsic
          block-tickets block-disputes block-preimages
          block-assurances block-guarantees block-slot
          ;; Encoding/Decoding
          encode-block decode-block
          ;; Hashing
          compute-block-hash
          ;; Helpers
          validate-block-structure block-size))
