;;;; block/header.lisp — JAM Block Header
;;;; Gray Paper §5 — Structure, encoding, decoding, hashing
;;;;
;;;; Single source of truth for header H.
;;;; Depends on: codec/primitives, codec/types, jam-crypto

(in-package :jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)    (GP §5.1)
;;; ═════════════════════════════════════════════════════════════════

;;; -----------------------------------------------------------------
;;; Epoch Marker (HE) — GP §6.6
;;; -----------------------------------------------------------------

(defun encode-epoch-marker (epoch-mark)
  "Encode Option<EpochMarker> (HE).
   
   None: [0x00]
   Some: [0x01] [entropy:32] [tickets_entropy:32] [validators:NV*64]
   
   Validators are FIXED SIZE (NV from chainspec), no compact prefix."
  (if epoch-mark
      (let* ((entropy (encode-hash-32 (getf epoch-mark :entropy)))
             (tickets-entropy (encode-hash-32 (getf epoch-mark :tickets-entropy)))
             (validators (getf epoch-mark :validators))
             (validators-encoded (encode-validator-sequence validators)))
        (concatenate '(vector (unsigned-byte 8))
                     #(1) entropy tickets-entropy validators-encoded))
      #(0)))

(defun decode-epoch-marker (bytes offset num-validators)
  "Decode Option<EpochMarker> (HE).
   Returns: (values epoch-mark-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0) (values nil 1))
      ((= tag 1)
       (let* ((entropy (subseq bytes (1+ offset) (+ offset 33)))
              (tickets-entropy (subseq bytes (+ offset 33) (+ offset 65)))
              (validators-offset (+ offset 65)))
         (multiple-value-bind (validators validators-size)
             (decode-validator-sequence bytes validators-offset num-validators)
           (values
            (list :entropy entropy
                  :tickets-entropy tickets-entropy
                  :validators validators)
            (+ 1 32 32 validators-size)))))
      (t (error "Invalid option tag for epoch marker: ~A" tag)))))

;;; -----------------------------------------------------------------
;;; Tickets Mark (HW) — GP §6.6
;;; -----------------------------------------------------------------

(defun encode-tickets-mark (tickets-mark)
  "Encode Option<TicketsMark> (HW).
   TODO: Implement full TicketsMark structure."
  (if tickets-mark
      (concatenate '(vector (unsigned-byte 8)) #(1) tickets-mark)
      #(0)))

(defun decode-tickets-mark (bytes offset)
  "Decode Option<TicketsMark> (HW).
   Returns: (values tickets-mark-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0) (values nil 1))
      ((= tag 1)
       (multiple-value-bind (num-tickets len-bytes)
           (decode-compact bytes (1+ offset))
         (let ((tickets-data (subseq bytes (+ offset 1)
                                     (+ offset 1 len-bytes (* num-tickets 32)))))
           (values tickets-data
                   (+ 1 len-bytes (* num-tickets 32))))))
      (t (error "Invalid option tag for tickets mark: ~A" tag)))))

;;; -----------------------------------------------------------------
;;; Offenders (HO) — GP §10
;;; -----------------------------------------------------------------

(defun encode-offenders (offenders)
  "Encode Vec<Ed25519PublicKey> (HO).
   Format: [compact-length] [key1:32] [key2:32] ..."
  (encode-sequence (or offenders '()) #'encode-ed25519-key))

(defun decode-offenders (bytes offset)
  "Decode Vec<Ed25519PublicKey> (HO).
   Returns: (values list-of-keys bytes-consumed)"
  (decode-sequence bytes #'decode-ed25519-key offset))

;;; ═════════════════════════════════════════════════════════════════
;;; HEADER ENCODING (GP §5.8)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
;;; E(H)  = EU(H) || HS

(defun encode-header-unsealed (parent-hash state-root extrinsic-hash
                                slot epoch-mark tickets-mark
                                offenders-mark author-index entropy-source)
  "Encode header WITHOUT seal — EU(H).
   Used for computing the seal signature."
  (concatenate '(vector (unsigned-byte 8))
               (encode-hash-32 parent-hash)        ; HP (32)
               (encode-hash-32 state-root)         ; HR (32)
               (encode-hash-32 extrinsic-hash)     ; HX (32)
               (E4 slot)                           ; HT (4)
               (encode-epoch-marker epoch-mark)    ; HE (variable)
               (encode-tickets-mark tickets-mark)  ; HW (1+ or variable)
               (E2 author-index)                   ; HI (2)
               (encode-signature-96 entropy-source) ; HV (96)
               (encode-offenders offenders-mark))) ; HO (variable)

(defun encode-header (parent-hash state-root extrinsic-hash
                      slot epoch-mark tickets-mark
                      offenders-mark author-index entropy-source seal)
  "Encode complete header WITH seal — E(H) = EU(H) || HS."
  (concatenate '(vector (unsigned-byte 8))
               (encode-header-unsealed parent-hash state-root extrinsic-hash
                                      slot epoch-mark tickets-mark
                                      offenders-mark author-index entropy-source)
               (encode-signature-96 seal)))

;;; ═════════════════════════════════════════════════════════════════
;;; HEADER DECODING
;;; ═════════════════════════════════════════════════════════════════

(defun decode-header (bytes &optional (offset 0))
  "Decode complete header from binary.
   
   GP §5.8: E(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO, HS)
   
   Returns: (values header-plist bytes-consumed)"
  (let ((pos offset)
        (result '()))
    ;; HP - Parent hash (32 bytes)
    (let ((parent-hash (subseq bytes pos (+ pos 32))))
      (setf result (append result (list :parent-hash parent-hash)))
      (incf pos 32))
    ;; HR - State root (32 bytes)
    (let ((state-root (subseq bytes pos (+ pos 32))))
      (setf result (append result (list :state-root state-root)))
      (incf pos 32))
    ;; HX - Extrinsic hash (32 bytes)
    (let ((extrinsic-hash (subseq bytes pos (+ pos 32))))
      (setf result (append result (list :extrinsic-hash extrinsic-hash)))
      (incf pos 32))
    ;; HT - Timeslot (u32, 4 bytes)
    (multiple-value-bind (slot bytes-consumed)
        (decode-u32 bytes pos)
      (setf result (append result (list :slot slot)))
      (incf pos bytes-consumed))
    ;; HE - Epoch mark
    (multiple-value-bind (epoch-mark epoch-size)
        (decode-epoch-marker bytes pos (num-validators))
      (setf result (append result (list :epoch-mark epoch-mark)))
      (incf pos epoch-size))
    ;; HW - Tickets mark
    (multiple-value-bind (tickets-mark tickets-size)
        (decode-tickets-mark bytes pos)
      (setf result (append result (list :tickets-mark tickets-mark)))
      (incf pos tickets-size))
    ;; HI - Author index (u16, 2 bytes)
    (multiple-value-bind (author-index bytes-consumed)
        (decode-u16 bytes pos)
      (setf result (append result (list :author-index author-index)))
      (incf pos bytes-consumed))
    ;; HV - Entropy source (96 bytes)
    (let ((entropy-source (subseq bytes pos (+ pos 96))))
      (setf result (append result (list :entropy-source entropy-source)))
      (incf pos 96))
    ;; HO - Offenders mark
    (multiple-value-bind (offenders offenders-size)
        (decode-offenders bytes pos)
      (setf result (append result (list :offenders-mark offenders)))
      (incf pos offenders-size))
    ;; HS - Seal (96 bytes) - if present
    (when (>= (- (length bytes) pos) 96)
      (let ((seal (subseq bytes pos (+ pos 96))))
        (setf result (append result (list :seal seal)))
        (incf pos 96)))
    (values result (- pos offset))))

;;; ═════════════════════════════════════════════════════════════════
;;; HEADER HASHING (GP §5.2)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; HP ≡ H(E(P(H)))  — Blake2b-256 of sealed encoded header

(defun compute-header-hash (parent-hash state-root extrinsic-hash
                             slot epoch-mark tickets-mark
                             offenders-mark author-index entropy-source seal)
  "Compute H(E(H)) — Blake2b-256 of sealed encoded header."
  (jam.ffi:blake2b-256
   (encode-header parent-hash state-root extrinsic-hash
                  slot epoch-mark tickets-mark
                  offenders-mark author-index entropy-source seal)))

(defun compute-header-hash-from-plist (header-plist)
  "Compute H(E(H)) from a decoded header plist."
  (jam.ffi:blake2b-256
   (encode-header (getf header-plist :parent-hash)
                  (getf header-plist :state-root)
                  (getf header-plist :extrinsic-hash)
                  (getf header-plist :slot)
                  (getf header-plist :epoch-mark)
                  (getf header-plist :tickets-mark)
                  (getf header-plist :offenders-mark)
                  (getf header-plist :author-index)
                  (getf header-plist :entropy-source)
                  (getf header-plist :seal))))

;; Backward compat alias
(defun compute-header-hash-from-decoded (header-plist)
  "Alias for compute-header-hash-from-plist."
  (compute-header-hash-from-plist header-plist))

;;; ═════════════════════════════════════════════════════════════════
;;; HEADER CLOSURE — make-header
;;; ═════════════════════════════════════════════════════════════════

(defun make-header (&key parent-hash state-root extrinsic-hash
                         slot epoch-mark tickets-mark
                         author-index entropy-source offenders-mark seal)
  "Creates header closure H.
   
   Gray Paper §5.1:
     H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
   
   Immutable. Encoding and hashing computed lazily."
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      ;; Core fields (GP §5.1)
      (:parent-hash parent-hash)       ; HP
      (:state-root state-root)         ; HR
      (:extrinsic-hash extrinsic-hash) ; HX
      (:slot slot)                     ; HT
      (:epoch-mark epoch-mark)         ; HE
      (:tickets-mark tickets-mark)     ; HW
      (:author-index author-index)     ; HI
      (:entropy-source entropy-source) ; HV
      (:offenders-mark offenders-mark) ; HO
      (:seal seal)                     ; HS
      
      ;; Derived
      (:timeslot slot)
      (:is-genesis (or (null parent-hash) (every #'zerop parent-hash)))
      
      ;; Encoding (lazy)
      (:encoded
       (encode-header parent-hash state-root extrinsic-hash
                     slot epoch-mark tickets-mark
                     offenders-mark author-index entropy-source seal))
      (:encoded-unsealed
       (encode-header-unsealed parent-hash state-root extrinsic-hash
                              slot epoch-mark tickets-mark
                              offenders-mark author-index entropy-source))
      
      ;; Hashing (lazy)
      (:hash
       (jam.ffi:blake2b-256
        (encode-header parent-hash state-root extrinsic-hash
                      slot epoch-mark tickets-mark
                      offenders-mark author-index entropy-source seal)))
      
      ;; Snapshot
      (:as-plist
       (list :parent-hash parent-hash :state-root state-root
             :extrinsic-hash extrinsic-hash :slot slot
             :epoch-mark epoch-mark :tickets-mark tickets-mark
             :offenders-mark offenders-mark :author-index author-index
             :entropy-source entropy-source :seal seal))
      
      ;; Metadata
      (:type :header)
      
      (otherwise (error "Unknown header message: ~a" msg)))))

;;; ═════════════════════════════════════════════════════════════════
;;; ACCESSORS
;;; ═════════════════════════════════════════════════════════════════

(defun header-parent-hash (h) "HP" (funcall h :parent-hash))
(defun header-state-root (h) "HR" (funcall h :state-root))
(defun header-extrinsic-hash (h) "HX" (funcall h :extrinsic-hash))
(defun header-slot (h) "HT" (funcall h :slot))
(defun header-epoch-mark (h) "HE" (funcall h :epoch-mark))
(defun header-tickets-mark (h) "HW" (funcall h :tickets-mark))
(defun header-author-index (h) "HI" (funcall h :author-index))
(defun header-entropy-source (h) "HV" (funcall h :entropy-source))
(defun header-offenders-mark (h) "HO" (funcall h :offenders-mark))
(defun header-seal (h) "HS" (funcall h :seal))
(defun header-hash (h) "H(E(H))" (funcall h :hash))

(defun header-is-genesis-p (header)
  "Genesis has no parent (HP = null or all zeros)"
  (funcall header :is-genesis))

;;; ═════════════════════════════════════════════════════════════════
;;; PARENT / ANCESTORS (GP §5.2-5.3)
;;; ═════════════════════════════════════════════════════════════════

(defun parent-function (header)
  "P(H) — GP §5.2: returns parent hash for lookup."
  (unless (header-is-genesis-p header)
    (funcall header :parent-hash)))

(defun compute-parent-hash (parent-header)
  "HP ≡ H(E(P(H))) — hash of encoded parent header."
  (if parent-header
      (funcall parent-header :hash)
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defconstant +ancestor-retention-hours+ 24
  "L = 24 hours — GP §5.3")

(defun compute-ancestor-set (header &optional (max-depth 14400))
  "Ancestor set A — GP §5.3. Requires blockchain store."
  (declare (ignore max-depth))
  (list header))

(defun is-ancestor-p (h1 h2)
  "Checks if h1 is an ancestor of h2."
  (equalp (funcall h1 :hash) (funcall h2 :parent-hash)))

;;; ═════════════════════════════════════════════════════════════════
;;; EXPORTS
;;; ═════════════════════════════════════════════════════════════════

(export '(;; Encoding/Decoding
          encode-header encode-header-unsealed decode-header
          encode-epoch-marker decode-epoch-marker
          encode-tickets-mark decode-tickets-mark
          encode-offenders decode-offenders
          ;; Hashing
          compute-header-hash compute-header-hash-from-plist
          compute-header-hash-from-decoded
          ;; Closure
          make-header
          ;; Accessors
          header-parent-hash header-state-root header-extrinsic-hash
          header-slot header-epoch-mark header-tickets-mark
          header-author-index header-entropy-source header-offenders-mark
          header-seal header-hash header-is-genesis-p
          ;; Ancestors
          parent-function compute-parent-hash
          +ancestor-retention-hours+ compute-ancestor-set is-ancestor-p))
