;;;; block/header.lisp — JAM Block Header
;;;; Gray Paper §5 — Structure, encoding, decoding, hashing
;;;;
;;;; Single source of truth for header H.
;;;; Depends on: codec/primitives, codec/types, jam-crypto

(in-package #:jotl)

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
   None: [0x00]
   Some: [0x01] [{id:32, attempt:u8}]* — fixed-size (ET), NO compact prefix."
  (if tickets-mark
      (let ((encoded-tickets
              (apply #'concatenate '(vector (unsigned-byte 8))
                     (mapcar (lambda (ticket)
                               (concatenate '(vector (unsigned-byte 8))
                                            (encode-hash-32 (getf ticket :id))
                                            (E1 (getf ticket :attempt))))
                             tickets-mark))))
        (concatenate '(vector (unsigned-byte 8))
                     #(1)
                     encoded-tickets))
      #(0)))

(defun decode-tickets-mark (bytes offset)
  "Decode Option<TicketsMark> (HW).
   Fixed-size array of ET tickets (no compact prefix).
   Each ticket: {id ∈ H(32), attempt ∈ u8} = 33 bytes.
   Returns: (values list-of-ticket-plists-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0) (values nil 1))
      ((= tag 1)
       (let* ((ticket-size 33)  ; 32 (hash) + 1 (attempt)
              (num-tickets (epoch-duration))  ; E from chainspec
              (data-start (1+ offset))
              (tickets (loop for i below num-tickets
                             for toff = (+ data-start (* i ticket-size))
                             collect (list :id (subseq bytes toff (+ toff 32))
                                           :attempt (aref bytes (+ toff 32))))))
         (values tickets
                 (+ 1 (* num-tickets ticket-size)))))
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
    ;; TODO: pass-through — decode as Bandersnatch VRF output, not raw blob
    (let ((entropy-source (subseq bytes pos (+ pos 96))))
      (setf result (append result (list :entropy-source entropy-source)))
      (incf pos 96))
    ;; HO - Offenders mark
    (multiple-value-bind (offenders offenders-size)
        (decode-offenders bytes pos)
      (setf result (append result (list :offenders-mark offenders)))
      (incf pos offenders-size))
    ;; HS - Seal (96 bytes) - if present
    ;; TODO: pass-through — decode as Bandersnatch signature, not raw blob
    (when (>= (- (length bytes) pos) 96)
      (let ((seal (subseq bytes pos (+ pos 96))))
        (setf result (append result (list :seal seal)))
        (incf pos 96)))
    (values result (- pos offset))))

;;; ═════════════════════════════════════════════════════════════════
;;; HEADER CLOSURE — via define-value-object
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; GP §5.1: H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
;;;
;;; Fields → :parent-hash, :state-root, etc.
;;; Memoized → :encoded, :encoded-unsealed, :hash (computed once)
;;; Computed → :timeslot (alias), :is-genesis

(define-value-object header
  ((parent-hash nil) (state-root nil) (extrinsic-hash nil)
   (slot nil) (epoch-mark nil) (tickets-mark nil)
   (author-index nil) (entropy-source nil) (offenders-mark nil) (seal nil))
  ;; Aliases
  (:timeslot slot)
  (:is-genesis (or (null parent-hash) (every #'zerop parent-hash)))
  ;; Memoized encoding + hashing
  (:encoded :memo
   (encode-header parent-hash state-root extrinsic-hash
                  slot epoch-mark tickets-mark
                  offenders-mark author-index entropy-source seal))
  (:encoded-unsealed :memo
   (encode-header-unsealed parent-hash state-root extrinsic-hash
                           slot epoch-mark tickets-mark
                           offenders-mark author-index entropy-source))
  (:hash :memo (blake2b-256 (self :encoded))))

;;; Non-field accessors (not generated by macro)

(defun header-hash (h) "H(E(H))" (funcall h :hash))

;;; Exports managed in package.lisp (single source of truth)
