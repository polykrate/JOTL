;;;; bloc/header.lisp — JAM Block Header H
;;;; Gray Paper §5 — Structure, encoding, decoding, hashing
;;;;
;;;; H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)    (GP §5.1)
;;;;
;;;; Sub-component closures (compound types with internal structure):
;;;;   epoch-mark    — HE: Option<{entropy, tickets-entropy, validators}>
;;;;   tickets-mark  — HW: Option<[{id, attempt}; ET]>
;;;;
;;;; Messages:
;;;;   :parent-hash, :state-root, :extrinsic-hash, :slot, :epoch-mark,
;;;;   :tickets-mark, :author-index, :entropy-source, :offenders-mark, :seal
;;;;   :timeslot          — alias for :slot
;;;;   :is-genesis        — true if parent-hash is zero
;;;;   :save              — E(H) = EU(H) || HS
;;;;   :save-unsealed     — EU(H) without seal
;;;;   :hash              — H(E(H))

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; EPOCH MARK closure — HE: Option<{entropy, tickets-entropy, validators}>
;;; GP §6.6, §6.27
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; When present (Some), the closure holds 3 fields accessible via messages.
;;; When absent (None), the header's :epoch-mark field is nil.
;;; The Option tag byte (0x00/0x01) is handled by :save / load-epoch-mark.

(define-state-closure epoch-mark
  ((entropy nil) (tickets-entropy nil) (validators nil))

  ;; ── Save: [0x01][entropy:32][tickets-entropy:32][validators:NV*64] ──
  (:save :memo
        (concatenate '(vector (unsigned-byte 8))
                #(1)
                (encode-hash-32 entropy)
                (encode-hash-32 tickets-entropy)
                (encode-validator-sequence validators)))

  ;; ── Load: Option<EpochMarker> ──────────────────────────────
  ;; Returns nil for None (tag=0), epoch-mark closure for Some (tag=1).
  (:decode (bytes offset)
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0) (values nil 1))
      ((= tag 1)
         (let* ((ent  (subseq bytes (1+ offset) (+ offset 33)))
                (tent (subseq bytes (+ offset 33) (+ offset 65)))
                (voff (+ offset 65)))
           (multiple-value-bind (vals vsize)
               (decode-validator-sequence bytes voff (num-validators))
             (values (make-epoch-mark :entropy ent
                                      :tickets-entropy tent
                                      :validators vals)
                     (+ 1 32 32 vsize)))))
        (t (error "Invalid option tag for epoch marker: ~A" tag))))))

;;; ═════════════════════════════════════════════════════════════════
;;; TICKETS MARK closure — HW: Option<[{id, attempt}; ET]>
;;; GP §6.6, §6.28
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; When present (Some), wraps a fixed-size list of ticket plists.
;;; Individual tickets stay as plists {:id H, :attempt u8} — leaf data.

(define-state-closure tickets-mark
  ((tickets nil))   ; list of ticket plists {:id H, :attempt u8}

  ;; ── Convenience ──────────────────────────────────────────────
  (:count (length tickets))

  ;; ── Save: [0x01][{id:32, attempt:u8}]* ─────────────────────
  (:save :memo
   (concatenate '(vector (unsigned-byte 8))
                #(1)
              (apply #'concatenate '(vector (unsigned-byte 8))
                     (mapcar (lambda (ticket)
                               (concatenate '(vector (unsigned-byte 8))
                                            (encode-hash-32 (getf ticket :id))
                                            (E1 (getf ticket :attempt))))
                               tickets))))

  ;; ── Load: Option<TicketsMark> ──────────────────────────────
  ;; Returns nil for None (tag=0), tickets-mark closure for Some (tag=1).
  (:decode (bytes offset)
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0) (values nil 1))
      ((= tag 1)
         (let* ((ticket-size 33)
                (num-tickets (epoch-duration))
              (data-start (1+ offset))
                (tix (loop for i below num-tickets
                             for toff = (+ data-start (* i ticket-size))
                             collect (list :id (subseq bytes toff (+ toff 32))
                                           :attempt (aref bytes (+ toff 32))))))
           (values (make-tickets-mark :tickets tix)
                 (+ 1 (* num-tickets ticket-size)))))
        (t (error "Invalid option tag for tickets mark: ~A" tag))))))

;;; ═════════════════════════════════════════════════════════════════
;;; Offenders codec (HO) — flat list, stays as primitive codec
;;; GP §10
;;; ═════════════════════════════════════════════════════════════════

(defun encode-offenders (offenders)
  "Encode Vec<Ed25519PublicKey> (HO)."
  (encode-sequence (or offenders '()) #'encode-ed25519-key))

(defun decode-offenders (bytes offset)
  "Decode Vec<Ed25519PublicKey> (HO).
   Returns: (values list-of-keys bytes-consumed)"
  (decode-sequence bytes #'decode-ed25519-key offset))

;;; ═════════════════════════════════════════════════════════════════
;;; HEADER CLOSURE — define-state-closure
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; GP §5.1: H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
;;;
;;; HE and HW are closures (epoch-mark, tickets-mark) or nil.
;;; Primitives (HP, HR, HX, HT, HI, HV, HO, HS) stay as raw values.

(define-state-closure header
  ((parent-hash nil) (state-root nil) (extrinsic-hash nil)
   (slot nil) (epoch-mark nil) (tickets-mark nil)
   (author-index nil) (entropy-source nil) (offenders-mark nil) (seal nil))

  ;; ── Aliases ──────────────────────────────────────────────────
  (:timeslot slot)
  (:is-genesis (or (null parent-hash) (every #'zerop parent-hash)))

  ;; ── Derived: Y(HV) — VRF output hash (32 bytes) ───────────
  ;; GP §6.22: η'₀ = H(η₀ ⌢ Y(HV))
  (:vrf-entropy :memo
   (when entropy-source (jam.ffi:Y entropy-source)))

  ;; ── Save EU(H) — GP §5.8 ──────────────────────────────────
  (:save-unsealed :memo
   (concatenate '(vector (unsigned-byte 8))
                (encode-hash-32 parent-hash)         ; HP (32)
                (encode-hash-32 state-root)          ; HR (32)
                (encode-hash-32 extrinsic-hash)      ; HX (32)
                (E4 slot)                            ; HT (4)
                (if epoch-mark                       ; HE (variable)
                    (funcall epoch-mark :save)
                    #(0))
                (if tickets-mark                     ; HW (variable)
                    (funcall tickets-mark :save)
                    #(0))
                (E2 author-index)                    ; HI (2)
                (encode-signature-96 entropy-source) ; HV (96)
                (encode-offenders offenders-mark)))  ; HO (variable)

  ;; ── Save E(H) = EU(H) || HS ───────────────────────────────
  (:save :memo
   (concatenate '(vector (unsigned-byte 8))
                (self :save-unsealed)
                (encode-signature-96 seal)))         ; HS (96)

  ;; ── Hash H(E(H)) ────────────────────────────────────────────
  (:hash :memo (blake2b-256 (self :save)))

  ;; ── Load: bytes → H closure ───────────────────────────────
  ;; GP §5.8: E(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO, HS)
  (:decode (bytes offset)
    (let ((pos offset)
          hp hr hx ht he hw hi hv ho hs)
      (setf hp (subseq bytes pos (+ pos 32)))  (incf pos 32)   ; HP
      (setf hr (subseq bytes pos (+ pos 32)))  (incf pos 32)   ; HR
      (setf hx (subseq bytes pos (+ pos 32)))  (incf pos 32)   ; HX
      (multiple-value-bind (v n) (decode-u32 bytes pos)         ; HT
        (setf ht v) (incf pos n))
      (multiple-value-bind (v n)                                ; HE → closure or nil
          (load-epoch-mark bytes pos)
        (setf he v) (incf pos n))
      (multiple-value-bind (v n)                                ; HW → closure or nil
          (load-tickets-mark bytes pos)
        (setf hw v) (incf pos n))
      (multiple-value-bind (v n) (decode-u16 bytes pos)         ; HI
        (setf hi v) (incf pos n))
      (setf hv (subseq bytes pos (+ pos 96)))  (incf pos 96)   ; HV
      (multiple-value-bind (v n) (decode-offenders bytes pos)   ; HO
        (setf ho v) (incf pos n))
      (when (>= (- (length bytes) pos) 96)                     ; HS (optional)
        (setf hs (subseq bytes pos (+ pos 96)))
        (incf pos 96))
      (values
       (make-header :parent-hash hp :state-root hr :extrinsic-hash hx
                    :slot ht :epoch-mark he :tickets-mark hw
                    :author-index hi :entropy-source hv
                    :offenders-mark ho :seal hs)
       (- pos offset)))))

;;; load-header is auto-generated by define-state-closure:
;;;   (load-header bytes offset) → (values H-closure consumed)
