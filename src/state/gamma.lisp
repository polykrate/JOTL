;;;; state/gamma.lisp — γ Safrole State (GP §6)
;;;;
;;;; (6.3) γ ≡ (γP, γZ, γS, γA) where:
;;;;   γP ∈ ⟦K⟧V   Pending validator keys (same format as κ)
;;;;   γZ ∈ B̂       Ring commitment (144 bytes) — (6.4)
;;;;   γS           Sealing state (discriminated union) — (6.5):
;;;;                  variant :tickets → ⟦T⟧E  (E tickets)
;;;;                  variant :keys    → ⟦Ĥ⟧E  (E bandersnatch keys, fallback)
;;;;   γA ∈ ⟦T⟧≤E   Accumulated tickets — (6.5)
;;;;
;;;; T ≡ (y ∈ H, e ∈ NN) — ticket = (id: hash, attempt: u8) — (6.6)
;;;; K ≡ B336 — validator key = (kb, ke, kl, km) — (6.8)-(6.12)
;;;;
;;;; State key: C(4)
;;;; Transition: γ' < (H, τ, ET, γ, ι, η', κ', ψ')  — GP (4.7)
;;;;
;;;; Key rotation (6.13):
;;;;   (γ'P, κ', λ', γ'Z) ≡
;;;;     (Φ(ι), γP, κ, z)   if e' > e   (epoch change)
;;;;     (γP, κ, λ, γZ)     otherwise
;;;;   where z = O([kb | k ≺ γ'P]) — ring commitment from new pending keys
;;;;
;;;; Offender filter (6.14):
;;;;   Φ(k) ≡ [[0,0,...] if ke ∈ ψ'O, k otherwise] | k ≺ k
;;;;
;;;; Messages:
;;;;   :pending-keys, :ring-commitment, :sealing, :accumulator — field accessors
;;;;   :gamma-k, :gamma-z, :gamma-s, :gamma-a — GP aliases
;;;;   :kappa — alias for pending-keys (validator-compatible)
;;;;   :sealing-variant       → :tickets or :keys (abstracts γS variant)
;;;;   :seal-entry-at slot    → ticket plist or key bytes at slot mod E
;;;;   :save :memo — binary codec
;;;;   :decode (bytes offset) — decoder
;;;;   (Merkle key C(4) owned by σ)
;;;;   :transition (&key tau tau-prime tickets iota eta-prime kappa-prime psi-prime) — GP (4.7)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; ERROR CONDITION
;;; ═══════════════════════════════════════════════════════════════

(define-condition safrole-error (error)
  ((code   :initarg :code   :reader safrole-error-code)
   (detail :initarg :detail :reader safrole-error-detail :initform nil))
  (:report (lambda (c s)
             (format s "Safrole error: ~A~@[ — ~A~]"
                     (safrole-error-code c) (safrole-error-detail c)))))

(defun reject-safrole (code &optional detail)
  "Signal a safrole validation error."
  (error 'safrole-error :code code :detail detail))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE TICKET CODEC — T = (id: H, attempt: u8) = 33 bytes
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; NOTE: Different from block extrinsic ticket (785 bytes: attempt + VRF sig).
;;; State tickets are the reduced form: {id: 32B, attempt: 1B} = 33 bytes.

(defun encode-state-ticket (ticket)
  "Encode a state ticket T = (id ⌢ attempt) = 33 bytes.
   NOT the same as block extrinsic ticket (which has a VRF signature)."
  (let ((id (getf ticket :id))
        (attempt (getf ticket :attempt)))
    (concatenate '(vector (unsigned-byte 8))
                 (encode-hash-32 id)
                 (vector attempt))))

(defun load-state-ticket (bytes offset)
  "Decode a state ticket T.
   Returns: (values plist 33)"
  (values
   (list :id      (subseq bytes offset (+ offset 32))
         :attempt (aref bytes (+ offset 32)))
   33))

;;; ═══════════════════════════════════════════════════════════════
;;; γs CODEC — Discriminated union (sealing state)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Encoding: discriminant(1) ⌢ data
;;;   discriminant = 0 → tickets: E × 33 bytes
;;;   discriminant = 1 → keys:    E × 32 bytes

(defun encode-gamma-sealing (sealing)
  "Encode γs. sealing = (:variant :keys/:tickets :data [...])"
  (let ((variant (getf sealing :variant))
        (data    (getf sealing :data)))
    (ecase variant
      (:tickets
       (concatenate '(vector (unsigned-byte 8))
                    (vector 0)
                    (apply #'concatenate '(vector (unsigned-byte 8))
                           (mapcar #'encode-state-ticket data))))
      (:keys
       (concatenate '(vector (unsigned-byte 8))
                    (vector 1)
                    (apply #'concatenate '(vector (unsigned-byte 8))
                           (mapcar #'encode-bandersnatch-key data)))))))

(defun load-gamma-sealing (bytes offset)
  "Decode γs. Returns: (values plist bytes-consumed)"
  (let* ((discriminant (aref bytes offset))
         (pos (1+ offset))
         (e (epoch-duration)))
    (ecase discriminant
      (0 ;; tickets: E × 33 bytes
       (let ((tickets '()))
         (dotimes (i e)
           (multiple-value-bind (ticket size) (load-state-ticket bytes pos)
             (push ticket tickets)
             (incf pos size)))
         (values (list :variant :tickets :data (nreverse tickets))
                 (- pos offset))))
      (1 ;; keys: E × 32 bytes
       (let ((keys '()))
         (dotimes (i e)
           (push (subseq bytes pos (+ pos 32)) keys)
           (incf pos 32))
         (values (list :variant :keys :data (nreverse keys))
                 (- pos offset)))))))

;;; ═══════════════════════════════════════════════════════════════
;;; Φ — OFFENDER FILTER (GP 6.14)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Φ(k) ≡ [[0,0,...] if ke ∈ ψ'O, k otherwise] | k ≺ k
;;;
;;; Now a message on validator closures (κ, ι):
;;;   (funcall iota :filter-offenders offenders) → filtered validator list
;;; See kappa.lisp / iota.lisp for implementation.
;;; +null-validator-key+ defined in lib/types.lisp.

;;; ═══════════════════════════════════════════════════════════════
;;; Z — OUTSIDE-IN SEQUENCER (GP 6.25)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Z: ⟦T⟧E → ⟦T⟧E
;;;   s ↦ [s₀, s|s|-1, s₁, s|s|-2, ...]
;;;
;;; Interleaves elements from beginning and end to distribute
;;; early vs late tickets evenly across the epoch.

(defun outside-in-sequencer (seq)
  "Z(s) — GP (6.25): Outside-in sequencer.
   Interleaves elements from beginning and end.
   [s₀, s|s|-1, s₁, s|s|-2, ...]"
  (let* ((n (length seq))
         (v (coerce seq 'vector))
         (result '())
         (lo 0)
         (hi (1- n)))
    (loop while (<= lo hi)
          do (push (aref v lo) result)
             (incf lo)
             (when (<= lo hi)
               (push (aref v hi) result)
               (decf hi)))
    (nreverse result)))

;;; ═══════════════════════════════════════════════════════════════
;;; F — FALLBACK KEY SEQUENCE (GP 6.26)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; F: (H, ⟦K⟧) → ⟦Ĥ⟧E
;;;   (r, k) ↦ [k_{E⁻¹₄(H(r ⌢ E₄(i)))^○}_b | i ∈ NE]
;;;
;;; Now a message on validator closures (κ):
;;;   (funcall kappa-prime :fallback-keys eta-2-prime) → list of E bandersnatch keys
;;; See kappa.lisp for implementation.

;;; ═══════════════════════════════════════════════════════════════
;;; Y — CLOSING OFFSET (GP §6.5-6.7)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Y is the slot index within an epoch at which the closing period
;;; begins. Once m ≥ Y, no new tickets can be submitted.

(defun closing-offset ()
  "Y — GP §6.5-6.7: Slot offset within epoch where ticket-submission ends.
   After this offset, no more tickets can be submitted.
   Returns: contest-duration (Y in the GP, NOT P which is slot-period).
   Tiny: 10, Full: 500."
  (contest-duration))

;;; ═══════════════════════════════════════════════════════════════
;;; TICKET VALIDATION & ACCUMULATION — GP §6.7 (6.29)-(6.35)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; (6.29) ET ∈ [[(e ∈ NN, p ∈ V̂○_{γ'Z}(XT ⌢ η'₂ ⌢ e))]]
;;; (6.30) |ET| ≤ { K if m' < Y, 0 otherwise }
;;; (6.31) n = [(y · Y(ip), e · ie) | i ≺ ET]
;;; (6.32) n = [x ∈ n]↕xy     (sorted by id)
;;; (6.33) {xy|x∈n} ∤ {xy|x∈γA}  (no duplicates)
;;; (6.34) γ'A = [x ∈ n ∪ base ↓ xy]^≤E   (merge + take E smallest)
;;; (6.35) n ⊆ γ'A             (all new tickets in result)

(defun validate-ticket-count (tickets m-prime)
  "GP (6.30) — |ET| ≤ K if m' < Y, 0 otherwise.
   Signals SAFROLE-ERROR if too many tickets."
  (let ((max-allowed (if (< m-prime (closing-offset))
                         (max-tickets-per-extrinsic)
                         0)))
    (when (> (length tickets) max-allowed)
      (reject-safrole :too-many-tickets
                      (format nil "|ET|=~D > ~D (m'=~D, Y=~D)"
                             (length tickets) max-allowed
                             m-prime (closing-offset))))))

(defun validate-ticket-proof (ticket gamma-z-prime eta-2-prime)
  "GP (6.29) — Validate a single ticket's Ring VRF proof.
   e must be < N (tickets_per_validator).
   p ∈ V̂○_{γ'Z}(XT ⌢ η'₂ ⌢ e).
   Signals SAFROLE-ERROR on failure."
  (let* ((attempt   (getf ticket :attempt))
         (signature (getf ticket :signature)))
    ;; e ∈ NN: attempt < N
    (unless (< attempt (tickets-per-validator))
      (reject-safrole :bad-ticket-attempt
                      (format nil "attempt ~D ≥ N=~D"
                             attempt (tickets-per-validator))))
    ;; VRF input = XT ⌢ η'₂ ⌢ E1(e) — helper from FFI
    (let ((vrf-input (jam.ffi:ticket-vrf-input eta-2-prime attempt)))
      ;; Ring VRF verification against γ'Z
      (unless (jam.ffi:bandersnatch-verify-ring-vrf
               gamma-z-prime vrf-input signature
               :ring-size (num-validators))
        (reject-safrole :bad-ticket-proof
                        (format nil "Ring VRF failed for attempt ~D" attempt))))))

(defun extract-new-tickets (tickets)
  "GP (6.31) — n = [(y · Y(ip), e · ie) | i ≺ ET]
   Extract state ticket entries (id=Y(p), attempt=e) from extrinsic tickets."
  (mapcar (lambda (ticket)
            (let* ((signature (getf ticket :signature))
                   (attempt   (getf ticket :attempt))
                   (id        (jam.ffi:Y signature)))
              (unless id
                (reject-safrole :bad-ticket-vrf-output
                                (format nil "Y(p) returned nil for attempt ~D" attempt)))
              (list :id id :attempt attempt)))
          tickets))

(defun ticket-id< (a b)
  "Compare state tickets by id (lexicographic byte comparison)."
  (hash< (getf a :id) (getf b :id)))

(defun validate-new-tickets-sorted (new-tickets)
  "GP (6.32) — n must be sorted by ticket id (ascending)."
  (loop for (a b) on new-tickets
        while b
        unless (ticket-id< a b)
        do (reject-safrole :bad-ticket-order "Tickets not sorted by identifier")))

(defun validate-new-tickets-no-duplicates (new-tickets accumulator)
  "GP (6.33) — {xy | x ∈ n} ∤ {xy | x ∈ γA}
   No ticket id in new-tickets may already exist in accumulator."
  (dolist (ticket new-tickets)
    (when (find (getf ticket :id) accumulator
                :key (lambda (a) (getf a :id)) :test #'equalp)
      (reject-safrole :duplicate-ticket "Ticket id already in accumulator"))))

(defun compute-accumulator-prime (new-tickets accumulator epoch-change-p)
  "GP (6.34) — γ'A = [x ∈ n ∪ base ↓ xy]^≤E
   Merge new tickets with base (∅ if epoch change, γA otherwise),
   sort ascending by id, take at most E smallest."
  (let* ((base (if epoch-change-p nil accumulator))
         (merged (sort (append (copy-list new-tickets) (copy-list base))
                       #'ticket-id<))
         (e (epoch-duration)))
    (if (<= (length merged) e)
        merged
        (subseq merged 0 e))))

(defun validate-tickets-included (new-tickets accumulator-prime)
  "GP (6.35) — n ⊆ γ'A
   All submitted tickets must end up in the final accumulator."
  (dolist (ticket new-tickets)
    (unless (find (getf ticket :id) accumulator-prime
                  :key (lambda (a) (getf a :id)) :test #'equalp)
      (reject-safrole :ticket-not-included "Submitted ticket not in final accumulator"))))

(defun process-ticket-extrinsic (tickets gamma-z-prime eta-2-prime
                                 gamma-a m-prime epoch-change-p)
  "GP (6.29)-(6.35) — Full ticket processing pipeline.
   Args:
     tickets: raw extrinsic tickets (ET) — list of (:attempt u8 :signature 784B)
     gamma-z-prime: γ'Z ring commitment for VRF verification
     eta-2-prime: η'₂ for VRF input
     gamma-a: current accumulator (or nil)
     m-prime: phase within epoch = τ' mod E (not a closure)
     epoch-change-p: T if e' > e
   Returns: γ'A (new accumulator)"
  (progn
    ;; (6.30) Check ticket count limits
    (validate-ticket-count tickets m-prime)
    ;; Early return if no tickets
    (when (null tickets)
      (return-from process-ticket-extrinsic
        (if epoch-change-p nil gamma-a)))
    ;; (6.29) Validate each ticket's Ring VRF proof
    (dolist (ticket tickets)
      (validate-ticket-proof ticket gamma-z-prime eta-2-prime))
    ;; (6.31) Extract state ticket entries: n = [(Y(p), e) | ...]
    (let ((new-tickets (extract-new-tickets tickets)))
      ;; (6.32) Must be sorted by id
      (validate-new-tickets-sorted new-tickets)
      ;; (6.33) No duplicates with existing accumulator
      (validate-new-tickets-no-duplicates new-tickets (if epoch-change-p nil gamma-a))
      ;; (6.34) Merge + sort + take E smallest
      (let ((gamma-a-prime (compute-accumulator-prime
                            new-tickets gamma-a epoch-change-p)))
        ;; (6.35) All new tickets must be in the result
        (validate-tickets-included new-tickets gamma-a-prime)
        gamma-a-prime))))

;;; ═══════════════════════════════════════════════════════════════
;;; STATE CLOSURE — γ (define-state-closure)
;;; ═══════════════════════════════════════════════════════════════

(define-state-closure gamma-state
  ((pending-keys nil)     ;; γP: list of V full validator plists
   (ring-commitment nil)  ;; γZ: 144-byte vector (BLS commitment)
   (sealing nil)          ;; γS: plist (:variant :keys/:tickets :data [...])
   (accumulator nil))     ;; γA: list of ticket plists (:id bytes :attempt int)

  ;; GP subscript aliases
  (:gamma-k pending-keys)
  (:gamma-z ring-commitment)
  (:gamma-s sealing)
  (:gamma-a accumulator)
  (:kappa   pending-keys)

  ;; ── Sealing queries — encapsulate γS internals ─────────────
  ;; Seal validation (§6.15-6.20) needs these but should not know
  ;; the variant/data layout of γS.
  (:sealing-variant (getf sealing :variant))

  (:seal-entry-at (slot)
    (nth (seal-key-index slot) (getf sealing :data)))

  ;; ── Codec ──────────────────────────────────────────────────
  (:encode :memo
    (concatenate '(vector (unsigned-byte 8))
                 (encode-full-validator-sequence pending-keys)
                 (if ring-commitment
                     (ensure-bytes ring-commitment)
                     (make-array +bls-key-size+ :element-type '(unsigned-byte 8)
                                                :initial-element 0))
                 (encode-gamma-sealing sealing)
                 (encode-sequence accumulator #'encode-state-ticket)))

  (:decode (bytes offset)
    (let ((pos offset))
      ;; γP: V × 336 bytes
      (multiple-value-bind (pk pk-size)
          (decode-full-validator-sequence bytes pos)
        (incf pos pk-size)
        ;; γZ: 144 bytes
        (let ((zz (subseq bytes pos (+ pos +bls-key-size+))))
          (incf pos +bls-key-size+)
          ;; γS: discriminant + data
          (multiple-value-bind (gs gs-size)
              (load-gamma-sealing bytes pos)
            (incf pos gs-size)
            ;; γA: compact-prefixed sequence of tickets
            (multiple-value-bind (ga ga-size)
                (decode-sequence bytes #'load-state-ticket pos)
              (incf pos ga-size)
              (values
               (make-gamma-state :pending-keys pk
                                 :ring-commitment zz
                                 :sealing gs
                                 :accumulator ga)
               (- pos offset))))))))

  ;; ── Transition: γ' < (H, τ, ET, γ, ι, η', κ', ψ') — GP §6 ──
  ;;
  ;; H is not needed: τ' is received directly as tau-prime closure.
  ;; (6.13) Key rotation at epoch boundary: γ'P, γ'Z
  ;; (6.14) Offender filtering: Φ(k)
  ;; (6.24) Slot key sequence γ'S: Z(γA) | γS | F(η'₂, κ')
  ;; (6.25) Outside-in sequencer Z
  ;; (6.26) Fallback key sequence F
  ;; (6.29-6.35) Ticket validation + accumulation γ'A
  (:transition (&key tau tau-prime tickets iota eta-prime kappa-prime psi-prime)
    (let* (;; Epoch math via tau closures
           (epoch-change      (funcall tau :epoch-changed? tau-prime))
           (m                 (funcall tau :phase))    ;; prior slot within epoch
           (m-prime           (funcall tau-prime :phase)) ;; new slot within epoch
           ;; η'₂ for VRF input (ticket validation + fallback sequence)
           (eta-2-prime       (funcall eta-prime :vrf-entropy))
           ;; Offenders from ψ'
           (offenders         (funcall psi-prime :offenders)))
    (if epoch-change
        ;; ══════════════════════════════════════════════════════════
        ;; EPOCH CHANGE (e' > e)
        ;; ══════════════════════════════════════════════════════════
        (let* (               ;; (6.13) γ'P = Φ(ι) — filter offenders from enqueued keys
               (gamma-p-prime (funcall iota :filter-offenders offenders))
               ;; (6.13) z = O([kb | k ≺ γ'P]) — ring commitment from new pending keys
               (bander-keys (mapcar (lambda (k) (getf k :bandersnatch))
                                    gamma-p-prime))
               (gamma-z-prime (or (jam.ffi:bandersnatch-compute-ring-commitment
                                   (coerce bander-keys 'vector))
                                    ring-commitment))  ;; fallback if SRS not loaded
               ;; (6.24) γ'S — Slot key sequence
               ;; Tickets enacted iff contest closed (m > Y) AND accumulator full
               (gamma-s-prime
                (if (and (> m (closing-offset))
                           (= (length accumulator) (epoch-duration)))
                    ;; TICKETS MODE: Z(γA)
                    (list :variant :tickets
                            :data (outside-in-sequencer accumulator))
                    ;; FALLBACK MODE: F(η'₂, κ')
                    (list :variant :keys
                          :data (funcall kappa-prime :fallback-keys eta-2-prime))))
                 ;; (6.29-6.35) Ticket accumulation (base = ∅ on epoch change)
               (gamma-a-prime (process-ticket-extrinsic
                               tickets gamma-z-prime eta-2-prime
                                 accumulator m-prime t)))
            (make-gamma-state :pending-keys gamma-p-prime
                      :ring-commitment gamma-z-prime
                      :sealing gamma-s-prime
                      :accumulator gamma-a-prime))
        ;; ══════════════════════════════════════════════════════════
        ;; NO EPOCH CHANGE (e' = e)
        ;; ══════════════════════════════════════════════════════════
        ;; (6.24) γ'S = γS — unchanged
        ;; (6.13) γ'P = γP, γ'Z = γZ — unchanged
        ;; (6.29-6.35) Ticket accumulation (base = γA)
        (let ((gamma-a-prime (process-ticket-extrinsic
                                tickets ring-commitment eta-2-prime
                                accumulator m-prime nil)))
            (make-gamma-state :pending-keys pending-keys
                              :ring-commitment ring-commitment
                              :sealing sealing
                              :accumulator gamma-a-prime))))))

;;; ═══════════════════════════════════════════════════════════════
;;; SEAL VALIDATION — GP §6.4 (6.15)-(6.20)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; let i = γ'S[HT]^○   (seal key at timeslot position, circular)
;;;
;;; (6.15) tickets mode: γ'S ∈ ⟦T⟧E →
;;;   iy = Y(HS)
;;;   HS ∈ V̂○ₖ(XT ⌢ η'₃ ⌢ ie)     Ring VRF, input = ticket_seal ⌢ η'₃ ⌢ attempt
;;;   T = 1
;;;
;;; (6.16) fallback mode: γ'S ∈ ⟦Ĥ⟧E →
;;;   i = HA
;;;   HS ∈ V̂ₖ(XF ⌢ η'₃)           Plain Bandersnatch VRF, input = fallback_seal ⌢ η'₃
;;;   T = 0
;;;
;;; (6.17) HV ∈ V̄[]_{HA}(XE ⌢ Y(HS))   Entropy VRF, input = entropy ⌢ Y(seal)
;;;
;;; (6.18) XE = $jam_entropy
;;; (6.19) XF = $jam_fallback_seal
;;; (6.20) XT = $jam_ticket_seal

(defun seal-key-index (timeslot)
  "γ'S[HT]^○ — Circular index into sealing series.
   Returns: HT mod E"
  (mod timeslot (epoch-duration)))

(defun validate-seal-tickets (slot seal gamma-prime eta-3-prime gamma-z
                               unsealed-header kappa-prime author-idx)
  "GP (6.15) — Validate seal in tickets mode.
   - γ'S[HT mod E] is the ticket at this timeslot
   - iy = Y(HS): VRF output matches ticket ID
   - HS ∈ V̂^{EU(H)}_{HA}(XT ⌢ η'₃ ⌢ ie): IETF VRF (96 bytes)
     key = κ'[HI].kb (author bandersnatch key), ad = EU(H)
     input = jam_ticket_seal ⌢ η'₃ ⌢ E1(ie)
   slot: HT (integer), seal: HS (96 bytes = output||proof).
   unsealed-header: EU(H) bytes — additional data for VRF (GP §6.4).
   kappa-prime: κ' closure for author key lookup.
   author-idx: HI (integer) — author index.
   Signals SAFROLE-ERROR on failure."
  (let* ((ticket   (funcall gamma-prime :seal-entry-at slot))
         ;; (6.15) iy = Y(HS)
         (vrf-out  (jam.ffi:Y seal)))
    (unless vrf-out
      (reject-safrole :bad-seal-vrf-output "Y(HS) extraction failed (tickets mode)"))
    (unless (equalp vrf-out (getf ticket :id))
      (reject-safrole :bad-seal-ticket-mismatch
                      (format nil "Y(HS) ≠ ticket id at slot ~D" slot)))
    ;; (6.15) HS ∈ V̂^{EU(H)}_{HA}(XT ⌢ η'₃ ⌢ ie) — IETF VRF
    ;; key = κ'[HI].kb, input = XT ⌢ η'₃ ⌢ E1(ie), ad = EU(H)
    (let* ((seal-key  (funcall kappa-prime :bandersnatch-key author-idx))
           (attempt   (getf ticket :attempt))
           (vrf-input (concatenate '(vector (unsigned-byte 8))
                                   +ctx-ticket-seal+
                                   (ensure-bytes eta-3-prime)
                                   (vector attempt)))
           (vrf-output (subseq seal 0 32))
           (vrf-proof  (subseq seal 32)))
      (unless seal-key
        (reject-safrole :bad-seal-no-key
                        (format nil "No bandersnatch key for author ~D" author-idx)))
      (unless (jam.ffi:bandersnatch-verify-vrf
               seal-key vrf-input vrf-output vrf-proof unsealed-header)
        (reject-safrole :bad-seal-vrf-verify
                        "Bandersnatch VRF verification failed (tickets mode)")))))

(defun validate-seal-fallback (slot seal gamma-prime eta-3-prime
                                unsealed-header)
  "GP (6.16) — Validate seal in fallback (keys) mode.
   - γ'S[HT mod E]: fallback key at timeslot position (NOT author index)
   - HS ∈ V̂ₖᵐ(XF ⌢ η'₃) where k=γ'S[HT], m = EU(H)
   slot: HT (integer), seal: HS (96 bytes = output||proof).
   unsealed-header: EU(H) bytes (GP §6.4 additional data for VRF).
   Signals SAFROLE-ERROR on failure."
  (let* (;; i = γ'S[HT mod E] — key at timeslot position in fallback sequence
         (seal-key   (funcall gamma-prime :seal-entry-at slot))
         ;; (6.16) VRF input = XF ⌢ η'₃
         (vrf-input  (concatenate '(vector (unsigned-byte 8))
                                  +ctx-fallback-seal+
                                  (ensure-bytes eta-3-prime)))
         ;; HS = [output: 32 bytes] [proof: 64 bytes]
         (vrf-output (subseq seal 0 32))
         (vrf-proof  (subseq seal 32)))
    (unless seal-key
      (reject-safrole :bad-seal-no-key
                      (format nil "No fallback key at slot ~D" slot)))
    ;; Verify as Bandersnatch IETF VRF with ad = EU(H) (GP §6.4)
    (unless (jam.ffi:bandersnatch-verify-vrf
             seal-key vrf-input vrf-output vrf-proof unsealed-header)
      (reject-safrole :bad-seal-vrf-verify
                      "Bandersnatch VRF verification failed (fallback mode)"))))

(defun validate-seal (slot author-idx seal gamma-prime eta-3-prime gamma-z
                      unsealed-header &key kappa-prime)
  "GP (6.15)/(6.16) — Dispatch seal validation based on γ'S variant.
   slot: HT, author-idx: HI, seal: HS — raw values.
   gamma-prime: γ' closure (messages :sealing-variant, :seal-entry-at).
   unsealed-header: EU(H) bytes — additional data for VRF (GP §6.4).
   kappa-prime: κ' closure — needed in tickets mode for author key lookup.
   Signals SAFROLE-ERROR on failure."
  (let ((variant (funcall gamma-prime :sealing-variant)))
    (ecase variant
      (:tickets  (validate-seal-tickets  slot seal gamma-prime eta-3-prime gamma-z
                                         unsealed-header kappa-prime author-idx))
      (:keys     (validate-seal-fallback slot seal gamma-prime eta-3-prime
                                         unsealed-header)))))

(defun validate-entropy-source (slot seal entropy-source
                                 gamma-prime unsealed-header
                                 &key kappa-prime author-idx)
  "GP (6.17) — Validate entropy source HV.
   HV ∈ V̂^[]_{HA}(XE ⌢ Y(HS))
   Key = HA (author's bandersnatch key):
   - fallback mode: HA = γ'S[HT mod E] (slot-indexed fallback key)
   - tickets mode:  HA = κ'[HI].kb (author's key from validator set)
   VRF input = XE ⌢ Y(HS), ad = [] (empty).
   slot: HT, seal: HS, entropy-source: HV — raw values.
   gamma-prime: γ' closure (messages :sealing-variant, :seal-entry-at).
   kappa-prime: κ' validator closure (message :bandersnatch-key).
   author-idx: HI (integer) — author index (needed for tickets mode).
   Signals SAFROLE-ERROR on failure."
  (let* (;; Y(HS) — VRF output of the seal
         (seal-vrf-out    (jam.ffi:Y seal))
         ;; VRF input = XE ⌢ Y(HS)
         (vrf-input       (concatenate '(vector (unsigned-byte 8))
                                       +ctx-entropy+
                                       seal-vrf-out)))
    (unless seal-vrf-out
      (reject-safrole :bad-entropy-source "Y(HS) extraction failed for entropy validation"))
    ;; Key = HA: γ'S[HT mod E] in fallback; κ'[HI].kb in tickets
    (let ((entropy-key (ecase (funcall gamma-prime :sealing-variant)
                         (:keys    (funcall gamma-prime :seal-entry-at slot))
                         (:tickets (when kappa-prime
                                     (funcall kappa-prime :bandersnatch-key
                                              author-idx))))))
      (when entropy-key
        ;; HV = [output: 32 bytes] [proof: 64 bytes]
        (let ((entropy-vrf-output (subseq entropy-source 0 32))
              (entropy-vrf-proof  (subseq entropy-source 32)))
          ;; GP (6.17): ad = [] (empty — no additional data for entropy VRF)
          (unless (jam.ffi:bandersnatch-verify-vrf
                   entropy-key vrf-input entropy-vrf-output entropy-vrf-proof)
            (reject-safrole :bad-entropy-source
                            "Entropy VRF verification failed")))))))

;;; ═══════════════════════════════════════════════════════════════
;;; HI — AUTHOR INDEX VALIDATION (GP §5)
;;; ═══════════════════════════════════════════════════════════════

(defun validate-author-index (author-idx)
  "GP §5 — HI < V.
   Author index must be a valid validator index.
   author-idx: HI (integer, not a closure).
   Signals SAFROLE-ERROR on failure."
  (unless (and (integerp author-idx) (< author-idx (num-validators)))
    (reject-safrole :bad-author-index
                    (format nil "HI=~A, V=~D" author-idx (num-validators)))))

;;; ═══════════════════════════════════════════════════════════════
;;; HE — EPOCH MARKER (GP 6.27)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; (6.27) HE ≡ {
;;;   (η₀, η₁, [(kb, ke) | k ≺ γ'P])   if e' > e
;;;   ∅                                    otherwise
;;; }
;;;
;;; On epoch change, the header must contain:
;;;   - η₀ (current entropy accumulator)
;;;   - η₁ (end-of-last-epoch entropy)
;;;   - For each validator in γ'P: (bandersnatch, ed25519) key pair

(defun compute-epoch-mark (epoch-change-p eta-0 eta-1 gamma-p-prime)
  "GP (6.27) — Compute expected epoch marker HE.
   Args: epoch-change-p (boolean), eta-0 (32B hash), eta-1 (32B hash),
         gamma-p-prime (γ'P: new pending validator keys)
   Returns: epoch-mark closure (same type as header's HE) or NIL."
  (if epoch-change-p
      ;; Epoch change → emit marker as closure
      (make-epoch-mark
       :entropy         eta-0    ;; η₀
       :tickets-entropy eta-1    ;; η₁
       :validators
       (mapcar (lambda (k)
                 (list :bandersnatch (getf k :bandersnatch)
                       :ed25519      (getf k :ed25519)))
               gamma-p-prime))
      ;; No epoch change → ∅
      nil))

;;; ═══════════════════════════════════════════════════════════════
;;; HW — WINNING TICKETS MARKER (GP 6.28)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; (6.28) HW ≡ {
;;;   Z(γA)   if e' = e ∧ m < Y ≤ m' ∧ |γA| = E
;;;   ∅       otherwise
;;; }
;;;
;;; Within the same epoch, when the closing threshold Y is crossed
;;; (m was before Y, m' is at or after Y) and exactly E tickets
;;; are accumulated, emit the winning tickets (reordered via Z).

(defun compute-winning-tickets-mark (epoch-change-p m m-prime gamma-a)
  "GP (6.28) — Compute expected winning-tickets marker HW.
   Args: epoch-change-p (boolean), m (prior phase), m-prime (new phase),
         gamma-a (accumulated tickets list)
   Returns: tickets-mark closure (same type as header's HW) or NIL."
  (let ((y (closing-offset)))
    (if (and (not epoch-change-p)                           ;; e' = e
             (< m y)                                        ;; m < Y
             (<= y m-prime)                                 ;; Y ≤ m'
             (= (length gamma-a) (epoch-duration)))         ;; |γA| = E
        ;; Threshold crossed + enough tickets → Z(γA) as closure
        (make-tickets-mark :tickets (outside-in-sequencer gamma-a))
        ;; Otherwise → ∅
        nil)))

;;; ═══════════════════════════════════════════════════════════════
;;; HEADER FIELD VALIDATION — HI, HS, HV, HE, HW
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Called from transition-state (upsilon.lisp) AFTER transition-gamma
;;; to validate header fields that depend on γ' intermediates.
;;; Not called from transition-gamma itself to keep the STF pure
;;; and avoid breaking test stubs that use minimal header closures.

(defun compare-epoch-marks (a b)
  "Compare two epoch marks (closures or nil).
   Both sides are epoch-mark closures from make-epoch-mark.
   Compares via serialized bytes for type-safe deep equality."
  (cond
    ((and (null a) (null b)) t)
    ((or (null a) (null b)) nil)
    (t (equalp (funcall a :encode) (funcall b :encode)))))

(defun compare-tickets-marks (a b)
  "Compare two tickets marks (closures or nil).
   Both sides are tickets-mark closures from make-tickets-mark.
   Compares via serialized bytes for type-safe deep equality."
  (cond
    ((and (null a) (null b)) t)
    ((or (null a) (null b)) nil)
    (t (equalp (funcall a :encode) (funcall b :encode)))))

(defun validate-header-safrole (header tau tau-prime gamma-prev eta eta-prime
                                 gamma-prime kappa-prime)
  "GP §5-6 — Validate header fields that depend on safrole state.
   Called from transition-state after computing γ'.
   Validates: HI (author index), HS (seal VRF), HV (entropy VRF),
   HE (epoch mark), HW (tickets mark).
   GP G.1: VRF ad parameter = EU(H) (header without seal).
   Signals SAFROLE-ERROR on any mismatch.

   Boundary function: extracts raw values from closures via messages,
   then delegates to standalone helpers."
  (let* (;; Extract raw values from closures — once at the top
         (slot           (funcall header :slot))
         (seal           (funcall header :seal))
         (author-idx     (funcall header :author-index))
         (entropy-source (funcall header :entropy-source))
         (actual-he      (funcall header :epoch-mark))
         (actual-hw      (funcall header :tickets-mark))
         (gamma-z-prime  (funcall gamma-prime :ring-commitment))
         (gamma-p-prime  (funcall gamma-prime :pending-keys))
         (gamma-a        (funcall gamma-prev :accumulator))
         (eta-3-prime    (funcall eta-prime :seal-entropy))
         (eta-0          (funcall eta :accumulator))
         (eta-1          (funcall eta :last-epoch-entropy))
         (epoch-change   (funcall tau :epoch-changed? tau-prime))
         (m              (funcall tau :phase))
         (m-prime        (funcall tau-prime :phase)))
    ;; ── HI: author index < V ──
    (validate-author-index author-idx)
    ;; ── HS: seal VRF verification (GP §6.15/6.16) ──
    ;; ad = EU(H) — header serialization without seal (GP §6.4)
    (let ((unsealed-header (funcall header :encode-unsealed)))
      (validate-seal slot author-idx seal gamma-prime eta-3-prime gamma-z-prime
                     unsealed-header :kappa-prime kappa-prime)
      ;; ── HV: entropy source VRF verification (GP §6.17) ──
      (validate-entropy-source slot seal entropy-source
                               gamma-prime unsealed-header
                               :kappa-prime kappa-prime
                               :author-idx author-idx))
    ;; ── HE: epoch mark consistency ──
    (let ((expected-he (compute-epoch-mark epoch-change eta-0 eta-1 gamma-p-prime)))
      (unless (compare-epoch-marks actual-he expected-he)
        (reject-safrole :bad-epoch-mark
                        (format nil "HE mismatch: expected ~A, got ~A"
                               (not (null expected-he)) (not (null actual-he))))))
    ;; ── HW: tickets mark consistency ──
    (let ((expected-hw (compute-winning-tickets-mark epoch-change m m-prime gamma-a)))
      (unless (compare-tickets-marks actual-hw expected-hw)
        (reject-safrole :bad-tickets-mark
                        (format nil "HW mismatch: expected ~A, got ~A"
                               (not (null expected-hw)) (not (null actual-hw))))))))
