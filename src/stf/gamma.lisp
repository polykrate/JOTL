;;;; stf/gamma.lisp — γ (Safrole State)
;;;; Gray Paper §6
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

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; VALUE OBJECT
;;; ═══════════════════════════════════════════════════════════════

(define-value-object gamma
  ((pending-keys nil)     ;; γk: list of V full validators
   (ring-commitment nil)  ;; γz: 144-byte vector
   (sealing nil)          ;; γs: plist (:variant :keys/:tickets :data [...])
   (accumulator nil))     ;; γa: list of ticket plists (:id bytes :attempt int)
  ;; GP subscript aliases
  (:kappa  pending-keys)
  (:gamma-k pending-keys)
  (:gamma-z ring-commitment)
  (:gamma-s sealing)
  (:gamma-a accumulator)
  ;; Memoized encoding
  (:encoded :memo
    (concatenate '(vector (unsigned-byte 8))
                 (encode-full-validator-sequence pending-keys)
                 (if ring-commitment
                     ring-commitment
                     (make-array +bls-key-size+ :element-type '(unsigned-byte 8) :initial-element 0))
                 (encode-gamma-sealing sealing)
                 (encode-sequence accumulator #'encode-state-ticket))))

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

(defun decode-state-ticket (bytes offset)
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

(defun decode-gamma-sealing (bytes offset)
  "Decode γs. Returns: (values plist bytes-consumed)"
  (let* ((discriminant (aref bytes offset))
         (pos (1+ offset))
         (e (epoch-duration)))
    (ecase discriminant
      (0 ;; tickets: E × 33 bytes
       (let ((tickets '()))
         (dotimes (i e)
           (multiple-value-bind (ticket size) (decode-state-ticket bytes pos)
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
;;; STATE CODEC — C(4) ↦ E(γk, γz, discriminant ⌢ γs, ↕γa)
;;; ═══════════════════════════════════════════════════════════════

(defun encode-state-gamma (gamma)
  "C(4) ↦ E(γ) — uses gamma closure's memoized encoding."
  (funcall gamma :encoded))

(defun decode-state-gamma (bytes &optional (offset 0))
  "Decode γ from state binary.
   Returns: (values gamma-closure bytes-consumed)"
  (let ((pos offset))
    ;; γk: V × 336 bytes
    (multiple-value-bind (pending-keys pk-size)
        (decode-full-validator-sequence bytes pos)
      (incf pos pk-size)
      ;; γz: 144 bytes
      (let ((ring-commitment (subseq bytes pos (+ pos 144))))
        (incf pos 144)
        ;; γs: discriminant + data
        (multiple-value-bind (sealing gs-size)
            (decode-gamma-sealing bytes pos)
          (incf pos gs-size)
          ;; γa: compact-prefixed sequence of tickets
          (multiple-value-bind (accumulator ga-size)
              (decode-sequence bytes #'decode-state-ticket pos)
            (incf pos ga-size)
            (values
             (make-gamma :pending-keys pending-keys
                         :ring-commitment ring-commitment
                         :sealing sealing
                         :accumulator accumulator)
             (- pos offset))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; SEAL & ENTROPY VALIDATION — GP §6.4 (6.15)-(6.20)
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

(define-condition safrole-error (error)
  ((code   :initarg :code   :reader safrole-error-code)
   (detail :initarg :detail :reader safrole-error-detail :initform nil))
  (:report (lambda (c s)
             (format s "SAFROLE-ERROR: ~A~@[ — ~A~]"
                     (safrole-error-code c) (safrole-error-detail c)))))

(defun seal-key-index (timeslot)
  "γ'S[HT]^○ — Circular index into sealing series.
   Returns: HT mod E"
  (mod timeslot (epoch-duration)))

(defun validate-seal-tickets (header gamma-s-prime eta-3-prime gamma-z)
  "GP (6.15) — Validate seal in tickets mode.
   - γ'S[HT mod E] is the ticket at this timeslot
   - iy = Y(HS): VRF output matches ticket ID
   - HS verified via Ring VRF with input = XT ⌢ η'₃ ⌢ ie
   Signals SAFROLE-ERROR on failure."
  (let* ((slot     (funcall header :slot))
         (seal     (funcall header :seal))
         (idx      (seal-key-index slot))
         (ticket   (nth idx (getf gamma-s-prime :data)))
         ;; (6.15) iy = Y(HS)
         (vrf-out  (jam.ffi:Y seal)))
    (unless vrf-out
      (error 'safrole-error :code :bad-seal :detail "Y(HS) extraction failed"))
    (unless (equalp vrf-out (getf ticket :id))
      (error 'safrole-error :code :bad-seal
             :detail (format nil "Y(HS) ≠ ticket id at slot ~D" slot)))
    ;; (6.15) HS ∈ V̂○(XT ⌢ η'₃ ⌢ ie)
    (let* ((attempt  (getf ticket :attempt))
           (vrf-input (concatenate '(vector (unsigned-byte 8))
                                   +ctx-ticket-seal+
                                   eta-3-prime
                                   (vector attempt)))
           (valid-p  (jam.ffi:bandersnatch-verify-ring-vrf
                      gamma-z vrf-input seal
                      :ring-size (num-validators))))
      (unless valid-p
        (error 'safrole-error :code :bad-seal
               :detail "Ring VRF verification failed (tickets mode)")))))

(defun validate-seal-fallback (header gamma-s-prime eta-3-prime)
  "GP (6.16) — Validate seal in fallback (keys) mode.
   - i = HA: seal key is the author's bandersnatch key
   - HS ∈ V̂(XF ⌢ η'₃): Bandersnatch VRF with input = fallback_seal ⌢ η'₃
   Signals SAFROLE-ERROR on failure."
  (let* ((author-idx (funcall header :author-index))
         (seal       (funcall header :seal))
         (keys       (getf gamma-s-prime :data))
         ;; i = HA — the bandersnatch key at author index
         (seal-key   (nth author-idx keys))
         ;; (6.16) VRF input = XF ⌢ η'₃
         (vrf-input  (concatenate '(vector (unsigned-byte 8))
                                  +ctx-fallback-seal+
                                  eta-3-prime)))
    (unless seal-key
      (error 'safrole-error :code :bad-seal
             :detail (format nil "No fallback key at author index ~D" author-idx)))
    ;; Verify as Bandersnatch VRF (plain, not ring)
    (let ((vrf-out (jam.ffi:Y seal)))
      (unless vrf-out
        (error 'safrole-error :code :bad-seal :detail "Y(HS) extraction failed"))
      (unless (jam.ffi:bandersnatch-verify-vrf
               seal-key vrf-input vrf-out seal)
        (error 'safrole-error :code :bad-seal
               :detail "Bandersnatch VRF verification failed (fallback mode)")))))

(defun validate-seal (header gamma-s-prime eta-3-prime gamma-z)
  "GP (6.15)/(6.16) — Dispatch seal validation based on γ'S variant.
   Signals SAFROLE-ERROR on failure."
  (ecase (getf gamma-s-prime :variant)
    (:tickets  (validate-seal-tickets  header gamma-s-prime eta-3-prime gamma-z))
    (:keys     (validate-seal-fallback header gamma-s-prime eta-3-prime))))

(defun validate-entropy-source (header gamma-s-prime)
  "GP (6.17) — Validate entropy source HV.
   HV ∈ V̂_{HA}(XE ⌢ Y(HS))
   The entropy source must be a valid Bandersnatch VRF with:
     - public key: the author's bandersnatch key from γ'S
     - VRF input: jam_entropy ⌢ Y(HS)
   Signals SAFROLE-ERROR on failure."
  (let* ((seal            (funcall header :seal))
         (entropy-source  (funcall header :entropy-source))
         (author-idx      (funcall header :author-index))
         ;; Y(HS) — VRF output of the seal
         (seal-vrf-out    (jam.ffi:Y seal))
         ;; VRF input = XE ⌢ Y(HS)
         (vrf-input       (concatenate '(vector (unsigned-byte 8))
                                       jam.ffi:+jam-entropy+
                                       seal-vrf-out)))
    (unless seal-vrf-out
      (error 'safrole-error :code :bad-entropy-source :detail "Y(HS) extraction failed"))
    ;; Find the author's bandersnatch key
    (let ((author-key (ecase (getf gamma-s-prime :variant)
                        (:tickets
                         ;; In tickets mode, we need the key from kappa
                         ;; The author IS the ticket holder — we don't know their identity
                         ;; (anonymized by Ring VRF). Use HA to look up in κ.
                         ;; NOTE: this requires κ to be passed. For now, skip.
                         nil)
                        (:keys
                         ;; In fallback mode, the key at HA in γS
                         (nth author-idx (getf gamma-s-prime :data))))))
      (when author-key
        (let ((entropy-vrf-out (jam.ffi:Y entropy-source)))
          (unless entropy-vrf-out
            (error 'safrole-error :code :bad-entropy-source
                   :detail "Y(HV) extraction failed"))
          (unless (jam.ffi:bandersnatch-verify-vrf
                   author-key vrf-input entropy-vrf-out entropy-source)
            (error 'safrole-error :code :bad-entropy-source
                   :detail "Entropy VRF verification failed")))))))

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
;;; For each slot i ∈ [0, E):
;;;   1. Compute H(r ⌢ E₄(i))      — hash of entropy ⌢ slot index
;;;   2. Take first 4 bytes as u32  — pseudo-random index
;;;   3. k[idx mod V]               — circular index into validators
;;;   4. Extract bandersnatch key   — _b suffix

(defun fallback-key-sequence (randomness validators)
  "F(r, k) — GP (6.26): Fallback key sequence.
   Creates E bandersnatch keys by pseudo-randomly indexing into validators.
   - randomness: H (32-byte hash) = η'₂
   - validators: ⟦K⟧ = κ' (list of full validator plists)
   Returns: list of E bandersnatch public keys (32 bytes each)."
  (let* ((e (epoch-duration))
         (v (length validators)))
    (when (zerop v)
      (error 'safrole-error :code :no-validators
             :detail "Empty validator set for fallback"))
    (loop for i below e
          for e4-i = (E4 i)
          for hash = (blake2b-256
                      (concatenate '(vector (unsigned-byte 8))
                                   randomness e4-i))
          for idx = (mod (decode-fixed-le (subseq hash 0 4)) v)
          collect (getf (nth idx validators) :bandersnatch))))

;;; ═══════════════════════════════════════════════════════════════
;;; Y — CLOSING OFFSET (GP §6)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Y is the slot index within an epoch at which the closing period
;;; begins. Once m ≥ Y, no new tickets can be submitted.
;;; TODO: verify exact GP definition — using E - R for now.

(defun closing-offset ()
  "Y — GP §6.5-6.7: Slot offset within epoch where ticket-submission ends.
   After this offset, no more tickets can be submitted.
   Returns: contest-duration (Y in the GP, NOT P which is slot-period).
   Tiny: 10, Full: 500."
  (contest-duration))

;;; ═══════════════════════════════════════════════════════════════
;;; Φ — OFFENDER FILTER (GP 6.14)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Φ(k) ≡ [[0,0,...] if ke ∈ ψ'O, k otherwise] | k ≺ k
;;;
;;; Replace any validator whose Ed25519 key (ke) is in the offenders
;;; set with an all-zeros key (336 bytes of 0x00).

(defparameter +null-validator-key+
  (list :bandersnatch (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
        :ed25519      (make-array +ed25519-key-size+ :element-type '(unsigned-byte 8) :initial-element 0)
        :bls          (make-array +bls-key-size+ :element-type '(unsigned-byte 8) :initial-element 0)
        :metadata     (make-array +metadata-size+ :element-type '(unsigned-byte 8) :initial-element 0))
  "K = [0,0,...] — null validator key (+validator-key-size+ zero bytes). GP (6.14).")

(defun filter-offenders (validators offenders)
  "Φ(k) — GP (6.14): Zero out validators whose ke ∈ ψ'O.
   Args: validators (list of K plists), offenders (list of ed25519 keys)
   Returns: new list with offending validators replaced by null keys."
  (if (null offenders)
      validators  ;; No offenders → unchanged
      (mapcar (lambda (k)
                (let ((ke (getf k :ed25519)))
                  (if (member-hash ke offenders)
                      +null-validator-key+
                      k)))
              validators)))

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

(defun compute-epoch-mark (tau tau-prime eta gamma-p-prime)
  "GP (6.27) — Compute expected epoch marker HE.
   Args: tau (prior timeslot), tau-prime (new timeslot),
         eta (pre-transition entropy list: η₀ η₁ η₂ η₃),
         gamma-p-prime (γ'P: new pending validator keys)
   Returns: epoch-mark plist or NIL."
  (if (new-epoch-p tau tau-prime)
      ;; Epoch change → emit marker
      (list :entropy         (nth 0 eta)   ;; η₀
            :tickets-entropy (nth 1 eta)   ;; η₁
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

(defun compute-winning-tickets-mark (tau tau-prime gamma-a)
  "GP (6.28) — Compute expected winning-tickets marker HW.
   Args: tau (prior timeslot), tau-prime (new timeslot),
         gamma-a (accumulated tickets list)
   Returns: list of tickets (Z-reordered) or NIL."
  (let* ((e   (epoch-duration))
         (y   (closing-offset))
         (m   (mod tau e))         ;; prior slot within epoch
         (m-prime (mod tau-prime e)))  ;; new slot within epoch
    (if (and (not (new-epoch-p tau tau-prime))   ;; e' = e
             (< m y)                              ;; m < Y
             (<= y m-prime)                       ;; Y ≤ m'
             (= (length gamma-a) e))              ;; |γA| = E
        ;; Threshold crossed + enough tickets → Z(γA)
        (outside-in-sequencer gamma-a)
        ;; Otherwise → ∅
        nil)))

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
      (error 'safrole-error :code :too-many-tickets
             :detail (format nil "|ET|=~D > ~D (m'=~D, Y=~D)"
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
      (error 'safrole-error :code :bad-ticket-attempt
             :detail (format nil "attempt ~D ≥ N=~D"
                             attempt (tickets-per-validator))))
    ;; VRF input = XT ⌢ η'₂ ⌢ E1(e) — helper from FFI
    (let ((vrf-input (jam.ffi:ticket-vrf-input eta-2-prime attempt)))
      ;; Ring VRF verification against γ'Z
      (unless (jam.ffi:bandersnatch-verify-ring-vrf
               gamma-z-prime vrf-input signature
               :ring-size (num-validators))
        (error 'safrole-error :code :bad-ticket-proof
               :detail "Ring VRF verification failed")))))

(defun extract-new-tickets (tickets)
  "GP (6.31) — n = [(y · Y(ip), e · ie) | i ≺ ET]
   Extract state ticket entries (id=Y(p), attempt=e) from extrinsic tickets."
  (mapcar (lambda (ticket)
            (let* ((signature (getf ticket :signature))
                   (attempt   (getf ticket :attempt))
                   (id        (jam.ffi:Y signature)))
              (unless id
                (error 'safrole-error :code :bad-ticket-vrf-output
                       :detail "Y(p) returned nil"))
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
        do (error 'safrole-error :code :bad-ticket-order
                  :detail "Tickets not sorted by identifier")))

(defun validate-new-tickets-no-duplicates (new-tickets accumulator)
  "GP (6.33) — {xy | x ∈ n} ∤ {xy | x ∈ γA}
   No ticket id in new-tickets may already exist in accumulator."
  (dolist (ticket new-tickets)
    (when (find (getf ticket :id) accumulator
                :key (lambda (a) (getf a :id)) :test #'equalp)
      (error 'safrole-error :code :duplicate-ticket
             :detail "Ticket id already in accumulator"))))

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
      (error 'safrole-error :code :ticket-not-included
             :detail "Submitted ticket not in final accumulator"))))

(defun process-ticket-extrinsic (tickets gamma-z-prime eta-2-prime
                                 gamma-a tau-prime epoch-change-p)
  "GP (6.29)-(6.35) — Full ticket processing pipeline.
   Args:
     tickets: raw extrinsic tickets (ET) — list of (:attempt u8 :signature 784B)
     gamma-z-prime: γ'Z ring commitment for VRF verification
     eta-2-prime: η'₂ for VRF input
     gamma-a: current accumulator (or nil)
     tau-prime: new timeslot (τ')
     epoch-change-p: T if e' > e
   Returns: γ'A (new accumulator)"
  (let ((m-prime (mod tau-prime (epoch-duration))))
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
;;; γ TRANSITION — GP §6
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; (4.7) γ' < (H, τ, ET, γ, ι, η', κ', ψ')
;;;
;;; Key rotation (6.13):
;;;   if e' > e (epoch change):
;;;     γ'P = Φ(ι)              — enqueued keys, filtered through offenders
;;;     γ'Z = O([kb | k ≺ γ'P]) — ring commitment from new pending keys
;;;   otherwise:
;;;     γ'P = γP, γ'Z = γZ
;;;
;;; Slot key sequence (6.24):
;;;   Z(γA) | γS | F(η'₂, κ')
;;;
;;; Ticket accumulation (6.29-6.35):
;;;   Validate Ring VRF proofs, merge into accumulator, take E smallest

(defun transition-gamma (header tau tickets gamma iota eta-prime kappa-prime psi-prime)
  "GP §6 — Safrole state transition.
   γ' ≺ (H, τ, E_T, γ, ι, η', κ', ψ')

   Implemented:
     (6.13) Key rotation at epoch boundary: γ'P, γ'Z
     (6.14) Offender filtering: Φ(k)
     (6.24) Slot key sequence γ'S: Z(γA) | γS | F(η'₂, κ')
     (6.25) Outside-in sequencer Z
     (6.26) Fallback key sequence F
     (6.27) Epoch marker HE (compute-epoch-mark)
     (6.28) Winning tickets marker HW (compute-winning-tickets-mark)
     (6.29-6.35) Ticket validation + accumulation γ'A

   Args: header (H, block header closure), tau (τ, prior timeslot),
         tickets (ET list), gamma (γ closure),
         iota (ι list), eta-prime (η' list),
         kappa-prime (κ' list), psi-prime (ψ' plist)
   Returns: γ'"
  (let* ((tau-prime (funcall header :slot))  ;; τ' = HT
         ;; Current γ components
         (gamma-p (funcall gamma :pending-keys))
         (gamma-z (funcall gamma :ring-commitment))
         (gamma-s (funcall gamma :sealing))
         (gamma-a (funcall gamma :accumulator))
         ;; Epoch math
         (epoch-change (new-epoch-p tau tau-prime))
         (m (mod tau (epoch-duration)))  ;; prior slot position within epoch
         ;; η'₂ for VRF input (ticket validation + fallback sequence)
         (eta-2-prime (nth 2 eta-prime))
         ;; Offenders from ψ'
         (offenders (getf psi-prime :offenders)))
    (if epoch-change
        ;; ══════════════════════════════════════════════════════════
        ;; EPOCH CHANGE (e' > e)
        ;; ══════════════════════════════════════════════════════════
        (let* (;; (6.13) γ'P = Φ(ι) — filter offenders from enqueued keys
               (gamma-p-prime (filter-offenders iota offenders))
               ;; (6.13) z = O([kb | k ≺ γ'P]) — ring commitment from new pending keys
               (bander-keys (mapcar (lambda (k) (getf k :bandersnatch))
                                    gamma-p-prime))
               (gamma-z-prime (or (jam.ffi:bandersnatch-compute-ring-commitment
                                   (coerce bander-keys 'vector))
                                  gamma-z))  ;; fallback if SRS not loaded
               ;; (6.24) γ'S — Slot key sequence
               ;; Tickets enacted iff contest closed (m > Y) AND accumulator full
               (gamma-s-prime
                (if (and (> m (closing-offset))
                         (= (length gamma-a) (epoch-duration)))
                    ;; TICKETS MODE: Z(γA)
                    (list :variant :tickets
                          :data (outside-in-sequencer gamma-a))
                    ;; FALLBACK MODE: F(η'₂, κ')
                    (list :variant :keys
                          :data (fallback-key-sequence eta-2-prime kappa-prime))))
               ;; (6.29-6.35) Ticket accumulation (base = ∅ on epoch)
               (gamma-a-prime (process-ticket-extrinsic
                               tickets gamma-z-prime eta-2-prime
                               gamma-a tau-prime t)))  ;; epoch-change-p = T
          (make-gamma :pending-keys gamma-p-prime
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
                              tickets gamma-z eta-2-prime
                              gamma-a tau-prime nil)))  ;; epoch-change-p = NIL
          (make-gamma :pending-keys gamma-p
                      :ring-commitment gamma-z
                      :sealing gamma-s
                      :accumulator gamma-a-prime)))))
