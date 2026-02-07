;;;; header.lisp - JAM Block Header (Pure FP)
;;;; Gray Paper Section 5

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 5.1: THE HEADER
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.1:

The header comprises a parent hash and prior state root (HP and HR),
an extrinsic hash HX, a time-slot index HT, the epoch, winning-tickets
and offenders markers HE, HW and HO, a block author index HI and two
Bandersnatch signatures; the entropy-yielding VRF signature HV and
a block seal HS.

Headers may be serialized to an octet sequence with and without
the latter seal component using E and EU respectively.

Formally:

  H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)           (5.1)

Where:
  HP : Parent hash (Hash of parent header)
  HR : Prior state root
  HX : Extrinsic hash (Merkle commitment)
  HT : Time-slot index (τ')
  HE : Epoch marker (validators, entropy)
  HW : Winning-tickets marker
  HO : Offenders marker
  HI : Block author index
  HV : Entropy-yielding VRF signature (Bandersnatch)
  HS : Block seal (Bandersnatch signature)

The blockchain is a sequence of blocks, each cryptographically
referencing some prior block by including a hash derived from the
parent's header, all the way back to some first block which
references the genesis header.

We already presume consensus over the genesis header H0 and the
state it represents defined as σ0.
|#

;;; ═══════════════════════════════════════════════════════════════
;;; HEADER CONSTRUCTION (Pure FP with Closures)
;;; ═══════════════════════════════════════════════════════════════

(defun make-header (&key parent-hash
                         state-root
                         extrinsic-hash
                         slot
                         epoch-mark
                         tickets-mark
                         author-index
                         entropy-source
                         offenders-mark
                         seal)
  "Creates a header closure H
   
   Gray Paper §5.1
   
   Args:
     parent-hash     - HP : Hash of parent block header
     state-root      - HR : Root of state trie
     extrinsic-hash  - HX : Merkle root of extrinsic data
     slot            - HT : Timeslot τ'
     epoch-mark      - HE : Epoch marker (validators, entropy)
     tickets-mark    - HW : Tickets marker
     author-index    - Hi : Validator index who authored
     entropy-source  - HV : VRF entropy source
     offenders-mark  - HO : List of offending validators
     seal            - HS : Block seal (signature)
   
   Returns: Header closure H"
  
  (lambda (msg &rest args)
    (case msg
      ;; Core fields
      (:parent-hash parent-hash)
      (:state-root state-root)
      (:extrinsic-hash extrinsic-hash)
      (:slot slot)
      (:epoch-mark epoch-mark)
      (:tickets-mark tickets-mark)
      (:author-index author-index)
      (:entropy-source entropy-source)
      (:offenders-mark offenders-mark)
      (:seal seal)
      
      ;; Derived queries
      (:timeslot slot)  ; Alias for slot (τ')
      (:is-genesis (null parent-hash))
      
      ;; Hash of this header (E(H))
      (:hash (compute-header-hash parent-hash state-root extrinsic-hash 
                                  slot epoch-mark tickets-mark author-index
                                  entropy-source offenders-mark seal))
      
      ;; Metadata
      (:type :header)
      
      (otherwise (error "Unknown header message: ~a" msg)))))

;;; ═══════════════════════════════════════════════════════════════
;;; HEADER ACCESSORS
;;; ═══════════════════════════════════════════════════════════════

(defun header-parent-hash (header)
  "HP - Parent hash"
  (funcall header :parent-hash))

(defun header-state-root (header)
  "HR - State root"
  (funcall header :state-root))

(defun header-extrinsic-hash (header)
  "HX - Extrinsic hash"
  (funcall header :extrinsic-hash))

(defun header-slot (header)
  "HT - Timeslot (τ')"
  (funcall header :slot))

(defun header-epoch-mark (header)
  "HE - Epoch marker"
  (funcall header :epoch-mark))

(defun header-tickets-mark (header)
  "HW - Tickets marker"
  (funcall header :tickets-mark))

(defun header-author-index (header)
  "Hi - Author index"
  (funcall header :author-index))

(defun header-entropy-source (header)
  "HV - Entropy source (VRF)"
  (funcall header :entropy-source))

(defun header-offenders-mark (header)
  "HO - Offenders mark"
  (funcall header :offenders-mark))

(defun header-seal (header)
  "HS - Seal (signature)"
  (funcall header :seal))

(defun header-hash (header)
  "H(E(H)) - Hash of encoded header"
  (funcall header :hash))

;;; ═══════════════════════════════════════════════════════════════
;;; HEADER HASHING (Gray Paper §5)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.2:

HP ∈ H, HP ≡ H(E(P(H)))

The parent hash HP is the hash of the encoding of the parent header.

For any header H:
  Hash = H(E(H))
  
Where:
  H() = Blake2b-256 hash function
  E() = SCALE encoding function
|#

(defun compute-header-hash (parent-hash state-root extrinsic-hash 
                            slot epoch-mark tickets-mark author-index
                            entropy-source offenders-mark seal)
  "Computes H(E(H)) - hash of encoded header
   
   Gray Paper §5.2
   
   TODO: Implement SCALE encoding and Blake2b hashing"
  
  ;; Placeholder: return dummy hash for now
  ;; Will implement with SCALE codec + ironclad Blake2b
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 5.2: PARENT HASH (HP)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.2:

Excepting the Genesis header, all block headers H have an
associated parent header, whose hash is HP.

We denote the parent header H⁻ = P(H):

  HP ∈ H, HP ≡ H(E(P(H)))                              (5.2)

Translation:
  HP = Hash of the encoding of the parent header
  HP = H(E(P(H)))

Where:
  H()   = Blake2b-256 hash function
  E()   = SCALE encoding function
  P(H)  = Parent header (mapping from header to parent)
  H⁻    = Parent header (alternative notation)

P is thus defined as being the mapping from one block header
to its parent block header.

Special case:
  - Genesis header H0: HP = null (or all zeros)
  - All other headers: HP must reference a valid parent
|#

(defun parent-function (header)
  "P(H) - Returns the parent header from a given header
   
   Gray Paper §5.2
   
   Args:
     header - Current header H
   
   Returns:
     Parent header H⁻, or NIL if genesis
   
   Note: In practice, this requires a blockchain store to
         look up the parent by HP hash."
  
  (if (header-is-genesis-p header)
      nil
      ;; In a real implementation, this would:
      ;; 1. Get HP (parent hash) from header
      ;; 2. Look up header with hash = HP from blockchain store
      ;; For now, we just return the parent-hash
      (funcall header :parent-hash)))

(defun compute-parent-hash (parent-header)
  "Computes HP ≡ H(E(P(H)))
   
   Gray Paper §5.2
   
   Args:
     parent-header - The parent header H⁻
   
   Returns:
     32-byte hash (HP)
   
   Formula:
     HP = H(E(H⁻))
     
   Where:
     H() = Blake2b-256
     E() = SCALE encoding"
  
  ;; TODO: Implement SCALE encoding and Blake2b
  ;; For now, return the parent's hash if available
  (if parent-header
      (funcall parent-header :hash)
      ;; Genesis: return null hash (32 zeros)
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun header-is-genesis-p (header)
  "Checks if header is the genesis header H0
   
   Gray Paper §5.2
   
   Genesis has no parent (HP = null or all zeros)
   
   Returns: T if genesis, NIL otherwise"
  
  (let ((parent-hash (funcall header :parent-hash)))
    (or (null parent-hash)
        (every #'zerop parent-hash))))

(defun validate-parent-hash (header parent-header)
  "Validates that HP in header matches H(E(parent-header))
   
   Gray Paper §5.2: HP ≡ H(E(P(H)))
   
   Args:
     header        - Current header H
     parent-header - Parent header H⁻
   
   Returns: T if valid, NIL otherwise"
  
  (let ((claimed-hp (funcall header :parent-hash))
        (computed-hp (compute-parent-hash parent-header)))
    
    (equalp claimed-hp computed-hp)))

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 5.7: TIMESLOT VALIDATION (HT)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.7:

A block may only be regarded as valid once the time-slot index HT
is in the past. It is always strictly greater than that of its
parent. Formally:

  HT ∈ ℕT, P(H)T < HT ∧ HT · P ≤ T                    (5.7)

Translation:

1. HT ∈ ℕT
   - HT must be a natural number (timeslot index)

2. P(H)T < HT
   - HT must be strictly greater than parent's timeslot
   - P(H)T = timeslot of parent header
   - This ensures monotonically increasing timeslots

3. HT · P ≤ T
   - Timeslot converted to real time must be in the past
   - HT · P = timeslot * slot_duration (in seconds)
   - T = current time (in seconds)
   - This prevents blocks "from the future"

Special note:
Blocks considered invalid by this rule may become valid as T
advances (time catches up to the timeslot).

Where:
  HT = Timeslot of current header (τ')
  P(H)T = Timeslot of parent header (τ)
  P = Slot period duration (6 seconds)
  T = Current time (Unix timestamp in seconds)
  ℕT = Natural numbers for timeslots
|#

(defun validate-timeslot (header &optional parent-header (current-time (get-universal-time)))
  "Validates HT according to Gray Paper §5.7
   
   HT ∈ ℕT, P(H)T < HT ∧ HT · P ≤ T
   
   Args:
     header        - Current header H
     parent-header - Parent header P(H) (optional, required for non-genesis)
     current-time  - Current time T (default: now)
   
   Returns:
     (values valid-p reason)
     - valid-p: T if valid, NIL otherwise
     - reason: String explaining validation result"
  
  (let* ((HT (funcall header :slot))
         (P (slot-duration))  ; Slot period (6 seconds)
         
         ;; Convert current-time (Common Lisp universal-time) to Unix time
         (T-unix (- current-time 2208988800)))
    
    ;; Check 1: HT ∈ ℕT (natural number)
    (unless (and (integerp HT) (>= HT 0))
      (return-from validate-timeslot
        (values nil (format nil "HT must be natural number, got: ~A" HT))))
    
    ;; Check 2: P(H)T < HT (strictly greater than parent)
    (when parent-header
      (let ((parent-HT (funcall parent-header :slot)))
        (unless (> HT parent-HT)
          (return-from validate-timeslot
            (values nil (format nil "HT (~D) must be > parent timeslot (~D)" HT parent-HT))))))
    
    ;; Check 3: HT · P ≤ T (timeslot in the past)
    (let ((block-time (* HT P)))  ; HT · P
      (unless (<= block-time T-unix)
        (return-from validate-timeslot
          (values nil (format nil "Block from future: HT·P=~D > T=~D (diff: ~D seconds)"
                             block-time T-unix (- block-time T-unix))))))
    
    ;; All checks passed
    (values t "Valid timeslot")))

(defun timeslot-in-past-p (header &optional (current-time (get-universal-time)))
  "Checks if HT · P ≤ T (timeslot is in the past)
   
   Gray Paper §5.7
   
   Returns: T if timeslot is in past, NIL if in future"
  
  (let* ((HT (funcall header :slot))
         (P (slot-duration))
         (T-unix (- current-time 2208988800)))
    
    (<= (* HT P) T-unix)))

(defun timeslot-greater-than-parent-p (header parent-header)
  "Checks if P(H)T < HT (current timeslot > parent timeslot)
   
   Gray Paper §5.7
   
   Returns: T if HT > parent's HT, NIL otherwise"
  
  (let ((HT (funcall header :slot))
        (parent-HT (funcall parent-header :slot)))
    
    (> HT parent-HT)))

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 5.3: ANCESTOR SET (A)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.3:

With P, we are able to define the set of ancestor headers A:

  h ∈ A ⇔ h = H ∨ (∃i ∈ A : h = P(i))                 (5.3)

Translation:
A header h is in the ancestor set A if and only if:
  - h is the current header H, OR
  - h is the parent of some header i which is already in A

This is a recursive definition. The ancestor set includes:
  - The current header H
  - The parent P(H)
  - The grandparent P(P(H))
  - The great-grandparent P(P(P(H)))
  - ... all the way back to genesis H0

Retention requirement:
We only require implementations to store headers of ancestors
which were authored in the previous L = 24 hours of any block B
they wish to validate.

Where:
  L = 24 hours
  24 hours = 14400 timeslots (at 6 seconds per slot)
|#

(defconstant +ancestor-retention-hours+ 24
  "L = 24 hours - Gray Paper §5.3
   
   Implementations must store ancestors from last 24h")

(defun compute-ancestor-set (header &optional (max-depth 14400))
  "Computes the ancestor set A for a header
   
   Gray Paper §5.3:
   h ∈ A ⇔ h = H ∨ (∃i ∈ A : h = P(i))
   
   Args:
     header    - Current header H
     max-depth - Maximum depth to traverse (default: 24h = 14400 slots)
   
   Returns:
     List of ancestor headers [H, P(H), P(P(H)), ...]
   
   Note: In a real implementation, this would query a blockchain
         store. For now, we return a placeholder."
  
  ;; Placeholder: In reality, we'd walk the chain via P(H)
  ;; using a blockchain database
  (list header))

(defun is-ancestor-p (h1 h2)
  "Checks if h1 is an ancestor of h2
   
   Gray Paper §5.3:
   h1 ∈ A(h2)
   
   Returns: T if h1 is ancestor of h2, NIL otherwise
   
   Implementation: Walk from h2 backwards via P() until we
   find h1 or reach genesis."
  
  ;; Placeholder: Would require blockchain store
  ;; Compare hashes
  (equalp (funcall h1 :hash) (funcall h2 :parent-hash)))

;;; ═══════════════════════════════════════════════════════════════
;;; GRAY PAPER SECTION 5.4-5.6: EXTRINSIC HASH (HX)
;;; ═══════════════════════════════════════════════════════════════

#|
Gray Paper §5.4-5.6:

The extrinsic hash HX is a Merkle commitment to the block's
extrinsic data, taking care to allow for the possibility of
reports to individually have their inclusion proven.

Given any block B = (H, E), then formally:

  HX ∈ H, HX ≡ HEH#(a)                                 (5.4)

where:
  a = [ET(ET), EP(EP), g, EA(EA), ED(ED)]              (5.5)

and:
  g = E(↕[(H(r), E4(t), ↕a) | (r,t,a) ← EG])          (5.6)

Translation:

§5.4:
  HX = Merkle root of array a
  HEH# = Binary Merkle tree root function

§5.5:
  Array a contains 5 encoded components:
    1. ET(ET) - Encoded tickets
    2. EP(EP) - Encoded preimages
    3. g      - Encoded reports (with special structure)
    4. EA(EA) - Encoded assurances
    5. ED(ED) - Encoded disputes

§5.6:
  Reports (g) have special encoding to allow Merkle proofs:
  g = E(↕[triple | triple ← EG])
  
  Each triple is:
    (H(r), E4(t), ↕a)
    
  Where:
    H(r)  = Hash of report r
    E4(t) = 4-byte encoding of type t
    ↕a    = Authorization data a
    
  The ↕ operator means "sequence of"
  The | means "for each"
  (r,t,a) ← EG means: for each (report, type, auth) in guarantees

Why this structure?
The special encoding of reports allows individual reports to have
their inclusion proven via Merkle proofs without revealing the
entire extrinsic data.
|#

(defun compute-extrinsic-hash (extrinsic)
  "Computes HX ≡ HEH#(a) - Extrinsic hash
   
   Gray Paper §5.4-5.6
   
   Args:
     extrinsic - Extrinsic closure E
   
   Returns:
     32-byte hash (HX)
   
   Formula:
     HX = HEH#(a)
     where a = [ET(ET), EP(EP), g, EA(EA), ED(ED)]
     and g = E(↕[(H(r), E4(t), ↕a) | (r,t,a) ← EG])"
  
  ;; Step 1: Extract components from extrinsic
  (let* ((tickets (funcall extrinsic :tickets))
         (preimages (funcall extrinsic :preimages))
         (guarantees (funcall extrinsic :guarantees))
         (assurances (funcall extrinsic :assurances))
         (disputes (funcall extrinsic :disputes))
         
         ;; Step 2: Encode each component (§5.5)
         (encoded-tickets (encode-tickets tickets))       ; ET(ET)
         (encoded-preimages (encode-preimages preimages)) ; EP(EP)
         (encoded-guarantees (encode-guarantees-with-merkle guarantees)) ; g (§5.6)
         (encoded-assurances (encode-assurances assurances)) ; EA(EA)
         (encoded-disputes (encode-disputes disputes))    ; ED(ED)
         
         ;; Step 3: Build array a
         (a (vector encoded-tickets
                    encoded-preimages
                    encoded-guarantees
                    encoded-assurances
                    encoded-disputes)))
    
    ;; Step 4: Compute Merkle root HEH#(a)
    (merkle-root a)))

(defun encode-guarantees-with-merkle (guarantees)
  "Encodes guarantees with Merkle proof structure
   
   Gray Paper §5.6:
   g = E(↕[(H(r), E4(t), ↕a) | (r,t,a) ← EG])
   
   Each guarantee/report is encoded as a triple:
     (H(r), E4(t), ↕a)
   
   Where:
     H(r)  = Blake2b hash of report r
     E4(t) = 4-byte little-endian encoding of type t
     ↕a    = Sequence of authorization data"
  
  ;; TODO: Implement SCALE encoding
  ;; For each guarantee (r, t, a):
  ;;   1. Hash report: H(r)
  ;;   2. Encode type as u32: E4(t)
  ;;   3. Encode auth data: ↕a
  ;;   4. Combine into triple
  ;; Then encode the sequence of triples
  
  ;; Placeholder
  (make-array 0 :element-type '(unsigned-byte 8)))

;;; Encoding stubs (to be implemented with SCALE codec)

(defun encode-tickets (tickets)
  "ET(ET) - SCALE encoding of tickets"
  (make-array 0 :element-type '(unsigned-byte 8)))

(defun encode-preimages (preimages)
  "EP(EP) - SCALE encoding of preimages"
  (make-array 0 :element-type '(unsigned-byte 8)))

(defun encode-assurances (assurances)
  "EA(EA) - SCALE encoding of assurances"
  (make-array 0 :element-type '(unsigned-byte 8)))

(defun encode-disputes (disputes)
  "ED(ED) - SCALE encoding of disputes"
  (make-array 0 :element-type '(unsigned-byte 8)))

;;; Merkle tree (stub - to be implemented properly)

(defun merkle-root (leaves)
  "HEH# - Computes binary Merkle tree root
   
   Binary Merkle tree with Blake2b hashing
   
   TODO: Implement proper binary Merkle tree"
  
  ;; Placeholder: return dummy hash
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

;;; ═══════════════════════════════════════════════════════════════
;;; EXAMPLES
;;; ═══════════════════════════════════════════════════════════════

#|
Usage:

;; Genesis header
(let ((genesis (make-header :parent-hash nil
                            :state-root (initial-state-root)
                            :slot 0
                            ...)))
  (header-is-genesis-p genesis))  ; => T

;; Regular header
(let ((header (make-header :parent-hash parent-hash
                           :state-root new-state-root
                           :slot 10
                           ...)))
  (header-slot header)            ; => 10
  (header-parent-hash header))    ; => parent-hash

Code is Law - Pure FP Headers ! 🚀
|#
