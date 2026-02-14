;;;; state/delta.lisp — δ Service Accounts (GP §9)
;;;;
;;;; δ[s] = service account for service index s.
;;;; Service accounts use Merkle key C(255, s), NOT a fixed segment C(n).
;;;; They live in sigma's extra-kvs, not in a segment field.
;;;;
;;;; §9.1 ServiceInfo binary layout (89 bytes):
;;;;   version:                U8   (1)
;;;;   code_hash:              H    (32)
;;;;   balance:                U64  (8)   = a_b
;;;;   min_item_gas:           U64  (8)   = a_g  (min gas per accumulate)
;;;;   min_memo_gas:           U64  (8)   = a_m  (min gas per deferred-transfer)
;;;;   bytes:                  U64  (8)   = a_o  (total storage octets, derived)
;;;;   deposit_offset:         U64  (8)   = a_f  (balance offset for threshold)
;;;;   items:                  U32  (4)   = a_i  (storage items, derived)
;;;;   creation_slot:          U32  (4)
;;;;   last_accumulation_slot: U32  (4)
;;;;   parent_service:         U32  (4)
;;;;                                -- 89 bytes total
;;;;
;;;; GP §9.3 eq (9.8): threshold is DERIVED, not stored:
;;;;   a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f)
;;;;   B_S=100, B_I=10, B_L=1
;;;;
;;;; Trie key formats:
;;;;   C(255, s) = [255, E4(s)_0..3, 0...0]   -> ServiceInfo (89 bytes)
;;;;   Sub-items = interleaved [s[0],h[0],s[1],h[1],s[2],h[2],s[3],h[3],h[4..26]]
;;;;     where s = E4(service_id), h = hash of sub-key
;;;;
;;;; Messages:
;;;;   :accounts       → list of (:id sid :service plist)
;;;;   :account (sid)  → service plist for specific service, or NIL
;;;;   :extra-kvs      → the underlying key-value pairs for Merkle
;;;;   :save           → nil (delta doesn't encode to a single segment)
;;;;   :transition     → GP (4.18): delta' ◁ (EP, delta-dagger, tau')

(in-package #:jotl)

;;; =====================================================================
;;; SERVICE INFO CODEC -- 89-byte fixed-size binary <-> plist
;;; =====================================================================

(defconstant +service-info-size+ 89
  "Fixed binary size of ServiceInfo: 1 + 32 + 5*8 + 4*4 = 89 bytes.")

(defun load-service-info (bytes &optional (offset 0))
  "Decode a 89-byte ServiceInfo from BYTES at OFFSET.
   Returns (values plist bytes-consumed).
   Plist keys match the jam-types.asn field names."
  (let ((pos offset))
    (flet ((read-u8 ()
             (prog1 (aref bytes pos) (incf pos 1)))
           (read-hash ()
             (prog1 (subseq bytes pos (+ pos 32)) (incf pos 32)))
           (read-u64 ()
             (prog1 (decode-fixed-le (subseq bytes pos (+ pos 8)))
               (incf pos 8)))
           (read-u32 ()
             (prog1 (decode-fixed-le (subseq bytes pos (+ pos 4)))
               (incf pos 4))))
      (let* ((version (read-u8))
             (code-hash (read-hash))
             (balance (read-u64))
             (min-accum-gas (read-u64))
             (min-memo-gas (read-u64))
             (total-bytes (read-u64))
             (deposit-offset (read-u64))
             (items (read-u32))
             (creation-slot (read-u32))
             (last-accum-slot (read-u32))
             (parent-service (read-u32)))
        (values
         (list :version version
               :code-hash code-hash
               :balance balance
               :min-accum-gas min-accum-gas
               :min-memo-gas min-memo-gas
               :bytes total-bytes
               :deposit-offset deposit-offset
               :items items
               :creation-slot creation-slot
               :last-accumulation-slot last-accum-slot
               :parent-service parent-service)
         (- pos offset))))))

(defun encode-service-info (info)
  "Encode a ServiceInfo plist to 89-byte binary.
   INFO is a plist with keys matching load-service-info output."
  (let ((buf (make-array +service-info-size+
                         :element-type '(unsigned-byte 8)
                         :initial-element 0))
        (pos 0))
    (flet ((write-u8 (v)
             (setf (aref buf pos) (logand v #xFF))
             (incf pos 1))
           (write-hash (h)
             (let ((h (ensure-bytes h)))
               (replace buf h :start1 pos :end1 (+ pos 32))
               (incf pos 32)))
           (write-u64 (v)
             (let ((enc (E8 v)))
               (replace buf enc :start1 pos :end1 (+ pos 8))
               (incf pos 8)))
           (write-u32 (v)
             (let ((enc (E4 v)))
               (replace buf enc :start1 pos :end1 (+ pos 4))
               (incf pos 4))))
      (write-u8  (or (getf info :version) 0))
      (write-hash (getf info :code-hash))
      (write-u64 (getf info :balance))
      (write-u64 (getf info :min-accum-gas))
      (write-u64 (getf info :min-memo-gas))
      (write-u64 (getf info :bytes))
      (write-u64 (getf info :deposit-offset))
      (write-u32 (getf info :items))
      (write-u32 (getf info :creation-slot))
      (write-u32 (getf info :last-accumulation-slot))
      (write-u32 (getf info :parent-service)))
    buf))

;;; =====================================================================
;;; TRIE KEY CONSTRUCTION -- GP Appendix D
;;; =====================================================================

(defun interleave-sub-key (service-id h-27)
  "Build a 31-byte interleaved trie key from service-id and 27-byte hash.
   GP D.1: C(s, a) = [s0,a0,s1,a1,s2,a2,s3,a3,a4,...,a26]
   where s = E4(service-id)."
  (let ((s (E4 service-id))
        (k (make-array 31 :element-type '(unsigned-byte 8))))
    ;; First 8 bytes: interleaved s[0..3] and h[0..3]
    (setf (aref k 0) (aref s 0)
          (aref k 1) (aref h-27 0)
          (aref k 2) (aref s 1)
          (aref k 3) (aref h-27 1)
          (aref k 4) (aref s 2)
          (aref k 5) (aref h-27 2)
          (aref k 6) (aref s 3)
          (aref k 7) (aref h-27 3))
    ;; Remaining 23 bytes: h[4..26]
    (loop for i from 4 below 27 do (setf (aref k (+ i 4)) (aref h-27 i)))
    k))

(defun storage-trie-h (key-bytes)
  "Compute the 27-byte trie sub-key hash for a storage entry.
   GP D.1: H(E4(2^32-1) . key)[0:27]"
  (subseq (jam.ffi:blake2b-256
           (concatenate '(vector (unsigned-byte 8))
                        (E4 (- (ash 1 32) 1))  ;; 0xFFFFFFFF
                        (ensure-bytes key-bytes)))
          0 27))

(defun encode-lookup-value (statuses)
  "Encode lookup entry value: compact(n) . n*E4(s).
   STATUSES: list of u32 timeslots."
  (let ((buf (make-array 32 :element-type '(unsigned-byte 8)
                         :fill-pointer 0 :adjustable t)))
    (let ((enc (encode-compact (length statuses))))
      (loop for b across enc do (vector-push-extend b buf)))
    (dolist (s statuses)
      (let ((e (E4 s)))
        (loop for b across e do (vector-push-extend b buf))))
    (let ((result (make-array (fill-pointer buf) :element-type '(unsigned-byte 8))))
      (replace result buf)
      result)))

;;; =====================================================================
;;; TRIE KEY CLASSIFICATION
;;; =====================================================================

(defun service-metadata-key-p (key-31)
  "Is KEY-31 a service metadata key C(255, s)?
   Format: [255, E4(s)_0..3, 0...0] -- first byte 255, bytes 5-30 all zero."
  (and (= (aref key-31 0) 255)
       (loop for i from 5 below (length key-31) always (zerop (aref key-31 i)))))

(defun service-id-from-metadata-key (key-31)
  "Extract service ID from C(255, s) metadata key.
   s = u32_le(key[1], key[2], key[3], key[4])."
  (logior (aref key-31 1)
          (ash (aref key-31 2) 8)
          (ash (aref key-31 3) 16)
          (ash (aref key-31 4) 24)))

(defun service-id-from-sub-key (key-31)
  "Extract service ID from interleaved sub-key.
   s = u32_le(key[0], key[2], key[4], key[6])."
  (logior (aref key-31 0)
          (ash (aref key-31 2) 8)
          (ash (aref key-31 4) 16)
          (ash (aref key-31 6) 24)))

;;; =====================================================================
;;; SUB-KEY CLASSIFICATION -- GP Appendix D.1
;;; =====================================================================
;;;
;;; Trie sub-key discriminants (verified empirically against test vectors):
;;;   Preimage blob: a = H(E4(2^32-2) . H(val))[0:27]
;;;   Lookup:        a = H(E4(length) . hash)[0:27]
;;;   Storage:       a = H(E4(2^32-1) . key)[0:27]
;;;
;;; Classification algorithm:
;;;   1. For each sub-key (h, val): compute H(val), check preimage formula
;;;   2. For each confirmed preimage: check lookup formula against remaining keys
;;;   3. Everything else -> storage (with trie-hash as pseudo-key)

(defun extract-sub-key-h (trie-key)
  "Extract 27-byte hash from interleaved sub-key.
   Format: [s0,h0,s1,h1,s2,h2,s3,h3,h4..h26]
   Returns: 27-byte vector."
  (let ((h (make-array 27 :element-type '(unsigned-byte 8))))
    (setf (aref h 0) (aref trie-key 1)
          (aref h 1) (aref trie-key 3)
          (aref h 2) (aref trie-key 5)
          (aref h 3) (aref trie-key 7))
    (loop for i from 4 below 27 do (setf (aref h i) (aref trie-key (+ i 4))))
    h))

(defun preimage-trie-h (blob-hash)
  "Compute the 27-byte trie sub-key hash for a preimage blob.
   GP D.1: H(E4(0xFFFFFFFE) . blob_hash)[0:27]"
  (subseq (jam.ffi:blake2b-256
           (concatenate '(vector (unsigned-byte 8))
                        (E4 (- (ash 1 32) 2))  ;; 0xFFFFFFFE
                        (ensure-bytes blob-hash)))
          0 27))

(defun lookup-trie-h (preimage-hash preimage-length)
  "Compute the 27-byte trie sub-key hash for a lookup entry.
   GP D.1: H(E4(length) . hash)[0:27]"
  (subseq (jam.ffi:blake2b-256
           (concatenate '(vector (unsigned-byte 8))
                        (E4 preimage-length)
                        (ensure-bytes preimage-hash)))
          0 27))

(defun load-lookup-value (val-bytes)
  "Decode a lookup entry value: compact(n) . n*u32_LE -> list of timeslot u32s."
  (when (and val-bytes (plusp (length val-bytes)))
    (multiple-value-bind (count consumed) (decode-compact val-bytes 0)
      (loop for i below count
            for off = consumed then (+ off 4)
            collect (decode-fixed-le (subseq val-bytes off (+ off 4)))))))

(defun classify-service-sub-keys (service-id extra-kvs)
  "Parse all sub-keys for SERVICE-ID from EXTRA-KVS into categories.
   Uses GP D.1 discriminant formulas to classify each entry.

   Returns plist:
     :metadata   -- ServiceInfo plist (from C(255,s) key)
     :code-blob  -- code blob bytes (the preimage matching code-hash), or nil
     :preimages  -- alist of (hash-32 . blob-bytes) for PVM
     :lookup     -- list of (hash-32 length . (timeslot-u32 ...)) for PVM
     :storage    -- alist of (hash-27 . val-bytes) -- pseudo-keyed storage"
  (let ((metadata nil)
        (sub-entries nil)   ;; (h-27 . val-bytes)
        (code-hash nil))
    ;; -- Pass 0: Collect metadata + sub-keys for this service --
    (dolist (kv extra-kvs)
      (let ((key (car kv)) (val (cdr kv)))
        (cond
          ;; Metadata key C(255, s)
          ((and (service-metadata-key-p key)
                (= (service-id-from-metadata-key key) service-id))
           (setf metadata (load-service-info val))
           (setf code-hash (getf metadata :code-hash)))
          ;; Sub-key for this service (interleaved)
          ((and (not (service-metadata-key-p key))
                (not (segment-key-p key))
                (= (service-id-from-sub-key key) service-id))
           (push (cons (extract-sub-key-h key) val) sub-entries)))))
    (setf sub-entries (nreverse sub-entries))

    ;; -- Pass 1: Identify preimage blobs --
    ;; For each entry, check: H(E4(0xFFFFFFFE) . H(val))[0:27] == h?
    (let ((preimages nil)   ;; (hash-32 . blob-bytes)
          (remaining nil)   ;; entries not yet classified
          (code-blob nil))
      (dolist (entry sub-entries)
        (let* ((h (car entry))
               (val (cdr entry))
               (val-hash (jam.ffi:blake2b-256 val))
               (expected-h (preimage-trie-h val-hash)))
          (if (equalp h expected-h)
              ;; It's a preimage blob
              (progn
                (push (cons val-hash val) preimages)
                ;; Check if this is the code blob
                (when (and code-hash (equalp val-hash code-hash))
                  (setf code-blob val)))
              (push entry remaining))))
      (setf preimages (nreverse preimages))
      (setf remaining (nreverse remaining))

      ;; -- Pass 2: Identify lookup entries --
      ;; For each remaining entry, try matching against known preimage hashes
      (let ((lookup nil)
            (storage nil))
        (dolist (entry remaining)
          (let* ((h (car entry))
                 (val (cdr entry))
                 (found-lookup nil))
            ;; Try each known preimage (hash, blob-length)
            (dolist (pre preimages)
              (let* ((pre-hash (car pre))
                     (pre-len (length (cdr pre)))
                     (expected-h (lookup-trie-h pre-hash pre-len)))
                (when (equalp h expected-h)
                  (let ((statuses (load-lookup-value val)))
                    (push (list* pre-hash pre-len statuses) lookup))
                  (setf found-lookup t)
                  (return))))
            (unless found-lookup
              ;; Unclassified -> storage (pseudo-keyed by trie hash)
              (push entry storage))))
        (setf lookup (nreverse lookup))
        (setf storage (nreverse storage))

        (list :metadata  metadata
              :code-blob code-blob
              :preimages preimages
              :lookup    lookup
              :storage   storage)))))

;;; =====================================================================
;;; PARSE SERVICE ACCOUNTS FROM EXTRA-KVS
;;; =====================================================================

(defun parse-service-accounts (extra-kvs)
  "Parse service accounts from sigma's extra-kvs.
   Returns list of (:id sid :service plist) sorted by service ID.
   Only C(255,s) metadata keys are decoded; sub-keys (storage, preimages)
   are not decoded here."
  (let ((accounts nil))
    (dolist (kv extra-kvs)
      (let ((key (car kv))
            (val (cdr kv)))
        (when (service-metadata-key-p key)
          (let ((sid (service-id-from-metadata-key key))
                (info (load-service-info val)))
            (push (list :id sid :service info) accounts)))))
    ;; Sort by service ID for deterministic ordering
    (sort accounts #'< :key (lambda (a) (getf a :id)))))

;;; =====================================================================
;;; PREIMAGE INTEGRATION -- GP S9.2 / S4.18
;;; =====================================================================

(defun make-metadata-key (service-id)
  "Build the C(255, s) metadata trie key for SERVICE-ID.
   Format: [255, E4(s)_0..3, 0...0] -- 31 bytes."
  (let ((k (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0))
        (s (E4 service-id)))
    (setf (aref k 0) 255)
    (replace k s :start1 1 :end1 5)
    k))

(defun bytes< (a b)
  "Lexicographic less-than for byte vectors."
  (let ((la (length a)) (lb (length b)))
    (loop for i below (min la lb) do
      (cond ((< (aref a i) (aref b i)) (return t))
            ((> (aref a i) (aref b i)) (return nil)))
      finally (return (< la lb)))))

(defun integrate-preimages (raw-kvs preimages timeslot)
  "GP S9.2 / S4.18 -- Integrate EP preimages into delta's raw key-value pairs.
   For each (s, d) in EP:
     h = H(d), l = |d|
     1. Validate: service s exists, lookup (h,l) exists with even-length status
     2. Store preimage blob: C(s, preimage-trie-h(h)) -> d
     3. Update lookup:       C(s, lookup-trie-h(h,l)) -> [...statuses, tau']
   Note: ordering of EP is checked during block validation, not here.
   Returns: new raw-kvs list."
  ;; -- Annotate: compute hashes --
  (let ((annotated
         (mapcar (lambda (p)
                   (let* ((sid  (getf p :requester))
                          (blob (ensure-bytes (getf p :blob)))
                          (hash (jam.ffi:blake2b-256 blob)))
                     (list :sid sid :hash hash :blob blob)))
                 preimages)))

    ;; -- Validate necessity + Integrate --
    (let ((new-kvs (copy-list raw-kvs)))
      (flet ((find-kv (target-key)
               (find target-key new-kvs :key #'car :test #'equalp))
             (replace-kv-val (target-key new-val)
               (let ((pair (find target-key new-kvs :key #'car :test #'equalp)))
                 (when pair (setf (cdr pair) new-val)))))

        (dolist (a annotated)
          (let* ((sid  (getf a :sid))
                 (hash (getf a :hash))
                 (blob (getf a :blob))
                 (len  (length blob))
                 (lookup-key (interleave-sub-key sid (lookup-trie-h hash len)))
                 (blob-key   (interleave-sub-key sid (preimage-trie-h hash))))

            ;; GP §9.2: skip if service doesn't exist
            (when (find-kv (make-metadata-key sid))
              ;; Check lookup entry exists with even-length status (solicited)
              (let ((lookup-entry (find-kv lookup-key)))
                (when (and lookup-entry
                           (let ((statuses (load-lookup-value (cdr lookup-entry))))
                             (evenp (length statuses))))
                  (let ((statuses (load-lookup-value (cdr lookup-entry))))
                    ;; Store preimage blob
                    (push (cons blob-key (ensure-bytes blob)) new-kvs)
                    ;; Update lookup: append tau' to status list
                    (replace-kv-val lookup-key
                                    (encode-lookup-value (append statuses (list timeslot)))))))))))
      new-kvs)))

;;; =====================================================================
;;; STATE CLOSURE
;;; =====================================================================

(define-state-closure delta-state
  ((raw-kvs nil)
   (accounts-cache nil))

  ;; delta doesn't encode to a single segment byte vector.
  (:save nil)

  ;; Access the underlying Merkle key-value pairs.
  (:extra-kvs raw-kvs)

  ;; Decoded accounts list -- lazy parse from raw-kvs.
  (:accounts
   (or accounts-cache
       (setf accounts-cache (parse-service-accounts raw-kvs))))

  ;; Single account lookup by service ID.
  (:account (sid)
   (let ((accts (self :accounts)))
     (find sid accts :key (lambda (a) (getf a :id)))))

  (:decode (bytes offset)
    ;; delta is not decoded from segment bytes -- this is a fallback.
    ;; Real loading happens via load-delta-from-extra-kvs.
    (values (make-delta-state :raw-kvs nil) (- (length bytes) offset)))

  ;; -- Transition: delta' < (EP, delta-dagger, tau') -- GP S4.18 + S9.2
  (:transition (&key preimages tau-prime)
    (let ((timeslot (when tau-prime (funcall tau-prime :slot))))
      (if (or (null preimages) (zerop (length preimages)) (not timeslot))
          (make-delta-state :raw-kvs raw-kvs)
          (make-delta-state
           :raw-kvs (integrate-preimages raw-kvs preimages timeslot))))))

(defun load-delta-from-extra-kvs (extra-kvs)
  "Build delta from sigma's extra-kvs (C(255,s) entries + sub-keys).
   Returns: delta-state closure."
  (make-delta-state :raw-kvs extra-kvs))
