;;;; state/delta.lisp — δ Service Accounts (GP §9)
;;;;
;;;; δ[s] = service account for service index s.
;;;; Service accounts use Merkle key C(255, s), NOT a fixed segment C(n).
;;;; They live in sigma's delta-kvs (multi-key Merkle entries).
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
;;;;   :save           → raw-kvs (multi-key Merkle pairs for σ)
;;;;   :all-service-ids          → list of all service IDs in delta
;;;;   :service-data (sid)       → classified sub-keys for a service (GP D.1)
;;;;   :cross-service-accounts (caller-id) → cross-service alist for ΩJ
;;;;   :transition-dagger (&key delta-results timeslot) → δ† with PVM effects applied
;;;;   :transition     → GP (4.18): delta' ◁ (EP, delta-dagger, tau')

(in-package #:jotl)

;;; =====================================================================
;;; ERROR CONDITION
;;; =====================================================================

(define-condition preimages-error (error)
  ((code   :initarg :code   :reader preimages-error-code)
   (detail :initarg :detail :reader preimages-error-detail :initform nil))
  (:report (lambda (c s)
             (format s "preimages error: ~A~@[ -- ~A~]"
                     (preimages-error-code c) (preimages-error-detail c)))))

;;; =====================================================================
;;; SERVICE INFO CODEC -- 89-byte fixed-size binary <-> plist
;;; =====================================================================

(defconstant +service-info-size+ 89
  "Fixed binary size of ServiceInfo: 1 + 32 + 5*8 + 4*4 = 89 bytes.")

(defun load-service-info (bytes &optional (offset 0))
  "Decode a 89-byte ServiceInfo from BYTES at OFFSET.
   Returns (values plist bytes-consumed).
   Plist keys match the jam-types.asn field names.
   Optimized: reads directly from buffer without subseq allocations."
  (declare (optimize (speed 3) (safety 1)))
  (let ((pos offset))
    (flet ((read-u8 ()
             (prog1 (aref bytes pos) (incf pos 1)))
           (read-hash ()
             (let ((h (make-array 32 :element-type '(unsigned-byte 8))))
               (replace h bytes :start2 pos :end2 (+ pos 32))
               (incf pos 32)
               h))
           (read-u64 ()
             (prog1 (logior (aref bytes pos)
                            (ash (aref bytes (+ pos 1)) 8)
                            (ash (aref bytes (+ pos 2)) 16)
                            (ash (aref bytes (+ pos 3)) 24)
                            (ash (aref bytes (+ pos 4)) 32)
                            (ash (aref bytes (+ pos 5)) 40)
                            (ash (aref bytes (+ pos 6)) 48)
                            (ash (aref bytes (+ pos 7)) 56))
               (incf pos 8)))
           (read-u32 ()
             (prog1 (logior (aref bytes pos)
                            (ash (aref bytes (+ pos 1)) 8)
                            (ash (aref bytes (+ pos 2)) 16)
                            (ash (aref bytes (+ pos 3)) 24))
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

(declaim (inline service-id-from-sub-key service-id-from-metadata-key extract-sub-key-h))

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
   GP D.1: H(E4(2^32-1) . key)[0:27]
   Optimized: pre-allocates buffer instead of concatenate."
  (declare (optimize (speed 3) (safety 1)))
  (let* ((kb (ensure-bytes key-bytes))
         (buf (make-array (+ 4 (length kb)) :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) #xFF (aref buf 1) #xFF
          (aref buf 2) #xFF (aref buf 3) #xFF)
    (replace buf kb :start1 4)
    (subseq (jam.ffi:blake2b-256 buf) 0 27)))

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

(defun make-service-metadata-key (service-id)
  "Create a 31-byte metadata trie key C(255, s) for SERVICE-ID.
   Format: interleave(255, [E4(s), 0..0]) — GP Appendix D."
  (let ((h (make-array 27 :element-type '(unsigned-byte 8) :initial-element 0))
        (e4-sid (E4 service-id)))
    (setf (aref h 0) (aref e4-sid 0)
          (aref h 1) (aref e4-sid 1)
          (aref h 2) (aref e4-sid 2)
          (aref h 3) (aref e4-sid 3))
    (interleave-sub-key 255 h)))

(defun service-metadata-key-p (key-31)
  "Is KEY-31 a service metadata key C(255, s)?
   Interleaved format: interleave(255, [E4(s), 0..0]).
   The SID at positions [0,2,4,6] must encode 255 (LE: 0xFF,0x00,0x00,0x00),
   and hash bytes h[4..26] must be zero (positions 8..30 in interleaved key).
   Optimized: direct byte checks without extract-sub-key-h allocation."
  (declare (optimize (speed 3) (safety 1)))
  ;; 255 in LE u32 = [0xFF, 0x00, 0x00, 0x00]
  ;; Interleaved positions: key[0]=s0, key[2]=s1, key[4]=s2, key[6]=s3
  (and (= (aref key-31 0) #xFF)
       (zerop (aref key-31 2))
       (zerop (aref key-31 4))
       (zerop (aref key-31 6))
       ;; Hash bytes h[4..26] must be zero → positions 8..30 in interleaved key
       (loop for i fixnum from 8 below 31 always (zerop (aref key-31 i)))))

(defun service-id-from-metadata-key (key-31)
  "Extract service ID from C(255, s) metadata key.
   The actual SID is in the first 4 bytes of the hash part (sub-key h)."
  (let ((h (extract-sub-key-h key-31)))
    (logior (aref h 0)
            (ash (aref h 1) 8)
            (ash (aref h 2) 16)
            (ash (aref h 3) 24))))

(defun service-id-from-sub-key (key-31)
  "Extract service ID from interleaved sub-key.
   s = u32_le(key[0], key[2], key[4], key[6])."
  (declare (optimize (speed 3) (safety 1)))
  (the (unsigned-byte 32)
       (logior (aref key-31 0)
               (ash (aref key-31 2) 8)
               (ash (aref key-31 4) 16)
               (ash (aref key-31 6) 24))))

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
   GP D.1: H(E4(0xFFFFFFFE) . blob_hash)[0:27]
   Optimized: pre-allocates buffer instead of concatenate."
  (declare (optimize (speed 3) (safety 1)))
  (let* ((bh (ensure-bytes blob-hash))
         (buf (make-array (+ 4 (length bh)) :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) #xFE (aref buf 1) #xFF
          (aref buf 2) #xFF (aref buf 3) #xFF)
    (replace buf bh :start1 4)
    (subseq (jam.ffi:blake2b-256 buf) 0 27)))

(defun lookup-trie-h (preimage-hash preimage-length)
  "Compute the 27-byte trie sub-key hash for a lookup entry.
   GP D.1: H(E4(length) . hash)[0:27]
   Optimized: pre-allocates buffer instead of concatenate."
  (declare (optimize (speed 3) (safety 1)))
  (let* ((ph (ensure-bytes preimage-hash))
         (buf (make-array (+ 4 (length ph)) :element-type '(unsigned-byte 8))))
    ;; E4(preimage-length) inline
    (setf (aref buf 0) (logand preimage-length #xFF)
          (aref buf 1) (logand (ash preimage-length -8) #xFF)
          (aref buf 2) (logand (ash preimage-length -16) #xFF)
          (aref buf 3) (logand (ash preimage-length -24) #xFF))
    (replace buf ph :start1 4)
    (subseq (jam.ffi:blake2b-256 buf) 0 27)))

(defun load-lookup-value (val-bytes)
  "Decode a lookup entry value: compact(n) . n*u32_LE -> list of timeslot u32s.
   Optimized: direct byte access without subseq allocation."
  (when (and val-bytes (plusp (length val-bytes)))
    (multiple-value-bind (count consumed) (decode-compact val-bytes 0)
      (loop for i below count
            for off fixnum = consumed then (+ off 4)
            collect (logior (aref val-bytes off)
                            (ash (aref val-bytes (+ off 1)) 8)
                            (ash (aref val-bytes (+ off 2)) 16)
                            (ash (aref val-bytes (+ off 3)) 24))))))

(defun valid-lookup-value-p (val)
  "Check if VAL could be a valid lookup entry encoding: compact(n) . n*E4(t).
   Used to identify candidate orphaned lookup entries in the trie."
  (when (and val (plusp (length val)))
    (handler-case
        (multiple-value-bind (count consumed) (decode-compact val 0)
          (and (<= count 3)  ;; lookups have at most 3 timeslots per GP
               (= (length val) (+ consumed (* 4 count)))))
      (error () nil))))

;;; =====================================================================
;;; SID INDEX — O(1) lookup by service-id instead of O(N) scans
;;; =====================================================================

(defun build-sid-index (delta-kvs)
  "Build hash-table mapping service-id → (metadata-kv sub-kvs-list).
   One pass over delta-kvs; segment keys C(1..16) are excluded.
   METADATA-KV is the single (key . val) cons for C(255,s), or NIL.
   SUB-KVS is the list of non-metadata (key . val) entries for that SID."
  (declare (optimize (speed 3) (safety 1)))
  (let ((index (make-hash-table :test 'eql)))
    (dolist (kv delta-kvs)
      (let ((key (car kv)))
        (unless (segment-key-p key)
          (if (service-metadata-key-p key)
              ;; Metadata entry — store in car of (metadata . sub-kvs) pair
              (let* ((sid (service-id-from-metadata-key key))
                     (entry (gethash sid index)))
                (if entry
                    (setf (car entry) kv)
                    (setf (gethash sid index) (cons kv nil))))
              ;; Sub-key entry — push to cdr of pair
              (let* ((sid (service-id-from-sub-key key))
                     (entry (gethash sid index)))
                (if entry
                    (push kv (cdr entry))
                    (setf (gethash sid index) (cons nil (list kv)))))))))
    ;; Reverse sub-kvs lists to maintain insertion order
    (maphash (lambda (k v)
               (declare (ignore k))
               (setf (cdr v) (nreverse (cdr v))))
             index)
    index))

(defun classify-service-sub-keys (service-id delta-kvs &optional sid-index)
  "Parse all sub-keys for SERVICE-ID from DELTA-KVS into categories.
   Uses GP D.1 discriminant formulas to classify each entry.
   When SID-INDEX is provided, uses O(1) lookup instead of O(N) scan.

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
    (if sid-index
        ;; Fast path: use pre-built index
        (let ((indexed (gethash service-id sid-index)))
          (when indexed
            (let ((meta-kv (car indexed)))
              (when meta-kv
                (setf metadata (load-service-info (cdr meta-kv)))
                (setf code-hash (getf metadata :code-hash))))
            (dolist (kv (cdr indexed))
              (push (cons (extract-sub-key-h (car kv)) (cdr kv)) sub-entries))
            (setf sub-entries (nreverse sub-entries))))
        ;; Slow path: scan all delta-kvs (fallback)
        (progn
          (dolist (kv delta-kvs)
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
          (setf sub-entries (nreverse sub-entries))))

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
      ;; Pre-build hash-table: expected-h → (pre-hash . pre-len) for O(1) matching
      (let ((lookup nil)
            (storage nil)
            (lookup-map (make-hash-table :test 'equalp :size (length preimages))))
        ;; Build lookup map: O(|preimages|) blake2b calls
        (dolist (pre preimages)
          (let* ((pre-hash (car pre))
                 (pre-len (length (cdr pre)))
                 (expected-h (lookup-trie-h pre-hash pre-len)))
            (setf (gethash expected-h lookup-map) (cons pre-hash pre-len))))
        ;; Classify remaining entries: O(|remaining|) with O(1) hash-table lookups
        (let ((candidate-orphans nil))
          (dolist (entry remaining)
            (let* ((h (car entry))
                   (val (cdr entry))
                   (match (gethash h lookup-map)))
              (if match
                  (let ((statuses (load-lookup-value val)))
                    (push (list* (car match) (cdr match) statuses) lookup))
                  (if (valid-lookup-value-p val)
                      (push entry candidate-orphans)
                      (push entry storage)))))
          (setf lookup (nreverse lookup))
          (setf storage (nreverse storage))
          (setf candidate-orphans (nreverse candidate-orphans))

          (list :metadata  metadata
                :code-blob code-blob
                :preimages preimages
                :lookup    lookup
                :storage   storage
                :candidate-orphans candidate-orphans))))))

;;; =====================================================================
;;; PARSE SERVICE ACCOUNTS FROM EXTRA-KVS
;;; =====================================================================

(defun parse-service-accounts (delta-kvs)
  "Parse service accounts from delta's raw-kvs.
   Returns list of (:id sid :service plist) sorted by service ID.
   Only C(255,s) metadata keys are decoded; sub-keys (storage, preimages)
   are not decoded here."
  (let ((accounts nil))
    (dolist (kv delta-kvs)
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
   Format: interleave(255, [E4(s), 0..0]) -- 31 bytes."
  (let ((a (make-array 27 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace a (E4 service-id) :start1 0 :end1 4)
    (interleave-sub-key 255 a)))

;; bytes< is defined in lib/types.lisp

(defun validate-ep-ordering (preimages)
  "GP §12.36 -- EP = [i ∈ EP __ i]
   EP must be sorted ascending by (service-index, blob-data) with no duplicates.
   Signals preimages-error if violated."
  (loop for (p1 p2) on preimages while p2 do
    (let ((s1 (getf p1 :requester))
          (s2 (getf p2 :requester))
          (b1 (ensure-bytes (getf p1 :blob)))
          (b2 (ensure-bytes (getf p2 :blob))))
      (cond ((< s1 s2)) ;; OK: ascending by service index
            ((> s1 s2)
             (error 'preimages-error
                    :code :ep-not-sorted
                    :detail (format nil "EP not sorted: sid ~D before ~D" s1 s2)))
            ;; Same service index — check blob ordering
            ((bytes< b1 b2)) ;; OK: ascending by blob
            ((equalp b1 b2)
             (error 'preimages-error
                    :code :ep-duplicate
                    :detail (format nil "EP duplicate entry for service ~D" s1)))
            (t
             (error 'preimages-error
                    :code :ep-not-sorted
                    :detail (format nil "EP not sorted by blob for service ~D" s1)))))))

(defun integrate-preimages (raw-kvs preimages timeslot)
  "GP S9.2 / S4.18 -- Integrate EP preimages into delta's raw key-value pairs.
   For each (s, d) in EP:
     h = H(d), l = |d|
     0. Validate: EP is sorted and without duplicates (GP §12.36)
     1. Validate: service s exists, lookup (h,l) exists with even-length status
     2. Store preimage blob: C(s, preimage-trie-h(h)) -> d
     3. Update lookup:       C(s, lookup-trie-h(h,l)) -> [...statuses, tau']
   Returns: new raw-kvs list.
   Optimized: COW pattern — only K modified entries get fresh cons cells (K << N).
   Unmodified entries share the original cons cells (fork-safe: no mutation)."
  ;; GP §12.36: EP must be sorted ascending by (s, d) with no duplicates
  (validate-ep-ordering preimages)
  ;; -- Annotate: compute hashes --
  (let ((annotated
         (mapcar (lambda (p)
                   (let* ((sid  (getf p :requester))
                          (blob (ensure-bytes (getf p :blob)))
                          (hash (jam.ffi:blake2b-256 blob)))
                     (list :sid sid :hash hash :blob blob)))
                 preimages)))

    ;; -- COW: index original (read-only), track patches + additions --
    ;; No copy-alist: builds kv-index from the ORIGINAL raw-kvs.
    ;; Patches record modified values; additions collect new entries.
    ;; Materializes at the end: O(K) fresh cons cells instead of O(N).
    (let ((kv-index (make-hash-table :test 'equalp :size (length raw-kvs)))
          (patches  (make-hash-table :test 'equalp))   ;; key → new-value
          (additions nil))                              ;; new (key . value) pairs
      ;; Index original entries (read-only reference)
      (dolist (kv raw-kvs)
        (setf (gethash (car kv) kv-index) kv))
      (flet ((find-kv-exists-p (target-key)
               ;; Does the key exist in original?
               (nth-value 1 (gethash target-key kv-index)))
             (find-kv-val (target-key)
               ;; Read patched value if available, else original
               (multiple-value-bind (val found) (gethash target-key patches)
                 (if found val
                     (let ((pair (gethash target-key kv-index)))
                       (when pair (cdr pair))))))
             (patch-kv-val (target-key new-val)
               (setf (gethash target-key patches) new-val)))

        (dolist (a annotated)
          (let* ((sid  (getf a :sid))
                 (hash (getf a :hash))
                 (blob (getf a :blob))
                 (len  (length blob))
                 (meta-key   (make-service-metadata-key sid))
                 (lookup-key (interleave-sub-key sid (lookup-trie-h hash len)))
                 (blob-key   (interleave-sub-key sid (preimage-trie-h hash))))

            ;; GP §9.2: preimage MUST be required — reject block otherwise.
            ;;   1. Service s must exist (has metadata key C(255,s))
            (unless (find-kv-exists-p meta-key)
              (error 'preimages-error
                     :code :preimage-not-required
                     :detail (format nil "service ~D does not exist" sid)))
            ;;   2. Lookup entry (h,l) must exist with even-length status list
            (unless (find-kv-exists-p lookup-key)
              (error 'preimages-error
                     :code :preimage-not-required
                     :detail (format nil "no lookup entry for preimage in service ~D" sid)))
            (let* ((lookup-val (find-kv-val lookup-key))
                   (statuses (load-lookup-value lookup-val)))
              (unless (null statuses)
                (error 'preimages-error
                       :code :preimage-not-required
                       :detail (format nil "preimage status not [] for service ~D" sid)))
              ;; Store preimage blob (addition — new entry)
              (push (cons blob-key (ensure-bytes blob)) additions)
              ;; Update lookup: append tau' to status list (patch — modify existing value)
              (patch-kv-val lookup-key
                            (encode-lookup-value (append statuses (list timeslot))))))))

      ;; -- Materialize: original entries (with patches) + additions --
      ;; Only patched entries get fresh cons cells; unmodified entries
      ;; share the original (key . value) cons cells (fork-safe).
      (let ((result additions))
        (dolist (kv raw-kvs)
          (multiple-value-bind (new-val found) (gethash (car kv) patches)
            (if found
                (push (cons (car kv) new-val) result)
                (push kv result))))
        result))))

;;; =====================================================================
;;; CROSS-SERVICE & SERVICE-ID EXTRACTION
;;; =====================================================================

(defun extract-all-service-ids (delta-kvs &optional sid-index)
  "Extract list of all service IDs present in delta-kvs.
   When SID-INDEX is provided, uses O(1) key iteration instead of O(N) scan."
  (if sid-index
      ;; Fast path: iterate index keys, filter to those with metadata
      (loop for sid being the hash-keys of sid-index
            using (hash-value entry)
            when (car entry)  ;; has metadata key
            collect sid)
      ;; Slow path: scan all delta-kvs
      (let ((ids (make-hash-table :test 'eql)))
        (dolist (kv delta-kvs)
          (when (service-metadata-key-p (car kv))
            (setf (gethash (service-id-from-metadata-key (car kv)) ids) t)))
        (loop for id being the hash-keys of ids collect id))))

(defun build-cross-service-accounts (caller-id delta-kvs &optional sid-index)
  "Build alist of (service-id . plist) for all services EXCEPT caller-id.
   Each plist contains :code-hash :balance :threshold :min-accum-gas :min-memo-gas
   :items-count :footprint :creation-slot :last-accum-slot :parent-service
   :storage :preimages :lookup.
   Storage is h27-keyed (trie-classified) — PVM hashes raw keys internally.
   When SID-INDEX is provided, uses O(1) lookup instead of O(S×N) scans."
  (let ((result nil)
        (idx (or sid-index (build-sid-index delta-kvs))))
    (dolist (sid (extract-all-service-ids delta-kvs idx))
      (unless (= sid caller-id)
        (let* ((svc-data (classify-service-sub-keys sid delta-kvs idx))
               (metadata (getf svc-data :metadata)))
          (when metadata
            (push (cons sid
                        (list :code-hash (or (getf metadata :code-hash)
                                             (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 0))
                              :balance (or (getf metadata :balance) 0)
                              :threshold (or (getf metadata :deposit-offset) 0)
                              :min-accum-gas (or (getf metadata :min-accum-gas) 0)
                              :min-memo-gas (or (getf metadata :min-memo-gas) 0)
                              :items-count (or (getf metadata :items) 0)
                              :footprint (or (getf metadata :bytes) 0)
                              :creation-slot (or (getf metadata :creation-slot) 0)
                              :last-accum-slot (or (getf metadata :last-accumulation-slot) 0)
                              :parent-service (or (getf metadata :parent-service) 0)
                              :storage (getf svc-data :storage)
                              :preimages (getf svc-data :preimages)
                              :lookup (getf svc-data :lookup)))
                  result)))))
    result))

;;; =====================================================================
;;; ABSORB-EFFECTS — apply PVM side-effects to raw-kvs (GP 12.30-12.31)
;;; =====================================================================

(defun make-h27-set (h27-list)
  "Build a hash-table set from a list of 27-byte vectors for O(1) membership.
   Returns NIL if the list is empty (fast check: no set needed)."
  (when h27-list
    (let ((ht (make-hash-table :test 'equalp :size (length h27-list))))
      (dolist (h h27-list) (setf (gethash h ht) t))
      ht)))

(defun remove-by-sid-and-scope (kvs sid scope-ht)
  "Remove entries from KVS that belong to SID and whose h27 is in SCOPE-HT.
   Optimized: uses hash-table O(1) membership instead of list O(n) member."
  (if (null scope-ht)
      kvs
      (remove-if (lambda (kv)
                   (let ((key (car kv)))
                     (and (not (service-metadata-key-p key))
                          (not (segment-key-p key))
                          (= (service-id-from-sub-key key) sid)
                          (gethash (extract-sub-key-h key) scope-ht))))
                 kvs)))

(defun absorb-delta-effects (raw-kvs delta-results timeslot)
  "Apply all PVM accumulation effects to raw key-value pairs.
   DELTA-RESULTS: hash-table of (sid → effects-plist)
   TIMESLOT: current timeslot for last-accumulation-slot updates
   Returns: new raw-kvs list.
   Optimized: copy-list + selective COW for metadata entries only.
   Non-metadata entries share original cons cells (fork-safe: never mutated).
   Only metadata cons cells (~S entries, S << N) get fresh copies for safe mutation."
  ;; copy-list copies the list spine (N backbone cons cells).
  ;; Then we walk the spine and replace ONLY metadata elements with fresh
  ;; cons cells. This saves (N - S) cons cell copies vs copy-alist.
  ;; (setf (car tail) ...) mutates OUR spine copy, not the original.
  ;; remove-if, push etc. create new list structure from the copied spine.
  (let ((current-kvs (copy-list raw-kvs))
        ;; Pre-build metadata index: sid → FRESH kv cons cell for safe mutation
        (meta-index (make-hash-table :test 'eql)))
    ;; One pass: replace metadata elements with fresh cons cells in our spine copy
    (do ((tail current-kvs (cdr tail)))
        ((null tail))
      (let ((kv (car tail)))
        (when (service-metadata-key-p (car kv))
          ;; Fresh cons cell for this metadata entry — safe to mutate via (setf (cdr ...))
          (let ((fresh-kv (cons (car kv) (cdr kv))))
            (setf (car tail) fresh-kv)
            (setf (gethash (service-id-from-metadata-key (car kv)) meta-index) fresh-kv)))))
    (maphash
     (lambda (sid effects)
       ;; Update metadata entry for this service.
       ;; If :no-code flag is set, only update balance (service never ran PVM).
       ;; Otherwise, also update last-accumulation-slot and PVM-final fields.
       (let ((meta-entry (gethash sid meta-index)))
         (when meta-entry
           (let ((info (load-service-info (cdr meta-entry))))
             ;; Update balance if provided (always, even no-code)
             (when (and effects (getf effects :balance))
               (setf (getf info :balance) (getf effects :balance)))
            ;; Skip last-accumulation-slot + PVM fields if no code ran
            (unless (getf effects :no-code)
              (setf (getf info :last-accumulation-slot) timeslot)
              ;; Update code_hash, min_accum_gas, min_memo_gas from PVM final state
              (when (and effects (getf effects :final-code-hash))
                (setf (getf info :code-hash) (getf effects :final-code-hash)))
              (when (and effects (getf effects :final-min-accum-gas))
                (setf (getf info :min-accum-gas) (getf effects :final-min-accum-gas)))
              (when (and effects (getf effects :final-min-memo-gas))
                (setf (getf info :min-memo-gas) (getf effects :final-min-memo-gas)))
              ;; Update items-count and footprint (bytes) — GP §9.1: a_i, a_o
              ;; These are tracked by the PVM during HC4 (write-storage) calls.
              ;; On panic/OOG without checkpoint: values are reverted to initial.
              ;; On halt: values reflect the final PVM storage state.
              (when (getf effects :items-count)
                (setf (getf info :items) (getf effects :items-count)))
              (when (getf effects :footprint)
                (setf (getf info :bytes) (getf effects :footprint))))
             (setf (cdr meta-entry) (encode-service-info info)))))

       ;; Apply side-effects if present (skip for :no-code services)
       (when (and effects (not (getf effects :no-code)))
         ;; ── Check PVM outcome for storage/lookup decisions ──
         (let* ((outcome (or (getf effects :outcome) 0))
                (update-storage-p
                 (not (and (member outcome '(1 2))
                           (null (getf effects :storage))
                           (null (getf effects :storage-deletes))
                           (null (getf effects :lookup))))))

           (when update-storage-p
             ;; ── MERGE storage: scope = overlay writes ∪ explicit deletes ──
             ;; Pure computation: no heuristic classification needed for storage.
             ;; Writes and deletes from the PVM overlay define the complete scope.
             (let* ((write-h27s (mapcar #'car (or (getf effects :storage) '())))
                    (delete-h27s (or (getf effects :storage-deletes) '()))
                    (scope-ht (make-h27-set
                               (remove-duplicates
                                (nconc write-h27s (copy-list delete-h27s))
                                :test #'equalp))))
               (when scope-ht
                 (setf current-kvs
                       (remove-by-sid-and-scope current-kvs sid scope-ht))))

             ;; ── Add new storage entries from overlay writes ──
             (dolist (s-entry (getf effects :storage))
               (let* ((h-27     (car s-entry))
                      (val      (cdr s-entry))
                      (trie-key (interleave-sub-key sid h-27)))
                 (push (cons trie-key (ensure-bytes val)) current-kvs)))

             ;; ── MERGE lookups: still uses classify for initial state ──
             ;; Lookup/preimage classification is unaffected by the storage overlay change.
             (let ((initial-classified (classify-service-sub-keys sid current-kvs)))

               (let* ((initial-lookup-h27s
                       (mapcar (lambda (l) (lookup-trie-h (first l) (second l)))
                               (getf initial-classified :lookup)))
                      (orphan-h27s
                       (mapcar #'car (getf initial-classified :candidate-orphans)))
                      (final-lookup-h27s
                       (mapcar (lambda (l) (lookup-trie-h (first l) (second l)))
                               (or (getf effects :lookup) '())))
                      (scope-ht (make-h27-set
                                 (remove-duplicates
                                  (nconc initial-lookup-h27s orphan-h27s
                                         final-lookup-h27s)
                                  :test #'equalp))))
                 (when scope-ht
                   (setf current-kvs
                         (remove-by-sid-and-scope current-kvs sid scope-ht))))

               (dolist (l-entry (getf effects :lookup))
                 (let* ((hash-32  (first l-entry))
                        (length   (second l-entry))
                        (statuses (cddr l-entry))
                        (h-27     (lookup-trie-h hash-32 length))
                        (trie-key (interleave-sub-key sid h-27))
                        (val      (encode-lookup-value statuses)))
                   (push (cons trie-key val) current-kvs)))

               ;; ── MERGE preimage blobs ──
               (let* ((initial-preimage-h27s
                       (mapcar (lambda (p) (preimage-trie-h (car p)))
                               (or (getf initial-classified :preimages) '())))
                      (final-preimage-h27s
                       (mapcar (lambda (p) (preimage-trie-h (car p)))
                               (or (getf effects :preimages) '())))
                      (scope-ht (make-h27-set
                                 (remove-duplicates
                                  (nconc initial-preimage-h27s final-preimage-h27s)
                                  :test #'equalp))))
                 (when scope-ht
                   (setf current-kvs
                         (remove-by-sid-and-scope current-kvs sid scope-ht)))
                 (dolist (p-entry (getf effects :preimages))
                   (let* ((hash-32  (car p-entry))
                          (blob     (cdr p-entry))
                          (h-27     (preimage-trie-h hash-32))
                          (trie-key (interleave-sub-key sid h-27)))
                     (push (cons trie-key (ensure-bytes blob)) current-kvs))))

               )) ;; close initial-classified + update-storage-p

           ;; ── Add provided preimages (always, even on panic) ──
           ;; hctx-provided-preimages entries are (list sid data), not (cons sid data).
           (dolist (pp (getf effects :provided-preimages))
             (let* ((pp-sid  (first pp))
                    (pp-data (second pp))
                    (pp-hash (jam-host:blake2b-256 pp-data))
                    (h-27    (preimage-trie-h pp-hash))
                    (trie-key (interleave-sub-key pp-sid h-27)))
               (push (cons trie-key (ensure-bytes pp-data)) current-kvs)))

           ;; ── Handle ejected services ──
           (dolist (ejection (getf effects :ejected))
             (let ((target-id (car ejection))
                   (ejector-id (second ejection)))
                 (declare (ignorable ejector-id))
               (setf current-kvs
                     (remove-if (lambda (kv)
                                  (let ((key (car kv)))
                                    (or (and (service-metadata-key-p key)
                                             (= (service-id-from-metadata-key key) target-id))
                                        (and (not (service-metadata-key-p key))
                                             (not (segment-key-p key))
                                             (= (service-id-from-sub-key key) target-id)))))
                                current-kvs))
               (remhash target-id meta-index)))

           ;; ── Handle created services (ΩN) ──
           ;; GP B.10: New service gets a lookup entry {((c,l)↦[])} and
           ;; items/bytes computed per ΩS footprint rules (items=2, bytes=81+l).
           (dolist (cs (getf effects :created-full))
             (let* ((new-sid      (getf cs :id))
                    (meta-key     (make-service-metadata-key new-sid))
                    (code-hash    (getf cs :code-hash))
                    (info (list :version 0
                                :code-hash code-hash
                                :balance (or (getf cs :balance) 0)
                                :min-accum-gas (or (getf cs :min-accum-gas) 0)
                                :min-memo-gas (or (getf cs :min-memo-gas) 0)
                                :bytes (or (getf cs :footprint) 0)
                                :deposit-offset (or (getf cs :deposit-offset) 0)
                                :items (or (getf cs :items-count) 0)
                                :creation-slot timeslot
                                :last-accumulation-slot 0
                                :parent-service (or (getf cs :parent-service) sid))))
               ;; Remove any existing metadata entry for this service
               (let ((old-meta (gethash new-sid meta-index)))
                 (when old-meta
                   (setf current-kvs (remove old-meta current-kvs :test #'eq))
                   (remhash new-sid meta-index)))
               ;; Add the new metadata entry
               (let ((new-kv (cons meta-key (encode-service-info info))))
                 (push new-kv current-kvs)
                 (setf (gethash new-sid meta-index) new-kv))

               ;; GP B.10: Create lookup entry {((c,l)↦[])} for the code hash.
               ;; The lookup trie key is interleave(new-sid, H(E4(l).hash)[0:27]).
               ;; Initial value is [] unless HC26 (provide-preimage) updated it to [τ'].
               (when (and code-hash (plusp (or (getf cs :code-length) 0)))
                 (let* ((code-len (getf cs :code-length))
                        (h-27    (lookup-trie-h code-hash code-len))
                        (trie-key (interleave-sub-key new-sid h-27))
                        ;; Check if a preimage was provided for this lookup entry
                        ;; (HC26 during same accumulation updates lookup [] → [τ'])
                        (provided-status
                         (dolist (pp (getf effects :provided-preimages))
                           (let* ((pp-sid  (first pp))
                                  (pp-data (second pp))
                                  (pp-len  (length pp-data)))
                             (when (and (= pp-sid new-sid)
                                        (= pp-len code-len)
                                        (equalp (jam-host:blake2b-256 pp-data) code-hash))
                               (return (list timeslot)))))))
                   (push (cons trie-key (encode-lookup-value provided-status))
                         current-kvs)))))

           ;; ── Update lookup entries for cross-service provided preimages ──
           ;; GP B.6: When HC26 provides a preimage for an EXISTING service
           ;; (not newly created), update that service's lookup entry [] → [τ'].
           ;; For newly-created services, this is already handled above.
           (dolist (pp (getf effects :provided-preimages))
             (let* ((pp-sid  (first pp))
                    (pp-data (second pp))
                    (pp-hash (jam-host:blake2b-256 pp-data))
                    (pp-len  (length pp-data))
                    (h-27    (lookup-trie-h pp-hash pp-len))
                    (trie-key (interleave-sub-key pp-sid h-27)))
               ;; Skip if this is the accumulating service (handled by merge-lookup)
               ;; or a newly-created service (handled above)
               (unless (or (= pp-sid sid)
                           (some (lambda (cs) (= (getf cs :id) pp-sid))
                                 (getf effects :created-full)))
                 ;; Remove old lookup entry and add updated one
                 (setf current-kvs
                       (remove-if (lambda (kv) (equalp (car kv) trie-key)) current-kvs))
                 (push (cons trie-key (encode-lookup-value (list timeslot)))
                       current-kvs))))

           ;; ── Update items/bytes from PVM-tracked values ──
           (when (and update-storage-p
                      (getf effects :items-count)
                      (getf effects :footprint))
             (let ((meta-entry (gethash sid meta-index)))
               (when meta-entry
                 (let ((info (load-service-info (cdr meta-entry))))
                   (setf (getf info :items) (getf effects :items-count))
                   (setf (getf info :bytes) (getf effects :footprint))
                   (setf (cdr meta-entry) (encode-service-info info)))))))))
     delta-results)
    current-kvs))

;;; =====================================================================
;;; STATE CLOSURE
;;; =====================================================================

(define-state-closure delta-state
  ((raw-kvs nil)
   (accounts-cache nil)
   (sid-index-cache nil))

  ;; δ's :save returns the multi-key Merkle pairs — σ stores them as delta-kvs.
  ;; Unlike segment components (single byte vector), δ is a list of (key . bytes).
  (:encode raw-kvs)

  ;; ── Lazy SID index — O(1) lookups instead of O(N) scans ──
  (:sid-index :memo
   (build-sid-index raw-kvs))

  ;; Decoded accounts list -- lazy parse from raw-kvs.
  (:accounts
   (or accounts-cache
       (setf accounts-cache (parse-service-accounts raw-kvs))))

  ;; Single account lookup by service ID.
  (:account (sid)
   (let ((accts (self :accounts)))
     (find sid accts :key (lambda (a) (getf a :id)))))

  ;; ── Sovereign queries for accumulate orchestrator ──────────

  ;; All known service IDs in delta (indexed).
  (:all-service-ids
   (extract-all-service-ids raw-kvs (self :sid-index)))

  ;; Classified service data for PVM invocation (GP D.1) — indexed.
  (:service-data (sid)
   (classify-service-sub-keys sid raw-kvs (self :sid-index)))

  ;; Raw sub-kvs for a service (list of (trie-key . value) pairs).
  ;; Used to build kvs-index for pure-computation ΩR/ΩW.
  (:sub-kvs (sid)
   (let ((indexed (gethash sid (self :sid-index))))
     (when indexed (cdr indexed))))

  ;; Cross-service accounts for ΩJ host call — indexed.
  (:cross-service-accounts (caller-id)
   (build-cross-service-accounts caller-id raw-kvs (self :sid-index)))

  ;; ── Transition-dagger: absorb PVM effects (δ → δ†) ─────────
  ;; Takes a hash-table of (sid → effects) + timeslot, returns δ†
  ;; with all storage/lookup/preimage/metadata updates applied.
  (:transition-dagger (&key delta-results timeslot)
    (make-delta-state
     :raw-kvs (absorb-delta-effects raw-kvs delta-results timeslot)))

  ;; -- Transition: delta' < (EP, delta-dagger, tau') -- GP S4.18 + S9.2
  (:transition (&key preimages tau-prime)
    (let ((timeslot (when tau-prime (funcall tau-prime :slot))))
      (if (or (null preimages) (zerop (length preimages)) (not timeslot))
          (make-delta-state :raw-kvs raw-kvs)
          (make-delta-state
           :raw-kvs (integrate-preimages raw-kvs preimages timeslot))))))


;;; ═══════════════════════════════════════════════════════════════
;;; CUSTOM DECODER FOR DELTA
;;; ═══════════════════════════════════════════════════════════════

(defun decode-delta-state (raw-kvs)
  "Decode δ from a list of multi-key Merkle pairs (delta-kvs).
   This serves as the public constructor for the orchestrator (σ),
   replacing the standard byte-array decoder."
  (make-delta-state :raw-kvs raw-kvs))
