;;;; helpers.lisp — Guest memory access & hashing helpers
;;;;
;;;; Safe read/write wrappers over JamVM's mem-read/mem-write,
;;;; storage key hashing (GP Appendix D), and LE encoding utilities.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; Guest memory access — wrapping JamVM mem-read / mem-write
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +max-guest-read+ (* 64 1024 1024)
  "Maximum bytes read-guest will allocate in one call (64 MB).
   Guest programs with wild register values can request GBs; cap to avoid OOM.")

(defun read-guest (vm addr len)
  "Read LEN bytes from guest memory at ADDR.
   Returns octet vector on success, NIL on page fault or oversized read."
  (when (zerop len) (return-from read-guest (make-array 0 :element-type '(unsigned-byte 8))))
  ;; Safety cap: refuse absurdly large reads that would exhaust the host heap
  (when (> len +max-guest-read+)
    (return-from read-guest nil))
  (multiple-value-bind (data ok) (mem-read (pvm-memory vm) addr len)
    (if data data nil)))

(defun write-guest (vm addr data)
  "Write DATA (octet vector) to guest memory at ADDR.
   Returns T on success, NIL on page fault."
  (when (zerop (length data)) (return-from write-guest t))
  (multiple-value-bind (ok fault-addr) (mem-write (pvm-memory vm) addr data)
    (declare (ignore fault-addr))
    ok))

(defun read-guest-u32 (vm addr)
  "Read a single u32 (LE) from guest memory. Returns value or NIL."
  (let ((buf (read-guest vm addr 4)))
    (when buf
      (logior (aref buf 0)
              (ash (aref buf 1) 8)
              (ash (aref buf 2) 16)
              (ash (aref buf 3) 24)))))

(defun read-guest-u64 (vm addr)
  "Read a single u64 (LE) from guest memory. Returns value or NIL."
  (let ((buf (read-guest vm addr 8)))
    (when buf
      (let ((val 0))
        (dotimes (i 8 val)
          (setf val (logior val (ash (aref buf i) (* 8 i)))))))))

(defun write-guest-u32 (vm addr val)
  "Write a u32 (LE) to guest memory. Returns T or NIL."
  (let ((buf (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4)
      (setf (aref buf i) (logand (ash val (* -8 i)) #xFF)))
    (write-guest vm addr buf)))

(defun write-guest-u64 (vm addr val)
  "Write a u64 (LE) to guest memory. Returns T or NIL."
  (let ((buf (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8)
      (setf (aref buf i) (logand (ash val (* -8 i)) #xFF)))
    (write-guest vm addr buf)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Storage key hashing — GP Appendix D
;;;
;;; H(E₄(2³²−1) ⌢ k)[0:27]
;;; Uses blake2b-256, takes first 27 bytes.
;;; ═══════════════════════════════════════════════════════════════════

(defun storage-hash-key (raw-key)
  "Compute the 27-byte trie sub-key hash for a storage entry.
   GP D.1: H(E₄(2³²−1) ⌢ k)[0:27].
   Requires ironclad for blake2b."
  (let* ((prefix (make-array 4 :element-type '(unsigned-byte 8)
                               :initial-contents '(#xFF #xFF #xFF #xFF)))
         (input (make-array (+ 4 (length raw-key))
                            :element-type '(unsigned-byte 8)))
         (digest (ironclad:make-digest :blake2/256)))
    (replace input prefix)
    (replace input raw-key :start1 4)
    (ironclad:update-digest digest input)
    (let ((hash (ironclad:produce-digest digest)))
      (subseq hash 0 27))))

;;; ═══════════════════════════════════════════════════════════════════
;;; LE encoding helpers (for building response buffers)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-u32-le (val)
  "Encode u32 VAL as 4-byte LE octet vector."
  (let ((buf (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 buf)
      (setf (aref buf i) (logand (ash val (* -8 i)) #xFF)))))

(defun encode-u64-le (val)
  "Encode u64 VAL as 8-byte LE octet vector."
  (let ((buf (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 buf)
      (setf (aref buf i) (logand (ash val (* -8 i)) #xFF)))))

(defun concat-octets (&rest vectors)
  "Concatenate octet vectors into one."
  (let* ((total (reduce #'+ vectors :key #'length))
         (result (make-array total :element-type '(unsigned-byte 8)))
         (off 0))
    (dolist (v vectors result)
      (replace result v :start1 off)
      (incf off (length v)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; JAM Compact Integer Encoding (GP C.5) — local copy to avoid dep on jotl
;;;
;;; Leading 1-bits in header byte = number of continuation bytes.
;;; Continuation bytes are LE. Header contains remaining high bits.
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-jam-compact (value)
  "Encode VALUE as JAM compact integer (GP C.5). Returns octet vector."
  (cond
    ;; value < 128 → single byte, high bit clear
    ((< value 128)
     (make-array 1 :element-type '(unsigned-byte 8) :initial-element value))
    ;; value needs full 8 bytes (≥ 2^56)
    ((>= value (expt 2 56))
     (let ((result (make-array 9 :element-type '(unsigned-byte 8) :initial-element 0)))
       (setf (aref result 0) #xFF)
       (loop for i from 1 to 8
             do (setf (aref result i) (ldb (byte 8 (* 8 (1- i))) value)))
       result))
    (t
     ;; Find minimal n (1..7): n leading 1-bits, total n+1 bytes
     ;; capacity = 8*n + (7-n) = 7n+7 data bits
     (let* ((n (loop for n from 1 to 7
                     for cap = (+ (* 8 n) (- 7 n))
                     when (< (integer-length value) (1+ cap))
                     return n
                     finally (return 7)))
            (total (1+ n))
            (result (make-array total :element-type '(unsigned-byte 8) :initial-element 0))
            (low-shift (* 8 n))
            (rem (ash value (- low-shift)))
            (data-bits (- 7 n))
            (prefix-mask (- (ash 1 8) (ash 1 (- 8 n))))
            (header (logior prefix-mask
                           (logand rem (1- (ash 1 data-bits))))))
       (setf (aref result 0) header)
       (loop for i from 1 below total
             do (setf (aref result i) (ldb (byte 8 (* 8 (1- i))) value)))
       result))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Hash table deep copy — for checkpoint snapshotting
;;; ═══════════════════════════════════════════════════════════════════

(defun copy-hash-table (ht)
  "Shallow copy of hash table HT (keys/values not cloned)."
  (let ((new (make-hash-table :test (hash-table-test ht)
                               :size (hash-table-count ht))))
    (maphash (lambda (k v) (setf (gethash k new) v)) ht)
    new))

(defun deep-copy-hash-table (ht)
  "Deep copy of hash table HT whose values are octet vectors.
   Keys are shared (they're immutable hash/octet refs), values are copied."
  (let ((new (make-hash-table :test (hash-table-test ht)
                               :size (hash-table-count ht))))
    (maphash (lambda (k v)
               (setf (gethash k new)
                     (if (typep v '(simple-array (unsigned-byte 8) (*)))
                         (copy-seq v)
                         v)))
             ht)
    new))

;;; ═══════════════════════════════════════════════════════════════════
;;; B.13 — Checkpoint save / collapse
;;;
;;; checkpoint-save:  Snapshot "y" context from current side-effects.
;;; checkpoint-collapse: Resolve dual context (x, y) given outcome o.
;;;
;;;   C: (u, o, (x, y)) →
;;;     (e: y_e, t: y_t, y: y_y, u, p: y_p)          if o ∈ {∞, ♯}
;;;     (e: x_e, t: x_t, y: o,   u, p: (x∪y)_p)      if o ∈ ℍ
;;;     (e: x_e, t: x_t, y: x_y, u, p: x_p)           otherwise
;;; ═══════════════════════════════════════════════════════════════════

(defun checkpoint-save (ctx)
  "GP B.13: Snapshot current side-effects into ctx.checkpoint (the y context).
   Called by ΩC (ecalli 17)."
  (setf (hctx-checkpoint ctx)
        (make-accumulate-checkpoint
         :transfers          (copy-list (hctx-transfers ctx))
         :ejected-services   (copy-list (hctx-ejected-services ctx))
         :created-services   (copy-list (hctx-created-services ctx))
         :upgrades           (copy-list (hctx-upgrades ctx))
         :yield-output       (hctx-yield-output ctx)
         :provided-preimages (copy-list (hctx-provided-preimages ctx))
         :storage            (deep-copy-hash-table (hctx-storage ctx))
         :lookup             (copy-hash-table (hctx-lookup ctx))
         :preimages          (deep-copy-hash-table (hctx-preimages ctx))
         :empower            (hctx-empower ctx)  ; struct is treated as immutable snapshot
         :items-count        (hctx-items-count ctx)
         :footprint          (hctx-footprint ctx)
         :balance            (hctx-balance ctx)
         :code-hash          (copy-seq (hctx-code-hash ctx))
         :min-accum-gas      (hctx-min-accum-gas ctx)
         :min-memo-gas       (hctx-min-memo-gas ctx))))

(defun checkpoint-collapse (ctx outcome gas-remaining)
  "GP B.13: Collapse dual context (x=current, y=checkpoint) given OUTCOME.
   OUTCOME is one of:
     :halt            — normal halt → keep x, yield = x_y
     :halt-with-yield — halt with hash → keep x, yield = hash (the OUTCOME arg is the hash)
     :panic           — revert to y
     :oog             — revert to y
   GAS-REMAINING is the final ϱ.
   Returns a fresh collapse-result plist:
     (:transfers ... :ejected-services ... :created-services ... :upgrades ...
      :yield-output ... :provided-preimages ... :gas-remaining ...
      :storage ... :lookup ... :preimages ... :empower ...
      :items-count ... :footprint ...)"
  (flet ((make-result (&key transfers ejected-services created-services upgrades
                            yield-output provided-preimages storage lookup
                            preimages empower items-count footprint)
           (list :transfers          transfers
                 :ejected-services   ejected-services
                 :created-services   created-services
                 :upgrades           upgrades
                 :yield-output       yield-output
                 :provided-preimages provided-preimages
                 :gas-remaining      gas-remaining
                 :storage            storage
                 :lookup             lookup
                 :preimages          preimages
                 :empower            empower
                 :items-count        items-count
                 :footprint          footprint)))

    (cond
      ;; ── o ∈ {∞, ♯}: revert to checkpoint (y) ────────────
      ((member outcome '(:panic :oog))
       (let ((cp (hctx-checkpoint ctx)))
         (if cp
             (make-result
              :transfers          (ckpt-transfers cp)
              :ejected-services   (ckpt-ejected-services cp)
              :created-services   (ckpt-created-services cp)
              :upgrades           (ckpt-upgrades cp)
              :yield-output       (ckpt-yield-output cp)
              :provided-preimages (ckpt-provided-preimages cp)
              :storage            (ckpt-storage cp)
              :lookup             (ckpt-lookup cp)
              :preimages          (ckpt-preimages cp)
              :empower            (ckpt-empower cp)
              :items-count        (ckpt-items-count cp)
              :footprint          (ckpt-footprint cp))
             ;; No checkpoint → empty side-effects
             (make-result
              :transfers          nil
              :ejected-services   nil
              :created-services   nil
              :upgrades           nil
              :yield-output       nil
              :provided-preimages nil
              :storage            (make-hash-table :test 'equalp)
              :lookup             (make-hash-table :test 'equalp)
              :preimages          (make-hash-table :test 'equalp)
              :empower            nil
              :items-count        0
              :footprint          0))))

      ;; ── o ∈ ℍ (halt-with-yield hash): keep x, yield = hash ──
      ((and (vectorp outcome) (= (length outcome) 32))
       (make-result
        :transfers          (hctx-transfers ctx)
        :ejected-services   (hctx-ejected-services ctx)
        :created-services   (hctx-created-services ctx)
        :upgrades           (hctx-upgrades ctx)
        :yield-output       outcome  ; the 32-byte hash
        :provided-preimages (hctx-provided-preimages ctx)
        :storage            (hctx-storage ctx)
        :lookup             (hctx-lookup ctx)
        :preimages          (hctx-preimages ctx)
        :empower            (hctx-empower ctx)
        :items-count        (hctx-items-count ctx)
        :footprint          (hctx-footprint ctx)))

      ;; ── otherwise (plain halt): keep x as-is ────────────
      (t
       (make-result
        :transfers          (hctx-transfers ctx)
        :ejected-services   (hctx-ejected-services ctx)
        :created-services   (hctx-created-services ctx)
        :upgrades           (hctx-upgrades ctx)
        :yield-output       (hctx-yield-output ctx)
        :provided-preimages (hctx-provided-preimages ctx)
        :storage            (hctx-storage ctx)
        :lookup             (hctx-lookup ctx)
        :preimages          (hctx-preimages ctx)
        :empower            (hctx-empower ctx)
        :items-count        (hctx-items-count ctx)
        :footprint          (hctx-footprint ctx))))))
