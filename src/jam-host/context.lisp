;;;; context.lisp — JamHostContext & ServiceAccount (GP Appendix B)
;;;;
;;;; Host context structures for GP Appendix B.
;;;; Pure Common Lisp structs with hash-table-based maps.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; ServiceAccount — d[s] for cross-service lookups
;;;
;;; GP: Ω_L needs a_P (preimages), Ω_R needs a_s (storage),
;;; Ω_I needs the full info record, Ω_W needs a_t for FULL check.
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (service-account (:conc-name sa-))
  "Service account view (d[s]). Fields follow GP §9 naming."
  ;; a_s — storage map: key (octet vector) → value (octet vector)
  (storage    (make-hash-table :test 'equalp) :type hash-table)
  ;; a_P — preimage lookup: hash (32-byte vector) → data (octet vector)
  (preimages  (make-hash-table :test 'equalp) :type hash-table)
  ;; a_l — preimage metadata: (hash . length) → status-tuple (list of u32)
  (lookup     (make-hash-table :test 'equalp) :type hash-table)
  ;; Scalar fields
  (balance         0 :type (unsigned-byte 64))   ; a_b
  (code-hash       (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 0)
                   :type (simple-array (unsigned-byte 8) (32))) ; a_c
  (threshold       0 :type (unsigned-byte 64))   ; a_f (balance offset)
  (min-accum-gas   0 :type (unsigned-byte 64))   ; a_g
  (min-memo-gas    0 :type (unsigned-byte 64))   ; a_m
  (items-count     0 :type (unsigned-byte 32))   ; a_i
  (footprint       0 :type (unsigned-byte 64))   ; a_o
  (creation-slot    0 :type (unsigned-byte 32))   ; a_r — creation timeslot
  (last-accum-slot  0 :type (unsigned-byte 32))   ; a_a — last accumulation timeslot
  (parent-service   0 :type (unsigned-byte 32)))  ; a_p — parent service ID

;;; ═══════════════════════════════════════════════════════════════════
;;; compute-threshold — GP §9.3 eq (9.8)
;;; a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f)
;;; ═══════════════════════════════════════════════════════════════════

(defun compute-threshold (items-count footprint balance-offset)
  "GP §9.3: a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f)."
  (let ((cost (+ +balance-base+
                 (* +balance-per-item+ items-count)
                 (* +balance-per-octet+ footprint))))
    (max 0 (- cost balance-offset))))

;;; ═══════════════════════════════════════════════════════════════════
;;; encode-service-info — Ω_I encoding (96 bytes)
;;;
;;; E(a_c, E_8(a_b, a_t, a_g, a_m, a_o), E_4(a_i), E_8(a_f), E_4(a_r, a_a, a_p))
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-service-info (sa)
  "Encode ServiceAccount SA into a 96-byte Ω_I info record."
  (let ((buf (make-array +service-info-size+
                         :element-type '(unsigned-byte 8)
                         :initial-element 0))
        (off 0))
    ;; a_c — 32 bytes
    (replace buf (sa-code-hash sa) :start1 off)
    (incf off 32)
    ;; E_8(a_b, a_t, a_g, a_m, a_o) — 5 × 8 = 40 bytes
    (let ((a-t (compute-threshold (sa-items-count sa)
                                  (sa-footprint sa)
                                  (sa-threshold sa))))
      (flet ((put-u64 (val)
               (dotimes (i 8) (setf (aref buf (+ off i))
                                    (logand (ash val (* -8 i)) #xFF)))
               (incf off 8)))
        (put-u64 (sa-balance sa))
        (put-u64 a-t)
        (put-u64 (sa-min-accum-gas sa))
        (put-u64 (sa-min-memo-gas sa))
        (put-u64 (sa-footprint sa))))
    ;; E_4(a_i) — 4 bytes
    (let ((ai (sa-items-count sa)))
      (dotimes (i 4) (setf (aref buf (+ off i))
                            (logand (ash ai (* -8 i)) #xFF)))
      (incf off 4))
    ;; E_8(a_f) — 8 bytes
    (let ((af (sa-threshold sa)))
      (dotimes (i 8) (setf (aref buf (+ off i))
                            (logand (ash af (* -8 i)) #xFF)))
      (incf off 8))
    ;; E_4(a_r, a_a, a_p) — 3 × 4 = 12 bytes
    (dolist (val (list (sa-creation-slot sa)
                       (sa-last-accum-slot sa)
                       (sa-parent-service sa)))
      (dotimes (i 4) (setf (aref buf (+ off i))
                            (logand (ash val (* -8 i)) #xFF)))
      (incf off 4))
    buf))

;;; ═══════════════════════════════════════════════════════════════════
;;; WorkItemInfo — S(w) structured work item for fetch kinds 11/12/13
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (work-item-info (:conc-name wi-))
  "Work item summary for S(w) encoding (GP B.6)."
  (service-id     0 :type (unsigned-byte 32))     ; w_s
  (code-hash      (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 0)
                  :type (simple-array (unsigned-byte 8) (32)))  ; w_c
  (gas-limit      0 :type (unsigned-byte 64))     ; w_g
  (gas-limit-accum 0 :type (unsigned-byte 64))    ; w_g_a
  (payload        (make-array 0 :element-type '(unsigned-byte 8))
                  :type (simple-array (unsigned-byte 8) (*))))  ; w_y

;;; ═══════════════════════════════════════════════════════════════════
;;; EmpowerState — B.7 privileged outputs (ΩB / ΩA / ΩD)
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (empower-state (:conc-name emp-))
  "Empower state x_e = (m, a, v, r, z, q, l)."
  (manager     0 :type (unsigned-byte 32))        ; m
  (auth-agents #() :type vector)                  ; a — vector of u32
  (validator   0 :type (unsigned-byte 32))        ; v
  (staker      0 :type (unsigned-byte 32))        ; r
  (gas-map     (make-hash-table) :type hash-table) ; z — service_id → gas
  (queues      #() :type vector)                  ; q — per-core auth queues
  (validators  #() :type vector)                  ; l — validator keys
  (bless-called nil :type boolean))               ; T iff ΩB was called (not just ΩD)

;;; ═══════════════════════════════════════════════════════════════════
;;; JamTransfer — ΩT side-effect record
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (jam-transfer (:conc-name xfer-))
  "Token transfer record (ΩT side-effect)."
  (from-service 0 :type (unsigned-byte 32))       ; x_s
  (to-service   0 :type (unsigned-byte 32))       ; d
  (amount       0 :type (unsigned-byte 64))       ; a
  (memo         (make-array +memo-size+
                            :element-type '(unsigned-byte 8)
                            :initial-element 0)
                :type (simple-array (unsigned-byte 8) (*)))  ; W_T bytes
  (gas-limit    0 :type (unsigned-byte 64)))      ; l

;;; ═══════════════════════════════════════════════════════════════════
;;; AccumulateCheckpoint — B.13 snapshot for rollback
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (accumulate-checkpoint (:conc-name ckpt-))
  "Snapshot of accumulate side-effects for checkpoint/rollback (GP B.13)."
  (transfers          nil :type list)
  (ejected-services   nil :type list)
  (created-services   nil :type list)
  (upgrades           nil :type list)
  (yield-output       nil)
  (provided-preimages nil :type list)
  (storage            (make-hash-table :test 'equalp) :type hash-table)
  ;; Tracks h27s explicitly deleted by HC4 (v_Z=0).
  ;; Distinguishes "not yet written" from "was deleted" in overlay mode.
  (storage-deletes    (make-hash-table :test 'equalp) :type hash-table)
  (lookup             (make-hash-table :test 'equalp) :type hash-table)
  (preimages          (make-hash-table :test 'equalp) :type hash-table)
  (empower            nil)
  (designated-validators nil)   ; ΩD without ΩB — separate from empower
  (items-count        0 :type (unsigned-byte 32))
  (footprint          0 :type (unsigned-byte 64))
  (balance            0 :type integer)
  (code-hash          nil)
  (min-accum-gas      0 :type integer)
  (min-memo-gas       0 :type integer))

;;; ═══════════════════════════════════════════════════════════════════
;;; JamHostContext — master state during PVM execution
;;;
;;; Host execution context — GP Appendix B.
;;; All fields use CL hash tables instead of Rust HashMap.
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (host-context (:conc-name hctx-))
  "Host context for JAM service execution (GP Appendix B).
   Contains all state available to host calls during PVM execution."

  ;; ── Invocation context ──────────────────────────────
  (invocation +ctx-accumulate+ :type keyword)

  ;; ── Service identity ────────────────────────────────
  (service-id      0 :type (unsigned-byte 32))
  (balance         0 :type (unsigned-byte 64))
  (slot            0 :type (unsigned-byte 32))
  (next-service-id 0 :type (unsigned-byte 32))
  (core-index      0 :type (unsigned-byte 16))

  ;; ── Own-service info (Ω_I self-lookup, Ω_W FULL check) ──
  (code-hash       (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 0)
                   :type (simple-array (unsigned-byte 8) (32)))
  (threshold       0 :type (unsigned-byte 64))   ; a_f
  (min-accum-gas   0 :type (unsigned-byte 64))   ; a_g
  (min-memo-gas    0 :type (unsigned-byte 64))   ; a_m
  (items-count     0 :type (unsigned-byte 32))   ; a_i
  (footprint       0 :type (unsigned-byte 64))   ; a_o
  (creation-slot    0 :type (unsigned-byte 32))   ; a_r — creation timeslot
  (last-accum-slot  0 :type (unsigned-byte 32))   ; a_a — last accumulation timeslot
  (parent-service   0 :type (unsigned-byte 32))   ; a_p — parent service ID

  ;; ── Storage overlay (ΩR / ΩW) — keyed by h27 hash ──────────
  ;; Write overlay: starts empty. ΩW inserts here, ΩR checks here first.
  ;; Reads that miss the overlay fall through to kvs-index (base layer).
  (storage         (make-hash-table :test 'equalp) :type hash-table)
  ;; Explicit deletes: h27 → T. Prevents fallback to kvs-index for deleted keys.
  (storage-deletes (make-hash-table :test 'equalp) :type hash-table)

  ;; ── KVS index (base layer for ΩR) — keyed by 31-byte trie key ──
  ;; Built once from delta-kvs for self-service. Immutable during execution.
  ;; Maps 31-byte interleaved trie keys to values (octet vectors).
  (kvs-index       (make-hash-table :test 'equalp) :type hash-table)

  ;; ── Preimages (ΩL) ─────────────────────────────────
  (preimages       (make-hash-table :test 'equalp) :type hash-table)

  ;; ── Preimage lookup table (ΩQ / ΩJ) ───────────────
  ;; Key: (hash . length), Value: status tuple (list of u32)
  (lookup          (make-hash-table :test 'equalp) :type hash-table)

  ;; ── Candidate orphaned lookups (lazy discovery) ────
  ;; h27 → encoded-value.  Unclassified trie entries available for
  ;; address-based discovery.  HC22/23/24 compute lookup-trie-h(hash,len)
  ;; and probe this table; on hit the entry is promoted to hctx-lookup.
  (candidate-lookups (make-hash-table :test 'equalp) :type hash-table)

  ;; h27s of orphans actually discovered during this PVM execution.
  ;; Needed for scope: HC24 forget may remove from hctx-lookup, but the
  ;; trie entry must still be in the removal scope.
  (discovered-orphan-h27s nil :type list)

  ;; ── Side-effects ────────────────────────────────────
  (logs                nil :type list)
  (transfers           nil :type list)
  (ejected-services    nil :type list)
  (created-services    nil :type list)
  (upgrades            nil :type list)
  (yield-output        nil)
  (provided-preimages  nil :type list)

  ;; ── Checkpoint (B.13) ───────────────────────────────
  (checkpoint nil)

  ;; ── Fetch data (ΩY) ────────────────────────────────
  (entropy-raw       (make-array 0 :element-type '(unsigned-byte 8))
                     :type (simple-array (unsigned-byte 8) (*)))
  (entropy           (make-array '(4 32) :element-type '(unsigned-byte 8)
                                         :initial-element 0))
  (accumulate-items  nil :type list)   ; list of octet vectors
  (work-package      (make-array 0 :element-type '(unsigned-byte 8))
                     :type (simple-array (unsigned-byte 8) (*)))
  (protocol-params   (make-array 0 :element-type '(unsigned-byte 8))
                     :type (simple-array (unsigned-byte 8) (*)))

  ;; ── Block context ───────────────────────────────────
  (header-hash       (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 0)
                     :type (simple-array (unsigned-byte 8) (32)))

  ;; ── Service registry (B.14) ─────────────────────────
  (existing-services (make-hash-table) :type hash-table) ; set of u32

  ;; ── Other service accounts ──────────────────────────
  ;; service_id → service-account struct
  (service-accounts  (make-hash-table) :type hash-table)

  ;; ── Protocol parameters ─────────────────────────────
  (segment-size      +default-segment-size+ :type (unsigned-byte 32))
  (max-exports       +default-max-exports+  :type (unsigned-byte 32))
  (export-base       0 :type (unsigned-byte 32))
  (timeslot          0 :type (unsigned-byte 32))
  (min-turnaround    32 :type (unsigned-byte 32))

  ;; ── Refine-specific data ────────────────────────────
  (payload           (make-array 0 :element-type '(unsigned-byte 8))
                     :type (simple-array (unsigned-byte 8) (*)))
  (package-hash      (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 0)
                     :type (simple-array (unsigned-byte 8) (32)))
  (import-segments   nil :type list)   ; list of octet vectors
  (authorizer-trace  (make-array 0 :element-type '(unsigned-byte 8))
                     :type (simple-array (unsigned-byte 8) (*)))
  (export-segments   nil :type list)
  (work-item-index   0 :type (unsigned-byte 32))
  (lookup-anchor-hash (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 0)
                      :type (simple-array (unsigned-byte 8) (32)))
  (extrinsics        nil :type list)   ; list of (list of octet vectors)
  (authorizer-code   (make-array 0 :element-type '(unsigned-byte 8))
                     :type (simple-array (unsigned-byte 8) (*)))
  (justification     (make-array 0 :element-type '(unsigned-byte 8))
                     :type (simple-array (unsigned-byte 8) (*)))
  (work-package-context (make-array 0 :element-type '(unsigned-byte 8))
                        :type (simple-array (unsigned-byte 8) (*)))
  (work-items        nil :type list)   ; list of work-item-info

  ;; ── Inner PVM machines (ΩM/ΩP/ΩO/ΩZ/ΩK/ΩX) ───────
  ;; Key: u32 index, Value: plist (:vm pvm-struct :initial-pc u32)
  (inner-machines    (make-hash-table) :type hash-table)

  ;; ── Protocol constants ──────────────────────────────
  (core-count        2  :type (unsigned-byte 16))   ; C
  (auth-queue-len    80 :type (unsigned-byte 16))   ; Q
  (val-count         6  :type (unsigned-byte 16))   ; V

  ;; ── Privileged outputs ──────────────────────────────
  (empower           nil)   ; empower-state or nil
  ;; ΩD without prior ΩB: validators stored separately to avoid
  ;; creating a phantom empower-state that corrupts omega-service checks
  (designated-validators nil)   ; vector of 336-byte keys, or nil
  (designate-service     0 :type (unsigned-byte 32))   ; χ_V at context creation

  ;; ── Debug trace ─────────────────────────────────────
  (debug-trace       nil :type boolean)
  (host-call-log     nil :type list)
  (debug-log         nil :type list))

;;; ═══════════════════════════════════════════════════════════════════
;;; Context helpers
;;; ═══════════════════════════════════════════════════════════════════

(defun context-allows-p (ctx id)
  "Return T if host call ID is allowed in CTX's invocation context.
   GP B.2 / B.6 / B.8 / B.11."
  (let ((inv (hctx-invocation ctx)))
    (ecase inv
      ;; B.2: IsAuthorized — gas(0), fetch(1), log(100)
      (:is-authorized (member id '(0 1 100)))
      ;; B.6: Refine — gas, fetch, hist-lookup(6), export(7), inner-PVM(8-13), log(100)
      (:refine (or (member id '(0 1 6 7 100))
                   (<= 8 id 13)))
      ;; B.11: Accumulate — 0-5, 14-26, 100
      (:accumulate (or (<= 0 id 5)
                       (<= 14 id 26)
                       (= id 100)))
      ;; B.8: OnTransfer — same as Accumulate minus 14,15,16
      (:on-transfer (or (<= 0 id 5)
                        (<= 17 id 26)
                        (= id 100))))))

(defun self-account-info (ctx)
  "Build a ServiceAccount view of own service for Ω_I self-lookup."
  (make-service-account
   :storage        (hctx-storage ctx)
   :preimages      (hctx-preimages ctx)
   :lookup         (hctx-lookup ctx)
   :balance        (hctx-balance ctx)
   :code-hash      (hctx-code-hash ctx)
   :threshold      (hctx-threshold ctx)
   :min-accum-gas  (hctx-min-accum-gas ctx)
   :min-memo-gas   (hctx-min-memo-gas ctx)
   :items-count    (hctx-items-count ctx)
   :footprint      (hctx-footprint ctx)
   :creation-slot   (hctx-creation-slot ctx)
   :last-accum-slot (hctx-last-accum-slot ctx)
   :parent-service  (hctx-parent-service ctx)))
