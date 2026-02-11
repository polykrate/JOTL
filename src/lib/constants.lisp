;;;; constants.lisp - JAM Protocol Constants (Pure FP with Closures)
;;;; Based on jamtestvectors chainspecs

(in-package #:jotl)

(defparameter *jotl-version* "3.0.0"
  "JOTL version")

;;; ═══════════════════════════════════════════════════════════════
;;; CHAINSPEC DEFINITIONS (from jamtestvectors/README.md)
;;; ═══════════════════════════════════════════════════════════════

#|
Two chainspecs:

TINY (for development and testing):
  - num_validators: 6
  - num_cores: 2
  - Small values for fast iteration

FULL (production, must match Gray Paper):
  - num_validators: 1023
  - num_cores: 341
  - Full scale parameters
|#

(defun make-chainspec (name specs)
  "Creates a chainspec closure
   
   A chainspec is a pure closure that returns protocol constants.
   
   Usage:
   (funcall chainspec :num-validators)  ; => 6 (for tiny)
   (funcall chainspec :name)            ; => :tiny"
  
  (lambda (key)
    (case key
      (:name name)
      (:num-validators (getf specs :num-validators))
      (:num-cores (getf specs :num-cores))
      (:preimage-expunge-period (getf specs :preimage-expunge-period))
      (:slot-duration (getf specs :slot-duration))
      (:epoch-duration (getf specs :epoch-duration))
      (:contest-duration (getf specs :contest-duration))
      (:tickets-per-validator (getf specs :tickets-per-validator))
      (:max-tickets-per-extrinsic (getf specs :max-tickets-per-extrinsic))
      (:rotation-period (getf specs :rotation-period))
      (:num-ec-pieces-per-segment (getf specs :num-ec-pieces-per-segment))
      (:max-block-gas (getf specs :max-block-gas))
      (:max-refine-gas (getf specs :max-refine-gas))
      (:all specs)  ; Return all specs as plist
      (otherwise (error "Unknown chainspec key: ~A" key)))))

;;; Define the two chainspecs

(defparameter +tiny-chainspec+
  (make-chainspec
   :tiny
   '(:num-validators 6
     :num-cores 2
     :preimage-expunge-period 32
     :slot-duration 6
     :epoch-duration 12
     :contest-duration 10
     :tickets-per-validator 3
     :max-tickets-per-extrinsic 3
     :rotation-period 4
     :num-ec-pieces-per-segment 1026
     :max-block-gas 20000000
     :max-refine-gas 1000000000))
  "TINY chainspec - for development and testing")

(defparameter +full-chainspec+
  (make-chainspec
   :full
   '(:num-validators 1023
     :num-cores 341
     :preimage-expunge-period 19200
     :slot-duration 6
     :epoch-duration 600
     :contest-duration 500
     :tickets-per-validator 2
     :max-tickets-per-extrinsic 16
     :rotation-period 10
     :num-ec-pieces-per-segment 6
     :max-block-gas 3500000000
     :max-refine-gas 5000000000))
  "FULL chainspec - production, must match Gray Paper")

;;; ═══════════════════════════════════════════════════════════════
;;; ACTIVE CHAIN (Dynamic, switchable)
;;; ═══════════════════════════════════════════════════════════════

(defvar *chain* +tiny-chainspec+
  "Currently active chainspec (default: tiny)
   
   Switch with: (switch-chain :full)
   Or use with-chain macro for lexical override.")

(defun chain ()
  "Returns the current active chainspec"
  *chain*)

(defun switch-chain (name)
  "Switch the global active chain
   
   Usage:
   (switch-chain :tiny)   ; Development
   (switch-chain :full)   ; Production
   
   Returns: new chainspec"
  (setf *chain*
        (case name
          (:tiny +tiny-chainspec+)
          (:full +full-chainspec+)
          (otherwise (error "Unknown chain: ~A (use :tiny or :full)" name))))
  (format t "~&Switched to ~A chain~%" name)
  *chain*)

(defmacro with-chain (name &body body)
  "Execute body with a specific chainspec
   
   Usage:
   (with-chain :full
     (num-validators))  ; Uses full chainspec
   
   Does not affect global *chain*"
  `(let ((*chain* (case ,name
                    (:tiny +tiny-chainspec+)
                    (:full +full-chainspec+)
                    (otherwise (error "Unknown chain: ~A" ,name)))))
     ,@body))

;;; ═══════════════════════════════════════════════════════════════
;;; CONVENIENT ACCESSORS (use current *chain*)
;;; ═══════════════════════════════════════════════════════════════

(defun num-validators ()
  "V — Number of validators in current chain (GP I.4.4)."
  (funcall *chain* :num-validators))

(defun num-cores ()
  "C — Number of cores in current chain (GP I.4.4)."
  (funcall *chain* :num-cores))

(defun slot-duration ()
  "P — Slot period in seconds, always 6 (GP §4.8)."
  (funcall *chain* :slot-duration))

(defun epoch-duration ()
  "E — Epoch length in timeslots (GP §4.8)."
  (funcall *chain* :epoch-duration))

(defun max-block-gas ()
  "GT — Total gas allocated across all Accumulation (GP I.4.4)."
  (funcall *chain* :max-block-gas))

(defun max-refine-gas ()
  "GR — Gas allocated for Refine logic (GP I.4.4)."
  (funcall *chain* :max-refine-gas))

(defun preimage-expunge-period ()
  "D — Preimage expunge period in timeslots (GP I.4.4)."
  (funcall *chain* :preimage-expunge-period))

(defun contest-duration ()
  "Y — Ticket-submission closing offset in timeslots (GP §6.5-6.7)."
  (funcall *chain* :contest-duration))

(defun tickets-per-validator ()
  "N — Number of ticket entries per validator (GP §6.29)."
  (funcall *chain* :tickets-per-validator))

(defun max-tickets-per-extrinsic ()
  "K — Maximum tickets per extrinsic (GP §6.30)."
  (funcall *chain* :max-tickets-per-extrinsic))

(defun rotation-period ()
  "R — Rotation period of validator-core assignments in timeslots (GP §11.3-11.4)."
  (funcall *chain* :rotation-period))

(defun num-ec-pieces-per-segment ()
  "WP — Number of erasure coding pieces per segment (GP H.4)."
  (funcall *chain* :num-ec-pieces-per-segment))

;;; show-chain-config and compare-chains → utils/display.lisp

;;; ═══════════════════════════════════════════════════════════════
;;; PROTOCOL CONSTANTS — Fixed values from Gray Paper I.4.4
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; GP Letter → Lisp Name Mapping:
;;;
;;; ── Chainspec-variable (in make-chainspec) ──────────────────
;;;  C  → (num-cores)                  §I.4.4  Total cores
;;;  D  → (preimage-expunge-period)    §I.4.4  Preimage expunge period
;;;  E  → (epoch-duration)             §4.8    Epoch length (timeslots)
;;;  GR → (max-refine-gas)             §I.4.4  Max refine gas
;;;  GT → (max-block-gas)              §I.4.4  Total accumulation gas
;;;  K  → (max-tickets-per-extrinsic)  §6.30   Max tickets per extrinsic
;;;  N  → (tickets-per-validator)      §6.29   Ticket entries per validator
;;;  P  → (slot-duration)              §4.8    Slot period (seconds, always 6)
;;;  R  → (rotation-period)            §11.3   Rotation period (timeslots)
;;;  V  → (num-validators)             §I.4.4  Total validators
;;;  WP → (num-ec-pieces-per-segment)  §H.4    Erasure pieces per segment
;;;  Y  → (contest-duration)           §6.5    Ticket submission closing offset
;;;
;;; ── Fixed protocol constants (defconstant) ──────────────────

;;; ─── Special values ──────────────────────────────────────────

(defparameter +zero-hash+
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
  "H0 — the zero hash (32 bytes of 0x00). GP notation: ∅ for hashes.")

(defparameter +mmr-peak-prefix+
  (map '(vector (unsigned-byte 8)) #'char-code "peak")
  "The 'peak' prefix used in MMR super-peak computation (GP E.11).")

;;; ─── Core protocol constants (GP I.4.4) ──────────────────────

(defconstant +history-size+ 8
  "H — Size of recent history, in blocks (GP §7.8).")

(defconstant +availability-timeout+ 5
  "U — Period in timeslots after which reported but unavailable work
   may be replaced (GP §11, eq 11.17). H_T ≥ t + U → stale.")

(defconstant +max-work-items+ 16
  "I — Maximum work items in a package (GP §11.2, §14.2).")

(defconstant +max-dependencies+ 8
  "J — Maximum sum of dependency items in a work-report (GP §11.3).")

(defconstant +max-lookup-anchor-age+ 14400
  "L — Maximum age in timeslots of the lookup anchor (GP §11.34).")

(defconstant +max-auth-pool+ 8
  "O — Maximum number of items in the authorizations pool (GP §8.1).")

(defconstant +auth-queue-size+ 80
  "Q — Number of items in the authorizations queue (GP §8.1).")

(defconstant +min-service-index+ (expt 2 16)
  "S — Minimum public service index (GP B.14). 2^16 = 65536.")

(defconstant +max-work-package-extrinsics+ 128
  "T — Maximum number of extrinsics in a work-package (GP §14.4).")

;;; ─── Gas constants ────────────────────────────────────────────

(defconstant +accumulation-gas+ 10000000
  "GA — Gas allocated for a work-report's Accumulation logic (GP I.4.4).")

(defconstant +is-authorized-gas+ 50000000
  "GI — Gas allocated for a work-package's Is-Authorized logic (GP I.4.4).")

;;; ─── Balance constants ────────────────────────────────────────

(defconstant +min-balance+ 100
  "BS — Basic minimum balance required by all services (GP §9.8).")

(defconstant +min-balance-per-item+ 10
  "BI — Additional minimum balance per item of elective state (GP §9.8).")

(defconstant +min-balance-per-octet+ 1
  "BL — Additional minimum balance per octet of elective state (GP §9.8).")

;;; ─── Audit constants ──────────────────────────────────────────

(defconstant +audit-tranche-period+ 8
  "A — Period in seconds between audit tranches (GP §17.3).")

(defconstant +audit-bias-factor+ 2
  "F — Expected additional auditors per no-show in previous tranche (GP §17.14).")

;;; ─── Work-package size constants ──────────────────────────────

(defconstant +max-is-authorized-code+ 64000
  "WA — Maximum size of is-authorized code in octets (GP B.1).")

(defconstant +max-service-code+ 4000000
  "WC — Maximum size of service code in octets (GP B.5, B.9).")

(defconstant +erasure-piece-size+ 684
  "WE — Basic size of erasure-coded pieces in octets (GP H.4).")

(defconstant +segment-size+ 4104
  "WG — Size of a segment in octets = WP × WE (GP §14.2.1).")

(defconstant +max-imports+ 3072
  "WM — Maximum number of imports in a work-package (GP §14.4).")

(defconstant +max-exports+ 3072
  "WX — Maximum number of exports in a work-package (GP §14.4).")

(defconstant +max-unbounded-blob-size+ (* 48 1024)
  "WR — Maximum total size of all unbounded blobs in a work-report = 48·2^10 (GP §11.8).")

(defconstant +transfer-memo-size+ 128
  "WT — Size of a transfer memo in octets (GP §12.14).")

;;; ─── PVM Host-Call Result Constants (GP B.1) ─────────────────
;;; These are u64 values returned in register A0 to the guest PVM.
;;; They live near 2^64 so they cannot be confused with valid lengths.

(defconstant +hc-ok+   0
  "OK: general success (GP B.1).")

(defconstant +hc-none+ (1- (expt 2 64))
  "NONE = 2^64−1: item does not exist (GP B.1).")

(defconstant +hc-what+ (- (expt 2 64) 2)
  "WHAT = 2^64−2: name unknown (GP B.1).")

(defconstant +hc-oob+  (- (expt 2 64) 3)
  "OOB = 2^64−3: inner PVM memory index not accessible (GP B.1).")

(defconstant +hc-who+  (- (expt 2 64) 4)
  "WHO = 2^64−4: index unknown (GP B.1).")

(defconstant +hc-full+ (- (expt 2 64) 5)
  "FULL = 2^64−5: storage full or resource already allocated (GP B.1).")

(defconstant +hc-core+ (- (expt 2 64) 6)
  "CORE = 2^64−6: core index unknown (GP B.1).")

(defconstant +hc-cash+ (- (expt 2 64) 7)
  "CASH = 2^64−7: insufficient funds (GP B.1).")

(defconstant +hc-low+  (- (expt 2 64) 8)
  "LOW = 2^64−8: gas limit too low (GP B.1).")

(defconstant +hc-huh+  (- (expt 2 64) 9)
  "HUH = 2^64−9: already solicited / cannot forget / privilege invalid (GP B.1).")

;;; Inner PVM invocation result codes (GP B.1)

(defconstant +pvm-halt+  0 "HALT: invocation halted normally (GP B.1).")
(defconstant +pvm-panic+ 1 "PANIC: invocation panicked (GP B.1).")
(defconstant +pvm-fault+ 2 "FAULT: page fault (GP B.1).")
(defconstant +pvm-host+  3 "HOST: host-call fault (GP B.1).")
(defconstant +pvm-oog+   4 "OOG: out of gas (GP B.1).")

;;; ─── PVM constants ────────────────────────────────────────────

(defconstant +pvm-address-alignment+ 2
  "ZA — PVM dynamic address alignment factor (GP A.18).")

(defconstant +pvm-init-data-size+ (expt 2 24)
  "ZI — Standard PVM program initialization input data size (GP A.7).")

(defconstant +pvm-page-size+ (expt 2 12)
  "ZP — PVM memory page size (GP §4.24).")

(defconstant +pvm-init-zone-size+ (expt 2 16)
  "ZZ — Standard PVM program initialization zone size (GP A.7).")

;;; ─── Validator key layout sizes (GP §6.9-6.12) ───────────────
;;; Not protocol parameters — fixed by the cryptographic types.

(defconstant +bandersnatch-key-size+ 32
  "kb — Bandersnatch public key size in bytes (GP §6.9).")

(defconstant +ed25519-key-size+ 32
  "ke — Ed25519 public key size in bytes (GP §6.10).")

(defconstant +bls-key-size+ 144
  "kl — BLS public key size in bytes (GP §6.11).")

(defconstant +metadata-size+ 128
  "km — Validator metadata size in bytes (GP §6.12).")

(defconstant +validator-key-size+ 336
  "K — Full validator key size = kb+ke+kl+km = 32+32+144+128 (GP §6.9-6.12).")

;;; ─── Context strings X (GP I.4.5) ────────────────────────────
;;; All 10 signing contexts defined in the Gray Paper.
;;; Note: crypto/primitives.lisp also defines +jam-entropy+, +jam-ticket-seal+,
;;; +jam-fallback-seal+ in jam.ffi — those are used directly by the FFI layer.
;;; These +ctx-*+ constants are the canonical jotl-level references.

(defparameter +ctx-available+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_available")
  "XA — Ed25519 Availability assurances (GP §11.13).")

(defparameter +ctx-beefy+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_beefy")
  "XB — BLS Accumulate-result-root-mmr commitment (GP §18.1).")

(defparameter +ctx-entropy+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_entropy")
  "XE — On-chain entropy generation (GP §6.17).")

(defparameter +ctx-fallback-seal+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_fallback_seal")
  "XF — Bandersnatch Fallback block seal (GP §6.16).")

(defparameter +ctx-guarantee+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_guarantee")
  "XG — Ed25519 Guarantee statements (GP §11.26).")

(defparameter +ctx-announce+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_announce")
  "XI — Ed25519 Audit announcement statements (GP §17.8).")

(defparameter +ctx-ticket-seal+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_ticket_seal")
  "XT — Bandersnatch RingVRF Ticket generation and regular block seal (GP §6.15).")

(defparameter +ctx-audit+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_audit")
  "XU — Bandersnatch Audit selection entropy (GP §17.3, §17.14).")

(defparameter +ctx-valid+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_valid")
  "X⊤ — Ed25519 Judgments for valid work-reports (GP §17.17).")

(defparameter +ctx-invalid+
  (map '(vector (unsigned-byte 8)) #'char-code "jam_invalid")
  "X⊥ — Ed25519 Judgments for invalid work-reports (GP §17.17).")

;;; Exports managed in package.lisp
