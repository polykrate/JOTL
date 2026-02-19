;;;; constants.lisp — GP B.1 Host-Call Result Constants & Protocol Constants
;;;;
;;;; Ported from crypto/jam-crypto/src/pvm/context.rs lines 119-158.
;;;; These u64 sentinel values live near 2^64 and cannot collide with
;;;; valid lengths or indices.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; B.1 — Host-Call Result Constants
;;;
;;; Returned in register A0 (φ₇) to the guest PVM.
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +hc-ok+   0                       "OK = 0: general success.")
(defconstant +hc-none+ (1- (expt 2 64))        "NONE = 2⁶⁴−1: item does not exist.")
(defconstant +hc-what+ (- (expt 2 64) 2)       "WHAT = 2⁶⁴−2: name unknown.")
(defconstant +hc-oob+  (- (expt 2 64) 3)       "OOB  = 2⁶⁴−3: memory index not accessible.")
(defconstant +hc-who+  (- (expt 2 64) 4)       "WHO  = 2⁶⁴−4: index unknown.")
(defconstant +hc-full+ (- (expt 2 64) 5)       "FULL = 2⁶⁴−5: storage full / already allocated.")
(defconstant +hc-core+ (- (expt 2 64) 6)       "CORE = 2⁶⁴−6: core index unknown.")
(defconstant +hc-cash+ (- (expt 2 64) 7)       "CASH = 2⁶⁴−7: insufficient funds.")
(defconstant +hc-low+  (- (expt 2 64) 8)       "LOW  = 2⁶⁴−8: gas limit too low.")
(defconstant +hc-huh+  (- (expt 2 64) 9)       "HUH  = 2⁶⁴−9: invalid operation / already solicited.")

;;; ═══════════════════════════════════════════════════════════════════
;;; Inner PVM result codes (used by ΩK invoke — not A0 return values)
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +pvm-halt+  0 "Inner PVM: halt.")
(defconstant +pvm-panic+ 1 "Inner PVM: panic.")
(defconstant +pvm-fault+ 2 "Inner PVM: page fault.")
(defconstant +pvm-host+  3 "Inner PVM: host-call fault (inner has no host calls).")
(defconstant +pvm-oog+   4 "Inner PVM: out of gas.")

;;; ═══════════════════════════════════════════════════════════════════
;;; Invocation contexts — gate which host calls are available
;;;
;;; GP B.2 (IsAuthorized), B.6 (Refine), B.8 (OnTransfer), B.11 (Accumulate)
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +ctx-is-authorized+ :is-authorized
  "B.2: Only gas(0), fetch(1), log(100).")

(defconstant +ctx-refine+ :refine
  "B.6: gas, fetch, hist-lookup(6), export(7), inner-PVM(8-13), log(100).")

(defconstant +ctx-accumulate+ :accumulate
  "B.11: gas, fetch, lookup, read, write, info(0-5),
   privileged(14-17), svc-mgmt(18-21), preimage-mgmt(22-24),
   yield(25), provide(26), log(100). NO inner-PVM(8-13).")

(defconstant +ctx-on-transfer+ :on-transfer
  "B.8: Same as Accumulate minus bless(14), assign(15), designate(16).")

;;; ═══════════════════════════════════════════════════════════════════
;;; Protocol constants — GP §I.4
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +host-call-gas-cost+ 10
  "Default gas cost per host call (GP B.15: g = 10).")

(defconstant +default-segment-size+ 4104
  "W_G — segment size in bytes (GP §I.4).")

(defconstant +default-max-exports+ 3072
  "W_X — max export segments (GP §I.4).")

(defconstant +service-info-size+ 96
  "Ω_I encoded service info record: 32+40+4+8+12 = 96 bytes.")

;;; Balance constants for threshold computation (GP §9.3 eq 9.8)
;;; a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f)

(defconstant +balance-base+      100 "B_S — basic minimum balance.")
(defconstant +balance-per-item+   10 "B_I — additional per item of elective state.")
(defconstant +balance-per-octet+   1 "B_L — additional per octet of elective state.")

;;; ═══════════════════════════════════════════════════════════════════
;;; FetchKind — GP B.5 (ΩY data kinds)
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +fetch-protocol-params+   0)
(defconstant +fetch-entropy+           1)
(defconstant +fetch-auth-trace+        2)
(defconstant +fetch-any-extrinsic+     3)
(defconstant +fetch-our-extrinsic+     4)
(defconstant +fetch-any-import+        5)
(defconstant +fetch-our-import+        6)
(defconstant +fetch-work-package+      7)
(defconstant +fetch-authorizer+        8)
(defconstant +fetch-auth-token+        9)
(defconstant +fetch-refine-context+   10)
(defconstant +fetch-items-summary+    11)
(defconstant +fetch-any-item-summary+ 12)
(defconstant +fetch-any-payload+      13)
(defconstant +fetch-accumulate-items+ 14)
(defconstant +fetch-any-accum-item+   15)

;;; ═══════════════════════════════════════════════════════════════════
;;; Transfer memo size (GP §9.1)
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +memo-size+ 128 "W_T — memo bytes per transfer.")

;;; ═══════════════════════════════════════════════════════════════════
;;; Integer bounds
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +u32-max+ (1- (expt 2 32)) "2³²−1 = 4294967295.")
