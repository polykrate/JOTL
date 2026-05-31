;;;; package.lisp — JAM Host-Call Layer (GP Appendix B)
;;;;
;;;; Transfers the Rust Ω implementations to pure Common Lisp.
;;;; Operates on top of the JamVM (GP Appendix A) infrastructure.

(defpackage #:jam-host
  (:use #:cl #:jamvm)
  (:documentation
   "JAM Host-Call Layer — Pure Common Lisp Ω implementations (GP Appendix B).

    Implements GP Appendix B — all host calls (Ω₀–Ω₂₅) and context.
    Uses JamVM (GP Appendix A) for PVM execution; no polkavm dependency.

    Key entry points:
      HOST-DISPATCH     — dispatch ecalli id → Ω function
      MAKE-HOST-CONTEXT — create host context with service state
      HOST-RUN          — run VM with integrated host-call handling")
  (:export
   ;; ── B.1 Result constants ────────────────────────
   #:+hc-ok+   #:+hc-none+ #:+hc-what+ #:+hc-oob+
   #:+hc-who+  #:+hc-full+ #:+hc-core+ #:+hc-cash+
   #:+hc-low+  #:+hc-huh+

   ;; ── Context ─────────────────────────────────────
   #:host-context
   #:make-host-context

   ;; ── Service account ─────────────────────────────
   #:service-account
   #:make-service-account
   #:encode-service-info

   ;; ── Dispatch ────────────────────────────────────
   #:host-dispatch

   ;; ── Integrated run ──────────────────────────────
   #:host-run

   ;; ── Checkpoint / Collapse ───────────────────────
   #:checkpoint-save
   #:checkpoint-collapse
   #:accumulate-checkpoint
   #:make-accumulate-checkpoint

   ;; ── Invocation contexts ─────────────────────────
   #:+ctx-is-authorized+
   #:+ctx-refine+
   #:+ctx-accumulate+
   #:+ctx-on-transfer+

   ;; ── Inner PVM result codes ────────────────────
   #:+pvm-halt+ #:+pvm-panic+ #:+pvm-fault+ #:+pvm-host+ #:+pvm-oog+

   ;; ── Service management ────────────────────────
   #:jam-transfer
   #:make-jam-transfer
   #:empower-state
   #:make-empower-state

   ;; ── Service ID computation (B.10 + B.14) ────
   #:raw-next-service-id
   #:compute-next-service-id
   #:check-service-id
   #:advance-service-id
   #:+service-index-min+
   #:+service-id-modulus+

   ;; ── Helpers ───────────────────────────────────
   #:read-guest
   #:write-guest
   #:storage-hash-key

   ;; ── PVM Adapter (replaces jam.ffi) ──────────
   #:lisp-pvm-run-accumulate
   #:encode-work-item-record
   #:encode-transfer-record
   #:encode-accumulate-params
   #:encode-gp-constants
   #:populate-host-context
   #:collect-effects
   #:blake2b-256

   ;; ── Context accessors ──────────────────────
   #:hctx-storage
   #:hctx-preimages
   #:hctx-lookup
   #:hctx-candidate-lookups
   #:hctx-yield-output
   #:hctx-balance
   #:hctx-transfers
   #:hctx-ejected-services
   #:hctx-created-services
   #:hctx-upgrades
   #:hctx-provided-preimages
   #:hctx-empower
   #:hctx-designated-validators
   #:hctx-designate-service
   #:hctx-items-count
   #:hctx-footprint
   #:hctx-code-hash
   #:hctx-min-accum-gas
   #:hctx-min-memo-gas
   #:hctx-service-id
   #:hctx-debug-trace
   #:hctx-host-call-log
   #:hctx-debug-log))
