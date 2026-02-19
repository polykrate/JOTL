;;;; package.lisp — JAM Host-Call Layer (GP Appendix B)
;;;;
;;;; Transfers the Rust Ω implementations to pure Common Lisp.
;;;; Operates on top of the JamVM (GP Appendix A) infrastructure.

(defpackage #:jam-host
  (:use #:cl #:jamvm)
  (:documentation
   "JAM Host-Call Layer — Pure Common Lisp Ω implementations (GP Appendix B).

    Ported from crypto/jam-crypto/src/pvm/{context.rs, host_calls.rs}.
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

   ;; ── Helpers ───────────────────────────────────
   #:read-guest
   #:write-guest
   #:storage-hash-key))
