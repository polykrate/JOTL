;;;; dispatch.lisp — Host-call dispatch table (GP B.15–B.16)
;;;;
;;;; Ported from crypto/jam-crypto/src/pvm/host_calls.rs dispatch().
;;;; Maps ecalli index → Ω function, handles gas gating and context gating.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; Omega function registry
;;;
;;; Each Ω function has signature:
;;;   (omega-fn vm ctx) → :continue | :fault | :oog
;;;
;;; Register A0 is set by the omega for result codes (HC_OK, HC_NONE, …).
;;; ═══════════════════════════════════════════════════════════════════

(defvar *omega-table* (make-hash-table)
  "Map: ecalli-id (u32) → omega function (lambda (vm ctx) → keyword).")

(defmacro defomega (id name (vm ctx) &body body)
  "Define and register an omega host-call handler for ecalli ID."
  `(progn
     (defun ,name (,vm ,ctx)
       ,@body)
     (setf (gethash ,id *omega-table*) #',name)))

;;; ═══════════════════════════════════════════════════════════════════
;;; host-dispatch — THE canonical dispatch function
;;;
;;; GP B.15: ϱ' = ϱ − g (g = 10 for all host calls)
;;; GP B.16: if ϱ < g → (∞, φ, μ, s) — OOG, no mutations
;;;
;;; Context gating: if host call not allowed in invocation context,
;;; charge gas but leave registers untouched (GP B.2/B.6).
;;; ═══════════════════════════════════════════════════════════════════

(defun host-dispatch (vm ctx id)
  "Dispatch host call ID for VM with host context CTX.
   Returns :continue, :fault, or :oog.
   Called by vm-run-host's f function on ecalli."
  (let ((gas (pvm-gas vm))
        (cost +host-call-gas-cost+))

    ;; ── B.16: OOG gating ──────────────────────────────
    (when (< gas cost)
      (decf (pvm-gas vm) cost)  ; go negative to signal OOG
      (return-from host-dispatch :oog))

    ;; ── B.15: ϱ' = ϱ − g ──────────────────────────────
    (decf (pvm-gas vm) cost)

    ;; ── Context gating ─────────────────────────────────
    (unless (context-allows-p ctx id)
      ;; Blocked: charge gas, don't touch registers, continue
      (when (hctx-debug-trace ctx)
        (push (list id gas (- gas cost) (reg vm +a0+)
                    (hash-table-count (hctx-storage ctx)))
              (hctx-host-call-log ctx)))
      (return-from host-dispatch :continue))

    ;; ── Dispatch to Ω function ─────────────────────────
    (let ((omega-fn (gethash id *omega-table*)))
      (unless omega-fn
        ;; B.11 fallback: φ'₇ = WHAT
        (set-reg vm +a0+ +hc-what+)
        (when (hctx-debug-trace ctx)
          (push (list :id id :gas-before gas :gas-after (- gas cost)
                      :a0-before (reg vm +a0+) :a0-after +hc-what+
                      :result :unknown-id)
                (hctx-host-call-log ctx)))
        (return-from host-dispatch :continue))

      ;; ── Capture pre-call register state for debug ──
      (let ((pre-a0 (reg vm +a0+))
            (pre-a1 (reg vm +a1+))
            (pre-a2 (reg vm +a2+))
            (pre-a3 (reg vm +a3+))
            (pre-a4 (reg vm +a4+))
            (pre-a5 (reg vm +a5+)))

        (let ((result (funcall omega-fn vm ctx)))

          ;; ── Debug trace BEFORE+AFTER dispatch ──────────
          (when (hctx-debug-trace ctx)
            (format *error-output*
                    "~&[HC] sid=~D id=~D a0=~D→~D a1=~D→~D a2=~D a3=~D a4=~D a5=~D result=~A~%"
                    (hctx-service-id ctx) id
                    pre-a0 (reg vm +a0+) pre-a1 (reg vm +a1+)
                    pre-a2 pre-a3 pre-a4 pre-a5
                    result)
            (push (list :id id :gas-before gas :gas-after (- gas cost)
                        :a0-before pre-a0 :a1-before pre-a1
                        :a2-before pre-a2 :a3-before pre-a3
                        :a4-before pre-a4 :a5-before pre-a5
                        :a0-after (reg vm +a0+)
                        :a1-after (reg vm +a1+)
                        :storage-cnt (hash-table-count (hctx-storage ctx))
                        :result result)
                  (hctx-host-call-log ctx)))

          result)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; host-run — Full execution with integrated host-call handling
;;;
;;; Wraps vm-run-host with host-dispatch as the handler function.
;;; This is the top-level entry point for running a PVM program
;;; with full host-call support.
;;; ═══════════════════════════════════════════════════════════════════

(defun host-run (vm ctx)
  "Run VM with full host-call handling via CTX.
   Returns (values exit-status exit-arg ctx)."
  (vm-run-host vm
               (lambda (h vm x)
                 (let ((result (host-dispatch vm x h)))
                   (case result
                     (:continue (values :continue x))
                     (:fault    (values :panic x))
                     (:oog      (values :oog x))
                     (t         (values :panic x)))))
               ctx))
