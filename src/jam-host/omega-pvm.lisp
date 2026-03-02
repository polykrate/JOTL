;;;; omega-pvm.lisp — Ω₈-₁₃ Inner PVM operations
;;;;
;;;; Implements GP Appendix B.17–B.19 (PVM spawning and invocation).
;;;; Uses JamVM natively — no polkavm dependency.
;;;; Inner PVM machines are JamVM `pvm` structs stored in a hash table.

(in-package #:jam-host)

;;; ═══════════════════════════════════════════════════════════════════
;;; Inner machine helper
;;; ═══════════════════════════════════════════════════════════════════

(defun next-machine-id (ctx)
  "Allocate the next available inner machine index."
  (let ((n 0))
    (loop while (gethash n (hctx-inner-machines ctx)) do (incf n))
    n))

;;; ═══════════════════════════════════════════════════════════════════
;;; Inner memory access helpers
;;;
;;; These operate on an inner JamVM pvm struct's memory,
;;; distinct from the outer VM's read-guest/write-guest.
;;; ═══════════════════════════════════════════════════════════════════

(defun read-guest-inner (inner-vm addr len)
  "Read LEN bytes from inner PVM memory. Returns octet vector or NIL."
  (when (zerop len)
    (return-from read-guest-inner
      (make-array 0 :element-type '(unsigned-byte 8))))
  (let ((mem (pvm-memory inner-vm)))
    (when mem
      (multiple-value-bind (data ok) (mem-read mem addr len)
        (declare (ignore ok))
        (if data data nil)))))

(defun write-guest-inner (inner-vm addr data)
  "Write DATA to inner PVM memory. Returns T or NIL."
  (when (zerop (length data)) (return-from write-guest-inner t))
  (let ((mem (pvm-memory inner-vm)))
    (when mem
      (multiple-value-bind (ok fault-addr) (mem-write mem addr data)
        (declare (ignore fault-addr))
        ok))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 8 — ΩM Make-pvm
;;;
;;; machine(p_O, p_Z, i) → n | HUH
;;; A0=p_O (blob addr), A1=p_Z (blob len), A2=i (initial PC)
;;;
;;; Reads program blob from outer guest, debobs it, creates inner PVM.
;;; Returns allocated machine index n, or HUH if deblob fails.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 8 omega-make-pvm (vm ctx)
  "ΩM: Create an inner PVM machine from a program blob."
  (let* ((p-o  (u32 (reg vm +a0+)))
         (p-z  (u32 (reg vm +a1+)))
         (pc-i (u32 (reg vm +a2+))))

    ;; Read blob from outer guest memory
    (let ((blob (read-guest vm p-o p-z)))
      (unless blob (return-from omega-make-pvm :fault))

      ;; Deblob — uses JamVM's make-vm (parses blob + initializes memory)
      (let ((inner-vm (make-vm blob)))
        (unless inner-vm
          (set-reg vm +a0+ +hc-huh+)
          (return-from omega-make-pvm :continue))

        ;; Allocate machine index
        (let ((n (next-machine-id ctx)))
          ;; Store as plist: (:vm inner-pvm :initial-pc pc-i)
          (setf (gethash n (hctx-inner-machines ctx))
                (list :vm inner-vm :initial-pc pc-i))
          (set-reg vm +a0+ (u64 n))
          :continue)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 9 — ΩP Peek-pvm
;;;
;;; peek(n, o, s, z) → OK | WHO | OOB
;;; A0=n (machine), A1=o (outer dest), A2=s (inner src), A3=z (len)
;;;
;;; Copy z bytes from inner machine memory at s to outer guest at o.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 9 omega-peek-pvm (vm ctx)
  "ΩP: Read from inner PVM memory into outer guest memory."
  (let* ((n (u32 (reg vm +a0+)))
         (o (u32 (reg vm +a1+)))
         (s (u32 (reg vm +a2+)))
         (z (u32 (reg vm +a3+))))

    ;; n ∉ K(m) → WHO
    (let ((entry (gethash n (hctx-inner-machines ctx))))
      (unless entry
        (set-reg vm +a0+ +hc-who+)
        (return-from omega-peek-pvm :continue))

      (let ((inner-vm (getf entry :vm)))
        ;; Read from inner machine memory
        (let ((data (read-guest-inner inner-vm s z)))
          (unless data
            (set-reg vm +a0+ +hc-oob+)
            (return-from omega-peek-pvm :continue))

          ;; Write to outer guest
          (when (plusp z)
            (unless (write-guest vm o data)
              (return-from omega-peek-pvm :fault)))

          (set-reg vm +a0+ +hc-ok+)
          :continue)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 10 — ΩO Poke-pvm
;;;
;;; poke(n, s, o, z) → OK | WHO | OOB
;;; A0=n, A1=s (outer src), A2=o (inner dest), A3=z (len)
;;;
;;; Copy z bytes from outer guest at s to inner machine memory at o.
;;; ═══════════════════════════════════════════════════════════════════

(defomega 10 omega-poke-pvm (vm ctx)
  "ΩO: Write to inner PVM memory from outer guest memory."
  (let* ((n (u32 (reg vm +a0+)))
         (s (u32 (reg vm +a1+)))
         (o (u32 (reg vm +a2+)))
         (z (u32 (reg vm +a3+))))

    ;; Read from outer guest
    (let ((data (read-guest vm s z)))
      (unless data (return-from omega-poke-pvm :fault))

      ;; n ∉ K(m) → WHO
      (let ((entry (gethash n (hctx-inner-machines ctx))))
        (unless entry
          (set-reg vm +a0+ +hc-who+)
          (return-from omega-poke-pvm :continue))

        (let ((inner-vm (getf entry :vm)))
          ;; Write to inner machine memory
          (when (plusp z)
            (unless (write-guest-inner inner-vm o data)
              (set-reg vm +a0+ +hc-oob+)
              (return-from omega-poke-pvm :continue)))

          (set-reg vm +a0+ +hc-ok+)
          :continue)))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 11 — ΩZ Pages inner-pvm memory
;;;
;;; pages(n, p, c, r) → OK | WHO | HUH
;;; A0=n, A1=p (start page), A2=c (page count), A3=r (protection mode)
;;;
;;; r = 0: inaccessible
;;; r = 1: zero + read-only
;;; r = 2: zero + read-write
;;; r = 3: keep data + read-only
;;; r = 4: keep data + read-write
;;; ═══════════════════════════════════════════════════════════════════

(defomega 11 omega-pages-pvm (vm ctx)
  "ΩZ: Manage inner PVM memory pages."
  (let* ((n (u32 (reg vm +a0+)))
         (p (u32 (reg vm +a1+)))
         (c (u32 (reg vm +a2+)))
         (r (u32 (reg vm +a3+))))

    ;; n ∉ K(m) → WHO
    (let ((entry (gethash n (hctx-inner-machines ctx))))
      (unless entry
        (set-reg vm +a0+ +hc-who+)
        (return-from omega-pages-pvm :continue))

      ;; Parameter validation: r > 4 ∨ p < 16 ∨ p+c ≥ 2³²/Z_P → HUH
      (let ((max-pages (floor +u32-max+ +page-size+)))
        (when (or (> r 4) (< p 16) (>= (+ p c) max-pages))
          (set-reg vm +a0+ +hc-huh+)
          (return-from omega-pages-pvm :continue)))

      (let* ((inner-vm (getf entry :vm))
             (inner-mem (when inner-vm (pvm-memory inner-vm))))

        (unless inner-mem
          (set-reg vm +a0+ +hc-huh+)
          (return-from omega-pages-pvm :continue))

        ;; r > 2 → pages must already be accessible
        (when (> r 2)
          (dotimes (i c)
            (let* ((page-idx (+ p i))
                   (mode (jamvm::page-access inner-mem page-idx)))
              (when (eq mode :inaccessible)
                (set-reg vm +a0+ +hc-huh+)
                (return-from omega-pages-pvm :continue)))))

        ;; Apply page changes
        (dotimes (i c)
          (let ((page-idx (+ p i)))
            (ecase r
              ;; r=0: make inaccessible
              (0 (setf (aref (jamvm::mem-pages inner-mem) page-idx) nil)
                 (setf (aref (jamvm::mem-access inner-mem) page-idx) :inaccessible))
              ;; r=1: zero + read-only
              (1 (let ((page (jamvm::ensure-page inner-mem page-idx)))
                   (fill page 0))
                 (setf (aref (jamvm::mem-access inner-mem) page-idx) :read-only))
              ;; r=2: zero + read-write
              (2 (let ((page (jamvm::ensure-page inner-mem page-idx)))
                   (fill page 0))
                 (setf (aref (jamvm::mem-access inner-mem) page-idx) :read-write))
              ;; r=3: keep data + read-only
              (3 (setf (aref (jamvm::mem-access inner-mem) page-idx) :read-only))
              ;; r=4: keep data + read-write
              (4 (setf (aref (jamvm::mem-access inner-mem) page-idx) :read-write)))))

        (set-reg vm +a0+ +hc-ok+)
        :continue))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 12 — ΩK Kickoff-pvm (invoke)
;;;
;;; invoke(n, o) → HALT | HOST h | FAULT x | OOG | PANIC | WHO
;;; A0=n, A1=o (memory offset for I/O: 8 bytes gas + 13×8 bytes regs = 112)
;;; ═══════════════════════════════════════════════════════════════════

(defconstant +invoke-io-size+ 112
  "8 bytes gas + 13×8 bytes registers = 112 bytes for ΩK I/O.")

(defun parse-invoke-io (buf)
  "Parse 112-byte I/O buffer into (values gas regs-array).
   Gas is signed 64-bit, regs is 13-element u64 array."
  (let ((g (let ((raw 0))
             (dotimes (i 8) (setf raw (logior raw (ash (aref buf i) (* 8 i)))))
             ;; Interpret as signed 64-bit
             (if (>= raw (expt 2 63)) (- raw (expt 2 64)) raw)))
        (w (make-array 13 :element-type '(unsigned-byte 64) :initial-element 0)))
    (dotimes (i 13)
      (let ((val 0)
            (base (+ 8 (* i 8))))
        (dotimes (j 8)
          (setf val (logior val (ash (aref buf (+ base j)) (* 8 j)))))
        (setf (aref w i) val)))
    (values g w)))

(defun encode-invoke-io (gas regs)
  "Encode gas + 13 registers into 112-byte I/O buffer."
  (let ((buf (make-array +invoke-io-size+
                         :element-type '(unsigned-byte 8)
                         :initial-element 0))
        ;; Encode gas as unsigned for LE bytes
        (g-raw (u64 gas)))
    (dotimes (i 8)
      (setf (aref buf i) (logand (ash g-raw (* -8 i)) #xFF)))
    (dotimes (r 13)
      (let ((val (aref regs r))
            (base (+ 8 (* r 8))))
        (dotimes (j 8)
          (setf (aref buf (+ base j)) (logand (ash val (* -8 j)) #xFF)))))
    buf))

(defomega 12 omega-invoke-pvm (vm ctx)
  "ΩK: Invoke an inner PVM machine (run Ψ on it)."
  (let* ((n (u32 (reg vm +a0+)))
         (o (u32 (reg vm +a1+))))

    ;; Read 112 bytes: E_8(g) ~ E_8(w) from μ_{o…+112}
    (let ((io-buf (read-guest vm o +invoke-io-size+)))
      (unless io-buf (return-from omega-invoke-pvm :fault))

      ;; Parse g and w
      (multiple-value-bind (g w) (parse-invoke-io io-buf)

        ;; n ∉ K(m) → WHO
        (let ((entry (gethash n (hctx-inner-machines ctx))))
          (unless entry
            (set-reg vm +a0+ +hc-who+)
            (return-from omega-invoke-pvm :continue))

          ;; Set up inner PVM: gas, registers, PC
          (let ((inner-vm (getf entry :vm))
                (initial-pc (getf entry :initial-pc)))
            (setf (pvm-gas inner-vm) g
                  (pvm-pc inner-vm) initial-pc
                  (pvm-status inner-vm) nil)
            (dotimes (i 13)
              (set-reg inner-vm i (aref w i)))

            ;; Run Ψ(inner)
            (multiple-value-bind (status exit-arg) (vm-run inner-vm)

              ;; Read back g' and w'
              (let ((w-prime (make-array 13 :element-type '(unsigned-byte 64)
                                            :initial-element 0)))
                (dotimes (i 13)
                  (setf (aref w-prime i) (reg inner-vm i)))

                ;; Write E_8(g') ~ E_8(w') back to μ_{o…+112}
                (let ((out-buf (encode-invoke-io (pvm-gas inner-vm) w-prime)))
                  (write-guest vm o out-buf))

                ;; Update m*[n]_i based on exit condition
                (let ((inner-pc (pvm-pc inner-vm)))
                  (case status
                    (:host-call
                     ;; m*[n]_i = i' + skip(i') + 1
                     (let ((skip (skip-distance inner-vm inner-pc)))
                       (setf (getf (gethash n (hctx-inner-machines ctx)) :initial-pc)
                             (u32 (+ inner-pc 1 skip)))))
                    (t
                     (setf (getf (gethash n (hctx-inner-machines ctx)) :initial-pc)
                           inner-pc))))

                ;; Map outcome to GP result codes
                (case status
                  (:halt
                   (set-reg vm +a0+ (u64 +pvm-halt+))
                   :continue)
                  (:host-call
                   (set-reg vm +a0+ (u64 +pvm-host+))
                   (set-reg vm +a1+ (u64 exit-arg))
                   :continue)
                  (:page-fault
                   (set-reg vm +a0+ (u64 +pvm-fault+))
                   (set-reg vm +a1+ (u64 exit-arg))
                   :continue)
                  (:oog
                   (set-reg vm +a0+ (u64 +pvm-oog+))
                   :continue)
                  (t ; panic or any other
                   (set-reg vm +a0+ (u64 +pvm-panic+))
                   :continue))))))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; 13 — ΩX Expunge-pvm
;;;
;;; expunge(n) → initial_pc | WHO
;;; A0=n
;;; ═══════════════════════════════════════════════════════════════════

(defomega 13 omega-expunge-pvm (vm ctx)
  "ΩX: Remove an inner PVM machine and return its PC."
  (let ((n (u32 (reg vm +a0+))))
    (let ((entry (gethash n (hctx-inner-machines ctx))))
      (cond
        ((null entry)
         (set-reg vm +a0+ +hc-who+))
        (t
         (let ((pc (getf entry :initial-pc)))
           (remhash n (hctx-inner-machines ctx))
           (set-reg vm +a0+ (u64 pc)))))
      :continue)))
