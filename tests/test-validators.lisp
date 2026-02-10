(in-package :jotl)

(defun make-test-validators (n)
  (loop for i from 0 below n
        collect (let ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element i)))
                  (list :bandersnatch key
                        :ed25519 key
                        :bls (make-array 144 :element-type '(unsigned-byte 8) :initial-element i)
                        :metadata (make-array 128 :element-type '(unsigned-byte 8) :initial-element i)))))

(defun run-validator-tests ()
  (format t "~%=== Validator closures test ===~%")
  (let* ((vals (make-test-validators 6))
         (pass 0) (fail 0)
         ;; Build all three closures
         (iota  (make-iota-state :validators vals))
         (kappa (make-kappa-state :validators vals))
         (lam   (make-lambda-state :validators vals))
         ;; Encode
         (iota-bytes  (funcall iota :encoded))
         (kappa-bytes (funcall kappa :encoded))
         (lam-bytes   (funcall lam :encoded))
         ;; Decode back
         (iota-back  (funcall (make-iota-state) :decode iota-bytes 0))
         (kappa-back (funcall (make-kappa-state) :decode kappa-bytes 0))
         (lam-back   (funcall (make-lambda-state) :decode lam-bytes 0)))
    (flet ((check (name ok)
             (if ok
                 (progn (incf pass) (format t "  ✅ ~A~%" name))
                 (progn (incf fail) (format t "  ✗ ~A~%" name)))))

      ;; ── Types ──
      (check "ι type" (eq (funcall iota :type) :iota-state))
      (check "κ type" (eq (funcall kappa :type) :kappa-state))
      (check "λ type" (eq (funcall lam :type) :lambda-state))

      ;; ── Encoded sizes ──
      (check "ι encoded = 6×336" (= (length iota-bytes) (* 6 336)))
      (check "κ encoded = 6×336" (= (length kappa-bytes) (* 6 336)))
      (check "λ encoded = 6×336" (= (length lam-bytes) (* 6 336)))

      ;; ── Validator count (raw + :count) ──
      (check "ι 6 validators" (= (length (funcall iota :validators)) 6))
      (check "κ 6 validators" (= (length (funcall kappa :validators)) 6))
      (check "λ 6 validators" (= (length (funcall lam :validators)) 6))
      (check "ι :count = 6" (= (funcall iota :count) 6))
      (check "κ :count = 6" (= (funcall kappa :count) 6))
      (check "λ :count = 6" (= (funcall lam :count) 6))

      ;; ── :validator-at ──
      (check "κ :validator-at 0" (equalp (funcall kappa :validator-at 0) (first vals)))
      (check "κ :validator-at 5" (equalp (funcall kappa :validator-at 5) (fifth (cdr vals))))
      (check "κ :validator-at 6 = NIL" (null (funcall kappa :validator-at 6)))

      ;; ── :ed25519-key ──
      (check "κ :ed25519-key 0" (equalp (funcall kappa :ed25519-key 0)
                                         (getf (first vals) :ed25519)))
      (check "ι :ed25519-key 3" (equalp (funcall iota :ed25519-key 3)
                                         (getf (fourth vals) :ed25519)))
      (check "κ :ed25519-key 6 = NIL" (null (funcall kappa :ed25519-key 6)))

      ;; ── :bandersnatch-key ──
      (check "κ :bandersnatch-key 0" (equalp (funcall kappa :bandersnatch-key 0)
                                              (getf (first vals) :bandersnatch)))
      (check "λ :bandersnatch-key 2" (equalp (funcall lam :bandersnatch-key 2)
                                              (getf (third vals) :bandersnatch)))
      (check "κ :bandersnatch-key 6 = NIL" (null (funcall kappa :bandersnatch-key 6)))

      ;; ── :all-ed25519-keys ──
      (check "κ :all-ed25519-keys length" (= (length (funcall kappa :all-ed25519-keys)) 6))
      (check "κ :all-ed25519-keys first" (equalp (first (funcall kappa :all-ed25519-keys))
                                                   (getf (first vals) :ed25519)))

      ;; ── Roundtrip ──
      (check "ι roundtrip" (equalp (funcall iota-back :encoded) iota-bytes))
      (check "κ roundtrip" (equalp (funcall kappa-back :encoded) kappa-bytes))
      (check "λ roundtrip" (equalp (funcall lam-back :encoded) lam-bytes))

      ;; ── Same data → same bytes ──
      (check "ι=κ=λ same bytes" (and (equalp iota-bytes kappa-bytes)
                                      (equalp kappa-bytes lam-bytes)))

      ;; ── Sigma byte store + Merkle (σ owns C(n) mapping) ──
      (let ((sigma (make-sigma-state :iota iota-bytes :kappa kappa-bytes :lambda* lam-bytes)))
        ;; σ stores raw bytes
        (check "σ :segment :iota" (equalp (funcall sigma :segment :iota) iota-bytes))
        (check "σ :segment :kappa" (equalp (funcall sigma :segment :kappa) kappa-bytes))
        (check "σ :segment :lambda" (equalp (funcall sigma :segment :lambda) lam-bytes))
        ;; Merkle KVs
        (let ((kvs (funcall sigma :merkle-kvs)))
          (check "σ merkle-kvs contains ι" (assoc +C7+ kvs :test #'equalp))
          (check "σ merkle-kvs ι bytes" (equalp (cdr (assoc +C7+ kvs :test #'equalp)) iota-bytes))
          (check "σ merkle-kvs κ key" (assoc +C8+ kvs :test #'equalp))
          (check "σ merkle-kvs λ key" (assoc +C9+ kvs :test #'equalp)))
        ;; σ :load dispatch
        (check "σ :load :iota" (functionp (funcall sigma :load :iota)))
        (check "σ :load :kappa" (functionp (funcall sigma :load :kappa)))
        (check "σ :load :lambda" (functionp (funcall sigma :load :lambda))))

      ;; ── Standalone decoder functions ──
      (multiple-value-bind (decoded consumed) (decode-iota-state iota-bytes 0)
        (check "decode-iota-state roundtrip" (and (= consumed (length iota-bytes))
                                                   (equalp (funcall decoded :encoded) iota-bytes))))
      (multiple-value-bind (decoded consumed) (decode-kappa-state kappa-bytes 0)
        (check "decode-kappa-state roundtrip" (and (= consumed (length kappa-bytes))
                                                    (equalp (funcall decoded :encoded) kappa-bytes))))

      ;; ── Transitions ──
      (let* ((tau (make-tau-state :slot 11))
             (tau-prime-epoch (make-tau-state :slot 12))    ;; epoch change (tiny: E=12)
             (tau-prime-same  (make-tau-state :slot 10))    ;; no epoch change
             (new-vals (make-test-validators 3))
             (fake-gamma (lambda (&rest args)
                           (case (car args)
                             (:pending-keys new-vals)
                             (t nil)))))

        ;; κ transition: epoch → gets γ pending-keys
        (let ((kp (funcall kappa :transition :tau tau :tau-prime tau-prime-epoch :gamma fake-gamma)))
          (check "κ epoch→new keys (3)" (= (length (funcall kp :validators)) 3))
          (check "κ epoch→different bytes" (not (equalp (funcall kp :encoded) kappa-bytes))))

        ;; κ transition: no epoch → identity
        (let ((kp (funcall kappa :transition :tau tau :tau-prime tau-prime-same :gamma fake-gamma)))
          (check "κ same→identity" (equalp (funcall kp :encoded) kappa-bytes)))

        ;; λ transition: epoch → takes κ's validators
        (let ((lp (funcall lam :transition :tau tau :tau-prime tau-prime-epoch :kappa kappa)))
          (check "λ epoch→gets κ" (equalp (funcall lp :encoded) kappa-bytes)))

        ;; λ transition: no epoch → identity
        (let ((lp (funcall lam :transition :tau tau :tau-prime tau-prime-same :kappa kappa)))
          (check "λ same→identity" (equalp (funcall lp :encoded) lam-bytes))))

      (format t "~%  Validators: ~D/~D passed~%" pass (+ pass fail))
      (when (> fail 0)
        (format t "  ✗ ~D FAILED~%" fail)))))

(run-validator-tests)
