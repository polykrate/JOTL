;;;; diag-gamma.lisp — Diagnose GAMMA divergence on a specific trace step

(in-package #:jotl)

(defvar *step-file*
  (or (uiop:getenv "STEP_FILE")
      (let ((base (asdf:system-source-directory :jotl)))
        (namestring
         (merge-pathnames
          "../jam-conformance/fuzz-reports/0.7.2/traces/1766243493_1163/00000016.bin"
          base)))))

(defun run-diag-gamma ()
  (format t "~%═══ GAMMA DIAGNOSTIC ═══~%")
  (format t "Step file: ~A~%~%" *step-file*)

  (let ((bytes (alexandria:read-file-into-byte-vector *step-file*)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root post-root))

      (let* ((tau        (funcall pre-sigma :load :tau))
             (tau-prime  (funcall tau :transition :header (funcall block-cl :header)))
             (gamma      (funcall pre-sigma :load :gamma))
             (kappa      (funcall pre-sigma :load :kappa))
             (iota       (funcall pre-sigma :load :iota))
             (eta        (funcall pre-sigma :load :eta))
             (psi        (funcall pre-sigma :load :psi))
             (lambda-prev (funcall pre-sigma :load :lambda)))

        (format t "τ = ~D, τ' = ~D~%" (funcall tau :slot) (funcall tau-prime :slot))
        (format t "Epoch change: ~A~%" (funcall tau :epoch-changed? tau-prime))
        (format t "m = ~D, m' = ~D, Y = ~D~%~%"
                (funcall tau :phase) (funcall tau-prime :phase) (closing-offset))

        ;; Wave 1 intermediates
        (let* ((eta-prime    (funcall eta :transition
                                      :header (funcall block-cl :header)
                                      :tau tau :tau-prime tau-prime))
               (kappa-prime  (funcall kappa :transition
                                      :tau tau :tau-prime tau-prime :gamma gamma))
               (psi-prime    (funcall psi :transition
                                      :disputes (funcall block-cl :disputes)
                                      :tau tau :kappa kappa :lambda-prev lambda-prev)))

          (format t "Offenders: ~A~%~%"
                  (let ((off (funcall psi-prime :offenders)))
                    (if off (length off) "NONE")))

          ;; Compute γ'
          (let* ((gamma-prime (funcall gamma :transition
                                       :tau tau :tau-prime tau-prime
                                       :tickets (funcall block-cl :tickets)
                                       :iota iota
                                       :eta-prime eta-prime
                                       :kappa-prime kappa-prime
                                       :psi-prime psi-prime))
                 (expected-gamma (funcall post-sigma :load :gamma)))

            ;; Overall comparison
            (format t "=== γ' comparison ===~%")
            (format t "  computed bytes: ~D~%" (length (funcall gamma-prime :save)))
            (format t "  expected bytes: ~D~%" (length (funcall expected-gamma :save)))
            (format t "  match: ~A~%~%" (equalp (funcall gamma-prime :save)
                                                (funcall expected-gamma :save)))

            ;; Sub-component comparison
            (format t "  γP: ~A~%"
                    (if (equalp (encode-full-validator-sequence (funcall gamma-prime :pending-keys))
                                (encode-full-validator-sequence (funcall expected-gamma :pending-keys)))
                        "MATCH" "DIFFER"))
            (format t "  γZ: ~A~%"
                    (if (equalp (funcall gamma-prime :ring-commitment)
                                (funcall expected-gamma :ring-commitment))
                        "MATCH" "DIFFER"))
            (format t "  γS: ~A~%"
                    (if (equalp (encode-gamma-sealing (funcall gamma-prime :sealing))
                                (encode-gamma-sealing (funcall expected-gamma :sealing)))
                        "MATCH" "DIFFER"))
            (format t "  γA: ~A~%~%"
                    (if (equalp (funcall gamma-prime :accumulator)
                                (funcall expected-gamma :accumulator))
                        "MATCH" "DIFFER"))

            ;; Cross-checks
            (format t "=== Cross-checks ===~%")
            (format t "  γ'P == pre-ι: ~A~%"
                    (equalp (encode-full-validator-sequence (funcall gamma-prime :pending-keys))
                            (encode-full-validator-sequence (funcall iota :validators))))
            (format t "  κ' == old γP: ~A~%"
                    (equalp (funcall kappa-prime :save)
                            (encode-full-validator-sequence (funcall gamma :pending-keys))))
            (format t "  η'₂: ~A~%~%"
                    (subseq (bytes-to-hex-string (funcall eta-prime :vrf-entropy)) 0 16))

            ;; Ring commitment from expected keys
            (let* ((exp-bander-keys (mapcar (lambda (k) (getf k :bandersnatch))
                                            (funcall expected-gamma :pending-keys)))
                   (key-vector (coerce exp-bander-keys 'vector))
                   (expected-gz (funcall expected-gamma :ring-commitment))
                   (our-gz (funcall gamma-prime :ring-commitment))
                   (ffi-gz (jam.ffi:bandersnatch-compute-ring-commitment key-vector)))

              (format t "=== Ring commitment verification ===~%")
              (format t "  FFI(expected γ'P): ~A~%"
                      (if ffi-gz (subseq (bytes-to-hex-string ffi-gz) 0 32) "NIL"))
              (format t "  Expected γ'Z:      ~A~%"
                      (subseq (bytes-to-hex-string expected-gz) 0 32))
              (format t "  Our γ'Z:           ~A~%"
                      (subseq (bytes-to-hex-string our-gz) 0 32))
              (format t "  FFI matches expected: ~A~%~%" (equalp ffi-gz expected-gz))

              ;; Show keys
              (format t "=== Keys being tested (~D validators) ===~%" (length key-vector))
              (dotimes (i (length key-vector))
                (format t "  [~D] ~A~A~%" i
                        (bytes-to-hex-string (elt key-vector i))
                        (if (every #'zerop (elt key-vector i)) " *** ZERO ***" "")))

              ;; === TEST DIFFERENT RING SIZES ===
              (format t "~%=== Ring commitment with different ring_size values ===~%")
              (format t "  Expected γ'Z: ~A~%~%" (bytes-to-hex-string expected-gz))
              (dolist (rs '(6 12 1023 1024 2048))
                (format t "  ring_size=~5D: " rs)
                (force-output)
                (let ((result (jam.ffi:bandersnatch-compute-ring-commitment-padded
                               key-vector rs)))
                  (format t "~A  ~A~%"
                          (if result
                              (subseq (bytes-to-hex-string result) 0 32)
                              "FAILED                         ")
                          (if (and result (equalp result expected-gz))
                              "*** MATCH ***"
                              "")))))

            ;; Fallback keys
            (format t "~%=== Fallback key computation ===~%")
            (let* ((fb-keys (funcall kappa-prime :fallback-keys
                                     (funcall eta-prime :vrf-entropy)))
                   (expected-s (funcall expected-gamma :sealing)))
              (format t "  Computed ~D fallback keys~%" (length fb-keys))
              (format t "  Expected variant: ~A~%" (getf expected-s :variant))
              (when (eq (getf expected-s :variant) :keys)
                (let ((exp-keys (getf expected-s :data)))
                  (format t "  Expected ~D keys~%" (length exp-keys))
                  (dotimes (i (min (length fb-keys) (length exp-keys)))
                    (unless (equalp (nth i fb-keys) (nth i exp-keys))
                      (format t "    key ~D DIFFERS~%" i))))))))))))

(run-diag-gamma)
(sb-ext:exit :code 0)
