;;;; diagnose-wave.lisp — Replay forks up to pair 52, then trace wave by wave
(in-package #:jotl)

(defvar *forks-dir*
  (or (uiop:getenv "FORKS_DIR")
      (error "Set FORKS_DIR env var")))

(defun replay-to-pair (mgr pairs target-pair)
  "Replay all pairs up to (but not including) TARGET-PAIR.
   Skips mutations (expected errors). Returns pair-num reached."
  (let ((pair-num 0)
        (*chain-log-level* nil))
    (dolist (pair pairs)
      (incf pair-num)
      (when (= pair-num target-pair)
        (return-from replay-to-pair pair-num))
      (let* ((fuzzer-bytes (alexandria:read-file-into-byte-vector (car pair)))
             (target-bytes (alexandria:read-file-into-byte-vector (cdr pair))))
        (multiple-value-bind (msg-type payload) (decode-fuzz-message fuzzer-bytes)
          (multiple-value-bind (exp-type _) (decode-fuzz-message target-bytes)
            (declare (ignore _))
            (case msg-type
              (:peer-info nil)
              (:initialize
               (fuzz-handle-initialize mgr payload)
               (format t "  ~3D  Init~%" pair-num))
              (:import-block
               (if (eq exp-type :error)
                   (format t "  ~3D  skip~%" pair-num)
                   (progn
                     (fuzz-handle-import-block mgr payload)
                     (format t "  ~3D  ✓~%" pair-num)))))))))
    pair-num))

(defun dump-rho-detail (rho label)
  (format t "~%--- ~A ρ ---~%" label)
  (let ((asgn (funcall rho :assignments)))
    (loop for a in asgn for ci from 0 do
      (if a
          (let* ((wr (getf a :report))
                 (timeout (getf a :timeout))
                 (results (getf wr :results)))
            (format t "  core ~D: FILLED timeout=~D core_idx=~D ~D items~%"
                    ci timeout (getf wr :core-index) (length results))
            (dolist (r results)
              (format t "    sid=~D gas=~D result=~A~%"
                      (getf r :service-id) (getf r :accumulate-gas)
                      (if (getf r :result) "present" "nil"))))
          (format t "  core ~D: EMPTY~%" ci)))))

(defun analyze-pair-52 (mgr pair)
  "Deep wave-by-wave analysis of pair 52."
  (let* ((fuzzer-bytes (alexandria:read-file-into-byte-vector (car pair)))
         (target-bytes (alexandria:read-file-into-byte-vector (cdr pair))))
    (multiple-value-bind (msg-type payload) (decode-fuzz-message fuzzer-bytes)
      (declare (ignore msg-type))
      (multiple-value-bind (exp-type exp-payload) (decode-fuzz-message target-bytes)
        (let* ((h   (funcall payload :header))
               (e-t (funcall payload :tickets))
               (e-d (funcall payload :disputes))
               (e-p (funcall payload :preimages))
               (e-a (funcall payload :assurances))
               (e-g (funcall payload :guarantees))
               (parent-hash (funcall h :parent-hash))
               (parent-sigma (fuzz-lookup-state mgr parent-hash)))

          (format t "~%═══ PAIR 52 WAVE ANALYSIS ═══~%")
          (format t "  slot=~D author=~D~%" (funcall h :slot) (funcall h :author-index))
          (format t "  assurances=~D guarantees=~D~%" (length e-a) (length e-g))
          (when (eq exp-type :state-root)
            (format t "  expected root: ~A~%" (bytes-to-hex-string exp-payload)))

          ;; Parent ρ
          (let ((rho (funcall parent-sigma :load :rho)))
            (dump-rho-detail rho "Parent")
            (format t "  parent ρ save: ~D bytes~%" (length (funcall rho :save)))

            ;; Assurances vote count
            (format t "~%--- Assurances detail ---~%")
            (format t "  super-majority threshold = ~D (V=~D)~%" (super-majority) (num-validators))
            (dolist (a e-a)
              (format t "  validator=~D bitfield=~A~%"
                      (getf a :validator-index)
                      (bytes-to-hex-string (ensure-bytes (getf a :bitfield)))))
            (let ((votes (count-core-votes e-a (num-cores))))
              (dotimes (ci (num-cores))
                (format t "  core ~D: ~D votes ~A~%"
                        ci (aref votes ci)
                        (if (>= (aref votes ci) (super-majority)) "→ AVAILABLE" "→ not avail"))))

            ;; WAVE 0
            (let* ((tau (funcall parent-sigma :load :tau))
                   (tau-prime (funcall tau :transition :header h)))
              (format t "~%--- Wave 0: τ' = ~D ---~%" (funcall tau-prime :slot))

              ;; WAVE 1
              (let* ((beta (funcall parent-sigma :load :beta))
                     (eta (funcall parent-sigma :load :eta))
                     (kappa (funcall parent-sigma :load :kappa))
                     (lambda-prev (funcall parent-sigma :load :lambda))
                     (gamma (funcall parent-sigma :load :gamma))
                     (psi (funcall parent-sigma :load :psi))
                     (beta-dagger (funcall beta :transition-dagger :header h))
                     (eta-prime (funcall eta :transition :header h :tau tau :tau-prime tau-prime))
                     (kappa-prime (funcall kappa :transition :tau tau :tau-prime tau-prime :gamma gamma))
                     (lambda-prime (funcall lambda-prev :transition :tau tau :tau-prime tau-prime :kappa kappa))
                     (psi-prime (funcall psi :transition :disputes e-d :tau tau :kappa kappa :lambda-prev lambda-prev))
                     (rho-dagger (funcall rho :transition-dagger :v-list (funcall psi-prime :v-list))))

                (dump-rho-detail rho-dagger "Wave 1: ρ†")

                ;; WAVE 2
                (let* ((iota (funcall parent-sigma :load :iota))
                       (gamma-prime (funcall gamma :transition
                                             :tau tau :tau-prime tau-prime
                                             :tickets e-t :iota iota
                                             :eta-prime eta-prime :kappa-prime kappa-prime
                                             :psi-prime psi-prime)))
                  (validate-header-safrole h tau tau-prime gamma eta eta-prime gamma-prime kappa-prime)
                  (let ((rho-ddagger (funcall rho-dagger :transition-ddagger
                                              :assurances e-a :tau-prime tau-prime
                                              :parent-hash (funcall h :parent-hash)
                                              :kappa kappa)))

                    (dump-rho-detail rho-ddagger "Wave 2: ρ‡")
                    (let ((r-star (funcall rho-ddagger :reported)))
                      (format t "  R* = ~D work reports~%" (length r-star))
                      (dolist (wr r-star)
                        (format t "    core=~D ~D results sids=~A~%"
                                (getf wr :core-index)
                                (length (getf wr :results))
                                (mapcar (lambda (r) (getf r :service-id)) (getf wr :results)))))

                    ;; WAVE 3
                    (let* ((alpha (funcall parent-sigma :load :alpha))
                           (delta (funcall parent-sigma :load :delta))
                           (rho-prime (funcall rho-ddagger :transition
                                               :guarantees e-g :tau-prime tau-prime
                                               :kappa kappa :lambda-prev lambda-prev
                                               :eta eta-prime :psi-prime psi-prime
                                               :recent-blocks beta-dagger
                                               :alpha alpha :delta delta)))

                      (dump-rho-detail rho-prime "Wave 3: ρ'")
                      (format t "  ρ' save: ~D bytes~%" (length (funcall rho-prime :save)))

                      ;; Accumulation
                      (let* ((omega (funcall parent-sigma :load :omega))
                             (xi (funcall parent-sigma :load :xi))
                             (chi (funcall parent-sigma :load :chi))
                             (phi (funcall parent-sigma :load :phi)))
                        (format t "~%--- Wave 3: Accumulation ---~%")
                        (format t "  R* = ~D reports~%" (length (funcall rho-ddagger :reported)))

                        (let ((accum (transition-accumulate
                                      (funcall rho-ddagger :reported)
                                      omega xi delta chi iota phi
                                      tau tau-prime :eta eta-prime :header h)))
                          (format t "  δ† keys: ~D (parent: ~D)~%"
                                  (length (funcall (getf accum :delta-dagger) :save))
                                  (length (funcall delta :save)))

                          ;; WAVE 4: build σ'
                          (let* ((delta-dagger (getf accum :delta-dagger))
                                 (delta-prime (funcall delta-dagger :transition
                                                       :preimages e-p :tau-prime tau-prime))
                                 (phi-prime (getf accum :phi-prime))
                                 (offender-auth-hashes (funcall rho :offender-auth-hashes e-d))
                                 (alpha-prime (funcall alpha :transition
                                                       :tau tau :tau-prime tau-prime
                                                       :phi-prime phi-prime
                                                       :offender-auth-hashes offender-auth-hashes))
                                 (pi-stats (funcall parent-sigma :load :pi))
                                 (pi-prime (funcall pi-stats :transition
                                                    :header h :tau tau :tau-prime tau-prime
                                                    :tickets e-t :preimages e-p
                                                    :assurances e-a :guarantees e-g
                                                    :kappa-prime kappa-prime
                                                    :accum-stats (getf accum :service-stats)
                                                    :r-star (funcall rho-ddagger :reported)))
                                 (beta-prime (funcall beta-dagger :transition
                                                      :header h :guarantees e-g
                                                      :theta-prime (getf accum :commitments))))

                            (format t "~%--- Wave 4: Build σ' ---~%")
                            (format t "  β' save: ~D bytes (parent: ~D)~%"
                                    (length (funcall beta-prime :save))
                                    (length (funcall beta :save)))
                            (format t "  δ' keys: ~D (parent: ~D)~%"
                                    (length (funcall delta-prime :save))
                                    (length (funcall delta :save)))

                            ;; Build σ'
                            (let ((sigma-prime
                                    (make-sigma-state
                                     :alpha (funcall alpha-prime :save)
                                     :beta (funcall beta-prime :save)
                                     :gamma (funcall gamma-prime :save)
                                     :eta (funcall eta-prime :save)
                                     :iota (funcall (getf accum :iota-prime) :save)
                                     :kappa (funcall kappa-prime :save)
                                     :lambda* (funcall lambda-prime :save)
                                     :rho (funcall rho-prime :save)
                                     :tau (funcall tau-prime :save)
                                     :phi (funcall phi-prime :save)
                                     :chi (funcall (getf accum :chi-prime) :save)
                                     :psi (funcall psi-prime :save)
                                     :pi* (funcall pi-prime :save)
                                     :omega (funcall (getf accum :omega-prime) :save)
                                     :xi (funcall (getf accum :xi-prime) :save)
                                     :theta (funcall (getf accum :theta-prime) :save)
                                     :delta-kvs (funcall delta-prime :save))))
                              (format t "~%--- FINAL RESULT ---~%")
                              (format t "  σ' root:    ~A~%"
                                      (bytes-to-hex-string (funcall sigma-prime :state-root)))
                              (when (eq exp-type :state-root)
                                (format t "  expected:   ~A~%"
                                        (bytes-to-hex-string exp-payload))
                                (format t "  match: ~A~%"
                                        (if (equalp (funcall sigma-prime :state-root) exp-payload)
                                            "YES ✓" "NO ✗"))))))))))))))))))

(defun run-wave-diag ()
  (format t "~%═══ WAVE-BY-WAVE DIAGNOSTIC ═══~%")
  (let ((fuzzer-files '())
        (target-files '()))
    (dolist (p (directory (merge-pathnames "*_fuzzer_*.bin" *forks-dir*)))
      (push (namestring p) fuzzer-files))
    (dolist (p (directory (merge-pathnames "*_target_*.bin" *forks-dir*)))
      (push (namestring p) target-files))
    (setf fuzzer-files (sort fuzzer-files #'string<))
    (setf target-files (sort target-files #'string<))
    (let* ((pairs (mapcar #'cons fuzzer-files target-files))
           (mgr (make-fuzz-state-manager)))
      ;; Replay up to pair 52
      (replay-to-pair mgr pairs 52)
      ;; Now analyze pair 52
      (let ((pair-52 (nth 51 pairs)))  ;; 0-indexed
        (analyze-pair-52 mgr pair-52)))))

(run-wave-diag)
(sb-ext:exit :code 0)
