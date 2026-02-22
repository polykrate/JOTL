;;;; diag-block82.lisp — Deep diagnostic for block 82 beta+theta divergence

(in-package #:jotl)

(defun diag-block82 ()
  (let* ((dir "tests/jamtestvectors/traces/fuzzy/")
         (step-path (trace-block-path dir 82))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root post-root))
      (let ((*chain-log-level* nil))
        (declare (special *chain-log-level*))

        ;; Enable debug tracing to capture host call logs
        (let ((*debug-pvm-trace* t))
          (declare (special *debug-pvm-trace*))
          (multiple-value-bind (sigma-prime computed-root)
              (import-block pre-sigma block-cl)
            (declare (ignore computed-root))

            ;; === THETA comparison ===
            (format t "~%═══ THETA (θ) ═══~%")
            (let ((exp-theta (funcall post-sigma :segment :theta))
                  (got-theta (funcall sigma-prime :segment :theta)))
              (format t "~%--- Expected theta entries ---~%")
              (decode-theta-entries exp-theta)
              (format t "~%--- Got theta entries ---~%")
              (decode-theta-entries got-theta))

            ;; === Trace the accumulate to see yield details ===
            (format t "~%═══ RE-RUNNING ACCUMULATE WITH TRACING ═══~%")
            (trace-accumulate-block82 pre-sigma block-cl)))))))

(defun trace-accumulate-block82 (pre-sigma block-cl)
  "Re-run block 82 transition but intercept accumulate-service to trace yields."
  ;; Load components needed for transition-accumulate
  (let* ((header (funcall block-cl :header))
         (timeslot (funcall header :timeslot))
         ;; We need rho-ddagger to get R*
         ;; Instead of re-running the full transition, let's look at what
         ;; the omega-prime R* contains
         ;; Load relevant pre-state components
         (rho (funcall pre-sigma :load :rho))
         (omega (funcall pre-sigma :load :omega))
         (xi (funcall pre-sigma :load :xi))
         (delta (funcall pre-sigma :load :delta))
         (tau (funcall pre-sigma :load :tau)))

    (format t "~%Pre-state timeslot (tau): ~D~%" (funcall tau :slot))
    (format t "Block timeslot: ~D~%~%" timeslot)

    ;; Get the guaranteed reports from the block
    (let ((guarantees (funcall block-cl :reports)))
      (format t "Number of guarantees: ~D~%" (length guarantees))
      (when guarantees
        (dolist (g guarantees)
          (let ((report (getf g :report)))
            (format t "~%  Report package-spec service-id: ~A~%"
                    (getf (getf report :package-spec) :service-id))
            (format t "  Results count: ~D~%" (length (getf report :results)))
            (dolist (w (getf report :results))
              (format t "    Work item: sid=~D gas=~D result-type=~A~%"
                      (getf w :service-id)
                      (getf w :accumulate-gas)
                      (if (getf w :result)
                          (if (listp (getf w :result))
                              (car (getf w :result))
                              (getf w :result))
                          :nil)))))))

    ;; Now let's manually run accumulate with tracing for each service
    ;; First, get R* through omega transition
    (let* ((r-star-input (funcall rho :reported))
           (prev-timeslot (if tau (funcall tau :slot) (1- timeslot)))
           (omega-prime (funcall omega :transition
                                :reports r-star-input
                                :xi-flattened (funcall xi :flattened)
                                :timeslot timeslot
                                :prev-timeslot prev-timeslot))
           (r-star (funcall omega-prime :r-star)))

      (format t "~%═══ R* (ready reports) ═══~%")
      (format t "Number of R* reports: ~D~%" (length r-star))

      (when r-star
        ;; Extract operand tuples
        (let ((all-tuples '()))
          (dolist (report r-star)
            (let ((tuples (extract-operand-tuples report)))
              (dolist (tup tuples)
                (push tup all-tuples))))
          (setf all-tuples (nreverse all-tuples))

          ;; Group by service
          (let ((by-svc (group-by-service all-tuples)))
            (format t "Services in R*: ")
            (maphash (lambda (k v)
                       (format t "~D(~D items) " k (length v)))
                     by-svc)
            (format t "~%")

            ;; For each service, run accumulate with detailed tracing
            (let ((chi (funcall pre-sigma :load :chi)))
              (maphash (lambda (sid items)
                         (format t "~%═══ SERVICE ~D ═══~%" sid)
                         (trace-service-accumulate sid items delta chi timeslot pre-sigma))
                       by-svc))))))))

(defun trace-service-accumulate (sid items delta chi timeslot pre-sigma)
  "Run accumulate for a single service with detailed yield tracing."
  (let* ((svc-data (funcall delta :service-data sid))
         (code-hash (getf svc-data :code-hash))
         (code-blob (getf svc-data :code))
         (balance (getf svc-data :balance)))

    (unless code-blob
      (format t "  No code for service ~D~%" sid)
      (return-from trace-service-accumulate))

    (format t "  Code hash: ~A~%" (bytes-to-hex-string (ensure-bytes code-hash)))
    (format t "  Balance: ~D~%" balance)
    (format t "  Code size: ~D bytes~%" (length code-blob))
    (format t "  Items count: ~D~%" (length items))

    ;; Build gas-limit (simplified — use per-item gas from items)
    (let* ((gas-limit (reduce #'+ items :key (lambda (i) (or (getf i :gas) 0)) :initial-value 0))
           (h27-storage (getf svc-data :storage))
           ;; Minimal cross-services
           (existing-services (funcall delta :existing-services))
           (cross-services (funcall delta :cross-service-data)))

      (format t "  Gas limit: ~D~%" gas-limit)

      ;; Run PVM accumulate with debug trace
      (let ((*debug-pvm-trace* t))
        (declare (special *debug-pvm-trace*))
        (handler-case
            (multiple-value-bind (effects gas-used)
                (jam-host:lisp-pvm-run-accumulate
                 code-blob sid balance timeslot
                 :gas             gas-limit
                 :entropy         (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)
                 :header-hash     (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                 :code-hash       code-hash
                 :threshold       (or (getf svc-data :threshold) 0)
                 :min-accum-gas   (or (getf svc-data :min-accum-gas) 0)
                 :min-memo-gas    (or (getf svc-data :min-memo-gas) 0)
                 :items-count     (or (getf svc-data :items-count) 0)
                 :footprint       (or (getf svc-data :footprint) 0)
                 :creation-slot   (or (getf svc-data :creation-slot) 0)
                 :last-accum-slot (or (getf svc-data :last-accum-slot) 0)
                 :parent-service  (or (getf svc-data :parent-service) 0)
                 :storage         h27-storage
                 :preimages       (getf svc-data :preimages)
                 :lookup          (getf svc-data :lookup)
                 :service-accounts cross-services
                 :existing-services existing-services
                 :accumulate-items (encode-accumulate-items items nil)
                 :debug-trace t)

              (format t "  Gas used: ~D~%" gas-used)
              (format t "  Outcome: ~A~%" (when effects (getf effects :outcome)))

              (when effects
                (let ((yield (getf effects :yield-output)))
                  (if yield
                      (format t "  YIELD OUTPUT: ~A~%" (bytes-to-hex-string yield))
                      (format t "  NO YIELD OUTPUT~%")))

                ;; Show host call log if available
                (let ((hclog (getf effects :host-call-log)))
                  (when hclog
                    (format t "  Host call log (~D calls):~%" (length hclog))
                    (dolist (entry hclog)
                      (format t "    ~A~%" entry))))))

          (error (e)
            (format t "  ERROR: ~A~%" e)))))))

(defun decode-theta-entries (bytes)
  "Decode and print theta (sid, yield-hash) entries."
  (when (and bytes (plusp (length bytes)))
    (multiple-value-bind (count consumed)
        (decode-compact bytes 0)
      (format t "  Count: ~D (compact used ~D bytes)~%" count consumed)
      (let ((offset consumed))
        (dotimes (i count)
          (when (> (+ offset 36) (length bytes))
            (format t "  [truncated at entry ~D]~%" i)
            (return))
          (let ((sid (logior (aref bytes offset)
                             (ash (aref bytes (+ offset 1)) 8)
                             (ash (aref bytes (+ offset 2)) 16)
                             (ash (aref bytes (+ offset 3)) 24)))
                (hash (subseq bytes (+ offset 4) (+ offset 36))))
            (format t "  [~D] SID=~D hash=~A~%"
                    i sid (bytes-to-hex-string hash))
            (incf offset 36)))))))
