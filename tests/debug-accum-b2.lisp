;;;; debug-accum-b2.lisp — Trace PVM execution for storage_light block 2
;;;;
;;;; Goal: find why ACCUMULATE-GAS-USED = 6024 vs expected 110846
;;;;
;;;; Usage: sbcl --noinform --load scripts/load-jotl.lisp --load tests/debug-accum-b2.lisp

(in-package #:jotl)

(format t "~%═══ DEBUG: storage_light block 2 — PVM accumulate trace ═══~%")

(let* ((trace-dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path trace-dir 2)))
  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore post-sigma pre-root post-root))

    (let* ((reports (funcall block-cl :reports))
           (r-star (loop for g in reports
                         for r = (getf g :report) when r collect r))
           (all-tuples (mapcan #'extract-operand-tuples r-star))
           (by-service (group-by-service all-tuples))
           (first-sid (car (first all-tuples)))
           (items (gethash first-sid by-service))
           (sid first-sid)
           (delta-kvs (funcall pre-sigma :merkle-kvs))
           (svc-data (classify-service-sub-keys sid delta-kvs))
           (metadata (getf svc-data :metadata))
           (code-blob (getf svc-data :code-blob))
           (h27-storage (getf svc-data :storage))
           (cross-services (build-cross-service-accounts sid delta-kvs))
           (existing-services (extract-all-service-ids delta-kvs))
           (gas-limit (reduce #'+ items :key (lambda (u) (or (getf u :gas) 0))))
           (balance (or (getf metadata :balance) 0))
           (timeslot (funcall (funcall block-cl :header) :slot))
           (code-hash (or (getf metadata :code-hash)
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
           (accum-items (encode-accumulate-items items nil)))

      (format t "  sid=~D gas=~D blob=~D items=~D accum-item-sizes=~{~D~^ ~}~%"
              sid gas-limit (length code-blob) (length items)
              (mapcar #'length accum-items))

      ;; ── Use lisp-pvm-run-accumulate (same path as real execution) ──
      ;; but with debug-trace enabled
      (format t "~%  ─── Running via lisp-pvm-run-accumulate ───~%")
      (let ((jam-host::*omega-table* jam-host::*omega-table*)) ;; preserve
        (multiple-value-bind (effects gas-used)
            (jam-host:lisp-pvm-run-accumulate
             code-blob sid balance timeslot
             :gas gas-limit
             :entropy (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)
             :header-hash (funcall block-cl :hash)
             :code-hash code-hash
             :threshold (or (getf metadata :deposit-offset) 0)
             :min-accum-gas (or (getf metadata :min-accum-gas) 0)
             :min-memo-gas (or (getf metadata :min-memo-gas) 0)
             :items-count (or (getf metadata :items) 0)
             :footprint (or (getf metadata :bytes) 0)
             :creation-slot (or (getf metadata :creation-slot) 0)
             :last-accum-slot (or (getf metadata :last-accumulation-slot) 0)
             :parent-service (or (getf metadata :parent-service) 0)
             :storage h27-storage
             :preimages (getf svc-data :preimages)
             :lookup (getf svc-data :lookup)
             :service-accounts cross-services
             :existing-services existing-services
             :accumulate-items accum-items
             :debug-trace t)

          (format t "~%  ─── Results ───~%")
          (if effects
              (progn
                (format t "  outcome: ~D (0=halt 1=panic 2=oog 3=yield)~%"
                        (getf effects :outcome))
                (format t "  gas-used: ~D (expected 110846)~%"  gas-used)
                (format t "  gas-remaining: ~D~%" (getf effects :gas-remaining))
                (format t "  balance: ~D~%" (getf effects :balance))
                (format t "  storage: ~D entries~%" (length (getf effects :storage)))
                (format t "  transfers: ~D~%" (length (getf effects :transfers)))

                ;; Host-call log
                (let ((hclog (getf effects :host-call-log)))
                  (format t "~%  ─── Host Call Log (~D calls) ───~%" (length hclog))
                  (dolist (entry hclog)
                    (format t "    HC#~D gas=~D→~D result=~A~%"
                            (getf entry :id)
                            (getf entry :gas-before)
                            (getf entry :gas-after)
                            (getf entry :result))
                    (format t "      IN:  A0=~D A1=~D A2=~D A3=~D A4=~D A5=~D~%"
                            (getf entry :a0-before)
                            (getf entry :a1-before)
                            (getf entry :a2-before)
                            (getf entry :a3-before)
                            (getf entry :a4-before)
                            (getf entry :a5-before))
                    (format t "      OUT: A0=~D A1=~D~%"
                            (getf entry :a0-after)
                            (getf entry :a1-after)))))
              (format t "  effects = NIL (PVM failed)~%")))))))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
