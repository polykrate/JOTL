;;;; diagnose-pvm-gas.lisp — Deep PVM execution trace for storage_light step 2
(in-package #:jotl)

(let* ((trace-dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path trace-dir 2)))
  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore post-sigma pre-root post-root))
    
    (let ((*chain-log-level* nil))
      (declare (special *chain-log-level*))
      
      (let ((orig-host-run (symbol-function 'jam-host::host-run)))
        (setf (symbol-function 'jam-host::host-run)
              (lambda (vm ctx)
                (format t "~%═══ host-run pc=~D gas=~D ═══~%"
                        (jamvm:pvm-pc vm) (jamvm:pvm-gas vm))
                
                (let ((step-count 0) (host-calls 0))
                  (loop
                    (when (>= step-count 500000)
                      (format t "  [stop: 500k]~%")
                      (return (funcall orig-host-run vm ctx)))
                    
                    ;; Capture pre-step state
                    (let* ((pre-pc (jamvm:pvm-pc vm))
                           (opc (when (< pre-pc (length (jamvm:pvm-code vm)))
                                  (aref (jamvm:pvm-code vm) pre-pc)))
                           (pre-gas (jamvm:pvm-gas vm)))
                      
                      (let ((result (jamvm:vm-step vm)))
                        (incf step-count)
                        
                        ;; Show last 10 steps before any exit + host calls
                        (when (and (> step-count 5930) (< step-count 5950))
                          (format t "  ~4D pc=~5D opc=~3A gas=~D → ~A (post-pc=~D)~%"
                                  step-count pre-pc (or opc "?") pre-gas result (jamvm:pvm-pc vm)))
                        
                        (cond
                          ((null result) nil)
                          
                          ((eq result :host-call)
                           (incf host-calls)
                           (let ((hc-id (jamvm:pvm-exit-arg vm)))
                             (format t "  ★ HC#~D id=~D pc=~D gas=~D~%"
                                     host-calls hc-id pre-pc (jamvm:pvm-gas vm))
                             (let ((hresult (jam-host::host-dispatch vm ctx hc-id)))
                               (format t "    → ~A A0=~D gas=~D~%"
                                       hresult (jamvm:reg vm jamvm:+a0+) (jamvm:pvm-gas vm))
                               (case hresult
                                 (:continue 
                                  (let ((pc-bef (jamvm:pvm-pc vm)))
                                    (jamvm::vm-advance-past-ecalli vm)
                                    (format t "    advance ~D → ~D~%" pc-bef (jamvm:pvm-pc vm))
                                    ;; Show opcode at new PC
                                    (let ((npc (jamvm:pvm-pc vm)))
                                      (when (< npc (length (jamvm:pvm-code vm)))
                                        (format t "    next opc=~D at pc=~D~%"
                                                (aref (jamvm:pvm-code vm) npc) npc)))))
                                 (:oog (return (values :oog 0 ctx)))
                                 (t (return (values :panic 0 ctx)))))))
                          
                          ((eq result :halt)
                           (format t "  ═ HALT: ~D steps, ~D HCs, gas=~D A0=~D ═~%"
                                   step-count host-calls (jamvm:pvm-gas vm) (jamvm:reg vm jamvm:+a0+))
                           (return (values :halt 0 ctx)))
                          ((eq result :panic)
                           (format t "  ═ PANIC: ~D steps, ~D HCs, gas=~D pre-pc=~D opc=~A ═~%"
                                   step-count host-calls (jamvm:pvm-gas vm) pre-pc (or opc "?"))
                           ;; Show bytes around the panicking PC
                           (format t "    bytes at ~D:" pre-pc)
                           (loop for i from pre-pc below (min (+ pre-pc 8) (length (jamvm:pvm-code vm)))
                                 do (format t " ~2,'0X" (aref (jamvm:pvm-code vm) i)))
                           (terpri)
                           ;; Check if it's a valid basic block
                           (format t "    basic-block? ~A~%"
                                   (if (jamvm::pvm-basic-blocks vm)
                                       (gethash pre-pc (jamvm::pvm-basic-blocks vm))
                                       :no-bb-table))
                           (return (values :panic 0 ctx)))
                          ((eq result :oog)
                           (format t "  ═ OOG: ~D steps, ~D HCs, gas=~D ═~%"
                                   step-count host-calls (jamvm:pvm-gas vm))
                           (return (values :oog 0 ctx)))
                          ((eq result :page-fault)
                           (format t "  ═ PAGE-FAULT at 0x~X ═~%"
                                   (jamvm:pvm-exit-arg vm))
                           (return (values :page-fault (jamvm:pvm-exit-arg vm) ctx)))
                          (t
                           (format t "  ═ UNK ~A ═~%" result)
                           (return (values :panic 0 ctx)))))))))))
        
        (unwind-protect
             (import-block pre-sigma block-cl)
          (setf (symbol-function 'jam-host::host-run) orig-host-run))))))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
