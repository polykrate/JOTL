;;;; diag-pi-reporters.lisp — Investigate reporter-set G for PI guarantee count
;;;; This divergence: validator 0's guarantee count is 0 (should be 1)
(in-package #:jotl)

(defvar *trace-dir*
  (merge-pathnames "../jam-conformance/fuzz-reports/0.7.2/traces/1766243493_6113/"
                   (asdf:system-source-directory :jotl)))

(defvar *step-file*
  (merge-pathnames "00000035.bin" *trace-dir*))

(format t "~%=== PI REPORTERS DIAGNOSTIC ===~%")

(let* ((bytes (alexandria:read-file-into-byte-vector *step-file*))
       (vals (multiple-value-list (decode-trace-step-bin bytes)))
       (pre-sigma  (first vals))
       (block-cl   (second vals))
       (post-sigma (third vals)))
  
  (let* ((header (funcall block-cl :header))
         (slot (funcall header :slot))
         (author (funcall header :author-index))
         (e (epoch-duration))
         (r (rotation-period)))
    
    (format t "Slot: ~D  Author: ~D  Epoch: ~D  RotPeriod: ~D~%"
            slot author e r)
    
    ;; Load state components we need
    (let* ((tau-prime (funcall post-sigma :load :tau))
           (tau (funcall pre-sigma :load :tau))
           (kappa (funcall pre-sigma :load :kappa))
           (kappa-prime (funcall post-sigma :load :kappa))
           (lambda-prev (funcall pre-sigma :load :lambda))
           (pi-pre (funcall pre-sigma :load :pi))
           (pi-post (funcall post-sigma :load :pi)))
      
      (let ((tau-prime-val (funcall tau-prime :slot))
            (tau-val (funcall tau :slot)))
        (format t "tau=~D  tau'=~D~%" tau-val tau-prime-val)
        (format t "epoch_old=~D  epoch_new=~D~%"
                (floor tau-val e) (floor tau-prime-val e))
        
        ;; Check guarantees
        (let ((guarantees (funcall block-cl :guarantees)))
          (format t "~%=== GUARANTEES ===~%")
          (format t "Number of guarantees: ~D~%" (length guarantees))
          
          (dolist (g guarantees)
            (let* ((guarantee-slot (getf g :slot))
                   (same-rotation-p (= (floor tau-prime-val r)
                                       (floor guarantee-slot r)))
                   (same-epoch-p (= (floor tau-prime-val e)
                                    (floor guarantee-slot e))))
              (format t "~%  Guarantee slot: ~D~%" guarantee-slot)
              (format t "  floor(tau'/R)=~D  floor(g_slot/R)=~D  same-rotation=~A~%"
                      (floor tau-prime-val r) (floor guarantee-slot r) same-rotation-p)
              (format t "  floor(tau'/E)=~D  floor(g_slot/E)=~D  same-epoch=~A~%"
                      (floor tau-prime-val e) (floor guarantee-slot e) same-epoch-p)
              
              ;; Select validators
              (let ((validators
                     (if same-rotation-p
                         (progn (format t "  → Using κ (same rotation)~%") kappa)
                         (if same-epoch-p
                             (progn (format t "  → Using κ (same epoch, diff rotation)~%") kappa)
                             (progn (format t "  → Using λ (different epoch)~%") lambda-prev)))))
                
                ;; Show signatures
                (format t "  Signatures: ~D~%" (length (getf g :signatures)))
                (dolist (sig (getf g :signatures))
                  (let* ((vi (getf sig :validator-index))
                         (ed-key (when validators
                                   (funcall validators :ed25519-key vi))))
                    (format t "    sig vi=~D ed-key=~A~%"
                            vi
                            (when ed-key
                              (subseq (bytes-to-hex-string ed-key) 0 16)))))))))
        
        ;; Check kappa-prime ed25519 keys
        (format t "~%=== κ' Ed25519 keys ===~%")
        (dotimes (vi (num-validators))
          (let ((ed-key (when kappa-prime
                          (funcall kappa-prime :ed25519-key vi))))
            (format t "  κ'[~D].ed25519 = ~A~%"
                    vi
                    (when ed-key
                      (subseq (bytes-to-hex-string ed-key) 0 16)))))
        
        ;; Check kappa ed25519 keys
        (format t "~%=== κ Ed25519 keys ===~%")
        (dotimes (vi (num-validators))
          (let ((ed-key (when kappa
                          (funcall kappa :ed25519-key vi))))
            (format t "  κ[~D].ed25519 = ~A~%"
                    vi
                    (when ed-key
                      (subseq (bytes-to-hex-string ed-key) 0 16)))))
        
        ;; Build reporters-G exactly like the transition does
        (format t "~%=== Reporters G (set of Ed25519 keys) ===~%")
        (let ((reporters-g (make-hash-table :test 'equalp)))
          (dolist (g (funcall block-cl :guarantees))
            (let* ((guarantee-slot (getf g :slot))
                   (same-rotation-p (= (floor tau-prime-val r)
                                       (floor guarantee-slot r)))
                   (validators
                    (if same-rotation-p
                        kappa
                        (if (= (floor tau-prime-val e)
                               (floor guarantee-slot e))
                            kappa
                            lambda-prev))))
              (dolist (sig (getf g :signatures))
                (let* ((vi (getf sig :validator-index))
                       (ed-key (when validators
                                 (funcall validators :ed25519-key vi))))
                  (when ed-key
                    (setf (gethash ed-key reporters-g) t))))))
          
          (format t "Reporters G contains ~D keys:~%"
                  (hash-table-count reporters-g))
          (maphash (lambda (k v)
                     (declare (ignore v))
                     (format t "  ~A~%"
                             (subseq (bytes-to-hex-string k) 0 16)))
                   reporters-g)
          
          ;; Check which κ' validators are in G
          (format t "~%=== κ'[v].ed25519 ∈ G? ===~%")
          (dotimes (vi (num-validators))
            (let* ((ed-key (when kappa-prime
                             (funcall kappa-prime :ed25519-key vi)))
                   (in-g (and ed-key (gethash ed-key reporters-g))))
              (format t "  v=~D key=~A in_G=~A~%"
                      vi
                      (when ed-key (subseq (bytes-to-hex-string ed-key) 0 16))
                      in-g))))
        
        ;; Show expected PI values
        (format t "~%=== Expected PI (post-state) ===~%")
        (let ((exp-curr (funcall pi-post :vals-curr)))
          (dolist (vc exp-curr)
            (format t "  ~A~%" vc)))
        
        ;; Show pre-state PI values
        (format t "~%=== Pre-state PI ===~%")
        (let ((pre-curr (funcall pi-pre :vals-curr)))
          (dolist (vc pre-curr)
            (format t "  ~A~%" vc)))))))

(format t "~%=== DONE ===~%")
(sb-ext:exit :code 0)
