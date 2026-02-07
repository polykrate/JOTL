;;;; extrinsic.lisp - Complete Extrinsic Orchestrator
;;;; Gray Paper §4.3 - E ≡ (ET, ED, EP, EA, EG)

(in-package :jotl)

;;; ==========================================================================
;;; Complete Extrinsic Encoding (Gray Paper §4.3)
;;; ==========================================================================
;;;
;;; E ≡ (ET, ED, EP, EA, EG)
;;;
;;; The extrinsic data is split into its several portions:
;;;   ET : Tickets - validator block authoring permissions
;;;   ED : Disputes - disputes between validators
;;;   EP : Preimages - static data for on-demand fetching
;;;   EA : Assurances - validator availability statements
;;;   EG : Guarantees - work reports with guarantor signatures

(defun encode-extrinsic (tickets disputes preimages assurances guarantees)
  "Encode complete extrinsic E ≡ (ET, ED, EP, EA, EG).
   
   Gray Paper §4.3
   E ≡ (ET, ED, EP, EA, EG)
   
   Args:
     tickets: ET - list of ticket plists (✅ implemented)
     disputes: ED - disputes structure (✅ implemented)
     preimages: EP - list of preimage plists (✅ implemented)
     assurances: EA - list of assurance plists (✅ implemented)
     guarantees: EG - list of guarantee plists (⏳ stub - only accepts empty for now)
   
   Returns:
     byte array"
  (concatenate '(vector (unsigned-byte 8))
               ;; ET - Tickets (✅ implemented)
               (encode-tickets-extrinsic tickets)
               
               ;; ED - Disputes (✅ implemented)
               (if disputes
                   (encode-disputes-extrinsic disputes)
                   ;; Empty disputes = (verdicts:[], culprits:[], faults:[])
                   (concatenate '(vector (unsigned-byte 8))
                                (encode-compact 0)  ; verdicts
                                (encode-compact 0)  ; culprits
                                (encode-compact 0))) ; faults
               
               ;; EP - Preimages (✅ implemented)
               (encode-preimages-extrinsic preimages)
               
               ;; EA - Assurances (✅ implemented)
               (if assurances
                   (encode-assurances-extrinsic assurances)
                   (encode-compact 0)) ; Empty sequence = compact(0)
               
               ;; EG - Guarantees (⏳ stub - only accepts empty for now)
               (encode-guarantees-extrinsic guarantees)))

(defun decode-extrinsic (bytes offset)
  "Decode complete extrinsic E ≡ (ET, ED, EP, EA, EG).
   
   Returns: (values extrinsic-plist bytes-consumed)"
  (let ((pos offset))
    ;; ET - Tickets (✅ implemented)
    (multiple-value-bind (tickets bytes-consumed-tickets)
        (decode-tickets-extrinsic bytes pos)
      (incf pos bytes-consumed-tickets)
      
      ;; ED - Disputes (✅ implemented)
      (multiple-value-bind (disputes bytes-consumed-disputes)
          (decode-disputes-extrinsic bytes pos)
        (incf pos bytes-consumed-disputes)
        
        ;; EP - Preimages (✅ implemented)
        (multiple-value-bind (preimages bytes-consumed-preimages)
            (decode-preimages-extrinsic bytes pos)
          (incf pos bytes-consumed-preimages)
          
          ;; EA - Assurances (✅ implemented)
          (multiple-value-bind (assurances bytes-consumed-assurances)
              (decode-assurances-extrinsic bytes pos)
            (incf pos bytes-consumed-assurances)
            
            ;; EG - Guarantees (⏳ stub - expects empty only)
            (multiple-value-bind (guarantees bytes-consumed-guarantees)
                (decode-guarantees-extrinsic bytes pos)
              (incf pos bytes-consumed-guarantees)
              
              (values (list :tickets tickets
                            :disputes disputes
                            :preimages preimages
                            :assurances assurances
                            :guarantees guarantees)
                      (- pos offset)))))))))

;;; ==========================================================================
;;; Extrinsic Closure (Pure FP)
;;; ==========================================================================

(defun make-extrinsic-encoded (&key tickets disputes preimages assurances guarantees)
  "Create an extrinsic closure with encoding support.
   
   Pure FP closure for extrinsic E ≡ (ET, ED, EP, EA, EG).
   Lazy evaluation for :encoded.
   
   Args:
     tickets: ET - list of ticket plists (✅ implemented)
     disputes: ED - disputes structure (✅ implemented)
     preimages: EP - list of preimage plists (✅ implemented)
     assurances: EA - list of assurance plists (✅ implemented)
     guarantees: EG - list of guarantee plists (⏳ stub)
   
   Returns: closure with extrinsic interface"
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      ;; Core fields (Gray Paper §4.3)
      (:tickets tickets)
      (:disputes disputes)
      (:preimages preimages)
      (:assurances assurances)
      (:guarantees guarantees)
      
      ;; Encoding (computed on demand)
      (:encoded (encode-extrinsic tickets disputes preimages assurances guarantees))
      
      ;; Metadata
      (:type :extrinsic)
      (:num-tickets (length tickets))
      (:num-preimages (length preimages))
      (:num-assurances (if assurances (length assurances) 0))
      (:num-guarantees (if guarantees (length guarantees) 0))
      
      (otherwise (error "Unknown extrinsic message: ~a" msg)))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-extrinsic
          decode-extrinsic
          make-extrinsic-encoded))
