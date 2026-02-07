;;;; extrinsic.lisp - Complete Extrinsic Orchestrator
;;;; ACTUAL BINARY ORDER: ET → EP → EG → EA → ED
;;;;
;;;; ⚠️  IMPORTANT: Gray Paper §4.3 states E ≡ (ET, ED, EP, EA, EG)
;;;;     BUT actual test vectors use order: (ET, EP, EG, EA, ED)
;;;;     See: docs/TODO-EXTRINSIC-ORDER.md

(in-package :jotl)

;;; ==========================================================================
;;; Complete Extrinsic Encoding (ACTUAL BINARY ORDER)
;;; ==========================================================================
;;;
;;; ACTUAL ORDER: ET → EP → EG → EA → ED
;;;
;;; The extrinsic data is split into its several portions:
;;;   ET : Tickets - validator block authoring permissions
;;;   EP : Preimages - static data for on-demand fetching
;;;   EG : Guarantees - work reports with guarantor signatures
;;;   EA : Assurances - validator availability statements
;;;   ED : Disputes - disputes between validators

(defun encode-extrinsic (tickets disputes preimages assurances guarantees)
  "Encode complete extrinsic with ACTUAL binary order: ET → EP → EG → EA → ED.
   
   ⚠️  Gray Paper §4.3 says E ≡ (ET, ED, EP, EA, EG)
   ⚠️  BUT test vectors use: (ET, EP, EG, EA, ED)
   
   Args:
     tickets: ET - list of ticket plists (✅ implemented)
     disputes: ED - disputes structure (✅ implemented)
     preimages: EP - list of preimage plists (✅ implemented)
     assurances: EA - list of assurance plists (✅ implemented)
     guarantees: EG - list of guarantee plists (✅ implemented)
   
   Returns:
     byte array"
  (concatenate '(vector (unsigned-byte 8))
               ;; ET - Tickets (✅ implemented)
               (encode-tickets-extrinsic tickets)
               
               ;; EP - Preimages (✅ implemented)
               (encode-preimages-extrinsic preimages)
               
               ;; EG - Guarantees (✅ implemented)
               (encode-guarantees-extrinsic guarantees)
               
               ;; EA - Assurances (✅ implemented)
               (if assurances
                   (encode-assurances-extrinsic assurances)
                   (encode-compact 0)) ; Empty sequence = compact(0)
               
               ;; ED - Disputes (✅ implemented)
               (if disputes
                   (encode-disputes-extrinsic disputes)
                   ;; Empty disputes = (verdicts:[], culprits:[], faults:[])
                   (concatenate '(vector (unsigned-byte 8))
                                (encode-compact 0)  ; verdicts
                                (encode-compact 0)  ; culprits
                                (encode-compact 0)))))

(defun decode-extrinsic (bytes offset)
  "Decode complete extrinsic with ACTUAL binary order: ET → EP → EG → EA → ED.
   
   Returns: (values extrinsic-plist bytes-consumed)"
  (let ((pos offset))
    ;; ET - Tickets (✅ implemented)
    (multiple-value-bind (tickets bytes-consumed-tickets)
        (decode-tickets-extrinsic bytes pos)
      (incf pos bytes-consumed-tickets)
      
      ;; EP - Preimages (✅ implemented)
      (multiple-value-bind (preimages bytes-consumed-preimages)
          (decode-preimages-extrinsic bytes pos)
        (incf pos bytes-consumed-preimages)
        
        ;; EG - Guarantees (✅ implemented)
        (multiple-value-bind (guarantees bytes-consumed-guarantees)
            (decode-guarantees-extrinsic bytes pos)
          (incf pos bytes-consumed-guarantees)
          
          ;; EA - Assurances (✅ implemented)
          (multiple-value-bind (assurances bytes-consumed-assurances)
              (decode-assurances-extrinsic bytes pos)
            (incf pos bytes-consumed-assurances)
            
            ;; ED - Disputes (✅ implemented)
            (multiple-value-bind (disputes bytes-consumed-disputes)
                (decode-disputes-extrinsic bytes pos)
              (incf pos bytes-consumed-disputes)
              
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
