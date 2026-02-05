;;;; header.lisp
;;;; JAM Block Header structure (H)
;;;; Graypaper references: Section 5, Equations 5.1-5.10, Appendix C.22-C.23

(in-package :jotl-bloc)

;;; Block Header H
;;;
;;; Graypaper Section 5: The Header
;;; Equation 5.1: H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
;;;
;;; The header comprises:
;;; - HP, HR: Parent hash and prior state root (Eq. 5.2, 5.8)
;;; - HX: Extrinsic hash (Eq. 5.4)
;;; - HT: Time-slot index (Eq. 5.7)
;;; - HE, HW, HO: Epoch, winning-tickets and offenders markers (Eq. 5.10)
;;; - HI: Block author index (Eq. 5.9)
;;; - HV: Bandersnatch VRF signature (entropy-yielding)
;;; - HS: Block seal (Bandersnatch signature)

(defstruct header
  "JAM Block Header structure.
   
   Graypaper Equation 5.1: H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)"
  
  ;; HP ∈ H : parent hash (Equation 5.2)
  (parent-hash nil :type (or null hash))
  
  ;; HR ∈ H : prior state root (Equation 5.8)
  (prior-state-root nil :type (or null hash))
  
  ;; HX ∈ H : extrinsic hash (Equation 5.4)
  (extrinsic-hash nil :type (or null hash))
  
  ;; HT ∈ NT : time-slot index (Equation 5.7)
  (timeslot nil :type (or null natural))
  
  ;; HE ∈ {...}? : epoch marker (Equation 5.10) - optional
  ;; TODO: Define precise type from Section 6.6
  (epoch-marker nil :type t)  ; ∅ or complex structure
  
  ;; HW ∈ ⟦T⟧E? : winning-tickets marker (Equation 5.10) - optional
  ;; Sequence of E=600 slot sealing tickets for next epoch
  (winning-tickets nil :type (or null list))
  
  ;; HO ∈ ⟦¯H⟧ : offenders marker (Equation 5.10)
  ;; Ed25519 public keys of newly misbehaving validators
  (offenders nil :type list)  ; list of ed25519-public-key
  
  ;; HI ∈ NV : block author index (Equation 5.9)
  (author-index nil :type (or null natural))
  
  ;; HV : Bandersnatch VRF signature (entropy-yielding)
  (vrf-signature nil :type (or null bandersnatch-vrf-signature))
  
  ;; HS : block seal (Bandersnatch signature)
  (seal nil :type (or null bandersnatch-signature)))

;;; Header encoding
;;;
;;; Graypaper Appendix C.22: E(H) = E(EU(H), HS)
;;; Graypaper Appendix C.23: EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)

(defun encode-header (header)
  "Encode a complete block header including seal.
   
   Graypaper Appendix C.22: E(H) = E(EU(H), HS)
   
   Args:
     header: A jam-header structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets (encode-header-unsigned header)
                 (blob-to-list (header-seal header))))

(defun encode-header-unsigned (header)
  "Encode header without seal (unsigned).
   
   Graypaper Appendix C.23: EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
   
   Args:
     header: A jam-header structure
   
   Returns:
     Encoded octet sequence (without seal)"
  (concat-octets
   ;; HP, HR, HX : hashes (B32, identity encoding)
   (blob-to-list (header-parent-hash header))
   (blob-to-list (header-prior-state-root header))
   (blob-to-list (header-extrinsic-hash header))
   
   ;; E4(HT) : timeslot on 4 octets
   (e4 (header-timeslot header))
   
   ;; ¿HE : optional epoch marker
   (let ((epoch-marker (header-epoch-marker header)))
     (if epoch-marker
         (concat-octets (list 1) (encode-epoch-marker epoch-marker))
         (list 0)))
   
   ;; ¿HW : optional winning tickets (TODO: implement encoding)
   (let ((winning-tickets (header-winning-tickets header)))
     (if winning-tickets
         (progn
           (format t "Warning: winning tickets encoding not yet implemented~%")
           (list 0))  ; For now, encode as absent
         (list 0)))
   
   ;; E2(HI) : author index on 2 octets
   (e2 (header-author-index header))
   
   ;; HV : VRF signature
   (blob-to-list (header-vrf-signature header))
   
   ;; ↕HO : length-prefixed offenders
   (encode-with-length (header-offenders header))))


(defun decode-header (octets &optional (start 0) (num-validators 6))
  "Decode a block header from octets.
   
   Graypaper Appendix C.22-C.23:
     E(H) = E(EU(H), HS)
     EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
   
   Args:
     octets: Encoded header data
     start: Starting position
   
   Returns:
     values: (jam-header bytes-consumed)"
  (let ((pos start))
    ;; HP : parent hash (32 bytes)
    (let ((parent-hash (list-to-blob (subseq octets pos (+ pos 32)))))
      (incf pos 32)
      
      ;; HR : prior state root (32 bytes)
      (let ((prior-state-root (list-to-blob (subseq octets pos (+ pos 32)))))
        (incf pos 32)
        
        ;; HX : extrinsic hash (32 bytes)
        (let ((extrinsic-hash (list-to-blob (subseq octets pos (+ pos 32)))))
          (incf pos 32)
          
          ;; E4(HT) : timeslot (4 bytes)
          (let* ((timeslot-octets (subseq octets pos (+ pos 4)))
                 (timeslot (decode-fixed-integer timeslot-octets 4)))
            (incf pos 4)
            
            ;; ¿HE : optional epoch marker
            (let ((epoch-discriminator (nth pos octets)))
              (incf pos 1)
              (let ((epoch-marker
                     (if (zerop epoch-discriminator)
                         +empty+
                         (multiple-value-bind (marker consumed)
                             (decode-epoch-marker octets pos (num-validators))
                           (incf pos consumed)
                           marker))))
                
                ;; ¿HW : optional winning tickets (TODO: define structure)
                (let ((tickets-discriminator (nth pos octets)))
                  (incf pos 1)
                  (let ((winning-tickets
                         (if (zerop tickets-discriminator)
                             +empty+
                             ;; TODO: decode winning tickets structure
                             (progn
                               (format t "Warning: winning tickets present but not yet decoded~%")
                               +empty+))))
                    
                    ;; E2(HI) : author index (2 bytes)
                    (let* ((author-octets (subseq octets pos (+ pos 2)))
                           (author-index (decode-fixed-integer author-octets 2)))
                      (incf pos 2)
                      
                      ;; HV : VRF signature (96 bytes)
                      (let ((vrf-signature (list-to-blob (subseq octets pos (+ pos 96)))))
                        (incf pos 96)
                        
                        ;; ↕HO : length-prefixed offenders
                        (multiple-value-bind (offenders offenders-consumed)
                            (decode-with-length octets pos)
                          (incf pos offenders-consumed)
                          
                          ;; HS : block seal (96 bytes)
                          (let ((seal (list-to-blob (subseq octets pos (+ pos 96)))))
                            (incf pos 96)
                            
                            (values
                             (make-header
                              :parent-hash parent-hash
                              :prior-state-root prior-state-root
                              :extrinsic-hash extrinsic-hash
                              :timeslot timeslot
                              :epoch-marker (unless (eq epoch-marker +empty+) epoch-marker)
                              :winning-tickets (unless (eq winning-tickets +empty+) winning-tickets)
                              :author-index author-index
                              :vrf-signature vrf-signature
                              :offenders offenders
                              :seal seal)
                             (- pos start))))))))))))))))
