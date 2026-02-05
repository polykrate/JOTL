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

;;; Header structure is defined in types.lisp

;;; Header encoding
;;;
;;; Graypaper Appendix C.22: E(H) = E(EU(H), HS)
;;; Graypaper Appendix C.23: EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)

(defun encode-header (header &key (as-blob nil))
  "Encode a complete block header including seal.
   
   Graypaper Appendix C.22: E(H) = E(EU(H), HS)
   
   Args:
     header: A header structure
     as-blob: If t, convert result to vector; if nil (default), return list
   
   Returns:
     Encoded header as list (default) or vector"
  (let ((octets (concat-octets (encode-header-unsigned header)
                                (header-seal header))))
    (if as-blob
        (coerce octets 'vector)
        octets)))

(defun encode-header-unsigned (header)
  "Encode header without seal (unsigned).
   
   Graypaper Appendix C.23: EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
   
   Args:
     header: A header structure
   
   Returns:
     Encoded octet sequence (without seal)"
  (concat-octets
   ;; HP, HR, HX : hashes (B32, identity encoding C.2)
   (header-parent-hash header)
   (header-prior-state-root header)
   (header-extrinsic-hash header)
   
   ;; E4(HT) : timeslot (C.12)
   (e4 (header-timeslot header))
   
   ;; ¿HE : optional epoch marker (C.8)
   (let ((epoch-marker (header-epoch-marker header)))
     (if (eq epoch-marker +empty+)
         (list 0)
         (concat-octets (list 1) (encode-epoch-marker epoch-marker))))
   
   ;; ¿HW : optional winning tickets (C.8)
   ;; HW ∈ ⟦T⟧_E : fixed-length sequence of E tickets
   (let ((winning-tickets (header-winning-tickets header)))
     (if (eq winning-tickets +empty+)
         (list 0)
         (concat-octets (list 1) (encode-winning-tickets winning-tickets))))
   
   ;; E2(HI) : author index (C.12)
   (e2 (header-author-index header))
   
   ;; HV : VRF signature (B96, identity C.2)
   (header-vrf-signature header)
   
   ;; ↕HO : offenders (C.7, length-prefixed sequence of Ed25519 keys)
   (encode-length-prefixed-sequence (header-offenders header) :pre-encoded t)))

(defun decode-header (blob &optional (start 0))
  "Decode a block header from octets.
   
   Graypaper Appendix C.22-C.23:
     E(H) = E(EU(H), HS)
     EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
   
   Args:
     blob: Encoded header data (vector or list)
     start: Starting position
   
   Returns:
     values: (header bytes-consumed)"
  (let ((octets (coerce blob 'list))
        (pos start))
    (decode>> (octets pos)
      ;; HP, HR, HX : parent hash, prior state root, extrinsic hash (3x 32 bytes)
      (parent-hash (decode-hash octets pos))
      (prior-state-root (decode-hash octets pos))
      (extrinsic-hash (decode-hash octets pos))
      
      ;; E4(HT) : timeslot (4 bytes)
      (timeslot (decode-e4 octets pos))
      
      ;; ¿HE : optional epoch marker
      (epoch-marker-raw (decode-optional octets 
                                         (lambda (o s) (decode-epoch-marker o s (num-validators)))
                                         pos))
      
      ;; ¿HW : optional winning tickets
      (winning-tickets-raw (decode-optional octets
                                            (lambda (o s) (decode-winning-tickets o s (epoch-duration)))
                                            pos))
      
      ;; E2(HI) : author index (2 bytes)
      (author-index (decode-e2 octets pos))
      
      ;; HV : VRF signature (96 bytes)
      (vrf-signature (decode-fixed-bytes octets pos 96))
      
      ;; ↕HO : offenders (length-prefixed sequence of hashes)
      (offenders (decode-length-prefixed-sequence octets
                                                  (lambda (o s) (decode-hash o s))
                                                  pos))
      
      ;; HS : block seal (96 bytes)
      (seal (decode-fixed-bytes octets pos 96))
      
      ;; Return (header bytes-consumed)
      (values
       (make-header
        :parent-hash parent-hash
        :prior-state-root prior-state-root
        :extrinsic-hash extrinsic-hash
        :timeslot timeslot
        :epoch-marker epoch-marker-raw
        :winning-tickets winning-tickets-raw
        :author-index author-index
        :vrf-signature vrf-signature
        :offenders offenders
        :seal seal)
       (- pos start)))))
