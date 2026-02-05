;;;; block.lisp
;;;; JAM Block structure (B)
;;;; Graypaper references: Equations 4.2-4.3, 5.1, Appendix C.16

(in-package :jotl-bloc)

;;; Block B
;;;
;;; Graypaper Equations 4.2-4.3:
;;; B ≡ (H, E)
;;;
;;; Where:
;;; - H: Header (Eq. 5.1)
;;; - E: Extrinsic data (Eq. 4.3)
;;;
;;; Graypaper Equation 4.3:
;;; E ≡ (ET, ED, EP, EA, EG)
;;;
;;; Where:
;;; - ET: Tickets
;;; - ED: Disputes
;;; - EP: Preimages
;;; - EA: Availability assurances
;;; - EG: Guarantees (reports)
;;;
;;; Graypaper Appendix C.16:
;;; E(B) = E(H, ET(ET), EP(EP), EG(EG), EA(EA), ED(ED))

;;; Extrinsic encoding/decoding

(defun encode-extrinsic (extrinsic)
  "Encode extrinsic data.
   
   Graypaper Appendix C.16 (partial): E(B) = E(H, ET(ET), EP(EP), EG(EG), EA(EA), ED(ED))
   
   Args:
     extrinsic: An extrinsic structure
   
   Returns:
     Encoded octet sequence"
  (concat-octets
   ;; ET(ET) : tickets (Appendix C.17)
   (encode-tickets (extrinsic-tickets extrinsic))
   
   ;; EP(EP) : preimages (Appendix C.18)
   (encode-preimages (extrinsic-preimages extrinsic))
   
   ;; EG(EG) : reports (Appendix C.19)
   (encode-reports (extrinsic-reports extrinsic))
   
   ;; EA(EA) : availability (Appendix C.20)
   (encode-availability (extrinsic-availability extrinsic))
   
   ;; ED(ED) : disputes (Appendix C.21)
   (encode-disputes (extrinsic-disputes extrinsic))))

(defun decode-extrinsic (octets &optional (start 0) (validators-super-majority 5))
  "Decode extrinsic data from octets.
   
   Inverse of encode-extrinsic.
   
   Args:
     octets: Encoded extrinsic data
     start: Starting position
     validators-super-majority: Number of judgements per verdict (default 5 for tiny)
   
   Returns:
     values: (extrinsic bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      ;; ET(ET) : tickets (Appendix C.17)
      (tickets (decode-tickets octets pos))
      
      ;; EP(EP) : preimages (Appendix C.18)
      (preimages (decode-preimages octets pos))
      
      ;; EG(EG) : reports (Appendix C.19)
      (reports (decode-reports octets pos))
      
      ;; EA(EA) : availability (Appendix C.20)
      (availability (decode-availability octets pos))
      
      ;; ED(ED) : disputes (Appendix C.21)
      (disputes (decode-disputes octets pos validators-super-majority))
      
      (values
       (make-extrinsic
        :tickets tickets
        :preimages preimages
        :reports reports
        :availability availability
        :disputes disputes)
       (- pos start)))))

;;; Block encoding/decoding

(defun encode-chain-block (block &key (as-blob nil))
  "Encode a complete JAM block.
   
   Graypaper Appendix C.16: E(B) = E(H, ET(ET), EP(EP), EG(EG), EA(EA), ED(ED))
   
   Args:
     block: A chain-block structure
     as-blob: If t, convert result to vector; if nil (default), return list
   
   Returns:
     Encoded block as list (default) or vector"
  (let ((octets (concat-octets
                 ;; H : header
                 (encode-header (chain-block-header block))
                 ;; E : extrinsic
                 (encode-extrinsic (chain-block-extrinsic block)))))
    (if as-blob
        (coerce octets 'vector)
        octets)))

(defun decode-chain-block (blob &optional (start 0))
  "Decode a complete JAM block from octets.
   
   Graypaper Appendix C.16: E(B) = E(H, ET(ET), EP(EP), EG(EG), EA(EA), ED(ED))
   
   Args:
     blob: Encoded block data (vector or list)
     start: Starting position
   
   Returns:
     values: (chain-block bytes-consumed)"
  (let ((octets (coerce blob 'list))
        (pos start))
    ;; Decode header first
    (multiple-value-bind (header header-consumed)
        (decode-header octets pos)
      (incf pos header-consumed)
      
      ;; Calculate validators-super-majority from header if epoch-marker exists
      (let ((vsm (if (and (header-epoch-marker header)
                          (not (eq (header-epoch-marker header) +empty+)))
                     ;; Extract from epoch-marker validators and calculate
                     (validators-super-majority (length (epoch-marker-validators (header-epoch-marker header))))
                     ;; Default from current chainspec
                     (validators-super-majority))))
        
        ;; Decode extrinsic with calculated vsm
        (multiple-value-bind (extrinsic extrinsic-consumed)
            (decode-extrinsic octets pos vsm)
          (incf pos extrinsic-consumed)
          
          (values
           (make-chain-block
            :header header
            :extrinsic extrinsic)
           (- pos start)))))))

;;; Convenience aliases

(defun encode-block (block &key (as-blob nil))
  "Alias for encode-chain-block."
  (encode-chain-block block :as-blob as-blob))

(defun decode-block (blob &optional (start 0))
  "Alias for decode-chain-block."
  (decode-chain-block blob start))
