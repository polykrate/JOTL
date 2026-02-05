;;;; block.lisp
;;;; JAM Block structure
;;;; Graypaper references: Section 4.1-4.2, Equations 4.2-4.3, Appendix C.16

(in-package :jotl-bloc)

;;; The Block
;;;
;;; Graypaper Section 4.1: The Block
;;; Equation 4.2: B ≡ (H, E)
;;; Equation 4.3: E ≡ (ET, ED, EP, EA, EG)
;;;
;;; The block B is partitioned into functional components:
;;; - H: Header (metadata and cryptographic references)
;;; - E: Extrinsic data (external input data)

(defstruct jam-block
  "JAM Block structure.
   
   Graypaper Equation 4.2: B ≡ (H, E)
   - H: Header (immutable, known a priori)
   - E: Extrinsic data (external to the system)"
  (header nil :type (or null jam-header))
  (extrinsic nil :type (or null jam-extrinsic)))

(defstruct jam-extrinsic
  "Extrinsic data structure.
   
   Graypaper Equation 4.3: E ≡ (ET, ED, EP, EA, EG)
   - ET: Tickets (validator selection mechanism)
   - ED: Disputes (validity disputes between validators)
   - EP: Preimages (static data for workloads)
   - EA: Availability (assurances of received data)
   - EG: Reports (guarantees of completed workloads)"
  (tickets nil :type list)            ; ET
  (disputes nil :type (or null jam-disputes))  ; ED
  (preimages nil :type list)          ; EP
  (availability nil :type list)       ; EA
  (reports nil :type list))           ; EG

;;; Block encoding/decoding
;;; Will be implemented after component structures are defined

;;; Block encoding
;;;
;;; Graypaper Appendix C.16: E(B) = E(H, ET(ET), EP(EP), EC(EG), EA(EA), ED(ED))

(defun encode-jam-block (block)
  "Encode a JAM block.
   
   Graypaper Appendix C.16: E(B) = E(H, ET(ET), EP(EP), EC(EG), EA(EA), ED(ED))
   
   Args:
     block: A jam-block structure
   
   Returns:
     Encoded octet sequence"
  (let* ((header (jam-block-header block))
         (extrinsic (jam-block-extrinsic block))
         (et (jam-extrinsic-tickets extrinsic))
         (ep (jam-extrinsic-preimages extrinsic))
         (eg (jam-extrinsic-reports extrinsic))
         (ea (jam-extrinsic-availability extrinsic))
         (ed (jam-extrinsic-disputes extrinsic)))
    (concat-octets (encode-jam-header header)
                   (encode-tickets et)
                   (encode-preimages ep)
                   (encode-reports eg)
                   (encode-availability ea)
                   (encode-disputes ed))))

(defun decode-jam-block (octets &optional (start 0))
  "Decode a JAM block from octets.
   
   Graypaper Appendix C.16: E(B) = E(H, ET(ET), EP(EP), EC(EG), EA(EA), ED(ED))
   
   Args:
     octets: Encoded block data
     start: Starting position
   
   Returns:
     values: (jam-block bytes-consumed)"
  (let ((pos start))
    ;; H : Header
    (multiple-value-bind (header header-consumed)
        (decode-jam-header octets pos)
      (incf pos header-consumed)
      
      ;; ET(ET) : Tickets
      (multiple-value-bind (tickets tickets-consumed)
          (decode-tickets octets pos)
        (incf pos tickets-consumed)
        
        ;; EP(EP) : Preimages
        (multiple-value-bind (preimages preimages-consumed)
            (decode-preimages octets pos)
          (incf pos preimages-consumed)
          
          ;; EC(EG) : Reports
          (multiple-value-bind (reports reports-consumed)
              (decode-reports octets pos)
            (incf pos reports-consumed)
            
            ;; EA(EA) : Availability
            (multiple-value-bind (availability availability-consumed)
                (decode-availability octets pos)
              (incf pos availability-consumed)
              
              ;; ED(ED) : Disputes
              (multiple-value-bind (disputes disputes-consumed)
                  (decode-disputes octets pos)
                (incf pos disputes-consumed)
                
                ;; Construct the block
                (values
                 (make-jam-block
                  :header header
                  :extrinsic (make-jam-extrinsic
                              :tickets tickets
                              :disputes disputes
                              :preimages preimages
                              :availability availability
                              :reports reports))
                 (- pos start))))))))))
