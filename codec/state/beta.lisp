;;;; beta.lisp
;;;; β - Recent Blocks (Graypaper equation 7.1)
;;;;
;;;; Log of recent activity: block info (βH) + Merkle belt (βB).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 7.1: β ∈ (βH, βB)
;;; Equation 7.2: βH - Information on the most recent blocks
;;; Equations 7.3, 7.7: βB - Merkle mountain belt
;;; 
;;; β is the composite state tracking recent block activity:
;;;   βH: Recent block headers and timeslots
;;;   βB: Merkle mountain belt for accumulating Accumulation outputs
;;;
;;; βH = ⟦(header: H, timeslot: ℕT)⟧
;;; βB = (peaks: ⟦H⟧, leaves_count: ℕ)

;;; ═══════════════════════════════════════════════════════════════════
;;; βH - RECENT BLOCKS INFO (equation 7.2)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-recent-blocks-info (info)
  "Encode recent blocks info βH.
   
   Graypaper equation 7.2: βH - block headers and timeslots
   
   Args:
     info: recent-blocks-info struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-pre-encoded-sequence  ; Block headers (list of hashes)
    (mapcar #'encode-hash (recent-blocks-info-block-headers info)))
   (encode-pre-encoded-sequence  ; Timeslots (list of u32)
    (mapcar #'encode-e4 (recent-blocks-info-timeslots info)))))

(defun decode-recent-blocks-info (octets position)
  "Decode recent blocks info βH.
   
   Graypaper equation 7.2: βH - block headers and timeslots
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values recent-blocks-info new-position)"
  (decode>> (octets position)
    (block-headers <- decode-length-prefixed-sequence #'decode-hash)
    (timeslots     <- decode-length-prefixed-sequence #'decode-e4)
    :result (make-recent-blocks-info
             :block-headers block-headers
             :timeslots timeslots)))

;;; ═══════════════════════════════════════════════════════════════════
;;; βB - MERKLE MOUNTAIN BELT (equations 7.3, 7.7)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-merkle-mountain-belt (belt)
  "Encode Merkle mountain belt βB.
   
   Graypaper equations 7.3, 7.7: βB - Merkle accumulator
   
   Args:
     belt: merkle-mountain-belt struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-pre-encoded-sequence  ; Peaks (list of hashes)
    (mapcar #'encode-hash (merkle-mountain-belt-peaks belt)))
   (encode-natural (merkle-mountain-belt-leaves-count belt))))  ; Total leaves count

(defun decode-merkle-mountain-belt (octets position)
  "Decode Merkle mountain belt βB.
   
   Graypaper equations 7.3, 7.7: βB - Merkle accumulator
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values merkle-mountain-belt new-position)"
  (decode>> (octets position)
    (peaks        <- decode-length-prefixed-sequence #'decode-hash)
    (leaves-count <- decode-natural)
    :result (make-merkle-mountain-belt
             :peaks peaks
             :leaves-count leaves-count)))

;;; ═══════════════════════════════════════════════════════════════════
;;; β - COMPOSITE RECENT BLOCKS (equation 7.1)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-recent-blocks (blocks)
  "Encode the full recent blocks state β.
   
   Graypaper equation 7.1: β ∈ (βH, βB)
   
   Args:
     blocks: recent-blocks struct (composite of βH and βB)
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-recent-blocks-info (recent-blocks-info blocks))      ; βH
   (encode-merkle-mountain-belt (recent-blocks-merkle-belt blocks))))  ; βB

(defun decode-recent-blocks (octets position)
  "Decode the full recent blocks state β.
   
   Graypaper equation 7.1: β ∈ (βH, βB)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values recent-blocks new-position)"
  (decode>> (octets position)
    (info        <- decode-recent-blocks-info)
    (merkle-belt <- decode-merkle-mountain-belt)
    :result (make-recent-blocks
             :info info
             :merkle-belt merkle-belt)))
