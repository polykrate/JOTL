;;;; pi.lisp
;;;; π - Validator Statistics (Graypaper equation 13.1)
;;;;
;;;; Activity statistics for validators (performance tracking).

(in-package :jotl-state)

;;; ═══════════════════════════════════════════════════════════════════
;;; GRAYPAPER REFERENCE
;;; ═══════════════════════════════════════════════════════════════════
;;; 
;;; Equation 13.1: π ∈ (ℕV → Stats)
;;; 
;;; π maps validator indices to their performance statistics.
;;;
;;; Stats = (blocks: ℕ, votes: ℕ, slashes: ℕ, rewards: ℕG) where:
;;;   blocks: Number of blocks produced
;;;   votes: Number of votes cast
;;;   slashes: Number of slashes received
;;;   rewards: Accumulated rewards (gas amount)

;;; ═══════════════════════════════════════════════════════════════════
;;; ENCODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun encode-validator-stats (stats)
  "Encode validator statistics π[v].
   
   Graypaper equation 13.1: π ∈ (ℕV → Stats)
   
   Args:
     stats: validator-stats struct
   
   Returns:
     Encoded octet list"
  (concat-octets
   (encode-natural (validator-stats-validator-index stats))  ; v: Validator index
   (encode-natural (validator-stats-blocks-produced stats))  ; blocks: Count
   (encode-natural (validator-stats-votes-cast stats))       ; votes: Count
   (encode-natural (validator-stats-slashes stats))          ; slashes: Count
   (encode-e8 (validator-stats-rewards stats))))             ; rewards: Gas (u64)

(defun encode-validator-statistics (stats-list)
  "Encode the full validator statistics π.
   
   Graypaper equation 13.1: π ∈ (ℕV → Stats)
   
   Args:
     stats-list: list of validator-stats structs
   
   Returns:
     Encoded octet list (length-prefixed sequence)"
  (encode-pre-encoded-sequence
   (mapcar #'encode-validator-stats stats-list)))

;;; ═══════════════════════════════════════════════════════════════════
;;; DECODING (Appendix D)
;;; ═══════════════════════════════════════════════════════════════════

(defun decode-validator-stats (octets position)
  "Decode validator statistics π[v].
   
   Graypaper equation 13.1: π ∈ (ℕV → Stats)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values validator-stats new-position)"
  (let ((pos position))
    (decode>> (octets pos)
      (validator-index   (decode-natural octets pos))
      (blocks-produced   (decode-natural octets pos))
      (votes-cast        (decode-natural octets pos))
      (slashes           (decode-natural octets pos))
      (rewards           (decode-e8 octets pos))
      (values
       (make-validator-stats
        :validator-index validator-index
        :blocks-produced blocks-produced
        :votes-cast votes-cast
        :slashes slashes
        :rewards rewards)
       pos))))

(defun decode-validator-statistics (octets position)
  "Decode the full validator statistics π.
   
   Graypaper equation 13.1: π ∈ (ℕV → Stats)
   
   Args:
     octets: octet list
     position: starting position
   
   Returns:
     (values stats-list new-position)"
  (decode-length-prefixed-sequence
   octets position #'decode-validator-stats))
