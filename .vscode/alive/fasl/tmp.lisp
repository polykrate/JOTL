;;;; tickets.lisp
;;;; JAM Tickets (T)
;;;; Graypaper references: Section 6.6, Equation 6.6, Appendix C.17

(in-package :jotl-bloc)

;;; Ticket T
;;;
;;; Graypaper Equation 6.6:
;;; T ≡ (y, e ∈ N)
;;;
;;; Where:
;;; - y: ticket signature (784 bytes - Bandersnatch ring VRF signature)
;;; - e: attempt number (natural number)
;;;
;;; Note: Graypaper says "y ∈ H" (32 bytes) but actual implementation uses
;;; 784-byte ring signatures for anonymity.
;;;
;;; Graypaper Appendix C.17:
;;; ET(ET) = E(↕ET)
;;; E(T) = y ⌢ E(e)
;;;
;;; Tickets are encoded as a length-prefixed sequence.
;;; Each ticket T = (y, e) is encoded as E(T) = E(y, e) = E(y) ⌢ E(e)
;;; where:
;;; - y: 784 bytes (identity encoding)
;;; - e ∈ N (natural, variable-length encoding per C.5)

(defun encode-tickets (tickets)
  "Encode tickets (ET).
   
   Graypaper Appendix C.17: ET(ET) = E(↕ET)
   where ↕ means length-prefixed sequence (count of elements, then elements)
   
   Args:
     tickets: List of ticket structures
   
   Returns:
     Encoded octet sequence"
  (encode-length-prefixed-sequence
   (mapcar (lambda (ticket)
             (concat-octets 
              (ticket-identifier ticket)
              (encode-natural (ticket-attempt ticket))))
           tickets)
   :pre-encoded t))

(defun decode-ticket (octets &optional (start 0))
  "Decode a single ticket.
   
   E(T) = y ⌢ E(e) where y is 784-byte signature, e ∈ N is attempt
   
   Note: Graypaper uses 'y ∈ H' but the actual implementation uses
   784-byte ring signatures (Bandersnatch ring VRF).
   
   Returns: (values ticket bytes-consumed)"
  (let ((pos start))
    (decode>> (octets pos)
      (signature (decode-fixed-bytes octets pos 784))
      (attempt (decode-natural octets pos))
      (values (make-ticket :identifier signature :attempt attempt)
              (- pos start)))))

(defun decode-tickets (octets &optional (start 0))
  "Decode tickets from octets.
   
   Inverse of encode-tickets (Appendix C.17).
   ↕ET means count-prefixed sequence of tickets.
   
   Args:
     octets: Encoded tickets data
     start: Starting position
   
   Returns:
     values: (list-of-ticket bytes-consumed)"
  (decode-length-prefixed-sequence octets #'decode-ticket start))

;;; Winning Tickets (HW)
;;; Unlike ET (extrinsic tickets), HW has NO length prefix because
;;; it's always E tickets (epoch-duration).

(defun encode-winning-tickets (tickets)
  "Encode winning tickets (HW) - fixed-length sequence.
   
   Args:
     tickets: List of exactly E ticket structures
   
   Returns:
     Encoded octet sequence (no length prefix)"
  (let ((encoded-tickets
         (mapcar (lambda (ticket)
                   (concat-octets 
                    (ticket-identifier ticket)
                    (encode-natural (ticket-attempt ticket))))
                 tickets)))
    (apply #'concat-octets encoded-tickets)))

(defun decode-winning-tickets (octets start count)
  "Decode fixed-length sequence of winning tickets.
   
   Args:
     octets: Encoded data
     start: Starting position
     count: Number of tickets to decode (E = epoch-duration)
   
   Returns:
     values: (list-of-ticket bytes-consumed)"
  (let ((tickets '())
        (pos start))
    (dotimes (i count)
      (let ((y (subseq octets pos (+ pos 32))))
        (incf pos 32)
        (multiple-value-bind (e e-consumed)
            (decode-natural octets pos)
          (incf pos e-consumed)
          (push (make-ticket :identifier y :attempt e) tickets))))
    (values (nreverse tickets) (- pos start))))
