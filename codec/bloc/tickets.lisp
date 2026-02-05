;;;; tickets.lisp
;;;; JAM Tickets (T)
;;;; Graypaper references: Section 6.6, Equation 6.6, Appendix C.17

(in-package :jotl-bloc)

;;; Ticket T
;;;
;;; Graypaper Equation 6.6:
;;; T ≡ (y ∈ H, e ∈ N)
;;;
;;; Where:
;;; - y: ticket identifier (H, 32-byte hash)
;;; - e: attempt number (natural number)
;;;
;;; Graypaper Appendix C.17:
;;; ET(ET) = E(↕ET)
;;; E(T) = y ⌢ E(e)
;;;
;;; Tickets are encoded as a length-prefixed sequence.
;;; Each ticket T = (y, e) is encoded as E(T) = E(y, e) = E(y) ⌢ E(e)
;;; where:
;;; - y ∈ H (32 bytes, identity encoding per C.2)
;;; - e ∈ NN (natural, variable-length encoding per C.5)

(defun encode-tickets (tickets)
  "Encode tickets (ET).
   
   Graypaper Appendix C.17: ET(ET) = E(↕ET)
   
   Args:
     tickets: List of ticket structures
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-tickets
         (mapcar (lambda (ticket)
                   (concat-octets 
                    (ticket-identifier ticket)
                    (encode-natural (ticket-attempt ticket))))
                 tickets)))
    (let ((concatenated (apply #'concat-octets encoded-tickets)))
      (concat-octets (encode-natural (length concatenated))
                     concatenated))))

(defun decode-tickets (octets &optional (start 0))
  "Decode tickets from octets.
   
   Inverse of encode-tickets (Appendix C.17).
   
   Args:
     octets: Encoded tickets data
     start: Starting position
   
   Returns:
     values: (list-of-ticket bytes-consumed)"
  (multiple-value-bind (total-length length-bytes)
      (decode-natural octets start)
    (let ((tickets '())
          (pos (+ start length-bytes))
          (end-pos (+ start length-bytes total-length)))
      (loop while (< pos end-pos) do
        (let ((y (subseq octets pos (+ pos 32))))
          (incf pos 32)
          (multiple-value-bind (e e-consumed)
              (decode-natural octets pos)
            (incf pos e-consumed)
            (push (make-ticket :identifier y :attempt e) tickets))))
      (values (nreverse tickets) (+ length-bytes total-length)))))

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
