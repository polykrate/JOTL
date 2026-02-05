;;;; tickets.lisp
;;;; JAM Tickets (ET) - Validator selection mechanism
;;;; Graypaper references: Section 6, Equation 6.6, Appendix C.17

(in-package :jotl-bloc)

;;; Tickets ET
;;;
;;; Used for the mechanism which manages the selection of validators
;;; for the permissioning of block authoring.
;;;
;;; Graypaper Section 6.2: Safrole Basic State
;;; Equation 6.6: T ≡ {y ∈ H, e ∈ NN}

;;; Ticket structure (Equation 6.6)
;;; T ≡ {y ∈ H, e ∈ NN}
;;; A ticket is a combination of:
;;; - y ∈ H: verifiably random ticket identifier (hash, 32 bytes)
;;; - e ∈ NN: ticket's entry-index (natural number)

(defstruct jam-ticket
  "A ticket for validator selection.
   
   Graypaper Equation 6.6: T ≡ {y ∈ H, e ∈ NN}
   
   Tickets are used in the mechanism that manages validator selection
   for block authoring permissions."
  
  ;; y ∈ H : ticket identifier (verifiably random hash, 32 bytes)
  (identifier nil :type (or null hash))
  
  ;; e ∈ NN : entry-index (natural number)
  (entry-index nil :type (or null natural)))

(deftype jam-tickets ()
  "Sequence of tickets (ET)"
  'list)

;;; Encoding (Appendix C.17)
;;; Graypaper C.17: ET(ET) = E(↕ET)
;;;
;;; Tickets are encoded as a length-prefixed sequence.
;;; Each ticket T = (y, e) is encoded as E(T) = E(y, e) = E(y) ⌢ E(e)
;;; where:
;;; - y ∈ H (32 bytes, identity encoding per C.2)
;;; - e ∈ NN (natural, variable-length encoding per C.5)

(defun encode-tickets (tickets)
  "Encode tickets (ET).
   
   Graypaper Appendix C.17: ET(ET) = E(↕ET)
   
   Each ticket T = (y ∈ H, e ∈ NN) from Equation 6.6 is encoded as:
   E(T) = y ⌢ E(e)
   
   Args:
     tickets: List of jam-ticket structures
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-tickets
         (mapcar (lambda (ticket)
                   (let ((y (jam-ticket-identifier ticket))
                         (e (jam-ticket-entry-index ticket)))
                     ;; E(y, e) = y ⌢ E(e)
                     ;; y is H (32 bytes) with identity encoding
                     ;; e is natural, encoded with encode-natural
                     (concat-octets (blob-to-list y)
                                    (encode-natural e))))
                 tickets)))
    ;; ↕ET : length-prefixed sequence
    (let ((concatenated (apply #'concat-octets encoded-tickets)))
      (concat-octets (encode-natural (length concatenated))
                     concatenated))))

(defun decode-tickets (octets &optional (start 0))
  "Decode tickets from octets.
   
   Inverse of encode-tickets (Appendix C.17).
   Decodes length-prefixed sequence of tickets where each ticket is (y, e).
   
   Args:
     octets: Encoded tickets data
     start: Starting position
   
   Returns:
     values: (list-of-jam-ticket bytes-consumed)"
  ;; First, decode the length prefix
  (multiple-value-bind (total-length length-bytes)
      (decode-natural octets start)
    (let ((tickets '())
          (pos (+ start length-bytes))
          (end-pos (+ start length-bytes total-length)))
      ;; Decode each ticket (y, e)
      (loop while (< pos end-pos) do
        ;; Decode y : H (32 bytes)
        (let* ((y (list-to-blob (subseq octets pos (+ pos 32)))))
          (incf pos 32)
          ;; Decode e : natural number
          (multiple-value-bind (e e-consumed)
              (decode-natural octets pos)
            (incf pos e-consumed)
            ;; Create ticket structure
            (push (make-jam-ticket :identifier y
                                   :entry-index e)
                  tickets))))
      (values (nreverse tickets) (+ length-bytes total-length)))))
