;;;; block/extrinsic/tickets.lisp — ET (Tickets Extrinsic)
;;;; Gray Paper §6.4, §6.29-6.35

(in-package :jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Tickets Extrinsic (ET)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Ticket ≡ (attempt: u8, signature: [u8; 784])
;;; ET is a compact-prefixed sequence of tickets.

(defun encode-ticket (ticket)
  "Encode a single ticket (attempt: u8, signature: 784 bytes)."
  (let ((attempt (getf ticket :attempt))
        (signature (getf ticket :signature)))
    (assert (typep attempt '(integer 0 255)) ()
            "Ticket attempt must be u8, got: ~a" attempt)
    (let ((sig-bytes (etypecase signature
                       ((simple-array (unsigned-byte 8) (*)) signature)
                       (string (jam.ffi:hex-string-to-bytes signature))
                       (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length sig-bytes) 784) ()
              "Ticket signature must be 784 bytes, got: ~a" (length sig-bytes))
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u8 attempt)
                   sig-bytes))))

(defun decode-ticket (bytes offset)
  "Decode a single ticket.
   Returns: (values ticket-plist bytes-consumed)"
  (let* ((attempt (decode-u8 bytes offset))
         (signature (subseq bytes (+ offset 1) (+ offset 1 784))))
    (values (list :attempt attempt :signature signature)
            785)))

(defun encode-tickets-extrinsic (tickets)
  "Encode tickets extrinsic (ET).
   Structure: compact(n) || ticket[0] || ... || ticket[n-1]"
  (let ((encoded-tickets (mapcar #'encode-ticket tickets)))
    (concatenate '(vector (unsigned-byte 8))
                 (encode-compact (length tickets))
                 (apply #'concatenate '(vector (unsigned-byte 8)) encoded-tickets))))

(defun decode-tickets-extrinsic (bytes offset)
  "Decode tickets extrinsic (ET).
   Returns: (values tickets bytes-consumed)"
  (multiple-value-bind (num-tickets bytes-consumed-len)
      (decode-compact bytes offset)
    (let ((tickets '())
          (pos (+ offset bytes-consumed-len)))
      (dotimes (i num-tickets)
        (multiple-value-bind (ticket ticket-size)
            (decode-ticket bytes pos)
          (push ticket tickets)
          (incf pos ticket-size)))
      (values (nreverse tickets) (- pos offset)))))

(export '(encode-ticket decode-ticket
          encode-tickets-extrinsic decode-tickets-extrinsic))
