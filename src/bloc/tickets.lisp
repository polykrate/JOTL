;;;; bloc/tickets.lisp — ET (Tickets Extrinsic)
;;;; Gray Paper §6.4, §6.29-6.35

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Tickets Extrinsic (ET)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Ticket ≡ (attempt: N, signature: [u8; 784])
;;; attempt uses GP C.5 compact natural encoding.
;;; ET is a compact-prefixed sequence of tickets.

(defun encode-ticket (ticket)
  "Encode a single ticket (attempt: compact natural, signature: 784 bytes)."
  (let ((attempt (getf ticket :attempt))
        (signature (getf ticket :signature)))
    (check-type attempt (integer 0 *))
    (let ((sig-bytes (etypecase signature
                       ((simple-array (unsigned-byte 8) (*)) signature)
                       (string (jam.ffi:hex-string-to-bytes signature))
                       (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length sig-bytes) 784) ()
              "Ticket signature must be 784 bytes, got: ~a" (length sig-bytes))
      (concatenate '(vector (unsigned-byte 8))
                   (encode-compact attempt)
                   sig-bytes))))

(defun decode-ticket (bytes offset)
  "Decode a single ticket.
   Returns: (values ticket-plist bytes-consumed)"
  (multiple-value-bind (attempt attempt-bytes)
      (decode-compact bytes offset)
    (let* ((sig-start (+ offset attempt-bytes))
           (signature (subseq bytes sig-start (+ sig-start 784))))
      (values (list :attempt attempt :signature signature)
              (+ attempt-bytes 784)))))

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

;;; Exports managed in package.lisp
