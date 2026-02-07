;;;; tickets.lisp - ET (Tickets Extrinsic) Encoding/Decoding
;;;; Gray Paper §6.4, §6.29-6.35

(in-package :jotl)

;;; ==========================================================================
;;; Tickets Extrinsic (ET)
;;; ==========================================================================
;;; Gray Paper §6.4: Tickets mechanism
;;; Gray Paper §6.29-6.35: Ticket structure and validation
;;;
;;; Ticket ≡ (attempt: u8, signature: [u8; 784])
;;;
;;; where:
;;;   attempt   : Entry index (validator index) - u8 (0-255)
;;;   signature : Bandersnatch Ring VRF proof - 784 bytes
;;;
;;; ET is a sequence of tickets, compact-length prefixed:
;;; E(ET) = E(↕[E(ticket) | ticket ← ET])

(defun encode-ticket (ticket)
  "Encode a single ticket (attempt: u8, signature: 784 bytes).
   
   Args:
     ticket: plist with :attempt and :signature
   
   Returns:
     byte array"
  (let ((attempt (getf ticket :attempt))
        (signature (getf ticket :signature)))
    ;; Validate
    (assert (typep attempt '(integer 0 255)) ()
            "Ticket attempt must be u8 (0-255), got: ~a" attempt)
    
    ;; Convert signature to bytes if it's a hex string
    (let ((sig-bytes (etypecase signature
                       ((simple-array (unsigned-byte 8) (*)) signature)
                       (string (jam.ffi:hex-string-to-bytes signature))
                       (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length sig-bytes) 784) ()
              "Ticket signature must be 784 bytes, got: ~a" (length sig-bytes))
      
      ;; Encode: u8 + signature (784 bytes)
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u8 attempt)
                   sig-bytes))))

(defun decode-ticket (bytes offset)
  "Decode a single ticket from bytes.
   
   Returns: (values ticket-plist bytes-consumed)"
  (let* ((attempt (decode-u8 bytes offset))
         (signature (subseq bytes (+ offset 1) (+ offset 1 784))))
    (values (list :attempt attempt
                  :signature signature)
            785))) ; 1 (u8) + 784 (signature)

(defun encode-tickets-extrinsic (tickets)
  "Encode tickets extrinsic (ET).
   
   Gray Paper §6.29-6.30:
     ET ∈ E[{e ∈ ℕN, p ∈ ○V[]}]
     |ET| ≤ K if m' < Y, else 0
   
   Structure: compact(n) || ticket[0] || ... || ticket[n-1]
   Each ticket: u8 (attempt) || [u8; 784] (signature)
   
   Args:
     tickets: list of ticket plists
   
   Returns:
     byte array"
  ;; Encode as a compact-prefixed sequence
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
      (values (nreverse tickets)
              (- pos offset)))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(encode-ticket
          decode-ticket
          encode-tickets-extrinsic
          decode-tickets-extrinsic))
