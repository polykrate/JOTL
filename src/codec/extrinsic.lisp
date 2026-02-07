;;;; extrinsic.lisp - JAM Extrinsic Encoding/Decoding
;;;; Gray Paper §4.3 - Extrinsic data encoding

(in-package :jotl)

;;; ==========================================================================
;;; Extrinsic Structure (Gray Paper §4.2-4.3)
;;; ==========================================================================
;;;
;;; E ≡ (ET, ED, EP, EA, EG)
;;;
;;; Component Types:
;;;   ET : Tickets extrinsic
;;;   ED : Disputes extrinsic
;;;   EP : Preimages extrinsic
;;;   EA : Assurances extrinsic
;;;   EG : Guarantees extrinsic (work reports)

;;; ==========================================================================
;;; Tickets Extrinsic (ET)
;;; ==========================================================================
;;; Gray Paper §6.4: Tickets mechanism
;;; Gray Paper §6.29-6.35: Ticket structure and validation
;;;
;;; Ticket ≡ (attempt: u16, signature: [u8; 784])
;;;
;;; where:
;;;   attempt   : Entry index (validator index) - u16
;;;   signature : Bandersnatch Ring VRF proof - 784 bytes
;;;
;;; ET is a sequence of tickets, compact-length prefixed:
;;; E(ET) = E(↕[E(ticket) | ticket ← ET])

(defun encode-ticket (ticket)
  "Encode a single ticket (attempt: u16, signature: 784 bytes).
   
   Args:
     ticket: plist with :attempt and :signature
   
   Returns:
     byte array"
  (let ((attempt (getf ticket :attempt))
        (signature (getf ticket :signature)))
    ;; Validate
    (assert (typep attempt '(integer 0 65535)) ()
            "Ticket attempt must be u16 (0-65535), got: ~a" attempt)
    
    ;; Convert signature to bytes if it's a hex string
    (let ((sig-bytes (etypecase signature
                       ((simple-array (unsigned-byte 8) (*)) signature)
                       (string (jam.ffi:hex-string-to-bytes signature))
                       (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length sig-bytes) 784) ()
              "Ticket signature must be 784 bytes, got: ~a" (length sig-bytes))
      
      ;; Encode: u16 (little-endian) + signature
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u16 attempt)
                   sig-bytes))))

(defun decode-ticket (bytes offset)
  "Decode a single ticket from bytes.
   
   Returns: (values ticket-plist bytes-consumed)"
  (let* ((attempt (decode-u16 bytes offset))
         (signature (subseq bytes (+ offset 2) (+ offset 2 784))))
    (values (list :attempt attempt
                  :signature signature)
            786))) ; 2 (u16) + 784 (signature)

(defun encode-tickets-extrinsic (tickets)
  "Encode tickets extrinsic (ET).
   
   Gray Paper §6.29-6.30:
     ET ∈ E[{e ∈ ℕN, p ∈ ○V[]}]
     |ET| ≤ K if m' < Y, else 0
   
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
;;; Disputes Extrinsic (ED)
;;; ==========================================================================
;;; TODO: Implement based on Gray Paper §10

(defun encode-disputes-extrinsic (disputes)
  "Encode disputes extrinsic (ED).
   
   Gray Paper §10: Disputes and judgements
   
   TODO: Implement full structure
   
   Args:
     disputes: disputes data structure
   
   Returns:
     byte array"
  (declare (ignore disputes))
  (error "Disputes extrinsic encoding not yet implemented"))

(defun decode-disputes-extrinsic (bytes offset)
  "Decode disputes extrinsic (ED).
   
   ⏳ STUB: Returns empty list, expects empty sequence in data.
   TODO: Implement full structure from Gray Paper §10
   
   Returns: (values disputes bytes-consumed)"
  (decode-empty-sequence-stub bytes offset "Disputes"))

;;; ==========================================================================
;;; Preimages Extrinsic (EP)
;;; ==========================================================================
;;; Gray Paper §7.4: Preimages for lookup
;;;
;;; Preimage ≡ (requester: u32, blob: [u8])
;;;
;;; where:
;;;   requester : Service ID - u32
;;;   blob      : Data blob - variable length, compact-prefixed
;;;
;;; EP is a sequence of preimages, compact-length prefixed:
;;; E(EP) = E(↕[E(preimage) | preimage ← EP])

(defun encode-preimage (preimage)
  "Encode a single preimage (requester: u32, blob: bytes).
   
   Args:
     preimage: plist with :requester and :blob
   
   Returns:
     byte array"
  (let ((requester (getf preimage :requester))
        (blob (getf preimage :blob)))
    ;; Validate requester (u32)
    (assert (typep requester '(integer 0 4294967295)) ()
            "Preimage requester must be u32 (0-4294967295), got: ~a" requester)
    
    ;; Convert blob to bytes if it's a hex string
    (let ((blob-bytes (etypecase blob
                        ((simple-array (unsigned-byte 8) (*)) blob)
                        (string (jam.ffi:hex-string-to-bytes blob))
                        (vector (coerce blob '(simple-array (unsigned-byte 8) (*)))))))
      
      ;; Encode: u32 (little-endian) + compact-length + blob
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u32 requester)
                   (encode-compact (length blob-bytes))
                   blob-bytes))))

(defun decode-preimage (bytes offset)
  "Decode a single preimage from bytes.
   
   Returns: (values preimage-plist bytes-consumed)"
  (let* ((requester (decode-u32 bytes offset))
         (pos (+ offset 4)))
    (multiple-value-bind (blob-length bytes-consumed-len)
        (decode-compact bytes pos)
      (incf pos bytes-consumed-len)
      (let ((blob (subseq bytes pos (+ pos blob-length))))
        (values (list :requester requester
                      :blob blob)
                (+ 4 bytes-consumed-len blob-length))))))

(defun encode-preimages-extrinsic (preimages)
  "Encode preimages extrinsic (EP).
   
   Gray Paper §7.4: Preimages for lookup
   
   Args:
     preimages: list of preimage plists
   
   Returns:
     byte array"
  ;; Encode as a compact-prefixed sequence
  (let ((encoded-preimages (mapcar #'encode-preimage preimages)))
    (concatenate '(vector (unsigned-byte 8))
                 (encode-compact (length preimages))
                 (apply #'concatenate '(vector (unsigned-byte 8)) encoded-preimages))))

(defun decode-preimages-extrinsic (bytes offset)
  "Decode preimages extrinsic (EP).
   
   Returns: (values preimages bytes-consumed)"
  (multiple-value-bind (num-preimages bytes-consumed-len)
      (decode-compact bytes offset)
    (let ((preimages '())
          (pos (+ offset bytes-consumed-len)))
      (dotimes (i num-preimages)
        (multiple-value-bind (preimage preimage-size)
            (decode-preimage bytes pos)
          (push preimage preimages)
          (incf pos preimage-size)))
      (values (nreverse preimages)
              (- pos offset)))))

;;; ==========================================================================
;;; Assurances Extrinsic (EA)
;;; ==========================================================================
;;; TODO: Implement based on Gray Paper §11

(defun encode-assurances-extrinsic (assurances)
  "Encode assurances extrinsic (EA).
   
   Gray Paper §11: Availability assurances
   
   TODO: Implement full structure
   
   Args:
     assurances: assurances data structure
   
   Returns:
     byte array"
  (declare (ignore assurances))
  (error "Assurances extrinsic encoding not yet implemented"))

(defun decode-assurances-extrinsic (bytes offset)
  "Decode assurances extrinsic (EA).
   
   ⏳ STUB: Returns empty list, expects empty sequence in data.
   TODO: Implement full structure from Gray Paper §11
   
   Returns: (values assurances bytes-consumed)"
  (decode-empty-sequence-stub bytes offset "Assurances"))

;;; ==========================================================================
;;; Guarantees Extrinsic (EG) - Work Reports
;;; ==========================================================================
;;; TODO: Implement based on Gray Paper §11-12

(defun encode-guarantees-extrinsic (guarantees)
  "Encode guarantees extrinsic (EG) - work reports.
   
   Gray Paper §11-12: Work reports and guarantees
   
   TODO: Implement full structure
   
   Args:
     guarantees: guarantees data structure (work reports)
   
   Returns:
     byte array"
  (declare (ignore guarantees))
  (error "Guarantees extrinsic encoding not yet implemented"))

(defun decode-guarantees-extrinsic (bytes offset)
  "Decode guarantees extrinsic (EG) - work reports.
   
   ⏳ STUB: Returns empty list, expects empty sequence in data.
   TODO: Implement full structure from Gray Paper §11-12
   
   Returns: (values guarantees bytes-consumed)"
  (decode-empty-sequence-stub bytes offset "Guarantees"))

;;; ==========================================================================
;;; Complete Extrinsic Encoding
;;; ==========================================================================

(defun encode-extrinsic (tickets disputes preimages assurances guarantees)
  "Encode complete extrinsic E ≡ (ET, ED, EP, EA, EG).
   
   Gray Paper §4.3
   E ≡ (ET, ED, EP, EA, EG)
   
   Args:
     tickets: ET - list of ticket plists (✅ implemented)
     disputes: ED - disputes structure (⏳ stub - returns empty)
     preimages: EP - list of preimage plists (✅ implemented)
     assurances: EA - list of assurance plists (⏳ stub - returns empty)
     guarantees: EG - list of guarantee plists (⏳ stub - returns empty)
   
   Returns:
     byte array"
  (concatenate '(vector (unsigned-byte 8))
               ;; ET - Tickets (implemented)
               (encode-tickets-extrinsic tickets)
               
               ;; ED - Disputes (stub - encode empty sequence for now)
               (if disputes
                   (encode-disputes-extrinsic disputes)
                   (encode-compact 0)) ; Empty sequence = compact(0)
               
               ;; EP - Preimages (implemented)
               (encode-preimages-extrinsic preimages)
               
               ;; EA - Assurances (stub - encode empty sequence for now)
               (if assurances
                   (encode-assurances-extrinsic assurances)
                   (encode-compact 0)) ; Empty sequence = compact(0)
               
               ;; EG - Guarantees (stub - encode empty sequence for now)
               (if guarantees
                   (encode-guarantees-extrinsic guarantees)
                   (encode-compact 0)))) ; Empty sequence = compact(0)

(defun decode-extrinsic (bytes offset)
  "Decode complete extrinsic E ≡ (ET, ED, EP, EA, EG).
   
   Returns: (values extrinsic-plist bytes-consumed)"
  (let ((pos offset))
    ;; ET - Tickets (✅ implemented)
    (multiple-value-bind (tickets bytes-consumed-tickets)
        (decode-tickets-extrinsic bytes pos)
      (incf pos bytes-consumed-tickets)
      
      ;; ED - Disputes (⏳ stub - skip compact length, expect empty)
      (multiple-value-bind (disputes bytes-consumed-disputes)
          (decode-disputes-extrinsic bytes pos)
        (declare (ignore disputes)) ; Stub returns empty
        (incf pos bytes-consumed-disputes)
        
        ;; EP - Preimages (✅ implemented)
        (multiple-value-bind (preimages bytes-consumed-preimages)
            (decode-preimages-extrinsic bytes pos)
          (incf pos bytes-consumed-preimages)
          
          ;; EA - Assurances (⏳ stub - skip compact length, expect empty)
          (multiple-value-bind (assurances bytes-consumed-assurances)
              (decode-assurances-extrinsic bytes pos)
            (declare (ignore assurances)) ; Stub returns empty
            (incf pos bytes-consumed-assurances)
            
            ;; EG - Guarantees (⏳ stub - skip compact length, expect empty)
            (multiple-value-bind (guarantees bytes-consumed-guarantees)
                (decode-guarantees-extrinsic bytes pos)
              (declare (ignore guarantees)) ; Stub returns empty
              (incf pos bytes-consumed-guarantees)
              
              (values (list :tickets tickets
                            :disputes '()      ; Stub
                            :preimages preimages
                            :assurances '()    ; Stub
                            :guarantees '())   ; Stub
                      (- pos offset)))))))))

;; Helper for stub decoders: just read compact length and skip
(defun decode-empty-sequence-stub (bytes offset decoder-name)
  "Stub decoder for unimplemented sequence types.
   Reads compact length, expects 0, returns empty list.
   
   Args:
     bytes: byte array
     offset: starting position
     decoder-name: string for error messages
   
   Returns: (values '() bytes-consumed)"
  (multiple-value-bind (num-items bytes-consumed-len)
      (decode-compact bytes offset)
    (unless (zerop num-items)
      (error "~a: Expected empty sequence (not yet implemented), got length ~a"
             decoder-name num-items))
    (values '() bytes-consumed-len)))

;;; ==========================================================================
;;; Extrinsic Closure (for consistency with header)
;;; ==========================================================================

(defun make-extrinsic-encoded (&key tickets disputes preimages assurances guarantees)
  "Create an extrinsic closure with encoding support.
   
   Pure FP closure for extrinsic E ≡ (ET, ED, EP, EA, EG).
   Lazy evaluation for :encoded.
   
   Args:
     tickets: ET - list of ticket plists (✅ implemented)
     disputes: ED - disputes structure (⏳ stub)
     preimages: EP - list of preimage plists (✅ implemented)
     assurances: EA - list of assurance plists (⏳ stub)
     guarantees: EG - list of guarantee plists (⏳ stub)
   
   Returns: closure with extrinsic interface"
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      ;; Core fields (Gray Paper §4.3)
      (:tickets tickets)
      (:disputes disputes)
      (:preimages preimages)
      (:assurances assurances)
      (:guarantees guarantees)
      
      ;; Encoding (computed on demand)
      (:encoded (encode-extrinsic tickets disputes preimages assurances guarantees))
      
      ;; Metadata
      (:type :extrinsic)
      (:num-tickets (length tickets))
      (:num-preimages (length preimages))
      (:num-assurances (if assurances (length assurances) 0))
      (:num-guarantees (if guarantees (length guarantees) 0))
      
      (otherwise (error "Unknown extrinsic message: ~a" msg)))))

;;; ==========================================================================
;;; Exports
;;; ==========================================================================

(export '(;; Ticket encoding/decoding (ET) ✅
          encode-ticket
          decode-ticket
          encode-tickets-extrinsic
          decode-tickets-extrinsic
          
          ;; Preimage encoding/decoding (EP) ✅
          encode-preimage
          decode-preimage
          encode-preimages-extrinsic
          decode-preimages-extrinsic
          
          ;; Stub components (EA, ED, EG) ⏳
          encode-disputes-extrinsic
          decode-disputes-extrinsic
          encode-assurances-extrinsic
          decode-assurances-extrinsic
          encode-guarantees-extrinsic
          decode-guarantees-extrinsic
          
          ;; Complete extrinsic
          encode-extrinsic
          decode-extrinsic
          make-extrinsic-encoded
          
          ;; Helpers
          decode-empty-sequence-stub))
