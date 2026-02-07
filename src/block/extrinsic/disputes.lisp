;;;; block/extrinsic/disputes.lisp — ED (Disputes Extrinsic)
;;;; Gray Paper §10

(in-package :jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Disputes Extrinsic (ED)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; GP C.21: ED((v, c, f)) = E(↕[...], ↕c, ↕f)
;;;
;;; Verdict ≡ (target: H, age: u32, votes: [...])
;;; Culprit ≡ (target: H, key: H, signature: [u8; 64])
;;; Fault   ≡ (target: H, vote: bool, key: H, signature: [u8; 64])

;;; ----- Votes -----

(defun encode-vote (vote)
  "Encode a single vote (vote: bool, index: u16, signature: [u8; 64])."
  (let ((vote-bool (getf vote :vote))
        (index (getf vote :index))
        (signature (getf vote :signature)))
    (let ((sig-bytes (etypecase signature
                       ((simple-array (unsigned-byte 8) (*)) signature)
                       (string (jam.ffi:hex-string-to-bytes signature))
                       (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length sig-bytes) 64) ()
              "Vote signature must be 64 bytes, got: ~a" (length sig-bytes))
      (concatenate '(vector (unsigned-byte 8))
                   (encode-u8 (if vote-bool 1 0))
                   (encode-u16 index)
                   sig-bytes))))

(defun decode-vote (bytes offset)
  "Decode a single vote.
   Returns: (values vote-plist bytes-consumed)"
  (let* ((vote-bool (not (zerop (decode-u8 bytes offset))))
         (index (decode-u16 bytes (+ offset 1)))
         (signature (subseq bytes (+ offset 3) (+ offset 67))))
    (values (list :vote vote-bool :index index :signature signature)
            67)))

;;; ----- Verdicts -----

(defun encode-verdict (verdict)
  "Encode a verdict. Votes have NO compact prefix (fixed count from chainspec)."
  (let ((target (getf verdict :target))
        (age (getf verdict :age))
        (votes (getf verdict :votes)))
    (let ((target-bytes (etypecase target
                          ((simple-array (unsigned-byte 8) (*)) target)
                          (string (jam.ffi:hex-string-to-bytes target))
                          (vector (coerce target '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length target-bytes) 32))
      (let ((expected-votes (1+ (floor (* 2 (num-validators)) 3))))
        (assert (= (length votes) expected-votes) ()
                "Verdict must have ~a votes, got: ~a" expected-votes (length votes)))
      (let ((encoded-votes (mapcar #'encode-vote votes)))
        (concatenate '(vector (unsigned-byte 8))
                     target-bytes
                     (encode-u32 age)
                     (apply #'concatenate '(vector (unsigned-byte 8)) encoded-votes))))))

(defun decode-verdict (bytes offset)
  "Decode a verdict. Vote count from chainspec: ⌊2V/3⌋+1.
   Returns: (values verdict-plist bytes-consumed)"
  (let* ((target (subseq bytes offset (+ offset 32)))
         (age (decode-u32 bytes (+ offset 32)))
         (pos (+ offset 36))
         (num-votes (1+ (floor (* 2 (num-validators)) 3)))
         (votes '()))
    (dotimes (i num-votes)
      (multiple-value-bind (vote vote-size)
          (decode-vote bytes pos)
        (push vote votes)
        (incf pos vote-size)))
    (values (list :target target :age age :votes (nreverse votes))
            (- pos offset))))

;;; ----- Culprits -----

(defun encode-culprit (culprit)
  "Encode a culprit (target: H, key: H, signature: [u8; 64])."
  (let ((target (getf culprit :target))
        (key (getf culprit :key))
        (signature (getf culprit :signature)))
    (let ((target-bytes (etypecase target
                          ((simple-array (unsigned-byte 8) (*)) target)
                          (string (jam.ffi:hex-string-to-bytes target))
                          (vector (coerce target '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length target-bytes) 32))
      (let ((key-bytes (etypecase key
                         ((simple-array (unsigned-byte 8) (*)) key)
                         (string (jam.ffi:hex-string-to-bytes key))
                         (vector (coerce key '(simple-array (unsigned-byte 8) (*)))))))
        (assert (= (length key-bytes) 32))
        (let ((sig-bytes (etypecase signature
                           ((simple-array (unsigned-byte 8) (*)) signature)
                           (string (jam.ffi:hex-string-to-bytes signature))
                           (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
          (assert (= (length sig-bytes) 64))
          (concatenate '(vector (unsigned-byte 8))
                       target-bytes key-bytes sig-bytes))))))

(defun decode-culprit (bytes offset)
  "Decode a culprit.
   Returns: (values culprit-plist bytes-consumed)"
  (let ((target (subseq bytes offset (+ offset 32)))
        (key (subseq bytes (+ offset 32) (+ offset 64)))
        (signature (subseq bytes (+ offset 64) (+ offset 128))))
    (values (list :target target :key key :signature signature)
            128)))

;;; ----- Faults -----

(defun encode-fault (fault)
  "Encode a fault (target: H, vote: bool, key: H, signature: [u8; 64])."
  (let ((target (getf fault :target))
        (vote (getf fault :vote))
        (key (getf fault :key))
        (signature (getf fault :signature)))
    (let ((target-bytes (etypecase target
                          ((simple-array (unsigned-byte 8) (*)) target)
                          (string (jam.ffi:hex-string-to-bytes target))
                          (vector (coerce target '(simple-array (unsigned-byte 8) (*)))))))
      (assert (= (length target-bytes) 32))
      (let ((key-bytes (etypecase key
                         ((simple-array (unsigned-byte 8) (*)) key)
                         (string (jam.ffi:hex-string-to-bytes key))
                         (vector (coerce key '(simple-array (unsigned-byte 8) (*)))))))
        (assert (= (length key-bytes) 32))
        (let ((sig-bytes (etypecase signature
                           ((simple-array (unsigned-byte 8) (*)) signature)
                           (string (jam.ffi:hex-string-to-bytes signature))
                           (vector (coerce signature '(simple-array (unsigned-byte 8) (*)))))))
          (assert (= (length sig-bytes) 64))
          (concatenate '(vector (unsigned-byte 8))
                       target-bytes
                       (encode-u8 (if vote 1 0))
                       key-bytes sig-bytes))))))

(defun decode-fault (bytes offset)
  "Decode a fault.
   Returns: (values fault-plist bytes-consumed)"
  (let ((target (subseq bytes offset (+ offset 32)))
        (vote (not (zerop (decode-u8 bytes (+ offset 32)))))
        (key (subseq bytes (+ offset 33) (+ offset 65)))
        (signature (subseq bytes (+ offset 65) (+ offset 129))))
    (values (list :target target :vote vote :key key :signature signature)
            129)))

;;; ----- Complete Disputes -----

(defun encode-disputes-extrinsic (disputes)
  "Encode disputes extrinsic (ED)."
  (let ((verdicts (getf disputes :verdicts))
        (culprits (getf disputes :culprits))
        (faults (getf disputes :faults)))
    (let ((encoded-verdicts (mapcar #'encode-verdict verdicts))
          (encoded-culprits (mapcar #'encode-culprit culprits))
          (encoded-faults (mapcar #'encode-fault faults)))
      (concatenate '(vector (unsigned-byte 8))
                   (encode-compact (length verdicts))
                   (apply #'concatenate '(vector (unsigned-byte 8)) encoded-verdicts)
                   (encode-compact (length culprits))
                   (apply #'concatenate '(vector (unsigned-byte 8)) encoded-culprits)
                   (encode-compact (length faults))
                   (apply #'concatenate '(vector (unsigned-byte 8)) encoded-faults)))))

(defun decode-disputes-extrinsic (bytes offset)
  "Decode disputes extrinsic (ED).
   Returns: (values disputes-plist bytes-consumed)"
  (let ((pos offset))
    (multiple-value-bind (num-verdicts bytes-consumed-len-v)
        (decode-compact bytes pos)
      (incf pos bytes-consumed-len-v)
      (let ((verdicts '()))
        (dotimes (i num-verdicts)
          (multiple-value-bind (verdict verdict-size)
              (decode-verdict bytes pos)
            (push verdict verdicts)
            (incf pos verdict-size)))
        (setf verdicts (nreverse verdicts))
        (multiple-value-bind (num-culprits bytes-consumed-len-c)
            (decode-compact bytes pos)
          (incf pos bytes-consumed-len-c)
          (let ((culprits '()))
            (dotimes (i num-culprits)
              (multiple-value-bind (culprit culprit-size)
                  (decode-culprit bytes pos)
                (push culprit culprits)
                (incf pos culprit-size)))
            (setf culprits (nreverse culprits))
            (multiple-value-bind (num-faults bytes-consumed-len-f)
                (decode-compact bytes pos)
              (incf pos bytes-consumed-len-f)
              (let ((faults '()))
                (dotimes (i num-faults)
                  (multiple-value-bind (fault fault-size)
                      (decode-fault bytes pos)
                    (push fault faults)
                    (incf pos fault-size)))
                (setf faults (nreverse faults))
                (values (list :verdicts verdicts :culprits culprits :faults faults)
                        (- pos offset))))))))))

(export '(encode-vote decode-vote
          encode-verdict decode-verdict
          encode-culprit decode-culprit
          encode-fault decode-fault
          encode-disputes-extrinsic decode-disputes-extrinsic))
