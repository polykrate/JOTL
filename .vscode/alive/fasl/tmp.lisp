;;;; preimages.lisp
;;;; JAM Preimages (EP) - Static data for workloads
;;;; Graypaper references: Section 4.2, Appendix C.18

(in-package :jotl-bloc)

;;; Preimages EP
;;;
;;; Static data which is presently being requested to be available
;;; for workloads to be able to fetch on demand.
;;;
;;; Graypaper Section 4.2: The Block (extrinsic data component)

(defstruct preimage
  "A preimage entry (s, d).
   
   Static data that is made available for workloads to fetch on demand.
   - s ∈ N: service ID (natural number)
   - d ∈ B: data blob (octet sequence)"
  
  (service-id nil :type (or null natural))  ; s ∈ N
  (data nil :type (or null blob)))          ; d ∈ B

(deftype preimages ()
  "Sequence of preimages (EP)"
  'list)

;;; Encoding (Appendix C.18)
;;; Graypaper C.18: EP(EP) = E(↕[(E4(s), ↕d) | (s,d) ∈ EP])
;;;
;;; Length-prefixed sequence of (service_id, data) pairs where:
;;; - s: service ID encoded on 4 octets (E4)
;;; - d: data blob with length prefix (↕d per C.7)

(defun encode-preimages (preimages)
  "Encode preimages (EP).
   
   Graypaper Appendix C.18: EP(EP) = E(↕[(E4(s), ↕d) | (s,d) ∈ EP])
   
   Args:
     preimages: List of preimage structures or (service-id . data) pairs
   
   Returns:
     Encoded octet sequence"
  (let ((encoded-pairs
         (mapcar (lambda (preimage)
                   (let ((s (if (preimage-p preimage)
                               (preimage-service-id preimage)
                               (car preimage)))
                         (d (if (preimage-p preimage)
                               (preimage-data preimage)
                               (cdr preimage))))
                    ;; E4(s), ↕d
                    ;; Convert blob to list if needed
                    (let ((d-octets (if (listp d) d (blob-to-list d))))
                      (concat-octets (e4 s)
                                     (encode-with-length d-octets)))))
                 preimages)))
    ;; ↕[...] : length-prefixed sequence
    (let ((concatenated (apply #'concat-octets encoded-pairs)))
      (concat-octets (encode-natural (length concatenated))
                     concatenated))))

(defun decode-preimages (octets &optional (start 0))
  "Decode preimages from octets.
   
   Inverse of encode-preimages (Appendix C.18).
   Decodes: EP(EP) = E(↕[(E4(s), ↕d) | (s,d) ∈ EP])
   
   Args:
     octets: Encoded preimages data
     start: Starting position
   
   Returns:
     values: (list-of-preimages bytes-consumed)"
  ;; First, decode the length prefix
  (multiple-value-bind (total-length length-bytes)
      (decode-natural octets start)
    (let ((preimages '())
          (pos (+ start length-bytes))
          (end-pos (+ start length-bytes total-length)))
      ;; Decode each (E4(s), ↕d) pair
      (loop while (< pos end-pos) do
        ;; Decode E4(s) : service ID on 4 octets
        (let* ((service-id-octets (subseq octets pos (+ pos 4)))
               (service-id (decode-fixed-integer service-id-octets 4)))
          (incf pos 4)
          ;; Decode ↕d : length-prefixed data
          (multiple-value-bind (data data-consumed)
              (decode-with-length octets pos)
            (incf pos data-consumed)
            ;; Create preimage structure
            (push (make-preimage :service-id service-id
                                     :data (list-to-blob data))
                  preimages))))
      (values (nreverse preimages) (+ length-bytes total-length)))))
