;;;; block/extrinsic/extrinsic.lisp — Extrinsic Orchestrator + HX
;;;; Gray Paper §4.3, §5.4-5.6
;;;;
;;;; E ≡ (ET, ED, EP, EA, EG)
;;;; HX ≡ H(E(H#(a)))
;;;;
;;;; Binary order: ET → EP → EG → EA → ED

(in-package :jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; EXTRINSIC ENCODING / DECODING
;;; ═════════════════════════════════════════════════════════════════

(defun encode-extrinsic (tickets disputes preimages assurances guarantees)
  "Encode complete extrinsic. Binary order: ET → EP → EG → EA → ED."
  (concatenate '(vector (unsigned-byte 8))
               (encode-tickets-extrinsic tickets)
               (encode-preimages-extrinsic preimages)
               (encode-guarantees-extrinsic guarantees)
               (if assurances
                   (encode-assurances-extrinsic assurances)
                   (encode-compact 0))
               (if disputes
                   (encode-disputes-extrinsic disputes)
                   (concatenate '(vector (unsigned-byte 8))
                                (encode-compact 0)
                                (encode-compact 0)
                                (encode-compact 0)))))

(defun decode-extrinsic (bytes offset)
  "Decode complete extrinsic. Binary order: ET → EP → EG → EA → ED.
   Returns: (values extrinsic-plist bytes-consumed)"
  (let ((pos offset))
    (multiple-value-bind (tickets bytes-consumed-tickets)
        (decode-tickets-extrinsic bytes pos)
      (incf pos bytes-consumed-tickets)
      (multiple-value-bind (preimages bytes-consumed-preimages)
          (decode-preimages-extrinsic bytes pos)
        (incf pos bytes-consumed-preimages)
        (multiple-value-bind (guarantees bytes-consumed-guarantees)
            (decode-guarantees-extrinsic bytes pos)
          (incf pos bytes-consumed-guarantees)
          (multiple-value-bind (assurances bytes-consumed-assurances)
              (decode-assurances-extrinsic bytes pos)
            (incf pos bytes-consumed-assurances)
            (multiple-value-bind (disputes bytes-consumed-disputes)
                (decode-disputes-extrinsic bytes pos)
              (incf pos bytes-consumed-disputes)
              (values (list :tickets tickets :disputes disputes
                            :preimages preimages :assurances assurances
                            :guarantees guarantees)
                      (- pos offset)))))))))

;;; ═════════════════════════════════════════════════════════════════
;;; EXTRINSIC CLOSURE — make-extrinsic
;;; ═════════════════════════════════════════════════════════════════

(defun make-extrinsic (&key tickets disputes preimages assurances guarantees)
  "Creates extrinsic closure E ≡ (ET, ED, EP, EA, EG).
   
   Gray Paper §4.3. Immutable, lazy encoding."
  (lambda (msg &rest args)
    (declare (ignore args))
    (case msg
      ;; Core fields
      (:tickets tickets)
      (:disputes disputes)
      (:preimages preimages)
      (:assurances assurances)
      (:guarantees guarantees)
      
      ;; Aliases
      (:reports guarantees)
      
      ;; Encoding (lazy)
      (:encoded (encode-extrinsic tickets disputes preimages assurances guarantees))
      
      ;; Snapshot
      (:as-plist (list :tickets tickets :disputes disputes
                       :preimages preimages :assurances assurances
                       :guarantees guarantees))
      
      ;; Counts
      (:num-tickets (length (or tickets '())))
      (:num-disputes (if (and disputes (listp disputes))
                         (+ (length (or (getf disputes :verdicts) '()))
                            (length (or (getf disputes :culprits) '()))
                            (length (or (getf disputes :faults) '())))
                         0))
      (:num-preimages (length (or preimages '())))
      (:num-assurances (length (or assurances '())))
      (:num-guarantees (length (or guarantees '())))
      
      ;; Metadata
      (:type :extrinsic)
      
      (otherwise (error "Unknown extrinsic message: ~a" msg)))))

;;; ═════════════════════════════════════════════════════════════════
;;; EXTRINSIC ACCESSORS
;;; ═════════════════════════════════════════════════════════════════

(defun extrinsic-tickets (e) "ET" (funcall e :tickets))
(defun extrinsic-disputes (e) "ED" (funcall e :disputes))
(defun extrinsic-preimages (e) "EP" (funcall e :preimages))
(defun extrinsic-assurances (e) "EA" (funcall e :assurances))
(defun extrinsic-guarantees (e) "EG" (funcall e :guarantees))

;;; ═════════════════════════════════════════════════════════════════
;;; EXTRINSIC HASH — HX (GP §5.4-5.6)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; HX ≡ H(E(H#(a)))
;;; HX = blake2b-256(H(ET) || H(EP) || H(g) || H(EA) || H(ED))
;;;
;;; where g = E(↕[(H(r), E4(t), ↕a) | (r, t, a) ← EG])

(defun encode-guarantee-summary (guarantee)
  "Encode a single guarantee summary for HX: (H(r), E4(t), ↕a).
   H(r) = Blake2b-256 of the JAM-encoded work report."
  (let* ((report-bytes (or (getf guarantee :report-raw-bytes)
                            (encode-work-report (getf guarantee :report))))
         (h-r (jam.ffi:blake2b-256 report-bytes))
         (e4-t (encode-u32 (getf guarantee :slot)))
         (sigs (encode-guarantee-signatures (getf guarantee :signatures))))
    (concatenate '(vector (unsigned-byte 8)) h-r e4-t sigs)))

(defun compute-guarantee-summaries (guarantees)
  "Compute g = E(↕[(H(r), E4(t), ↕a) | ...]).
   Compact-prefixed sequence of guarantee summaries."
  (encode-sequence (or guarantees '()) #'encode-guarantee-summary))

(defun compute-extrinsic-hash (extrinsic-data)
  "Compute HX from extrinsic data (plist).
   
   GP §5.4-5.6:
     HX = blake2b(H(ET) || H(EP) || H(g) || H(EA) || H(ED))
   
   Args:
     extrinsic-data: plist with :tickets :preimages :assurances :disputes :guarantees
   
   Returns: 32-byte hash"
  (let* ((tickets    (getf extrinsic-data :tickets))
         (preimages  (getf extrinsic-data :preimages))
         (guarantees (getf extrinsic-data :guarantees))
         (assurances (getf extrinsic-data :assurances))
         (disputes   (getf extrinsic-data :disputes))
         ;; Encode each component
         (encoded-tickets    (encode-tickets-extrinsic (or tickets '())))
         (encoded-preimages  (encode-preimages-extrinsic (or preimages '())))
         (encoded-assurances (encode-assurances-extrinsic (or assurances '())))
         (encoded-disputes   (if disputes
                                 (encode-disputes-extrinsic disputes)
                                 (concatenate '(vector (unsigned-byte 8))
                                              (encode-compact 0)
                                              (encode-compact 0)
                                              (encode-compact 0))))
         ;; g = guarantee summaries
         (g (compute-guarantee-summaries guarantees))
         ;; H#(a) = [H(ET), H(EP), H(g), H(EA), H(ED)]
         (h-et (jam.ffi:blake2b-256 encoded-tickets))
         (h-ep (jam.ffi:blake2b-256 encoded-preimages))
         (h-g  (jam.ffi:blake2b-256 g))
         (h-ea (jam.ffi:blake2b-256 encoded-assurances))
         (h-ed (jam.ffi:blake2b-256 encoded-disputes))
         ;; E(H#(a)) = H(ET) || H(EP) || H(g) || H(EA) || H(ED) = 160 bytes
         (concatenated (concatenate '(vector (unsigned-byte 8))
                                    h-et h-ep h-g h-ea h-ed)))
    (jam.ffi:blake2b-256 concatenated)))

(defun compute-extrinsic-hash-from-closure (extrinsic-closure)
  "Compute HX from an extrinsic closure."
  (compute-extrinsic-hash (funcall extrinsic-closure :as-plist)))

(export '(;; Encoding/Decoding
          encode-extrinsic decode-extrinsic
          ;; Closure
          make-extrinsic
          ;; Accessors
          extrinsic-tickets extrinsic-disputes extrinsic-preimages
          extrinsic-assurances extrinsic-guarantees
          ;; HX
          encode-guarantee-summary compute-guarantee-summaries
          compute-extrinsic-hash compute-extrinsic-hash-from-closure))
