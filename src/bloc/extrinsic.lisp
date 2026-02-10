;;;; bloc/extrinsic.lisp — Extrinsic E ≡ (ET, ED, EP, EA, EG) + HX
;;;; Gray Paper §4.3, §5.4-5.6
;;;;
;;;; Binary order: ET → EP → EG → EA → ED
;;;;
;;;; Messages:
;;;;   :tickets, :disputes, :preimages, :assurances, :guarantees
;;;;   :reports           — alias for :guarantees
;;;;   :encoded           — E(E)
;;;;   :extrinsic-hash    — HX = H(H#(ET) ⌢ H#(EP) ⌢ H#(g) ⌢ H#(EA) ⌢ H#(ED))
;;;;   :num-tickets, :num-disputes, :num-preimages, :num-assurances, :num-guarantees
;;;;   :decode bytes off  — (values E-closure consumed)

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; HX helpers — sub-computations for :extrinsic-hash
;;; ═════════════════════════════════════════════════════════════════

(defun encode-guarantee-summary (guarantee)
  "Encode a single guarantee summary for HX: (H(r), E4(t), ↕a)."
  (let* ((report-bytes (or (getf guarantee :report-raw-bytes)
                            (encode-work-report (getf guarantee :report))))
         (h-r (jam.ffi:blake2b-256 report-bytes))
         (e4-t (encode-u32 (getf guarantee :slot)))
         (sigs (encode-guarantee-signatures (getf guarantee :signatures))))
    (concatenate '(vector (unsigned-byte 8)) h-r e4-t sigs)))

(defun compute-guarantee-summaries (guarantees)
  "Compute g = E(↕[(H(r), E4(t), ↕a) | ...])."
  (encode-sequence (or guarantees '()) #'encode-guarantee-summary))

;;; ═════════════════════════════════════════════════════════════════
;;; EXTRINSIC CLOSURE — define-state-closure
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; GP §4.3: E ≡ (ET, ED, EP, EA, EG)
;;;
;;; Tout passe par messages — pas de defun encode/decode standalone.

(define-state-closure extrinsic
  ((tickets nil) (disputes nil) (preimages nil)
   (assurances nil) (guarantees nil))

  ;; ── Alias ────────────────────────────────────────────────────
  (:reports guarantees)

  ;; ── Encode E(E) — Binary order: ET → EP → EG → EA → ED ─────
  (:encoded :memo
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

  ;; ── HX — GP §5.4-5.6 ────────────────────────────────────────
  ;; HX = blake2b(H(ET) || H(EP) || H(g) || H(EA) || H(ED))
  (:extrinsic-hash :memo
   (let* ((enc-t  (encode-tickets-extrinsic (or tickets '())))
          (enc-p  (encode-preimages-extrinsic (or preimages '())))
          (enc-a  (encode-assurances-extrinsic (or assurances '())))
          (enc-d  (if disputes
                      (encode-disputes-extrinsic disputes)
                      (concatenate '(vector (unsigned-byte 8))
                                   (encode-compact 0)
                                   (encode-compact 0)
                                   (encode-compact 0))))
          (g      (compute-guarantee-summaries guarantees))
          (h-et   (jam.ffi:blake2b-256 enc-t))
          (h-ep   (jam.ffi:blake2b-256 enc-p))
          (h-g    (jam.ffi:blake2b-256 g))
          (h-ea   (jam.ffi:blake2b-256 enc-a))
          (h-ed   (jam.ffi:blake2b-256 enc-d)))
     (jam.ffi:blake2b-256
      (concatenate '(vector (unsigned-byte 8))
                   h-et h-ep h-g h-ea h-ed))))

  ;; ── Counts ───────────────────────────────────────────────────
  (:num-tickets (length (or tickets '())))
  (:num-disputes (if (and disputes (listp disputes))
                     (+ (length (or (getf disputes :verdicts) '()))
                        (length (or (getf disputes :culprits) '()))
                        (length (or (getf disputes :faults) '())))
                     0))
  (:num-preimages (length (or preimages '())))
  (:num-assurances (length (or assurances '())))
  (:num-guarantees (length (or guarantees '())))

  ;; ── Decode: bytes → E closure ───────────────────────────────
  ;; Binary order: ET → EP → EG → EA → ED
  (:decode (bytes offset)
    (let ((pos offset))
      (multiple-value-bind (et et-bytes)
          (decode-tickets-extrinsic bytes pos)
        (incf pos et-bytes)
        (multiple-value-bind (ep ep-bytes)
            (decode-preimages-extrinsic bytes pos)
          (incf pos ep-bytes)
          (multiple-value-bind (eg eg-bytes)
              (decode-guarantees-extrinsic bytes pos)
            (incf pos eg-bytes)
            (multiple-value-bind (ea ea-bytes)
                (decode-assurances-extrinsic bytes pos)
              (incf pos ea-bytes)
              (multiple-value-bind (ed ed-bytes)
                  (decode-disputes-extrinsic bytes pos)
                (incf pos ed-bytes)
                (values (make-extrinsic
                         :tickets et :disputes ed :preimages ep
                         :assurances ea :guarantees eg)
                        (- pos offset))))))))))

;;; decode-extrinsic is auto-generated by define-state-closure:
;;;   (decode-extrinsic bytes offset) → (values E-closure consumed)
