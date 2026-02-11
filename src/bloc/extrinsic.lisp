;;;; bloc/extrinsic.lisp — Extrinsic E ≡ (ET, ED, EP, EA, EG)
;;;; Gray Paper §4.3, §5.4-5.6
;;;;
;;;; The extrinsic is NOT a closure — it is raw data consumed by the state
;;;; transition.  The block (B) is a message, not an actor; its extrinsic
;;;; sub-elements are open data that state closures consume directly.
;;;;
;;;; This module provides pure functions for:
;;;;   encode-extrinsic-data   — E(E) binary encoding
;;;;   decode-extrinsic-data   — bytes → (values ET ED EP EA EG consumed)
;;;;   compute-extrinsic-hash  — HX = H(H#(ET) ⌢ H#(EP) ⌢ H#(g) ⌢ H#(EA) ⌢ H#(ED))
;;;;
;;;; Binary order: ET → EP → EG → EA → ED

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; HX helpers — sub-computations for compute-extrinsic-hash
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
;;; ENCODE — E(E), binary order: ET → EP → EG → EA → ED
;;; ═════════════════════════════════════════════════════════════════

(defun encode-extrinsic-data (tickets disputes preimages assurances guarantees)
  "Encode extrinsic data E(E) = ET || EP || EG || EA || ED."
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

;;; ═════════════════════════════════════════════════════════════════
;;; DECODE — bytes → raw extrinsic parts
;;; ═════════════════════════════════════════════════════════════════

(defun decode-extrinsic-data (bytes offset)
  "Decode extrinsic data from BYTES at OFFSET.
   Binary order: ET → EP → EG → EA → ED.
   Returns: (values tickets disputes preimages assurances guarantees consumed)"
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
              (values et ed ep ea eg
                      (- pos offset)))))))))

;;; ═════════════════════════════════════════════════════════════════
;;; HX — Extrinsic Hash (GP §5.4-5.6)
;;; ═════════════════════════════════════════════════════════════════

(defun compute-extrinsic-hash (tickets disputes preimages assurances guarantees)
  "HX = blake2b(H(ET) || H(EP) || H(g) || H(EA) || H(ED)) — §5.4-5.6.
   Pure function on raw extrinsic data."
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
