;;;; tests/test-codecs.lisp — Codec validation against jamtestvectors/codec
;;;;
;;;; Tests codec round-trip for all JAM protocol structures:
;;;;   1. Read binary file
;;;;   2. Decode to Lisp structure
;;;;   3. Re-encode
;;;;   4. Compare with original binary
;;;;
;;;; Vectors: work_item, work_package, work_report, work_result,
;;;;          tickets, disputes, preimages, assurances, guarantees,
;;;;          header, extrinsic, block, refine_context

(ql:quickload :cl-json :silent t)

(in-package :jotl)

;; Load shared test helpers
(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun decode-header-closure (bytes offset)
  "Decode header via closure :decode."
  (funcall (make-header) :decode bytes offset))

(defun encode-header-closure (header)
  "Encode header via closure :encoded."
  (funcall header :encoded))

(defun decode-block-closure (bytes offset)
  "Decode block via closure :decode."
  (funcall (make-block) :decode bytes offset))

(defun encode-block-closure (block)
  "Encode block via closure :encoded."
  (funcall block :encoded))

(defun read-binary-file (path)
  "Read binary file as byte vector."
  (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
    (let ((buf (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence buf in)
      buf)))

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC TEST RUNNERS
;;; ═══════════════════════════════════════════════════════════════

(defun test-codec-roundtrip (name bin-path decoder-fn encoder-fn &optional json-path)
  "Test codec round-trip: decode binary → encode → compare.
   Returns :pass, :fail, or :skip."
  (declare (ignorable json-path))
  (handler-case
      (let* ((original-bytes (read-binary-file bin-path))
             (decoded (funcall decoder-fn original-bytes 0))
             (re-encoded (funcall encoder-fn decoded)))
        (if (equalp original-bytes re-encoded)
            (progn
              (format t "  ~A ✅~%" name)
              :pass)
            (progn
              (format t "  ~A ❌ (length: ~D ≠ ~D)~%"
                      name (length original-bytes) (length re-encoded))
              ;; Show first diff
              (loop for i from 0 below (min (length original-bytes) (length re-encoded))
                    when (not (= (aref original-bytes i) (aref re-encoded i)))
                    do (format t "    First diff at byte ~D: 0x~2,'0X ≠ 0x~2,'0X~%"
                               i (aref original-bytes i) (aref re-encoded i))
                       (return))
              :fail)))
    (error (e)
      (format t "  ~A 💥 ~A~%" name e)
      :error)))

;;; ═══════════════════════════════════════════════════════════════
;;; CODEC DISPATCH TABLE
;;; ═══════════════════════════════════════════════════════════════

(defparameter *codec-tests*
  '(    ;; ── Work structures ──
    ("work_item"     :skip "Not implemented (internal only)")
    ("work_package"  :skip "WorkPackage is not a GP type (only WorkPackageSpec)")
    ("work_result_0" decode-work-result   encode-work-result)
    ("work_result_1" decode-work-result   encode-work-result)
    ("work_report"   decode-work-report   encode-work-report)
    ("refine_context" :skip "Not implemented (internal only)")
    
    ;; ── Extrinsics ──
    ("tickets_extrinsic"    decode-tickets-extrinsic    encode-tickets-extrinsic)
    ("disputes_extrinsic"   decode-disputes-extrinsic   encode-disputes-extrinsic)
    ("preimages_extrinsic"  decode-preimages-extrinsic  encode-preimages-extrinsic)
    ("assurances_extrinsic" decode-assurances-extrinsic encode-assurances-extrinsic)
    ("guarantees_extrinsic" decode-guarantees-extrinsic encode-guarantees-extrinsic)
    
    ;; ── Block structures ──
    ("header_0"   decode-header-closure   encode-header-closure)
    ("header_1"   decode-header-closure   encode-header-closure)
    ("extrinsic"  :skip "Extrinsic is composite (no standalone codec)")
    ("block"      decode-block-closure    encode-block-closure))
  "Codec test dispatch: (name decoder-fn encoder-fn) or (name :skip reason).")

;;; ═══════════════════════════════════════════════════════════════
;;; RUN ALL TESTS
;;; ═══════════════════════════════════════════════════════════════

(defun run-codec-tests (&key (spec :tiny))
  "Run codec round-trip tests against jamtestvectors/codec.
   SPEC: :tiny or :full"
  (let* ((base-dir (merge-pathnames
                    (format nil "jamtestvectors/codec/~(~A~)/"
                            spec)
                    (make-pathname :directory (pathname-directory *load-pathname*))))
         (pass 0) (fail 0) (skip 0) (error-count 0))

    (format t "~%╔═══════════════════════════════════════════════════════════╗~%")
    (format t "║  CODEC TESTS — ~A~40T║~%" (string-upcase (string spec)))
    (format t "╚═══════════════════════════════════════════════════════════╝~%~%")

    (with-chain spec
      (dolist (test-spec *codec-tests*)
        (let* ((name (first test-spec))
               (decoder (second test-spec))
               (encoder (third test-spec))
               (bin-path (merge-pathnames (format nil "~A.bin" name) base-dir))
               (json-path (merge-pathnames (format nil "~A.json" name) base-dir)))
          
          (cond
            ;; Skip marker
            ((eq decoder :skip)
             (format t "  ~A ⏭ ~A~%" name (or encoder "(no reason)"))
             (incf skip))
            
            ;; Test doesn't exist
            ((not (probe-file bin-path))
             (format t "  ~A ⏭ (file not found)~%" name)
             (incf skip))
            
            ;; Run test
            (t
             (let ((result (test-codec-roundtrip name bin-path decoder encoder json-path)))
               (case result
                 (:pass  (incf pass))
                 (:fail  (incf fail))
                 (:error (incf error-count))
                 (t      (incf skip)))))))))

    (format t "~%────────────────────────────────────────────────~%")
    (format t "  ✅ ~D pass  ❌ ~D fail  💥 ~D error  ⏭ ~D skip~%"
            pass fail error-count skip)
    (format t "────────────────────────────────────────────────~%~%")

    (values pass fail error-count skip)))

;;; ═══════════════════════════════════════════════════════════════
;;; ENTRY POINT
;;; ═══════════════════════════════════════════════════════════════

(format t "~%Running codec tests...~%")

;; Run tiny vectors
(multiple-value-bind (pass fail errors skip)
    (run-codec-tests :spec :tiny)
  (declare (ignorable pass fail errors skip)))
