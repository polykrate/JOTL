;;;; tests/test-codec-roundtrip.lisp — Codec roundtrip: decode → encode → same bytes
;;;;
;;;; For each state component with a decoder, we take raw bytes from the
;;;; fallback traces, decode into a closure, re-encode, and verify byte
;;;; equality.  Then we build σ from re-encoded bytes and verify the
;;;; Merkle state_root matches the trace.
;;;;
;;;; This proves our codecs are lossless (no passthrough needed for
;;;; implemented components).

(in-package #:jotl)

(load (merge-pathnames "test-utils.lisp" *load-pathname*))

;;; ═══════════════════════════════════════════════════════════════
;;; EXTRACT SEGMENT BYTES FROM TRACE KEYVALS
;;; ═══════════════════════════════════════════════════════════════

(defun extract-segment-bytes (state-json)
  "Parse trace state JSON → alist mapping C(n) index → raw bytes.
   Only returns segment keys (C(1)..C(16), plus C(255) for services).
   Non-segment keys (service storage, etc.) are collected separately."
  (let ((segments '())
        (other-kvs '()))
    (dolist (kv (cdr (assoc :keyvals state-json)))
      (let* ((key (hex-to-bytes (cdr (assoc :key kv))))
             (val (hex-to-bytes (cdr (assoc :value kv))))
             (first-byte (aref key 0))
             ;; Check if all remaining bytes are zero → segment key
             (is-segment (loop for i from 1 below (length key)
                               always (zerop (aref key i)))))
        (if is-segment
            (push (cons first-byte val) segments)
            (push (cons key val) other-kvs))))
    (values (nreverse segments) (nreverse other-kvs))))

;;; ═══════════════════════════════════════════════════════════════
;;; C(n) → COMPONENT KEYWORD
;;; ═══════════════════════════════════════════════════════════════

(defparameter +cn-to-keyword+
  '((1  . :alpha)  (2  . :phi)    (3  . :beta)   (4  . :gamma)
    (5  . :psi)    (6  . :eta)    (7  . :iota)   (8  . :kappa)
    (9  . :lambda) (10 . :rho)    (11 . :tau)    (12 . :chi)
    (13 . :pi)     (14 . :omega)  (15 . :xi)     (16 . :theta)))

(defparameter +implemented-decoders+
  '(:tau :eta :kappa :lambda :iota :beta :psi :rho :gamma :pi)
  "Components with full decode→encode codec.")

(defun cn-keyword (n)
  (cdr (assoc n +cn-to-keyword+)))

(defun component-has-decoder-p (kw)
  (member kw +implemented-decoders+))

;;; ═══════════════════════════════════════════════════════════════
;;; SINGLE-COMPONENT ROUNDTRIP
;;; ═══════════════════════════════════════════════════════════════

(defun roundtrip-component (kw raw-bytes)
  "Decode RAW-BYTES into a closure for component KW, re-encode,
   and return (values re-encoded-bytes closure consumed).
   Signals an error if the decoder fails."
  (let ((closure (sigma-decode-segment kw raw-bytes)))
    (values (funcall closure :encoded) closure)))

(defun test-roundtrip-one (kw raw-bytes &key (verbose t))
  "Test decode → encode roundtrip for one component.
   Returns T if bytes match, NIL otherwise."
  (handler-case
      (multiple-value-bind (re-encoded closure) (roundtrip-component kw raw-bytes)
        (declare (ignore closure))
        (let ((ok (equalp re-encoded raw-bytes)))
          (when verbose
            (format t "  ~12A  ~6D bytes  ~A~%"
                    kw (length raw-bytes) (if ok "✓" "✗"))
            (unless ok
              (format t "    original:    ~D bytes~%" (length raw-bytes))
              (format t "    re-encoded:  ~D bytes~%" (length re-encoded))
              ;; Find first difference
              (let ((min-len (min (length raw-bytes) (length re-encoded))))
                (loop for i from 0 below min-len
                      when (/= (aref raw-bytes i) (aref re-encoded i))
                      do (format t "    first diff at byte ~D: ~2,'0X vs ~2,'0X~%"
                                 i (aref raw-bytes i) (aref re-encoded i))
                         (return)))))
          ok))
    (error (e)
      (when verbose
        (format t "  ~12A  ~6D bytes  ERROR: ~A~%" kw (length raw-bytes) e))
      nil)))

;;; ═══════════════════════════════════════════════════════════════
;;; FULL STATE ROUNDTRIP (all segments from a trace state)
;;; ═══════════════════════════════════════════════════════════════

(defun test-roundtrip-state (state-json &key (label "state") (verbose t))
  "Test codec roundtrip for all segments in a trace state.
   Returns: (values all-ok pass-count fail-count passthrough-count)."
  (multiple-value-bind (segments other-kvs) (extract-segment-bytes state-json)
    (declare (ignore other-kvs))
    (let ((pass 0) (fail 0) (passthrough 0)
          (re-encoded-segments '()))
      (when verbose
        (format t "~%  ── ~A: ~D segments ──~%" label (length segments)))
      ;; Test each segment
      (dolist (entry segments)
        (let* ((cn (car entry))
               (raw (cdr entry))
               (kw (cn-keyword cn)))
          (cond
            ;; Unknown C(n) (e.g. C(255) for services)
            ((null kw)
             (when verbose
               (format t "  C(~3D)          ~6D bytes  (service/other — passthrough)~%" cn (length raw)))
             (incf passthrough))
            ;; Implemented: try roundtrip
            ((component-has-decoder-p kw)
             (if (test-roundtrip-one kw raw :verbose verbose)
                 (progn
                   (incf pass)
                   ;; Use re-encoded bytes for Merkle check
                   (push (cons cn (funcall (sigma-decode-segment kw raw) :encoded))
                         re-encoded-segments))
                 (progn
                   (incf fail)
                   ;; Still include original bytes
                   (push (cons cn raw) re-encoded-segments))))
            ;; Not yet implemented: passthrough
            (t
             (when verbose
               (format t "  ~12A  ~6D bytes  (no decoder — passthrough)~%" kw (length raw)))
             (incf passthrough)
             (push (cons cn raw) re-encoded-segments)))))
      (when verbose
        (format t "  ── ~D passed, ~D failed, ~D passthrough ──~%" pass fail passthrough))
      (values (zerop fail) pass fail passthrough re-encoded-segments))))

;;; ═══════════════════════════════════════════════════════════════
;;; MERKLE VERIFICATION FROM RE-ENCODED BYTES
;;; ═══════════════════════════════════════════════════════════════

(defun build-sigma-from-segments (segments other-kvs)
  "Build a σ from segment bytes (C(n) . bytes) and other key-value pairs.
   Returns the computed state root."
  ;; Build Merkle KV pairs: C(n) as 31-byte keys + raw bytes
  (let ((kvs '()))
    ;; Fixed segments C(1)..C(16)
    (dolist (entry segments)
      (let* ((cn (car entry))
             (raw (cdr entry))
             (key (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0)))
        (setf (aref key 0) cn)
        (push (cons key raw) kvs)))
    ;; Other KVs (service accounts etc.) — pass through as-is
    (dolist (kv other-kvs)
      (push kv kvs))
    (compute-state-root (nreverse kvs))))

(defun test-roundtrip-merkle (state-json expected-root &key (label "state"))
  "Verify that re-encoded segments produce the same Merkle root."
  (multiple-value-bind (segments other-kvs) (extract-segment-bytes state-json)
    ;; Build re-encoded segments (decode → encode for implemented components)
    (let ((re-segments '()))
      (dolist (entry segments)
        (let* ((cn (car entry))
               (raw (cdr entry))
               (kw (cn-keyword cn)))
          (if (and kw (component-has-decoder-p kw))
              ;; Roundtrip through codec
              (handler-case
                  (let ((closure (sigma-decode-segment kw raw)))
                    (push (cons cn (funcall closure :encoded)) re-segments))
                (error (e)
                  (declare (ignore e))
                  (push (cons cn raw) re-segments)))
              ;; Passthrough
              (push (cons cn raw) re-segments))))
      (let* ((computed (build-sigma-from-segments (nreverse re-segments) other-kvs))
             (ok (equalp computed expected-root)))
        (format t "  Merkle ~A: ~A~%" label (if ok "✓" "✗"))
        (unless ok
          (format t "    expected: ~A~%" (jam.ffi:bytes-to-hex-string expected-root))
          (format t "    computed: ~A~%" (jam.ffi:bytes-to-hex-string computed)))
        ok))))

;;; ═══════════════════════════════════════════════════════════════
;;; GENESIS TEST
;;; ═══════════════════════════════════════════════════════════════

(defun test-codec-genesis ()
  "Roundtrip test on genesis state."
  (format t "~%═══════════════════════════════════════════════════~%")
  (format t "  Codec Roundtrip — Genesis~%")
  (format t "═══════════════════════════════════════════════════~%")
  (let* ((json (load-json "tests/jamtestvectors/traces/fallback/genesis.json"))
         (state-json (cdr (assoc :state json)))
         (expected-root (hex-to-bytes (cdr (assoc :state--root state-json)))))
    (multiple-value-bind (ok pass fail pt)
        (test-roundtrip-state state-json :label "genesis")
      (declare (ignore pass fail pt))
      ;; Now verify Merkle root from re-encoded bytes
      (let ((merkle-ok (test-roundtrip-merkle state-json expected-root
                                               :label "genesis (re-encoded)")))
        (and ok merkle-ok)))))

;;; ═══════════════════════════════════════════════════════════════
;;; BLOCK-BY-BLOCK TEST
;;; ═══════════════════════════════════════════════════════════════

(defun test-codec-block (block-num &key (verbose t))
  "Roundtrip test on a single block's pre and post states."
  (let* ((path (format nil "tests/jamtestvectors/traces/fallback/~8,'0D.json" block-num))
         (json (load-json path))
         (pre-json (cdr (assoc :pre--state json)))
         (post-json (cdr (assoc :post--state json)))
         (pre-root (hex-to-bytes (cdr (assoc :state--root pre-json))))
         (post-root (hex-to-bytes (cdr (assoc :state--root post-json))))
         (pre-ok t) (post-ok t))
    ;; Pre-state roundtrip
    (multiple-value-bind (ok _p _f _pt)
        (test-roundtrip-state pre-json :label (format nil "block ~D pre" block-num)
                                        :verbose verbose)
      (declare (ignore _p _f _pt))
      (unless ok (setf pre-ok nil)))
    ;; Post-state roundtrip
    (multiple-value-bind (ok _p _f _pt)
        (test-roundtrip-state post-json :label (format nil "block ~D post" block-num)
                                         :verbose verbose)
      (declare (ignore _p _f _pt))
      (unless ok (setf post-ok nil)))
    ;; Merkle verification
    (unless (test-roundtrip-merkle pre-json pre-root
                                    :label (format nil "block ~D pre" block-num))
      (setf pre-ok nil))
    (unless (test-roundtrip-merkle post-json post-root
                                    :label (format nil "block ~D post" block-num))
      (setf post-ok nil))
    (and pre-ok post-ok)))

(defun test-codec-blocks (&key (from 1) (to 10) (verbose nil))
  "Roundtrip test on a range of fallback blocks."
  (format t "~%═══════════════════════════════════════════════════~%")
  (format t "  Codec Roundtrip — Blocks ~D to ~D~%" from to)
  (format t "═══════════════════════════════════════════════════~%")
  (let ((pass 0) (fail 0))
    (loop for b from from to to do
      (handler-case
          (if (test-codec-block b :verbose verbose)
              (progn
                (unless verbose
                  (format t "  Block ~3D: ✓~%" b))
                (incf pass))
              (progn
                (format t "  Block ~3D: ✗ (roundtrip failure)~%" b)
                (incf fail)))
        (error (e)
          (format t "  Block ~3D: ERROR ~A~%" b e)
          (incf fail))))
    (format t "~%  Results: ~D passed, ~D failed~%" pass fail)
    (zerop fail)))

;;; ═══════════════════════════════════════════════════════════════
;;; RUNNER
;;; ═══════════════════════════════════════════════════════════════

(defun run-codec-roundtrip-tests ()
  "Run all codec roundtrip tests."
  (with-chain :tiny
    (let ((ok t))
      (unless (test-codec-genesis) (setf ok nil))
      (unless (test-codec-blocks :from 1 :to 10) (setf ok nil))
      ok)))
