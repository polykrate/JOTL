;;;; import.lisp — M1 Block Importer (GP Milestone 1)
;;;;
;;;; Production-grade API for importing blocks from binary trace data.
;;;; Same code path for test (trace vectors) and production.
;;;;
;;;; Binary formats (from jamtestvectors/traces/convert.py):
;;;;
;;;;   RawState  = OpaqueHash (32 bytes) + Vec<KeyValue>
;;;;   KeyValue  = key ([u8; 31]) + value (ByteSequence, compact-prefixed)
;;;;   Genesis   = Header + RawState
;;;;   TraceStep = RawState + Block + RawState
;;;;
;;;; API:
;;;;   decode-raw-state-bin(bytes offset)  → (values keyvals state-root consumed)
;;;;   decode-genesis-bin(bytes)           → (values header σ₀ state-root)
;;;;   decode-trace-step-bin(bytes)        → (values pre-σ block post-σ pre-root post-root)
;;;;   import-block(σ block)               → (values σ' state-root)
;;;;   run-trace(dir &key from to verbose) → (values pass fail)

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; BINARY PARSERS — JAM codec for trace/genesis files
;;; ═══════════════════════════════════════════════════════════════

(defun decode-keyvalue-bin (bytes offset)
  "Decode a single KeyValue = key ([u8;31]) + value (ByteSequence).
   ByteSequence = compact-length-prefix + raw bytes.
   Returns: (values (key-31b . value-bytes) consumed)."
  (let* ((pos offset)
         ;; Key: fixed 31 bytes
         (key (subseq bytes pos (+ pos 31))))
    (incf pos 31)
    ;; Value: compact-length-prefixed byte sequence
    (multiple-value-bind (val-len len-consumed) (decode-compact bytes pos)
      (incf pos len-consumed)
      (let ((val (subseq bytes pos (+ pos val-len))))
        (incf pos val-len)
        (values (cons key val) (- pos offset))))))

(defun decode-raw-state-bin (bytes offset)
  "Decode RawState = OpaqueHash (32 bytes) + Vec<KeyValue>.
   Returns: (values keyvals state-root consumed).
   keyvals is a list of (key-31b . value-bytes) pairs."
  (let* ((pos offset)
         ;; state_root: 32 bytes
         (state-root (subseq bytes pos (+ pos 32))))
    (incf pos 32)
    ;; keyvals: compact-length-prefixed sequence of KeyValue
    (multiple-value-bind (kv-count count-consumed) (decode-compact bytes pos)
      (incf pos count-consumed)
      (let ((keyvals '()))
        (dotimes (i kv-count)
          (multiple-value-bind (kv consumed) (decode-keyvalue-bin bytes pos)
            (push kv keyvals)
            (incf pos consumed)))
        (values (nreverse keyvals) state-root (- pos offset))))))

(defun decode-genesis-bin (bytes)
  "Decode Genesis = Header + RawState from binary bytes.
   Returns: (values header σ₀ state-root)."
  (let ((pos 0))
    ;; Header
    (multiple-value-bind (header h-consumed) (decode-header bytes pos)
      (incf pos h-consumed)
      ;; RawState
      (multiple-value-bind (keyvals state-root _consumed)
          (decode-raw-state-bin bytes pos)
        (declare (ignore _consumed))
        (let ((sigma (load-state-from-keyvals keyvals)))
          (values header sigma state-root))))))

(defun decode-trace-step-bin (bytes)
  "Decode TraceStep = RawState + Block + RawState from binary bytes.
   Returns: (values pre-σ block post-σ pre-root post-root)."
  (let ((pos 0))
    ;; Pre-state
    (multiple-value-bind (pre-kvs pre-root pre-consumed)
        (decode-raw-state-bin bytes pos)
      (incf pos pre-consumed)
      ;; Block
      (multiple-value-bind (block blk-consumed) (decode-block bytes pos)
        (incf pos blk-consumed)
        ;; Post-state
        (multiple-value-bind (post-kvs post-root _consumed)
            (decode-raw-state-bin bytes pos)
          (declare (ignore _consumed))
          (let ((pre-sigma  (load-state-from-keyvals pre-kvs))
                (post-sigma (load-state-from-keyvals post-kvs)))
            (values pre-sigma block post-sigma pre-root post-root)))))))

;;; ═══════════════════════════════════════════════════════════════
;;; FILE LOADERS — convenience wrappers for loading from disk
;;; ═══════════════════════════════════════════════════════════════

(defun load-genesis (path)
  "Load genesis.bin from PATH.
   Returns: (values header σ₀ state-root)."
  (let ((bytes (alexandria:read-file-into-byte-vector path)))
    (decode-genesis-bin bytes)))

(defun load-trace-step (path)
  "Load a trace step .bin from PATH.
   Returns: (values pre-σ block post-σ pre-root post-root)."
  (let ((bytes (alexandria:read-file-into-byte-vector path)))
    (decode-trace-step-bin bytes)))

;;; ═══════════════════════════════════════════════════════════════
;;; IMPORT-BLOCK — Υ(σ, B) → (σ', state-root)
;;; ═══════════════════════════════════════════════════════════════
;;; The core M1 operation: apply a block to a state and return
;;; the new state with its Merkle root.

(defun import-block (sigma block)
  "M1 Block Import: Υ(σ, B) → (σ', state-root).
   Applies the STF and computes the Merkle root of σ'.
   Returns: (values σ' state-root)."
  (let ((sigma-prime (apply-block sigma block)))
    (values sigma-prime (funcall sigma-prime :state-root))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN-TRACE — chain runner for M1 conformance testing
;;; ═══════════════════════════════════════════════════════════════
;;; Two modes:
;;;   1. Chain mode (fallback): genesis → block 1 → block 2 → ...
;;;      Our σ' from block N becomes σ for block N+1.
;;;   2. Step mode (fuzzy/any): each step independent, use trace pre_state.
;;;
;;; Both verify state_root against expected post_state root.

(defun trace-block-path (dir block-num)
  "Build the path to block BLOCK-NUM's .bin file in DIR."
  (format nil "~A/~8,'0D.bin" dir block-num))

(defun trace-genesis-path (dir)
  "Build the path to genesis.bin in DIR."
  (format nil "~A/genesis.bin" dir))

(defun trace-has-genesis-p (dir)
  "Does DIR contain a genesis.bin?"
  (probe-file (trace-genesis-path dir)))

(defun count-trace-blocks (dir)
  "Count how many numbered .bin files exist in DIR."
  (loop for i from 1
        while (probe-file (trace-block-path dir i))
        finally (return (1- i))))

(defun run-trace (dir &key (from 1) to (mode :chain) (verbose t))
  "Run M1 block import trace from DIR.

   MODE:
     :chain — Load genesis (or step 1 pre_state), apply blocks sequentially.
              Our σ' from block N becomes σ for block N+1.
              Compare our state-root against trace post_state root at each step.
     :step  — Each block loaded independently from trace pre_state.
              Useful when chain diverges early (e.g. fuzzy with accumulate).

   Returns: (values pass fail)."
  (let* ((max-block (count-trace-blocks dir))
         (end-block (min (or to max-block) max-block))
         (pass 0) (fail 0)
         (sigma nil))

    (when verbose
      (format t "~%═══════════════════════════════════════════════════~%")
      (format t "  M1 Block Import — ~A~%" (enough-namestring dir))
      (format t "  Blocks ~D to ~D  (mode: ~A)~%" from end-block mode)
      (format t "═══════════════════════════════════════════════════~%"))

    ;; Initialize σ for chain mode
    (when (eq mode :chain)
      (if (trace-has-genesis-p dir)
          ;; Has genesis: load it
          (multiple-value-bind (header genesis-sigma genesis-root)
              (load-genesis (trace-genesis-path dir))
            (declare (ignore header))
            (setf sigma genesis-sigma)
            (let* ((computed-root (funcall sigma :state-root))
                   (ok (equalp computed-root genesis-root)))
              (when verbose
                (format t "  Genesis: ~A  (~D segments)~%"
                        (if ok "✓" "✗")
                        (length (funcall sigma :components))))
              (unless ok
                (format t "    expected: ~A~%"
                        (jam.ffi:bytes-to-hex-string genesis-root))
                (format t "    computed: ~A~%"
                        (bytes-to-hex-string computed-root)))))
          ;; No genesis: load pre_state from first step
          (multiple-value-bind (pre-sigma _block _post-sigma _pre-root _post-root)
              (load-trace-step (trace-block-path dir from))
            (declare (ignore _block _post-sigma _pre-root _post-root))
            (setf sigma pre-sigma)
            (when verbose
              (format t "  No genesis.bin — using block ~D pre_state~%" from)))))

    ;; Process blocks
    (loop for b from from to end-block do
      (handler-case
          (let ((step-path (trace-block-path dir b)))
            (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
                (load-trace-step step-path)
              (declare (ignore post-sigma))
              ;; In step mode, always use trace's pre_state
              (when (eq mode :step)
                (setf sigma pre-sigma))
              ;; Sanity: verify our σ matches trace pre_state root (chain mode)
              (when (and (eq mode :chain) verbose)
                (let ((our-root (funcall sigma :state-root)))
                  (unless (equalp our-root pre-root)
                    (format t "  Block ~3D: pre-state DRIFT~%" b)
                    (format t "    ours:     ~A~%"
                            (bytes-to-hex-string our-root))
                    (format t "    expected: ~A~%"
                            (bytes-to-hex-string pre-root)))))
              ;; Apply block
              (multiple-value-bind (sigma-prime computed-root)
                  (import-block sigma block-cl)
                (let ((ok (equalp computed-root post-root)))
                  (if ok
                      (progn
                        (incf pass)
                        (when verbose
                          (format t "  Block ~3D: ✓~%" b)))
                      (progn
                        (incf fail)
                        (when verbose
                          (format t "  Block ~3D: ✗~%" b)
                          (format t "    expected: ~A~%"
                                  (bytes-to-hex-string post-root))
                          (format t "    computed: ~A~%"
                                  (bytes-to-hex-string computed-root)))))
                  ;; Advance σ for chain mode
                  (when (eq mode :chain)
                    (setf sigma sigma-prime))))))
        (error (e)
          (incf fail)
          (when verbose
            (format t "  Block ~3D: ERROR ~A~%" b e)))))

    (when verbose
      (format t "~%  Results: ~D/~D passed~%" pass (+ pass fail)))
    (values pass fail)))
