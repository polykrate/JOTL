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
    (multiple-value-bind (header h-consumed) (load-header bytes pos)
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
      (multiple-value-bind (block blk-consumed) (load-block bytes pos)
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
;;; CHAIN LOG — boundary observation, no instrumentation
;;; ═══════════════════════════════════════════════════════════════
;;; Logs only what import-block can see: σ, B, σ', wall-clock.
;;; The STF below is pure.  Logs live here at the frontier.
;;;
;;; *chain-log-level*:
;;;   NIL      — silent (default, no overhead)
;;;   :minimal — one line per block
;;;   :normal  — + extrinsic counts, epoch events

(defvar *chain-log-level* :normal
  "Chain log verbosity: NIL :minimal :normal")

(defvar *chain-log-stream* *error-output*
  "Destination for chain logs.  Defaults to stderr.")

(defvar *chain-block-count* 0
  "Running block counter since last init.")

(defun chain-log (level fmt &rest args)
  "Emit a log line if *chain-log-level* is at or above LEVEL."
  (when (and *chain-log-level*
             (member *chain-log-level*
                     (ecase level
                       (:minimal '(:minimal :normal))
                       (:normal  '(:normal)))))
    (apply #'format *chain-log-stream* fmt args)
    (force-output *chain-log-stream*)))

(defun chain-log-block (block sigma-prime state-root elapsed-ms)
  "Observe B and σ' at the boundary.  One line per block."
  (incf *chain-block-count*)
  (let* ((h          (funcall block :header))
         (slot       (funcall h :slot))
         (epoch      (floor slot (epoch-duration)))
         (kvs-count  (length (funcall sigma-prime :merkle-kvs)))
         (root-short (subseq (bytes-to-hex-string state-root) 0 16)))
    ;; :minimal — one compact line
    (chain-log :minimal
               "~&[jotl] #~D slot=~D e=~D root=~A kvs=~D ~Dms~%"
               *chain-block-count* slot epoch root-short kvs-count elapsed-ms)
    ;; :normal — extrinsic counts when non-empty
    (let ((n-et (length (funcall block :tickets)))
          (n-ed (length (funcall block :disputes)))
          (n-ep (length (funcall block :preimages)))
          (n-ea (length (funcall block :assurances)))
          (n-eg (length (funcall block :guarantees))))
      (when (plusp (+ n-et n-ed n-ep n-ea n-eg))
        (chain-log :normal
                   "~&[jotl] #~D   ET=~D ED=~D EP=~D EA=~D EG=~D~%"
                   *chain-block-count* n-et n-ed n-ep n-ea n-eg)))
    ;; :normal — epoch boundary
    (when (funcall h :epoch-mark)
      (chain-log :normal "~&[jotl] ═══ epoch ~D ═══~%" epoch))))

;;; ═══════════════════════════════════════════════════════════════
;;; IMPORT-BLOCK — Υ(σ, B) → (σ', state-root)
;;; ═══════════════════════════════════════════════════════════════
;;; The core M1 operation: apply a block to a state and return
;;; the new state with its Merkle root.

(defun import-block (sigma block)
  "M1 Block Import: Υ(σ, B) → (σ', state-root).
   Applies the STF and computes the Merkle root of σ'.
   If any extrinsic validation fails (guarantee-error, assurance-error,
   disputes-error, safrole-error), the block is treated as invalid:
   the pre-state is returned unchanged (GP: invalid blocks are simply
   not applied).
   Emits chain logs when *chain-log-level* is set.
   Returns: (values σ' state-root)."
  (let* ((t0 (get-internal-real-time))
         (sigma-prime
          (prof :stf
            (handler-case
                (apply-block sigma block)
              (guarantee-error (e)
                (declare (ignore e))
                sigma)
              (assurance-error (e)
                (declare (ignore e))
                sigma)
              (disputes-error (e)
                (declare (ignore e))
                sigma)
              (safrole-error (e)
                (declare (ignore e))
                sigma))))
         (state-root (prof :merkle
                       (funcall sigma-prime :state-root)))
         (elapsed-ms (round (* 1000 (/ (- (get-internal-real-time) t0)
                                        internal-time-units-per-second)))))
    (when *chain-log-level*
      (chain-log-block block sigma-prime state-root elapsed-ms))
    (values sigma-prime state-root)))

;;; ═══════════════════════════════════════════════════════════════
;;; KEY DISPLAY — human-readable 31-byte Merkle key names
;;; ═══════════════════════════════════════════════════════════════

(defun kv-key-name (key-31)
  "Human-readable name for a 31-byte Merkle key."
  (cond
    ((segment-key-p key-31)
     (let* ((cn (aref key-31 0))
            (entry (rassoc cn +sigma-segment-order+)))
       (if entry
           (format nil "C(~D)=~A" cn (car entry))
           (format nil "C(~D)" cn))))
    ((service-metadata-key-p key-31)
     (format nil "meta(~D)" (service-id-from-metadata-key key-31)))
    (t
     (let ((sid (service-id-from-sub-key key-31)))
       (format nil "sub(~D)/~A" sid
               (subseq (bytes-to-hex-string (extract-sub-key-h key-31)) 0 8))))))

;;; ═══════════════════════════════════════════════════════════════
;;; TRACE FILE HELPERS — used by both chain and test runner
;;; ═══════════════════════════════════════════════════════════════

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

