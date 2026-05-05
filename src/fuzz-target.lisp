;;;; fuzz-target.lisp — fuzz-v1 protocol target server for JOTL
;;;;
;;;; Implements a Unix socket server that speaks the fuzz-v1 protocol
;;;; for JAM conformance testing.
;;;;
;;;; Three layers:
;;;;   A. Message Codec  — encode/decode fuzz-v1 binary messages
;;;;   B. State Manager  — fork-aware chain state (hash-table)
;;;;   C. Socket Server  — Unix domain socket server with read/dispatch/respond
;;;;
;;;; Entry point: (run-fuzz-target :socket "/tmp/jam_target.sock")
;;;;
;;;; See jam-conformance/fuzz-proto/README.md for the protocol specification.
;;;; See jam-conformance/fuzz-proto/fuzz-v1.asn for the ASN.1 schema.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; Layer A — Message Codec (fuzz-v1)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Wire format: [4-byte LE length][message_bytes]
;;; Each message starts with a variant discriminant byte.

;;; ── Variant discriminants ───────────────────────────────────────

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defconstant +fuzz-peer-info+    #x00)
  (defconstant +fuzz-initialize+   #x01)
  (defconstant +fuzz-state-root+   #x02)
  (defconstant +fuzz-import-block+ #x03)
  (defconstant +fuzz-get-state+    #x04)
  (defconstant +fuzz-state+        #x05)
  (defconstant +fuzz-error+        #xFF))

;;; ── Feature bits ────────────────────────────────────────────────

(defconstant +feature-ancestry+ 1)   ; 2^0 — ancestry support [M1]
(defconstant +feature-forks+    2)   ; 2^1 — simple forking   [M1]

;;; ── Decode helpers ──────────────────────────────────────────────

(defun decode-fuzz-kvs (bytes offset)
  "Decode compact(count) + count * KeyValue from BYTES at OFFSET.
   KeyValue = key(31 bytes) + compact(val_len) + val_bytes.
   Reuses existing decode-keyvalue-bin from import.lisp.
   Returns: (values kvs-list bytes-consumed)."
  (multiple-value-bind (kv-count count-consumed) (decode-compact bytes offset)
    (let ((pos (+ offset count-consumed))
          (kvs '()))
      (dotimes (i kv-count)
        (multiple-value-bind (kv consumed) (decode-keyvalue-bin bytes pos)
          (push kv kvs)
          (incf pos consumed)))
      (values (nreverse kvs) (- pos offset)))))

(defun decode-fuzz-ancestry (bytes offset)
  "Decode compact(count) + count * AncestryItem from BYTES at OFFSET.
   AncestryItem = u32LE(slot) + hash(32 bytes).
   Returns: (values ancestry-list bytes-consumed)."
  (multiple-value-bind (count count-consumed) (decode-compact bytes offset)
    (let ((pos (+ offset count-consumed))
          (items '()))
      (dotimes (i count)
        (multiple-value-bind (slot _n) (decode-u32 bytes pos)
          (declare (ignore _n))
          (incf pos 4)
          (let ((hash (subseq bytes pos (+ pos 32))))
            (incf pos 32)
            (push (list :slot slot :hash hash) items))))
      (values (nreverse items) (- pos offset)))))

;;; ── Main message decoder ────────────────────────────────────────

(defun decode-fuzz-message (bytes)
  "Decode a fuzz-v1 message from binary BYTES.
   Returns: (values type payload).
   TYPE is one of: :peer-info :initialize :import-block
                   :get-state :state-root :state :error.
   PAYLOAD depends on TYPE."
  (let ((variant (aref bytes 0)))
    (case variant
      ;; ── PeerInfo ──
      (#.+fuzz-peer-info+
       (let ((pos 1))
         (let ((fuzz-ver (aref bytes pos)))
           (incf pos)
           (multiple-value-bind (features _n) (decode-u32 bytes pos)
             (declare (ignore _n))
             (incf pos 4)
             (let ((jmaj (aref bytes pos))
                   (jmin (aref bytes (+ pos 1)))
                   (jpat (aref bytes (+ pos 2))))
               (incf pos 3)
               (let ((amaj (aref bytes pos))
                     (amin (aref bytes (+ pos 1)))
                     (apat (aref bytes (+ pos 2))))
                 (incf pos 3)
                 (multiple-value-bind (name-len nc) (decode-compact bytes pos)
                   (incf pos nc)
                   (let ((name (map 'string #'code-char
                                    (subseq bytes pos (+ pos name-len)))))
                     (values :peer-info
                             (list :fuzz-version fuzz-ver
                                   :features features
                                   :jam-version (list jmaj jmin jpat)
                                   :app-version (list amaj amin apat)
                                   :app-name name))))))))))

      ;; ── Initialize ──
      (#.+fuzz-initialize+
       (let ((pos 1))
         ;; Decode header (reuse existing decode-header)
         (multiple-value-bind (header h-consumed) (decode-header bytes pos)
           (incf pos h-consumed)
           ;; Decode KVs
           (multiple-value-bind (kvs kv-consumed) (decode-fuzz-kvs bytes pos)
             (incf pos kv-consumed)
             ;; Decode ancestry
             (multiple-value-bind (ancestry _ac) (decode-fuzz-ancestry bytes pos)
               (declare (ignore _ac))
               (values :initialize
                       (list :header header
                             :keyvals kvs
                             :ancestry ancestry)))))))

      ;; ── StateRoot ──
      (#.+fuzz-state-root+
       (values :state-root (subseq bytes 1 33)))

      ;; ── ImportBlock ──
      (#.+fuzz-import-block+
       (multiple-value-bind (block _consumed) (decode-block bytes 1)
         (declare (ignore _consumed))
         (values :import-block block)))

      ;; ── GetState ──
      (#.+fuzz-get-state+
       (values :get-state (subseq bytes 1 33)))

      ;; ── State ──
      (#.+fuzz-state+
       (multiple-value-bind (kvs _consumed) (decode-fuzz-kvs bytes 1)
         (declare (ignore _consumed))
         (values :state kvs)))

      ;; ── Error ──
      (#.+fuzz-error+
       (let ((pos 1))
         (multiple-value-bind (msg-len nc) (decode-compact bytes pos)
           (incf pos nc)
           (values :error
                   (map 'string #'code-char
                        (subseq bytes pos (+ pos msg-len)))))))

      (otherwise
       (error "Unknown fuzz message variant: #x~2,'0X" variant)))))

;;; ── Encoders ────────────────────────────────────────────────────

(defun encode-fuzz-peer-info (&key (fuzz-version 1)
                                   (features (logior +feature-ancestry+
                                                     +feature-forks+))
                                   (jam-version '(0 7 2))
                                   (app-version '(5 0 0))
                                   (app-name "jotl"))
  "Encode our PeerInfo response.
   Default features = 3 (ancestry + forks) for M1 conformance.
   Binary layout:
     0x00 + u8(fuzz_ver) + u32LE(features) + 3xu8(jam_ver) + 3xu8(app_ver)
     + compact(name_len) + utf8(name)"
  (let* ((name-bytes (map '(vector (unsigned-byte 8)) #'char-code app-name))
         (name-len-enc (encode-compact (length name-bytes))))
    (concatenate '(vector (unsigned-byte 8))
                 (vector +fuzz-peer-info+)
                 (vector fuzz-version)
                 (E4 features)
                 (vector (first jam-version)
                         (second jam-version)
                         (third jam-version))
                 (vector (first app-version)
                         (second app-version)
                         (third app-version))
                 name-len-enc
                 name-bytes)))

(defun encode-fuzz-state-root (hash-32)
  "Encode StateRoot = 0x02 + 32 bytes."
  (let ((result (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref result 0) +fuzz-state-root+)
    (replace result (ensure-bytes hash-32) :start1 1 :end1 33)
    result))

(defun encode-fuzz-error (message)
  "Encode Error = 0xFF + compact(len) + ASCII bytes.
   Non-ASCII characters (like em-dash) are replaced with '?' to avoid
   (UNSIGNED-BYTE 8) overflow."
  (let* ((msg-bytes (map '(vector (unsigned-byte 8))
                         (lambda (c)
                           (let ((code (char-code c)))
                             (if (< code 128) code (char-code #\?))))
                         message))
         (len-enc (encode-compact (length msg-bytes))))
    (concatenate '(vector (unsigned-byte 8))
                 (vector +fuzz-error+)
                 len-enc
                 msg-bytes)))

(defun encode-fuzz-kv (kv)
  "Encode a single KeyValue = key(31 bytes) + compact(val_len) + val_bytes."
  (let* ((key (car kv))
         (val (cdr kv))
         (len-enc (encode-compact (length val))))
    (concatenate '(vector (unsigned-byte 8))
                 (ensure-bytes key)
                 len-enc
                 (ensure-bytes val))))

(defun encode-fuzz-state (kvs)
  "Encode State = 0x05 + compact(count) + KV pairs."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (vector +fuzz-state+)
         (encode-compact (length kvs))
         (mapcar #'encode-fuzz-kv kvs)))


;;; ═══════════════════════════════════════════════════════════════
;;; Layer B — State Manager (fork-aware)
;;; ═══════════════════════════════════════════════════════════════
;;;
;;; Maintains a hash table of header-hash → sigma for fork support.
;;; Fork depth is limited to 1 (mutations never become parents).
;;; Ancestry is maintained as a list of (slot, header-hash) pairs.

(defconstant +max-live-states+ 128
  "Maximum number of states to keep in memory.
   Oldest states are GC'd when this limit is exceeded.
   Set high enough for fuzzer forks scenarios (up to ~50 concurrent chains).")

(defconstant +gc-interval-blocks+ 1000
  "Trigger a full GC every N block imports to bound heap growth.
   Each import allocates O(S) cons cells (COW metadata, S = services) +
   O(|delta-kvs| log |delta-kvs|) byte vectors (Merkle recompute).
   Without periodic collection these promote to older GC generations
   and the heap grows monotonically over long sessions (100K+ blocks).")

(defstruct fuzz-state-manager
  "Fork-aware state manager for fuzz-v1 sessions."
  ;; Hash table: header-hash (32 bytes, equalp) → sigma closure
  (states (make-hash-table :test 'equalp) :type hash-table)
  ;; Current head hash (most recent successful import on main chain)
  (head-hash nil)
  ;; Ordered list of stored hashes (most recent first) for GC
  (hash-order nil :type list)
  ;; Ancestry: list of (:slot N :hash H) plists, most recent first
  (ancestry nil :type list))

(defun fuzz-store-state (mgr hash sigma)
  "Store sigma by header hash in the state manager.
   Trims old states when the table exceeds +max-live-states+."
  (setf (gethash hash (fuzz-state-manager-states mgr)) sigma)
  (setf (fuzz-state-manager-head-hash mgr) hash)
  ;; Track insertion order for GC
  (push hash (fuzz-state-manager-hash-order mgr))
  ;; GC: remove oldest states when over limit
  (let ((order (fuzz-state-manager-hash-order mgr)))
    (when (> (length order) +max-live-states+)
      (let ((to-remove (nthcdr +max-live-states+ order)))
        (dolist (old-hash to-remove)
          (remhash old-hash (fuzz-state-manager-states mgr)))
        (setf (fuzz-state-manager-hash-order mgr)
              (subseq order 0 +max-live-states+))))))

(defun fuzz-lookup-state (mgr hash)
  "Look up a state by header hash. Returns sigma closure or NIL."
  (gethash hash (fuzz-state-manager-states mgr)))

;;; ── Message handlers ────────────────────────────────────────────

(defun fuzz-handle-initialize (mgr payload)
  "Handle Initialize message.
   Decodes header + KVs, builds sigma, stores by header hash.
   Returns: state-root (32 bytes)."
  (let* ((header    (getf payload :header))
         (kvs       (getf payload :keyvals))
         (ancestry  (getf payload :ancestry))
         (header-hash (funcall header :hash))
         (sigma     (load-state-from-keyvals kvs))
         (state-root (funcall sigma :state-root)))
    ;; Clear all previous states (re-initialization)
    (clrhash (fuzz-state-manager-states mgr))
    (setf (fuzz-state-manager-hash-order mgr) nil)
    ;; Store genesis state
    (fuzz-store-state mgr header-hash sigma)
    ;; Store ancestry
    (setf (fuzz-state-manager-ancestry mgr) ancestry)
    state-root))

(defun fuzz-handle-import-block (mgr block)
  "Handle ImportBlock: find parent state, apply STF, store result.
   Returns: (values :ok state-root) or (values :error message).
   Unlike import-block, errors are returned as Error messages
   instead of returning the pre-state unchanged.

   Pre-STF checks:
     1. Parent must exist in our state table
     2. HP (parent state root in header) must match parent σ's state root"
  (let* ((header (funcall block :header))
         (parent-hash (funcall header :parent-hash))
         (parent-sigma (fuzz-lookup-state mgr parent-hash)))
    ;; Check 1: Parent must exist in our state table
    (unless parent-sigma
      (return-from fuzz-handle-import-block
        (values :error
                (format nil "Unknown parent: 0x~A"
                        (subseq (bytes-to-hex-string parent-hash) 0 16)))))
    ;; Check 2: HP — header's parent state root must match actual parent SR
    (let ((header-sr (funcall header :state-root))
          (parent-sr (funcall parent-sigma :state-root)))
      (unless (equalp header-sr parent-sr)
        (return-from fuzz-handle-import-block
          (values :error
                  (format nil "Invalid parent state root: expected 0x~A, got 0x~A"
                          (subseq (bytes-to-hex-string parent-sr) 0 16)
                          (subseq (bytes-to-hex-string header-sr) 0 16))))))
    ;; Apply STF — let errors propagate to handler-case
    (handler-case
        (let* ((sigma-prime (apply-block parent-sigma block))
               (state-root (funcall sigma-prime :state-root))
               (block-hash (funcall header :hash)))
          ;; Store new state by block hash
          (fuzz-store-state mgr block-hash sigma-prime)
          ;; Update ancestry (prepend, trim to L=24)
          (let ((slot (funcall header :slot)))
            (push (list :slot slot :hash block-hash)
                  (fuzz-state-manager-ancestry mgr))
            (when (> (length (fuzz-state-manager-ancestry mgr)) 24)
              (setf (fuzz-state-manager-ancestry mgr)
                    (subseq (fuzz-state-manager-ancestry mgr) 0 24))))
          (values :ok state-root))
      ;; GP-defined validation errors → Error message
      (guarantee-error (e)
        (values :error (format nil "Guarantee error: ~A" e)))
      (assurance-error (e)
        (values :error (format nil "Assurance error: ~A" e)))
      (disputes-error (e)
        (values :error (format nil "Disputes error: ~A" e)))
      (safrole-error (e)
        (values :error (format nil "Safrole error: ~A" e)))
      (preimages-error (e)
        (values :error (format nil "Preimages error: ~A" e)))
      ;; Block validation errors (from validate-block in apply-block)
      (simple-error (e)
        (values :error (format nil "Block error: ~A" e))))))

(defun fuzz-handle-get-state (mgr hash)
  "Handle GetState: look up sigma by header hash, return merkle KVs.
   Returns: (values :ok kvs-list) or (values :error message)."
  (let ((sigma (fuzz-lookup-state mgr hash)))
    (if sigma
        (values :ok (funcall sigma :merkle-kvs))
        (values :error
                (format nil "Unknown state: 0x~A"
                        (subseq (bytes-to-hex-string hash) 0 16))))))


;;; ═══════════════════════════════════════════════════════════════
;;; Layer C — Socket Server (sb-bsd-sockets)
;;; ═══════════════════════════════════════════════════════════════

(defun fuzz-read-exact (stream buf)
  "Read exactly (length BUF) bytes from binary STREAM into BUF.
   Returns T on success, NIL on EOF/short read."
  (let ((total (length buf))
        (pos 0))
    (loop while (< pos total) do
      (let ((n (read-sequence buf stream :start pos)))
        (when (= n pos) ; no progress → EOF
          (return-from fuzz-read-exact nil))
        (setf pos n)))
    t))

(defun fuzz-recv-message (stream)
  "Read a length-prefixed fuzz-v1 message from binary STREAM.
   Wire format: [4-byte LE length][message_bytes].
   Returns: raw message bytes, or NIL on EOF."
  (let ((len-buf (make-array 4 :element-type '(unsigned-byte 8))))
    (unless (fuzz-read-exact stream len-buf)
      (return-from fuzz-recv-message nil))
    (let ((msg-len (logior (aref len-buf 0)
                           (ash (aref len-buf 1) 8)
                           (ash (aref len-buf 2) 16)
                           (ash (aref len-buf 3) 24))))
      (when (zerop msg-len)
        (return-from fuzz-recv-message nil))
      (let ((msg-buf (make-array msg-len :element-type '(unsigned-byte 8))))
        (unless (fuzz-read-exact stream msg-buf)
          (return-from fuzz-recv-message nil))
        msg-buf))))

(defun fuzz-send-message (stream bytes)
  "Send a length-prefixed fuzz-v1 message to binary STREAM.
   Wire format: [4-byte LE length][message_bytes]."
  (let ((len (length bytes))
        (len-buf (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref len-buf 0) (logand len #xFF)
          (aref len-buf 1) (logand (ash len -8) #xFF)
          (aref len-buf 2) (logand (ash len -16) #xFF)
          (aref len-buf 3) (logand (ash len -24) #xFF))
    (write-sequence len-buf stream)
    (write-sequence bytes stream)
    (force-output stream)))

;;; ── Session loop ────────────────────────────────────────────────

(defun fuzz-session-loop (stream mgr)
  "Main session loop: read messages, dispatch, respond.
   Runs until the connection is closed (EOF).
   Rejects a second Initialize within the same session (closes connection).
   Periodic GC every +gc-interval-blocks+ imports to bound heap growth
   over long fuzzing sessions (100K+ blocks)."
  (let ((import-count 0)
        (initialized-p nil))
  (loop
    (let ((raw (fuzz-recv-message stream)))
      (unless raw
        (format t "~&[jotl-fuzz] Connection closed by peer~%")
        (force-output)
        (return))

      ;; Decode and dispatch
      (handler-case
          (multiple-value-bind (msg-type payload) (decode-fuzz-message raw)
            (format t "[jotl-fuzz] << ~A~%" msg-type)
            (force-output)

            (let ((response
                    (case msg-type
                      ;; ── PeerInfo → PeerInfo ──
                      (:peer-info
                       (let ((fuzz-ver (getf payload :fuzz-version)))
                         (unless (= fuzz-ver 1)
                           (format t "[jotl-fuzz] WARNING: fuzz version ~D (expected 1)~%"
                                   fuzz-ver))
                         (format t "[jotl-fuzz] >> peer-info (jotl, features=3)~%")
                         (encode-fuzz-peer-info)))

                      ;; ── Initialize → StateRoot (reject double) ──
                      (:initialize
                       (when initialized-p
                         (format t "[jotl-fuzz] Rejecting second Initialize, closing session~%")
                         (force-output)
                         (return))
                       (let ((state-root (fuzz-handle-initialize mgr payload)))
                         (setf initialized-p t)
                         (format t "[jotl-fuzz] >> state-root ~A...~%"
                                 (subseq (bytes-to-hex-string state-root) 0 16))
                         (encode-fuzz-state-root state-root)))

                      ;; ── ImportBlock → StateRoot or Error ──
                      (:import-block
                       (multiple-value-bind (status result)
                           (fuzz-handle-import-block mgr payload)
                         (incf import-count)
                         (when (zerop (mod import-count +gc-interval-blocks+))
                           (sb-ext:gc :full t)
                           (format t "[jotl-fuzz] GC after ~D imports~%" import-count))
                         (if (eq status :ok)
                             (progn
                               (format t "[jotl-fuzz] >> state-root ~A...~%"
                                       (subseq (bytes-to-hex-string result) 0 16))
                               (encode-fuzz-state-root result))
                             (progn
                               (format t "[jotl-fuzz] >> error: ~A~%" result)
                               (encode-fuzz-error result)))))

                      ;; ── GetState → State or Error ──
                      (:get-state
                       (multiple-value-bind (status result)
                           (fuzz-handle-get-state mgr payload)
                         (if (eq status :ok)
                             (progn
                               (format t "[jotl-fuzz] >> state (~D kvs)~%"
                                       (length result))
                               (encode-fuzz-state result))
                             (progn
                               (format t "[jotl-fuzz] >> error: ~A~%" result)
                               (encode-fuzz-error result)))))

                      ;; ── Unknown message type ──
                      (otherwise
                       (format t "[jotl-fuzz] >> error: unexpected ~A~%" msg-type)
                       (encode-fuzz-error
                        (format nil "Unexpected message type: ~A" msg-type))))))

              (force-output)
              (fuzz-send-message stream response)))

        ;; Catch decode/processing errors — send Error and continue
        (error (e)
          (let ((msg (format nil "Internal error: ~A" e)))
            (format t "[jotl-fuzz] !! ~A~%" msg)
            (force-output)
            (handler-case
                (fuzz-send-message stream (encode-fuzz-error msg))
              (error () (return))))))))))

;;; ── Main entry point ────────────────────────────────────────────

(defun fuzz-log-level-from-keyword (kw)
  "Map JAM_FUZZ_LOG_LEVEL keyword to *chain-log-level* value.
   :error/:warn → NIL (silent), :info → :minimal, :debug/:trace → :normal."
  (case kw
    ((:error :warn) nil)
    (:info :minimal)
    ((:debug :trace) :normal)
    (otherwise nil)))

(defun run-fuzz-target (&key (socket "/tmp/jam_target.sock")
                             (spec :tiny)
                             (log-level :info))
  "Run the JOTL fuzz-v1 target server on a Unix domain socket.
   Accepts multiple sequential sessions without restart.
   Each session starts with a fresh handshake + one Initialize.

   SPEC selects chainspec: :tiny or :full.
   LOG-LEVEL maps to chain log verbosity.

   Usage:
     (run-fuzz-target :socket \"/tmp/jam/fuzz.sock\"
                      :spec :tiny :log-level :info)"
  ;; Switch chainspec
  (switch-chain spec)

  ;; Clean up old socket file if present
  (when (probe-file socket)
    (delete-file socket))

  (let ((server (make-instance 'sb-bsd-sockets:local-socket :type :stream))
        (chain-log (fuzz-log-level-from-keyword log-level)))
    (unwind-protect
        (progn
          (sb-bsd-sockets:socket-bind server socket)
          (sb-bsd-sockets:socket-listen server 1)
          (format t "~&[jotl-fuzz] JOTL v~A | spec=~A | log=~A~%"
                  *jotl-version* spec log-level)
          (format t "[jotl-fuzz] Listening on ~A~%" socket)
          (force-output)

          ;; Accept connections in a loop (multi-session support)
          (loop
            (format t "[jotl-fuzz] Waiting for connection...~%")
            (force-output)
            (let ((client (sb-bsd-sockets:socket-accept server)))
              (format t "[jotl-fuzz] Client connected~%")
              (force-output)
              (unwind-protect
                  (let ((stream (sb-bsd-sockets:socket-make-stream
                                 client
                                 :input t :output t
                                 :element-type '(unsigned-byte 8)
                                 :buffering :full))
                        (mgr (make-fuzz-state-manager))
                        (*chain-log-level* chain-log))
                    (fuzz-session-loop stream mgr))
                (sb-bsd-sockets:socket-close client))
              (format t "[jotl-fuzz] Session ended, ready for next~%")
              (force-output))))

      ;; Cleanup server
      (sb-bsd-sockets:socket-close server)
      (when (probe-file socket)
        (delete-file socket))
      (format t "~&[jotl-fuzz] Server stopped~%")
      (force-output))))
