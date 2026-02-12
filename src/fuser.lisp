;;;; fuser.lisp — Unix Socket Fuser for JOTL
;;;;
;;;; A long-running SBCL process that exposes the JAM STF over a Unix socket.
;;;; Holds one mutable σ slot and applies blocks sequentially.
;;;;
;;;; Binary protocol (little-endian):
;;;;
;;;;   Request:  op(u8) + payload-len(u32-LE) + payload(N bytes)
;;;;   Response: status(u8) + payload-len(u32-LE) + payload(N bytes)
;;;;
;;;; Operations:
;;;;   0x01 = init-state : payload = genesis.bin → response = state-root (32 bytes)
;;;;   0x02 = add-block  : payload = block binary (E(B)) → response = state-root (32 bytes)
;;;;   0x03 = debug      : payload = block binary (E(B)) → response = raw-state.bin
;;;;
;;;; Status:
;;;;   0x00 = OK
;;;;   0x01 = Error (payload = UTF-8 error message)
;;;;
;;;; Usage:
;;;;   (fuser-start "/tmp/jotl.sock")        ;; blocking — serves forever
;;;;   (fuser-start "/tmp/jotl.sock" :bg t)   ;; background thread
;;;;
;;;; From outside:
;;;;   echo -ne '\x01...' | socat - UNIX-CONNECT:/tmp/jotl.sock
;;;;
;;;; Or from any language:
;;;;   connect() → write(op + len + payload) → read(status + len + payload) → close()

(in-package #:jotl)

(require :sb-bsd-sockets)

;;; ═══════════════════════════════════════════════════════════════
;;; ENCODE-RAW-STATE-BIN — inverse of decode-raw-state-bin
;;; ═══════════════════════════════════════════════════════════════
;;; Format: state-root(32) + compact(count) + [key(31) + compact(val-len) + val]*

(defun encode-raw-state-bin (sigma)
  "Serialize σ to the RawState binary format.
   Format: state-root(32) + compact(count) + [key(31) + compact(val-len) + val]*
   Returns: byte vector."
  (let* ((root (funcall sigma :state-root))
         (kvs  (funcall sigma :merkle-kvs))
         (count (length kvs))
         (parts nil))
    ;; Header: state-root + compact(count)
    (push root parts)
    (push (encode-compact count) parts)
    ;; Encode each key-value pair
    (dolist (kv kvs)
      (let ((key (car kv))
            (val (cdr kv)))
        ;; Key: 31 bytes (pad if shorter, though should always be 31)
        (push (if (= (length key) 31)
                  key
                  (let ((k (make-array 31 :element-type '(unsigned-byte 8)
                                          :initial-element 0)))
                    (replace k key)
                    k))
              parts)
        ;; Value: compact-length-prefix + raw bytes
        (push (encode-compact (length val)) parts)
        (push val parts)))
    ;; Concatenate all parts (nreverse since we pushed in order)
    (apply #'concatenate '(vector (unsigned-byte 8)) (nreverse parts))))

;;; ═══════════════════════════════════════════════════════════════
;;; FUSER — σ slot holder with 3 operations
;;; ═══════════════════════════════════════════════════════════════

(defvar *fuser-sigma* nil
  "The fuser's current σ (state closure). Mutated by init-state and add-block.")

(defvar *fuser-block-count* 0
  "Number of blocks applied since init.")

(defun fuser-init-state (genesis-bytes)
  "Init the fuser from genesis binary.
   Returns: state-root (32 bytes)."
  (multiple-value-bind (header sigma _root)
      (decode-genesis-bin genesis-bytes)
    (declare (ignore header _root))
    (setf *fuser-sigma* sigma)
    (setf *fuser-block-count* 0)
    (let ((computed-root (funcall sigma :state-root)))
      (format *error-output* "~&[fuser] init: ~D segments, root=~A~%"
              (length (funcall sigma :components))
              (bytes-to-hex-string computed-root))
      computed-root)))

(defun fuser-add-block (block-bytes)
  "Decode a block from binary, apply STF, advance σ.
   Returns: state-root (32 bytes)."
  (unless *fuser-sigma*
    (error "Fuser not initialized — call init-state first"))
  (multiple-value-bind (block consumed) (decode-block block-bytes 0)
    (declare (ignore consumed))
    (multiple-value-bind (sigma-prime state-root)
        (import-block *fuser-sigma* block)
      (setf *fuser-sigma* sigma-prime)
      (incf *fuser-block-count*)
      (format *error-output* "~&[fuser] block ~D: root=~A~%"
              *fuser-block-count*
              (bytes-to-hex-string state-root))
      state-root)))

(defun fuser-debug (block-bytes)
  "Decode a block, apply STF, return the full post-state as RawState binary.
   Does NOT advance the fuser σ — this is a read-only probe."
  (unless *fuser-sigma*
    (error "Fuser not initialized — call init-state first"))
  (multiple-value-bind (block consumed) (decode-block block-bytes 0)
    (declare (ignore consumed))
    (multiple-value-bind (sigma-prime state-root)
        (import-block *fuser-sigma* block)
      (declare (ignore state-root))
      (format *error-output* "~&[fuser] debug: root=~A (~D kvs)~%"
              (bytes-to-hex-string (funcall sigma-prime :state-root))
              (length (funcall sigma-prime :merkle-kvs)))
      (encode-raw-state-bin sigma-prime))))

;;; ═══════════════════════════════════════════════════════════════
;;; SOCKET I/O HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun read-exact (stream n)
  "Read exactly N bytes from STREAM. Returns byte vector or NIL on EOF."
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (let ((pos 0))
      (loop while (< pos n) do
        (let ((byte (read-byte stream nil nil)))
          (unless byte (return-from read-exact nil))
          (setf (aref buf pos) byte)
          (incf pos)))
      buf)))

(defun read-u32-le (stream)
  "Read a little-endian u32 from STREAM. Returns integer or NIL on EOF."
  (let ((buf (read-exact stream 4)))
    (when buf
      (logior (aref buf 0)
              (ash (aref buf 1) 8)
              (ash (aref buf 2) 16)
              (ash (aref buf 3) 24)))))

(defun write-u32-le (stream value)
  "Write a little-endian u32 to STREAM."
  (write-byte (logand value #xFF) stream)
  (write-byte (logand (ash value -8) #xFF) stream)
  (write-byte (logand (ash value -16) #xFF) stream)
  (write-byte (logand (ash value -24) #xFF) stream))

(defun write-response (stream status payload)
  "Write a response: status(u8) + len(u32-LE) + payload."
  (write-byte status stream)
  (write-u32-le stream (length payload))
  (write-sequence payload stream)
  (force-output stream))

(defun write-ok (stream payload)
  "Write a success response."
  (write-response stream #x00 payload))

(defun write-error (stream message)
  "Write an error response with UTF-8 message."
  (write-response stream #x01
                  (sb-ext:string-to-octets message :external-format :utf-8)))

;;; ═══════════════════════════════════════════════════════════════
;;; CONNECTION HANDLER
;;; ═══════════════════════════════════════════════════════════════

(defun handle-fuser-request (stream)
  "Read one request from STREAM, dispatch, write response.
   Returns T if connection should continue, NIL on EOF."
  ;; Read op byte
  (let ((op (read-byte stream nil nil)))
    (unless op (return-from handle-fuser-request nil))
    ;; Read payload length
    (let ((payload-len (read-u32-le stream)))
      (unless payload-len (return-from handle-fuser-request nil))
      ;; Read payload
      (let ((payload (if (> payload-len 0)
                         (read-exact stream payload-len)
                         (make-array 0 :element-type '(unsigned-byte 8)))))
        (unless payload (return-from handle-fuser-request nil))
        ;; Dispatch
        (handler-case
            (ecase op
              (#x01  ;; init-state
               (let ((root (fuser-init-state payload)))
                 (write-ok stream root)))
              (#x02  ;; add-block
               (let ((root (fuser-add-block payload)))
                 (write-ok stream root)))
              (#x03  ;; debug
               (let ((raw-state (fuser-debug payload)))
                 (write-ok stream raw-state))))
          (error (e)
            (write-error stream (format nil "~A" e))))
        ;; One request per connection
        nil))))

;;; ═══════════════════════════════════════════════════════════════
;;; FUSER SERVER — Unix Domain Socket
;;; ═══════════════════════════════════════════════════════════════

(defun fuser-start (socket-path &key (bg nil))
  "Start the fuser server on a Unix domain socket.

   SOCKET-PATH: path for the Unix socket (e.g. /tmp/jotl.sock)
   BG: if T, run in a background thread (returns thread object)

   Protocol per connection:
     client connects → sends one request → reads one response → disconnects.

   The fuser is single-threaded: one request at a time."
  (if bg
      (sb-thread:make-thread
       (lambda () (fuser-serve socket-path))
       :name "jotl-fuser")
      (fuser-serve socket-path)))

(defun fuser-serve (socket-path)
  "Blocking server loop. Listens on SOCKET-PATH, handles one client at a time."
  ;; Clean up stale socket
  (when (probe-file socket-path)
    (delete-file socket-path))

  (let ((server (make-instance 'sb-bsd-sockets:local-socket
                               :type :stream)))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-bind server socket-path)
           (sb-bsd-sockets:socket-listen server 5)
           (format *error-output* "~&[fuser] listening on ~A~%" socket-path)
           (force-output *error-output*)

           ;; Accept loop
           (loop
             (let ((client (sb-bsd-sockets:socket-accept server)))
               (unwind-protect
                    (let ((stream (sb-bsd-sockets:socket-make-stream
                                   client
                                   :element-type '(unsigned-byte 8)
                                   :input t :output t :buffering :full)))
                      (handler-case
                          (handle-fuser-request stream)
                        (error (e)
                          (format *error-output* "~&[fuser] client error: ~A~%" e)))
                      (force-output stream)
                      (close stream))
                 (sb-bsd-sockets:socket-close client)))))

      ;; Cleanup
      (sb-bsd-sockets:socket-close server)
      (when (probe-file socket-path)
        (delete-file socket-path))
      (format *error-output* "~&[fuser] stopped~%"))))

;;; ═══════════════════════════════════════════════════════════════
;;; FUSER-SET-STATE — reset σ from a trace pre-state (recovery)
;;; ═══════════════════════════════════════════════════════════════

(defun fuser-set-state (sigma)
  "Directly set the fuser's σ (for recovery from trace pre-state).
   Does NOT change block-count."
  (setf *fuser-sigma* sigma))

;;; ═══════════════════════════════════════════════════════════════
;;; FUSER-RUN-ALL-TRACES — run all trace dirs through the fuser
;;; ═══════════════════════════════════════════════════════════════
;;; For each trace:
;;;   1. Init from genesis
;;;   2. Chain-mode: apply blocks 1..N via fuser-add-block
;;;   3. Compare returned root with expected post-root
;;;   4. On crash or mismatch → recover from next block's pre-state
;;;   5. Report per-trace and grand total

(defvar *trace-base-dir* "tests/jamtestvectors/traces/"
  "Base directory for trace vectors.")

(defun list-trace-dirs ()
  "List all trace sub-directories that contain a genesis.bin."
  (let ((dirs nil))
    (dolist (p (directory (merge-pathnames "*/genesis.bin" *trace-base-dir*)))
      (push (directory-namestring p) dirs))
    (sort dirs #'string<)))

(defun fuser-run-trace (dir &key (verbose t))
  "Run a single trace directory through the fuser (chain mode with recovery).

   Returns (values chain-pass chain-fail step-pass step-fail errors).
   - chain-pass/fail: how many blocks matched/mismatched in chain mode
   - step-pass/fail:  how many blocks matched/mismatched using trace pre-state
   - errors: how many blocks caused a crash"
  (let* ((max-block (count-trace-blocks dir))
         (genesis-path (trace-genesis-path dir))
         (chain-pass 0) (chain-fail 0)
         (step-pass 0)  (step-fail 0)
         (errors 0)
         (chain-ok t))  ;; tracks if chain hasn't diverged

    (when verbose
      (format t "~%╔═══════════════════════════════════════════════════╗~%")
      (format t "║  ~A  (~D blocks)~34T║~%"
              (enough-namestring dir) max-block)
      (format t "╚═══════════════════════════════════════════════════╝~%"))

    ;; Init from genesis
    (handler-case
        (let* ((genesis-bytes (alexandria:read-file-into-byte-vector genesis-path))
               (root (fuser-init-state genesis-bytes)))
          (when verbose
            (format t "  Genesis: ✓  root=~A~%"
                    (subseq (bytes-to-hex-string root) 0 16))))
      (error (e)
        (when verbose
          (format t "  Genesis: FATAL ~A~%" e))
        (return-from fuser-run-trace
          (values 0 max-block 0 0 1))))

    ;; Process blocks
    (loop for b from 1 to max-block do
      (handler-case
          (let ((step-path (trace-block-path dir b)))
            (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
                (load-trace-step step-path)
              (declare (ignore post-sigma))

              ;; Get raw block bytes
              (let ((block-bytes (funcall block-cl :encoded)))

                ;; === CHAIN MODE ===
                (when chain-ok
                  (handler-case
                      (let ((computed-root (fuser-add-block block-bytes)))
                        (if (equalp computed-root post-root)
                            (progn
                              (incf chain-pass)
                              (when verbose
                                (format t "  Block ~3D: chain ✓~%" b)))
                            (progn
                              (incf chain-fail)
                              (setf chain-ok nil) ;; chain diverged
                              (when verbose
                                (format t "  Block ~3D: chain ✗  (diverged, switching to step mode)~%" b)
                                (format t "    expected: ~A~%"
                                        (subseq (bytes-to-hex-string post-root) 0 16))
                                (format t "    computed: ~A~%"
                                        (subseq (bytes-to-hex-string computed-root) 0 16))))))
                    (error (e)
                      (incf errors)
                      (setf chain-ok nil)
                      (when verbose
                        (format t "  Block ~3D: chain ERROR ~A~%" b
                                (type-of e))))))

                ;; === STEP MODE (always, for stats) ===
                ;; Reset sigma from trace pre-state and apply
                (handler-case
                    (progn
                      (fuser-set-state pre-sigma)
                      (let ((computed-root (fuser-add-block block-bytes)))
                        (if (equalp computed-root post-root)
                            (incf step-pass)
                            (incf step-fail))))
                  (error (e)
                    (declare (ignore e))
                    (incf step-fail)))

                ;; If chain is broken, recover sigma for step mode continuity
                (unless chain-ok
                  (fuser-set-state pre-sigma)
                  ;; Try to advance so the next block can attempt chain again? No.
                  ;; Just leave sigma at pre-sigma; step mode will reset anyway.
                  ))))
        (error (e)
          (incf errors)
          (when verbose
            (format t "  Block ~3D: LOAD ERROR ~A~%" b (type-of e))))))

    (when verbose
      (format t "~%  Chain: ~D/~D   Step: ~D/~D   Errors: ~D~%"
              chain-pass max-block step-pass max-block errors))

    (values chain-pass chain-fail step-pass step-fail errors)))


(defun fuser-run-all-traces (&key (verbose t) (traces nil))
  "Run all traces through the fuser. Reports a summary table.

   TRACES: optional list of trace dir names (e.g. '(\"fallback\" \"safrole\")).
           If nil, runs all directories with a genesis.bin.
   VERBOSE: if T, print per-block details.

   Returns: grand-total plist (:chain-pass N :chain-fail N :step-pass N :step-fail N :errors N)"
  (let ((dirs (if traces
                  (mapcar (lambda (name)
                            (namestring
                             (merge-pathnames (format nil "~A/" name)
                                              *trace-base-dir*)))
                          traces)
                  (list-trace-dirs)))
        (results nil)
        (grand-chain-pass 0) (grand-chain-fail 0)
        (grand-step-pass 0)  (grand-step-fail 0)
        (grand-errors 0))

    (dolist (dir dirs)
      (let ((name (car (last (pathname-directory (pathname dir))))))
        (multiple-value-bind (cp cf sp sf err)
            (fuser-run-trace dir :verbose verbose)
          (push (list name cp cf sp sf err) results)
          (incf grand-chain-pass cp)
          (incf grand-chain-fail cf)
          (incf grand-step-pass sp)
          (incf grand-step-fail sf)
          (incf grand-errors err))))

    ;; Summary table
    (format t "~%~%")
    (format t "╔══════════════════╦════════════╦════════════╦════════╗~%")
    (format t "║ Trace            ║   Chain    ║   Step     ║ Errors ║~%")
    (format t "╠══════════════════╬════════════╬════════════╬════════╣~%")
    (dolist (r (nreverse results))
      (destructuring-bind (name cp cf sp sf err) r
        (let ((chain-total (+ cp cf))
              (step-total  (+ sp sf)))
          (format t "║ ~16A ║ ~3D/~3D ~A ║ ~3D/~3D ~A ║ ~4D   ║~%"
                  name
                  cp chain-total (if (zerop cf) "✓" "✗")
                  sp step-total  (if (zerop sf) "✓" "✗")
                  err))))
    (let ((grand-chain-total (+ grand-chain-pass grand-chain-fail))
          (grand-step-total  (+ grand-step-pass  grand-step-fail)))
      (format t "╠══════════════════╬════════════╬════════════╬════════╣~%")
      (format t "║ TOTAL            ║ ~3D/~3D ~A ║ ~3D/~3D ~A ║ ~4D   ║~%"
              grand-chain-pass grand-chain-total
              (if (zerop grand-chain-fail) "✓" "✗")
              grand-step-pass grand-step-total
              (if (zerop grand-step-fail) "✓" "✗")
              grand-errors)
      (format t "╚══════════════════╩════════════╩════════════╩════════╝~%"))

    (list :chain-pass grand-chain-pass :chain-fail grand-chain-fail
          :step-pass grand-step-pass :step-fail grand-step-fail
          :errors grand-errors)))
