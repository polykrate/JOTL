;;; debug-fuzz.lisp — Minimal fuzz debug: capture + analyze first block
;;;
;;; Run: sbcl --load scripts/load-jotl.lisp --load tests/debug-fuzz.lisp
;;; Then in another terminal:
;;;   docker run --rm -v /tmp/jam-fuzz:/shared --network none \
;;;     ghcr.io/jambrains/graymatter/gm:conformance-fuzzer-latest \
;;;     fuzz-m1-source --num-blocks 1 --target /shared/jam_target.sock

(in-package #:jotl)

;; Override apply-block to dump per-segment details
(defvar *fuzz-debug-block-count* 0)

(defun debug-fuzz-import (sigma block)
  "Debug wrapper: run apply-block and dump segment comparison."
  (let* ((header (funcall block :header))
         (slot (funcall header :slot)))
    (format t "~%═══ BLOCK slot=~D ═══~%" slot)
    (format t "  ET=~D ED=~D EP=~D EA=~D EG=~D~%"
            (length (funcall block :tickets))
            (length (funcall block :disputes))
            (length (funcall block :preimages))
            (length (funcall block :assurances))
            (length (funcall block :guarantees)))

    ;; Dump header fields
    (format t "~%  ── Header detail ──~%")
    (format t "    Author idx: ~D~%" (funcall header :author-index))
    (format t "    Entropy: 0x~A~%" (subseq (bytes-to-hex-string (funcall header :entropy-source)) 0 16))
    (format t "    Seal: ~A~%" (if (funcall header :seal) "present" "NIL"))
    (format t "    Epoch mark: ~A~%" (if (funcall header :epoch-mark) "YES" "no"))
    (format t "    W-tickets: ~A~%" (if (funcall header :tickets-mark) "present" "NIL"))
    (format t "    Block hash: 0x~A~%" (subseq (bytes-to-hex-string (funcall header :hash)) 0 16))

    ;; Dump disputes details (ED is a plist with :verdicts :culprits :faults)
    (let ((disputes (funcall block :disputes)))
      (when disputes
        (let ((nv (length (getf disputes :verdicts)))
              (nc (length (getf disputes :culprits)))
              (nf (length (getf disputes :faults))))
          (when (plusp (+ nv nc nf))
            (format t "~%  ── Disputes detail ──~%")
            (format t "    Verdicts: ~D  Culprits: ~D  Faults: ~D~%" nv nc nf)))))

    ;; Run STF
    (let ((sigma-prime (apply-block sigma block)))
      ;; Compare segments
      (format t "~%  ── Segment comparison (pre → post) ──~%")
      (dolist (seg-pair +sigma-segment-order+)
        (let* ((kw (car seg-pair))
               (cn (cdr seg-pair))
               (old-bytes (funcall sigma :segment kw))
               (new-bytes (funcall sigma-prime :segment kw)))
          (let ((changed (and old-bytes new-bytes (not (equalp old-bytes new-bytes)))))
            (format t "    C(~2D) ~8A: ~A → ~A ~A~%"
                    cn kw
                    (if old-bytes
                        (subseq (bytes-to-hex-string (blake2b-256 old-bytes)) 0 12)
                        "NIL         ")
                    (if new-bytes
                        (subseq (bytes-to-hex-string (blake2b-256 new-bytes)) 0 12)
                        "NIL         ")
                    (cond ((and (null old-bytes) (null new-bytes)) "")
                          ((null old-bytes) "[NEW]")
                          ((null new-bytes) "[DEL]")
                          ((not changed) "=")
                          (t "CHANGED")))
            ;; Dump first bytes of changed segments for debugging
            (when changed
              (format t "           pre[0:32]: ~A~%"
                      (subseq (bytes-to-hex-string old-bytes) 0 (min 64 (* 2 (length old-bytes)))))
              (format t "           post[0:32]: ~A~%"
                      (subseq (bytes-to-hex-string new-bytes) 0 (min 64 (* 2 (length new-bytes)))))))))

      ;; State root — compare incremental vs full-build
      (let ((sr (funcall sigma-prime :state-root)))
        (format t "~%  State root (incremental): 0x~A~%" (bytes-to-hex-string sr))
        ;; Force full rebuild: make a fresh sigma from the same bytes (no parent trie)
        (let* ((fresh-sigma (make-sigma-state
                             :alpha (funcall sigma-prime :segment :alpha)
                             :beta (funcall sigma-prime :segment :beta)
                             :gamma (funcall sigma-prime :segment :gamma)
                             :eta (funcall sigma-prime :segment :eta)
                             :iota (funcall sigma-prime :segment :iota)
                             :kappa (funcall sigma-prime :segment :kappa)
                             :lambda* (funcall sigma-prime :segment :lambda)
                             :rho (funcall sigma-prime :segment :rho)
                             :tau (funcall sigma-prime :segment :tau)
                             :phi (funcall sigma-prime :segment :phi)
                             :chi (funcall sigma-prime :segment :chi)
                             :psi (funcall sigma-prime :segment :psi)
                             :pi* (funcall sigma-prime :segment :pi)
                             :omega (funcall sigma-prime :segment :omega)
                             :xi (funcall sigma-prime :segment :xi)
                             :theta (funcall sigma-prime :segment :theta)
                             :delta-kvs (funcall sigma-prime :delta-kvs)))
               (fresh-sr (funcall fresh-sigma :state-root)))
          (format t "  State root (full-build):  0x~A~%" (bytes-to-hex-string fresh-sr))
          (if (equalp sr fresh-sr)
              (format t "  => MATCH (incremental OK)~%")
              (format t "  => MISMATCH! Incremental Merkle bug!~%")))
        (format t "═══════════════════════════════════~%")
        (force-output)
        sigma-prime))))

;; Minimal fuzz server that processes exactly 1 block then exits
(defun run-debug-fuzz-server (socket-path)
  (delete-file-if-exists socket-path)
  (let ((server (make-instance 'sb-bsd-sockets:local-socket :type :stream)))
    (sb-bsd-sockets:socket-bind server socket-path)
    (sb-bsd-sockets:socket-listen server 1)
    ;; Make socket world-accessible for Docker
    (sb-posix:chmod socket-path #o777)
    (format t "[debug-fuzz] Listening on ~A~%" socket-path)
    (force-output)
    (let ((client (sb-bsd-sockets:socket-accept server)))
      (unwind-protect
          (let ((stream (sb-bsd-sockets:socket-make-stream
                         client :input t :output t :element-type '(unsigned-byte 8))))
            ;; Read PeerInfo
            (let ((msg-bytes (fuzz-recv-message stream)))
              (multiple-value-bind (type payload) (decode-fuzz-message msg-bytes)
                (declare (ignore payload))
                (format t "[debug-fuzz] << ~A~%" type)
                ;; Send PeerInfo response
                (fuzz-send-message stream (encode-fuzz-peer-info))))

            ;; Read Initialize
            (let ((msg-bytes (fuzz-recv-message stream)))
              (multiple-value-bind (type payload) (decode-fuzz-message msg-bytes)
                (format t "[debug-fuzz] << ~A~%" type)
                (let* ((header (getf payload :header))
                       (kvs (getf payload :keyvals))
                       (ancestry (getf payload :ancestry))
                       (sigma (load-state-from-keyvals kvs))
                       (state-root (funcall sigma :state-root)))
                  (declare (ignore header ancestry))
                  (format t "[debug-fuzz] Genesis root: 0x~A~%"
                          (subseq (bytes-to-hex-string state-root) 0 16))
                  ;; Send StateRoot
                  (fuzz-send-message stream (encode-fuzz-state-root state-root))
                  (force-output)

                  ;; Read ImportBlock
                  (let ((msg-bytes (fuzz-recv-message stream)))
                    (multiple-value-bind (type block) (decode-fuzz-message msg-bytes)
                      (format t "[debug-fuzz] << ~A~%" type)
                      (handler-case
                          (let* ((sigma-prime (debug-fuzz-import sigma block))
                                 (sr (funcall sigma-prime :state-root)))
                            (fuzz-send-message stream (encode-fuzz-state-root sr)))
                        (error (e)
                          (format t "[debug-fuzz] ERROR: ~A~%" e)
                          (fuzz-send-message stream
                                            (encode-fuzz-error (format nil "~A" e)))))))))))
        (sb-bsd-sockets:socket-close client)))
    (sb-bsd-sockets:socket-close server))
  (format t "~%[debug-fuzz] Done.~%")
  (force-output))

(defun delete-file-if-exists (path)
  (when (probe-file path)
    (delete-file path)))

(run-debug-fuzz-server "/tmp/jam-fuzz/jam_target.sock")
