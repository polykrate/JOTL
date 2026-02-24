;;;; dump-components.lisp — Dump raw bytes of each changed component at pair 52
(in-package #:jotl)

(defvar *forks-dir* "/home/polycrate/Projets/Jam/jam-conformance/fuzz-proto/examples/0.7.2/forks/")

(defun collect-pairs ()
  (let ((ff nil) (tf nil))
    (dolist (p (directory (merge-pathnames "*_fuzzer_*.bin" *forks-dir*)))
      (push (namestring p) ff))
    (dolist (p (directory (merge-pathnames "*_target_*.bin" *forks-dir*)))
      (push (namestring p) tf))
    (mapcar #'cons (sort ff #'string<) (sort tf #'string<))))

(defun hex-dump-short (bytes &optional (max 64))
  (let ((len (min (length bytes) max)))
    (format nil "~{~2,'0X~}~A" (coerce (subseq bytes 0 len) 'list)
            (if (> (length bytes) max) "..." ""))))

(defun hash-bytes (bytes)
  (bytes-to-hex-string (blake2b-256 bytes)))

(defun dump-pair-52 (sigma-prime parent-sigma)
  "Dump detailed component comparison."
  (format t "~%=== CHANGED SEGMENTS ===~%")

  ;; TAU
  (let ((tau-bytes (funcall sigma-prime :segment :tau))
        (parent-tau (funcall parent-sigma :segment :tau)))
    (format t "~%τ (TAU) C(11):~%")
    (format t "  parent: ~A~%" (hex-dump-short parent-tau))
    (format t "  σ':     ~A~%" (hex-dump-short tau-bytes))
    (format t "  hash:   ~A~%" (hash-bytes tau-bytes)))

  ;; ETA
  (let ((eta-bytes (funcall sigma-prime :segment :eta))
        (parent-eta (funcall parent-sigma :segment :eta)))
    (format t "~%η (ETA) C(6):~%")
    (format t "  parent: ~A~%" (hex-dump-short parent-eta))
    (format t "  σ':     ~A~%" (hex-dump-short eta-bytes))
    (format t "  hash:   ~A~%" (hash-bytes eta-bytes)))

  ;; BETA
  (let ((beta-bytes (funcall sigma-prime :segment :beta))
        (parent-beta (funcall parent-sigma :segment :beta)))
    (format t "~%β (BETA) C(3):~%")
    (format t "  parent: ~D bytes hash=~A~%"
            (length parent-beta) (hash-bytes parent-beta))
    (format t "  σ':     ~D bytes hash=~A~%"
            (length beta-bytes) (hash-bytes beta-bytes)))

  ;; RHO
  (let ((rho-bytes (funcall sigma-prime :segment :rho))
        (parent-rho (funcall parent-sigma :segment :rho)))
    (format t "~%ρ (RHO) C(10):~%")
    (format t "  parent: ~D bytes hash=~A~%"
            (length parent-rho) (hash-bytes parent-rho))
    (format t "  σ':     ~D bytes hash=~A~%"
            (length rho-bytes) (hash-bytes rho-bytes)))

  ;; PI
  (let ((pi-bytes (funcall sigma-prime :segment :pi))
        (parent-pi (funcall parent-sigma :segment :pi)))
    (format t "~%π (PI) C(13):~%")
    (format t "  parent: ~A~%" (hex-dump-short parent-pi 200))
    (format t "  σ':     ~A~%" (hex-dump-short pi-bytes 200)))

  ;; XI
  (let ((xi-bytes (funcall sigma-prime :segment :xi))
        (parent-xi (funcall parent-sigma :segment :xi)))
    (format t "~%ξ (XI) C(15):~%")
    (format t "  parent: ~D bytes hash=~A~%"
            (length parent-xi) (hash-bytes parent-xi))
    (format t "  σ':     ~D bytes hash=~A~%"
            (length xi-bytes) (hash-bytes xi-bytes)))

  ;; Delta KVs
  (let ((prime-dkvs (funcall sigma-prime :delta-kvs))
        (parent-dkvs (funcall parent-sigma :delta-kvs)))
    (format t "~%δ (DELTA) KVs:~%")
    (format t "  parent: ~D keys~%" (length parent-dkvs))
    (dolist (kv parent-dkvs)
      (format t "    ~A → ~D bytes~%"
              (hex-dump-short (car kv) 31) (length (cdr kv))))
    (format t "  σ':     ~D keys~%" (length prime-dkvs))
    (dolist (kv prime-dkvs)
      (format t "    ~A → ~D bytes~%"
              (hex-dump-short (car kv) 31) (length (cdr kv))))
    ;; Show diff
    (format t "~%  δ DIFF:~%")
    (let ((parent-ht (make-hash-table :test #'equalp)))
      (dolist (kv parent-dkvs)
        (setf (gethash (car kv) parent-ht) (cdr kv)))
      (dolist (kv prime-dkvs)
        (let ((pk (gethash (car kv) parent-ht)))
          (cond
            ((null pk)
             (format t "  + ADDED ~A (~D bytes)~%"
                     (hex-dump-short (car kv) 31) (length (cdr kv))))
            ((not (equalp pk (cdr kv)))
             (format t "  Δ CHANGED ~A: ~D→~D bytes~%"
                     (hex-dump-short (car kv) 31)
                     (length pk) (length (cdr kv)))
             (format t "    parent: ~A~%" (hex-dump-short pk 80))
             (format t "    σ':     ~A~%" (hex-dump-short (cdr kv) 80))))))))

  ;; UNCHANGED segments
  (format t "~%=== UNCHANGED SEGMENTS ===~%")
  (dolist (kw '(:alpha :gamma :kappa :lambda :psi :iota :phi :chi :omega :theta))
    (let ((s-bytes (funcall sigma-prime :segment kw))
          (p-bytes (funcall parent-sigma :segment kw)))
      (format t "  ~A: ~A (~D bytes)~%"
              kw
              (if (and s-bytes p-bytes (equalp s-bytes p-bytes))
                  "SAME" "DIFFERENT!")
              (if s-bytes (length s-bytes) 0)))))

(defun run-dump ()
  (format t "~%═══ COMPONENT DUMP AT PAIR 52 ═══~%")
  (let ((pairs (collect-pairs))
        (mgr (make-fuzz-state-manager))
        (pair-num 0)
        (*chain-log-level* nil))
    (dolist (pair pairs)
      (incf pair-num)
      (let* ((fb (alexandria:read-file-into-byte-vector (car pair)))
             (tb (alexandria:read-file-into-byte-vector (cdr pair))))
        (multiple-value-bind (msg-type payload) (decode-fuzz-message fb)
          (multiple-value-bind (exp-type exp-payload) (decode-fuzz-message tb)
            (declare (ignore exp-payload))
            (case msg-type
              (:peer-info nil)
              (:initialize (fuzz-handle-initialize mgr payload))
              (:import-block
               (unless (eq exp-type :error)
                 (fuzz-handle-import-block mgr payload)
                 (when (= pair-num 52)
                   (let* ((header (funcall payload :header))
                          (block-hash (funcall header :hash))
                          (parent-hash (funcall header :parent-hash))
                          (sigma-prime (fuzz-lookup-state mgr block-hash))
                          (parent-sigma (fuzz-lookup-state mgr parent-hash)))
                     (dump-pair-52 sigma-prime parent-sigma))
                   (return-from run-dump)))))))))))

(run-dump)
(sb-ext:exit :code 0)
