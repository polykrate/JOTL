;;; diag-ep-ordering.lisp — Check EP preimage ordering in standard test vectors
;;; Goal: find the correct ordering criterion used by the GP

(in-package #:jotl)

(let* ((base (asdf:system-source-directory :jotl))
       (trace-dir (merge-pathnames "../jam-conformance/test-vectors/0.7.2/codec/preimages/" base)))
  (format t "~&═══ EP ORDERING IN PREIMAGES TRACE ═══~%")
  (loop for step from 0 to 100
        for step-path = (merge-pathnames (format nil "~4,'0D.bin" step) trace-dir)
        when (probe-file step-path)
        do (handler-case
               (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
                   (load-trace-step step-path)
                 (declare (ignore pre-sigma post-sigma pre-root post-root))
                 (let* ((e-p (funcall block-cl :preimages))
                        (n (length e-p)))
                   (when (> n 1)
                     (format t "~%  Step ~D: ~D preimages~%" step n)
                     ;; Show ordering info for each pair
                     (let ((prev-sid nil)
                           (prev-hash nil)
                           (prev-len nil)
                           (sorted-by-sid t)
                           (sorted-by-key t))
                       (dolist (p e-p)
                         (let* ((sid (getf p :requester))
                                (blob (ensure-bytes (getf p :blob)))
                                (hash (jam.ffi:blake2b-256 blob))
                                (len (length blob))
                                (lookup-key (interleave-sub-key sid (lookup-trie-h hash len))))
                           (format t "    sid=~D hash=~A len=~D~%"
                                   sid (subseq (bytes-to-hex-string hash) 0 16) len)
                           (when prev-sid
                             (when (>= prev-sid sid)
                               (setf sorted-by-sid nil)
                               (format t "      ↑ NOT sorted by sid (prev=~D >= cur=~D)~%"
                                       prev-sid sid))
                             (unless (bytes< prev-hash hash)
                               (format t "      ↑ NOT sorted by hash~%"))
                             (let ((prev-key (interleave-sub-key prev-sid
                                              (lookup-trie-h prev-hash prev-len))))
                               (unless (bytes< prev-key lookup-key)
                                 (setf sorted-by-key nil)
                                 (format t "      ↑ NOT sorted by interleaved key~%"))))
                           (setf prev-sid sid
                                 prev-hash hash
                                 prev-len len)))
                       (format t "    Sorted by sid? ~A~%" sorted-by-sid)
                       (format t "    Sorted by interleaved key? ~A~%" sorted-by-key)))))
             (error (e)
               (declare (ignore e))))))
