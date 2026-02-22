;;;; diag-sid-swap.lisp — Check if delta-kvs values are correct but swapped between SIDs
;;;;
;;;; Usage:
;;;;   sbcl --noinform --dynamic-space-size 4096 \
;;;;        --load scripts/load-jotl.lisp \
;;;;        --eval '(setf jotl::*chain-log-level* nil)' \
;;;;        --load tests/diag-sid-swap.lisp --quit
(in-package :jotl)

(defun collect-all-u64-values (kvs)
  "Extract all 8-byte LE values from delta-kvs, grouped by service.
   Returns hash-table: sid → list of (h27 . u64-value)"
  (let ((ht (make-hash-table :test 'eql)))
    (dolist (kv kvs)
      (let ((key (car kv)) (val (cdr kv)))
        (when (and (arrayp key) (= (length key) 31)
                   (not (segment-key-p key))
                   (not (service-metadata-key-p key))
                   (arrayp val) (= (length val) 8))
          (let ((sid (service-id-from-sub-key key))
                (h27 (extract-sub-key-h key))
                (u64 (jamvm::decode-le-unsigned val 0 8)))
            (push (cons h27 u64) (gethash sid ht))))))
    ht))

(defun collect-all-storage (kvs)
  "Extract ALL storage entries from delta-kvs, grouped by service.
   Returns hash-table: sid → hash-table(h27 → value-bytes)"
  (let ((ht (make-hash-table :test 'eql)))
    (dolist (kv kvs)
      (let ((key (car kv)) (val (cdr kv)))
        (when (and (arrayp key) (= (length key) 31)
                   (not (segment-key-p key))
                   (not (service-metadata-key-p key)))
          (let ((sid (service-id-from-sub-key key))
                (h27 (extract-sub-key-h key)))
            (unless (gethash sid ht)
              (setf (gethash sid ht) (make-hash-table :test 'equalp)))
            (setf (gethash h27 (gethash sid ht)) val)))))
    ht))

(defun diag-swap-block (trace-dir block-num)
  "For one block, check if delta-kvs diffs are value-swaps between services.
   Returns NIL if no diffs, :SWAP if values are swapped, :OTHER otherwise."
  (let* ((step-path (trace-block-path trace-dir block-num))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma)
        (decode-trace-step-bin bytes)
      (let ((*chain-log-level* nil))
        (declare (special *chain-log-level*))
        (multiple-value-bind (sigma-prime computed-root)
            (import-block pre-sigma block-cl)
          (declare (ignore computed-root))
          (let ((exp-kvs (funcall post-sigma :merkle-kvs))
                (got-kvs (funcall sigma-prime :merkle-kvs)))
            ;; Build per-service storage maps
            (let ((exp-ht (collect-all-storage exp-kvs))
                  (got-ht (collect-all-storage got-kvs))
                  (diff-keys nil)      ;; list of (sid h27 exp-val got-val)
                  (all-exp-vals nil)   ;; all differing expected values (as hex)
                  (all-got-vals nil))  ;; all differing got values (as hex)
              ;; Find all diffs
              (maphash (lambda (sid exp-sub-ht)
                         (let ((got-sub-ht (gethash sid got-ht)))
                           (when got-sub-ht
                             (maphash (lambda (h27 exp-val)
                                        (let ((got-val (gethash h27 got-sub-ht)))
                                          (when (and got-val (not (equalp exp-val got-val)))
                                            (push (list sid h27 exp-val got-val) diff-keys)
                                            (push (bytes-to-hex-string exp-val) all-exp-vals)
                                            (push (bytes-to-hex-string got-val) all-got-vals))))
                                      exp-sub-ht))))
                       exp-ht)
              
              (when (null diff-keys)
                (return-from diag-swap-block nil))

              (format t "~%Block ~D: ~D storage diffs~%" block-num (length diff-keys))
              
              ;; Show each diff
              (dolist (d diff-keys)
                (destructuring-bind (sid h27 exp-val got-val) d
                  (format t "  SID=~D h27=~A~%"
                          sid (subseq (bytes-to-hex-string h27) 0 (min 12 (* 2 (length h27)))))
                  (format t "    exp(~2D)=~A~%" (length exp-val) (bytes-to-hex-string exp-val))
                  (format t "    got(~2D)=~A~%" (length got-val) (bytes-to-hex-string got-val))
                  (when (= (length exp-val) 8)
                    (format t "    exp-u64=~D  got-u64=~D~%"
                            (jamvm::decode-le-unsigned exp-val 0 8)
                            (jamvm::decode-le-unsigned got-val 0 8)))))
              
              ;; Check cross-SID swap: are the "expected" values found as "got" in other SIDs?
              (format t "~%  === Cross-SID value swap check ===~%")
              (let ((swap-count 0)
                    (total-diffs (length diff-keys)))
                ;; For each diff, check if the expected value appears somewhere in got-ht (any SID)
                (dolist (d diff-keys)
                  (destructuring-bind (sid h27 exp-val got-val) d
                    (declare (ignore h27))
                    ;; Search for exp-val in got-ht across ALL services
                    (let ((found-in nil))
                      (maphash (lambda (other-sid other-sub-ht)
                                 (when (/= other-sid sid)
                                   (maphash (lambda (other-h27 other-val)
                                              (declare (ignore other-h27))
                                              (when (equalp other-val exp-val)
                                                (push other-sid found-in)))
                                            other-sub-ht)))
                               got-ht)
                      ;; Also check if got-val appears in exp-ht across other services
                      (let ((got-found-in nil))
                        (maphash (lambda (other-sid other-sub-ht)
                                   (when (/= other-sid sid)
                                     (maphash (lambda (other-h27 other-val)
                                                (declare (ignore other-h27))
                                                (when (equalp other-val got-val)
                                                  (push other-sid got-found-in)))
                                              other-sub-ht)))
                                 exp-ht)
                        (when (or found-in got-found-in)
                          (incf swap-count)
                          (format t "  SWAP? SID=~D:~%" sid)
                          (when found-in
                            (format t "    exp-val found in got[SID=~{~D~^ ~}]~%" found-in))
                          (when got-found-in
                            (format t "    got-val found in exp[SID=~{~D~^ ~}]~%" got-found-in)))))))
                
                (if (plusp swap-count)
                    (progn
                      (format t "  → ~D/~D diffs look like cross-SID swaps~%" swap-count total-diffs)
                      :swap)
                    (progn
                      (format t "  → No cross-SID swaps detected. Values are genuinely different.~%")
                      ;; Also check: same-SID, different-key swap
                      (format t "~%  === Same-SID key swap check ===~%")
                      (let ((same-sid-swap 0))
                        (dolist (d diff-keys)
                          (destructuring-bind (sid h27 exp-val got-val) d
                            (declare (ignore h27))
                            (let ((got-sub-ht (gethash sid got-ht))
                                  (exp-sub-ht (gethash sid exp-ht)))
                              ;; Does exp-val appear under a different key in got-sub-ht?
                              (when got-sub-ht
                                (maphash (lambda (k v)
                                           (when (and (equalp v exp-val) (not (equalp k h27)))
                                             (incf same-sid-swap)
                                             (format t "  SAME-SID SWAP: SID=~D exp-val under different key~%" sid)))
                                         got-sub-ht))
                              ;; Does got-val appear under a different key in exp-sub-ht?
                              (when exp-sub-ht
                                (maphash (lambda (k v)
                                           (when (and (equalp v got-val) (not (equalp k h27)))
                                             (incf same-sid-swap)
                                             (format t "  SAME-SID SWAP: SID=~D got-val under different key~%" sid)))
                                         exp-sub-ht)))))
                        (if (plusp same-sid-swap)
                            (format t "  → ~D same-SID key swaps~%" same-sid-swap)
                            (format t "  → No same-SID key swaps either. Pure computation error.~%")))
                      :other))))))))))

;;; ═══════════════════════════════════════════════════════════════
;;; RUN — check all failing blocks
;;; ═══════════════════════════════════════════════════════════════
(let ((trace-dir (merge-pathnames "tests/jamtestvectors/traces/fuzzy/"
                                   (truename ".")))
      (swap-count 0)
      (other-count 0)
      (ok-count 0))
  (format t "~%═══ Cross-SID value swap diagnostic ═══~%")
  (loop for b from 1 to 200 do
    (handler-case
        (let ((result (diag-swap-block trace-dir b)))
          (case result
            ((nil) (incf ok-count))
            (:swap (incf swap-count))
            (:other (incf other-count))))
      (error (e) (format t "Block ~D: ERROR ~A~%" b e))))
  (format t "~%~%════════════════════════════════════════~%")
  (format t "SUMMARY: ~D ok, ~D with swaps, ~D with pure diffs~%"
          ok-count swap-count other-count))
