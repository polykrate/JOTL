;;;; diagnose-pi.lisp — Compare pi bytes for a failing storage_light step
;;;;
;;;; Usage: sbcl --load scripts/load-jotl.lisp --load tests/diagnose-pi.lisp

(in-package #:jotl)

(defun hex-dump (bytes &optional (max 200))
  "Print byte vector as hex with position markers."
  (loop for i from 0 below (min (length bytes) max)
        do (when (zerop (mod i 16))
             (format t "~%  ~4,'0X: " i))
           (format t "~2,'0X " (aref bytes i)))
  (terpri))

(defun compare-bytes (expected got label)
  "Compare two byte vectors and show differences."
  (format t "~%═══ ~A ═══~%" label)
  (format t "  Expected: ~D bytes~%" (length expected))
  (format t "  Got:      ~D bytes~%" (length got))
  (if (equalp expected got)
      (format t "  ✓ MATCH~%")
      (let ((min-len (min (length expected) (length got))))
        (format t "  ✗ DIFFER~%")
        (loop for i from 0 below min-len
              when (/= (aref expected i) (aref got i))
                do (format t "    byte ~D: exp=0x~2,'0X got=0x~2,'0X~%"
                           i (aref expected i) (aref got i)))
        (when (/= (length expected) (length got))
          (format t "    length diff: ~D bytes~%"
                  (- (length got) (length expected))))
        ;; Show the raw bytes around divergence
        (let ((first-diff (loop for i from 0 below min-len
                                when (/= (aref expected i) (aref got i))
                                  return i)))
          (when first-diff
            (let ((start (max 0 (- first-diff 4)))
                  (end (min min-len (+ first-diff 16))))
              (format t "~%  Expected around diff (~D):~%" first-diff)
              (loop for i from start below end
                    do (format t "~2,'0X " (aref expected i)))
              (format t "~%  Got around diff (~D):~%" first-diff)
              (loop for i from start below (min (length got) end)
                    do (format t "~2,'0X " (aref got i)))
              (terpri)))))))

(defun analyze-pi-encoding (bytes label)
  "Decode pi structure and show offsets."
  (format t "~%─── ~A structure ───~%" label)
  (let* ((v (num-validators))
         (v-size (* v 24))
         (pos 0))
    (format t "  π_V: offset=~D size=~D~%" pos v-size)
    (incf pos v-size)
    (format t "  π_L: offset=~D size=~D~%" pos v-size)
    (incf pos v-size)
    ;; π_C: C × 8 compact fields
    (let ((cores-start pos))
      (dotimes (ci (num-cores))
        (dotimes (fi 8)
          (multiple-value-bind (val consumed) (decode-compact bytes pos)
            (when (plusp val)
              (format t "  π_C[~D].field~D = ~D (offset=~D, ~D bytes)~%"
                      ci fi val pos consumed))
            (incf pos consumed))))
      (format t "  π_C: offset=~D size=~D~%" cores-start (- pos cores-start)))
    ;; π_S: compact(count) + entries
    (let ((svc-start pos))
      (multiple-value-bind (count count-len) (decode-compact bytes pos)
        (incf pos count-len)
        (format t "  π_S: offset=~D count=~D (count-len=~D)~%" svc-start count count-len)
        (dotimes (si count)
          (let ((sid (decode-fixed-le (subseq bytes pos (+ pos 4)))))
            (incf pos 4)
            (format t "    service ~D (sid=~D):~%" si sid)
            (dolist (fname '(:provided-count :provided-size
                             :refinement-count :refinement-gas-used
                             :imports :extrinsic-count :extrinsic-size :exports
                             :accumulate-count :accumulate-gas-used))
              (multiple-value-bind (val consumed) (decode-compact bytes pos)
                (when (plusp val)
                  (format t "      ~A = ~D (offset=~D, ~D bytes)~%" fname val pos consumed))
                (incf pos consumed)))))
        (format t "  π_S total: ~D bytes~%" (- pos svc-start))))
    (format t "  Total consumed: ~D / ~D bytes~%" pos (length bytes))))

(let* ((trace-dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path trace-dir 2)))
  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore pre-root))
    
    ;; Get expected pi from post-sigma
    (let* ((expected-kvs (funcall post-sigma :merkle-kvs))
           (pi-key (make-array 31 :element-type '(unsigned-byte 8) :initial-element 0))
           (_ (setf (aref pi-key 0) 13))  ;; C(13) = pi segment
           (expected-pi (cdr (assoc pi-key expected-kvs :test #'equalp))))
      (declare (ignore _))
      
      ;; Run import-block
      (let ((*chain-log-level* nil))
        (declare (special *chain-log-level*))
        (multiple-value-bind (sigma-prime computed-root)
            (import-block pre-sigma block-cl)
          (declare (ignore computed-root))
          
          ;; Get computed pi
          (let* ((computed-kvs (funcall sigma-prime :merkle-kvs))
                 (computed-pi (cdr (assoc pi-key computed-kvs :test #'equalp))))
            
            (compare-bytes expected-pi computed-pi "PI (C13)")
            
            (when expected-pi
              (analyze-pi-encoding expected-pi "EXPECTED"))
            (when computed-pi
              (analyze-pi-encoding computed-pi "COMPUTED"))))))))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
