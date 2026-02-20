;;;; trace-accum-items.lisp — Dump accumulate items encoding for comparison
;;;;
;;;; Usage: sbcl --noinform --load scripts/load-jotl.lisp --load tests/trace-accum-items.lisp

(in-package #:jotl)

(format t "~%═══ AccumulateItem encoding analysis — storage_light block 2 ═══~%")

(let* ((trace-dir "tests/jamtestvectors/traces/storage_light/")
       (step-path (trace-block-path trace-dir 2)))
  (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
      (load-trace-step step-path)
    (declare (ignore post-sigma pre-root post-root))

    (let* ((reports (funcall block-cl :reports))
           (r-star (loop for g in reports
                         for r = (getf g :report) when r collect r))
           (all-tuples (mapcan #'extract-operand-tuples r-star))
           (by-service (group-by-service all-tuples))
           (first-sid (car (first all-tuples)))
           (items (gethash first-sid by-service)))

      ;; Show raw item data
      (format t "~%Items (~D):~%" (length items))
      (dolist (u items)
        (format t "~%Item plist keys: ~A~%" (loop for k in u by #'cddr collect k))
        (format t "  :gas = ~A~%" (getf u :gas))
        (format t "  :package-hash = ~A (len=~D)~%" 
                (and (getf u :package-hash) (subseq (getf u :package-hash) 0 4))
                (length (or (getf u :package-hash) #())))
        (format t "  :exports-root = ~A (len=~D)~%"
                (and (getf u :exports-root) (subseq (getf u :exports-root) 0 4))
                (length (or (getf u :exports-root) #())))
        (format t "  :auth-hash = ~A (len=~D)~%"
                (and (getf u :auth-hash) (subseq (getf u :auth-hash) 0 4))
                (length (or (getf u :auth-hash) #())))
        (format t "  :payload-hash = ~A (len=~D)~%"
                (and (getf u :payload-hash) (subseq (getf u :payload-hash) 0 4))
                (length (or (getf u :payload-hash) #())))
        (format t "  :result = ~A~%" (getf u :result))
        (format t "  :auth-output len = ~D~%" (length (or (getf u :auth-output) #()))))

      ;; Encode items
      (let ((encoded-items (encode-accumulate-items items nil)))
        (format t "~%Encoded items (~D blobs):~%" (length encoded-items))
        (dolist (blob encoded-items)
          (format t "  Blob (~D bytes): first 50: ~{~2,'0X~^ ~}~%"
                  (length blob)
                  (coerce (subseq blob 0 (min 50 (length blob))) 'list))
          ;; Decode the blob structure
          (let ((pos 0))
            (format t "    [0] enum-tag = ~D (~A)~%" (aref blob 0)
                    (case (aref blob 0) (0 "WorkItem") (1 "Transfer") (t "???")))
            (incf pos 1)
            (format t "    [1..33] package-hash = ~{~2,'0X~^ ~}~%"
                    (coerce (subseq blob pos (+ pos 32)) 'list))
            (incf pos 32)
            (format t "    [33..65] exports-root = ~{~2,'0X~^ ~}~%"
                    (coerce (subseq blob pos (+ pos 32)) 'list))
            (incf pos 32)
            (format t "    [65..97] auth-hash = ~{~2,'0X~^ ~}~%"
                    (coerce (subseq blob pos (+ pos 32)) 'list))
            (incf pos 32)
            (format t "    [97..129] payload-hash = ~{~2,'0X~^ ~}~%"
                    (coerce (subseq blob pos (+ pos 32)) 'list))
            (incf pos 32)
            ;; gas_limit u64
            (let ((gas (loop for i from 0 below 8
                             sum (ash (aref blob (+ pos i)) (* 8 i)))))
              (format t "    [129..137] gas-limit = ~D~%" gas))
            (incf pos 8)
            ;; result tag
            (let ((result-tag (aref blob pos)))
              (format t "    [137] result-tag = ~D (~A)~%" result-tag
                      (case result-tag (0 "Ok") (1 "Err") (t "???")))
              (incf pos 1)
              (if (zerop result-tag)
                  ;; Ok(data): compact(len) + data
                  (let* ((len-byte (aref blob pos))
                         (data-len (if (< len-byte 128) len-byte 999)))
                    (format t "    [138] ok-data-len = ~D (raw byte: ~2,'0X)~%" data-len len-byte)
                    (incf pos 1)
                    (when (< data-len 128)
                      (format t "    [139..~D] ok-data: ~{~2,'0X~^ ~}~%"
                              (+ 139 (min data-len 30))
                              (coerce (subseq blob pos (min (+ pos data-len) (+ pos 30) (length blob))) 'list))
                      (incf pos data-len)))
                  ;; Err(variant)
                  (progn
                    (format t "    [138] error-variant = ~D~%" (aref blob pos))
                    (incf pos 1))))
            ;; auth_output: compact(len) + data
            (when (< pos (length blob))
              (let* ((ao-len-byte (aref blob pos))
                     (ao-len (if (< ao-len-byte 128) ao-len-byte 999)))
                (format t "    [~D] auth-output-len = ~D (raw byte: ~2,'0X)~%" pos ao-len ao-len-byte)
                (incf pos 1)
                (when (and (< ao-len 128) (< pos (length blob)))
                  (format t "    [~D..~D] auth-output: ~{~2,'0X~^ ~}~%"
                          pos (+ pos (min ao-len 30))
                          (coerce (subseq blob pos (min (+ pos ao-len) (+ pos 30) (length blob))) 'list)))))
            (format t "    Total decoded: ~D / ~D bytes~%" pos (length blob)))))

      ;; Encode with length prefix (as ΩY would return)
      (let* ((encoded-items (encode-accumulate-items items nil))
             (full-blob (jam-host::encode-accumulate-items-list encoded-items)))
        (format t "~%Full encoded list (JAM compact prefix + items) = ~D bytes~%" (length full-blob))
        (format t "  First 20: ~{~2,'0X~^ ~}~%"
                (coerce (subseq full-blob 0 (min 20 (length full-blob))) 'list))))))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
