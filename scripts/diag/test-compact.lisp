(in-package #:jotl)

(let ((values '(2000000 3333333 0 128 20000000)))
  (dolist (v values)
    (let ((compact (jam-host::encode-jam-compact v))
          (u64 (jam-host::encode-u64-le v)))
      (format t "~%value=~D~%  compact(~D bytes): ~{~2,'0X~}~%  u64-le(~D bytes): ~{~2,'0X~}~%"
              v (length compact) (coerce compact 'list)
              (length u64) (coerce u64 'list)))))

;; Now show what a WorkItemRecord looks like with gas=2000000
(format t "~%--- WorkItemRecord gas_limit encoding ---~%")
(let* ((gas 2000000)
       (wi (jam-host::encode-work-item-record
            (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA)
            (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB)
            (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC)
            (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD)
            gas
            0  ; result-kind = OK
            (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(1 2))
            nil)))
  (format t "WI total len=~D~%" (length wi))
  ;; The gas field starts at offset 1(disc) + 4*32(hashes) = 129
  (format t "Bytes around gas [128..140]: ~{~2,'0X~}~%"
          (coerce (subseq wi 128 (min 140 (length wi))) 'list))
  ;; Show also what it would be with u64
  (format t "~%If gas were u64-le(2000000): ~{~2,'0X~}~%"
          (coerce (jam-host::encode-u64-le 2000000) 'list))
  (format t "Compact gas (2000000): ~{~2,'0X~}~%"
          (coerce (jam-host::encode-jam-compact 2000000) 'list)))

;; Also show the transfer record
(format t "~%--- TransferRecord gas_limit encoding ---~%")
(let* ((xf (jam-host::encode-transfer-record 0 1 1000 nil 2000000)))
  (format t "XF total len=~D~%" (length xf))
  ;; gas_limit is last 8 bytes  
  (format t "Last 8 bytes (gas): ~{~2,'0X~}~%"
          (coerce (subseq xf (- (length xf) 8)) 'list)))

(sb-ext:exit :code 0)
