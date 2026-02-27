;;; diag-pp.lisp — Decode protocol params to verify encoding
(in-package #:jotl)

(let* ((pp (jam-host::encode-gp-constants :core-count 2 :val-count 6 :auth-queue-len 80))
       (pos 0))
  (flet ((read-u64 ()
           (prog1 (loop for i from 0 below 8 sum (ash (aref pp (+ pos i)) (* 8 i)))
             (incf pos 8)))
         (read-u32 ()
           (prog1 (loop for i from 0 below 4 sum (ash (aref pp (+ pos i)) (* 8 i)))
             (incf pos 4)))
         (read-u16 ()
           (prog1 (+ (aref pp pos) (ash (aref pp (1+ pos)) 8))
             (incf pos 2))))
    (format t "Protocol params: ~D bytes~%~%" (length pp))
    (format t "B_I  = ~D~%" (read-u64))  ;; 10
    (format t "B_L  = ~D~%" (read-u64))  ;; 1
    (format t "B_S  = ~D~%" (read-u64))  ;; 100
    (format t "C    = ~D~%" (read-u16))  ;; 2
    (format t "D    = ~D~%" (read-u32))  ;; 32
    (format t "E    = ~D~%" (read-u32))  ;; 12
    (format t "G_A  = ~D~%" (read-u64))  ;; 10000000
    (format t "G_I  = ~D~%" (read-u64))  ;; 50000000
    (format t "G_R  = ~D~%" (read-u64))  ;; 1000000000
    (format t "G_T  = ~D~%" (read-u64))  ;; 20000000
    (format t "H    = ~D~%" (read-u16))  ;; 8
    (format t "I    = ~D~%" (read-u16))  ;; 16
    (format t "J    = ~D~%" (read-u16))  ;; 8
    (format t "K    = ~D~%" (read-u16))  ;; 3
    (format t "L    = ~D~%" (read-u32))  ;; 24
    (format t "N    = ~D~%" (read-u16))  ;; 3
    (format t "O    = ~D~%" (read-u16))  ;; 8
    (format t "P    = ~D~%" (read-u16))  ;; 6
    (format t "Q    = ~D~%" (read-u16))  ;; 80
    (format t "R    = ~D~%" (read-u16))  ;; 4
    (format t "T    = ~D~%" (read-u16))  ;; 128
    (format t "U    = ~D~%" (read-u16))  ;; 5
    (format t "V    = ~D~%" (read-u16))  ;; 6
    (format t "W_A  = ~D~%" (read-u32))  ;; 64000
    (format t "W_B  = ~D~%" (read-u32))  ;; 13794305
    (format t "W_C  = ~D~%" (read-u32))  ;; 4000000
    (format t "W_E  = ~D~%" (read-u32))  ;; 4
    (format t "W_M  = ~D~%" (read-u32))  ;; 3072
    (format t "W_P  = ~D~%" (read-u32))  ;; 1026
    (format t "W_R  = ~D~%" (read-u32))  ;; 49152
    (format t "W_T  = ~D~%" (read-u32))  ;; 128
    (format t "W_X  = ~D~%" (read-u32))  ;; 3072
    (format t "Y    = ~D~%" (read-u32))  ;; 10
    (format t "~%pos=~D / ~D bytes~%" pos (length pp))))

(sb-ext:exit :code 0)
