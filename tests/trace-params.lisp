;;;; trace-params.lisp — Dump protocol parameters and compare with Rust
;;;;
;;;; Usage: sbcl --noinform --load scripts/load-jotl.lisp --load tests/trace-params.lisp

(in-package #:jam-host)

(format t "~%═══ Protocol Parameters comparison ═══~%")

;; Generate Lisp params
(let ((lisp-params (encode-gp-constants :core-count 2 :auth-queue-len 80 :val-count 6)))
  (format t "~%Lisp params (~D bytes):~%" (length lisp-params))
  (format t "  HEX: ~{~2,'0X~^ ~}~%" (coerce lisp-params 'list))

  ;; Decode and print each field
  (let ((pos 0))
    (flet ((read-u16 ()
             (prog1 (+ (aref lisp-params pos) (ash (aref lisp-params (1+ pos)) 8))
               (incf pos 2)))
           (read-u32 ()
             (prog1 (+ (aref lisp-params pos)
                       (ash (aref lisp-params (+ pos 1)) 8)
                       (ash (aref lisp-params (+ pos 2)) 16)
                       (ash (aref lisp-params (+ pos 3)) 24))
               (incf pos 4)))
           (read-u64 ()
             (prog1 (loop for i from 0 below 8
                          sum (ash (aref lisp-params (+ pos i)) (* 8 i)))
               (incf pos 8))))
      (format t "~%  Field-by-field decode:~%")
      (format t "    B_I  (deposit_per_item)       = ~D~%" (read-u64))      ;; 10
      (format t "    B_L  (deposit_per_byte)        = ~D~%" (read-u64))      ;; 1
      (format t "    B_S  (deposit_per_account)     = ~D~%" (read-u64))      ;; 100
      (format t "    C    (core_count)              = ~D~%" (read-u16))      ;; 2
      (format t "    D    (min_turnaround_period)   = ~D~%" (read-u32))      ;; 32
      (format t "    E    (epoch_period)            = ~D~%" (read-u32))      ;; 12
      (format t "    G_A  (max_accumulate_gas)      = ~D~%" (read-u64))      ;; 10000000
      (format t "    G_I  (max_is_authorized_gas)   = ~D~%" (read-u64))      ;; 50000000
      (format t "    G_R  (max_refine_gas)          = ~D~%" (read-u64))      ;; 1000000000
      (format t "    G_T  (block_gas_limit)         = ~D~%" (read-u64))      ;; 20000000
      (format t "    H    (recent_block_count)      = ~D~%" (read-u16))      ;; 8
      (format t "    I    (max_work_items)          = ~D~%" (read-u16))      ;; 16
      (format t "    J    (max_dependencies)        = ~D~%" (read-u16))      ;; 8
      (format t "    K    (max_tickets_per_block)   = ~D~%" (read-u16))      ;; 3
      (format t "    L    (max_lookup_anchor_age)   = ~D~%" (read-u32))      ;; 24
      (format t "    N    (tickets_attempts)        = ~D~%" (read-u16))      ;; 3
      (format t "    O    (auth_window)             = ~D~%" (read-u16))      ;; 8
      (format t "    P    (slot_period_sec)         = ~D~%" (read-u16))      ;; 6
      (format t "    Q    (auth_queue_len)          = ~D~%" (read-u16))      ;; 80
      (format t "    R    (rotation_period)         = ~D~%" (read-u16))      ;; 4
      (format t "    T    (max_extrinsics)          = ~D~%" (read-u16))      ;; 128
      (format t "    U    (availability_timeout)    = ~D~%" (read-u16))      ;; 5
      (format t "    V    (val_count)               = ~D~%" (read-u16))      ;; 6
      (format t "    W_A  (max_authorizer_code)     = ~D~%" (read-u32))      ;; 64000
      (format t "    W_B  (max_input)               = ~D~%" (read-u32))      ;; 13794305
      (format t "    W_C  (max_service_code)        = ~D~%" (read-u32))      ;; 4000000
      (format t "    W_E  (basic_piece_len)         = ~D~%" (read-u32))      ;; 4
      (format t "    W_M  (max_imports)             = ~D~%" (read-u32))      ;; 3072
      (format t "    W_P  (segment_piece_count)     = ~D~%" (read-u32))      ;; 1026
      (format t "    W_R  (max_report_elective)     = ~D~%" (read-u32))      ;; 49152
      (format t "    W_T  (transfer_memo_size)      = ~D~%" (read-u32))      ;; 128
      (format t "    W_X  (max_exports)             = ~D~%" (read-u32))      ;; 3072
      (format t "    Y    (epoch_tail_start)        = ~D~%" (read-u32))      ;; 10
      (format t "~%  Pos after decode: ~D (should be ~D)~%" pos (length lisp-params)))))

;; Now generate via Rust for comparison
(format t "~%~%═══ Checking Rust encode_gp_constants ═══~%")
(handler-case
    (let* ((rust-params (jam.ffi::jam-encode-gp-constants 2 80 6)))
      (if rust-params
          (progn
            (format t "Rust params (~D bytes):~%" (length rust-params))
            (format t "  HEX: ~{~2,'0X~^ ~}~%" (coerce rust-params 'list))
            ;; Compare
            (if (equalp lisp-params rust-params)
                (format t "~%  ✓ MATCH!~%")
                (progn
                  (format t "~%  ✗ MISMATCH!~%")
                  (dotimes (i (min (length lisp-params) (length rust-params)))
                    (unless (= (aref lisp-params i) (aref rust-params i))
                      (format t "    byte ~D: lisp=0x~2,'0X rust=0x~2,'0X~%" i (aref lisp-params i) (aref rust-params i)))))))
          (format t "  Rust returned NIL~%")))
  (error (e)
    (format t "  Could not call Rust: ~A~%" e)))

(format t "~%Done.~%")
(sb-ext:exit :code 0)
