;;;; Smoke test for epoch-mark and tickets-mark closures
(in-package #:jotl)

(defun test-epoch-mark-closure ()
  (format t "~%── epoch-mark closure ──~%")
  ;; NV validators needed for roundtrip (decode expects exactly NV)
  (let* ((nv (num-validators))
         (em (make-epoch-mark
              :entropy (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
              :tickets-entropy (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
              :validators (loop for i below nv
                                collect (list :bandersnatch
                                              (make-array 32 :element-type '(unsigned-byte 8) :initial-element (mod i 256))
                                              :ed25519
                                              (make-array 32 :element-type '(unsigned-byte 8) :initial-element (mod (1+ i) 256)))))))
    (assert (= 32 (length (funcall em :entropy))) () ":entropy length")
    (assert (= 2  (aref (funcall em :tickets-entropy) 0)) () ":tickets-entropy[0]")
    (assert (= nv (length (funcall em :validators))) () ":validators count")
    (let* ((bytes (funcall em :encoded))
           (tag   (aref bytes 0)))
      (assert (= 1 tag) () "encoded tag = 1")
      ;; Roundtrip
      (multiple-value-bind (decoded consumed) (funcall (make-epoch-mark) :decode bytes 0)
        (assert decoded () "decoded not nil")
        (assert (equalp (funcall decoded :entropy) (funcall em :entropy)) () "entropy roundtrip")
        (assert (equalp (funcall decoded :tickets-entropy) (funcall em :tickets-entropy)) () "t-entropy roundtrip")
        (assert (= (length (funcall decoded :validators)) nv) () "validators count roundtrip")
        (format t "  ✅ roundtrip OK (consumed=~A)~%" consumed)))
    ;; None case
    (multiple-value-bind (v n) (funcall (make-epoch-mark) :decode #(0) 0)
      (assert (null v) () "None → nil")
      (assert (= n 1) () "None consumed=1")
      (format t "  ✅ None decode OK~%"))))

(defun test-tickets-mark-closure ()
  (format t "~%── tickets-mark closure ──~%")
  ;; ET tickets — decode expects exactly (epoch-duration) tickets
  (let* ((et (epoch-duration))
         (tm (make-tickets-mark
              :tickets (loop for i below et
                             collect (list :id (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element (mod i 256))
                                           :attempt (mod i 256))))))
    (assert (= et (funcall tm :count)) () ":count")
    (assert (= et (length (funcall tm :tickets))) () ":tickets length")
    (assert (= 0 (getf (first (funcall tm :tickets)) :attempt)) () "ticket[0] :attempt")
    (let ((bytes (funcall tm :encoded)))
      (assert (= 1 (aref bytes 0)) () "encoded tag = 1")
      (format t "  ✅ encode OK (len=~A)~%" (length bytes)))
    ;; None case
    (multiple-value-bind (v n) (funcall (make-tickets-mark) :decode #(0) 0)
      (assert (null v) () "None → nil")
      (assert (= n 1) () "None consumed=1")
      (format t "  ✅ None decode OK~%"))))

(defun test-header-with-closures ()
  (format t "~%── header with sub-closures ──~%")
  (let* ((em (make-epoch-mark
              :entropy (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5)
              :tickets-entropy (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6)
              :validators nil))
         (h (make-header :slot 42 :epoch-mark em :tickets-mark nil
                         :parent-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
    ;; Sub-closure accessible via messages
    (assert (not (null (funcall h :epoch-mark))) () "epoch-mark present")
    (assert (= 5 (aref (funcall (funcall h :epoch-mark) :entropy) 0)) () "nested access")
    (assert (null (funcall h :tickets-mark)) () "tickets-mark nil")
    (format t "  ✅ nested closure access OK~%")
    ;; Header with both HE/HW nil — all required fields provided
    (let ((h2 (make-header :slot 7
                           :parent-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                           :state-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                           :extrinsic-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                           :author-index 0
                           :entropy-source (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0)
                           :seal (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0))))
      (let ((bytes (funcall h2 :encoded)))
        (assert (> (length bytes) 0) () "encode with nil HE/HW")
        (format t "  ✅ encode with nil HE/HW OK (len=~A)~%" (length bytes))
        ;; Roundtrip
        (multiple-value-bind (h3 consumed) (decode-header bytes 0)
          (assert (= 7 (funcall h3 :slot)) () "roundtrip slot")
          (assert (null (funcall h3 :epoch-mark)) () "roundtrip HE nil")
          (assert (null (funcall h3 :tickets-mark)) () "roundtrip HW nil")
          (format t "  ✅ roundtrip nil HE/HW OK (consumed=~A)~%" consumed))))))

(defun run-epoch-tickets-tests ()
  (format t "~%═══ Epoch-Mark & Tickets-Mark Closure Tests ═══~%")
  (test-epoch-mark-closure)
  (test-tickets-mark-closure)
  (test-header-with-closures)
  (format t "~%✅ All epoch-mark/tickets-mark tests passed!~%"))
