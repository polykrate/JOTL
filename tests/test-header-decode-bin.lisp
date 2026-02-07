;;;; test-header-decode-bin.lisp - Decode header_0.bin and compare with header_0.json
;;;; This is the REAL validation test!

(load "scripts/load-jotl.lisp")

(in-package :jotl)

(format t "~%~%=== Header Binary Decoding Test ===~%")
(format t "Goal: Decode header_0.bin and compare with header_0.json~%~%")

;;; ==========================================================================
;;; Load Binary File
;;; ==========================================================================

(defun read-binary-file (filepath)
  "Read entire binary file into byte array"
  (with-open-file (stream filepath
                          :direction :input
                          :element-type '(unsigned-byte 8))
    (let* ((length (file-length stream))
           (buffer (make-array length :element-type '(unsigned-byte 8))))
      (read-sequence buffer stream)
      buffer)))

(defparameter *header-bin-file*
  #P"/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/header_0.bin")

(format t "Loading binary file: ~A~%" (file-namestring *header-bin-file*))

(defparameter *header-bin* (read-binary-file *header-bin-file*))

(format t "  ✓ Loaded ~D bytes~%~%" (length *header-bin*))

;;; ==========================================================================
;;; Display Binary Structure
;;; ==========================================================================

(format t "Binary structure (first 100 bytes):~%")
(format t "  Offset | Hex                                      | ASCII~%")
(format t "  -------|------------------------------------------|----------~%")

(let ((display-length (min 100 (length *header-bin*))))
  (loop for i from 0 below display-length by 16
        do (format t "  ~6,'0X | " i)
           (loop for j from i below (min (+ i 16) display-length)
                 do (format t "~2,'0X " (aref *header-bin* j)))
           (loop for j from (min (+ i 16) display-length) below (+ i 16)
                 do (format t "   "))
           (format t "| ")
           (loop for j from i below (min (+ i 16) display-length)
                 do (let ((byte (aref *header-bin* j)))
                      (if (and (>= byte 32) (<= byte 126))
                          (format t "~C" (code-char byte))
                          (format t "."))))
           (format t "~%")))

(format t "~%")

;;; ==========================================================================
;;; Decode Header Components
;;; ==========================================================================

(format t "Decoding header components...~%~%")

;; Header format (from Gray Paper §5.1):
;; HP (32 bytes) + HR (32 bytes) + HX (32 bytes) + HT (4 bytes) + ...

(defun extract-bytes (buffer offset length)
  "Extract a slice of bytes from buffer"
  (subseq buffer offset (+ offset length)))

(defun decode-u32-le (bytes offset)
  "Decode little-endian u32 from bytes at offset"
  (logior (aref bytes offset)
          (ash (aref bytes (+ offset 1)) 8)
          (ash (aref bytes (+ offset 2)) 16)
          (ash (aref bytes (+ offset 3)) 24)))

(defun decode-u16-le (bytes offset)
  "Decode little-endian u16 from bytes at offset"
  (logior (aref bytes offset)
          (ash (aref bytes (+ offset 1)) 8)))

;; Decode fixed-size components
(let ((offset 0))
  ;; HP - Parent hash (32 bytes)
  (defparameter *decoded-parent* (extract-bytes *header-bin* offset 32))
  (setf offset (+ offset 32))
  (format t "  HP (Parent):         ~A~%" 
          (jam.ffi:bytes-to-hex-string *decoded-parent*))
  
  ;; HR - State root (32 bytes)
  (defparameter *decoded-state-root* (extract-bytes *header-bin* offset 32))
  (setf offset (+ offset 32))
  (format t "  HR (State root):     ~A~%" 
          (jam.ffi:bytes-to-hex-string *decoded-state-root*))
  
  ;; HX - Extrinsic hash (32 bytes)
  (defparameter *decoded-extrinsic* (extract-bytes *header-bin* offset 32))
  (setf offset (+ offset 32))
  (format t "  HX (Extrinsic hash): ~A~%" 
          (jam.ffi:bytes-to-hex-string *decoded-extrinsic*))
  
  ;; HT - Timeslot (4 bytes, u32 little-endian)
  (defparameter *decoded-slot* (decode-u32-le *header-bin* offset))
  (setf offset (+ offset 4))
  (format t "  HT (Slot):           ~D~%" *decoded-slot*)
  
  (format t "~%  Current offset: ~D bytes~%" offset)
  (format t "  Remaining: ~D bytes~%~%" (- (length *header-bin*) offset)))

;;; ==========================================================================
;;; Compare with Expected Values (from header_0.json)
;;; ==========================================================================

(format t "Comparing with expected values from header_0.json:~%~%")

(defparameter *expected-parent* 
  "0x5c743dbc514284b2ea57798787c5a155ef9d7ac1e9499ec65910a7a3d65897b7")
(defparameter *expected-state-root*
  "0x2591ebd047489f1006361a4254731466a946174af02fe1d86681d254cfd4a00b")
(defparameter *expected-extrinsic*
  "0x74a9e79d2618e0ce8720ff61811b10e045c02224a09299f04e404a9656e85c81")
(defparameter *expected-slot* 42)

(defun compare-hash (name decoded expected-hex)
  "Compare decoded hash with expected hex string"
  (let* ((decoded-hex (jam.ffi:bytes-to-hex-string decoded))
         (match (string-equal decoded-hex expected-hex)))
    (format t "  ~A:~%" name)
    (format t "    Expected: ~A~%" expected-hex)
    (format t "    Decoded:  ~A~%" decoded-hex)
    (format t "    Status:   ~A~%~%" 
            (if match 
                "✅ MATCH"
                "❌ MISMATCH"))
    match))

(defun compare-number (name decoded expected)
  "Compare decoded number with expected"
  (let ((match (= decoded expected)))
    (format t "  ~A:~%" name)
    (format t "    Expected: ~D~%" expected)
    (format t "    Decoded:  ~D~%" decoded)
    (format t "    Status:   ~A~%~%" 
            (if match 
                "✅ MATCH"
                "❌ MISMATCH"))
    match))

(defparameter *results* nil)

(push (compare-hash "Parent Hash" *decoded-parent* *expected-parent*) *results*)
(push (compare-hash "State Root" *decoded-state-root* *expected-state-root*) *results*)
(push (compare-hash "Extrinsic Hash" *decoded-extrinsic* *expected-extrinsic*) *results*)
(push (compare-number "Slot" *decoded-slot* *expected-slot*) *results*)

;;; ==========================================================================
;;; Final Result
;;; ==========================================================================

(let ((all-pass (every #'identity *results*))
      (passed (count t *results*))
      (total (length *results*)))
  (format t "~%╔════════════════════════════════════════════╗~%")
  (format t "║           TEST RESULTS                     ║~%")
  (format t "╚════════════════════════════════════════════╝~%")
  (format t "  Passed: ~D / ~D~%" passed total)
  (format t "  Status: ~A~%~%" 
          (if all-pass
              "✅ ALL TESTS PASSED"
              "❌ SOME TESTS FAILED"))
  
  (if all-pass
      (format t "🎉 Binary decoding matches JSON perfectly!~%~%")
      (format t "⚠️  Binary decoding has discrepancies with JSON~%~%")))
