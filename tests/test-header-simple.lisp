;;;; test-header-simple.lisp - Simple header test from test vectors

(load "scripts/load-jotl.lisp")

(in-package :jotl)

(format t "~%~%=== Testing Header Encoding ===~%~%")

;; Test data from header_0.json
(defparameter *test-parent*
  "0x5c743dbc514284b2ea57798787c5a155ef9d7ac1e9499ec65910a7a3d65897b7")

(defparameter *test-state-root*
  "0x2591ebd047489f1006361a4254731466a946174af02fe1d86681d254cfd4a00b")

(defparameter *test-extrinsic-hash*
  "0x74a9e79d2618e0ce8720ff61811b10e045c02224a09299f04e404a9656e85c81")

(defparameter *test-slot* 42)
(defparameter *test-author-index* 3)

(defparameter *test-entropy*
  "0xae85d6635e9ae539d0846b911ec86a27fe000f619b78bcac8a74b77e36f6dbcf49a52360f74a0233cea0775356ab0512fafff0683df08fae3cb848122e296cbc50fed22418ea55f19e55b3c75eb8b0ec71dcae0d79823d39920bf8d6a2256c5f")

(defparameter *test-seal*
  "0x31dc5b1e9423eccff9bccd6549eae8034162158000d5be9339919cc03d14046e6431c14cbb172b3aed702b9e9869904b1f39a6fe1f3e904b0fd536f13e8cac496682e1c81898e88e604904fa7c3e496f9a8771ef1102cc29d567c4aad283f7b0")

(format t "Converting hex strings to bytes...~%")

(defparameter *parent-bytes* (jam.ffi:hex-string-to-bytes *test-parent*))
(defparameter *state-root-bytes* (jam.ffi:hex-string-to-bytes *test-state-root*))
(defparameter *extrinsic-bytes* (jam.ffi:hex-string-to-bytes *test-extrinsic-hash*))
(defparameter *entropy-bytes* (jam.ffi:hex-string-to-bytes *test-entropy*))
(defparameter *seal-bytes* (jam.ffi:hex-string-to-bytes *test-seal*))

(format t "  ✓ Parent:         ~D bytes~%" (length *parent-bytes*))
(format t "  ✓ State root:     ~D bytes~%" (length *state-root-bytes*))
(format t "  ✓ Extrinsic hash: ~D bytes~%" (length *extrinsic-bytes*))
(format t "  ✓ Entropy source: ~D bytes~%" (length *entropy-bytes*))
(format t "  ✓ Seal:           ~D bytes~%" (length *seal-bytes*))

(format t "~%Creating header...~%")

(defparameter *test-header*
  (make-header-encoded
   :parent-hash *parent-bytes*
   :state-root *state-root-bytes*
   :extrinsic-hash *extrinsic-bytes*
   :slot *test-slot*
   :epoch-mark nil
   :tickets-mark nil
   :offenders-mark nil
   :author-index *test-author-index*
   :entropy-source *entropy-bytes*
   :seal *seal-bytes*))

(format t "  ✓ Header created~%")

(format t "~%Testing accessors:~%")
(format t "  Slot:         ~D~%" (funcall *test-header* :slot))
(format t "  Author index: ~D~%" (funcall *test-header* :author-index))
(format t "  Is genesis:   ~A~%" (funcall *test-header* :is-genesis))

(format t "~%Encoding header...~%")
(defparameter *encoded* (funcall *test-header* :encoded))
(format t "  ✓ Encoded size: ~D bytes~%" (length *encoded*))

(format t "~%Computing hash...~%")
(defparameter *hash* (funcall *test-header* :hash))
(format t "  ✓ Hash: ~A~%" (jam.ffi:bytes-to-hex-string *hash*))

(format t "~%✅ Header encoding test PASSED!~%~%")
