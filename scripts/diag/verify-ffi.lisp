;;;; verify-ffi.lisp — Verify FFI ring commitment against safrole test vector

(in-package #:jotl)

(defun run-verify-ffi ()
  ;; Safrole test vector keys (from enact-epoch-change-with-no-tickets-1.json)
  (let* ((key-hexes '("ff71c6c03ff88adb5ed52c9681de1629a54e702fc14729f6b50d2f0a76f185b3"
                       "dee6d555b82024f1ccf8a1e37e60fa60fd40b1958c4bb3006af78647950e1b91"
                       "9326edb21e5541717fde24ec085000b28709847b8aab1ac51f84e94b37ca1b66"
                       "0746846d17469fb2f95ef365efcab9f4e22fa1feb53111c995376be8019981cc"
                       "151e5c8fe2b9d8a606966a79edd2f9e5db47e83947ce368ccba53bf6ba20a40b"
                       "2105650944fcd101621fd5bb3124c9fd191d114b7ad936c1d79d734f9f21392e"))
         (keys (coerce (mapcar #'hex-string-to-bytes key-hexes) 'vector))
         (expected-gz-hex "af39b7de5fcfb9fb8a46b1645310529ce7d08af7301d9758249da4724ec698eb127f489b58e49ae9ab85027509116962a135fc4d97b66fbbed1d3df88cd7bf5cc6e5d7391d261a4b552246648defcb64ad440d61d69ec61b5473506a48d58e1992e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")
         (expected-gz (hex-string-to-bytes expected-gz-hex))
         (computed-gz (jam.ffi:bandersnatch-compute-ring-commitment keys)))

    (format t "~%=== FFI vs safrole test vector (TINY, 6 keys) ===~%")
    (format t "Expected: ~A~%" (subseq (bytes-to-hex-string expected-gz) 0 40))
    (format t "Computed: ~A~%" (if computed-gz (subseq (bytes-to-hex-string computed-gz) 0 40) "NIL"))
    (format t "Match: ~A~%~%" (equalp computed-gz expected-gz))

    (when (and computed-gz (not (equalp computed-gz expected-gz)))
      (format t "Full computed: ~A~%" (bytes-to-hex-string computed-gz))
      (format t "Full expected: ~A~%~%" (bytes-to-hex-string expected-gz))
      ;; Show byte-by-byte diff
      (format t "First differing byte: ")
      (loop for i from 0 below (min (length computed-gz) (length expected-gz))
            unless (= (aref computed-gz i) (aref expected-gz i))
            do (format t "position ~D~%" i) (return)))))

(run-verify-ffi)
(sb-ext:exit :code 0)
