;;;; test-work-report-decode.lisp - Test WorkReport decoding with simple test vector

(in-package :jotl)

(format t "~%=== Testing WorkReport Decode ===~%~%")

;; Test vector from user (simple WorkReport)
(defparameter *wr-hex*
  "1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e0400000009090909090909090909090909090909090909090909090909090909090909091f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f020014141414141414141414141414141414141414141414141414141414141414141515151515151515151515151515151515151515151515151515151515151515161616161616161616161616161616161616161616161616161616161616161617171717171717171717171717171717171717171717171717171717171717170c000000011818181818181818181818181818181818181818181818181818181818181818032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a9d4c0b61757468206f7574707574011e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f010a00000029292929292929292929292929292929292929292929292929292929292929290303030303030303030303030303030303030303030303030303030303030303e803000000000000000b776f726b20726573756c7493880101810000")

(defparameter *wr-bytes* (jam.ffi:hex-string-to-bytes *wr-hex*))

(format t "WorkReport binary: ~a bytes~%~%" (length *wr-bytes*))

;; Decode
(handler-case
    (multiple-value-bind (report bytes-consumed)
        (decode-work-report *wr-bytes* 0)
      (format t "✅ Decoded! Consumed ~a/~a bytes~%~%" bytes-consumed (length *wr-bytes*))
      
      ;; Validate fields
      (let ((spec (getf report :package-spec))
            (ctx (getf report :context))
            (pass t))
        
        ;; WorkPackageSpec
        (format t "WorkPackageSpec:~%")
        (format t "  hash:          ~a~%" (jam.ffi:bytes-to-hex-string (getf spec :hash)))
        (format t "  length:        ~a (expected: 4)~%" (getf spec :length))
        (unless (= (getf spec :length) 4) (setf pass nil) (format t "  ❌ length mismatch!~%"))
        (format t "  exports_count: ~a (expected: 2)~%" (getf spec :exports-count))
        (unless (= (getf spec :exports-count) 2) (setf pass nil) (format t "  ❌ exports_count mismatch!~%"))
        
        ;; RefineContext
        (format t "~%RefineContext:~%")
        (format t "  lookup_anchor_slot: ~a (expected: 12)~%" (getf ctx :lookup-anchor-slot))
        (unless (= (getf ctx :lookup-anchor-slot) 12) (setf pass nil) (format t "  ❌ slot mismatch!~%"))
        (format t "  prerequisites:     ~a items (expected: 1)~%" (length (getf ctx :prerequisites)))
        (unless (= (length (getf ctx :prerequisites)) 1) (setf pass nil) (format t "  ❌ prereqs mismatch!~%"))
        
        ;; Core fields
        (format t "~%Core fields:~%")
        (format t "  core_index:     ~a (expected: 3)~%" (getf report :core-index))
        (unless (= (getf report :core-index) 3) (setf pass nil) (format t "  ❌ core_index mismatch!~%"))
        (format t "  auth_gas_used:  ~a (expected: 7500)~%" (getf report :auth-gas-used))
        (unless (= (getf report :auth-gas-used) 7500) (setf pass nil) (format t "  ❌ auth_gas mismatch!~%"))
        (format t "  auth_output:    ~a bytes (expected: 11)~%" (length (getf report :auth-output)))
        (unless (= (length (getf report :auth-output)) 11) (setf pass nil) (format t "  ❌ auth_output mismatch!~%"))
        
        ;; Segment root lookup
        (format t "~%Segment root lookup:~%")
        (format t "  items:          ~a (expected: 1)~%" (length (getf report :segment-root-lookup)))
        (unless (= (length (getf report :segment-root-lookup)) 1) (setf pass nil) (format t "  ❌ seg_lookup mismatch!~%"))
        
        ;; Results
        (format t "~%Results:~%")
        (format t "  count:          ~a (expected: 1)~%" (length (getf report :results)))
        (unless (= (length (getf report :results)) 1) (setf pass nil) (format t "  ❌ results count mismatch!~%"))
        
        (when (> (length (getf report :results)) 0)
          (let ((r (first (getf report :results))))
            (format t "  service_id:     ~a (expected: 10)~%" (getf r :service-id))
            (unless (= (getf r :service-id) 10) (setf pass nil) (format t "  ❌ service_id mismatch!~%"))
            (format t "  accumulate_gas: ~a (expected: 1000)~%" (getf r :accumulate-gas))
            (unless (= (getf r :accumulate-gas) 1000) (setf pass nil) (format t "  ❌ acc_gas mismatch!~%"))
            (format t "  result:         ~a~%" (getf r :result))
            ;; RefineLoad
            (let ((load (getf r :refine-load)))
              (format t "  refine_load:~%")
              (format t "    gas_used:     ~a (expected: 5000)~%" (getf load :gas-used))
              (unless (= (getf load :gas-used) 5000) (setf pass nil) (format t "    ❌ gas_used mismatch!~%"))
              (format t "    imports:      ~a (expected: 1)~%" (getf load :imports))
              (format t "    ext_count:    ~a (expected: 1)~%" (getf load :extrinsic-count))
              (format t "    ext_size:     ~a (expected: 256)~%" (getf load :extrinsic-size))
              (unless (= (getf load :extrinsic-size) 256) (setf pass nil) (format t "    ❌ ext_size mismatch!~%"))
              (format t "    exports:      ~a (expected: 0)~%" (getf load :exports)))))
        
        ;; Round-trip: check all bytes consumed
        (unless (= bytes-consumed (length *wr-bytes*))
          (setf pass nil)
          (format t "~%❌ Not all bytes consumed: ~a / ~a~%" bytes-consumed (length *wr-bytes*)))
        
        (format t "~%~a~%" (if pass "✅ ALL FIELDS VALIDATED!" "❌ SOME FIELDS FAILED!"))
        (sb-ext:exit :code (if pass 0 1))))
  (error (e)
    (format t "❌ DECODE FAILED: ~a~%" e)
    (sb-ext:exit :code 1)))
