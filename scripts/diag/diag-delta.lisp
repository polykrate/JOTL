;;;; diag-delta.lisp — Deep DELTA-KVS divergence diagnostic
(in-package #:jotl)

(defun diag-decode-sub-key-sid (key-31)
  "Extract service-id from interleaved sub-key: s=[k0,k2,k4,k6] as LE u32."
  (logior (aref key-31 0)
          (ash (aref key-31 2) 8)
          (ash (aref key-31 4) 16)
          (ash (aref key-31 6) 24)))

(defun diag-decode-sub-key-h27 (key-31)
  "Extract 27-byte hash from interleaved sub-key."
  (let ((h (make-array 27 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (aref key-31 1)
          (aref h 1) (aref key-31 3)
          (aref h 2) (aref key-31 5)
          (aref h 3) (aref key-31 7))
    (loop for i from 4 below 27
          do (setf (aref h i) (aref key-31 (+ i 4))))
    h))

(defun diag-metadata-key-p (key-31)
  "Check if key matches metadata format C(255,s)."
  (and (= (aref key-31 0) #xFF)
       (zerop (aref key-31 2))
       (zerop (aref key-31 4))
       (zerop (aref key-31 6))
       (loop for i from 8 below 31 always (zerop (aref key-31 i)))))

(defun diag-decode-svc-info (bytes)
  "Decode 89-byte ServiceInfo into plist."
  (when (>= (length bytes) 89)
    (list :version (aref bytes 0)
          :code-hash (subseq bytes 1 33)
          :balance (decode-u64 bytes 33)
          :min-accum-gas (decode-u64 bytes 41)
          :min-memo-gas (decode-u64 bytes 49)
          :total-bytes (decode-u64 bytes 57)
          :deposit-offset (decode-u64 bytes 65)
          :items (decode-u32 bytes 73)
          :creation-slot (decode-u32 bytes 77)
          :last-accum-slot (decode-u32 bytes 81)
          :parent-service (decode-u32 bytes 85))))

(defun diag-show-metadata-diff (exp-bytes comp-bytes)
  "Compare two 89-byte ServiceInfo and show field-level differences."
  (let ((ef (diag-decode-svc-info exp-bytes))
        (cf (diag-decode-svc-info comp-bytes)))
    (loop for (fname eval) on ef by #'cddr
          for cval = (getf cf fname)
          do (cond
               ((and (arrayp eval) (arrayp cval))
                (unless (equalp eval cval)
                  (format t "    ~A: DIFF~%      exp=~A~%      got=~A~%"
                          fname (bytes-to-hex-string eval)
                          (bytes-to-hex-string cval))))
               ((not (eql eval cval))
                (format t "    ~A: exp=~D got=~D (diff=~D)~%"
                        fname eval cval (- (or cval 0) (or eval 0))))))))

(defun diag-show-subkey-diff (key-31 exp-val comp-val)
  "Show detailed sub-key value differences."
  (let ((h27 (diag-decode-sub-key-h27 key-31)))
    (format t "  type = SUB-KEY (storage/preimage/lookup)~%")
    (format t "  h27  = ~A~%" (bytes-to-hex-string h27))
    (format t "  exp-len=~D comp-len=~D~%" (length exp-val) (length comp-val))
    ;; Small values → show as u64
    (when (<= (length exp-val) 8)
      (let ((ev (loop for i from 0 below (length exp-val)
                      sum (ash (aref exp-val i) (* i 8))))
            (cv (loop for i from 0 below (length comp-val)
                      sum (ash (aref comp-val i) (* i 8)))))
        (format t "  exp-val (u64-LE) = ~D~%" ev)
        (format t "  got-val (u64-LE) = ~D~%" cv)
        (format t "  diff = ~D~%" (- cv ev))))
    ;; Larger values → show hex
    (when (> (length exp-val) 8)
      (format t "  exp-val = ~A~%" (bytes-to-hex-string exp-val))
      (format t "  got-val = ~A~%" (bytes-to-hex-string comp-val)))
    ;; Byte-level diff
    (let ((min-len (min (length exp-val) (length comp-val))))
      (loop for i from 0 below min-len
            when (not (= (aref exp-val i) (aref comp-val i)))
            do (format t "  byte[~D]: exp=~D got=~D~%"
                       i (aref exp-val i) (aref comp-val i))
            and count t into cnt
            when (>= cnt 10)
            do (format t "  ... (more diffs)~%")
            and do (return)))))

(defun diag-actual-service-id (key-31)
  "For metadata keys: actual SID is in h[0..3]. For sub-keys: in s[0..3]."
  (if (diag-metadata-key-p key-31)
      ;; Metadata: h = [E4(sid), 0...0], extract from h[0..3]
      (let ((h27 (diag-decode-sub-key-h27 key-31)))
        (logior (aref h27 0)
                (ash (aref h27 1) 8)
                (ash (aref h27 2) 16)
                (ash (aref h27 3) 24)))
      ;; Sub-key: sid is in s = [k0, k2, k4, k6]
      (diag-decode-sub-key-sid key-31)))

(defun diag-show-value-diff (key-31 exp-val comp-val idx)
  "Display a single value difference with key decoding."
  (format t "~%═══ VALUE DIFF #~D ═══~%" idx)
  (format t "  key = ~A~%" (bytes-to-hex-string key-31))
  (let ((sid (diag-actual-service-id key-31)))
    (format t "  service-id = ~D (0x~X)~%" sid sid)
    (if (diag-metadata-key-p key-31)
        (progn
          (format t "  type = METADATA (ServiceInfo, 89 bytes)~%")
          (diag-show-metadata-diff exp-val comp-val))
        (diag-show-subkey-diff key-31 exp-val comp-val))))

(defun diag-delta-deep (step-path)
  "Run one step and show detailed delta-kvs differences."
  (let ((bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root))
      (let ((*chain-log-level* nil))
        (handler-case
            (multiple-value-bind (sigma-prime computed-root)
                (import-block pre-sigma block-cl)
              (format t "Expected root: ~A~%" (bytes-to-hex-string post-root))
              (format t "Computed root: ~A~%" (bytes-to-hex-string computed-root))
              (format t "Match: ~A~%~%" (equalp computed-root post-root))

              (let ((computed-ht (make-hash-table :test 'equalp))
                    (expected-ht (make-hash-table :test 'equalp)))
                (dolist (kv (funcall sigma-prime :merkle-kvs))
                  (setf (gethash (car kv) computed-ht) (cdr kv)))
                (dolist (kv (funcall post-sigma :merkle-kvs))
                  (setf (gethash (car kv) expected-ht) (cdr kv)))

                (let ((extra-computed 0) (extra-expected 0) (value-diff 0))
                  ;; Expected vs computed
                  (maphash
                   (lambda (k v)
                     (unless (segment-key-p k)
                       (let ((cv (gethash k computed-ht)))
                         (cond
                           ((null cv)
                            (incf extra-expected)
                            (when (< extra-expected 5)
                              (format t "MISSING in computed: key=~A~%"
                                      (bytes-to-hex-string k))))
                           ((not (equalp cv v))
                            (incf value-diff)
                            (diag-show-value-diff k v cv value-diff))))))
                   expected-ht)
                  ;; Extra in computed
                  (maphash
                   (lambda (k v)
                     (declare (ignore v))
                     (unless (segment-key-p k)
                       (unless (gethash k expected-ht)
                         (incf extra-computed)
                         (when (< extra-computed 5)
                           (format t "EXTRA in computed: key=~A sid=~D~%"
                                   (bytes-to-hex-string k)
                                   (diag-decode-sub-key-sid k))))))
                   computed-ht)
                  (format t "~%Summary: extra-exp=~D extra-comp=~D value-diff=~D~%"
                          extra-expected extra-computed value-diff))))
          (error (e)
            (format t "STF error: ~A~%" e)))))))

(defun diag-delta-context (step-path target-sid)
  "Show timeslot, pre-state last-accum-slot, and accumulation decision for TARGET-SID."
  (let ((bytes (alexandria:read-file-into-byte-vector step-path)))
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore post-sigma pre-root post-root))
      ;; Block timeslot - try multiple access paths
      (handler-case
          (let ((header (funcall block-cl :header)))
            (format t "  Block header: ~A~%" (type-of header))
            (when header
              (format t "  Block timeslot (HT) = ~D~%" (funcall header :timeslot))))
        (error (e) (format t "  Header access error: ~A~%" e)))
      ;; Pre-state last-accum-slot for target service
      (let ((pre-delta (funcall pre-sigma :load :delta)))
        (when pre-delta
          (let ((svc-data (funcall pre-delta :service-data target-sid)))
            (let ((meta (getf svc-data :metadata)))
              (if meta
                  (format t "  Pre-state service ~D: last-accum=~D code-hash=~A~%"
                          target-sid
                          (getf meta :last-accumulation-slot)
                          (bytes-to-hex-string (getf meta :code-hash)))
                  (format t "  Pre-state: service ~D NOT FOUND in delta~%" target-sid))))))
      ;; Check if this service appears in work reports
      (handler-case
          (let ((guarantees (funcall block-cl :guarantees)))
            (format t "  Guarantees: ~A~%" (if guarantees "present" "nil"))
            (when guarantees
              (let ((glist (getf guarantees :guarantees)))
                (format t "  Guarantee count: ~D~%" (length glist))
                (dolist (g glist)
                  (let ((report (getf g :report)))
                    (when report
                      (let ((results (getf report :results)))
                        (dolist (r results)
                          (when (= (getf r :service-id) target-sid)
                            (format t "  >>> Service ~D FOUND in work report!~%"
                                    target-sid))))))))))
        (error (e) (format t "  Guarantees check error: ~A~%" e)))
      ;; Check pre-state chi (always-accumulate list)
      (handler-case
          (let ((chi (funcall pre-sigma :load :chi)))
            (when chi
              (let ((always (funcall chi :always-accum)))
                (format t "  χ_Z always-accum: ~A~%" always)
                (when (assoc target-sid always)
                  (format t "  >>> Service ~D is in always-accumulate!~%" target-sid)))))
        (error (e) (format t "  Chi check error: ~A~%" e))))))

(format t "~%══════ DELTA-KVS trace 1: 1766255635_2557 step 153 ══════~%")
(diag-delta-deep "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1766255635_2557/00000153.bin")
;; service-id = 2659158065 = 0x9E7F8831 — sub-key (storage)
(format t "  --- Context for service 2659158065 ---~%")
(diag-delta-context "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1766255635_2557/00000153.bin" 2659158065)

(format t "~%══════ DELTA-KVS trace 2: 1767889897_2969 step 2314 ══════~%")
(diag-delta-deep "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1767889897_2969/00002314.bin")
;; Actual service ID from metadata key: h[0..3] = [0xDD, 0x5B, 0x4F, 0xC4]
;; = 0xC44F5BDD = 3293535197
(format t "  --- Context for service 3293535197 ---~%")
(diag-delta-context "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1767889897_2969/00002314.bin" 3293535197)

(format t "~%══════ DELTA-KVS trace 3: 1767889897_3840 step 710 ══════~%")
(diag-delta-deep "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1767889897_3840/00000710.bin")
;; service-id = 994117200 = 0x3B410650 — sub-key (storage)
(format t "  --- Context for service 994117200 ---~%")
(diag-delta-context "/home/polycrate/Projets/Jam/jam-conformance/fuzz-reports/0.7.2/traces/1767889897_3840/00000710.bin" 994117200)

(sb-ext:exit :code 0)
