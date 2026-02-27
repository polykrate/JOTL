;;;; diag/diag-gamma.lisp — Diagnose GAMMA divergence in polkajam traces
;;;;
;;;; Usage: sbcl --load scripts/load-jotl.lisp --load scripts/diag/diag-gamma.lisp
;;;;
;;;; Replays a specific trace step and compares gamma sub-fields (γP, γZ, γS, γA).
;;;; Uses decode-trace-step-bin (same path as test runner).

(in-package :jotl)

(defvar *dg-trace-id* "1766243493_1163")
(defvar *dg-step* "00000016")

(defun dg-trace-dir ()
  (merge-pathnames (format nil "../jam-conformance/fuzz-reports/0.7.2/traces/~A/"
                           *dg-trace-id*)
                   (truename (asdf:system-source-directory :jotl))))

(defun dg-hex (bytes &optional (n 16))
  "Format first N bytes as hex string."
  (with-output-to-string (s)
    (dotimes (i (min n (length bytes)))
      (format s "~2,'0X " (aref bytes i)))))

(defun dg-run ()
  "Run gamma diagnostic on the configured trace step."
  (format t "~%=== GAMMA DIAGNOSTIC ===~%")
  (format t "Trace: ~A  Step: ~A~%" *dg-trace-id* *dg-step*)

  (let* ((step-path (merge-pathnames (format nil "~A.bin" *dg-step*)
                                     (dg-trace-dir)))
         (bytes (alexandria:read-file-into-byte-vector step-path)))
    ;; Decode: pre-σ, block, post-σ, pre-root, post-root
    (multiple-value-bind (pre-sigma block-cl post-sigma pre-root post-root)
        (decode-trace-step-bin bytes)
      (declare (ignore pre-root))

      (let ((expected-gamma (funcall post-sigma :segment :gamma)))
        (format t "Expected gamma: ~D bytes~%" (length expected-gamma))

        ;; Binary layout (TINY: V=6, E=12):
        ;; γP: compact(V) + V×336
        ;; γZ: 144 bytes
        ;; γS: 1 + E×33 (tickets) or 1 + E×32 (keys)
        ;; γA: compact-prefixed sequence of 33-byte tickets
        (let* ((V (num-validators))
               (E (epoch-duration))
               ;; NOTE: encode-full-validator-sequence has NO compact prefix
               (gp-prefix-size 0)
               (gp-size (* V 336))
               (gz-start gp-size)
               (gz-end (+ gz-start 144))
               (gs-disc-exp (aref expected-gamma gz-end))
               (gs-data-size (if (zerop gs-disc-exp) (* E 33) (* E 32)))
               (gs-end (+ gz-end 1 gs-data-size)))
          (format t "Layout: gP=0..~D  gZ=~D..~D  gS=~D..~D  gA=~D..~%"
                  (1- gp-size) gz-start (1- gz-end) gz-end (1- gs-end) gs-end)

          ;; Apply block
          (format t "~%── Applying block ──~%")
          (let ((ts (funcall (funcall block-cl :header) :timeslot)))
            (format t "Block timeslot: ~D (epoch ~D, phase ~D)~%" ts (floor ts E) (mod ts E)))

          (handler-case
              (let* ((*chain-log-level* nil)
                     (sigma-prime (import-block pre-sigma block-cl))
                     (computed-gamma (funcall sigma-prime :segment :gamma)))
                (format t "Computed gamma: ~D bytes~%" (length computed-gamma))

                (if (equalp computed-gamma expected-gamma)
                    (format t "~%RESULT: gamma MATCH (no divergence)~%")
                    (progn
                      (format t "~%RESULT: gamma MISMATCH~%")

                      ;; ── γP ──
                      (let ((c-gp (subseq computed-gamma 0 gp-size))
                            (e-gp (subseq expected-gamma 0 gp-size)))
                        (if (equalp c-gp e-gp)
                            (format t "  gP: OK~%")
                            (progn
                              (format t "  gP: DIVERGE~%")
                              (dotimes (v V)
                                (let* ((start (+ gp-prefix-size (* v 336)))
                                       (end (+ start 336))
                                       (cv (subseq computed-gamma start end))
                                       (ev (subseq expected-gamma start end)))
                                  (unless (equalp cv ev)
                                    (format t "    validator ~D differs~%" v)
                                    (format t "      kb(bander,0..31):  c=~A~%" (dg-hex (subseq cv 0 32)))
                                    (format t "      kb(bander,0..31):  e=~A~%" (dg-hex (subseq ev 0 32)))
                                    (format t "      ke(ed25519,32..63):c=~A~%" (dg-hex (subseq cv 32 64)))
                                    (format t "      ke(ed25519,32..63):e=~A~%" (dg-hex (subseq ev 32 64)))
                                    (format t "      kl(bls,64..207):   c=~A~%" (dg-hex (subseq cv 64 208) 16))
                                    (format t "      kl(bls,64..207):   e=~A~%" (dg-hex (subseq ev 64 208) 16))
                                    (format t "      km(meta,208..335): c=~A~%" (dg-hex (subseq cv 208 336) 16))
                                    (format t "      km(meta,208..335): e=~A~%" (dg-hex (subseq ev 208 336) 16))
                                    ;; Find exact differing byte
                                    (dotimes (b 336)
                                      (unless (= (aref cv b) (aref ev b))
                                        (format t "      first diff at byte ~D: c=~2,'0X e=~2,'0X~%" b (aref cv b) (aref ev b))
                                        (cond
                                          ((< b 32)  (format t "      -> in kb (bandersnatch)~%"))
                                          ((< b 64)  (format t "      -> in ke (ed25519)~%"))
                                          ((< b 208) (format t "      -> in kl (BLS, offset ~D)~%" (- b 64)))
                                          (t         (format t "      -> in km (metadata, offset ~D)~%" (- b 208))))
                                        (return)))))))))

                      ;; ── γZ ──
                      (let ((c-gz (subseq computed-gamma gz-start gz-end))
                            (e-gz (subseq expected-gamma gz-start gz-end)))
                        (if (equalp c-gz e-gz)
                            (format t "  gZ: OK~%")
                            (progn
                              (format t "  gZ: DIVERGE~%")
                              (format t "    computed: ~A...~%" (dg-hex c-gz 16))
                              (format t "    expected: ~A...~%" (dg-hex e-gz 16))
                              (let ((n 0))
                                (dotimes (i 144)
                                  (unless (= (aref c-gz i) (aref e-gz i)) (incf n)))
                                (format t "    ~D/144 bytes differ~%" n)))))

                      ;; ── γS ──
                      (let* ((c-gs-disc (aref computed-gamma gz-end))
                             (c-gs-data-size (if (zerop c-gs-disc) (* E 33) (* E 32)))
                             (c-gs-end (+ gz-end 1 c-gs-data-size)))
                        (let ((c-gs (subseq computed-gamma gz-end c-gs-end))
                              (e-gs (subseq expected-gamma gz-end gs-end)))
                          (if (equalp c-gs e-gs)
                              (format t "  gS: OK~%")
                              (progn
                                (format t "  gS: DIVERGE (c-disc=~D e-disc=~D)~%"
                                        c-gs-disc gs-disc-exp)
                                (when (= c-gs-disc gs-disc-exp)
                                  (let ((entry-size (if (zerop c-gs-disc) 33 32)))
                                    (dotimes (i E)
                                      (let ((off (+ gz-end 1 (* i entry-size))))
                                        (unless (equalp (subseq computed-gamma off (+ off entry-size))
                                                        (subseq expected-gamma off (+ off entry-size)))
                                          (format t "    entry ~D differs~%" i))))))))))

                      ;; ── γA ──
                      (let* ((c-gs-disc (aref computed-gamma gz-end))
                             (c-gs-data-size (if (zerop c-gs-disc) (* E 33) (* E 32)))
                             (c-gs-end (+ gz-end 1 c-gs-data-size))
                             (c-ga (subseq computed-gamma c-gs-end))
                             (e-ga (subseq expected-gamma gs-end)))
                        (format t "  gA: computed=~D bytes, expected=~D bytes~%"
                                (length c-ga) (length e-ga))
                        (if (equalp c-ga e-ga)
                            (format t "  gA: OK~%")
                            (format t "  gA: DIVERGE~%")))

                      ;; ── Deep dive: compare loaded gamma closures ──
                      (format t "~%── Deep gamma closure comparison ──~%")
                      (let ((c-gamma (funcall sigma-prime :load :gamma))
                            (e-gamma (funcall post-sigma :load :gamma)))
                        (when (and c-gamma e-gamma)
                          ;; Compare ring commitments decoded
                          (let ((c-rc (funcall c-gamma :gamma-z))
                                (e-rc (funcall e-gamma :gamma-z)))
                            (format t "  gZ decoded: c=~A~%" (dg-hex c-rc 16))
                            (format t "  gZ decoded: e=~A~%" (dg-hex e-rc 16))
                          ;; Compare sealing variant
                          (format t "  gS variant: c=~A e=~A~%"
                                  (funcall c-gamma :sealing-variant)
                                  (funcall e-gamma :sealing-variant))
                          ;; Compare accumulator lengths
                          (format t "  gA count: c=~D e=~D~%"
                                  (length (funcall c-gamma :gamma-a))
                                  (length (funcall e-gamma :gamma-a)))
                          ;; Compare pending keys: are the bandersnatch keys the same?
                          (let ((c-pk (funcall c-gamma :pending-keys))
                                (e-pk (funcall e-gamma :pending-keys)))
                            (format t "  gP count: c=~D e=~D~%" (length c-pk) (length e-pk))
                            (dotimes (v (min (length c-pk) (length e-pk)))
                              (let ((ck (getf (nth v c-pk) :bandersnatch))
                                    (ek (getf (nth v e-pk) :bandersnatch)))
                                (unless (equalp ck ek)
                                  (format t "    validator ~D bandersnatch key DIFFERS~%" v)))))

                          ;; ── CRITICAL TEST: compute O(expected_keys) independently ──
                          (format t "~%── Independent O(expected_gP) test ──~%")
                          (let* ((e-pk (funcall e-gamma :pending-keys))
                                 (e-bander-keys (mapcar (lambda (k) (getf k :bandersnatch)) e-pk))
                                 (recomputed-gz (jam.ffi:bandersnatch-compute-ring-commitment
                                                 (coerce e-bander-keys 'vector))))
                            (format t "  Expected gZ:    ~A~%" (dg-hex e-rc 16))
                            (format t "  Recomputed gZ:  ~A~%" (if recomputed-gz (dg-hex recomputed-gz 16) "NIL"))
                            (format t "  Our computed gZ:~A~%" (dg-hex c-rc 16))
                            (when recomputed-gz
                              (format t "  Recomputed == Expected: ~A~%" (equalp recomputed-gz e-rc))
                              (format t "  Recomputed == Ours:     ~A~%" (equalp recomputed-gz c-rc)))

                            ;; Print all 6 bandersnatch keys for debugging
                            (format t "~%  Input bandersnatch keys:~%")
                            (dotimes (v (length e-bander-keys))
                              (let ((key (nth v e-bander-keys)))
                                (format t "    v~D: ~A (zero=~A)~%"
                                        v (dg-hex key 32)
                                        (every #'zerop key))))

                            ;; ── RING SIZE SWEEP: try different domain sizes ──
                            (format t "~%── Ring size sweep ──~%")
                            (dolist (rs '(6 7 8 12 16 32 64 128 256 512 1024 2048))
                              (let ((gz-rs (jam.ffi:bandersnatch-compute-ring-commitment-padded
                                            (coerce e-bander-keys 'vector) rs)))
                                (format t "  ring_size=~4D: ~A  match=~A~%"
                                        rs
                                        (if gz-rs (dg-hex gz-rs 8) "FAILED")
                                        (and gz-rs (equalp gz-rs e-rc)))))

                            ;; Also check: what does gamma transition use?
                            (let* ((c-pk (funcall c-gamma :pending-keys))
                                   (c-bander-keys (mapcar (lambda (k) (getf k :bandersnatch)) c-pk))
                                   (c-recomputed (jam.ffi:bandersnatch-compute-ring-commitment
                                                  (coerce c-bander-keys 'vector))))
                              (format t "~%  O(our_computed_gP) == our_gZ: ~A~%"
                                      (and c-recomputed (equalp c-recomputed c-rc)))
                              (format t "  our_gP == expected_gP: ~A~%"
                                      (equalp (coerce c-bander-keys 'vector)
                                              (coerce e-bander-keys 'vector))))))))))
            (error (e) (format t "~%ERROR: ~A~%" e)))))))

  (format t "~%=== END DIAGNOSTIC ===~%")))

(dg-run)
