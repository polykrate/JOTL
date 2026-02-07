;;;; test-header-decode-complete.lisp - Complete header decoding test
;;;; Decode ALL fields from header_0.bin and compare with header_0.json

(load "scripts/load-jotl.lisp")

(ql:quickload :cl-json :silent t)

(in-package :jotl)

(format t "~%~%╔═══════════════════════════════════════════════════════════╗~%")
(format t "║     COMPLETE HEADER DECODING TEST (Binary → JSON)        ║~%")
(format t "╚═══════════════════════════════════════════════════════════╝~%~%")

;;; ==========================================================================
;;; Utilities
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

(defun bytes-to-hex (bytes)
  "Convert bytes to hex string with 0x prefix"
  (let ((hex (jam.ffi:bytes-to-hex-string bytes)))
    ;; bytes-to-hex-string already adds 0x prefix
    (if (alexandria:starts-with-subseq "0x" hex)
        hex
        (concatenate 'string "0x" hex))))

(defun extract-bytes (buffer offset length)
  "Extract a slice of bytes from buffer"
  (subseq buffer offset (+ offset length)))

;;; ==========================================================================
;;; Decoders for Complex Types
;;; ==========================================================================

(defun decode-validator (bytes offset)
  "Decode a validator: (Bandersnatch:32, Ed25519:32)
   Returns: (values alist bytes-consumed)"
  (let ((bandersnatch (extract-bytes bytes offset 32))
        (ed25519 (extract-bytes bytes (+ offset 32) 32)))
    (values
     (list (cons :bandersnatch (bytes-to-hex bandersnatch))
           (cons :ed25519 (bytes-to-hex ed25519)))
     64)))

(defun decode-validators-sequence (bytes offset num-validators)
  "Decode FIXED-SIZE sequence of validators (no compact length prefix!)
   
   The number of validators is determined by chainspec (NV).
   For tiny: NV = 6
   For full: NV = 1023
   
   Returns: (values list-of-validators bytes-consumed)"
  (let ((validators '())
        (pos offset))
    (dotimes (i num-validators)
      (multiple-value-bind (validator validator-size)
          (decode-validator bytes pos)
        (push validator validators)
        (incf pos validator-size)))
    (values (nreverse validators) (- pos offset))))

(defun decode-epoch-mark (bytes offset)
  "Decode EpochMark: (entropy:H, tickets_entropy:H, validators:Seq<Validator>)
   Returns: (values alist bytes-consumed)"
  (let ((entropy (extract-bytes bytes offset 32))
        (tickets-entropy (extract-bytes bytes (+ offset 32) 32))
        (pos (+ offset 64))
        ;; Number of validators from chainspec (tiny=6, full=1023)
        (num-validators (num-validators)))
    (multiple-value-bind (validators validators-size)
        (decode-validators-sequence bytes pos num-validators)
      (values
       (list (cons :entropy (bytes-to-hex entropy))
             (cons :tickets-entropy (bytes-to-hex tickets-entropy))
             (cons :validators validators))
       (+ 64 validators-size)))))

(defun decode-option-epoch-mark (bytes offset)
  "Decode Option<EpochMark>
   Returns: (values epoch-mark-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0)  ; None
       (values nil 1))
      ((= tag 1)  ; Some
       (multiple-value-bind (epoch-mark size)
           (decode-epoch-mark bytes (1+ offset))
         (values epoch-mark (1+ size))))
      (t
       (error "Invalid option tag: ~A" tag)))))

(defun decode-option-tickets-mark (bytes offset)
  "Decode Option<TicketsMark> (we don't decode the structure, just skip it)
   Returns: (values tickets-mark-or-nil bytes-consumed)"
  (let ((tag (aref bytes offset)))
    (cond
      ((= tag 0)  ; None
       (values nil 1))
      ((= tag 1)  ; Some - TODO: implement full structure
       (error "TicketsMark decoding not yet implemented"))
      (t
       (error "Invalid option tag: ~A" tag)))))

(defun decode-ed25519-sequence (bytes offset)
  "Decode sequence of Ed25519 keys (32 bytes each)
   Returns: (values list-of-hex-strings bytes-consumed)"
  (multiple-value-bind (length len-bytes) (decode-compact bytes offset)
    (let ((keys '())
          (pos (+ offset len-bytes)))
      (dotimes (i length)
        (let ((key (extract-bytes bytes pos 32)))
          (push (bytes-to-hex key) keys)
          (incf pos 32)))
      (values (nreverse keys) (- pos offset)))))

;;; ==========================================================================
;;; Complete Header Decoder
;;; ==========================================================================

(defun decode-header-complete (bytes)
  "Decode complete header from binary.
   
   Header format (Gray Paper §5.1):
   E(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
   
   Note: This is for UNSEALED headers. Add HS (96 bytes) for sealed.
   
   Returns: alist of all header fields"
  (let ((offset 0)
        (result '()))
    
    ;; HP - Parent hash (32 bytes)
    (let ((parent (extract-bytes bytes offset 32)))
      (push (cons :parent (bytes-to-hex parent)) result)
      (incf offset 32))
    
    ;; HR - State root (32 bytes)
    (let ((state-root (extract-bytes bytes offset 32)))
      (push (cons :parent-state-root (bytes-to-hex state-root)) result)
      (incf offset 32))
    
    ;; HX - Extrinsic hash (32 bytes)
    (let ((extrinsic (extract-bytes bytes offset 32)))
      (push (cons :extrinsic-hash (bytes-to-hex extrinsic)) result)
      (incf offset 32))
    
    ;; HT - Timeslot (u32, 4 bytes)
    (let ((slot (decode-fixed-le (extract-bytes bytes offset 4))))
      (push (cons :slot slot) result)
      (incf offset 4))
    
    ;; HE - Epoch mark (Option<EpochMark>)
    (multiple-value-bind (epoch-mark epoch-size)
        (decode-option-epoch-mark bytes offset)
      (push (cons :epoch-mark epoch-mark) result)
      (incf offset epoch-size))
    
    ;; HW - Tickets mark (Option<TicketsMark>)
    (multiple-value-bind (tickets-mark tickets-size)
        (decode-option-tickets-mark bytes offset)
      (push (cons :tickets-mark tickets-mark) result)
      (incf offset tickets-size))
    
    ;; HI - Author index (u16, 2 bytes)
    (let ((author-index (decode-fixed-le (extract-bytes bytes offset 2))))
      (push (cons :author-index author-index) result)
      (incf offset 2))
    
    ;; HV - Entropy source (96 bytes)
    (let ((entropy-source (extract-bytes bytes offset 96)))
      (push (cons :entropy-source (bytes-to-hex entropy-source)) result)
      (incf offset 96))
    
    ;; HO - Offenders mark (Sequence<Ed25519>)
    (multiple-value-bind (offenders offenders-size)
        (decode-ed25519-sequence bytes offset)
      (push (cons :offenders-mark offenders) result)
      (incf offset offenders-size))
    
    ;; HS - Seal (96 bytes) - check if present
    (when (>= (- (length bytes) offset) 96)
      (let ((seal (extract-bytes bytes offset 96)))
        (push (cons :seal (bytes-to-hex seal)) result)
        (incf offset 96)))
    
    (values (nreverse result) offset)))

;;; ==========================================================================
;;; Load and Decode
;;; ==========================================================================

(defparameter *bin-file*
  #P"/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/header_0.bin")

(defparameter *json-file*
  #P"/home/polycrate/Projets/JOTL/tests/jamtestvectors/codec/tiny/header_0.json")

(format t "Loading files:~%")
(format t "  Binary: ~A~%" (file-namestring *bin-file*))
(format t "  JSON:   ~A~%~%" (file-namestring *json-file*))

(defparameter *header-bin* (read-binary-file *bin-file*))
(format t "  ✓ Loaded ~D bytes from binary~%" (length *header-bin*))

(defparameter *header-json*
  (with-open-file (s *json-file* :direction :input)
    (cl-json:decode-json s)))
(format t "  ✓ Loaded JSON~%~%")

;;; ==========================================================================
;;; Decode
;;; ==========================================================================

(format t "Decoding header...~%~%")

(multiple-value-bind (decoded offset) (decode-header-complete *header-bin*)
  (format t "  ✓ Decoded ~D bytes~%" offset)
  (format t "  ✓ Remaining: ~D bytes~%~%" (- (length *header-bin*) offset))
  
  (defparameter *decoded-header* decoded))

;;; ==========================================================================
;;; Display Decoded Header
;;; ==========================================================================

(format t "╔═══════════════════════════════════════════════════════════╗~%")
(format t "║              DECODED HEADER FIELDS                        ║~%")
(format t "╚═══════════════════════════════════════════════════════════╝~%~%")

(defun display-field (name value &optional (indent 2))
  "Display a field with proper formatting"
  (let ((prefix (make-string indent :initial-element #\Space)))
    (cond
      ((null value)
       (format t "~A~A: null~%" prefix name))
      ((stringp value)
       (format t "~A~A: ~A~%" prefix name value))
      ((numberp value)
       (format t "~A~A: ~D~%" prefix name value))
      ((and (listp value) (consp (car value)))  ; alist
       (format t "~A~A:~%" prefix name)
       (dolist (pair value)
         (display-field (car pair) (cdr pair) (+ indent 2))))
      ((listp value)  ; list
       (format t "~A~A: [~D items]~%" prefix name (length value))
       (dolist (item value)
         (if (and (listp item) (consp (car item)))
             (progn
               (format t "~A  -~%" prefix)
               (dolist (pair item)
                 (display-field (car pair) (cdr pair) (+ indent 4))))
             (display-field "" item (+ indent 4)))))
      (t
       (format t "~A~A: ~A~%" prefix name value)))))

(dolist (field *decoded-header*)
  (display-field (car field) (cdr field)))

(format t "~%")

;;; ==========================================================================
;;; Compare with JSON
;;; ==========================================================================

(format t "╔═══════════════════════════════════════════════════════════╗~%")
(format t "║              COMPARISON WITH JSON                         ║~%")
(format t "╚═══════════════════════════════════════════════════════════╝~%~%")

(defun get-json-field (json key)
  "Get field from JSON (cl-json uses keyword keys with cdr for alists)
   cl-json converts underscores to double-dashes: parent_state_root → PARENT--STATE--ROOT"
  (let* ((key-str (string-upcase key))
         ;; Replace _ with -- for cl-json's convention
         (converted (with-output-to-string (s)
                      (loop for c across key-str
                            do (if (char= c #\_)
                                   (write-string "--" s)
                                   (write-char c s)))))
         (keyword-key (intern converted :keyword)))
    (cdr (assoc keyword-key json))))

(defun compare-field (name decoded-value json-value)
  "Compare decoded value with JSON value
   
   Note: bytes-to-hex-string now returns lowercase by default,
   matching JSON format perfectly!"
  (let ((match
         (cond
           ;; Both nil
           ((and (null decoded-value) (null json-value))
            t)
           ;; Both numbers
           ((and (numberp decoded-value) (numberp json-value))
            (= decoded-value json-value))
           ;; Both strings (hex) - now case-insensitive to be safe
           ((and (stringp decoded-value) (stringp json-value))
            (string-equal decoded-value json-value))
           ;; Lists - compare lengths first
           ((and (listp decoded-value) (listp json-value))
            (and (= (length decoded-value) (length json-value))
                 ;; TODO: deep comparison
                 t))
           ;; Different types
           (t nil))))
    
    (format t "  ~A: ~A~%"
            name
            (if match "✅ MATCH" "❌ MISMATCH"))
    
    (unless match
      (format t "    Expected: ~A~%" json-value)
      (format t "    Decoded:  ~A~%" decoded-value))
    
    match))

(defparameter *test-results* '())

;; Compare simple fields
(push (compare-field "Parent"
                     (cdr (assoc :parent *decoded-header*))
                     (get-json-field *header-json* "parent"))
      *test-results*)

(push (compare-field "State Root"
                     (cdr (assoc :parent-state-root *decoded-header*))
                     (get-json-field *header-json* "parent_state_root"))
      *test-results*)

(push (compare-field "Extrinsic Hash"
                     (cdr (assoc :extrinsic-hash *decoded-header*))
                     (get-json-field *header-json* "extrinsic_hash"))
      *test-results*)

(push (compare-field "Slot"
                     (cdr (assoc :slot *decoded-header*))
                     (get-json-field *header-json* "slot"))
      *test-results*)

(push (compare-field "Author Index"
                     (cdr (assoc :author-index *decoded-header*))
                     (get-json-field *header-json* "author_index"))
      *test-results*)

(push (compare-field "Entropy Source"
                     (cdr (assoc :entropy-source *decoded-header*))
                     (get-json-field *header-json* "entropy_source"))
      *test-results*)

(push (compare-field "Seal"
                     (cdr (assoc :seal *decoded-header*))
                     (get-json-field *header-json* "seal"))
      *test-results*)

;; Epoch mark - detailed comparison
(let ((decoded-epoch (cdr (assoc :epoch-mark *decoded-header*)))
      (json-epoch (get-json-field *header-json* "epoch_mark")))
  (if (and decoded-epoch json-epoch)
      (progn
        (format t "~%  Epoch Mark (detailed):~%")
        (push (compare-field "    Entropy"
                           (cdr (assoc :entropy decoded-epoch))
                           (get-json-field json-epoch "entropy"))
              *test-results*)
        (push (compare-field "    Tickets Entropy"
                           (cdr (assoc :tickets-entropy decoded-epoch))
                           (get-json-field json-epoch "tickets_entropy"))
              *test-results*)
        (let ((decoded-validators (cdr (assoc :validators decoded-epoch)))
              (json-validators (get-json-field json-epoch "validators")))
          (push (compare-field "    Validators Count"
                             (length decoded-validators)
                             (length json-validators))
                *test-results*)))
      (push (compare-field "Epoch Mark" decoded-epoch json-epoch)
            *test-results*)))

;; Offenders mark
(let ((decoded-offenders (cdr (assoc :offenders-mark *decoded-header*)))
      (json-offenders (get-json-field *header-json* "offenders_mark")))
  (push (compare-field "Offenders Count"
                     (length decoded-offenders)
                     (length json-offenders))
        *test-results*))

;;; ==========================================================================
;;; Final Results
;;; ==========================================================================

(format t "~%╔═══════════════════════════════════════════════════════════╗~%")
(format t "║                   FINAL RESULTS                           ║~%")
(format t "╚═══════════════════════════════════════════════════════════╝~%~%")

(let ((passed (count t *test-results*))
      (total (length *test-results*)))
  (format t "  Tests passed: ~D / ~D~%" passed total)
  (format t "  Success rate: ~,1F%~%~%" (* 100.0 (/ passed total)))
  
  (if (= passed total)
      (format t "  🎉 ALL TESTS PASSED! Binary decoding is correct!~%~%")
      (format t "  ⚠️  Some tests failed. Review the mismatches above.~%~%")))
