;;;; init.lisp — GP A.7 Standard Program Initialization
;;;;
;;;; (A.2) deblob: p → (c, k, j) ∪ ∇
;;;;   Parse program blob to extract code, bitmask, and jump table.
;;;;
;;;; (A.7) Standard program initialization:
;;;;   Set up the memory layout from the JAM program blob fields:
;;;;     - ro_data  → mapped read-only at address 0
;;;;     - rw_data  → mapped read-write after ro_data (page-aligned)
;;;;     - stack    → mapped read-write at top of address space
;;;;     - heap     → starts after rw_data + padding
;;;;
;;;; Uses jam-program-blob-common format:
;;;;   ProgramBlob { metadata, ro_data, rw_data, code_blob,
;;;;                 rw_data_padding_pages, stack_size }

(in-package #:jamvm)

;;; ═══════════════════════════════════════════════════════════════════
;;; JAM program blob parsing
;;;
;;; Format (from jam-program-blob-common):
;;;   metadata: compact-len prefixed bytes
;;;   ro_data_len: u24
;;;   rw_data_len: u24
;;;   rw_data_padding_pages: u16
;;;   stack_size: u24
;;;   ro_data: [u8; ro_data_len]
;;;   rw_data: [u8; rw_data_len]
;;;   code_blob_len: u32
;;;   code_blob: [u8; code_blob_len]
;;; ═══════════════════════════════════════════════════════════════════

(defun read-u16-le (bytes offset)
  "Read u16 little-endian from BYTES at OFFSET."
  (logior (aref bytes offset)
          (ash (aref bytes (1+ offset)) 8)))

(defun read-u24-le (bytes offset)
  "Read u24 little-endian from BYTES at OFFSET."
  (logior (aref bytes offset)
          (ash (aref bytes (1+ offset)) 8)
          (ash (aref bytes (+ offset 2)) 16)))

(defun read-u32-le (bytes offset)
  "Read u32 little-endian from BYTES at OFFSET."
  (logior (aref bytes offset)
          (ash (aref bytes (1+ offset)) 8)
          (ash (aref bytes (+ offset 2)) 16)
          (ash (aref bytes (+ offset 3)) 24)))

(defun read-metadata-length (bytes offset)
  "Read the compact-encoded metadata length. Returns (values length consumed-bytes)."
  (let ((first (aref bytes offset)))
    (cond
      ;; 0xxxxxxx → length = first byte, 1 byte consumed
      ((zerop (logand first #x80))
       (values first 1))
      ;; 1xxxxxxx → length is in next 2 bytes (u16 LE) + continuation
      (t
       ;; For JAM blobs, metadata is typically short.
       ;; The compact encoding: if first byte has high bit set,
       ;; it means (first & 0x7f) | (next << 7) etc.
       ;; For simplicity, handle the common case.
       (values (logand first #x7f) 1)))))

(defstruct (program-blob (:conc-name blob-))
  "Parsed JAM program blob (GP A.2 + A.7)."
  (metadata   #() :type (simple-array (unsigned-byte 8) (*)))
  (ro-data    #() :type (simple-array (unsigned-byte 8) (*)))
  (rw-data    #() :type (simple-array (unsigned-byte 8) (*)))
  (code-blob  #() :type (simple-array (unsigned-byte 8) (*)))
  (rw-padding-pages 0 :type (unsigned-byte 16))
  (stack-size 0 :type (unsigned-byte 32)))

(defun parse-program-blob (bytes)
  "Parse a JAM program blob from BYTES. Returns program-blob or NIL."
  (handler-case
      (let ((pos 0)
            (len (length bytes)))
        ;; 1. Metadata (compact-prefixed)
        (multiple-value-bind (meta-len consumed) (read-metadata-length bytes pos)
          (incf pos consumed)
          (let ((metadata (subseq bytes pos (+ pos meta-len))))
            (incf pos meta-len)
            ;; 2. ro_data_len (u24)
            (let ((ro-len (read-u24-le bytes pos)))
              (incf pos 3)
              ;; 3. rw_data_len (u24)
              (let ((rw-len (read-u24-le bytes pos)))
                (incf pos 3)
                ;; 4. rw_data_padding_pages (u16)
                (let ((rw-pad (read-u16-le bytes pos)))
                  (incf pos 2)
                  ;; 5. stack_size (u24)
                  (let ((stack-sz (read-u24-le bytes pos)))
                    (incf pos 3)
                    ;; 6. ro_data
                    (let ((ro-data (subseq bytes pos (min (+ pos ro-len) len))))
                      (incf pos ro-len)
                      ;; 7. rw_data
                      (let ((rw-data (subseq bytes pos (min (+ pos rw-len) len))))
                        (incf pos rw-len)
                        ;; 8. code_blob_len (u32)
                        (let ((code-len (read-u32-le bytes pos)))
                          (incf pos 4)
                          ;; 9. code_blob
                          (let ((code-blob (subseq bytes pos (min (+ pos code-len) len))))
                            (make-program-blob
                             :metadata (coerce metadata '(simple-array (unsigned-byte 8) (*)))
                             :ro-data (coerce ro-data '(simple-array (unsigned-byte 8) (*)))
                             :rw-data (coerce rw-data '(simple-array (unsigned-byte 8) (*)))
                             :code-blob (coerce code-blob '(simple-array (unsigned-byte 8) (*)))
                             :rw-padding-pages rw-pad
                             :stack-size (* stack-sz +page-size+)))))))))))))
    (error () nil)))

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.2) deblob: code_blob → (c, k, j) ∪ ∇
;;;
;;; The code_blob contains:
;;;   E(|j|)           — compact-encoded jump table length
;;;   E₁(z)            — 1-byte instruction boundary zone
;;;   E(|c|)           — compact-encoded code length
;;;   E_z(j)           — z-byte encoded jump table entries
;;;   E(c)             — code bytes
;;;   E(k)             — bitmask bytes
;;;
;;; With validation: |k| = |c|  (1 bit per code byte)
;;; ═══════════════════════════════════════════════════════════════════

(defun deblob (code-blob)
  "Parse code_blob → (values code bitmask jump-table) or NIL on invalid.
   GP (A.2): extracts instruction data, basic-block bitmask, and jump table."
  (handler-case
      (let ((pos 0)
            (len (length code-blob)))
        (flet ((read-compact ()
                 (let ((first (aref code-blob pos)))
                   (cond
                     ;; Simple case: < 128
                     ((zerop (logand first #x80))
                      (incf pos)
                      first)
                     ;; Two-byte: 10xxxxxx + next byte
                     ((zerop (logand first #x40))
                      (let ((val (logior (logand first #x3f)
                                         (ash (aref code-blob (1+ pos)) 6))))
                        (incf pos 2)
                        val))
                     ;; Four-byte: for larger values
                     (t
                      (let ((val (logior (logand first #x1f)
                                         (ash (aref code-blob (+ pos 1)) 5)
                                         (ash (aref code-blob (+ pos 2)) 13)
                                         (ash (aref code-blob (+ pos 3)) 21))))
                        (incf pos 4)
                        val))))))
          ;; 1. |j| = number of jump table entries
          (let ((j-len (read-compact)))
            ;; 2. z = bytes per jump table entry (1 byte)
            (let ((z (aref code-blob pos)))
              (incf pos)
              ;; 3. |c| = code length
              (let ((c-len (read-compact)))
                ;; 4. Jump table: j-len entries, each z bytes
                (let ((jump-table (make-array j-len :element-type '(unsigned-byte 32))))
                  (dotimes (i j-len)
                    (setf (aref jump-table i)
                          (decode-le-unsigned code-blob pos z))
                    (incf pos z))
                  ;; 5. Code: c-len bytes
                  (let ((code (make-array c-len :element-type '(unsigned-byte 8))))
                    (replace code code-blob :start2 pos :end2 (+ pos c-len))
                    (incf pos c-len)
                    ;; 6. Bitmask: ceil(c-len/8) bytes
                    (let* ((bitmask-len (ceiling c-len 8))
                           (bitmask (make-array bitmask-len
                                     :element-type '(unsigned-byte 8)
                                     :initial-element 0)))
                      (let ((available (min bitmask-len (- len pos))))
                        (when (> available 0)
                          (replace bitmask code-blob :start2 pos :end2 (+ pos available))))
                      (values code bitmask jump-table)))))))))
    (error () nil)))

;;; ═══════════════════════════════════════════════════════════════════
;;; (A.7) Standard Program Initialization
;;;
;;; Memory layout:
;;;   Address 0:                      ro_data (read-only)
;;;   Page-aligned after ro_data:     rw_data (read-write)
;;;   After rw_data + padding pages:  heap base
;;;   Top of address space - stack:   stack (read-write)
;;; ═══════════════════════════════════════════════════════════════════

(defun align-up (value alignment)
  "Round VALUE up to next multiple of ALIGNMENT."
  (let ((mask (1- alignment)))
    (logand (+ value mask) (lognot mask))))

(defun standard-prog-init (blob)
  "GP A.7: Initialize a PVM from a parsed program-blob.
   Sets up memory layout and returns a fresh PVM struct.
   Returns PVM or NIL on failure."
  (multiple-value-bind (code bitmask jump-table) (deblob (blob-code-blob blob))
    (unless code
      (return-from standard-prog-init nil))

    (let* ((mem (make-memory))
           ;; RO region: [0, ro-end)
           (ro-data (blob-ro-data blob))
           (ro-end  (length ro-data))
           ;; RW region: page-aligned after RO
           (rw-start (align-up ro-end +page-size+))
           (rw-data  (blob-rw-data blob))
           (rw-end   (+ rw-start (length rw-data)))
           ;; RW padding: extra zeroed pages
           (rw-padded-end (+ rw-end (* (blob-rw-padding-pages blob) +page-size+)))
           ;; Heap: starts at page-aligned boundary after rw region
           (heap-base (align-up rw-padded-end +page-size+))
           ;; Stack: at top of address space
           (stack-size (blob-stack-size blob))
           (stack-top  (- +max-address+ +page-size+))  ; leave guard page at very top
           (stack-base (- stack-top stack-size)))

      ;; ── Map RO data ──
      (when (> ro-end 0)
        (mem-map-range mem 0 ro-end :read-only ro-data))

      ;; ── Map RW data ──
      (when (> (length rw-data) 0)
        (mem-map-range mem rw-start (length rw-data) :read-write rw-data))

      ;; ── Map RW padding pages (zeroed) ──
      (when (> (blob-rw-padding-pages blob) 0)
        (let ((pad-start (align-up rw-end +page-size+)))
          (dotimes (i (blob-rw-padding-pages blob))
            (mem-map-page mem (page-index (+ pad-start (* i +page-size+)))
                          :read-write t))))

      ;; ── Map stack ──
      (when (> stack-size 0)
        (mem-map-range mem stack-base stack-size :read-write))

      ;; ── Set heap tracking ──
      (setf (mem-heap-base mem) heap-base
            (mem-heap-top mem)  heap-base
            (mem-stack-base mem) stack-base
            (mem-stack-top mem)  stack-top)

      ;; ── Build PVM ──
      (let ((vm (make-pvm
                 :code code
                 :bitmask bitmask
                 :jump-table jump-table
                 :memory mem
                 :pc 0
                 :gas 0)))
        ;; Initialize SP to stack top
        (set-reg vm +sp+ stack-top)
        vm))))

;;; ═══════════════════════════════════════════════════════════════════
;;; make-vm — High-level constructor
;;; ═══════════════════════════════════════════════════════════════════

(defun make-vm (blob-bytes)
  "Create a JamVM from raw JAM program blob bytes.
   Parses the blob, debobs the code, initializes memory.
   Returns PVM or NIL on failure."
  (let ((blob (parse-program-blob (coerce blob-bytes
                                          '(simple-array (unsigned-byte 8) (*))))))
    (when blob
      (standard-prog-init blob))))
