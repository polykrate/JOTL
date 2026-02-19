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

(defun read-jam-compact (bytes offset)
  "Read a JAM compact-encoded integer (GP C.5).
   Returns (values value bytes-consumed) or signals error.
   Matches the Rust compact_from() in wire.rs exactly."
  (let* ((first (aref bytes offset))
         (leading-ones (- 8 (integer-length (logxor first #xFF))))
         ;; leading-ones: count of leading 1-bits in first byte
         ;; But we need to handle the case where first = 0xFF specially
         )
    ;; Correct leading-ones calculation:
    ;; Count how many leading 1-bits the byte has.
    (let ((leading-ones
            (cond
              ((= first #xFF) 8)
              (t (loop for i from 7 downto 0
                       while (logbitp i first)
                       count t)))))
      (let ((total (1+ leading-ones)))
        ;; Special case: 0xFF prefix = pure 8-byte LE
        (when (= leading-ones 8)
          (let ((val 0))
            (loop for i from 1 to 8
                  do (setf val (logior val (ash (aref bytes (+ offset i))
                                                (* 8 (1- i))))))
            (return-from read-jam-compact (values val 9))))
        ;; General case
        (let* ((data-bits (max 0 (- 7 leading-ones)))
               (mask (1- (ash 1 data-bits)))
               (rem (logand first mask))
               (low 0))
          (loop for i from 1 below total
                do (setf low (logior low (ash (aref bytes (+ offset i))
                                              (* 8 (1- i))))))
          (values (+ low (ash rem (* 8 leading-ones)))
                  total))))))

(defun read-metadata-length (bytes offset)
  "Read the compact-encoded metadata length. Returns (values length consumed-bytes)."
  (read-jam-compact bytes offset))

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
                             ;; stack_size is in BYTES (not pages), page-aligned
                             :stack-size (align-up stack-sz +page-size+)))))))))))))
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
                 (multiple-value-bind (val consumed)
                     (read-jam-compact code-blob pos)
                   (incf pos consumed)
                   val)))
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
   Sets up memory layout matching PolkaVM's MemoryMap exactly.
   Returns PVM or NIL on failure."
  (multiple-value-bind (code bitmask jump-table) (deblob (blob-code-blob blob))
    (unless code
      (return-from standard-prog-init nil))

    (let* ((mem (make-memory))
           ;; ── Constants matching polkavm-common/abi.rs ──
           (vm-max-page #x10000)                    ; VM_MAX_PAGE_SIZE = 64KB
           (addr-space-bottom vm-max-page)           ; VM_ADDRESS_SPACE_BOTTOM = 0x10000
           (addr-space-top (- +max-address+ vm-max-page)) ; VM_ADDRESS_SPACE_TOP = 0xFFFF0000

           ;; ── RO region: starts at VM_ADDRESS_SPACE_BOTTOM ──
           (ro-data (blob-ro-data blob))
           (ro-start addr-space-bottom)              ; 0x10000
           (ro-data-size (length ro-data))
           (ro-addr-space (align-up ro-data-size vm-max-page)) ; align to 64KB blocks
           (ro-data-aligned (align-up ro-data-size +page-size+))

           ;; ── RW region: after RO + guard gap ──
           ;; address_low = BOTTOM + ro_addr_space + VM_MAX_PAGE (guard)
           (rw-start (+ addr-space-bottom ro-addr-space vm-max-page)) ; e.g. 0x30000
           (rw-data (blob-rw-data blob))
           (rw-data-size (length rw-data))

           ;; ── Heap base: right after RW data ──
           (heap-base (+ rw-start rw-data-size))
           ;; RW data gets page-aligned for address space, heap gets slack
           (rw-data-aligned (align-up rw-data-size +page-size+))
           (rw-addr-space (align-up rw-data-size vm-max-page))
           ;; After rw_data_address_space + guard:
           ;; heap_slack = rw_addr_space - rw_data_size (rest of the aligned space)

           ;; ── Stack: at top of address space ──
           (stack-size (blob-stack-size blob))
           (stack-aligned (align-up stack-size +page-size+))
           (stack-addr-high addr-space-top)           ; 0xFFFF0000
           (stack-addr-low (- stack-addr-high stack-aligned))

           ;; ── Compute actual heap range ──
           ;; max_heap_size includes slack from RW alignment
           (address-low-after-heap (+ addr-space-bottom ro-addr-space vm-max-page
                                      rw-addr-space vm-max-page))
           (heap-slack (- (+ rw-start rw-addr-space) heap-base))
           (max-heap-size (+ (- (- stack-addr-high stack-aligned) address-low-after-heap)
                             heap-slack)))

      ;; ── Map RO data (read-only) ──
      (when (> ro-data-size 0)
        (mem-map-range mem ro-start ro-data-size :read-only ro-data))

      ;; ── Map RW data (read-write) ──
      (when (> rw-data-size 0)
        (mem-map-range mem rw-start rw-data-size :read-write rw-data))

      ;; ── Map RW padding pages (zeroed, read-write) ──
      ;; Padding starts right after RW data (page-aligned)
      (when (> (blob-rw-padding-pages blob) 0)
        (let ((pad-start (align-up (+ rw-start rw-data-size) +page-size+)))
          (dotimes (i (blob-rw-padding-pages blob))
            (mem-map-page mem (page-index (+ pad-start (* i +page-size+)))
                          :read-write t))
          ;; Update heap base to after padding
          (setf heap-base (+ pad-start (* (blob-rw-padding-pages blob) +page-size+)))))

      ;; ── Map stack (read-write) ──
      (when (> stack-aligned 0)
        (mem-map-range mem stack-addr-low stack-aligned :read-write))

      ;; ── Set heap tracking ──
      (setf (mem-heap-base mem) heap-base
            (mem-heap-top mem)  heap-base
            (mem-stack-base mem) stack-addr-low
            (mem-stack-top mem)  stack-addr-high)

      ;; ── Build PVM ──
      (let ((vm (make-pvm
                 :code code
                 :bitmask bitmask
                 :jump-table jump-table
                 :memory mem
                 :pc 0
                 :gas 0)))
        ;; Initialize SP to stack top (matching PolkaVM: stack_address_high)
        (set-reg vm +sp+ stack-addr-high)
        ;; Precompute basic-block starts ω̄ (GP A.5)
        (setf (pvm-basic-blocks vm) (compute-basic-block-starts vm))
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
