;;;; memory.lisp — GP A.1 Memory model (μ)
;;;;
;;;; Page-based RAM with access control and gas-tracked allocation.
;;;; Each page is Z_P = 4096 bytes. Pages can be:
;;;;   :inaccessible  — not mapped (access → page fault ∃)
;;;;   :read-only     — mapped RO (write → page fault ∃)
;;;;   :read-write    — mapped RW
;;;;
;;;; Memory layout (GP A.7):
;;;;   [0, |c_ro|)                          → ro_data (read-only)
;;;;   [ro_end, ro_end+|c_rw|)             → rw_data (read-write)
;;;;   [rw_end, rw_end+rw_padding*Z_P)     → rw padding (read-write, zeroed)
;;;;   [heap_base, heap_top)                → heap (grows up via sbrk)
;;;;   [stack_base, stack_top)              → stack (grows down)
;;;;
;;;; This implementation uses a hash-table of page-index → page-data
;;;; for sparse memory. Only touched pages consume host memory.

(in-package #:jamvm)

;;; ═══════════════════════════════════════════════════════════════════
;;; Page access modes
;;; ═══════════════════════════════════════════════════════════════════

;; Using keywords for clarity. Could be integers for speed later.
;; :inaccessible = default (not in hash table)
;; :read-only    = can read, write → fault
;; :read-write   = can read and write

;;; ═══════════════════════════════════════════════════════════════════
;;; Memory struct
;;; ═══════════════════════════════════════════════════════════════════

(defstruct (memory (:conc-name mem-))
  "Page-based guest memory (GP A.1: μ).
   Pages are 4096 bytes, indexed by page number (address / Z_P).
   Access modes tracked per page. Unallocated pages are :inaccessible."
  ;; page-index → (simple-array (unsigned-byte 8) (4096))
  (pages   (make-hash-table :test 'eql) :type hash-table)
  ;; page-index → :read-only | :read-write
  (access  (make-hash-table :test 'eql) :type hash-table)
  ;; Heap tracking
  (heap-base 0 :type (unsigned-byte 32))  ; start of heap region
  (heap-top  0 :type (unsigned-byte 32))  ; current sbrk pointer
  ;; Stack region
  (stack-base 0 :type (unsigned-byte 32)) ; bottom of stack region
  (stack-top  0 :type (unsigned-byte 32))) ; initial SP (top of stack)

;;; ═══════════════════════════════════════════════════════════════════
;;; Page helpers
;;; ═══════════════════════════════════════════════════════════════════

(declaim (inline page-index page-offset))

(defun page-index (address)
  "Page number for ADDRESS: ⌊address / Z_P⌋."
  (ash address -12))  ; / 4096

(defun page-offset (address)
  "Offset within page for ADDRESS: address mod Z_P."
  (logand address #xFFF))

(defun page-access (mem page-idx)
  "Get access mode for page PAGE-IDX. Returns :inaccessible if unmapped."
  (gethash page-idx (mem-access mem) :inaccessible))

(defun (setf page-access) (mode mem page-idx)
  "Set access mode for page PAGE-IDX."
  (setf (gethash page-idx (mem-access mem)) mode))

(defun ensure-page (mem page-idx)
  "Return the page data array for PAGE-IDX, creating if needed."
  (or (gethash page-idx (mem-pages mem))
      (let ((page (make-array +page-size+
                    :element-type '(unsigned-byte 8)
                    :initial-element 0)))
        (setf (gethash page-idx (mem-pages mem)) page)
        page)))

(defun page-mapped-p (mem page-idx)
  "True if page PAGE-IDX is mapped (not :inaccessible)."
  (not (eq :inaccessible (page-access mem page-idx))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Read / Write — byte-level
;;;
;;; Returns (values data t) on success, (values nil address) on fault.
;;; The fault address is the first byte that caused the fault.
;;; ═══════════════════════════════════════════════════════════════════

(defun mem-read (mem address length)
  "Read LENGTH bytes from guest memory at ADDRESS.
   Returns (values byte-vector T) on success,
           (values NIL fault-address) on page fault."
  (let ((result (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length (values result t))
      (let* ((addr (+ address i))
             (pidx (page-index addr))
             (poff (page-offset addr)))
        ;; Check page is readable
        (let ((mode (page-access mem pidx)))
          (when (eq mode :inaccessible)
            (return-from mem-read (values nil addr))))
        ;; Read byte
        (let ((page (gethash pidx (mem-pages mem))))
          (if page
              (setf (aref result i) (aref page poff))
              (setf (aref result i) 0)))))))  ; mapped but no data → 0

(defun mem-write (mem address data)
  "Write DATA (byte vector) to guest memory at ADDRESS.
   ATOMIC: checks ALL pages before writing any byte (GP A.8).
   Returns (values T T) on success,
           (values NIL fault-address) on page fault."
  (let ((len (length data)))
    ;; Phase 1: validate ALL pages are writable
    (dotimes (i len)
      (let* ((addr (+ address i))
             (pidx (page-index addr))
             (mode (page-access mem pidx)))
        (when (or (eq mode :inaccessible) (eq mode :read-only))
          (return-from mem-write (values nil addr)))))
    ;; Phase 2: all pages verified — commit writes
    (dotimes (i len (values t t))
      (let* ((addr (+ address i))
             (pidx (page-index addr))
             (poff (page-offset addr))
             (page (ensure-page mem pidx)))
        (setf (aref page poff) (aref data i))))))

;;; ═══════════════════════════════════════════════════════════════════
;;; Typed read/write helpers (little-endian)
;;; ═══════════════════════════════════════════════════════════════════

(defun mem-read-u8 (mem addr)
  "Read unsigned 8-bit from guest memory. Returns (values val ok)."
  (multiple-value-bind (data ok) (mem-read mem addr 1)
    (if ok (values (aref data 0) t) (values 0 nil))))

(defun mem-read-u16 (mem addr)
  "Read unsigned 16-bit LE from guest memory."
  (multiple-value-bind (data ok) (mem-read mem addr 2)
    (if ok
        (values (logior (aref data 0) (ash (aref data 1) 8)) t)
        (values 0 nil))))

(defun mem-read-u32 (mem addr)
  "Read unsigned 32-bit LE from guest memory."
  (multiple-value-bind (data ok) (mem-read mem addr 4)
    (if ok
        (values (logior (aref data 0)
                        (ash (aref data 1) 8)
                        (ash (aref data 2) 16)
                        (ash (aref data 3) 24))
                t)
        (values 0 nil))))

(defun mem-read-u64 (mem addr)
  "Read unsigned 64-bit LE from guest memory."
  (multiple-value-bind (data ok) (mem-read mem addr 8)
    (if ok
        (let ((val 0))
          (dotimes (i 8)
            (setf val (logior val (ash (aref data i) (* 8 i)))))
          (values val t))
        (values 0 nil))))

(defun mem-write-u8 (mem addr val)
  (mem-write mem addr (make-array 1 :element-type '(unsigned-byte 8)
                                    :initial-contents (list (logand val #xFF)))))

(defun mem-write-u16 (mem addr val)
  (mem-write mem addr (make-array 2 :element-type '(unsigned-byte 8)
                                    :initial-contents
                                    (list (logand val #xFF)
                                          (logand (ash val -8) #xFF)))))

(defun mem-write-u32 (mem addr val)
  (let ((buf (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref buf i) (logand (ash val (* -8 i)) #xFF)))
    (mem-write mem addr buf)))

(defun mem-write-u64 (mem addr val)
  (let ((buf (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8) (setf (aref buf i) (logand (ash val (* -8 i)) #xFF)))
    (mem-write mem addr buf)))

;;; ═══════════════════════════════════════════════════════════════════
;;; Page allocation / mapping
;;; ═══════════════════════════════════════════════════════════════════

(defun mem-map-page (mem page-idx mode &optional zero-fill)
  "Map a page with the given access MODE (:read-only or :read-write).
   If ZERO-FILL, ensure page data exists (zeroed)."
  (setf (page-access mem page-idx) mode)
  (when zero-fill
    (ensure-page mem page-idx)))

(defun mem-map-range (mem start-addr length mode &optional data)
  "Map a byte range [START-ADDR, START-ADDR+LENGTH) with MODE.
   If DATA is provided, write it into the mapped region."
  (let ((first-page (page-index start-addr))
        (last-page  (page-index (+ start-addr (max 1 length) -1))))
    ;; Map all pages in range
    (loop for pidx from first-page to last-page
          do (mem-map-page mem pidx mode t))
    ;; Write data if provided
    (when data
      (dotimes (i (min length (length data)))
        (let* ((addr (+ start-addr i))
               (pidx (page-index addr))
               (poff (page-offset addr))
               (page (ensure-page mem pidx)))
          (setf (aref page poff) (aref data i)))))))

(defun mem-sbrk (mem size)
  "Advance heap pointer by SIZE bytes. Returns old heap_top.
   Also returns the list of newly-crossed page indices that need gas charging.
   Returns (values old-top new-pages-list)."
  (when (zerop size)
    (return-from mem-sbrk (values (mem-heap-top mem) nil)))
  (let* ((old-top (mem-heap-top mem))
         (new-top (u32 (+ old-top size)))
         ;; Pages that need allocation
         (old-page (page-index (if (zerop old-top) 0 (1- old-top))))
         (new-page (page-index (1- new-top)))
         (new-pages nil))
    ;; Find pages that are newly crossed
    (loop for pidx from (if (zerop old-top) (page-index old-top) (1+ old-page))
          to new-page
          unless (page-mapped-p mem pidx)
          do (push pidx new-pages)
             (mem-map-page mem pidx :read-write t))
    (setf (mem-heap-top mem) new-top)
    (values old-top (nreverse new-pages))))

(defun mem-page-count (mem)
  "Number of mapped pages."
  (hash-table-count (mem-pages mem)))
