;;;; package.lisp
;;;; Package definition for JOTL codec primitives
;;;;
;;;; This follows Common Lisp convention: one package.lisp per package,
;;;; with all exports centralized for easy maintenance and visibility.

(defpackage #:jotl-codec
  (:use #:cl)
  (:documentation "JAM codec primitives for encoding/decoding")
  (:export
   
   ;; ══════════════════════════════════════════════════════════════
   ;; CONSTANTS & SENTINELS
   ;; ══════════════════════════════════════════════════════════════
   
   #:+empty+                    ; Sentinel for optional empty values
   
   ;; ══════════════════════════════════════════════════════════════
   ;; CORE ENCODING/DECODING (C.5 - Variable-Length Integers)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode                     ; Main dispatch function
   #:encode-natural             ; JAM compact integer (C.5)
   #:decode-natural             ; JAM compact integer decoder
   
   ;; ══════════════════════════════════════════════════════════════
   ;; TRIVIAL ENCODINGS (C.2-C.4 - Basic Operations)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode-empty               ; Empty sequence encoding
   #:encode-octet-sequence      ; Direct octet pass-through
   #:encode-tuple               ; Concatenate tuple elements
   #:concat-octets              ; Utility: concatenate octet lists
   
   ;; ══════════════════════════════════════════════════════════════
   ;; SEQUENCES (C.6 - Fixed & Length-Prefixed)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode-sequence            ; Concatenate encoded elements
   #:decode-sequence            ; Decode fixed-count sequence
   #:encode-length-prefixed-sequence  ; ↕[...] with count prefix
   #:decode-length-prefixed-sequence  ; Decode ↕[...] sequences
   #:encode-pre-encoded-sequence      ; Helper: ↕[pre-encoded] (common pattern)
   
   ;; ══════════════════════════════════════════════════════════════
   ;; DISCRIMINATORS (C.7-C.8 - Length & Optional)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode-with-length         ; ↕x - Length-prefixed data
   #:decode-with-length         ; Decode ↕x with length
   #:encode-optional            ; ¿x - Optional discriminator
   #:encode-optional-with       ; ¿x with custom encoder
   #:decode-optional            ; Decode ¿x optionals
   #:encode-discriminated       ; Generic discriminated union
   #:decode-discriminator       ; Read discriminator byte
   
   ;; ══════════════════════════════════════════════════════════════
   ;; BIT SEQUENCES (C.9 - Bitstrings)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode-bit-sequence        ; Raw bitstring encoding
   #:decode-bit-sequence        ; Decode bitstring
   #:encode-bit-sequence-with-length  ; ↕b with length
   #:decode-bit-sequence-with-length  ; Decode ↕b bitstrings
   
   ;; ══════════════════════════════════════════════════════════════
   ;; DICTIONARIES (C.10 - Key-Value Mappings)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode-dictionary          ; Dictionary → sorted pairs
   #:decode-dictionary          ; Decode to hash-table
   #:dict-to-sorted-pairs       ; Utility: sort dict by keys
   #:alist-to-hash              ; Utility: alist → hash-table
   
   ;; ══════════════════════════════════════════════════════════════
   ;; SETS (C.11 - Ordered Sets)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode-set                 ; Set → sorted sequence
   #:decode-set                 ; Decode to set
   #:encode-set-with-length     ; ↕{...} with length
   #:decode-set-with-length     ; Decode ↕{...} sets
   #:sort-set-elements          ; Utility: canonical ordering
   #:jam-make-set               ; Set constructor
   #:jam-set-member-p           ; Set membership test
   #:jam-set-union              ; Set union
   #:jam-set-intersection       ; Set intersection
   #:jam-set-difference         ; Set difference
   
   ;; ══════════════════════════════════════════════════════════════
   ;; FIXED-LENGTH INTEGERS (C.12 - Little-Endian)
   ;; ══════════════════════════════════════════════════════════════
   
   #:encode-fixed-integer       ; Generic fixed-length encoder
   #:decode-fixed-integer       ; Generic fixed-length decoder
   #:e1                         ; 1-byte (8-bit)
   #:e2                         ; 2-byte (16-bit)
   #:e4                         ; 4-byte (32-bit)
   #:e8                         ; 8-byte (64-bit)
   #:encode-e1                  ; Alias for e1 (symmetry)
   #:encode-e2                  ; Alias for e2 (symmetry)
   #:encode-e4                  ; Alias for e4 (symmetry)
   #:encode-e8                  ; Alias for e8 (symmetry)
   #:encode-fixed-tuple         ; Tuple of fixed-length ints
   #:encode-fixed-sequence      ; Sequence of fixed-length ints
   
   ;; ══════════════════════════════════════════════════════════════
   ;; DECODER COMPOSITION (Macros & Helpers)
   ;; ══════════════════════════════════════════════════════════════
   
   #:decode-fixed-bytes         ; Read N bytes exactly
   #:decode-e1                  ; Decode 1-byte integer
   #:decode-e2                  ; Decode 2-byte integer
   #:decode-e4                  ; Decode 4-byte integer
   #:decode-e8                  ; Decode 8-byte integer
   #:decode-hash                ; Decode 32-byte hash
   #:encode-hash                ; Encode hash (identity, for symmetry)
   #:decode>>                   ; Sequential decode pipeline macro
   ))
