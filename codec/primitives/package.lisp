;;;; package.lisp
;;;; Package definition for JOTL codec primitives

(defpackage #:jotl-codec
  (:use #:cl)
  (:documentation "JAM codec primitives for encoding/decoding")
  (:export
   ;; Constants
   #:+empty+
   
   ;; Main encode/decode
   #:encode
   #:decode-natural
   
   ;; Trivial encodings
   #:encode-empty
   #:encode-octet-sequence
   #:encode-tuple
   #:encode-natural
   #:concat-octets
   
   ;; Sequence encoding (C.6)
   #:encode-sequence
   #:decode-sequence
   #:encode-length-prefixed-sequence
   #:decode-length-prefixed-sequence
   
   ;; Discriminator encoding (C.7-C.8)
   #:encode-with-length
   #:decode-with-length
   #:encode-optional
   #:decode-optional
   #:encode-discriminated
   #:decode-discriminator
   
   ;; Bit sequence encoding (C.9)
   #:encode-bit-sequence
   #:decode-bit-sequence
   #:encode-bit-sequence-with-length
   #:decode-bit-sequence-with-length
   
   ;; Dictionary encoding (C.10)
   #:encode-dictionary
   #:decode-dictionary
   #:dict-to-sorted-pairs
   #:alist-to-hash
   
   ;; Set encoding (C.11)
   #:encode-set
   #:decode-set
   #:encode-set-with-length
   #:decode-set-with-length
   #:sort-set-elements
   #:jam-make-set
   #:jam-set-member-p
   #:jam-set-union
   #:jam-set-intersection
   #:jam-set-difference
   
   ;; Fixed-length integer encoding
   #:encode-fixed-integer
   #:decode-fixed-integer
   #:e1
   #:e2
   #:e4
   #:e8
   #:encode-fixed-tuple
   #:encode-fixed-sequence
   
   ;; Decoder macros (composition)
   #:decode-fixed-bytes
   #:decode-e1
   #:decode-e2
   #:decode-e4
   #:decode-e8
   #:decode-hash
   #:decode>>))
