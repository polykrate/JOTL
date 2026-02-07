;;;; tests/test-utils.lisp — Shared test utilities
;;;;
;;;; Loaded by all test files. Provides:
;;;;   hex-to-bytes, bytes=, hex=, load-json, load-bin

(in-package :jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; SHARED TEST HELPERS
;;; ═══════════════════════════════════════════════════════════════

(defun hex-to-bytes (hex)
  "Convert 0x-prefixed hex string to byte vector."
  (jam.ffi:hex-string-to-bytes hex))

(defun bytes= (a b)
  "Compare two byte vectors for equality."
  (equalp a b))

(defun hex= (bytes hex-string)
  "Compare byte vector against a 0x-prefixed hex string."
  (bytes= bytes (hex-to-bytes hex-string)))

(defun load-json (path)
  "Load a JSON file and return parsed alist."
  (cl-json:decode-json-from-string (uiop:read-file-string path)))

(defun load-bin (path)
  "Load a binary file into a byte vector."
  (alexandria:read-file-into-byte-vector path))
