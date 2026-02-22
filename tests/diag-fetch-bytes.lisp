;;;; diag-fetch-bytes.lisp — Dump the raw bytes returned by ΩY kind=14 for a SID
(in-package :jotl)

(let ((trace-dir (merge-pathnames "tests/jamtestvectors/traces/fuzzy/"
                                   (truename "."))))
  (diag-fetch-data trace-dir 45 3953987607))
