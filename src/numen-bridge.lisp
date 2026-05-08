;;;; numen-bridge.lisp — Bridge between JOTL and Numen game logic
;;;;
;;;; Bypasses the PVM for the designated Numen service, routing
;;;; accumulate calls directly to numen:numen-accumulate.
;;;;
;;;; Usage:
;;;;   (asdf:load-system :numen)
;;;;   (asdf:load-system :jotl)
;;;;   (jotl::install-numen-bridge <service-id>)
;;;;
;;;; The bridge wraps accumulate-service: when service-id matches,
;;;; Numen handles it natively (no PVM, no gas metering). Otherwise,
;;;; the original PVM path runs unchanged.

(in-package #:jotl)

;;; ─── Configuration ───────────────────────────────────────────────────

(defvar *numen-service-id* nil
  "When set (integer), accumulate-service bypasses the PVM for this
   service and dispatches to numen:numen-accumulate.")

(defvar *original-accumulate-service* nil
  "Saved reference to the original accumulate-service before wrapping.")

;;; ─── Storage helpers ─────────────────────────────────────────────────

(defun %sexp-to-bytes (sexp)
  "Deterministic sexp → octet vector via PRIN1 + UTF-8."
  (let ((str (with-output-to-string (s)
               (let ((*print-readably* t)
                     (*print-pretty* nil))
                 (prin1 sexp s)))))
    (map '(simple-array (unsigned-byte 8) (*))
         #'char-code str)))

(defun %string-to-bytes (string)
  "String → octet vector (ASCII range, sufficient for our keys)."
  (map '(simple-array (unsigned-byte 8) (*))
       #'char-code string))

;;; ─── Numen accumulate adapter ────────────────────────────────────────

(defun %numen-accumulate-adapter (service-id items gas-limit state
                                  &key (transfer-balance 0) (svc-transfers nil))
  "Translate JOTL accumulate-service args → numen:numen-accumulate.
   Extracts the Numen work-result from the first item's payload."
  (declare (ignore gas-limit svc-transfers))
  (let* ((delta (getf state :delta))
         (svc-data (when delta (funcall delta :service-data service-id)))
         (metadata (when svc-data (getf svc-data :metadata)))
         (balance (+ (or (when metadata (getf metadata :balance)) 0)
                     transfer-balance))
         ;; The work-result is stored under :numen-work-result in the first item.
         ;; In production, this would be deserialized from the work-result payload.
         (work-result (when items
                        (let ((first-item (first items)))
                          (if (listp first-item)
                              (getf first-item :numen-work-result)
                              nil)))))
    (if work-result
        ;; Run Numen's accumulate — pure state application, no graph traversal
        (let ((effects (numen:numen-accumulate work-result)))
          ;; Write the updated Numen world state into delta storage
          (let* ((world-kvs (getf effects :storage))
                 (storage-alist
                   (when world-kvs
                     (mapcar (lambda (pair)
                               (cons (%string-to-bytes (car pair))
                                     (%sexp-to-bytes (cdr pair))))
                             world-kvs))))
            (values (list :outcome 0
                          :balance balance
                          :storage storage-alist
                          :transfers nil)
                    0)))
        ;; No work-result → credit balance only (no-op accumulate)
        (values (list :outcome 0 :balance balance) 0))))

;;; ─── Bridge installation ─────────────────────────────────────────────

(defun install-numen-bridge (service-id)
  "Install the Numen bridge for SERVICE-ID.
   Wraps accumulate-service to bypass PVM when sid matches.
   Idempotent."
  (setf *numen-service-id* service-id)
  (unless *original-accumulate-service*
    (setf *original-accumulate-service* #'accumulate-service))
  (setf (fdefinition 'accumulate-service)
        (lambda (sid items gas-limit state
                 &key (transfer-balance 0) (svc-transfers nil))
          (if (and *numen-service-id* (eql sid *numen-service-id*))
              (%numen-accumulate-adapter sid items gas-limit state
                                        :transfer-balance transfer-balance
                                        :svc-transfers svc-transfers)
              (funcall *original-accumulate-service*
                       sid items gas-limit state
                       :transfer-balance transfer-balance
                       :svc-transfers svc-transfers))))
  (format t "~&[numen-bridge] Installed for service ~D~%" service-id)
  service-id)

(defun uninstall-numen-bridge ()
  "Restore the original accumulate-service."
  (when *original-accumulate-service*
    (setf (fdefinition 'accumulate-service) *original-accumulate-service*
          *original-accumulate-service* nil
          *numen-service-id* nil)
    (format t "~&[numen-bridge] Uninstalled~%"))
  (values))
