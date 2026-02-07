;;;; stf/rho.lisp — ρ (Core Assignments / Availability)
;;;; Gray Paper §10 (ρ†), §11 (ρ‡), §11-12 (ρ')
;;;;
;;;; Three transformations on ρ across the waves:
;;;;   WAVE 1: ρ† = transition-rho-dagger(ED, ρ)    — disputes invalidate assignments
;;;;   WAVE 2: ρ‡ = transition-rho-ddagger(EA, ρ†)   — assurances mark availability
;;;;   WAVE 3: ρ' = transition-rho(EG, ρ‡, κ, τ')    — guarantees register new reports

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; WAVE 1: ρ† — ASSIGNMENTS AFTER DISPUTES (GP §10)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-rho-dagger (disputes rho)
  "GP §10 — Invalidate availability assignments for bad verdicts.
   ρ† = ρ with entries nullified where work-report matches a bad verdict.

   Args: disputes (plist), rho (list of assignment-or-nil)
   Returns: ρ†"
  (let* ((verdicts (getf disputes :verdicts))
         ;; Find bad verdict targets
         (bad-targets
           (loop for v in verdicts
                 when (eq (classify-verdict v) :bad)
                 collect (getf v :target))))
    (if (null bad-targets)
        rho ;; No bad verdicts, ρ unchanged
        ;; STUB — TODO: for each ρ entry, if its work-report hash
        ;; matches a bad verdict target, set to nil
        (mapcar (lambda (assignment)
                  (if (and assignment
                           (let ((report-hash
                                   ;; STUB — TODO: extract work-report hash from assignment
                                   (getf assignment :report-hash)))
                             (member-hash report-hash bad-targets)))
                      nil
                      assignment))
                rho))))

;;; ═════════════════════════════════════════════════════════════════
;;; WAVE 2: ρ‡ — ASSIGNMENTS AFTER ASSURANCES (GP §11)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-rho-ddagger (assurances rho-dagger)
  "GP §11 — Mark availability from assurances. STUB"
  (declare (ignore assurances)) rho-dagger)

(defun compute-ready-reports (assurances rho-dagger)
  "GP §11 — Ready reports (sufficient assurances). STUB"
  (declare (ignore assurances rho-dagger)) nil)

;;; ═════════════════════════════════════════════════════════════════
;;; WAVE 3: ρ' — REGISTER GUARANTEES (GP §11-12)
;;; ═════════════════════════════════════════════════════════════════

(defun transition-rho (guarantees rho-ddagger kappa tau-prime)
  "GP §11-12 — Register guaranteed work-reports. STUB"
  (declare (ignore guarantees kappa tau-prime)) rho-ddagger)

;;; Exports managed in package.lisp
