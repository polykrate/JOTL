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

(defun transition-rho-dagger (v-list rho)
  "(10.15) ρ†[c] = ∅ if (H(ρ[c]r), t) ∈ v, t < ⌊⅔V⌋ ; ρ[c] otherwise
   Clear cores whose work-report was judged invalid (bad) or uncertain (wonky).
   Good verdicts (t = ⌊2V/3⌋+1) do NOT clear assignments.

   Args: v-list — list of (target . positive-count) from (10.12)
         rho — vector/list of core assignments (nil or plist with :report-hash)
   Returns: ρ† (same structure, with invalidated cores set to nil)"
  ;; Collect targets with t < ⌊2V/3⌋ (bad or wonky, not good)
  (let ((invalidated-targets
          (loop for (target . pos-count) in v-list
                when (< pos-count (floor (* 2 (num-validators)) 3))
                collect target)))
    (if (null invalidated-targets)
        rho
        (mapcar (lambda (assignment)
                  (if (and assignment
                           (let ((report-hash (getf assignment :report-hash)))
                             (and report-hash
                                  (member-hash report-hash invalidated-targets))))
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
