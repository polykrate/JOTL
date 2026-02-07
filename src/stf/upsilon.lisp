;;;; stf/upsilon.lisp — Υ(σ, B) → σ'
;;;; Gray Paper §4.1 & §4.2.1
;;;;
;;;; TOP-LEVEL STF — orchestrates all sub-STFs.
;;;; All inputs are closures — no plist dispatch.

(in-package #:jotl)

;;; ═════════════════════════════════════════════════════════════════
;;; Υ — BLOCK-LEVEL STATE TRANSITION (GP §4.1)
;;; ═════════════════════════════════════════════════════════════════

(defun apply-block (sigma block &key current-time parent-header-encoded)
  "Υ(σ, B) → σ' — Block-level state transition.
   
   1. Structural validation (no STF owns)
   2. Pure state transition
   
   Args: sigma (closure), block (closure)"
  (multiple-value-bind (valid-p errors)
      (validate-block sigma block
                      :current-time current-time
                      :parent-header-encoded parent-header-encoded)
    (unless valid-p
      (error "Υ: block invalid — ~{~A~^, ~}"
             (mapcar (lambda (e) (format nil "~A: ~A" (first e) (second e)))
                     errors))))
  (transition-state sigma block))

(defun import-block (sigma block &key current-time parent-header-encoded)
  "Alias for apply-block."
  (apply-block sigma block
               :current-time current-time
               :parent-header-encoded parent-header-encoded))

;;; ═════════════════════════════════════════════════════════════════
;;; transition-state — σ → σ' (GP §4.2.1)
;;; ═════════════════════════════════════════════════════════════════
;;;
;;; Pure composition of sub-STFs in dependency-graph order.
;;; All closures — no (if (functionp ...) ...) dispatch.

(defun transition-state (sigma block)
  "Υ-inner: σ → σ' — Pure state transition.
   
   GP §4.2.1 dependency graph (5 waves).
   Block is a closure from decode-block or make-block."
  (let* ((h (funcall block :header))
         (e (funcall block :extrinsic))
         ;; Extrinsic sub-components (from closures)
         (e-t (funcall e :tickets))
         (e-d (funcall e :disputes))
         (e-p (funcall e :preimages))
         (e-a (funcall e :assurances))
         (e-g (funcall e :guarantees))
         ;; Prior state segments
         (tau          (funcall sigma :tau))
         (eta          (funcall sigma :eta))
         (kappa        (funcall sigma :kappa))
         (lambda-prev  (funcall sigma :lambda))
         (gamma-prev   (funcall sigma :gamma))
         (rho          (funcall sigma :rho))
         (psi          (funcall sigma :psi))
         (beta         (funcall sigma :beta))
         (alpha-prev   (funcall sigma :alpha))
         (delta        (funcall sigma :delta))
         (iota         (funcall sigma :iota))
         (phi          (funcall sigma :phi))
         (chi          (funcall sigma :chi))
         (pi-prev      (funcall sigma :pi))
         (omega        (funcall sigma :omega))
         (xi           (funcall sigma :xi))
         ;; ═══════════════════════════════════════════
         ;; WAVE 1: Independent (σ, H, E only)
         ;; ═══════════════════════════════════════════
         (tau-prime     (apply-timeslot-transition tau h))
         (eta-prime     (transition-eta h tau eta))
         (psi-prime     (transition-psi e-d psi))
         (rho-dagger    (transition-rho-dagger e-d rho))
         (beta-dagger   (transition-beta-dagger h beta))
         ;; ═══════════════════════════════════════════
         ;; WAVE 2
         ;; ═══════════════════════════════════════════
         (kappa-prime   (transition-kappa h tau kappa gamma-prev))
         (lambda-prime  (transition-lambda h tau lambda-prev kappa))
         (rho-ddagger   (transition-rho-ddagger e-a rho-dagger))
         (r-star        (compute-ready-reports e-a rho-dagger))
         ;; ═══════════════════════════════════════════
         ;; WAVE 3
         ;; ═══════════════════════════════════════════
         (rho-prime     (transition-rho e-g rho-ddagger kappa tau-prime))
         (gamma-prime   (transition-gamma h tau e-t gamma-prev
                                          iota eta-prime kappa-prime psi-prime)))
    ;; ═══════════════════════════════════════════
    ;; WAVE 4: Accumulation
    ;; ═══════════════════════════════════════════
    (multiple-value-bind (omega-prime xi-prime delta-ddagger
                          chi-prime iota-prime phi-prime
                          theta-prime s-reports)
        (transition-accumulate r-star omega xi delta chi
                               iota phi tau tau-prime)
      ;; ═══════════════════════════════════════════
      ;; WAVE 5: Merge / Join
      ;; ═══════════════════════════════════════════
      (let* ((beta-prime   (transition-beta h e-g beta-dagger theta-prime))
             (delta-prime  (transition-delta e-p delta-ddagger tau-prime))
             (alpha-prime  (transition-alpha h e-g phi-prime alpha-prev))
             (pi-prime     (transition-pi e-g e-p e-a e-t tau
                                          kappa-prime pi-prev h s-reports)))
        ;; BUILD σ'
        (make-state
         :alpha   alpha-prime
         :beta    beta-prime
         :theta   theta-prime
         :gamma   gamma-prime
         :delta   delta-prime
         :eta     eta-prime
         :iota    iota-prime
         :kappa   kappa-prime
         :lambda* lambda-prime
         :rho     rho-prime
         :tau     tau-prime
         :phi     phi-prime
         :chi     chi-prime
         :psi     psi-prime
         :pi*     pi-prime
         :omega   omega-prime
         :xi      xi-prime)))))

;;; ═════════════════════════════════════════════════════════════════
;;; SUB-STF STUBS — GP §4.2.1 equations
;;; ═════════════════════════════════════════════════════════════════
;;; Each returns prior value (identity). Implement one by one.

(defun transition-eta (header tau eta)
  "GP §4.8 — Entropy. TODO: §7"
  (declare (ignore header tau)) eta)

(defun transition-psi (disputes psi)
  "GP §4.11 — Judgments. TODO: §10"
  (declare (ignore disputes)) psi)

(defun transition-rho-dagger (disputes rho)
  "GP §4.12 — Core assignments after disputes. TODO: §10"
  (declare (ignore disputes)) rho)

;; transition-beta-dagger → stf/beta.lisp

(defun transition-kappa (header tau kappa gamma)
  "GP §4.9 — Validator keys at epoch boundary. TODO: §6"
  (declare (ignore header tau gamma)) kappa)

(defun transition-lambda (header tau lambda-prev kappa)
  "GP §4.10 — Archived keys. TODO: §6"
  (declare (ignore header tau kappa)) lambda-prev)

(defun transition-rho-ddagger (assurances rho-dagger)
  "GP §4.13 — Core assignments after assurances. TODO: §11"
  (declare (ignore assurances)) rho-dagger)

(defun compute-ready-reports (assurances rho-dagger)
  "GP §4.15 — Ready reports. TODO: §11"
  (declare (ignore assurances rho-dagger)) nil)

(defun transition-rho (guarantees rho-ddagger kappa tau-prime)
  "GP §4.14 — Register guarantees. TODO: §11-12"
  (declare (ignore guarantees kappa tau-prime)) rho-ddagger)

(defun transition-gamma (header tau tickets gamma iota eta-prime kappa-prime psi-prime)
  "GP §4.7 — Safrole. TODO: §6"
  (declare (ignore header tau tickets iota eta-prime kappa-prime psi-prime)) gamma)

(defun transition-accumulate (r-star omega xi delta chi iota phi tau tau-prime)
  "GP §4.16 — Accumulation. TODO: §8 + PVM
   Returns: (values ω' ξ' δ‡ χ' ι' ϕ' θ' S)"
  (declare (ignore r-star tau tau-prime))
  (values omega xi delta chi iota phi nil nil))

;; transition-beta → stf/beta.lisp

(defun transition-delta (preimages delta-ddagger tau-prime)
  "GP §4.18 — Services: fold preimages. TODO: §7"
  (declare (ignore preimages tau-prime)) delta-ddagger)

(defun transition-alpha (header guarantees phi-prime alpha)
  "GP §4.19 — Core authorizations. TODO: §13"
  (declare (ignore header guarantees phi-prime)) alpha)

(defun transition-pi (guarantees preimages assurances tickets
                      tau kappa-prime pi-prev header s-reports)
  "GP §4.20 — Validator statistics. TODO: §15"
  (declare (ignore guarantees preimages assurances tickets
                   tau kappa-prime header s-reports))
  pi-prev)
