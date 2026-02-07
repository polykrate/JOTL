;;;; constants.lisp - JAM Protocol Constants (Pure FP with Closures)
;;;; Based on jamtestvectors chainspecs

(in-package #:jotl)

(defparameter *jotl-version* "3.0.0"
  "JOTL version")

;;; ═══════════════════════════════════════════════════════════════
;;; CHAINSPEC DEFINITIONS (from jamtestvectors/README.md)
;;; ═══════════════════════════════════════════════════════════════

#|
Two chainspecs:

TINY (for development and testing):
  - num_validators: 6
  - num_cores: 2
  - Small values for fast iteration

FULL (production, must match Gray Paper):
  - num_validators: 1023
  - num_cores: 341
  - Full scale parameters
|#

(defun make-chainspec (name specs)
  "Creates a chainspec closure
   
   A chainspec is a pure closure that returns protocol constants.
   
   Usage:
   (funcall chainspec :num-validators)  ; => 6 (for tiny)
   (funcall chainspec :name)            ; => :tiny"
  
  (lambda (key)
    (case key
      (:name name)
      (:num-validators (getf specs :num-validators))
      (:num-cores (getf specs :num-cores))
      (:preimage-expunge-period (getf specs :preimage-expunge-period))
      (:slot-duration (getf specs :slot-duration))
      (:epoch-duration (getf specs :epoch-duration))
      (:contest-duration (getf specs :contest-duration))
      (:tickets-per-validator (getf specs :tickets-per-validator))
      (:max-tickets-per-extrinsic (getf specs :max-tickets-per-extrinsic))
      (:rotation-period (getf specs :rotation-period))
      (:num-ec-pieces-per-segment (getf specs :num-ec-pieces-per-segment))
      (:max-block-gas (getf specs :max-block-gas))
      (:max-refine-gas (getf specs :max-refine-gas))
      (:all specs)  ; Return all specs as plist
      (otherwise (error "Unknown chainspec key: ~A" key)))))

;;; Define the two chainspecs

(defparameter +tiny-chainspec+
  (make-chainspec
   :tiny
   '(:num-validators 6
     :num-cores 2
     :preimage-expunge-period 32
     :slot-duration 6
     :epoch-duration 12
     :contest-duration 10
     :tickets-per-validator 3
     :max-tickets-per-extrinsic 3
     :rotation-period 4
     :num-ec-pieces-per-segment 1026
     :max-block-gas 20000000
     :max-refine-gas 1000000000))
  "TINY chainspec - for development and testing")

(defparameter +full-chainspec+
  (make-chainspec
   :full
   '(:num-validators 1023
     :num-cores 341
     :preimage-expunge-period 19200
     :slot-duration 6
     :epoch-duration 600
     :contest-duration 500
     :tickets-per-validator 2
     :max-tickets-per-extrinsic 16
     :rotation-period 10
     :num-ec-pieces-per-segment 6
     :max-block-gas 3500000000
     :max-refine-gas 5000000000))
  "FULL chainspec - production, must match Gray Paper")

;;; ═══════════════════════════════════════════════════════════════
;;; ACTIVE CHAIN (Dynamic, switchable)
;;; ═══════════════════════════════════════════════════════════════

(defvar *chain* +tiny-chainspec+
  "Currently active chainspec (default: tiny)
   
   Switch with: (switch-chain :full)
   Or use with-chain macro for lexical override.")

(defun chain ()
  "Returns the current active chainspec"
  *chain*)

(defun switch-chain (name)
  "Switch the global active chain
   
   Usage:
   (switch-chain :tiny)   ; Development
   (switch-chain :full)   ; Production
   
   Returns: new chainspec"
  (setf *chain*
        (case name
          (:tiny +tiny-chainspec+)
          (:full +full-chainspec+)
          (otherwise (error "Unknown chain: ~A (use :tiny or :full)" name))))
  (format t "~&Switched to ~A chain~%" name)
  *chain*)

(defmacro with-chain (name &body body)
  "Execute body with a specific chainspec
   
   Usage:
   (with-chain :full
     (num-validators))  ; Uses full chainspec
   
   Does not affect global *chain*"
  `(let ((*chain* (case ,name
                    (:tiny +tiny-chainspec+)
                    (:full +full-chainspec+)
                    (otherwise (error "Unknown chain: ~A" ,name)))))
     ,@body))

;;; ═══════════════════════════════════════════════════════════════
;;; CONVENIENT ACCESSORS (use current *chain*)
;;; ═══════════════════════════════════════════════════════════════

(defun num-validators ()
  "Number of validators in current chain"
  (funcall *chain* :num-validators))

(defun num-cores ()
  "Number of cores in current chain"
  (funcall *chain* :num-cores))

(defun slot-duration ()
  "Slot duration in seconds (always 6)"
  (funcall *chain* :slot-duration))

(defun epoch-duration ()
  "Epoch duration in timeslots"
  (funcall *chain* :epoch-duration))

(defun max-block-gas ()
  "Maximum gas per block"
  (funcall *chain* :max-block-gas))

(defun max-refine-gas ()
  "Maximum gas for refine operation"
  (funcall *chain* :max-refine-gas))

(defun preimage-expunge-period ()
  "Preimage expunge period in timeslots"
  (funcall *chain* :preimage-expunge-period))

(defun contest-duration ()
  "Contest duration in timeslots"
  (funcall *chain* :contest-duration))

(defun tickets-per-validator ()
  "Number of tickets per validator"
  (funcall *chain* :tickets-per-validator))

(defun max-tickets-per-extrinsic ()
  "Maximum tickets per extrinsic"
  (funcall *chain* :max-tickets-per-extrinsic))

(defun rotation-period ()
  "Rotation period in epochs"
  (funcall *chain* :rotation-period))

(defun num-ec-pieces-per-segment ()
  "Number of erasure coding pieces per segment"
  (funcall *chain* :num-ec-pieces-per-segment))

;;; ═══════════════════════════════════════════════════════════════
;;; DISPLAY / INSPECTION
;;; ═══════════════════════════════════════════════════════════════

(defun show-chain-config ()
  "Display current chain configuration"
  (format t "~%╔═══════════════════════════════════════════════╗~%")
  (format t "║  JAM CHAIN CONFIGURATION                     ║~%")
  (format t "╚═══════════════════════════════════════════════╝~%~%")
  (format t "Chain: ~A~%~%" (funcall *chain* :name))
  (format t "Validators:              ~10D~%" (num-validators))
  (format t "Cores:                   ~10D~%" (num-cores))
  (format t "Slot duration:           ~10D seconds~%" (slot-duration))
  (format t "Epoch duration:          ~10D timeslots~%" (epoch-duration))
  (format t "Contest duration:        ~10D timeslots~%" (contest-duration))
  (format t "Preimage expunge:        ~10D timeslots~%" (preimage-expunge-period))
  (format t "Tickets per validator:   ~10D~%" (tickets-per-validator))
  (format t "Max tickets/extrinsic:   ~10D~%" (max-tickets-per-extrinsic))
  (format t "Rotation period:         ~10D epochs~%" (rotation-period))
  (format t "EC pieces per segment:   ~10D~%" (num-ec-pieces-per-segment))
  (format t "Max block gas:           ~10D~%" (max-block-gas))
  (format t "Max refine gas:          ~10D~%~%" (max-refine-gas)))

(defun compare-chains ()
  "Compare tiny and full chainspecs"
  (format t "~%╔═════════════════════════════════════════════════════════════╗~%")
  (format t "║  CHAINSPEC COMPARISON: TINY vs FULL                        ║~%")
  (format t "╚═════════════════════════════════════════════════════════════╝~%~%")
  (format t "~40A ~12A ~12A~%" "Parameter" "TINY" "FULL")
  (format t "~40A ~12A ~12A~%" (make-string 40 :initial-element #\-) 
          (make-string 12 :initial-element #\-) 
          (make-string 12 :initial-element #\-))
  
  (labels ((show-param (name key)
             (format t "~40A ~12D ~12D~%" 
                     name
                     (funcall +tiny-chainspec+ key)
                     (funcall +full-chainspec+ key))))
    
    (show-param "Validators" :num-validators)
    (show-param "Cores" :num-cores)
    (show-param "Slot duration (seconds)" :slot-duration)
    (show-param "Epoch duration (timeslots)" :epoch-duration)
    (show-param "Contest duration (timeslots)" :contest-duration)
    (show-param "Preimage expunge (timeslots)" :preimage-expunge-period)
    (show-param "Tickets per validator" :tickets-per-validator)
    (show-param "Max tickets per extrinsic" :max-tickets-per-extrinsic)
    (show-param "Rotation period (epochs)" :rotation-period)
    (show-param "EC pieces per segment" :num-ec-pieces-per-segment)
    (show-param "Max block gas" :max-block-gas)
    (show-param "Max refine gas" :max-refine-gas))
  
  (format t "~%"))

;;; ═══════════════════════════════════════════════════════════════
;;; PROTOCOL CONSTANTS — Fixed values from Gray Paper
;;; ═══════════════════════════════════════════════════════════════

(defparameter +zero-hash+
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
  "H0 — the zero hash (32 bytes of 0x00). GP notation: ∅ for hashes.")

(defparameter +mmr-peak-prefix+
  (map '(vector (unsigned-byte 8)) #'char-code "peak")
  "The 'peak' prefix used in MMR super-peak computation (GP E.11).")

;;; ═══════════════════════════════════════════════════════════════
;;; EXAMPLES
;;; ═══════════════════════════════════════════════════════════════

#|
Usage examples:

;; Default chain (tiny)
(num-validators)  ; => 6

;; Switch to full
(switch-chain :full)
(num-validators)  ; => 1023

;; Temporary override
(with-chain :tiny
  (num-validators))  ; => 6

;; Show config
(show-chain-config)

;; Compare
(compare-chains)

Code is Law - Pure FP Constants ! 🚀
|#
