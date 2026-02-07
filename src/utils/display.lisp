;;;; utils/display.lisp — REPL display & inspection helpers
;;;;
;;;; NOT protocol logic. Purely for development convenience.

(in-package #:jotl)

;;; ═══════════════════════════════════════════════════════════════
;;; CHAIN DISPLAY
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
