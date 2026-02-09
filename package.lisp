;;;; package.lisp — Single source of truth for JOTL exports
;;;;
;;;; ALL exports are declared here. No (export ...) in source files.
;;;; Clean rebuild: only exports for active code (not archive/).

(defpackage #:jotl
  (:use #:cl #:alexandria)
  (:import-from #:jam.ffi
                #:blake2b-256
                #:keccak-256
                #:hex-string-to-bytes
                #:bytes-to-hex-string
                #:compute-core-assignments)
  (:documentation "JAM On The Lisp — State Transition Machine")
  (:export
   ;; ═══════════════════════════════════════════
   ;; Lib — Macros
   ;; ═══════════════════════════════════════════
   #:define-value-object
   #:define-state-closure
   #:*state-decoders*
   #:register-state-decoder
   #:decode-state-segment
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Constants
   ;; ═══════════════════════════════════════════
   #:*chain*
   #:chain
   #:switch-chain
   #:with-chain
   #:num-validators
   #:num-cores
   #:slot-duration
   #:epoch-duration
   #:max-block-gas
   #:max-refine-gas
   #:preimage-expunge-period
   #:contest-duration
   #:tickets-per-validator
   #:max-tickets-per-extrinsic
   #:rotation-period
   #:num-ec-pieces-per-segment
   ;; Protocol constants (GP I.4.4)
   #:+zero-hash+ #:+mmr-peak-prefix+
   #:+history-size+ #:+availability-timeout+
   #:+max-work-items+ #:+max-dependencies+
   #:+max-lookup-anchor-age+ #:+max-auth-pool+ #:+auth-queue-size+
   #:+min-service-index+ #:+max-work-package-extrinsics+
   #:+accumulation-gas+ #:+is-authorized-gas+
   #:+min-balance+ #:+min-balance-per-item+ #:+min-balance-per-octet+
   #:+audit-tranche-period+ #:+audit-bias-factor+
   #:+max-is-authorized-code+ #:+max-service-code+
   #:+erasure-piece-size+ #:+segment-size+
   #:+max-imports+ #:+max-exports+
   #:+max-unbounded-blob-size+ #:+transfer-memo-size+
   #:+pvm-address-alignment+ #:+pvm-init-data-size+
   #:+pvm-page-size+ #:+pvm-init-zone-size+
   ;; Validator key sizes (GP §6.9-6.12)
   #:+bandersnatch-key-size+ #:+ed25519-key-size+
   #:+bls-key-size+ #:+metadata-size+ #:+validator-key-size+
   ;; Context strings X (GP I.4.5)
   #:+ctx-available+     ;; XA
   #:+ctx-beefy+         ;; XB
   #:+ctx-entropy+       ;; XE
   #:+ctx-fallback-seal+ ;; XF
   #:+ctx-guarantee+     ;; XG
   #:+ctx-announce+      ;; XI
   #:+ctx-ticket-seal+   ;; XT
   #:+ctx-audit+         ;; XU
   #:+ctx-valid+         ;; X⊤
   #:+ctx-invalid+       ;; X⊥
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Codec Primitives (GP Appendix C)
   ;; ═══════════════════════════════════════════
   #:encode-fixed-le #:decode-fixed-le
   #:E1 #:E2 #:E4 #:E8
   #:encode-u8 #:encode-u16 #:encode-u32 #:encode-u64
   #:decode-u8 #:decode-u16 #:decode-u32 #:decode-u64
   #:encode-compact #:decode-compact
   #:encode-sequence #:decode-sequence
   #:encode-option #:decode-option
   #:ensure-bytes
   
   ;; ═══════════════════════════════════════════
   ;; Lib — State Keys (GP Appendix D)
   ;; ═══════════════════════════════════════════
   #:state-key #:service-key #:state-key-for-segment
   #:+C1+ #:+C2+ #:+C3+ #:+C4+ #:+C5+ #:+C6+ #:+C7+ #:+C8+
   #:+C9+ #:+C10+ #:+C11+ #:+C12+ #:+C13+ #:+C14+ #:+C15+ #:+C16+
   #:+state-key-names+
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Codec Types
   ;; ═══════════════════════════════════════════
   #:bytes<
   #:encode-auth-pools
   #:encode-hash-32 #:decode-hash-32
   #:encode-ed25519-key #:decode-ed25519-key
   #:encode-bandersnatch-key #:decode-bandersnatch-key
   #:encode-signature-96 #:decode-signature-96
   #:encode-validator #:decode-validator
   #:encode-validator-sequence #:decode-validator-sequence
   #:encode-full-validator #:decode-full-validator
   #:encode-full-validator-sequence #:decode-full-validator-sequence
   #:encode-service-account-index #:decode-service-account-index
   #:encode-validator-index #:decode-validator-index
   
   ;; ═══════════════════════════════════════════
   ;; Lib — Merkle Trie
   ;; ═══════════════════════════════════════════
   #:trie-bit #:trie-branch #:trie-leaf
   #:merkle-root #:compute-state-root #:pad-key-to-32
   #:+sigma-segment-keys+
   #:merklize-state #:validate-state-root
   
   ;; ═══════════════════════════════════════════
   ;; Lib — MMR (GP Appendix E)
   ;; ═══════════════════════════════════════════
   #:mmr-merge
   #:mmr-super-peak
   #:mmr-append
   #:mmr-leaf-count
   #:mmr-from-leaves
   #:binary-merkle-root-keccak
   
   ;; ═══════════════════════════════════════════
   ;; State — σ overall (GP §4.4)
   ;; ═══════════════════════════════════════════
   #:make-state #:make-genesis-state
   
   ;; ═══════════════════════════════════════════
   ;; State — τ Timeslot (GP §6.1-6.2)
   ;; ═══════════════════════════════════════════
   #:make-tau-state
   #:tau-state-slot
   
   ;; ═══════════════════════════════════════════
   ;; State — η Entropy (GP §6.21-6.23)
   ;; ═══════════════════════════════════════════
   #:make-eta-state
   
   ;; ═══════════════════════════════════════════
   ;; State — κ Current Validators (GP §6.15)
   ;; ═══════════════════════════════════════════
   #:make-kappa-state
   
   ;; ═══════════════════════════════════════════
   ;; State — λ Archived Validators (GP §6.16)
   ;; ═══════════════════════════════════════════
   #:make-lambda-state
   
   ;; ═══════════════════════════════════════════
   ;; Υ — Orchestrator (GP §4.1)
   ;; ═══════════════════════════════════════════
   #:transition-state
   #:apply-block
   
   ;; ═══════════════════════════════════════════
   ;; Crypto (re-exported from jam.ffi)
   ;; ═══════════════════════════════════════════
   #:blake2b-256 #:keccak-256
   #:hex-string-to-bytes #:bytes-to-hex-string
   
   ;; Version
   #:*jotl-version*))
