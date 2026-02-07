;;;; closure-demo.lisp - Démonstration interactive des closures JOTL

(format t "~%~%═══════════════════════════════════════════════════════════~%")
(format t "  JOTL - Démonstration des Closures et Pure FP~%")
(format t "═══════════════════════════════════════════════════════════~%~%")

;;; ==========================================================================
;;; NIVEAU 1 : Valeurs Simples (Pas de Closures)
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Niveau 1 : Valeurs Simples (τ = timeslot)              │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

;; τ est juste un nombre
(defparameter *tau* 42)
(format t "τ = ~D~%" *tau*)

;; Opérations = fonctions pures
(defun my-timeslot-epoch (tau)
  "Calcule l'époque (division par 12)"
  (floor tau 12))

(format t "Époque = floor(~D / 12) = ~D~%~%" *tau* (my-timeslot-epoch *tau*))

;;; ==========================================================================
;;; NIVEAU 2 : Pure Functions (Transformations)
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Niveau 2 : Pure Functions (Codec)                      │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(defun my-encode-u32 (value)
  "Encode u32 en little-endian (pure function)"
  (let ((result (make-array 4 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 4
          do (setf (aref result i) (ldb (byte 8 (* 8 i)) value)))
    result))

(defparameter *encoded* (my-encode-u32 42))
(format t "encode-u32(42) = ~A~%" *encoded*)
(format t "  → Toujours le même résultat (pure)~%")
(format t "  → Pas d'état caché~%")
(format t "  → Input → Output~%~%")

;;; ==========================================================================
;;; NIVEAU 3 : Closures (Données Complexes)
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Niveau 3 : Closures (Header)                           │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

;; Exemple simplifié de header
(defun my-make-header (&key parent-hash slot)
  "Crée un header comme une closure"
  (lambda (msg)
    (case msg
      (:parent-hash parent-hash)
      (:slot slot)
      (:is-genesis (null parent-hash))
      (:info (format nil "Header(slot=~D, genesis=~A)" 
                     slot (null parent-hash))))))

;; Créer un header
(format t "Création d'un header...~%")
(defparameter *my-header*
  (my-make-header :parent-hash #(1 2 3 4)
                  :slot 42))

(format t "  *my-header* est une FONCTION (closure)~%~%")

;; Accéder aux champs
(format t "Accès aux champs (via funcall):~%")
(format t "  (funcall *my-header* :slot)       => ~D~%" 
        (funcall *my-header* :slot))
(format t "  (funcall *my-header* :parent-hash) => ~A~%" 
        (funcall *my-header* :parent-hash))
(format t "  (funcall *my-header* :is-genesis)  => ~A~%" 
        (funcall *my-header* :is-genesis))
(format t "  (funcall *my-header* :info)        => ~A~%~%" 
        (funcall *my-header* :info))

;;; ==========================================================================
;;; COMPARAISON : OOP vs FP
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Comparaison : OOP (mutation) vs FP (immutabilité)      │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

;; Style OOP (avec defstruct - mutation possible)
(defstruct account-oop
  balance)

(defun oop-deposit (account amount)
  "MUTATION : modifie l'account"
  (incf (account-oop-balance account) amount))

(format t "Style OOP (mutation):~%")
(defparameter *acc-oop* (make-account-oop :balance 100))
(format t "  Balance initiale: ~D~%" (account-oop-balance *acc-oop*))
(oop-deposit *acc-oop* 50)
(format t "  Après deposit:    ~D~%" (account-oop-balance *acc-oop*))
(format t "  ❌ L'objet original a été MODIFIÉ~%~%")

;; Style FP (avec closure - immutabilité)
(defun fp-make-account (balance)
  "Crée un account immutable (closure)"
  (lambda (msg &optional arg)
    (case msg
      (:balance balance)
      (:deposit (fp-make-account (+ balance arg)))  ; NOUVEAU account
      (:info (format nil "Account(~D)" balance)))))

(format t "Style FP (immutabilité):~%")
(defparameter *acc-fp* (fp-make-account 100))
(format t "  Balance initiale: ~D~%" (funcall *acc-fp* :balance))
(defparameter *acc-fp-2* (funcall *acc-fp* :deposit 50))
(format t "  Nouveau account:  ~D~%" (funcall *acc-fp-2* :balance))
(format t "  Original intact:  ~D~%" (funcall *acc-fp* :balance))
(format t "  ✅ L'objet original est IMMUTABLE~%~%")

;;; ==========================================================================
;;; LAZY EVALUATION
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Lazy Evaluation (Calculs à la demande)                 │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(defun my-make-expensive-header (&key data)
  "Header avec calcul coûteux (lazy)"
  (lambda (msg)
    (case msg
      (:data data)
      (:expensive-hash
       (progn
         (format t "    → Calcul du hash (coûteux)...~%")
         (sleep 0.1)  ; Simule calcul
         (format t "    → Hash calculé !~%")
         #(42 42 42 42))))))  ; Hash simulé

(format t "Création du header (hash pas encore calculé)...~%")
(defparameter *lazy-header* (my-make-expensive-header :data #(1 2 3)))
(format t "  ✓ Header créé~%~%")

(format t "Premier accès au data (rapide):~%")
(funcall *lazy-header* :data)
(format t "  ✓ Data récupéré instantanément~%~%")

(format t "Premier accès au hash (déclenche le calcul):~%")
(funcall *lazy-header* :expensive-hash)
(format t "  ✓ Hash calculé seulement maintenant~%~%")

;;; ==========================================================================
;;; COMPOSITION
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Composition (Block = Header + Extrinsic)               │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(defun my-make-extrinsic (&key tickets disputes)
  "Crée un extrinsic (closure)"
  (lambda (msg)
    (case msg
      (:tickets tickets)
      (:disputes disputes)
      (:count (+ (length tickets) (length disputes))))))

(defun my-make-block (header extrinsic)
  "Compose header + extrinsic → block"
  (lambda (msg)
    (case msg
      (:header header)
      (:extrinsic extrinsic)
      ;; Délégation au header
      (:slot (funcall header :slot))
      (:parent-hash (funcall header :parent-hash))
      ;; Délégation à l'extrinsic
      (:tickets (funcall extrinsic :tickets))
      (:disputes (funcall extrinsic :disputes))
      ;; Propriété dérivée
      (:summary (format nil "Block(slot=~D, ~D items)"
                       (funcall header :slot)
                       (funcall extrinsic :count))))))

(format t "Création d'un block...~%")
(defparameter *my-extrinsic*
  (my-make-extrinsic :tickets '(t1 t2)
                     :disputes '(d1)))

(defparameter *my-block*
  (my-make-block *my-header* *my-extrinsic*))

(format t "  ✓ Block créé~%~%")

(format t "Accès aux propriétés (délégation):~%")
(format t "  Slot (du header):     ~D~%" (funcall *my-block* :slot))
(format t "  Tickets (extrinsic):  ~A~%" (funcall *my-block* :tickets))
(format t "  Summary (dérivée):    ~A~%~%" (funcall *my-block* :summary))

;;; ==========================================================================
;;; RÉSUMÉ
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Résumé : Les 3 Niveaux JOTL                            │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(format t "1. Valeurs Simples (τ):~%")
(format t "   → Juste des nombres~%")
(format t "   → Pas de closures~%~%")

(format t "2. Pure Functions (codec, hash):~%")
(format t "   → Input → Output~%")
(format t "   → Pas d'état~%~%")

(format t "3. Closures (Header, Block):~%")
(format t "   → Données complexes~%")
(format t "   → Immutables~%")
(format t "   → Encapsulation~%~%")

(format t "═══════════════════════════════════════════════════════════~%")
(format t "  Code is Law - Functions are Pure ! 🎯~%")
(format t "═══════════════════════════════════════════════════════════~%~%")
