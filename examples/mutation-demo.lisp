;;;; mutation-demo.lisp - Démonstration des problèmes de mutation

(format t "~%~%═══════════════════════════════════════════════════════════~%")
(format t "  Démonstration : Mutations vs Immutabilité~%")
(format t "═══════════════════════════════════════════════════════════~%~%")

;;; ==========================================================================
;;; PROBLÈME 1 : Perte d'Historique
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Problème 1 : Perte d'Historique                        │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

;; Version mutable
(defstruct account-mut balance)

(format t "❌ Avec mutation (defstruct):~%")
(defparameter *acc-mut* (make-account-mut :balance 100))
(format t "  Balance initiale: ~D~%" (account-mut-balance *acc-mut*))

(setf (account-mut-balance *acc-mut*) 150)
(format t "  Après +50:        ~D~%" (account-mut-balance *acc-mut*))

(setf (account-mut-balance *acc-mut*) 200)
(format t "  Après +50:        ~D~%" (account-mut-balance *acc-mut*))

(format t "  ❌ On a perdu les valeurs 100 et 150 !~%~%")

;; Version immutable
(defun make-account-immut (balance)
  (lambda (msg &optional arg)
    (case msg
      (:balance balance)
      (:deposit (make-account-immut (+ balance arg))))))

(format t "✅ Sans mutation (closure):~%")
(defparameter *acc-v1* (make-account-immut 100))
(format t "  Version 1: ~D~%" (funcall *acc-v1* :balance))

(defparameter *acc-v2* (funcall *acc-v1* :deposit 50))
(format t "  Version 2: ~D~%" (funcall *acc-v2* :balance))

(defparameter *acc-v3* (funcall *acc-v2* :deposit 50))
(format t "  Version 3: ~D~%" (funcall *acc-v3* :balance))

(format t "  ✅ On a gardé les 3 versions !~%")
(format t "     v1: ~D, v2: ~D, v3: ~D~%~%"
        (funcall *acc-v1* :balance)
        (funcall *acc-v2* :balance)
        (funcall *acc-v3* :balance))

;;; ==========================================================================
;;; PROBLÈME 2 : Aliasing (Action à Distance)
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Problème 2 : Aliasing (Spooky Action at a Distance)   │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(format t "❌ Avec mutation:~%")
(defparameter *block-mut* (make-account-mut :balance 42))
(defparameter *my-block* *block-mut*)  ; Référence

(format t "  *block-mut*: ~D~%" (account-mut-balance *block-mut*))
(format t "  *my-block*:  ~D~%" (account-mut-balance *my-block*))

(setf (account-mut-balance *block-mut*) 999)
(format t "~%  Après modification de *block-mut*:~%")
(format t "  *block-mut*: ~D~%" (account-mut-balance *block-mut*))
(format t "  *my-block*:  ~D  ← Changé aussi !~%" (account-mut-balance *my-block*))
(format t "  ❌ Action à distance invisible~%~%")

(format t "✅ Sans mutation:~%")
(defparameter *block-immut* (make-account-immut 42))
(defparameter *my-block-immut* *block-immut*)

(format t "  *block-immut*:    ~D~%" (funcall *block-immut* :balance))
(format t "  *my-block-immut*: ~D~%" (funcall *my-block-immut* :balance))

(defparameter *block-immut-2* (funcall *block-immut* :deposit 957))
(format t "~%  Après 'modification' (nouveau objet):~%")
(format t "  *block-immut*:    ~D  ← Original intact~%" (funcall *block-immut* :balance))
(format t "  *my-block-immut*: ~D  ← Original intact~%" (funcall *my-block-immut* :balance))
(format t "  *block-immut-2*:  ~D  ← Nouvelle version~%" (funcall *block-immut-2* :balance))
(format t "  ✅ Pas d'action à distance~%~%")

;;; ==========================================================================
;;; PROBLÈME 3 : Non-Reproductibilité
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Problème 3 : Non-Reproductibilité (Ordre d'Exécution) │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(defparameter *counter-mut* 0)

(defun increment-mut ()
  (incf *counter-mut*))

(defun decrement-mut ()
  (decf *counter-mut*))

(format t "❌ Avec mutation (ordre compte):~%")

;; Ordre 1
(setf *counter-mut* 0)
(increment-mut)
(increment-mut)
(decrement-mut)
(format t "  Ordre 1 (++--): ~D~%" *counter-mut*)

;; Ordre 2
(setf *counter-mut* 0)
(decrement-mut)
(increment-mut)
(increment-mut)
(format t "  Ordre 2 (-++): ~D~%" *counter-mut*)

(format t "  ❌ Résultat identique PAR CHANCE~%")
(format t "  ❌ Avec des ops complexes, résultats différents garantis~%~%")

;; Version immutable
(defun counter-increment (c)
  (1+ c))

(defun counter-decrement (c)
  (1- c))

(format t "✅ Sans mutation (ordre ne compte pas pour résultat final):~%")

;; Ordre 1
(let ((result (-> 0
                  counter-increment
                  counter-increment
                  counter-decrement)))
  (format t "  Ordre 1 (++--): ~D~%" result))

;; Ordre 2
(let ((result (-> 0
                  counter-decrement
                  counter-increment
                  counter-increment)))
  (format t "  Ordre 2 (-++): ~D~%" result))

(format t "  ✅ Chaque étape est explicite et traçable~%~%")

;;; ==========================================================================
;;; PROBLÈME 4 : Consensus Impossible
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Problème 4 : Consensus Impossible (JAM/Blockchain)    │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(defparameter *global-state* (make-hash-table))
(setf (gethash :balance *global-state*) 100)

(defun validator-1-mut ()
  "Validator 1 modifie le state"
  (setf (gethash :balance *global-state*)
        (+ (gethash :balance *global-state*) 50))
  (format t "  V1 voit balance: ~D~%" (gethash :balance *global-state*)))

(defun validator-2-mut ()
  "Validator 2 modifie le state"
  (setf (gethash :balance *global-state*)
        (- (gethash :balance *global-state*) 30))
  (format t "  V2 voit balance: ~D~%" (gethash :balance *global-state*)))

(format t "❌ Avec mutation (état partagé):~%")
(format t "  État initial: ~D~%" (gethash :balance *global-state*))

(validator-1-mut)
(validator-2-mut)

(format t "  État final: ~D~%" (gethash :balance *global-state*))
(format t "  ❌ Si ordre inversé, résultat différent !~%")
(format t "  ❌ Consensus impossible~%~%")

;; Version immutable
(defun make-state (balance)
  (lambda (msg &optional arg)
    (case msg
      (:balance balance)
      (:add (make-state (+ balance arg)))
      (:sub (make-state (- balance arg))))))

(format t "✅ Sans mutation (état isolé):~%")
(defparameter *initial-state* (make-state 100))
(format t "  État initial: ~D~%" (funcall *initial-state* :balance))

(defparameter *state-v1* (funcall *initial-state* :add 50))
(format t "  V1 crée state: ~D~%" (funcall *state-v1* :balance))

(defparameter *state-v2* (funcall *initial-state* :sub 30))
(format t "  V2 crée state: ~D~%" (funcall *state-v2* :balance))

(format t "  ✅ Les deux validators ont travaillé sur des copies~%")
(format t "  ✅ État initial intact: ~D~%" (funcall *initial-state* :balance))
(format t "  ✅ On peut comparer v1 et v2 pour choisir le gagnant~%~%")

;;; ==========================================================================
;;; RÉSUMÉ
;;; ==========================================================================

(format t "┌─────────────────────────────────────────────────────────┐~%")
(format t "│ Résumé : Mutations = Danger pour JAM                  │~%")
(format t "└─────────────────────────────────────────────────────────┘~%~%")

(format t "❌ Problèmes avec mutations:~%")
(format t "  1. Perte d'historique (pas d'audit)~%")
(format t "  2. Aliasing (action à distance)~%")
(format t "  3. Non-reproductibilité~%")
(format t "  4. Race conditions~%")
(format t "  5. Consensus impossible~%~%")

(format t "✅ Solutions avec immutabilité:~%")
(format t "  1. Historique complet~%")
(format t "  2. Pas d'effets de bord~%")
(format t "  3. Reproductibilité garantie~%")
(format t "  4. Thread-safe par défaut~%")
(format t "  5. Consensus déterministe~%~%")

(format t "═══════════════════════════════════════════════════════════~%")
(format t "  Code is Law - State is Immutable ! 🔒~%")
(format t "═══════════════════════════════════════════════════════════~%~%")
