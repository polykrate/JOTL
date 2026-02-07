# Pure FP : Quoi, Où, Pourquoi ?

## 🎯 La Question : Tout en Pure FP ?

**NON !** Il faut être **stratégique**.

Pure FP là où ça compte, pragmatique là où ça n'a pas d'impact.

---

## 📐 Les Trois Niveaux

### Niveau 1 : **Données Métier** (MUST be Pure FP)

**Ce qui représente l'état de la blockchain**

```lisp
;; ✅ PURE FP OBLIGATOIRE

;; Block
(defun make-block (header extrinsic)
  (lambda (msg)
    (case msg
      (:header header)
      (:extrinsic extrinsic))))

;; Header
(defun make-header (&key parent-hash state-root slot ...)
  (lambda (msg)
    (case msg
      (:parent-hash parent-hash)
      (:state-root state-root)
      (:slot slot)
      ...)))

;; State
(defun make-state (timeslot balances cores ...)
  (lambda (msg)
    (case msg
      (:timeslot timeslot)
      (:balances balances)
      (:cores cores)
      ...)))
```

**Pourquoi Pure FP ici ?**
- ✅ Ces objets **SONT** la blockchain
- ✅ Doivent être **immuables** pour consensus
- ✅ Doivent être **reproductibles** pour validation
- ✅ L'historique **doit être préservé**

**Impact mutations :** 💣 CATASTROPHIQUE (fork, perte de fonds)

---

### Niveau 2 : **Transformations** (SHOULD be Pure FP)

**Fonctions qui transforment des données**

```lisp
;; ✅ PURE FP RECOMMANDÉ

;; State Transition Function
(defun accumulate (state extrinsic)
  "σ' ← Ψ_A(σ, E)"
  ;; Retourne un NOUVEAU state
  (make-state
   :timeslot (1+ (funcall state :timeslot))
   :balances (update-balances (funcall state :balances) extrinsic)
   ...))

;; Validation
(defun validate-block (block parent-state)
  "Vérifie la validité sans modifier"
  (and
   (valid-slot-p (funcall (funcall block :header) :slot))
   (valid-parent-p (funcall (funcall block :header) :parent-hash) parent-state)
   ...))
```

**Pourquoi Pure FP ici ?**
- ✅ Facilite le raisonnement
- ✅ Testable unitairement
- ✅ Composable
- ✅ Thread-safe

**Impact mutations :** 🔥 GRAVE (bugs, consensus brisé)

---

### Niveau 3 : **Utilitaires & Codecs** (CAN be Pragmatic)

**Code qui facilite le travail mais n'affecte pas la logique**

#### 3a. Codecs (Encode/Decode)

```lisp
;; ✅ PRAGMATIQUE OK

;; Encoder : bytes → structure
(defun decode-header (bytes)
  "Transforme bytes en header (closure)"
  (let ((offset 0))  ; ← Mutation locale
    (let* ((parent-hash (read-bytes bytes offset 32))
           (offset (+ offset 32))  ; ← Mutation
           (state-root (read-bytes bytes offset 32))
           (offset (+ offset 32))  ; ← Mutation
           (slot (decode-u32 (read-bytes bytes offset 4)))
           (offset (+ offset 4)))  ; ← Mutation
      ;; Résultat : IMMUTABLE closure
      (make-header
       :parent-hash parent-hash
       :state-root state-root
       :slot slot))))

;; Ou même avec defstruct + conversion
(defstruct header-raw
  parent-hash state-root slot ...)

(defun decode-header-pragmatic (bytes)
  "Structure temporaire → closure finale"
  (let ((raw (decode-to-struct bytes)))  ; ← Peut utiliser mutation
    ;; Convertir en closure immutable
    (make-header
     :parent-hash (header-raw-parent-hash raw)
     :state-root (header-raw-state-root raw)
     :slot (header-raw-slot raw)
     ...)))
```

**Pourquoi pragmatique OK ici ?**
- ✅ Le codec est une **transformation ponctuelle**
- ✅ Les mutations sont **locales** (scope limité)
- ✅ Le résultat final est **immutable**
- ✅ Performance importante pour I/O

**Règle d'or :** 
```
Entrée (bytes) → [Processus: peut être impur] → Sortie (closure immutable)
```

#### 3b. Helpers & Utils

```lisp
;; ✅ PRAGMATIQUE OK

;; Hash table lookup
(defun state-get (state key)
  "Récupère une valeur du state"
  ;; Peut utiliser hash-table mutables en interne
  (gethash key (funcall state :internal-storage)))

;; Builder temporaire
(defun build-block-from-network (raw-data)
  "Parse réseau → block"
  (let ((temp-buffer (make-array 1024)))  ; ← Mutable
    ;; Accumule data
    (loop for byte across raw-data
          for i from 0
          do (setf (aref temp-buffer i) byte))
    ;; Résultat immutable
    (bytes-to-block temp-buffer)))
```

**Pourquoi pragmatique OK ici ?**
- ✅ Code **utilitaire**, pas logique métier
- ✅ Mutations **locales et cachées**
- ✅ Interface **pure** (input → output)
- ✅ Performance critique

---

## 🎯 Règle Générale : Boundary Pattern

```
┌─────────────────────────────────────────────────────────┐
│                   MONDE EXTÉRIEUR                       │
│          (Réseau, Disque, FFI, Mutation OK)             │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  CODEC LAYER   │  ← Peut être pragmatique
              │  (Transform)   │     (mutation locale)
              └────────┬───────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              CŒUR IMMUTABLE (Pure FP)                   │
│                                                         │
│  - Block, Header, State (closures)                      │
│  - STF (accumulate, refine, ...)                        │
│  - Validation, Consensus                                │
│                                                         │
│         AUCUNE MUTATION TOLÉRÉE ICI                     │
└─────────────────────────────────────────────────────────┘
```

**Principe :**
- **Frontières** = pragmatique (I/O, parsing, FFI)
- **Cœur** = Pure FP strict (logique métier)

---

## 📊 Tableau de Décision

| Composant                    | Pure FP ? | Raison                                |
|------------------------------|-----------|---------------------------------------|
| **Block**                    | ✅ OUI    | État blockchain, doit être immutable  |
| **Header**                   | ✅ OUI    | État blockchain, doit être immutable  |
| **State (σ)**                | ✅ OUI    | État blockchain, doit être immutable  |
| **STF (accumulate, etc.)**   | ✅ OUI    | Logique critique, doit être pure      |
| **Validation**               | ✅ OUI    | Logique critique, doit être pure      |
| **Codec (encode/decode)**    | 🟡 PEUT   | Transform, mutations locales OK       |
| **Network I/O**              | 🟡 PEUT   | Frontière externe, pragmatique OK     |
| **Crypto (via FFI)**         | 🟡 PEUT   | Frontière externe, FFI Rust OK        |
| **Logging**                  | 🟡 PEUT   | Side-effect, pas critique             |
| **Tests helpers**            | 🟡 PEUT   | Pas prod, pragmatisme OK              |

---

## 🔍 Exemples Concrets

### ✅ CORRECT : Codec Pragmatique → Core Pure

```lisp
;; === CODEC LAYER (pragmatique) ===

(defun decode-header-bytes (bytes)
  "Decode bytes avec mutation locale"
  (let ((pos 0)  ; ← Mutation locale
        (parent-hash nil)
        (state-root nil)
        (slot nil))
    
    ;; Parsing avec mutation
    (setf parent-hash (subseq bytes pos (+ pos 32)))
    (incf pos 32)
    (setf state-root (subseq bytes pos (+ pos 32)))
    (incf pos 32)
    (setf slot (decode-u32 (subseq bytes pos (+ pos 4))))
    (incf pos 4)
    
    ;; Conversion en closure immutable
    (values
     (make-header :parent-hash parent-hash
                  :state-root state-root
                  :slot slot)
     pos)))  ; Offset pour suite

;; === CORE (Pure FP strict) ===

(defun validate-and-apply (state encoded-block)
  "Valide et applique un block"
  ;; Decode (peut être impur en interne)
  (let* ((block (decode-block encoded-block))
         (header (funcall block :header)))
    
    ;; Validation (PURE)
    (if (valid-block-p block state)
        ;; Application (PURE - retourne nouveau state)
        (accumulate state (funcall block :extrinsic))
        ;; Reject
        (error "Invalid block"))))
```

**Pourquoi c'est bon ?**
1. ✅ Codec utilise mutation **localement** (performance)
2. ✅ Résultat du codec est **immutable** (closure)
3. ✅ Core métier est **Pure FP** (validation, STF)

---

### ❌ INCORRECT : Mutation dans Core

```lisp
;; ❌ MAUVAIS : Mutation du state en place
(defun accumulate-bad (state extrinsic)
  "WRONG: Modifie state directement"
  ;; Récupère timeslot actuel
  (let ((current-slot (funcall state :timeslot)))
    ;; ❌ MODIFIE en place
    (setf (funcall state :timeslot) (1+ current-slot))
    state))  ; Retourne le même state modifié

;; Problème :
(defparameter *state* (make-state :timeslot 100))
(defparameter *state-after* (accumulate-bad *state* extrinsic))

;; ❌ *state* a changé aussi !
(funcall *state* :timeslot)  ; => 101 (devrait être 100)
;; ❌ Impossible de rollback
;; ❌ Consensus brisé
```

---

## 🎯 Réponse à Ta Question

> "Pour les codecs du bloc, je me dis que c'est une structure dans sa forme  
> et qu'on la décode une fois, c'est peut-être cohérent ?"

**Réponse : OUI, c'est cohérent ! Voici comment :**

### Approche Hybride Optimale

```lisp
;; 1. Structure temporaire pour parsing (PRAGMATIQUE)
(defstruct header-temp
  parent-hash
  state-root
  extrinsic-hash
  slot
  epoch-mark
  tickets-mark
  offenders-mark
  author-index
  entropy-source
  seal)

;; 2. Decoder rapide avec structure
(defun decode-header-fast (bytes)
  "Parse bytes → defstruct (peut utiliser mutation)"
  (let ((h (make-header-temp))
        (offset 0))
    
    ;; Parsing efficace avec setf
    (setf (header-temp-parent-hash h) 
          (subseq bytes offset (+ offset 32)))
    (incf offset 32)
    
    (setf (header-temp-state-root h)
          (subseq bytes offset (+ offset 32)))
    (incf offset 32)
    
    ;; ... etc
    
    h))  ; Retourne structure

;; 3. Convertir en closure immutable pour le core
(defun header-temp-to-closure (h-temp)
  "Structure → Closure immutable"
  (make-header
   :parent-hash (header-temp-parent-hash h-temp)
   :state-root (header-temp-state-root h-temp)
   :slot (header-temp-slot h-temp)
   ...))

;; 4. API publique : renvoie closure
(defun decode-header (bytes)
  "API publique : bytes → closure immutable"
  (-> bytes
      decode-header-fast      ; Structure temporaire
      header-temp-to-closure)) ; Conversion immutable

;; 5. Usage dans le core
(defun process-block-from-network (raw-bytes)
  "Le core ne voit que des closures"
  (let* ((header (decode-header raw-bytes))  ; ← Closure immutable
         (state *current-state*))
    ;; Tout Pure FP à partir d'ici
    (validate-header header state)))
```

**Avantages :**
- ✅ **Performance** : parsing rapide avec defstruct + mutation
- ✅ **Sécurité** : conversion en closure avant d'entrer dans le core
- ✅ **Clarté** : séparation parsing vs logique métier
- ✅ **Pragmatisme** : le meilleur des deux mondes

---

## 🏗️ Architecture JOTL

```
┌────────────────────────────────────────────────────────┐
│                    NETWORK LAYER                       │
│              (Mutation OK, Performance)                │
└──────────────────────┬─────────────────────────────────┘
                       │ Raw bytes
                       ▼
┌────────────────────────────────────────────────────────┐
│                   CODEC LAYER                          │
│                                                        │
│  decode-header-fast (defstruct + mutation)             │
│         ↓                                              │
│  header-temp-to-closure (conversion)                   │
│         ↓                                              │
│  Résultat : Closure immutable                          │
└──────────────────────┬─────────────────────────────────┘
                       │ Header (closure)
                       ▼
┌────────────────────────────────────────────────────────┐
│                   CORE LAYER                           │
│                 (Pure FP Strict)                       │
│                                                        │
│  - validate-header (header) → bool                     │
│  - accumulate (state, extrinsic) → state'             │
│  - refine (state) → state'                             │
│                                                        │
│  Tout immutable, aucune mutation                       │
└────────────────────────────────────────────────────────┘
```

---

## ✅ Checklist : Quand Pure FP ?

### Pure FP OBLIGATOIRE si :
- ☑ Représente l'état blockchain (block, state, header)
- ☑ Logique de consensus (STF, validation)
- ☑ Transformation de données métier
- ☑ Peut être appelé plusieurs fois avec même input

### Pragmatique ACCEPTABLE si :
- ☑ Frontière externe (réseau, disque, FFI)
- ☑ Parsing/encoding (transformation ponctuelle)
- ☑ Mutations **locales** (scope limité)
- ☑ Résultat final **immutable**
- ☑ Interface **pure** (pas d'effet visible)

---

## 🎯 Conclusion

**Ce qu'il faut retenir :**

1. **Cœur métier** = Pure FP **strict** (block, state, STF)
2. **Frontières** = Pragmatique **acceptable** (codec, I/O)
3. **Règle d'or** = Interface pure, implémentation peut être pragmatique
4. **Test** = Si tu peux appeler 2x avec même input et avoir même output → Pure

**Pour les codecs :**
- ✅ OUI, utilise `defstruct` + mutation pour parsing
- ✅ OUI, convertis en closure avant d'entrer dans le core
- ✅ OUI, c'est l'approche optimale (perf + sécurité)

**Code is Law - Pure where it Matters !** 🎯
