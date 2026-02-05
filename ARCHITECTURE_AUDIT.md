# 🏗️ AUDIT ARCHITECTURE LISP - JOTL

Date: 2026-02-05  
Statut: Phase 1 (Block Codec) Complete, Phase 2 (State) Pending

---

## 📊 STRUCTURE ACTUELLE

```
JOTL/
├── jotl.asd                    # System definition ✅
├── codec/
│   ├── primitives/             # ✅ Primitives JAM (C.1-C.15)
│   │   ├── package.lisp
│   │   ├── trivial-encodings.lisp
│   │   ├── sequence-encoding.lisp
│   │   ├── discriminator-encoding.lisp
│   │   ├── bit-sequence-encoding.lisp
│   │   ├── dictionary-encoding.lisp
│   │   ├── set-encoding.lisp
│   │   ├── fixed-length-integer-encoding.lisp
│   │   └── decoder-macros.lisp
│   ├── bloc/                   # ✅ Block structures (C.16-C.35)
│   │   ├── package.lisp
│   │   ├── types.lisp
│   │   ├── config.lisp         # ⚠️ PROBLÈME
│   │   ├── work.lisp
│   │   ├── header.lisp
│   │   ├── epoch.lisp
│   │   ├── tickets.lisp
│   │   ├── disputes.lisp
│   │   ├── preimages.lisp
│   │   ├── availability.lisp
│   │   ├── reports.lisp
│   │   ├── block.lisp
│   │   └── JAM_BLOCK_STRUCTURE.md
│   └── state/                  # 🚧 VIDE (Phase 2)
├── STF/                        # 🚧 VIDE (Phase 3)
└── test/
    ├── jamtestvectors/         # ✅ Test vectors officiels
    └── *.lisp                  # ⚠️ DÉSORGANISÉ
```

---

## ✅ CE QUI EST BIEN

### 1. **Structure modulaire**
- ✅ Séparation claire `primitives/` → `bloc/` → `state/` → `STF/`
- ✅ Un `package.lisp` par module (convention CL)
- ✅ Ordre de chargement via `:serial t` dans `.asd`

### 2. **Primitives bien conçues**
- ✅ Suit le Graypaper (C.1-C.15)
- ✅ Macros de composition (`decode>>`)
- ✅ Helpers symétriques (`encode-e1`/`decode-e1`)

### 3. **Tests validés**
- ✅ Round-trip 100% (tiny + full blocks)
- ✅ Byte-by-byte match
- ✅ Test vectors officiels w3f

---

## ⚠️ PROBLÈMES ARCHITECTURAUX

### 🔴 **CRITIQUE : `config.lisp` dans `codec/bloc/`**

**Problème** :
```lisp
codec/bloc/config.lisp          ❌ Mauvais emplacement
  ↳ Contient chainspec (global)
  ↳ *validators-super-majority* (dynamic var)
  ↳ Utilisé par primitives ET bloc
```

**Solution** :
```lisp
src/config.lisp                 ✅ Top-level configuration
  ou
config/chainspec.lisp           ✅ Module dédié
```

**Rationale** :
- Configuration ≠ codec logic
- Chainspec est **global** (utilisé par bloc, state, STF)
- Convention CL : config au top-level ou module séparé

---

### 🟡 **MOYEN : Tests désorganisés**

**Problème** :
```
test/
  ├── test-block-codec.lisp     ❌ Ancien test
  ├── test-block-debug.lisp     ❌ Debug temporaire
  ├── test-validate-json.lisp   ❌ Temporaire
  └── jamtestvectors/           ✅ Official (submodule)

validate-block-codec.lisp       ❌ Root level (devrait être dans test/)
```

**Solution** :
```
test/
  ├── suite.lisp                ✅ Test runner principal
  ├── codec/
  │   ├── test-primitives.lisp
  │   ├── test-block-codec.lisp
  │   └── test-state-codec.lisp
  └── jamtestvectors/           ✅ Official (submodule)
```

---

### 🟡 **MOYEN : Markdown files dans `codec/bloc/`**

**Problème** :
```
codec/bloc/JAM_BLOCK_STRUCTURE.md     ❌ Devrait être dans docs/
```

**Solution** :
```
docs/
  ├── architecture.md
  ├── block-structure.md
  ├── codec-primitives.md
  └── conventions.md

README.md → Liens vers docs/
```

---

### 🟢 **MINEUR : `.asd` indentation inconsistante**

**Problème** :
```lisp
(:module "primitives"
  :serial t
  :components ((:file "package")
               (:file "trivial-encodings")
(:file "sequence-encoding")     ❌ Indentation cassée
```

**Solution** :
```lisp
(:module "primitives"
  :serial t
  :components ((:file "package")
               (:file "trivial-encodings")
               (:file "sequence-encoding")  ✅
```

---

## 🎯 PLAN DE REFACTORING

### **Phase A : Configuration (5 min)** 🔴

1. Créer `src/config.lisp` ou `config/chainspec.lisp`
2. Déplacer `codec/bloc/config.lisp` → `src/config.lisp`
3. Mettre à jour `jotl.asd` :
   ```lisp
   (:file "config")  ; Top-level, chargé avant codec
   (:module "codec" ...)
   ```
4. Mettre à jour package exports

---

### **Phase B : Tests (10 min)** 🟡

1. Créer structure `test/codec/`
2. Déplacer `validate-block-codec.lisp` → `test/codec/test-block.lisp`
3. Supprimer anciens tests (test-block-debug.lisp, etc.)
4. Créer `test/suite.lisp` (test runner)

---

### **Phase C : Documentation (5 min)** 🟡

1. Créer `docs/` directory
2. Déplacer `codec/bloc/JAM_BLOCK_STRUCTURE.md` → `docs/block-structure.md`
3. Créer `docs/architecture.md` (ce fichier nettoyé)

---

### **Phase D : `.asd` cleanup (2 min)** 🟢

1. Fixer indentation
2. Ajouter metadata (:homepage, :bug-tracker, :source-control)

---

## 📚 CONVENTIONS COMMON LISP RESPECTÉES

✅ **Un package par module**  
✅ **package.lisp en premier dans chaque module**  
✅ **:serial t pour ordre de chargement**  
✅ **defpackage avec exports centralisés**  
✅ **Dynamic variables avec \*earmuffs\***  
✅ **Naming: encode-foo / decode-foo (symmetric)**  
✅ **Docstrings sur toutes les fonctions publiques**  

---

## 📚 CONVENTIONS À AMÉLIORER

⚠️ **Configuration globale dans sous-module**  
⚠️ **Tests au root level**  
⚠️ **Documentation mélangée avec code**  
⚠️ **Pas de test suite centralisé**  

---

## 🎓 RÉFÉRENCES

- [ASDF Best Practices](https://asdf.common-lisp.dev/asdf.html#Best-Practices)
- [Cookbook: Project Structure](https://lispcookbook.github.io/cl-cookbook/systems.html)
- [Style Guide](https://google.github.io/styleguide/lispguide.xml)

---

## ✅ CONCLUSION

**Architecture actuelle : 7/10**

**Forces :**
- Modularité excellente
- Primitives bien conçues
- Tests validés

**Faiblesses :**
- Configuration mal placée (🔴 critique)
- Tests désorganisés (🟡 moyen)
- Documentation dispersée (🟡 moyen)

**Prochaines étapes recommandées :**
1. Phase A : Déplacer `config.lisp` (critique)
2. Phase 2 : Implémenter `state/` codec
3. Phase B : Réorganiser tests
4. Phase C : Centraliser documentation
