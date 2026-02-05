# Configuration LSP pour Common Lisp

## 🎯 Problème résolu

Le LSP analyse les fichiers Lisp **isolément**, sans comprendre l'ordre de chargement ASDF. Cela crée des faux positifs :

```lisp
;; preimages.lisp
(in-package :jotl-bloc)  ; ❌ LSP: "package does not exist"
```

Mais ASDF charge `package.lisp` **avant** `preimages.lisp`, donc le code est correct ✅

## 🛠️ Solution

### Fichiers de configuration

1. **`.vscode/settings.json`** - Configure le LSP pour charger le système ASDF
2. **`.lsp-config.lisp`** - Script de pré-chargement pour LSP
3. **`.cursorignore`** - Évite l'analyse de fichiers non-Lisp

### Comment ça marche

```json
{
  "lisp.lsp.startupCommands": [
    "(asdf:load-system :jotl)"  // ← Charge TOUT avant analyse
  ]
}
```

Le LSP exécute ces commandes au démarrage, chargeant tous les packages dans l'ordre ASDF.

## 🔄 Rafraîchir le LSP

Si tu vois encore du rouge :

1. **Ctrl+Shift+P** → `"Developer: Reload Window"`
2. Ou redémarre Cursor

## ✅ Vérification

```bash
sbcl --load .lsp-config.lisp
# Doit afficher:
# ✅ JOTL-CONFIG: #<PACKAGE "JOTL-CONFIG">
# ✅ JOTL-CODEC:  #<PACKAGE "JOTL-CODEC">
# ✅ JOTL-BLOC:   #<PACKAGE "JOTL-BLOC">
```

## 📚 Note

**Les lispers traditionnels n'utilisent pas de LSP.** Ils utilisent SLIME/SLY + Emacs avec un REPL connecté. Cette config est un compromis pour les éditeurs modernes (Cursor/VSCode).

**Code is law. SBCL is the compiler. LSP is just suggestions.**
