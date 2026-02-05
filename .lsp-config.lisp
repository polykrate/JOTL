;;;; .lsp-config.lisp
;;;; Configuration pour LSP Common Lisp (alive-lsp, cl-lsp)
;;;;
;;;; Ce fichier force le LSP à charger le système JOTL dans l'ordre ASDF
;;;; avant d'analyser les fichiers individuels, éliminant les faux positifs
;;;; "package does not exist".

(require :asdf)
(push #P"./" asdf:*central-registry*)

;; Charge le système complet pour que tous les packages soient définis
(handler-case
    (asdf:load-system :jotl :verbose nil)
  (error (e)
    (format t "~%⚠️  LSP config: Impossible de charger :jotl - ~A~%" e)))

;; Confirme que les packages sont disponibles
(format t "~%✅ LSP config chargé:~%")
(format t "   • JOTL-CONFIG: ~A~%" (find-package :jotl-config))
(format t "   • JOTL-CODEC:  ~A~%" (find-package :jotl-codec))
(format t "   • JOTL-BLOC:   ~A~%~%" (find-package :jotl-bloc))
