;;;; decoder-macros.lisp
;;;; Macros pour composer les primitives JAM et construire des décodeurs
;;;; Architecture: blob → list → primitives → structures

(in-package :jotl-codec)

;;; Helpers pour décodage de champs fixes

(defun decode-fixed-bytes (octets pos count)
  "Extrait count bytes à partir de pos.
   Retourne (values bytes count)"
  (values (subseq octets pos (+ pos count))
          count))

(defun decode-e1 (octets pos)
  "Décode 1 octet (E1).
   Retourne (values integer 1)"
  (values (decode-fixed-integer (subseq octets pos (+ pos 1)) 1)
          1))

(defun decode-e2 (octets pos)
  "Décode 2 octets (E2).
   Retourne (values integer 2)"
  (values (decode-fixed-integer (subseq octets pos (+ pos 2)) 2)
          2))

(defun decode-e4 (octets pos)
  "Décode 4 octets (E4).
   Retourne (values integer 4)"
  (values (decode-fixed-integer (subseq octets pos (+ pos 4)) 4)
          4))

(defun decode-e8 (octets pos)
  "Décode 8 octets (E8).
   Retourne (values integer 8)"
  (values (decode-fixed-integer (subseq octets pos (+ pos 8)) 8)
          8))

(defun decode-hash (octets pos)
  "Décode un hash (32 bytes).
   Retourne (values hash-list 32)"
  (values (subseq octets pos (+ pos 32))
          32))

;;; Macro de composition : threading des décodeurs

(defmacro decode>> ((octets-var pos-var) &body bindings)
  "Compose les primitives JAM en gérant automatiquement l'avancement de position.
   
   Chaque binding est (var decoder-call) où decoder-call retourne (values val consumed).
   La dernière forme (sans binding) est le retour de la fonction.
   
   Args:
     octets-var: variable contenant la liste d'octets
     pos-var: variable contenant la position (sera automatiquement incrémentée)
     bindings: liste de (var decoder-expr) suivie d'une forme de retour
   
   Retourne:
     Le résultat de la dernière forme
   
   Exemple:
     (decode>> (octets pos)
       (parent-hash (decode-hash octets pos))
       (timeslot (decode-e4 octets pos))
       (epoch-marker (decode-optional octets 
                                      (lambda (o s) (decode-epoch-marker o s)) 
                                      pos))
       (make-header :parent-hash parent-hash :timeslot timeslot ...))"
  (let* ((forms (butlast bindings))
         (return-form (car (last bindings))))
    `(let (,@(mapcar #'first forms))
       ,@(mapcar (lambda (binding)
                   (destructuring-bind (var decoder-expr) binding
                     (let ((val-sym (gensym "VAL"))
                           (consumed-sym (gensym "CONSUMED")))
                       `(multiple-value-bind (,val-sym ,consumed-sym) ,decoder-expr
                          (setf ,var ,val-sym)
                          (incf ,pos-var ,consumed-sym)))))
                 forms)
       ,return-form)))
