# Work Result Structure - FINAL RÉVÉLATION

## Résolution du mystère des "mystery bytes"

### Fausse piste initiale
Nous pensions avoir deux "mystery bytes" (0x00) inexpliqués dans la structure :
- Mystery byte #1 après accumulate-gas
- Mystery byte #2 avant le discriminant de result

Et nous pensions aussi voir DEUX refine-loads dans le binaire.

### DÉCOUVERTE MAJEURE 🎉

**Les "mystery bytes" étaient en fait les derniers octets de `accumulate-gas` encodé en E8 !**

#### Analyse qui nous a révélé la vérité

En lisant **tous** les fichiers d'encodage dans `codec/primitives`, nous avons cherché si les mystery bytes correspondaient à un format existant (C.7 Length Discriminator, C.8 Optional Discriminator, etc.).

En vérifiant l'ASN.1 schema (`jam-types.asn`), nous avons trouvé que `accumulate-gas` a le type `Gas` qui est défini comme `U64` (8 bytes), pas un NATURAL variable !

#### Preuve par les bytes

**Work Result #0:**
```
Position 68: 2a (qu'on pensait être NATURAL(42))
Position 69-75: 00 00 00 00 00 00 00 (qu'on pensait être mystery + refine)
```

**Mais en fait:**
```
E8(42) = 2a 00 00 00 00 00 00 00 (8 bytes en little-endian)
         ^^                       
         └─ Ce qu'on décodait comme NATURAL
            ^^^^^^^^^^^^^^^^^^^^^^^ 
            └─ Ce qu'on prenait pour "mystery + refine#1"
```

**Work Result #1:**
```
Position 68: 21 (qu'on pensait être NATURAL(33))
Position 69-75: 00 00 00 00 00 00 00
```

**Mais en fait:**
```
E8(33) = 21 00 00 00 00 00 00 00
```

## Structure CORRECTE et FINALE

### WorkResult (ASN.1 + Test Vectors)

```
1. service-id (E4):          4 bytes
2. code-hash (OpaqueHash):  32 bytes  
3. payload-hash (OpaqueHash): 32 bytes
4. accumulate-gas (Gas=U64=E8): 8 bytes  ← PAS NATURAL !
5. result (WorkExecResult):  variable
   - discriminant (NATURAL):  1 byte
   - data (↕ si disc=0):     0-N bytes
6. refine-load (RefineLoad): 5 bytes (si tous NATURAL=0)
   - gas-used (NATURAL)
   - imports (NATURAL)  
   - extrinsic-count (NATURAL)
   - extrinsic-size (NATURAL)
   - exports (NATURAL)
```

### Tailles réelles

**Work Result #0 (ok avec data):** 86 bytes
- service-id: 4
- hashes: 64
- accumulate-gas (E8): 8
- result disc: 1
- result length: 1
- result data: 3
- refine-load: 5
- **TOTAL: 86 ✅**

**Work Result #1 (panic sans data):** 82 bytes  
- service-id: 4
- hashes: 64
- accumulate-gas (E8): 8
- result disc: 1
- refine-load: 5
- **TOTAL: 82 ✅**

## Leçons apprises

1. **Toujours vérifier l'ASN.1 schema** pour les types de base (U64, U32, U16, etc.)
2. **Ne jamais supposer** qu'un champ est NATURAL juste parce que la valeur tient dans 1 byte
3. **Les "mystery bytes"** sont souvent un signe qu'on a mal décodé un champ précédent
4. **La différence 86-82 = 4 bytes** (length + data) était correcte, ce n'était pas un problème de "double refine-load"

## Validation finale

```bash
✅ work_result_0.bin: Round-trip SUCCESS (86 bytes)
✅ work_result_1.bin: Round-trip SUCCESS (82 bytes)
```

## Code Lisp final

```lisp
(defun encode-work-result (result)
  (concat-octets
   (e4 (work-result-service-id result))
   (work-result-code-hash result)
   (work-result-payload-hash result)
   (e8 (work-result-accumulate-gas result))  ; E8, not NATURAL!
   (encode-work-output (work-result-result result))
   (encode-refine-load (work-result-refine-load result))))
```

Date: 2026-02-05
