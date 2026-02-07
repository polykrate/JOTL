# JAM Codec - Structure du répertoire

Implémentation du codec JAM (Gray Paper Appendix C) organisée en modules logiques.

## 📁 Structure

```
src/codec/
├── primitives.lisp   ✅ Types primitifs
├── types.lisp        ✅ Types JAM réutilisables
├── header.lisp       ✅ Encoding Header (Gray Paper §5)
└── extrinsic.lisp    ⏳ Encoding Extrinsic (Gray Paper §4.3)
```

---

## 📄 `primitives.lisp` - Types Primitifs

**Responsabilité :** Types de base du codec JAM (Gray Paper Appendix C).

### Fonctions :

#### Fixed-Length Integers
- `encode-fixed-le(value, num-bytes)` - Little-endian encoding
- `decode-fixed-le(bytes)` - Little-endian decoding
- `E1(value)` - u8 (1 byte)
- `E2(value)` - u16 (2 bytes)
- `E4(value)` - u32 (4 bytes)
- `E8(value)` - u64 (8 bytes)

#### Variable-Length Integers (Compact)
- `encode-compact(value)` - Variable-length integer
- `decode-compact(bytes, offset)` - Decode compact

**Modes compact :**
- 0-63: 1 byte
- 64-16383: 2 bytes
- 16384-2^30: 4 bytes
- 2^30+: 5+ bytes

#### Sequences
- `encode-sequence(items, encoder-fn)` - [compact-length] [item1] [item2] ...
- `decode-sequence(bytes, decoder-fn, offset)` - Decode sequence

#### Options
- `encode-option(value, encoder-fn)` - None: [0x00], Some: [0x01] [value]
- `decode-option(bytes, decoder-fn, offset)` - Decode option

#### Results
- `encode-result(result, ok-encoder, err-encoder)` - Ok/Err encoding
- `decode-result(bytes, ok-decoder, err-decoder, offset)` - Decode result

---

## 📄 `types.lisp` - Types JAM Réutilisables

**Responsabilité :** Types JAM utilisés dans header, extrinsic, state.

### Fonctions :

#### Hashes (H)
- `encode-hash-32(hash)` - 32-byte hash (Blake2b-256)
- `decode-hash-32(bytes, offset)` - Decode hash

#### Keys
- `encode-ed25519-key(key)` - 32-byte Ed25519 public key (H̄)
- `decode-ed25519-key(bytes, offset)` - Decode Ed25519 key
- `encode-bandersnatch-key(key)` - 32-byte Bandersnatch key (H̃)
- `decode-bandersnatch-key(bytes, offset)` - Decode Bandersnatch key

#### Signatures
- `encode-signature-96(signature)` - 96-byte Bandersnatch VRF (Y)
- `decode-signature-96(bytes, offset)` - Decode signature

#### Validators
- `encode-validator(validator)` - (Bandersnatch:32, Ed25519:32)
- `decode-validator(bytes, offset)` - Decode validator
- `encode-validator-sequence(validators)` - **FIXED SIZE** (no compact length!)
- `decode-validator-sequence(bytes, offset, num-validators)` - Decode fixed-size

**Important :** Les séquences de validators dans les epoch markers sont de **taille fixe** (NV du chainspec), **PAS** préfixées par un compact length !

#### Indices
- `encode-validator-index(index)` - u16 (NV)
- `decode-validator-index(bytes, offset)` - Decode u16
- `encode-service-account-index(index)` - u32 (NS)
- `decode-service-account-index(bytes, offset)` - Decode u32

---

## 📄 `header.lisp` - Header Encoding

**Responsabilité :** Encoding/decoding du header JAM (Gray Paper §5).

### Structure du Header

```
H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)

HP : H (32 bytes)          - Parent hash
HR : H (32 bytes)          - State root
HX : H (32 bytes)          - Extrinsic hash
HT : u32 (4 bytes)         - Timeslot
HE : Option<EpochMarker>   - Epoch marker
HW : Option<TicketsMark>   - Tickets marker
HO : Vec<Ed25519>          - Offenders
HI : u16 (2 bytes)         - Author index
HV : Y (96 bytes)          - Entropy source (VRF)
HS : Y (96 bytes)          - Seal (signature)
```

### Ordre d'encodage (Gray Paper §5.8)

```
E(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
```

**Note :** HO (offenders) vient **APRÈS** HV (entropy source) !

### Fonctions :

#### Components
- `encode-epoch-marker(epoch-mark)` - Option<(entropy, tickets_entropy, validators)>
- `decode-epoch-marker(bytes, offset, num-validators)` - Decode epoch marker
- `encode-tickets-mark(tickets-mark)` - Option<TicketsMark> (TODO)
- `decode-tickets-mark(bytes, offset)` - Decode tickets mark (TODO)
- `encode-offenders(offenders)` - Vec<Ed25519>
- `decode-offenders(bytes, offset)` - Decode offenders

#### Complete Header
- `encode-header-unsealed(...)` - EU(H) - Header sans seal
- `encode-header(...)` - E(H) - Header complet avec seal
- `compute-header-hash(...)` - H(E(H)) - Blake2b-256 du header encodé

#### Closure
- `make-header-encoded(...)` - Crée une closure header avec encoding lazy

---

## 📄 `extrinsic.lisp` - Extrinsic Encoding

**Responsabilité :** Encoding/decoding de l'extrinsic JAM (Gray Paper §4.3).

### Structure de l'Extrinsic

```
E ≡ (ET, ED, EP, EA, EG)

ET : Tickets extrinsic     - Gray Paper §6.4
ED : Disputes extrinsic    - Gray Paper §10
EP : Preimages extrinsic   - Gray Paper §7.4
EA : Assurances extrinsic  - Gray Paper §11
EG : Guarantees extrinsic  - Gray Paper §11-12 (work reports)
```

### Fonctions (stubs pour l'instant)

- `encode-tickets-extrinsic(tickets)` - TODO
- `encode-disputes-extrinsic(disputes)` - TODO
- `encode-preimages-extrinsic(preimages)` - TODO
- `encode-assurances-extrinsic(assurances)` - TODO
- `encode-guarantees-extrinsic(guarantees)` - TODO
- `encode-extrinsic(...)` - Complete extrinsic - TODO
- `decode-extrinsic(bytes, offset)` - TODO
- `make-extrinsic-encoded(...)` - Closure extrinsic - TODO

---

## 🔍 Dépendances

```
primitives.lisp
    ↓
types.lisp (utilise primitives)
    ↓
header.lisp (utilise types + primitives)
extrinsic.lisp (utilise types + primitives)
```

**Ordre de chargement ASDF :**
1. `primitives.lisp`
2. `types.lisp`
3. `header.lisp`
4. `extrinsic.lisp`

---

## 🎯 Avantages de cette structure

### ✅ Séparation claire des responsabilités
- **Primitives** : Types de base (u8, compact, option)
- **Types** : Types JAM réutilisables (hash, signature, validator)
- **Header** : Spécifique au header
- **Extrinsic** : Spécifique à l'extrinsic

### ✅ Réutilisabilité
Les types dans `types.lisp` sont partagés entre :
- Header (epoch markers, validators, hashes)
- Extrinsic (à venir)
- State (à venir)

### ✅ Évolutivité
Facile d'ajouter de nouveaux modules :
- `state.lisp` - State encoding (Gray Paper §6-7)
- `block.lisp` - Block encoding (B ≡ (H, E))
- `work.lisp` - Work packages/reports (Gray Paper §11-12)

### ✅ Maintenabilité
- Fichiers plus courts (< 300 lignes chacun)
- Responsabilités claires
- Tests ciblés possibles

---

## 🧪 Tests

Tous les tests passent après réorganisation :
- ✅ Round-trip: 16/16 (100%)
- ✅ JSON decode: 11/11 (100%)
- ✅ Header decode: byte-by-byte match

---

## 📚 Références

- **Gray Paper §5** : Header structure
- **Gray Paper §4.3** : Extrinsic structure
- **Gray Paper Appendix C** : Codec specification
- **Gray Paper §6.6** : Epoch markers
- **Gray Paper §10** : Disputes and offenders

---

**Code is Law - Clean Architecture !** 🏗️✨
