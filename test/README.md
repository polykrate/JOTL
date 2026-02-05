# JOTL Test Suite

Tests pour le codec JAM implémenté en Common Lisp.

## Test Vectors Officiels

Les test vectors officiels de la Web3 Foundation sont dans `../jamtestvectors/` (cloné depuis https://github.com/w3f/jamtestvectors).

## Status Actuel

### ✅ Implémenté
- **Primitives (C.1-C.15)** : Tous les encodeurs/décodeurs de base
  - Trivial encodings, fixed-length integers
  - Sequences, discriminators, bit sequences
  - Dictionaries, sets
  
- **Structures de blocs** : Toutes définies avec `defstruct`
  - `jam-header`, `jam-block`, `jam-extrinsic`
  - `jam-ticket`, `jam-preimage`, `jam-report`
  - `jam-availability-assurance`, `jam-disputes`

### ⚠️  En Cours
- **Epoch Marker** : Structure complexe non encore définie
  - Contient entropy, tickets_entropy, validators
  - Nécessaire pour décoder les headers complets
  
- **Winning Tickets** : Structure non encore définie

### 🔧 À Faire
- Définir structures manquantes (epoch marker, winning tickets)
- Valider round-trip avec test vectors officiels
- Tests unitaires pour chaque composant

## Structures Utilisées

**On utilise des `defstruct` partout** (pas de hash tables) :
- Type safety ✓
- Accesseurs optimisés ✓
- Documentation intégrée ✓
- Performance optimale ✓
