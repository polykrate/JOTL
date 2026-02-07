# Architecture Rapide

## Deux approches complémentaires

**Closures (données)** → Header, Block, Extrinsic
- Entités avec plusieurs propriétés
- Exemple: `(funcall header :parent-hash)`

**Pure Functions (opérations)** → Codec, Crypto
- Transformations pures: input → output
- Exemple: `(encode-u32 42)`

**Timeslot = Pure Values** (τ = simple nombre)
- Pas besoin de closure pour un simple ℕ
- `(timeslot-epoch 42)` suffit !

## Verdict

✅ **Architecture actuelle = COHÉRENTE**

Code is Law !
