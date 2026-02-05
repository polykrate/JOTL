# Anatomie d'un Bloc JAM

## Vue d'ensemble

Un bloc JAM est composé de deux parties principales :

```
Bloc JAM (B) = Header (H) + Extrinsic (E)
```

**Taille typique** : Variable, de quelques Ko à plusieurs Mo selon l'activité

**Rôle** : Un bloc JAM représente un quantum de temps (un "slot") pendant lequel :
- Des calculs off-chain (work packages) sont validés
- Des données sont fournies aux services
- L'état global de la chaîne est mis à jour
- Le consensus avance

---

## 1. HEADER (H) - Les Métadonnées du Bloc

Le header contient les informations essentielles sur le bloc : son identité, sa position dans la chaîne, et les preuves cryptographiques de sa validité.

### 1.1 Champs de Chaînage

#### `parent-hash` (HP) - 32 bytes
**Rôle** : Hash du bloc parent
- Permet de chaîner les blocs entre eux
- Crée la structure de blockchain
- Si parent-hash invalide → bloc rejeté

**Exemple** :
```
parent-hash: 0x5c743dbc514284b2ea57798787c5a155ef9d7ac1e9499ec65910a7a3d65897b7
```

#### `prior-state-root` (HR) - 32 bytes
**Rôle** : Root du Merkle tree de l'état AVANT l'application du bloc
- Permet de vérifier que tout le monde part du même état
- Essentiel pour le consensus : tous les validateurs doivent voir le même état
- Permet la vérification légère (light clients)

**Analogie** : C'est comme le "checksum" de l'état de la base de données avant de faire des modifications

#### `extrinsic-hash` (HX) - 32 bytes
**Rôle** : Hash de toutes les données extrinsic du bloc
- Permet de séparer le header des données volumineuses
- Le header peut être propagé rapidement sur le réseau
- Les données complètes peuvent être récupérées séparément
- Détecte toute corruption des données

### 1.2 Champs Temporels

#### `timeslot` (HT) - 4 bytes (unsigned integer)
**Rôle** : Index temporel du bloc dans la chaîne
- Chaque slot = 6 secondes (typiquement)
- Permet de synchroniser tous les nœuds
- Utilisé pour calculer les timeouts et deadlines

**Exemple** :
```
timeslot: 42
→ Ce bloc a été produit 42 × 6 = 252 secondes après le genesis
```

### 1.3 Champs de Gouvernance

#### `epoch-marker` (HE) - OPTIONNEL
**Présence** : Seulement au premier bloc d'une nouvelle époque (toutes les ~4 heures)

**Contenu** :
```lisp
epoch-marker {
  entropy: H           ; 32 bytes - Entropie pour RNG de l'époque
  tickets-entropy: H   ; 32 bytes - Entropie pour sélection tickets
  validators: [        ; Liste des validateurs actifs
    {
      bandersnatch: 32 bytes  ; Clé pour VRF et consensus
      ed25519: 32 bytes       ; Clé pour signatures classiques
    }
  ]
}
```

**Rôle** :
1. **Rotation des validateurs** : Définit qui peut valider pendant cette époque
2. **Initialisation RNG** : Fournit l'entropie pour les tirages aléatoires
3. **Sécurité** : Change régulièrement le set de validateurs pour éviter la corruption

**Pourquoi optionnel ?** : Inclure la liste complète des validateurs dans chaque bloc serait trop lourd. On ne le fait qu'au début de chaque époque.

#### `winning-tickets` (HW) - OPTIONNEL
**Présence** : Seulement quand il y a des tickets gagnants à annoncer

**Contenu** :
```lisp
winning-tickets: [
  {
    identifier: 784 bytes  ; Signature du ticket
    attempt: N             ; Numéro de tentative
  }
]
```

**Rôle** : Distribution des récompenses
- Les validateurs soumettent des tickets pendant l'époque
- À la fin, certains tickets "gagnent" (tirage aléatoire vérifiable)
- Les gagnants reçoivent des récompenses

**Analogie** : C'est comme une loterie pour validateurs, mais prouvable cryptographiquement

### 1.4 Champs d'Identité

#### `author-index` (HI) - 2 bytes
**Rôle** : Index du validateur qui a produit ce bloc
- Identifie qui est responsable du bloc
- Utilisé pour attribuer les récompenses
- Permet de tracer les comportements malveillants

**Exemple** :
```
author-index: 3
→ Le validateur n°3 de la liste validators[] a produit ce bloc
```

### 1.5 Champs Cryptographiques

#### `vrf-signature` (HV) - 96 bytes
**Rôle** : Signature VRF (Verifiable Random Function)
- **Prouve** que le validateur avait le droit de produire ce bloc
- **Génère** l'entropie pour le prochain bloc
- **Vérifiable** : tout le monde peut vérifier sans refaire le calcul

**Processus** :
1. Le validateur signe le slot number avec sa clé VRF
2. La signature produit une valeur aléatoire
3. Si cette valeur est < threshold → il peut produire le bloc
4. Cette signature devient l'entropie du bloc suivant

**Analogie** : C'est comme un dé cryptographique dont le résultat est prouvable

#### `offenders` (HO) - Liste de clés Ed25519 (32 bytes chacune)
**Rôle** : Liste des validateurs qui ont mal agi
- Permet de punir les comportements malveillants
- Les validateurs listés ici perdent leurs stakes
- Types de fautes :
  - Double signing (signer deux blocs concurrents)
  - Invalider du travail correct
  - Ne pas valider quand requis

**Exemple** :
```lisp
offenders: [
  0x4418fb8c85bb3985394a8c2756d3643457ce614546202a2f50b093d762499ace
]
→ Ce validateur est banni et perd son stake
```

#### `seal` (HS) - 96 bytes
**Rôle** : Signature finale du bloc complet
- Le validateur signe le header complet (sauf le seal lui-même)
- C'est la preuve ultime que author-index a bien créé ce bloc
- Signature Bandersnatch (même clé que dans validators[])

**Processus de validation** :
1. Calculer hash(header sans seal)
2. Vérifier que seal est une signature valide de ce hash
3. Vérifier que la clé utilisée est celle de validators[author-index]

---

## 2. EXTRINSIC (E) - Les Données du Bloc

L'extrinsic contient toutes les données soumises au bloc par les validateurs et les utilisateurs.

```
Extrinsic (E) = (Tickets, Preimages, Guarantees, Availability, Disputes)
              = (ET,      EP,        EG,         EA,           ED)
```

### 2.1 Tickets (ET)

**Structure** :
```lisp
tickets: [
  {
    identifier: 784 bytes  ; Signature ring complète
    attempt: N             ; Numéro de tentative
  }
]
```

**Rôle** : Preuve de participation au consensus
- Les validateurs soumettent des tickets pour prouver qu'ils sont actifs
- Chaque validateur peut soumettre plusieurs tentatives
- Les tickets sont vérifiables cryptographiquement

**Processus** :
1. Validateur génère une signature ring basée sur l'entropie de l'époque
2. La signature incorpore son identité de manière anonyme
3. Si la signature est valide → le ticket est accepté
4. À la fin de l'époque, certains tickets gagnent (RNG basé sur tickets-entropy)

**Pourquoi 784 bytes ?** : Signature ring pour préserver l'anonymat tout en étant vérifiable

### 2.2 Preimages (EP)

**Structure** :
```lisp
preimages: [
  {
    service-id: 4 bytes    ; ID du service requesteur
    data: variable bytes   ; Les données demandées
  }
]
```

**Rôle** : Fournir des données aux smart contracts
- Les services (smart contracts) peuvent demander des données externes
- Les validateurs fournissent ces données dans les preimages
- Permet d'avoir des oracles décentralisés

**Cas d'usage** :
1. **Price feeds** : Un service DeFi demande le prix ETH/USD
2. **Données météo** : Un service d'assurance agricole demande les précipitations
3. **Résultats sportifs** : Un service de paris demande le score d'un match

**Exemple** :
```json
{
  "service-id": 16909060,
  "data": "0x81095e6122e3bc9d961e00014a7fc833"
}
```

**Pourquoi "preimage" ?** : C'est la donnée dont le hash était précédemment requis par le service

### 2.3 Guarantees (EG) - LE CŒUR DE JAM

**C'est ici que la magie opère !** Les guarantees sont des rapports de travail validés.

**Structure complète** :
```lisp
guarantees: [
  {
    report: {
      package-spec: {               ; Identification du work package
        hash: 32 bytes              ; Hash du package
        length: 4 bytes             ; Taille du package
        erasure-root: 32 bytes      ; Root pour erasure coding
        exports-root: 32 bytes      ; Root des exports
        exports-count: 2 bytes      ; Nombre d'exports
      }
      
      context: {                    ; Contexte d'exécution
        anchor: 32 bytes            ; Hash de référence
        state-root: 32 bytes        ; État au moment du travail
        beefy-root: 32 bytes        ; Root BEEFY pour interop
        lookup-anchor: 32 bytes     ; Anchor pour lookups
        lookup-anchor-slot: 4 bytes ; Slot de l'anchor
        prerequisites: []           ; Dépendances
      }
      
      core-index: 2 bytes           ; Quel core a fait le travail
      authorizer-hash: 32 bytes     ; Hash de l'authorizer
      auth-gas-used: 8 bytes        ; Gas utilisé pour auth
      auth-output: variable         ; Output de l'authorizer
      
      segment-root-lookup: []       ; Lookups de segments
      
      results: [                    ; Résultats d'exécution
        {
          service-id: 4 bytes       ; Service exécuté
          code-hash: 32 bytes       ; Code exécuté
          payload-hash: 32 bytes    ; Hash du payload
          accumulate-gas: 8 bytes   ; Gas pour accumulate
          
          result: {                 ; Résultat (discriminant)
            ok: data                ; OU
            panic: null             ; OU
            out-of-gas: null        ; etc.
          }
          
          refine-load: {            ; Stats d'exécution
            gas-used: 8 bytes
            imports: 8 bytes
            extrinsic-count: 8 bytes
            extrinsic-size: 8 bytes
            exports: 8 bytes
          }
        }
      ]
    }
    
    slot: 4 bytes                   ; Quand le travail a été fait
    
    signatures: [                   ; Validateurs qui garantissent
      {
        validator-index: 2 bytes    ; Qui signe
        signature: variable bytes   ; Signature
      }
    ]
  }
]
```

**Rôle** : **C'EST LE CŒUR DU SYSTÈME JAM**

1. **Work packages** : Des validateurs exécutent du code off-chain
2. **Validation distribuée** : Plusieurs validateurs vérifient indépendamment
3. **Consensus** : Si 2/3 des validateurs signent → le résultat est accepté
4. **État global** : Les résultats sont intégrés à l'état de la chaîne

**Processus détaillé** :

```
Étape 1: Un utilisateur soumet un work package
  ↓
Étape 2: Un validateur (sur un "core") exécute le package
  ↓
Étape 3: Le validateur génère un work-report avec les résultats
  ↓
Étape 4: D'autres validateurs vérifient en réexécutant
  ↓
Étape 5: Les validateurs signent le report (= guarantee)
  ↓
Étape 6: Si ≥ 2/3 signatures → inclus dans le bloc
  ↓
Étape 7: Les résultats modifient l'état global
```

**Exemple concret** :

Imaginons un service DeFi qui fait du swap de tokens :

1. **Package soumis** : "Swap 100 TokenA pour TokenB"
2. **Core 3 exécute** : 
   - Vérifie les balances
   - Calcule le taux
   - Effectue le swap
   - Résultat : "Success, 95 TokenB obtenus"
3. **Validateurs 0, 1, 2 vérifient** : Réexécutent et obtiennent le même résultat
4. **Ils signent** : 3 signatures dans guarantee.signatures[]
5. **Inclus dans bloc** : Le swap est finalisé
6. **État mis à jour** : Les balances sont modifiées

**Pourquoi c'est puissant ?**
- ✅ Exécution off-chain (scalable)
- ✅ Validation distribuée (sécurisé)
- ✅ Finalité on-chain (trustless)
- ✅ Pas de limite de complexité de calcul

### 2.4 Availability (EA)

**Structure** :
```lisp
availability: [
  {
    anchor: 32 bytes          ; Hash du work package
    bitfield: variable        ; Bitfield de disponibilité
    validator-index: 2 bytes  ; Validateur qui atteste
    signature: 64 bytes       ; Signature de l'attestation
  }
]
```

**Rôle** : Attester que les données d'un work package sont disponibles

**Problème résolu** : **Data Availability Problem**
- Un validateur malveillant pourrait soumettre un work report sans fournir les données
- Les autres ne pourraient pas vérifier
- Solution : Les validateurs attestent avoir les données

**Processus** :
1. Work package soumis et érasure-codé (divisé en morceaux redondants)
2. Chaque validateur reçoit un morceau
3. Si un validateur a son morceau → il signe une availability assurance
4. Si ≥ 1/3 des validateurs attestent → les données sont disponibles
5. Le work peut être exécuté

**Bitfield** : Indique quels morceaux le validateur possède
```
bitfield: 0b00000001
→ Le validateur a le morceau 0
```

### 2.5 Disputes (ED)

**Structure** :
```lisp
disputes: {
  verdicts: [                    ; Verdicts sur des work reports disputés
    {
      target: 32 bytes           ; Hash du report disputé
      age: 4 bytes               ; Âge de la dispute
      votes: [                   ; Votes des validateurs
        {
          vote: bool             ; guilty ou not-guilty
          index: 2 bytes         ; Validateur qui vote
          signature: 64 bytes    ; Signature du vote
        }
      ]
    }
  ]
  
  culprits: [                    ; Validateurs reconnus coupables
    {
      target: 32 bytes           ; Hash de la preuve de faute
      key: 32 bytes              ; Clé du validateur
      signature: 64 bytes        ; Signature prouvant la faute
    }
  ]
  
  faults: [                      ; Preuves de fautes
    {
      target: 32 bytes           ; Hash du report
      vote: bool                 ; Vote erroné
      key: 32 bytes              ; Validateur fautif
      signature: 64 bytes        ; Signature de la faute
    }
  ]
}
```

**Rôle** : Résolution des conflits et punition des validateurs malveillants

**Cas d'usage** :

**Scenario 1 : Dispute d'un work report**
```
1. Validateur A soumet un work report avec résultat X
2. Validateur B pense que le résultat devrait être Y
3. B ouvre une dispute sur ce report
4. Tous les validateurs rééxécutent et votent
5. Si majorité dit Y → A est puni (culprits)
6. Si majorité dit X → B est puni pour fausse accusation
```

**Scenario 2 : Preuve de double signing**
```
1. Validateur C signe deux blocs différents au même slot
2. Un validateur détecte et soumet les deux signatures (faults)
3. C est automatiquement banni (culprits)
4. C perd son stake
```

**Verdicts** : Résolution collective
- Chaque validateur vote guilty ou not-guilty
- Majorité 2/3 requis pour punir
- Empêche les fausses accusations

**Culprits** : Liste noire
- Validateurs prouvés malveillants
- Perdent leur stake immédiatement
- Bannis du set de validateurs

**Faults** : Preuves cryptographiques
- Double signing
- Validation incorrecte volontaire
- Censure de transactions

---

## 3. Flux de Vie d'un Bloc

```
T=0s: Début du slot 42
  ↓
T=0.5s: Validateur 3 calculé VRF → peut produire le bloc
  ↓
T=1s: Validateur 3 collecte:
  - Tickets des autres validateurs
  - Preimages requestées
  - Guarantees prêtes (≥2/3 signatures)
  - Availability assurances
  - Disputes en cours
  ↓
T=2s: Validateur 3 construit l'extrinsic
  ↓
T=3s: Calcul extrinsic-hash, prior-state-root
  ↓
T=4s: Construction du header unsigned
  ↓
T=5s: Signature du header (seal)
  ↓
T=5.5s: Broadcast du bloc au réseau
  ↓
T=6s: Les autres validateurs vérifient:
  - VRF valide ?
  - Seal valide ?
  - Extrinsic-hash correct ?
  - Guarantees ont ≥2/3 signatures ?
  - Prior-state-root correspond ?
  ↓
T=6s: Si valide → Bloc accepté, état mis à jour
  ↓
T=6s: Début du slot 43 (prochain bloc)
```

---

## 4. Pourquoi cette Architecture ?

### 4.1 Séparation Header/Extrinsic

**Avantage** : Propagation rapide
- Le header (petit) peut être diffusé rapidement
- Les données (volumineuses) peuvent suivre
- Les light clients ne téléchargent que les headers

### 4.2 Guarantees avec Signatures Multiples

**Avantage** : Sécurité distribuée
- Pas de "single point of failure"
- Un validateur malveillant ne peut pas tricher seul
- Besoin de corrompre 1/3 des validateurs (très coûteux)

### 4.3 Work Off-chain, Consensus On-chain

**Avantage** : Scalabilité infinie
- Le calcul lourd se fait off-chain (sur les cores)
- Seuls les résultats sont mis on-chain
- La chaîne peut valider n'importe quelle quantité de calcul

### 4.4 Availability Assurances

**Avantage** : Résistance à la censure
- Même si un validateur refuse de partager les données
- Les autres peuvent les reconstruire (erasure coding)
- Impossible de "cacher" un work package

### 4.5 Disputes On-chain

**Avantage** : Justice publique
- Tous les conflits sont résolus de manière transparente
- Les preuves sont permanentes
- Dissuasion forte contre la malveillance

---

## 5. Comparaison avec d'Autres Blockchains

| Aspect | Ethereum | Polkadot | JAM |
|--------|----------|----------|-----|
| **Exécution** | On-chain | Parachains | Off-chain (cores) |
| **Scalabilité** | ~15 TPS | ~1000 TPS | Illimitée |
| **Consensus sur** | Transactions | Relay chain + parachains | Work reports |
| **Data Availability** | Tous les nœuds | Validateurs | Erasure coding + attestations |
| **Disputes** | Révocation de blocs | Fishermen + GRANDPA | Votes collectifs on-chain |

---

## 6. Glossaire

- **Slot** : Période de 6 secondes pendant laquelle un bloc peut être produit
- **Epoch** : Période de ~4 heures regroupant plusieurs slots
- **Core** : Unité de calcul off-chain où les work packages sont exécutés
- **Work Package** : Tâche de calcul soumise pour exécution
- **Work Report** : Résultat d'exécution d'un work package
- **Guarantee** : Work report + signatures de validateurs
- **VRF** : Verifiable Random Function - RNG prouvable cryptographiquement
- **Erasure Coding** : Technique de redondance permettant de reconstruire les données
- **Anchor** : Point de référence dans l'état de la chaîne

---

## Références

- Graypaper JAM : Sections 4 (Blocks), 5 (State), 6 (Extrinsic), Appendix C (Encoding)
- Implémentation : `codec/bloc/` dans ce repository
