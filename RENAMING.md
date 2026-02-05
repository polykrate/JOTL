# Renommage des structures

## À faire

```
jam-header              → header
jam-block               → chain-block  (block = CL keyword)
jam-extrinsic           → extrinsic
jam-ticket              → ticket
jam-preimage            → preimage
jam-report              → report
jam-availability-assurance → availability-assurance
jam-disputes            → disputes
jam-verdict-entry       → verdict-entry
```

## À créer (pour epoch marker)

```
jam-epoch-marker        → epoch-marker
jam-validator           → validator
```

## Commit

Faire ce renommage AVANT d'implémenter epoch-marker pour éviter de devoir tout changer deux fois.
