# Work-Result Structure FINALE (JAM Codec)

## Structure Complète Confirmée

D'après les test vectors officiels `work_result_0.bin` et `work_result_1.bin` :

```
1. service-id (E4):           4 bytes
2. code-hash (32 bytes):     32 bytes  
3. payload-hash (32 bytes):  32 bytes
4. accumulate-gas (NATURAL):  1 byte
5. byte 0x00:                 1 byte (toujours 0 ?)
6. refine-load #1 (5×NAT):    5 bytes
7. result discriminant (E2):  2 bytes  ← VRAI DISCRIMINANT !
8. result data (↕):       0 ou N bytes (si discriminant=0)
9. refine-load #2 (5×NAT):    5 bytes
```

## Tailles

- **Discriminant = 0 (ok with data)**: 86 bytes total
  - Fixed part: 4+32+32+1+1+5+2 = 77 bytes
  - Data: 1 (length) + N (data) = variable
  - Refine #2: 5 bytes
  
- **Discriminant != 0 (panic, etc.)**: 82 bytes total
  - Fixed part: 4+32+32+1+1+5+2+5 = 82 bytes
  - Pas de data

## Valeurs Discriminant (E2)

- `0` : ok (avec data length-prefixed)
- `1` : out-of-gas
- `2` : panic (avec revert)
- `3` : panic (sans revert)
- `4` : bad work package
- `5` : service unavailable
- `6` : code too large

## Exemples Test Vectors

### work_result_0.bin (86 bytes)
```
service_id: 16909060
accumulate_gas: 42
result: {"ok": "0xaabbcc"}
→ Discriminant E2 = 0
→ Data = 03 aa bb cc (4 bytes)
```

### work_result_1.bin (82 bytes)
```
service_id: 84281096
accumulate_gas: 33
result: {"panic": null}
→ Discriminant E2 = 2
→ Pas de data
```

## Mystères Résolus

1. ✅ **Deux refine-loads** : Un avant et un après le result
2. ✅ **Champ E2** : C'est le VRAI discriminant du result
3. ✅ **Byte 0x00** au début : Rôle inconnu (toujours 0)
4. ✅ **JAM Codec** : Utilise NATURAL (compact) pour integers variables

## Encodage

JAM Codec = SCALE Codec SAUF pour compact integers qui utilisent JAM Compact (C.5)

- **NATURAL** : JAM Compact encoding (C.5)
- **E1/E2/E4/E8** : Fixed-length little-endian
- **Length-prefixed** : NATURAL(length) + data
- **Structs** : Concaténation séquentielle
