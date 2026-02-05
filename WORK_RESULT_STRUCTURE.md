# Work-Result Structure Discovery

## Problem Context
After fixing core-index (E1), auth-gas-used (NATURAL), and accumulate-gas (NATURAL), we discovered that work-result has a complex internal structure that differs significantly from the ASN.1 schema.

## Discoveries

### Work-Result Binary Structure (86 bytes total)

```
1. service-id (E4):           4 bytes
2. code-hash:                32 bytes  
3. payload-hash:             32 bytes
4. accumulate-gas (NATURAL):  1 byte
5. discriminant:              1 byte
6. refine-load #1 (5xNAT):    5 bytes
7. E2 field:                  2 bytes (value: 0 for WR#1)
8. result data (↕):           4 bytes (length=3, data=0xaabbcc for WR#1)
9. refine-load #2 (5xNAT):    5 bytes
-------------------------------------------
TOTAL:                       86 bytes ✅
```

### Test Results

**Work-Result #1** (JSON: `result.ok = "0xaabbcc"`):
- Position: 3475-3561 (86 bytes) ✅ PERFECT MATCH
- Discriminant: 0
- Refine-load #1: [0, 0, 0, 0, 0]
- E2 field: 0
- Data: `03 AA BB CC` (length=3, data=0xaabbcc) ✅
- Refine-load #2: [0, 0, 0, 0, 0]

**Work-Result #2** (JSON: `result.panic = null`):
- Discriminant: 0 (but JSON says "panic"!)
- Structure unclear - may have different layout when discriminant != 0

## Issues

1. **Two refine-loads**: JSON shows only ONE `refine_load` object, but binary has TWO 5-byte refine-load structures
2. **E2 mystery field**: There's a 2-byte E2 field (value 0) between refine-loads that's not in JSON or ASN.1
3. **Discriminant mismatch**: WR#2 has binary discriminant 0 but JSON says `"panic": null`
4. **Structure complexity**: The encoding is much more complex than C.29 formula or ASN.1 schema suggest

## Questions

1. What is the E2 field between the two refine-loads?
2. Why are there two refine-load structures?
3. How does the structure change when discriminant != 0 (panic, out-of-gas, etc.)?
4. Is the JSON structure a logical representation that doesn't match binary layout?

## Next Steps

Options:
A. Continue debugging WR#2 to understand discriminant != 0 case
B. Implement the discovered structure for discriminant=0 case
C. Search for official specification or reference implementation
D. Ask maintainers about work-result binary format
