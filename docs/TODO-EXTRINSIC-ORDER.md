# TODO: Fix Extrinsic Component Order

## Problem Identified

The order of extrinsic components in `extrinsic.bin` test vectors is **different** from the order specified in the Gray Paper!

### Gray Paper §4.3
```
E ≡ (ET, ED, EP, EA, EG)
```

### Actual Test Vector Order (discovered empirically)
```
E ≡ (ET, EP, EG, EA, ED)
```

### Component Positions in `extrinsic.bin` (4332 bytes total)

| Component | Position | Size | Name |
|-----------|----------|------|------|
| ET (Tickets) | 0-2355 | 2356 bytes | tickets_extrinsic.bin |
| EP (Preimages) | 2356-2419 | 64 bytes | preimages_extrinsic.bin |
| EG (Guarantees) | 2420-3002 | 583 bytes | guarantees_extrinsic.bin |
| EA (Assurances) | 3003-3201 | 199 bytes | assurances_extrinsic.bin |
| ED (Disputes) | 3202-4331 | 1130 bytes | disputes_extrinsic.bin |

### Required Changes

**Files to modify:**
- `src/codec/extrinsic/extrinsic.lisp`
  - `encode-extrinsic()`: Change order to ET → EP → EG → EA → ED
  - `decode-extrinsic()`: Change order to ET → EP → EG → EA → ED

**Current Status:**
- Individual component codecs (ET, EP, EA, ED) all work ✅
- Full `extrinsic.bin` fails because of wrong order ❌
- Attempted fix had parenthesis issues (reverted)

### Next Steps

1. Update `encode-extrinsic()` to use correct order
2. Update `decode-extrinsic()` to use correct order
3. Test with `extrinsic.bin` (should decode all 4332 bytes)
4. Update `compute-extrinsic-hash()` if needed (uses encode, so should be automatic)

### Notes

- This may be a version difference between Gray Paper and test vectors
- Or test vectors may use a different encoding convention
- All individual components are correctly implemented
- Only the orchestration order needs to be fixed
