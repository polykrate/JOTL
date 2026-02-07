# JAM Types Mapping - Python to Common Lisp

**Source**: `jam-types-py` (https://github.com/davxy/jam-types-py)  
**Target**: JOTL (Common Lisp implementation)

---

## 📦 Block & Header

### Block
```
header      : Header
extrinsic   : Extrinsics
```

### Header
```
parent              : OpaqueHash (32 bytes)
parent_state_root   : OpaqueHash (32 bytes)
extrinsic_hash      : OpaqueHash (32 bytes)
slot                : TimeSlot (u32)
epoch_mark          : Option<EpochMark>
tickets_mark        : Option<TicketsMark>
author_index        : U16
entropy_source      : BandersnatchVrfSignature (96 bytes)
offenders_mark      : Vec<Ed25519Public>
seal                : BandersnatchVrfSignature (96 bytes)
```

### EpochMark
```
entropy             : OpaqueHash (32 bytes)
tickets_entropy     : OpaqueHash (32 bytes)
validators          : EpochMarkValidatorsKeys (Vec of validator keys)
```

### TicketsMark
```
Vec of TicketBody (fixed-length array)
```

---

## 📦 Extrinsics

### Extrinsics
```
tickets     : TicketsXt
preimages   : PreimagesXt
guarantees  : GuaranteesXt
assurances  : AssurancesXt
disputes    : DisputesXt
```

**Note**: Gray Paper §4.3 order is `(ET, ED, EP, EA, EG)` but actual binary order in test vectors is `(ET, EP, EG, EA, ED)`.

---

## 🎫 Tickets (ET)

### TicketsXt
```
Vec of TicketEnvelope (bounded, max = max_tickets_per_extrinsic)
```

### TicketEnvelope
```
attempt     : TicketAttempt (u8)
signature   : BandersnatchRingVrfSignature (784 bytes)
```

### TicketBody
```
id          : TicketId (32 bytes)
attempt     : TicketAttempt (u8)
```

**Encoding**: `ET(ET) = E(↕ET)`  
**Gray Paper**: C.16

---

## 📄 Preimages (EP)

### PreimagesXt
```
Vec of Preimage
```

### Preimage
```
requester   : ServiceId (u32)
blob        : ByteSequence (Vec<u8>)
```

**Encoding**: `EP(EP) = E(↕[(E4(s), ↕d) | (s, d) ← EP])`  
**Gray Paper**: C.17

---

## ✅ Assurances (EA)

### AssurancesXt
```
Vec of AvailAssurance
```

### AvailAssurance
```
anchor              : OpaqueHash (32 bytes)
bitfield            : AvailabilityBitfield (raw bytes, ⌈num_cores/8⌉ bytes)
validator_index     : U16
signature           : Ed25519Signature (64 bytes)
```

**Encoding**: `EA(EA) = E(↕[(a, f, E2(v), s) | (a, f, v, s) ← EA])`  
**Gray Paper**: C.19

**Important**: `bitfield` is NOT compact-prefixed! Its length is derived from chainspec `num_cores`.

---

## ⚖️ Disputes (ED)

### DisputesXt
```
verdicts    : Vec<Verdict>
culprits    : Vec<Culprit>
faults      : Vec<Fault>
```

### Verdict
```
target      : WorkReportHash (32 bytes)
age         : EpochIndex (u32)
votes       : Judgements (Vec<Judgement>)
```

### Judgement
```
vote        : Bool (1 byte)
index       : ValidatorIndex (u16)
signature   : Ed25519Signature (64 bytes)
```

### Culprit
```
target      : WorkReportHash (32 bytes)
key         : Ed25519Public (32 bytes)
signature   : Ed25519Signature (64 bytes)
```

### Fault
```
target      : WorkReportHash (32 bytes)
vote        : Bool (1 byte)
key         : Ed25519Public (32 bytes)
signature   : Ed25519Signature (64 bytes)
```

**Encoding**: `ED((v, c, f)) = E(↕[(r, E4(a), [(v, E2(i), s)])], ↕c, ↕f)`  
**Gray Paper**: C.21

**Important**: 
- `age` is `u32` (E4), not `u16`!
- Votes within a verdict are NOT compact-prefixed!
- Vote count = `⌊2V/3⌋ + 1` (supermajority), where V = `num_validators` from chainspec.

---

## 🛡️ Guarantees (EG)

### GuaranteesXt
```
Vec of ReportGuarantee
```

### ReportGuarantee
```
report      : WorkReport
slot        : TimeSlot (u32)
signatures  : GuaranteeSignatures (Vec<GuaranteeSignature>)
```

### GuaranteeSignature
```
validator_index     : ValidatorIndex (u16)
signature           : Ed25519Signature (64 bytes)
```

**Encoding**: `EG(EG) = E(↕[(r, E4(t), ↕[(E2(v), s) | (v, s) ← a]) | (r, t, a) ← EG])`  
**Gray Paper**: C.18

---

## 📊 Work Report

### WorkReport
```
package_spec            : WorkPackageSpec
context                 : RefineContext
core_index              : Compact<CoreIndex>
authorizer_hash         : OpaqueHash (32 bytes)
auth_gas_used           : Compact<U64>
auth_output             : AuthorizerOutput (ByteSequence)
segment_root_lookup     : Vec<SegmentRootLookupItem>
results                 : WorkResults (Vec<WorkResult>)
```

### WorkPackageSpec
```
hash            : WorkPackageHash (32 bytes)
length          : U32
erasure_root    : OpaqueHash (32 bytes)
exports_root    : OpaqueHash (32 bytes)
exports_count   : U16
```

### RefineContext
```
anchor              : HeaderHash (32 bytes)
state_root          : OpaqueHash (32 bytes)
beefy_root          : OpaqueHash (32 bytes)
lookup_anchor       : HeaderHash (32 bytes)
lookup_anchor_slot  : TimeSlot (u32)
prerequisites       : Vec<OpaqueHash>
```

### WorkResult
```
service_id          : ServiceId (u32)
code_hash           : OpaqueHash (32 bytes)
payload_hash        : OpaqueHash (32 bytes)
accumulate_gas      : Gas (u64)
result              : WorkExecResult (Enum: Ok/Panic/OutOfGas)
refine_load         : RefineLoad (tuple of gas values)
```

**Status**: ⚠️ WorkReport currently handled as raw bytes in JOTL. Full structure implementation pending.

---

## 📦 Work Package

### WorkPackage
```
auth_code_host      : ServiceId (u32)
auth_code_hash      : OpaqueHash (32 bytes)
context             : RefineContext
authorization       : ByteSequence
authorizer_config   : ByteSequence
items               : Vec<WorkItem>
```

### WorkItem
```
service_id          : ServiceId (u32)
code_hash           : OpaqueHash (32 bytes)
payload_blob        : ByteSequence
accumulate_gas      : Gas (u64)
refine_gas          : Gas (u64)
inputs              : Vec<ByteSequence>
outputs             : Vec<ByteSequence>
```

---

## 🔑 Primitive Types

| Python Type | Lisp Type | Size | Encoding |
|-------------|-----------|------|----------|
| `U8` | `(unsigned-byte 8)` | 1 byte | `E1(x)` |
| `U16` | `(unsigned-byte 16)` | 2 bytes | `E2(x)` |
| `U32` | `(unsigned-byte 32)` | 4 bytes | `E4(x)` |
| `U64` | `(unsigned-byte 64)` | 8 bytes | `E8(x)` |
| `Bool` | `boolean` | 1 byte | `0x00` or `0x01` |
| `OpaqueHash` | `(vector (unsigned-byte 8) 32)` | 32 bytes | Raw bytes |
| `Ed25519Public` | `(vector (unsigned-byte 8) 32)` | 32 bytes | Raw bytes |
| `Ed25519Signature` | `(vector (unsigned-byte 8) 64)` | 64 bytes | Raw bytes |
| `BandersnatchVrfSignature` | `(vector (unsigned-byte 8) 96)` | 96 bytes | Raw bytes |
| `BandersnatchRingVrfSignature` | `(vector (unsigned-byte 8) 784)` | 784 bytes | Raw bytes |
| `ByteSequence` | `(vector (unsigned-byte 8))` | Variable | `↕` (compact-prefixed) |
| `Vec<T>` | `list` | Variable | `↕` (compact-prefixed) |
| `Option<T>` | `(or null T)` | Variable | `¿` (`0x00` or `0x01 + data`) |
| `Compact<T>` | `integer` | Variable | Compact encoding (C.1.5) |

---

## 📝 Implementation Status in JOTL

| Component | Status | Notes |
|-----------|--------|-------|
| **Header** | ✅ Complete | All fields decoded/encoded |
| **ET (Tickets)** | ✅ Complete | Tested with JSON validation |
| **EP (Preimages)** | ✅ Complete | Tested with JSON validation |
| **EA (Assurances)** | ✅ Complete | Tested with JSON validation |
| **ED (Disputes)** | ✅ Complete | Tested with JSON validation |
| **EG (Guarantees)** | ⚠️ Partial | Signatures OK, WorkReport as raw bytes |
| **WorkReport** | ⏳ Pending | Complex structure, needs full implementation |
| **WorkPackage** | ⏳ Pending | Not yet implemented |
| **Extrinsic Order** | ⚠️ Issue | Parenthesis errors when reordering |

---

## 🔧 Next Steps

1. **Fix Extrinsic Order**: Resolve parenthesis issues in `src/codec/extrinsic/extrinsic.lisp`
2. **Implement WorkReport**: Full structure encoding/decoding
3. **Test Full Block**: Decode `block.bin` and validate against `block.json`
4. **Implement STF**: State Transition Functions (Accumulate, Refine)

---

**Code is Law. Les bugs sont l'ennemi commun.** 🎯
