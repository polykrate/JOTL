//! Tests for wire.rs — JAM codec FFI boundary.

use super::super::context::{JamHostContext, EmpowerState, JamTransfer};
use super::{encode_side_effects, decode_pvm_config, compact_from, compact_to};

// ============================================================================
// compact_from / compact_to round-trip
// ============================================================================

#[test]
fn test_compact_roundtrip_zero() {
    let mut buf = Vec::new();
    compact_to(&mut buf, 0);
    let (val, consumed) = compact_from(&buf, 0).unwrap();
    assert_eq!(val, 0);
    assert_eq!(consumed, buf.len());
}

#[test]
fn test_compact_roundtrip_small() {
    for v in [1u64, 63, 127] {
        let mut buf = Vec::new();
        compact_to(&mut buf, v);
        let (val, consumed) = compact_from(&buf, 0).unwrap();
        assert_eq!(val, v, "failed for {}", v);
        assert_eq!(consumed, buf.len());
    }
}

#[test]
fn test_compact_roundtrip_medium() {
    for v in [128u64, 255, 1000, 16383] {
        let mut buf = Vec::new();
        compact_to(&mut buf, v);
        let (val, consumed) = compact_from(&buf, 0).unwrap();
        assert_eq!(val, v, "failed for {}", v);
        assert_eq!(consumed, buf.len());
    }
}

#[test]
fn test_compact_roundtrip_large() {
    for v in [65536u64, 1_000_000, u32::MAX as u64, u64::MAX] {
        let mut buf = Vec::new();
        compact_to(&mut buf, v);
        let (val, consumed) = compact_from(&buf, 0).unwrap();
        assert_eq!(val, v, "failed for {}", v);
        assert_eq!(consumed, buf.len());
    }
}

// ============================================================================
// encode_side_effects: empty context
// ============================================================================

#[test]
fn test_encode_side_effects_empty() {
    let ctx = JamHostContext::default();
    let blob = encode_side_effects(&ctx, 0);
    assert!(!blob.is_empty());

    // Should contain: u64(0) + i64(0) + 7 × compact(0) + 2 × option-none(0x00)
    // + items_count(4) + footprint(8)
    // balance(8) + gas(8) + storage(1) + transfers(1) + ejected(1) + created(1)
    // + upgrades(1) + empower-none(1) + provided(1) + lookup(1) + yield-none(1)
    // + items_count(4) + footprint(8)
    assert_eq!(blob.len(), 8 + 8 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 4 + 8);
}

// ============================================================================
// encode_side_effects → round-trip invariants
// ============================================================================

#[test]
fn test_encode_side_effects_with_transfers() {
    let mut ctx = JamHostContext::default();
    ctx.balance = 42;
    ctx.transfers.push(JamTransfer {
        from_service: 10,
        to_service: 20,
        amount: 100,
        memo: vec![0xAB; 128],
        gas_limit: 5000,
    });
    ctx.ejected_services.push((100, 42));
    ctx.created_services.push((200, [0xCC; 32]));
    ctx.upgrades.push((300, [0xDD; 32]));
    ctx.yield_output = Some([0xEE; 32]);

    let blob = encode_side_effects(&ctx, 999);
    assert!(!blob.is_empty());

    // Decode manually: balance
    let balance = u64::from_le_bytes(blob[0..8].try_into().unwrap());
    assert_eq!(balance, 42);
    let gas = i64::from_le_bytes(blob[8..16].try_into().unwrap());
    assert_eq!(gas, 999);
}

#[test]
fn test_encode_side_effects_with_storage() {
    let mut ctx = JamHostContext::default();
    ctx.storage.insert(vec![1, 2, 3], vec![4, 5]);

    let blob = encode_side_effects(&ctx, 0);
    // storage count should be 1 (compact = 0x01)
    // After balance(8) + gas(8) = offset 16
    assert_eq!(blob[16], 1); // compact(1) = 0x01
}

#[test]
fn test_encode_side_effects_with_empower() {
    let mut ctx = JamHostContext::default();
    ctx.empower = Some(EmpowerState {
        manager: 42,
        auth_agents: vec![1, 2],
        validator: 3,
        staker: 4,
        gas_map: Default::default(),
        queues: Default::default(),
        validators: Default::default(),
    });

    let blob = encode_side_effects(&ctx, 0);
    assert!(!blob.is_empty());
}

#[test]
fn test_encode_side_effects_with_lookup() {
    let mut ctx = JamHostContext::default();
    ctx.lookup.insert(([0xAA; 32], 64), vec![100, 200]);

    let blob = encode_side_effects(&ctx, 0);
    assert!(!blob.is_empty());
}

// ============================================================================
// GP §9.3: items_count and footprint formulas
// ============================================================================

#[test]
fn test_items_count_footprint_gp_9_3() {
    let mut ctx = JamHostContext::default();

    // 2 lookup entries: (hash_a, z=64) and (hash_b, z=128)
    ctx.lookup.insert(([0xAA; 32], 64), vec![100]);
    ctx.lookup.insert(([0xBB; 32], 128), vec![100, 200]);

    // 3 storage entries with known key/value sizes
    ctx.storage.insert(vec![1; 32], vec![0xDE; 100]);   // key=32, val=100
    ctx.storage.insert(vec![2; 32], vec![0xAD; 50]);    // key=32, val=50
    ctx.storage.insert(vec![3; 10], vec![0xBE; 200]);   // key=10, val=200

    // GP §9.3: a_i = 2·|a_l| + |a_s| = 2×2 + 3 = 7
    assert_eq!(ctx.compute_items_count(), 7);

    // GP §9.3: a_o = Σ_{(h,z)∈K(a_l)} (81+z) + Σ_{(x,y)∈a_s} (34+|y|+|x|)
    //        = (81+64) + (81+128) + (34+32+100) + (34+32+50) + (34+10+200)
    //        = 145 + 209 + 166 + 116 + 244 = 880
    assert_eq!(ctx.compute_footprint(), 880);

    // Verify via encode_side_effects: items_count and footprint at end of blob
    let blob = encode_side_effects(&ctx, 0);
    let len = blob.len();
    let items_bytes = &blob[len - 12..len - 8];
    let footprint_bytes = &blob[len - 8..len];
    let items = u32::from_le_bytes(items_bytes.try_into().unwrap());
    let footprint = u64::from_le_bytes(footprint_bytes.try_into().unwrap());
    assert_eq!(items, 7, "items_count in blob");
    assert_eq!(footprint, 880, "footprint in blob");
}

// ============================================================================
// decode_pvm_config: round-trip via hand-encoding
// ============================================================================

fn make_minimal_config_blob() -> Vec<u8> {
    let mut buf = Vec::new();

    // invocation: Accumulate (2)
    buf.push(2);
    // service_id: 42
    buf.extend_from_slice(&42u32.to_le_bytes());
    // balance: 1000
    buf.extend_from_slice(&1000u64.to_le_bytes());
    // timeslot: 100
    buf.extend_from_slice(&100u32.to_le_bytes());
    // entropy: 128 zero bytes
    buf.extend_from_slice(&[0u8; 128]);
    // header_hash: 32 bytes
    buf.extend_from_slice(&[0xAA; 32]);
    // code_hash: 32 bytes
    buf.extend_from_slice(&[0xBB; 32]);
    // threshold: u64
    buf.extend_from_slice(&500u64.to_le_bytes());
    // min_accum_gas: u64
    buf.extend_from_slice(&10u64.to_le_bytes());
    // min_item_gas: u64
    buf.extend_from_slice(&5u64.to_le_bytes());
    // min_on_transfer_gas: u64
    buf.extend_from_slice(&3u64.to_le_bytes());
    // items_count: u32
    buf.extend_from_slice(&2u32.to_le_bytes());
    // footprint: u64
    buf.extend_from_slice(&1024u64.to_le_bytes());
    // recent_count: u32
    buf.extend_from_slice(&8u32.to_le_bytes());
    // accum_gas_limit: u32
    buf.extend_from_slice(&99u32.to_le_bytes());
    // preimage_pages: u32
    buf.extend_from_slice(&7u32.to_le_bytes());
    // gas: i64
    buf.extend_from_slice(&5000i64.to_le_bytes());

    // storage: empty
    compact_to(&mut buf, 0);
    // preimages: empty
    compact_to(&mut buf, 0);
    // lookup: empty
    compact_to(&mut buf, 0);
    // service_accounts: empty
    compact_to(&mut buf, 0);
    // existing_services: empty
    compact_to(&mut buf, 0);
    // accumulate_items: empty
    compact_to(&mut buf, 0);
    // work_items: empty
    compact_to(&mut buf, 0);

    // core_count: u16
    buf.extend_from_slice(&2u16.to_le_bytes());
    // auth_queue_len: u16
    buf.extend_from_slice(&80u16.to_le_bytes());
    // val_count: u16
    buf.extend_from_slice(&6u16.to_le_bytes());

    buf
}

#[test]
fn test_decode_pvm_config_minimal() {
    let blob = make_minimal_config_blob();
    let mut ctx = JamHostContext::default();
    let consumed = decode_pvm_config(&blob, &mut ctx).unwrap();
    assert_eq!(consumed, blob.len());

    assert_eq!(ctx.service_id, 42);
    assert_eq!(ctx.balance, 1000);
    assert_eq!(ctx.timeslot, 100);
    assert_eq!(ctx.slot, 100);
    assert_eq!(ctx.header_hash, [0xAA; 32]);
    assert_eq!(ctx.code_hash, [0xBB; 32]);
    assert_eq!(ctx.threshold, 500);
    assert_eq!(ctx.min_accum_gas, 10);
    assert_eq!(ctx.min_item_gas, 5);
    assert_eq!(ctx.min_on_transfer_gas, 3);
    assert_eq!(ctx.items_count, 2);
    assert_eq!(ctx.footprint, 1024);
    assert_eq!(ctx.recent_count, 8);
    assert_eq!(ctx.accum_gas_limit, 99);
    assert_eq!(ctx.preimage_pages, 7);
    assert_eq!(ctx.core_count, 2);
    assert_eq!(ctx.auth_queue_len, 80);
    assert_eq!(ctx.val_count, 6);
    assert!(ctx.storage.is_empty());
    assert!(ctx.preimages.is_empty());
    assert!(ctx.lookup.is_empty());
    assert!(ctx.service_accounts.is_empty());
    assert!(ctx.existing_services.is_empty());
    assert!(ctx.accumulate_items.is_empty());
    assert!(ctx.work_items.is_empty());
}

#[test]
fn test_decode_pvm_config_with_storage() {
    let mut blob = Vec::new();

    // Fixed header (same as minimal)
    blob.push(2); // invocation
    blob.extend_from_slice(&42u32.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes()); // balance
    blob.extend_from_slice(&0u32.to_le_bytes()); // timeslot
    blob.extend_from_slice(&[0u8; 128]); // entropy
    blob.extend_from_slice(&[0u8; 32]); // header_hash
    blob.extend_from_slice(&[0u8; 32]); // code_hash
    blob.extend_from_slice(&[0u8; 8 * 4]); // threshold, min_accum_gas, min_item_gas, min_on_transfer_gas
    blob.extend_from_slice(&[0u8; 4]); // items_count
    blob.extend_from_slice(&[0u8; 8]); // footprint
    blob.extend_from_slice(&[0u8; 4 * 3]); // recent_count, accum_gas_limit, preimage_pages
    blob.extend_from_slice(&0i64.to_le_bytes()); // gas

    // storage: 1 entry: key=[1,2], value=[3,4,5]
    compact_to(&mut blob, 1);
    compact_to(&mut blob, 2); blob.extend_from_slice(&[1, 2]);
    compact_to(&mut blob, 3); blob.extend_from_slice(&[3, 4, 5]);

    // rest: all empty
    for _ in 0..6 { compact_to(&mut blob, 0); }

    // tail
    blob.extend_from_slice(&2u16.to_le_bytes());
    blob.extend_from_slice(&80u16.to_le_bytes());
    blob.extend_from_slice(&6u16.to_le_bytes());

    let mut ctx = JamHostContext::default();
    decode_pvm_config(&blob, &mut ctx).unwrap();

    assert_eq!(ctx.storage.len(), 1);
    assert_eq!(ctx.storage.get(&vec![1, 2]).unwrap(), &vec![3, 4, 5]);
}
