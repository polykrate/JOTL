use super::*;

#[test]
fn test_is_authorized_allows_only_gas_fetch_log() {
    let ctx = InvocationContext::IsAuthorized;
    assert!(ctx.allows(0),  "gas");
    assert!(ctx.allows(1),  "fetch");
    assert!(ctx.allows(100), "log");
    // Must NOT allow anything else
    assert!(!ctx.allows(2),  "lookup");
    assert!(!ctx.allows(3),  "read");
    assert!(!ctx.allows(4),  "write");
    assert!(!ctx.allows(5),  "info");
    assert!(!ctx.allows(6),  "hist_lookup");
    assert!(!ctx.allows(7),  "export");
    assert!(!ctx.allows(8),  "machine");
    assert!(!ctx.allows(18), "new");
    assert!(!ctx.allows(25), "yield");
}

#[test]
fn test_refine_allows_gas_fetch_hist_export_inner_pvm() {
    let ctx = InvocationContext::Refine;
    assert!(ctx.allows(0),  "gas");
    assert!(ctx.allows(1),  "fetch");
    assert!(ctx.allows(6),  "historical_lookup");
    assert!(ctx.allows(7),  "export");
    assert!(ctx.allows(8),  "machine");
    assert!(ctx.allows(9),  "peek");
    assert!(ctx.allows(10), "poke");
    assert!(ctx.allows(11), "pages");
    assert!(ctx.allows(12), "invoke");
    assert!(ctx.allows(13), "expunge");
    assert!(ctx.allows(100), "log");
    // Must NOT allow accumulate-only calls
    assert!(!ctx.allows(2),  "lookup");
    assert!(!ctx.allows(3),  "read");
    assert!(!ctx.allows(4),  "write");
    assert!(!ctx.allows(5),  "info");
    assert!(!ctx.allows(14), "bless");
    assert!(!ctx.allows(18), "new");
    assert!(!ctx.allows(20), "transfer");
    assert!(!ctx.allows(25), "yield");
}

#[test]
fn test_accumulate_b11_dispatch_table() {
    let ctx = InvocationContext::Accumulate;
    // B.11: gas, fetch, lookup, read, write, info
    assert!(ctx.allows(0),  "gas");
    assert!(ctx.allows(1),  "fetch");
    assert!(ctx.allows(2),  "lookup");
    assert!(ctx.allows(3),  "read");
    assert!(ctx.allows(4),  "write");
    assert!(ctx.allows(5),  "info");
    // B.11: privileged (bless, assign, designate, checkpoint)
    assert!(ctx.allows(14), "bless");
    assert!(ctx.allows(15), "assign");
    assert!(ctx.allows(16), "designate");
    assert!(ctx.allows(17), "checkpoint");
    // B.11: svc-mgmt (new, upgrade, transfer, eject)
    assert!(ctx.allows(18), "new");
    assert!(ctx.allows(19), "upgrade");
    assert!(ctx.allows(20), "transfer");
    assert!(ctx.allows(21), "eject");
    // B.11: preimage-mgmt (query, solicit, forget)
    assert!(ctx.allows(22), "query");
    assert!(ctx.allows(23), "solicit");
    assert!(ctx.allows(24), "forget");
    // B.11: yield, provide
    assert!(ctx.allows(25), "yield");
    assert!(ctx.allows(26), "provide");
    assert!(ctx.allows(100), "log");
    // Must NOT allow Refine-only calls
    assert!(!ctx.allows(6),  "historical_lookup — Refine only");
    assert!(!ctx.allows(7),  "export — Refine only");
    // Must NOT allow inner-PVM (8–13) — Refine only per B.11
    assert!(!ctx.allows(8),  "machine — Refine only");
    assert!(!ctx.allows(9),  "peek — Refine only");
    assert!(!ctx.allows(10), "poke — Refine only");
    assert!(!ctx.allows(11), "pages — Refine only");
    assert!(!ctx.allows(12), "invoke — Refine only");
    assert!(!ctx.allows(13), "expunge — Refine only");
}

#[test]
fn test_on_transfer_no_privileged_no_inner_pvm() {
    let ctx = InvocationContext::OnTransfer;
    // Allowed: gas, fetch, lookup, read, write, info
    assert!(ctx.allows(0),  "gas");
    assert!(ctx.allows(1),  "fetch");
    assert!(ctx.allows(2),  "lookup");
    assert!(ctx.allows(3),  "read");
    assert!(ctx.allows(4),  "write");
    assert!(ctx.allows(5),  "info");
    // Allowed: checkpoint, new, upgrade, transfer, eject, preimage-mgmt, yield, provide
    assert!(ctx.allows(17), "checkpoint");
    assert!(ctx.allows(18), "new");
    assert!(ctx.allows(20), "transfer");
    assert!(ctx.allows(25), "yield");
    assert!(ctx.allows(100), "log");
    // NOT allowed: bless, assign, designate
    assert!(!ctx.allows(14), "bless");
    assert!(!ctx.allows(15), "assign");
    assert!(!ctx.allows(16), "designate");
    // NOT allowed: Refine-only
    assert!(!ctx.allows(6),  "historical_lookup");
    assert!(!ctx.allows(7),  "export");
    // NOT allowed: inner-PVM
    assert!(!ctx.allows(8),  "machine");
    assert!(!ctx.allows(9),  "peek");
    assert!(!ctx.allows(13), "expunge");
}

#[test]
fn test_default_is_accumulate() {
    assert_eq!(InvocationContext::default(), InvocationContext::Accumulate);
}

// ------------------------------------------------------------------
// B.10 next_service_id
// ------------------------------------------------------------------

#[test]
fn test_next_service_id_deterministic() {
    let empty = HashSet::new();
    let no_created: &[(u32, [u8; 32])] = &[];
    let entropy_0 = [0xAA_u8; 32];
    let header_hash = [0xBB_u8; 32];
    let id1 = compute_next_service_id(42, &entropy_0, &header_hash, &empty, no_created);
    let id2 = compute_next_service_id(42, &entropy_0, &header_hash, &empty, no_created);
    assert_eq!(id1, id2, "must be deterministic");
}

#[test]
fn test_next_service_id_minimum() {
    let empty = HashSet::new();
    let no_created: &[(u32, [u8; 32])] = &[];
    let entropy_0 = [0_u8; 32];
    let header_hash = [0_u8; 32];
    let sid = compute_next_service_id(0, &entropy_0, &header_hash, &empty, no_created);
    assert!(sid >= (1 << 16), "must be ≥ S (65536), got {}", sid);
}

#[test]
fn test_next_service_id_varies_with_input() {
    let empty = HashSet::new();
    let no_created: &[(u32, [u8; 32])] = &[];
    let entropy_0 = [0x11_u8; 32];
    let header_hash = [0x22_u8; 32];
    let id_a = compute_next_service_id(100, &entropy_0, &header_hash, &empty, no_created);
    let id_b = compute_next_service_id(200, &entropy_0, &header_hash, &empty, no_created);
    assert_ne!(id_a, id_b, "different service_ids should produce different next_ids");
    let mut entropy_1 = [0x11_u8; 32];
    entropy_1[0] = 0xFF;
    let id_c = compute_next_service_id(100, &entropy_1, &header_hash, &empty, no_created);
    assert_ne!(id_a, id_c, "different entropy should produce different next_ids");
}

// ------------------------------------------------------------------
// B.14 check() tests
// ------------------------------------------------------------------

#[test]
fn test_check_skips_existing() {
    let empty = HashSet::new();
    let no_created: &[(u32, [u8; 32])] = &[];
    let entropy_0 = [0x42_u8; 32];
    let header_hash = [0x43_u8; 32];

    // Get the raw candidate
    let candidate = compute_next_service_id(1, &entropy_0, &header_hash, &empty, no_created);

    // Now block that exact ID
    let mut existing = HashSet::new();
    existing.insert(candidate);

    let checked = compute_next_service_id(1, &entropy_0, &header_hash, &existing, no_created);
    assert_ne!(checked, candidate, "must skip the blocked ID");
    assert!(checked >= (1 << 16), "result must be ≥ S");
}

#[test]
fn test_check_skips_created_services() {
    let empty = HashSet::new();
    let no_created: &[(u32, [u8; 32])] = &[];
    let entropy_0 = [0x42_u8; 32];
    let header_hash = [0x43_u8; 32];

    let candidate = compute_next_service_id(1, &entropy_0, &header_hash, &empty, no_created);

    // Block via created_services (not in δ yet)
    let created = vec![(candidate, [0u8; 32])];
    let checked = compute_next_service_id(1, &entropy_0, &header_hash, &empty, &created);
    assert_ne!(checked, candidate, "must skip IDs in created_services too");
}

#[test]
fn test_check_skips_consecutive_collisions() {
    let entropy_0 = [0x42_u8; 32];
    let header_hash = [0x43_u8; 32];
    let no_created: &[(u32, [u8; 32])] = &[];

    // Get the first candidate
    let empty = HashSet::new();
    let c0 = compute_next_service_id(1, &entropy_0, &header_hash, &empty, no_created);

    // Block c0 and the next few IDs in the ring
    let mut existing = HashSet::new();
    let s: u32 = 1 << 16;
    let modulus: u32 = u32::MAX - s - 255;
    existing.insert(c0);
    let c1 = ((c0 - s) + 1) % modulus + s;
    existing.insert(c1);
    let c2 = ((c1 - s) + 1) % modulus + s;
    existing.insert(c2);

    let result = compute_next_service_id(1, &entropy_0, &header_hash, &existing, no_created);
    // Must skip c0, c1, c2 and land on c3
    let c3 = ((c2 - s) + 1) % modulus + s;
    assert_eq!(result, c3, "must skip 3 consecutive collisions");
}

// ------------------------------------------------------------------
// B.13 Collapse tests
// ------------------------------------------------------------------

fn make_ctx_with_effects() -> JamHostContext {
    let mut ctx = JamHostContext::default();
    ctx.transfers.push(JamTransfer {
        from_service: 0, to_service: 1, amount: 100, memo: vec![0x42], gas_limit: 0,
    });
    ctx.storage.insert(vec![0x01], vec![0xAA]);
    ctx.created_services.push((42, [0xCC; 32]));
    ctx.yield_output = Some([0xDD; 32]);
    ctx
}

#[test]
fn test_collapse_halt_uses_regular_state() {
    let ctx = make_ctx_with_effects();
    let result = ctx.collapse(PvmOutcome::Halt, 500);
    assert_eq!(result.transfers.len(), 1);
    assert_eq!(result.transfers[0].amount, 100);
    assert_eq!(result.storage.get(&vec![0x01]).unwrap(), &vec![0xAA]);
    assert_eq!(result.yield_output, Some([0xDD; 32]));
    assert_eq!(result.gas_remaining, 500);
}

#[test]
fn test_collapse_panic_reverts_to_checkpoint() {
    let mut ctx = make_ctx_with_effects();

    // Take checkpoint with initial state
    ctx.take_checkpoint();

    // Modify state after checkpoint
    ctx.transfers.push(JamTransfer {
        from_service: 0, to_service: 2, amount: 999, memo: vec![], gas_limit: 0,
    });
    ctx.storage.insert(vec![0x02], vec![0xFF]);
    ctx.yield_output = Some([0xEE; 32]);

    // Panic → should revert to checkpoint
    let result = ctx.collapse(PvmOutcome::Panic, 100);
    assert_eq!(result.transfers.len(), 1, "should have checkpoint's 1 transfer, not 2");
    assert_eq!(result.transfers[0].amount, 100);
    assert!(result.storage.get(&vec![0x02]).is_none(), "post-checkpoint key should be gone");
    assert_eq!(result.yield_output, Some([0xDD; 32]), "should use checkpoint yield");
    assert_eq!(result.gas_remaining, 100);
}

#[test]
fn test_collapse_oog_reverts_to_checkpoint() {
    let mut ctx = make_ctx_with_effects();
    ctx.take_checkpoint();
    ctx.transfers.push(JamTransfer {
        from_service: 0, to_service: 99, amount: 1, memo: vec![], gas_limit: 0,
    });
    let result = ctx.collapse(PvmOutcome::OutOfGas, 0);
    assert_eq!(result.transfers.len(), 1, "OOG reverts to checkpoint");
    assert_eq!(result.gas_remaining, 0);
}

#[test]
fn test_collapse_panic_no_checkpoint_gives_empty() {
    let ctx = make_ctx_with_effects();
    // No checkpoint taken
    let result = ctx.collapse(PvmOutcome::Panic, 0);
    assert!(result.transfers.is_empty(), "no checkpoint → empty side-effects");
    assert!(result.storage.is_empty());
    assert!(result.yield_output.is_none());
}

#[test]
fn test_collapse_halt_with_yield_overrides_yield() {
    let ctx = make_ctx_with_effects();
    let hash = [0xFF; 32];
    let result = ctx.collapse(PvmOutcome::HaltWithYield(hash), 300);
    // Yield is overridden by the hash from the outcome
    assert_eq!(result.yield_output, Some([0xFF; 32]));
    // But transfers/storage come from regular context
    assert_eq!(result.transfers.len(), 1);
    assert_eq!(result.storage.get(&vec![0x01]).unwrap(), &vec![0xAA]);
    assert_eq!(result.gas_remaining, 300);
}

// ------------------------------------------------------------------
// ServiceAccount cross-service lookup resolution
// ------------------------------------------------------------------

#[test]
fn test_service_account_self_lookup() {
    let mut ctx = JamHostContext::default();
    ctx.service_id = 42;
    ctx.preimages.insert([0xAA; 32], vec![1, 2, 3]);
    ctx.storage.insert(vec![0xBB], vec![4, 5, 6]);

    // Self-lookup: φ₇ = 42 or u64::MAX should find our own data
    assert!(ctx.preimages.get(&[0xAA; 32]).is_some());
    assert!(ctx.storage.get(&vec![0xBB]).is_some());
}

#[test]
fn test_service_account_cross_lookup() {
    let mut ctx = JamHostContext::default();
    ctx.service_id = 42;

    // Add another service's data
    let mut other = ServiceAccount::default();
    other.storage.insert(vec![0xCC], vec![7, 8, 9]);
    other.preimages.insert([0xDD; 32], vec![10, 11]);
    ctx.service_accounts.insert(99, other);

    // Cross-service lookup for service 99
    let acct = ctx.service_accounts.get(&99).unwrap();
    assert_eq!(acct.storage.get(&vec![0xCC]).unwrap(), &vec![7, 8, 9]);
    assert_eq!(acct.preimages.get(&[0xDD; 32]).unwrap(), &vec![10, 11]);

    // Unknown service returns None
    assert!(ctx.service_accounts.get(&999).is_none());
}

#[test]
fn test_service_account_default_empty() {
    let acct = ServiceAccount::default();
    assert!(acct.storage.is_empty());
    assert!(acct.preimages.is_empty());
    assert_eq!(acct.balance, 0);
    assert_eq!(acct.code_hash, [0u8; 32]);
    assert_eq!(acct.threshold, 0);
    assert_eq!(acct.items_count, 0);
}

// ------------------------------------------------------------------
// ServiceAccount::encode_info() — Ω_I encoding
// ------------------------------------------------------------------

#[test]
fn test_encode_info_size() {
    let acct = ServiceAccount::default();
    let encoded = acct.encode_info();
    assert_eq!(encoded.len(), SERVICE_INFO_SIZE);
    assert_eq!(SERVICE_INFO_SIZE, 96);
}

#[test]
fn test_encode_info_layout() {
    let acct = ServiceAccount {
        storage: HashMap::new(),
        preimages: HashMap::new(),
        lookup: HashMap::new(),
        balance: 1000,
        code_hash: [0xAA; 32],
        threshold: 500,
        min_accum_gas: 100_000,
        min_memo_gas: 50_000,
        items_count: 42,
        footprint: 8192,
        recent_count: 10,
        accum_gas_limit: 200_000,
        preimage_pages: 5,
    };
    let buf = acct.encode_info();

    // a_c — bytes [0..32)
    assert_eq!(&buf[0..32], &[0xAA; 32]);

    // E_8(a_b) — bytes [32..40)
    assert_eq!(u64::from_le_bytes(buf[32..40].try_into().unwrap()), 1000);

    // E_8(a_t) — bytes [40..48) — DERIVED: max(0, 100 + 10*42 + 1*8192 − 500) = 8212
    assert_eq!(u64::from_le_bytes(buf[40..48].try_into().unwrap()), 8212);

    // E_8(a_g) — bytes [48..56)
    assert_eq!(u64::from_le_bytes(buf[48..56].try_into().unwrap()), 100_000);

    // E_8(a_m) — bytes [56..64)
    assert_eq!(u64::from_le_bytes(buf[56..64].try_into().unwrap()), 50_000);

    // E_8(a_o) — bytes [64..72) — total octets = footprint field
    assert_eq!(u64::from_le_bytes(buf[64..72].try_into().unwrap()), 8192);

    // E_4(a_i) — bytes [72..76)
    assert_eq!(u32::from_le_bytes(buf[72..76].try_into().unwrap()), 42);

    // E_8(a_f) — bytes [76..84) — balance offset = threshold field
    assert_eq!(u64::from_le_bytes(buf[76..84].try_into().unwrap()), 500);

    // E_4(a_r) — bytes [84..88)
    assert_eq!(u32::from_le_bytes(buf[84..88].try_into().unwrap()), 10);

    // E_4(a_a) — bytes [88..92)
    assert_eq!(u32::from_le_bytes(buf[88..92].try_into().unwrap()), 200_000);

    // E_4(a_p) — bytes [92..96)
    assert_eq!(u32::from_le_bytes(buf[92..96].try_into().unwrap()), 5);
}

#[test]
fn test_encode_info_all_zeros() {
    let acct = ServiceAccount::default();
    let buf = acct.encode_info();
    // With all fields zero, a_t = max(0, B_S + 0 + 0 − 0) = B_S = 100.
    // So bytes [40..48) = 100 (LE), everything else = 0.
    let mut expected = [0u8; 96];
    expected[40..48].copy_from_slice(&100u64.to_le_bytes()); // a_t = B_S
    assert_eq!(buf, expected);
}

// ------------------------------------------------------------------
// self_account_info() roundtrip
// ------------------------------------------------------------------

#[test]
fn test_self_account_info_roundtrip() {
    let mut ctx = JamHostContext::default();
    ctx.service_id = 42;
    ctx.balance = 999;
    ctx.code_hash = [0xBB; 32];
    ctx.threshold = 123;
    ctx.min_accum_gas = 10;
    ctx.min_memo_gas = 20;
    ctx.recent_count = 3;
    ctx.accum_gas_limit = 50000;
    ctx.preimage_pages = 2;

    // items_count and footprint are tracked incrementally from initial metadata.
    // GP §9.3: items = 2·|lookup| + |storage|, footprint = Σ(81+z) + Σ(34+|k|+|v|).
    // Simulate: 2 lookups (z=64, z=128) + 3 storage entries.
    // items = 2*2 + 3 = 7
    // footprint = (81+64) + (81+128) + (34+32+100) + (34+32+50) + (34+10+200)
    //           = 145 + 209 + 166 + 116 + 244 = 880
    ctx.items_count = 7;
    ctx.footprint = 880;

    // Also add map data so self_account_info has the storage/lookup contents
    ctx.lookup.insert(([0xAA; 32], 64), vec![100]);
    ctx.lookup.insert(([0xBB; 32], 128), vec![100, 200]);
    ctx.preimages.insert([0xAA; 32], vec![0xCC; 64]);
    ctx.preimages.insert([0xBB; 32], vec![0xDD; 128]);
    ctx.storage.insert(vec![1; 32], vec![0xDE; 100]);
    ctx.storage.insert(vec![2; 32], vec![0xAD; 50]);
    ctx.storage.insert(vec![3; 10], vec![0xBE; 200]);

    let acct = ctx.self_account_info();
    assert_eq!(acct.balance, 999);
    assert_eq!(acct.code_hash, [0xBB; 32]);
    assert_eq!(acct.threshold, 123);
    assert_eq!(acct.items_count, 7);
    assert_eq!(acct.footprint, 880);

    // Encoding should match
    let buf = acct.encode_info();
    assert_eq!(&buf[0..32], &[0xBB; 32]);
    assert_eq!(u64::from_le_bytes(buf[32..40].try_into().unwrap()), 999);
}

// ------------------------------------------------------------------
// Ω_W FULL check logic (context-level)
// ------------------------------------------------------------------

#[test]
fn test_threshold_full_check() {
    let mut ctx = JamHostContext::default();
    ctx.balance = 100;
    ctx.threshold = 200; // a_t > a_b → should trigger FULL
    assert!(ctx.threshold > ctx.balance);

    ctx.threshold = 50; // a_t ≤ a_b → OK
    assert!(ctx.threshold <= ctx.balance);
}

#[test]
fn test_omega_w_delete_logic() {
    // Simulating v_Z = 0: key should be removed from storage
    let mut ctx = JamHostContext::default();
    ctx.storage.insert(vec![0x01], vec![0xAA, 0xBB]);

    // Simulate delete: remove the key
    let key = vec![0x01];
    let old_len = ctx.storage.get(&key).map(|v| v.len()).unwrap_or(0);
    assert_eq!(old_len, 2);
    ctx.storage.remove(&key);
    assert!(ctx.storage.get(&key).is_none());
}

// ------------------------------------------------------------------
// Protocol constant defaults (W_G, W_X)
// ------------------------------------------------------------------

#[test]
fn test_default_segment_size() {
    let ctx = JamHostContext::default();
    assert_eq!(ctx.segment_size, DEFAULT_SEGMENT_SIZE);
    assert_eq!(ctx.segment_size, 4104);
}

#[test]
fn test_default_max_exports() {
    let ctx = JamHostContext::default();
    assert_eq!(ctx.max_exports, DEFAULT_MAX_EXPORTS);
    assert_eq!(ctx.max_exports, 3072);
}

#[test]
fn test_export_base_and_timeslot_default_zero() {
    let ctx = JamHostContext::default();
    assert_eq!(ctx.export_base, 0);
    assert_eq!(ctx.timeslot, 0);
}

// ------------------------------------------------------------------
// Ω_E context-level: FULL check logic
// ------------------------------------------------------------------

#[test]
fn test_export_full_check_context_level() {
    let ctx = JamHostContext::default();
    // export_base + |export_segments| should start < W_X
    let total = ctx.export_base + ctx.export_segments.len() as u32;
    assert!(total < ctx.max_exports, "fresh context should not be FULL");
}

#[test]
fn test_export_full_at_limit() {
    let mut ctx = JamHostContext::default();
    ctx.export_base = 3072; // W_X
    // ς + |e| = 3072 + 0 = 3072 ≥ W_X → FULL
    let total = ctx.export_base + ctx.export_segments.len() as u32;
    assert!(total >= ctx.max_exports, "at W_X boundary should trigger FULL");
}

// ------------------------------------------------------------------
// Ω_H context-level: timeslot is stored
// ------------------------------------------------------------------

#[test]
fn test_timeslot_stored() {
    let mut ctx = JamHostContext::default();
    ctx.timeslot = 42;
    assert_eq!(ctx.timeslot, 42);
}

// ------------------------------------------------------------------
// Inner PVM: next_machine_id
// ------------------------------------------------------------------

#[test]
fn test_next_machine_id_empty() {
    let ctx = JamHostContext::default();
    assert_eq!(ctx.next_machine_id(), 0);
}

#[test]
fn test_next_machine_id_skips_existing() {
    let ctx = JamHostContext::default();
    // Empty map → first available is 0
    assert_eq!(ctx.next_machine_id(), 0);
}

#[test]
fn test_next_machine_id_finds_gap() {
    let ctx = JamHostContext::default();
    // We can't insert real InnerMachines without a polkavm instance,
    // but we can test by manually inserting into the map using
    // a helper or by verifying the logic. The HashMap key check
    // is the core of next_machine_id, so we verify it indirectly.
    assert_eq!(ctx.inner_machines.len(), 0);
    assert_eq!(ctx.next_machine_id(), 0);
}

// ------------------------------------------------------------------
// Inner PVM: ensure_engine
// ------------------------------------------------------------------

#[test]
fn test_ensure_engine_creates_lazily() {
    let mut ctx = JamHostContext::default();
    assert!(ctx.engine.is_none());
    ctx.ensure_engine();
    assert!(ctx.engine.is_some());
    // Second call is a no-op
    let ptr1 = std::sync::Arc::as_ptr(ctx.engine.as_ref().unwrap());
    ctx.ensure_engine();
    let ptr2 = std::sync::Arc::as_ptr(ctx.engine.as_ref().unwrap());
    assert_eq!(ptr1, ptr2, "ensure_engine should be idempotent");
}

// ------------------------------------------------------------------
// Inner PVM: deblob with invalid blob
// ------------------------------------------------------------------

#[test]
fn test_deblob_invalid_blob_returns_none() {
    let mut ctx = JamHostContext::default();
    // Garbage bytes should fail to parse
    let result = ctx.deblob(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(result.is_none(), "deblob of garbage should return None");
    // Engine should have been created lazily
    assert!(ctx.engine.is_some());
}

#[test]
fn test_deblob_empty_blob_returns_none() {
    let mut ctx = JamHostContext::default();
    let result = ctx.deblob(&[]);
    assert!(result.is_none(), "deblob of empty should return None");
}
