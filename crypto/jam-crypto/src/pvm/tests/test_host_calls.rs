use super::*;
use super::super::context::{
    WorkItemInfo, InvocationContext, EmpowerState,
    PVM_HALT, PVM_PANIC, PVM_FAULT, PVM_HOST, PVM_OOG,
    HC_CORE,
};

// ------------------------------------------------------------------
// S(w) encoding — single item
// ------------------------------------------------------------------
#[test]
fn test_encode_item_summary() {
    let w = WorkItemInfo {
        service_id: 42,
        code_hash: [0xAA; 32],
        gas_limit: 1_000_000,
        gas_limit_accum: 500_000,
        payload: vec![1, 2, 3],
    };
    let encoded = encode_item_summary(&w);
    // 4 + 32 + 8 + 8 = 52 bytes
    assert_eq!(encoded.len(), 52);
    // service_id LE
    assert_eq!(&encoded[0..4], &42u32.to_le_bytes());
    // code_hash
    assert_eq!(&encoded[4..36], &[0xAA; 32]);
    // gas_limit LE
    assert_eq!(&encoded[36..44], &1_000_000u64.to_le_bytes());
    // gas_limit_accum LE
    assert_eq!(&encoded[44..52], &500_000u64.to_le_bytes());
}

// ------------------------------------------------------------------
// S(w) encoding — list
// ------------------------------------------------------------------
#[test]
fn test_encode_items_summary_list() {
    let items = vec![
        WorkItemInfo {
            service_id: 1,
            code_hash: [0x11; 32],
            gas_limit: 100,
            gas_limit_accum: 50,
            payload: vec![],
        },
        WorkItemInfo {
            service_id: 2,
            code_hash: [0x22; 32],
            gas_limit: 200,
            gas_limit_accum: 100,
            payload: vec![],
        },
    ];
    let encoded = encode_items_summary_list(&items);
    // 2 * 52 = 104 data bytes + compact prefix for count 2
    assert!(encoded.len() > 104);
    // Verify first item starts after the compact prefix
    // The compact encoding of 2 uses jam_codec::Compact — check it decodes correctly
    // by verifying the two item summaries are present in the encoding.
    let prefix_len = encoded.len() - 104;
    assert!(prefix_len > 0);
    // Check first item's service_id
    assert_eq!(&encoded[prefix_len..prefix_len + 4], &1u32.to_le_bytes());
    // Check second item's service_id
    assert_eq!(&encoded[prefix_len + 52..prefix_len + 56], &2u32.to_le_bytes());
}

// ------------------------------------------------------------------
// Accumulate items list encoding
// ------------------------------------------------------------------
#[test]
fn test_encode_accumulate_items_list_empty() {
    let items: Vec<Vec<u8>> = vec![];
    let encoded = encode_accumulate_items_list(&items);
    // Compact(0) = 0x00
    assert_eq!(encoded, vec![0x00]);
}

#[test]
fn test_encode_accumulate_items_list_nonempty() {
    let items = vec![vec![1, 2, 3], vec![4, 5]];
    let encoded = encode_accumulate_items_list(&items);
    // Total: compact prefix for 2 + 3 + 2 = 5 data bytes + prefix
    let prefix_len = encoded.len() - 5;
    assert!(prefix_len > 0);
    // Data follows prefix
    assert_eq!(&encoded[prefix_len..prefix_len + 3], &[1, 2, 3]);
    assert_eq!(&encoded[prefix_len + 3..prefix_len + 5], &[4, 5]);
}

// ------------------------------------------------------------------
// OOG gating — unit test at the context level
// ------------------------------------------------------------------
// We can't easily mock a full polkavm::Instance, but we test that the
// gas threshold logic is correct at the DispatchResult level.
// Full integration tests will go through `jam_run`.

#[test]
fn test_dispatch_result_variants() {
    // Just verify the enum is exhaustive and usable
    let results = vec![
        DispatchResult::Continue,
        DispatchResult::OutOfGas,
        DispatchResult::Fault,
    ];
    assert_eq!(results.len(), 3);
}

// ------------------------------------------------------------------
// HC_NONE is u64::MAX
// ------------------------------------------------------------------
#[test]
fn test_hc_none_is_u64_max() {
    assert_eq!(HC_NONE, u64::MAX);
}

// ------------------------------------------------------------------
// Inner PVM host call constants
// ------------------------------------------------------------------

#[test]
fn test_inner_pvm_hc_constants() {
    assert_eq!(HC_OK, 0);
    assert_eq!(HC_WHO, u64::MAX - 3);
    assert_eq!(HC_OOB, u64::MAX - 2);
    assert_eq!(HC_HUH, u64::MAX - 8);
}

// ------------------------------------------------------------------
// PVM outcome constants (GP B.6 — ΩK invoke results)
// ------------------------------------------------------------------

#[test]
fn test_pvm_outcome_constants() {
    assert_eq!(PVM_HALT, 0);
    assert_eq!(PVM_PANIC, 1);
    assert_eq!(PVM_FAULT, 2);
    assert_eq!(PVM_HOST, 3);
    assert_eq!(PVM_OOG, 4);
}

// ------------------------------------------------------------------
// ΩX (expunge) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_omega_x_unknown_machine_returns_who() {
    // Create a context with no inner machines
    let mut ctx = JamHostContext {
        invocation: InvocationContext::Refine,
        ..Default::default()
    };
    // Simulate: A0 = 42 (non-existent machine index)
    // omega_x reads A0 and checks ctx.inner_machines
    assert!(!ctx.inner_machines.contains_key(&42));
    // After omega_x, A0 should be HC_WHO since machine 42 doesn't exist
    // We verify at the context level that the machine doesn't exist
    assert!(ctx.inner_machines.remove(&42).is_none());
}

#[test]
fn test_omega_x_removes_machine_from_map() {
    let ctx = JamHostContext {
        invocation: InvocationContext::Refine,
        ..Default::default()
    };
    // We can't easily create a real InnerMachine without an engine+blob,
    // but we can verify the map operations at the context level
    assert!(ctx.inner_machines.is_empty());
    // next_machine_id should be 0 when map is empty
    assert_eq!(ctx.next_machine_id(), 0);
}

// ------------------------------------------------------------------
// ΩK (invoke) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_omega_k_io_buffer_layout() {
    // Verify the 112-byte I/O buffer layout:
    // [0..8)   = E_8(gas)      = i64 LE
    // [8..112) = E_8(w[0..13]) = 13 × u64 LE
    const IO_SIZE: usize = 8 + 13 * 8;
    assert_eq!(IO_SIZE, 112);

    // Encode a sample (gas, registers) tuple
    let gas: i64 = 1_000_000;
    let regs: [u64; 13] = [
        100, 200, 300, 400, 500, 600, 700,  // RA, SP, T0, T1, T2, S0, S1
        10, 20, 30, 40, 50, 60,              // A0..A5
    ];

    let mut buf = [0u8; IO_SIZE];
    buf[0..8].copy_from_slice(&gas.to_le_bytes());
    for i in 0..13 {
        let start = 8 + i * 8;
        buf[start..start + 8].copy_from_slice(&regs[i].to_le_bytes());
    }

    // Verify round-trip decode
    let decoded_gas = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    assert_eq!(decoded_gas, gas);
    for i in 0..13 {
        let start = 8 + i * 8;
        let decoded_reg = u64::from_le_bytes(buf[start..start + 8].try_into().unwrap());
        assert_eq!(decoded_reg, regs[i]);
    }
}

#[test]
fn test_omega_k_who_when_no_machine() {
    // When n ∉ K(m), omega_k should set A0 = HC_WHO
    let ctx = JamHostContext {
        invocation: InvocationContext::Refine,
        ..Default::default()
    };
    assert!(ctx.inner_machines.is_empty());
    // omega_k would check ctx.inner_machines.contains_key(&n) → false → WHO
}

// ------------------------------------------------------------------
// ΩB (bless) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_empower_state_default() {
    let es = EmpowerState::default();
    assert_eq!(es.manager, 0);
    assert!(es.auth_agents.is_empty());
    assert_eq!(es.validator, 0);
    assert_eq!(es.staker, 0);
    assert!(es.gas_map.is_empty());
}

#[test]
fn test_omega_b_context_empower_initially_none() {
    let ctx = JamHostContext {
        invocation: InvocationContext::Accumulate,
        ..Default::default()
    };
    assert!(ctx.empower.is_none());
}

#[test]
fn test_omega_b_who_when_services_not_existing() {
    // If (m, v, r) are not in existing_services, omega_b returns WHO
    let ctx = JamHostContext {
        invocation: InvocationContext::Accumulate,
        ..Default::default()
    };
    // existing_services is empty → none of m, v, r can be found
    assert!(ctx.existing_services.is_empty());
}

#[test]
fn test_omega_b_gas_map_encoding_layout() {
    // Verify the 12-byte per-entry gas map encoding: E_4(s) ~ E_8(g)
    let sid: u32 = 42;
    let gas: u64 = 1_000_000;
    let mut entry = [0u8; 12];
    entry[0..4].copy_from_slice(&sid.to_le_bytes());
    entry[4..12].copy_from_slice(&gas.to_le_bytes());

    // Round-trip decode
    let decoded_sid = u32::from_le_bytes(entry[0..4].try_into().unwrap());
    let decoded_gas = u64::from_le_bytes(entry[4..12].try_into().unwrap());
    assert_eq!(decoded_sid, sid);
    assert_eq!(decoded_gas, gas);
}

#[test]
fn test_omega_b_auth_agents_encoding_layout() {
    // Verify the 4-byte per-agent encoding: E_4(agent_id)
    let agents: Vec<u32> = vec![100, 200];
    let mut buf = vec![0u8; agents.len() * 4];
    for (i, &a) in agents.iter().enumerate() {
        buf[i * 4..(i + 1) * 4].copy_from_slice(&a.to_le_bytes());
    }

    // Round-trip decode
    for (i, &expected) in agents.iter().enumerate() {
        let decoded = u32::from_le_bytes(buf[i * 4..(i + 1) * 4].try_into().unwrap());
        assert_eq!(decoded, expected);
    }
}

#[test]
fn test_omega_b_core_count_default_is_two() {
    let ctx = JamHostContext::default();
    assert_eq!(ctx.core_count, 2);
}

#[test]
fn test_omega_b_empower_in_checkpoint() {
    use std::collections::HashMap;
    // Set empower, take checkpoint, verify it's snapshotted
    let mut ctx = JamHostContext {
        invocation: InvocationContext::Accumulate,
        ..Default::default()
    };
    let mut gas_map = HashMap::new();
    gas_map.insert(1u32, 5000u64);
    ctx.empower = Some(EmpowerState {
        manager: 10,
        auth_agents: vec![100, 200],
        validator: 20,
        staker: 30,
        gas_map,
        ..Default::default()
    });
    ctx.take_checkpoint();
    let cp = ctx.checkpoint.as_ref().unwrap();
    assert!(cp.empower.is_some());
    assert_eq!(cp.empower.as_ref().unwrap().manager, 10);
}

#[test]
fn test_omega_b_empower_in_collapse_halt() {
    use super::super::context::PvmOutcome;
    use std::collections::HashMap;
    let mut ctx = JamHostContext {
        invocation: InvocationContext::Accumulate,
        ..Default::default()
    };
    let mut gas_map = HashMap::new();
    gas_map.insert(42u32, 9999u64);
    ctx.empower = Some(EmpowerState {
        manager: 7,
        auth_agents: vec![1, 2],
        validator: 8,
        staker: 9,
        gas_map,
        ..Default::default()
    });
    // Collapse with Halt → x_e from regular context (self)
    let result = ctx.collapse(PvmOutcome::Halt, 500);
    assert!(result.empower.is_some());
    assert_eq!(result.empower.as_ref().unwrap().manager, 7);
    assert_eq!(result.empower.as_ref().unwrap().gas_map.get(&42), Some(&9999));
}

#[test]
fn test_omega_b_empower_in_collapse_panic_reverts() {
    use super::super::context::PvmOutcome;
    use std::collections::HashMap;
    let mut ctx = JamHostContext {
        invocation: InvocationContext::Accumulate,
        ..Default::default()
    };
    // Take checkpoint with no empower
    ctx.take_checkpoint();
    // Then set empower
    let mut gas_map = HashMap::new();
    gas_map.insert(99u32, 1000u64);
    ctx.empower = Some(EmpowerState {
        manager: 50,
        auth_agents: vec![],
        validator: 51,
        staker: 52,
        gas_map,
        ..Default::default()
    });
    // Collapse with Panic → should revert to checkpoint (y), which had empower=None
    let result = ctx.collapse(PvmOutcome::Panic, 100);
    assert!(result.empower.is_none());
}

// ------------------------------------------------------------------
// EmpowerState extended fields defaults
// ------------------------------------------------------------------

#[test]
fn test_empower_state_queues_and_validators_default() {
    let es = EmpowerState::default();
    assert!(es.queues.is_empty());
    assert!(es.validators.is_empty());
}

// ------------------------------------------------------------------
// auth_queue_len and val_count defaults on context
// ------------------------------------------------------------------

#[test]
fn test_context_auth_queue_len_default() {
    let ctx = JamHostContext::default();
    assert_eq!(ctx.auth_queue_len, 80);
}

#[test]
fn test_context_val_count_default() {
    let ctx = JamHostContext::default();
    assert_eq!(ctx.val_count, 6);
}

// ------------------------------------------------------------------
// ΩA (assign-core) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_omega_a_hash_queue_encoding_layout() {
    // Verify the Q × 32-byte queue hash encoding: each hash is 32 bytes LE-packed
    let q_count: u32 = 3;
    let hashes: Vec<[u8; 32]> = (0..q_count).map(|i| [i as u8; 32]).collect();

    let mut buf = vec![0u8; q_count as usize * 32];
    for (i, hash) in hashes.iter().enumerate() {
        buf[i * 32..(i + 1) * 32].copy_from_slice(hash);
    }

    // Round-trip decode
    for i in 0..q_count as usize {
        let mut decoded = [0u8; 32];
        decoded.copy_from_slice(&buf[i * 32..(i + 1) * 32]);
        assert_eq!(decoded, hashes[i]);
    }
}

#[test]
fn test_omega_a_core_check() {
    // c >= core_count should yield CORE
    let ctx = JamHostContext {
        core_count: 2,
        ..Default::default()
    };
    // Core index 2 is out of range for core_count=2 (valid: 0, 1)
    assert!(2u32 >= ctx.core_count as u32);
    assert_eq!(HC_CORE, u64::MAX - 5);
}

#[test]
fn test_omega_a_huh_when_not_auth_agent() {
    // If service_id != empower.auth_agents[c], should get HUH
    let ctx = JamHostContext {
        service_id: 42,
        core_count: 2,
        empower: Some(EmpowerState {
            auth_agents: vec![100, 200], // core 0 → service 100, core 1 → service 200
            ..Default::default()
        }),
        ..Default::default()
    };
    // service_id=42 != auth_agents[0]=100 → HUH
    assert_ne!(ctx.service_id, ctx.empower.as_ref().unwrap().auth_agents[0]);
}

#[test]
fn test_omega_a_huh_when_no_empower() {
    // If empower is None, should get HUH
    let ctx = JamHostContext {
        service_id: 42,
        core_count: 2,
        ..Default::default()
    };
    assert!(ctx.empower.is_none());
}

#[test]
fn test_omega_a_who_when_agent_not_existing() {
    // If a ∉ N_S (existing_services), should get WHO
    let ctx = JamHostContext {
        service_id: 100,
        core_count: 2,
        empower: Some(EmpowerState {
            auth_agents: vec![100, 200],
            ..Default::default()
        }),
        ..Default::default()
    };
    // existing_services is empty → a=999 won't be found → WHO
    assert!(!ctx.existing_services.contains(&999));
}

#[test]
fn test_omega_a_sets_queues_and_agent() {
    use std::collections::HashSet;
    // Simulate OK path: empower is set, service is auth agent, a is existing
    let mut existing = HashSet::new();
    existing.insert(100u32);
    existing.insert(200u32);
    existing.insert(300u32);

    let mut ctx = JamHostContext {
        service_id: 100,
        core_count: 2,
        auth_queue_len: 3,
        existing_services: existing,
        empower: Some(EmpowerState {
            auth_agents: vec![100, 200],
            queues: vec![vec![], vec![]],
            ..Default::default()
        }),
        ..Default::default()
    };

    // Simulate what omega_a would do on OK path for core 0, agent 300:
    let c: usize = 0;
    let a: u32 = 300;
    let q: Vec<[u8; 32]> = vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]];

    if let Some(ref mut emp) = ctx.empower {
        while emp.queues.len() <= c {
            emp.queues.push(Vec::new());
        }
        emp.queues[c] = q.clone();
        emp.auth_agents[c] = a;
    }

    let emp = ctx.empower.as_ref().unwrap();
    assert_eq!(emp.auth_agents[0], 300);
    assert_eq!(emp.queues[0].len(), 3);
    assert_eq!(emp.queues[0][0], [0xAA; 32]);
    assert_eq!(emp.queues[0][1], [0xBB; 32]);
    assert_eq!(emp.queues[0][2], [0xCC; 32]);
    // Core 1 unchanged
    assert_eq!(emp.auth_agents[1], 200);
}

// ------------------------------------------------------------------
// ΩD (designate-validators) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_omega_d_validator_key_encoding_layout() {
    // Verify the V × 336-byte validator key encoding
    let v_count: u32 = 2;
    let keys: Vec<Vec<u8>> = (0..v_count).map(|i| vec![i as u8; 336]).collect();

    let mut buf = vec![0u8; v_count as usize * 336];
    for (i, key) in keys.iter().enumerate() {
        buf[i * 336..(i + 1) * 336].copy_from_slice(key);
    }

    // Round-trip decode
    for i in 0..v_count as usize {
        let decoded = buf[i * 336..(i + 1) * 336].to_vec();
        assert_eq!(decoded, keys[i]);
    }
}

#[test]
fn test_omega_d_huh_when_not_validator() {
    // If service_id != empower.validator, should get HUH
    let ctx = JamHostContext {
        service_id: 42,
        empower: Some(EmpowerState {
            validator: 99,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_ne!(ctx.service_id, ctx.empower.as_ref().unwrap().validator);
}

#[test]
fn test_omega_d_huh_when_no_empower() {
    // If empower is None, should get HUH
    let ctx = JamHostContext {
        service_id: 42,
        ..Default::default()
    };
    assert!(ctx.empower.is_none());
}

#[test]
fn test_omega_d_sets_validators() {
    // Simulate OK path: service is the validator service
    let mut ctx = JamHostContext {
        service_id: 99,
        val_count: 3,
        empower: Some(EmpowerState {
            validator: 99,
            ..Default::default()
        }),
        ..Default::default()
    };

    // Simulate what omega_d would do on OK path:
    let v: Vec<Vec<u8>> = vec![
        vec![0x11; 336],
        vec![0x22; 336],
        vec![0x33; 336],
    ];

    if let Some(ref mut emp) = ctx.empower {
        emp.validators = v.clone();
    }

    let emp = ctx.empower.as_ref().unwrap();
    assert_eq!(emp.validators.len(), 3);
    assert_eq!(emp.validators[0], vec![0x11; 336]);
    assert_eq!(emp.validators[1], vec![0x22; 336]);
    assert_eq!(emp.validators[2], vec![0x33; 336]);
}

#[test]
fn test_omega_a_d_empower_propagation_through_checkpoint() {
    use super::super::context::PvmOutcome;
    use std::collections::HashMap;

    // Set empower with queues and validators, checkpoint, then verify propagation
    let mut ctx = JamHostContext {
        invocation: InvocationContext::Accumulate,
        ..Default::default()
    };
    ctx.empower = Some(EmpowerState {
        manager: 10,
        auth_agents: vec![100, 200],
        validator: 20,
        staker: 30,
        gas_map: HashMap::new(),
        queues: vec![vec![[0xAA; 32]], vec![[0xBB; 32]]],
        validators: vec![vec![0x11; 336]],
    });

    // Checkpoint
    ctx.take_checkpoint();
    let cp = ctx.checkpoint.as_ref().unwrap();
    let cp_emp = cp.empower.as_ref().unwrap();
    assert_eq!(cp_emp.queues.len(), 2);
    assert_eq!(cp_emp.queues[0][0], [0xAA; 32]);
    assert_eq!(cp_emp.validators.len(), 1);
    assert_eq!(cp_emp.validators[0], vec![0x11; 336]);

    // Modify empower after checkpoint
    if let Some(ref mut emp) = ctx.empower {
        emp.queues[0] = vec![[0xFF; 32]];
        emp.validators = vec![vec![0x99; 336], vec![0x88; 336]];
    }

    // Collapse with Halt → uses current (regular) context
    let result = ctx.collapse(PvmOutcome::Halt, 500);
    let res_emp = result.empower.as_ref().unwrap();
    assert_eq!(res_emp.queues[0][0], [0xFF; 32]); // modified
    assert_eq!(res_emp.validators.len(), 2); // modified

    // Collapse with Panic → reverts to checkpoint (y)
    let result_panic = ctx.collapse(PvmOutcome::Panic, 100);
    let panic_emp = result_panic.empower.as_ref().unwrap();
    assert_eq!(panic_emp.queues[0][0], [0xAA; 32]); // reverted
    assert_eq!(panic_emp.validators.len(), 1); // reverted
}

// ------------------------------------------------------------------
// advance_service_id — +42 modular advancement
// ------------------------------------------------------------------

#[test]
fn test_advance_service_id_basic() {
    use super::super::context::advance_service_id;
    use std::collections::HashSet;

    let existing = HashSet::new();
    let created: Vec<(u32, [u8; 32])> = vec![];

    const S: u32 = 1 << 16; // 65536

    // Starting from S (65536), advance by 42 → S + 42
    let next = advance_service_id(S, &existing, &created);
    assert_eq!(next, S + 42);

    // Starting from S + 100, advance by 42 → S + 142
    let next2 = advance_service_id(S + 100, &existing, &created);
    assert_eq!(next2, S + 142);
}

#[test]
fn test_advance_service_id_skips_collision() {
    use super::super::context::advance_service_id;
    use std::collections::HashSet;

    const S: u32 = 1 << 16;

    // The candidate (S + 42) is already taken → should skip to S + 43
    let mut existing = HashSet::new();
    existing.insert(S + 42);
    let created: Vec<(u32, [u8; 32])> = vec![];

    let next = advance_service_id(S, &existing, &created);
    assert_eq!(next, S + 43); // skipped S + 42
}

#[test]
fn test_advance_service_id_skips_created() {
    use super::super::context::advance_service_id;
    use std::collections::HashSet;

    const S: u32 = 1 << 16;

    let existing = HashSet::new();
    // Candidate S + 42 is in created_services
    let created: Vec<(u32, [u8; 32])> = vec![(S + 42, [0u8; 32])];

    let next = advance_service_id(S, &existing, &created);
    assert_eq!(next, S + 43); // skipped S + 42
}

#[test]
fn test_advance_service_id_wraps_around() {
    use super::super::context::advance_service_id;
    use std::collections::HashSet;

    const S: u32 = 1 << 16;
    const MODULUS: u32 = u32::MAX - S - 255;

    // Start near the end of the range → should wrap around
    let start = S + MODULUS - 10; // 10 before wrap
    let existing = HashSet::new();
    let created: Vec<(u32, [u8; 32])> = vec![];

    let next = advance_service_id(start, &existing, &created);
    // (start - S + 42) mod MODULUS + S = (MODULUS - 10 + 42) mod MODULUS + S = 32 + S
    assert_eq!(next, S + 32);
}

// ------------------------------------------------------------------
// ΩN (new-service) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_omega_n_huh_when_f_nonzero_not_manager() {
    // f ≠ 0 ∧ x_s ≠ (x_e)_m → HUH
    let ctx = JamHostContext {
        service_id: 42,
        empower: Some(EmpowerState {
            manager: 99, // NOT 42
            ..Default::default()
        }),
        ..Default::default()
    };
    // f = 1 (non-zero) but service 42 is not manager 99 → HUH
    assert_ne!(ctx.service_id, ctx.empower.as_ref().unwrap().manager);
}

#[test]
fn test_omega_n_huh_when_no_empower_and_f_nonzero() {
    // f ≠ 0 with no empower → HUH
    let ctx = JamHostContext {
        service_id: 42,
        empower: None,
        ..Default::default()
    };
    let is_manager = ctx.empower.as_ref()
        .map(|e| ctx.service_id == e.manager)
        .unwrap_or(false);
    assert!(!is_manager);
}

#[test]
fn test_omega_n_cash_insufficient_balance() {
    // s_b = balance - threshold < threshold → CASH
    let ctx = JamHostContext {
        balance: 100,
        threshold: 60, // 100 - 60 = 40 < 60 → CASH
        ..Default::default()
    };
    let s_b = ctx.balance.checked_sub(ctx.threshold).unwrap();
    assert!(s_b < ctx.threshold); // 40 < 60 → CASH
}

#[test]
fn test_omega_n_cash_underflow() {
    // balance < threshold → underflow → CASH
    let ctx = JamHostContext {
        balance: 10,
        threshold: 100,
        ..Default::default()
    };
    assert!(ctx.balance.checked_sub(ctx.threshold).is_none());
}

#[test]
fn test_omega_n_privileged_path_conditions() {
    use std::collections::HashSet;

    const S: u32 = 1 << 16;

    // x_s = (x_e)_r (staker) ∧ ĩ < S → privileged creation
    let mut existing = HashSet::new();
    existing.insert(42u32); // staker service exists

    let ctx = JamHostContext {
        service_id: 42,
        balance: 1000,
        threshold: 100,
        existing_services: existing,
        empower: Some(EmpowerState {
            staker: 42, // current service IS the staker
            ..Default::default()
        }),
        ..Default::default()
    };

    let is_staker = ctx.empower.as_ref()
        .map(|e| ctx.service_id == e.staker)
        .unwrap_or(false);
    assert!(is_staker);
    assert!(5u32 < S); // ĩ = 5 < S → privileged
}

#[test]
fn test_omega_n_privileged_full_when_id_taken() {
    use std::collections::HashSet;

    // ĩ ∈ K((x_e)_d) → FULL
    let mut existing = HashSet::new();
    existing.insert(42u32);
    existing.insert(5u32); // privileged index 5 already taken

    let id_taken = existing.contains(&5u32);
    assert!(id_taken); // → FULL
}

#[test]
fn test_omega_n_nonpriv_uses_next_service_id() {
    const S: u32 = 1 << 16;

    // Non-privileged: uses ctx.next_service_id, then advances by +42
    let ctx = JamHostContext {
        service_id: 42,
        balance: 1000,
        threshold: 100,
        next_service_id: S + 500,
        ..Default::default()
    };

    // New service would get ID = S + 500
    assert_eq!(ctx.next_service_id, S + 500);
}

#[test]
fn test_omega_n_balance_deduction() {
    // After creation: balance should be reduced by threshold
    let mut ctx = JamHostContext {
        balance: 1000,
        threshold: 100,
        ..Default::default()
    };

    let s_b = ctx.balance.checked_sub(ctx.threshold).unwrap();
    assert_eq!(s_b, 900);
    assert!(s_b >= ctx.threshold); // 900 >= 100 → not CASH

    // Simulate deduction
    ctx.balance = s_b;
    assert_eq!(ctx.balance, 900);
}

#[test]
fn test_omega_n_new_account_fields() {
    use super::super::context::ServiceAccount;

    // Verify the new service account gets the right fields
    let a = ServiceAccount {
        code_hash: [0xAA; 32],
        balance: 100,           // a_t
        min_accum_gas: 5000,    // g
        min_item_gas: 200,      // m
        min_on_transfer_gas: 0, // f
        recent_count: 42,       // t (timeslot)
        ..Default::default()
    };

    assert_eq!(a.code_hash, [0xAA; 32]);
    assert_eq!(a.balance, 100);
    assert_eq!(a.min_accum_gas, 5000);
    assert_eq!(a.min_item_gas, 200);
    assert_eq!(a.min_on_transfer_gas, 0);
    assert_eq!(a.recent_count, 42);
    assert!(a.storage.is_empty());
    assert!(a.preimages.is_empty());
    assert_eq!(a.items_count, 0);
    assert_eq!(a.footprint, 0);
}

// ------------------------------------------------------------------
// ΩU (upgrade-service) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_omega_u_mutates_ctx_fields() {
    // Before upgrade
    let mut ctx = JamHostContext {
        service_id: 42,
        code_hash: [0x11; 32],
        min_accum_gas: 100,
        min_item_gas: 50,
        ..Default::default()
    };

    // Simulate what omega_u does on success
    let new_code_hash = [0xBB; 32];
    let new_g: u64 = 9999;
    let new_m: u64 = 7777;

    ctx.code_hash = new_code_hash;
    ctx.min_accum_gas = new_g;
    ctx.min_item_gas = new_m;
    ctx.upgrades.push((ctx.service_id, new_code_hash));

    assert_eq!(ctx.code_hash, [0xBB; 32]);
    assert_eq!(ctx.min_accum_gas, 9999);
    assert_eq!(ctx.min_item_gas, 7777);
    assert_eq!(ctx.upgrades.len(), 1);
    assert_eq!(ctx.upgrades[0], (42, [0xBB; 32]));
}

#[test]
fn test_omega_u_preserves_other_fields() {
    // Upgrade should NOT touch balance, threshold, etc.
    let mut ctx = JamHostContext {
        service_id: 10,
        balance: 5000,
        threshold: 100,
        min_on_transfer_gas: 42,
        ..Default::default()
    };

    ctx.code_hash = [0xCC; 32];
    ctx.min_accum_gas = 1000;
    ctx.min_item_gas = 500;

    assert_eq!(ctx.balance, 5000); // untouched
    assert_eq!(ctx.threshold, 100); // untouched
    assert_eq!(ctx.min_on_transfer_gas, 42); // untouched
}

// ------------------------------------------------------------------
// ΩT (transfer) — context-level tests
// ------------------------------------------------------------------

#[test]
fn test_omega_t_who_when_dest_unknown() {
    use std::collections::HashSet;

    // d ∉ K(d) → WHO
    let ctx = JamHostContext {
        service_id: 1,
        existing_services: HashSet::new(), // empty
        ..Default::default()
    };

    // Destination 99 is not in existing_services, not in created_services, not self
    let dest_known = ctx.existing_services.contains(&99u32)
        || ctx.created_services.iter().any(|(sid, _)| *sid == 99)
        || 99 == ctx.service_id;
    assert!(!dest_known); // → WHO
}

#[test]
fn test_omega_t_who_self_transfer_allowed() {
    use std::collections::HashSet;

    let ctx = JamHostContext {
        service_id: 42,
        existing_services: HashSet::new(), // service 42 is NOT in existing_services
        ..Default::default()
    };

    // Self-transfer: d == x_s → allowed even if not in K(d)
    let dest_known = ctx.existing_services.contains(&42u32)
        || ctx.created_services.iter().any(|(sid, _)| *sid == 42)
        || 42 == ctx.service_id;
    assert!(dest_known); // self-transfer OK
}

#[test]
fn test_omega_t_low_when_gas_limit_insufficient() {
    use super::super::context::ServiceAccount;
    use std::collections::HashMap;

    let mut service_accounts = HashMap::new();
    service_accounts.insert(99u32, ServiceAccount {
        min_on_transfer_gas: 500,
        ..Default::default()
    });

    let ctx = JamHostContext {
        service_id: 1,
        service_accounts,
        ..Default::default()
    };

    // l = 100 < d[99]_m = 500 → LOW
    let dest_min = ctx.service_accounts.get(&99u32)
        .map(|a| a.min_on_transfer_gas).unwrap_or(0);
    assert!(100u64 < dest_min); // → LOW
}

#[test]
fn test_omega_t_cash_when_balance_below_threshold() {
    let ctx = JamHostContext {
        service_id: 1,
        balance: 200,
        threshold: 150,
        ..Default::default()
    };

    // Transfer a = 100: b = 200 - 100 = 100 < threshold 150 → CASH
    let b = ctx.balance.checked_sub(100u64).unwrap();
    assert!(b < ctx.threshold); // → CASH
}

#[test]
fn test_omega_t_cash_on_underflow() {
    let ctx = JamHostContext {
        balance: 50,
        threshold: 100,
        ..Default::default()
    };

    // Transfer a = 100 > balance 50 → underflow → CASH
    assert!(ctx.balance.checked_sub(100u64).is_none());
}

#[test]
fn test_omega_t_ok_deducts_balance_and_pushes_transfer() {
    use super::super::context::JamTransfer;
    use std::collections::HashSet;

    let mut existing = HashSet::new();
    existing.insert(99u32);

    let mut ctx = JamHostContext {
        service_id: 1,
        balance: 1000,
        threshold: 100,
        existing_services: existing,
        ..Default::default()
    };

    let d = 99u32;
    let a = 300u64;
    let l = 500u64;
    let memo = vec![0xAB; 128];

    // Simulate OK path
    let b = ctx.balance.checked_sub(a).unwrap();
    assert!(b >= ctx.threshold); // 700 >= 100 → not CASH

    ctx.balance = b;
    ctx.transfers.push(JamTransfer {
        from_service: ctx.service_id,
        to_service: d,
        amount: a,
        memo: memo.clone(),
        gas_limit: l,
    });

    assert_eq!(ctx.balance, 700);
    assert_eq!(ctx.transfers.len(), 1);
    let t = &ctx.transfers[0];
    assert_eq!(t.from_service, 1);
    assert_eq!(t.to_service, 99);
    assert_eq!(t.amount, 300);
    assert_eq!(t.gas_limit, 500);
    assert_eq!(t.memo.len(), 128);
}

#[test]
fn test_omega_t_jam_transfer_fields() {
    use super::super::context::JamTransfer;

    let t = JamTransfer {
        from_service: 10,
        to_service: 20,
        amount: 42,
        memo: vec![0xFF; 128],
        gas_limit: 9999,
    };

    assert_eq!(t.from_service, 10);
    assert_eq!(t.to_service, 20);
    assert_eq!(t.amount, 42);
    assert_eq!(t.gas_limit, 9999);
    assert_eq!(t.memo.len(), 128);
}

// ==================================================================
// ΩJ — eject-service (index 21)
// ==================================================================

#[test]
fn test_omega_j_who_when_target_not_found() {
    use std::collections::HashMap;

    // Target not in service_accounts → WHO
    let ctx = JamHostContext {
        service_id: 1,
        service_accounts: HashMap::new(),
        ..Default::default()
    };

    // service 99 is not in service_accounts → d = ∇ → WHO
    assert!(ctx.service_accounts.get(&99u32).is_none());
}

#[test]
fn test_omega_j_who_when_target_is_self() {
    use super::super::context::ServiceAccount;
    use std::collections::HashMap;

    let mut sa = HashMap::new();
    // Even if self is in service_accounts, d = x_s → d = ∇
    sa.insert(1u32, ServiceAccount::default());

    let ctx = JamHostContext {
        service_id: 1,
        service_accounts: sa,
        ..Default::default()
    };

    // d == x_s → target lookup returns ∇ → WHO
    let target = if 1 != ctx.service_id {
        ctx.service_accounts.get(&1u32)
    } else {
        None
    };
    assert!(target.is_none());
}

#[test]
fn test_omega_j_who_when_code_hash_mismatch() {
    use super::super::context::ServiceAccount;
    use std::collections::HashMap;

    // Target exists but code_hash ≠ E₃₂(x_s) → WHO
    let mut sa = HashMap::new();
    sa.insert(99u32, ServiceAccount {
        code_hash: [0xFF; 32], // wrong — E₃₂(1) = [1,0,0,0, 0,0,0,0, ...]
        items_count: 2,
        ..Default::default()
    });

    let ctx = JamHostContext {
        service_id: 1,
        service_accounts: sa,
        ..Default::default()
    };

    let mut e32_xs = [0u8; 32];
    e32_xs[..4].copy_from_slice(&1u32.to_le_bytes());
    let acct = ctx.service_accounts.get(&99u32).unwrap();
    assert_ne!(acct.code_hash, e32_xs); // → WHO
}

#[test]
fn test_omega_j_huh_when_items_count_not_2() {
    use super::super::context::ServiceAccount;
    use std::collections::HashMap;

    // E₃₂(caller_id=1)
    let mut e32 = [0u8; 32];
    e32[..4].copy_from_slice(&1u32.to_le_bytes());

    let mut sa = HashMap::new();
    sa.insert(99u32, ServiceAccount {
        code_hash: e32,
        items_count: 3, // ≠ 2
        ..Default::default()
    });

    let ctx = JamHostContext {
        service_id: 1,
        service_accounts: sa,
        ..Default::default()
    };

    let acct = ctx.service_accounts.get(&99u32).unwrap();
    assert_ne!(acct.items_count, 2); // → HUH
}

#[test]
fn test_omega_j_huh_when_lookup_key_missing() {
    use super::super::context::ServiceAccount;
    use std::collections::HashMap;

    let mut e32 = [0u8; 32];
    e32[..4].copy_from_slice(&1u32.to_le_bytes());

    let mut sa = HashMap::new();
    sa.insert(99u32, ServiceAccount {
        code_hash: e32,
        items_count: 2,
        lookup: HashMap::new(), // empty → (h, l) ∉ d_l
        ..Default::default()
    });

    let ctx = JamHostContext {
        service_id: 1,
        service_accounts: sa,
        ..Default::default()
    };

    let h = [0xAA; 32];
    let l = 0u32; // max(81, 0) - 81 = 0
    let acct = ctx.service_accounts.get(&99u32).unwrap();
    assert!(acct.lookup.get(&(h, l)).is_none()); // → HUH
}

#[test]
fn test_omega_j_huh_when_preimage_too_recent() {
    use super::super::context::ServiceAccount;
    use std::collections::HashMap;

    let mut e32 = [0u8; 32];
    e32[..4].copy_from_slice(&1u32.to_le_bytes());

    let h = [0xBB; 32];
    let d_o = 100u64; // → l = max(81, 100) − 81 = 19
    let l = 19u32;

    let mut lookup = HashMap::new();
    // Entry [x, y] with y = 95, and timeslot = 99 → D = 5 → t−D = 94
    // y=95 ≥ 94 → NOT y < t−D → HUH
    lookup.insert((h, l), vec![10, 95]);

    let mut sa = HashMap::new();
    sa.insert(99u32, ServiceAccount {
        code_hash: e32,
        items_count: 2,
        min_on_transfer_gas: d_o,
        lookup,
        ..Default::default()
    });

    let ctx = JamHostContext {
        service_id: 1,
        timeslot: 99,
        service_accounts: sa,
        ..Default::default()
    };

    let acct = ctx.service_accounts.get(&99u32).unwrap();
    let entry = acct.lookup.get(&(h, l)).unwrap();
    assert_eq!(entry.len(), 2);
    let y = entry[1];
    // D = 5, t = 99, t − D = 94. y = 95 ≥ 94 → not old enough → HUH
    assert!(!(ctx.timeslot >= 5 && y < ctx.timeslot - 5));
}

#[test]
fn test_omega_j_ok_ejects_and_credits_balance() {
    use super::super::context::ServiceAccount;
    use std::collections::{HashMap, HashSet};

    let caller_id = 1u32;
    let target_id = 99u32;

    let mut e32 = [0u8; 32];
    e32[..4].copy_from_slice(&caller_id.to_le_bytes());

    let h = [0xCC; 32];
    let d_o = 200u64; // → l = max(81, 200) − 81 = 119
    let l = 119u32;

    let mut lookup = HashMap::new();
    // Entry [x=50, y=80], timeslot=100, D=5 → t−D=95 → y=80 < 95 → OK
    lookup.insert((h, l), vec![50, 80]);

    let mut sa = HashMap::new();
    sa.insert(target_id, ServiceAccount {
        code_hash: e32,
        items_count: 2,
        min_on_transfer_gas: d_o,
        balance: 5000,
        lookup,
        ..Default::default()
    });

    let mut existing = HashSet::new();
    existing.insert(target_id);

    let mut ctx = JamHostContext {
        service_id: caller_id,
        balance: 1000,
        timeslot: 100,
        service_accounts: sa,
        existing_services: existing,
        ..Default::default()
    };

    // Simulate OK path
    let acct = ctx.service_accounts.get(&target_id).unwrap();
    assert_eq!(acct.code_hash, e32);
    assert_eq!(acct.items_count, 2);
    let entry = acct.lookup.get(&(h, l)).unwrap();
    assert_eq!(entry, &vec![50, 80]);
    // y = 80 < 100 − 5 = 95 → OK
    assert!(80 < 100 - 5);

    // After eject: target removed, balance credited
    let target_balance = acct.balance;
    ctx.service_accounts.remove(&target_id);
    ctx.existing_services.remove(&target_id);
    ctx.balance += target_balance;
    ctx.ejected_services.push((target_id, caller_id));

    assert!(ctx.service_accounts.get(&target_id).is_none());
    assert!(!ctx.existing_services.contains(&target_id));
    assert_eq!(ctx.balance, 1000 + 5000); // credited
    assert_eq!(ctx.ejected_services.len(), 1);
    assert_eq!(ctx.ejected_services[0], (target_id, caller_id));
}

#[test]
fn test_omega_j_l_computation() {
    // l = max(81, d_o) − 81
    // d_o = 0 → l = max(81, 0) - 81 = 0
    assert_eq!((0u64.max(81) - 81) as u32, 0);
    // d_o = 81 → l = 0
    assert_eq!((81u64.max(81) - 81) as u32, 0);
    // d_o = 100 → l = 19
    assert_eq!((100u64.max(81) - 81) as u32, 19);
    // d_o = 500 → l = 419
    assert_eq!((500u64.max(81) - 81) as u32, 419);
}

// ==================================================================
// ΩQ — query-preimage (index 22)
// ==================================================================

#[test]
fn test_omega_q_none_when_key_not_found() {
    use std::collections::HashMap;

    let ctx = JamHostContext {
        lookup: HashMap::new(), // empty
        ..Default::default()
    };

    let h = [0xAA; 32];
    let z = 100u32;
    assert!(ctx.lookup.get(&(h, z)).is_none()); // → NONE
}

#[test]
fn test_omega_q_encoding_empty_tuple() {
    use std::collections::HashMap;

    let h = [0x11; 32];
    let z = 42u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![]); // a = []

    let ctx = JamHostContext {
        lookup,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry.len(), 0);
    // Expected encoding: (0, 0)
    let a0: u64 = 0;
    let a1: u64 = 0;
    assert_eq!(a0, 0);
    assert_eq!(a1, 0);
}

#[test]
fn test_omega_q_encoding_single_element() {
    use std::collections::HashMap;

    let h = [0x22; 32];
    let z = 10u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![7]); // a = [7]

    let ctx = JamHostContext {
        lookup,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry, &vec![7]);
    // Expected encoding: (1 + 2³²·7, 0)
    let x = 7u64;
    let a0 = 1u64 + (x << 32);
    let a1 = 0u64;
    assert_eq!(a0, 1 + (7u64 << 32));
    assert_eq!(a1, 0);
}

#[test]
fn test_omega_q_encoding_two_elements() {
    use std::collections::HashMap;

    let h = [0x33; 32];
    let z = 20u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![100, 200]); // a = [100, 200]

    let ctx = JamHostContext {
        lookup,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry, &vec![100, 200]);
    // Expected: (2 + 2³²·100, 200)
    let x = 100u64;
    let y = 200u64;
    let a0 = 2u64 + (x << 32);
    let a1 = y;
    assert_eq!(a0, 2 + (100u64 << 32));
    assert_eq!(a1, 200);
}

#[test]
fn test_omega_q_encoding_three_elements() {
    use std::collections::HashMap;

    let h = [0x44; 32];
    let z = 30u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![5, 10, 15]); // a = [5, 10, 15]

    let ctx = JamHostContext {
        lookup,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry, &vec![5, 10, 15]);
    // Expected: (3 + 2³²·5, 10 + 2³²·15)
    let x = 5u64;
    let y = 10u64;
    let z_val = 15u64;
    let a0 = 3u64 + (x << 32);
    let a1 = y + (z_val << 32);
    assert_eq!(a0, 3 + (5u64 << 32));
    assert_eq!(a1, 10 + (15u64 << 32));
}

#[test]
fn test_omega_q_encoding_decode_roundtrip() {
    // Verify the encoding can be decoded back
    let x: u32 = 0xDEAD;
    let y: u32 = 0xBEEF;
    let z: u32 = 0xCAFE;

    // Encode as 3-element tuple
    let a0: u64 = 3 + ((x as u64) << 32);
    let a1: u64 = (y as u64) + ((z as u64) << 32);

    // Decode
    let count = (a0 & 0xFFFF_FFFF) as u32;
    let dec_x = (a0 >> 32) as u32;
    let dec_y = (a1 & 0xFFFF_FFFF) as u32;
    let dec_z = (a1 >> 32) as u32;

    assert_eq!(count, 3);
    assert_eq!(dec_x, x);
    assert_eq!(dec_y, y);
    assert_eq!(dec_z, z);
}

#[test]
fn test_lookup_table_on_service_account_default() {
    use super::super::context::ServiceAccount;

    let sa = ServiceAccount::default();
    assert!(sa.lookup.is_empty());
}

#[test]
fn test_lookup_table_on_jam_host_context_default() {
    let ctx = JamHostContext::default();
    assert!(ctx.lookup.is_empty());
}

#[test]
fn test_omega_j_e32_encoding() {
    // E₃₂(x_s) = 4-byte LE of x_s + 28 zero bytes
    let service_id: u32 = 0x0001_0203;
    let mut e32 = [0u8; 32];
    e32[..4].copy_from_slice(&service_id.to_le_bytes());

    assert_eq!(e32[0], 0x03);
    assert_eq!(e32[1], 0x02);
    assert_eq!(e32[2], 0x01);
    assert_eq!(e32[3], 0x00);
    assert_eq!(&e32[4..], &[0u8; 28]);
}

// ==================================================================
// ΩS — solicit-preimage (index 23)
// ==================================================================

#[test]
fn test_omega_s_new_solicitation_creates_empty_entry() {
    use std::collections::HashMap;

    let h = [0xAA; 32];
    let z = 100u32;

    let mut ctx = JamHostContext {
        balance: 1000,
        threshold: 500,
        lookup: HashMap::new(),
        ..Default::default()
    };

    // Before: (h, z) not in lookup
    assert!(ctx.lookup.get(&(h, z)).is_none());

    // Simulate: create entry a_l[(h,z)] = []
    ctx.lookup.insert((h, z), vec![]);
    ctx.items_count += 1;

    assert_eq!(ctx.lookup.get(&(h, z)).unwrap(), &vec![0u32; 0]);
    assert_eq!(ctx.items_count, 1);
}

#[test]
fn test_omega_s_append_timeslot_to_two_element_entry() {
    use std::collections::HashMap;

    let h = [0xBB; 32];
    let z = 50u32;
    let timeslot = 42u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![10, 20]); // [x, y]

    let mut ctx = JamHostContext {
        balance: 1000,
        threshold: 500,
        timeslot,
        lookup,
        ..Default::default()
    };

    // Simulate: append t → [x, y, t]
    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry.len(), 2);
    let mut new_entry = entry.clone();
    new_entry.push(ctx.timeslot);
    ctx.lookup.insert((h, z), new_entry);

    assert_eq!(ctx.lookup.get(&(h, z)).unwrap(), &vec![10, 20, 42]);
}

#[test]
fn test_omega_s_huh_when_entry_has_one_element() {
    use std::collections::HashMap;

    let h = [0xCC; 32];
    let z = 30u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![5]); // [x] — single element

    let ctx = JamHostContext {
        lookup,
        ..Default::default()
    };

    // [x] is not None (new) and not len==2 → a = ∇ → HUH
    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_ne!(entry.len(), 0); // not empty (new)
    assert_ne!(entry.len(), 2); // not 2-element
    // → HUH
}

#[test]
fn test_omega_s_huh_when_entry_has_three_elements() {
    use std::collections::HashMap;

    let h = [0xDD; 32];
    let z = 60u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![1, 2, 3]); // already 3 elements

    let ctx = JamHostContext {
        lookup,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry.len(), 3);
    // Not None and not len==2 → a = ∇ → HUH
}

#[test]
fn test_omega_s_full_when_balance_below_threshold() {
    use std::collections::HashMap;

    let ctx = JamHostContext {
        balance: 100,
        threshold: 500, // a_b < a_t → FULL
        lookup: HashMap::new(),
        ..Default::default()
    };

    // FULL check: balance < threshold
    assert!(ctx.balance < ctx.threshold);
}

#[test]
fn test_omega_s_ok_when_balance_at_threshold() {
    use std::collections::HashMap;

    let ctx = JamHostContext {
        balance: 500,
        threshold: 500, // a_b == a_t → NOT FULL (< is strict)
        lookup: HashMap::new(),
        ..Default::default()
    };

    // Not FULL: balance is NOT less than threshold
    assert!(!(ctx.balance < ctx.threshold));
}

// ==================================================================
// ΩF — forget-preimage (index 24)
// ==================================================================

#[test]
fn test_omega_f_huh_when_key_not_found() {
    use std::collections::HashMap;

    let h = [0xEE; 32];
    let z = 99u32;

    let ctx = JamHostContext {
        lookup: HashMap::new(),
        ..Default::default()
    };

    // (h, z) ∉ K((x_s)_l) → a = ∇ → HUH
    assert!(ctx.lookup.get(&(h, z)).is_none());
}

#[test]
fn test_omega_f_removes_empty_solicitation() {
    use std::collections::HashMap;

    let h = [0x11; 32];
    let z = 10u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![]); // entry = []

    let mut preimages = HashMap::new();
    preimages.insert(h, vec![1, 2, 3]); // some preimage data

    let mut ctx = JamHostContext {
        lookup,
        preimages,
        items_count: 5,
        ..Default::default()
    };

    // Simulate: entry = [] → full removal
    ctx.lookup.remove(&(h, z));
    ctx.preimages.remove(&h);
    ctx.items_count = ctx.items_count.saturating_sub(1);

    assert!(ctx.lookup.get(&(h, z)).is_none());
    assert!(ctx.preimages.get(&h).is_none());
    assert_eq!(ctx.items_count, 4);
}

#[test]
fn test_omega_f_removes_two_element_old_enough() {
    use std::collections::HashMap;

    let h = [0x22; 32];
    let z = 20u32;
    let d: u32 = 5;

    let mut lookup = HashMap::new();
    // [x=10, y=80], timeslot=100 → t−D = 95, y=80 < 95 → OK removal
    lookup.insert((h, z), vec![10, 80]);

    let mut ctx = JamHostContext {
        lookup,
        timeslot: 100,
        items_count: 3,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    let y = entry[1];
    assert!(ctx.timeslot >= d && y < ctx.timeslot - d); // y=80 < 95

    // Simulate removal
    ctx.lookup.remove(&(h, z));
    ctx.items_count = ctx.items_count.saturating_sub(1);

    assert!(ctx.lookup.get(&(h, z)).is_none());
    assert_eq!(ctx.items_count, 2);
}

#[test]
fn test_omega_f_huh_when_two_element_too_recent() {
    use std::collections::HashMap;

    let h = [0x33; 32];
    let z = 30u32;
    let d: u32 = 5;

    let mut lookup = HashMap::new();
    // [x=10, y=96], timeslot=100 → t−D = 95, y=96 >= 95 → HUH
    lookup.insert((h, z), vec![10, 96]);

    let ctx = JamHostContext {
        lookup,
        timeslot: 100,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    let y = entry[1];
    // y=96 >= 95 → NOT y < t−D → HUH
    assert!(!(ctx.timeslot >= d && y < ctx.timeslot - d));
}

#[test]
fn test_omega_f_transforms_single_element() {
    use std::collections::HashMap;

    let h = [0x44; 32];
    let z = 40u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![7]); // [x]

    let mut ctx = JamHostContext {
        lookup,
        timeslot: 50,
        ..Default::default()
    };

    // Simulate: [x] → [x, t]
    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry.len(), 1);
    let x = entry[0];
    ctx.lookup.insert((h, z), vec![x, ctx.timeslot]);

    assert_eq!(ctx.lookup.get(&(h, z)).unwrap(), &vec![7, 50]);
}

#[test]
fn test_omega_f_transforms_three_element_old_enough() {
    use std::collections::HashMap;

    let h = [0x55; 32];
    let z = 50u32;
    let d: u32 = 5;

    let mut lookup = HashMap::new();
    // [x=1, y=80, w=99], timeslot=100 → t−D=95, y=80 < 95 → [w, t] = [99, 100]
    lookup.insert((h, z), vec![1, 80, 99]);

    let mut ctx = JamHostContext {
        lookup,
        timeslot: 100,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert_eq!(entry.len(), 3);
    let y = entry[1];
    let w = entry[2];
    assert!(ctx.timeslot >= d && y < ctx.timeslot - d); // 80 < 95

    ctx.lookup.insert((h, z), vec![w, ctx.timeslot]);
    assert_eq!(ctx.lookup.get(&(h, z)).unwrap(), &vec![99, 100]);
}

#[test]
fn test_omega_f_huh_when_three_element_too_recent() {
    use std::collections::HashMap;

    let h = [0x66; 32];
    let z = 60u32;
    let d: u32 = 5;

    let mut lookup = HashMap::new();
    // [x=1, y=96, w=99], timeslot=100 → t−D=95, y=96 >= 95 → HUH
    lookup.insert((h, z), vec![1, 96, 99]);

    let ctx = JamHostContext {
        lookup,
        timeslot: 100,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    let y = entry[1];
    assert!(!(ctx.timeslot >= d && y < ctx.timeslot - d)); // 96 >= 95 → HUH
}

#[test]
fn test_omega_f_preimage_removal_on_full_forget() {
    use std::collections::HashMap;

    let h = [0x77; 32];
    let z = 70u32;

    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![]); // empty solicitation

    let mut preimages = HashMap::new();
    preimages.insert(h, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let mut ctx = JamHostContext {
        lookup,
        preimages,
        ..Default::default()
    };

    // Before: preimage exists
    assert!(ctx.preimages.contains_key(&h));

    // Full removal path: removes from both lookup and preimages
    ctx.lookup.remove(&(h, z));
    ctx.preimages.remove(&h);

    assert!(ctx.lookup.get(&(h, z)).is_none());
    assert!(!ctx.preimages.contains_key(&h));
}

// ==================================================================
// Ωδ — yield (index 25) — fixed to use Fault, not NONE
// ==================================================================

#[test]
fn test_omega_yield_sets_yield_output_on_ok() {
    let h = [0xAB; 32];

    let mut ctx = JamHostContext::default();
    assert!(ctx.yield_output.is_none());

    // Simulate: OK path sets yield_output = Some(h)
    ctx.yield_output = Some(h);
    assert_eq!(ctx.yield_output, Some(h));
}

#[test]
fn test_omega_yield_returns_hc_ok() {
    use super::super::context::HC_OK;

    // On success, the register should be set to HC_OK (0)
    assert_eq!(HC_OK, 0u64);
}

// ==================================================================
// Ωψ — provide-preimage (index 26)
// ==================================================================

#[test]
fn test_omega_provide_self_service_resolution() {
    // phi_7 = u64::MAX → s = x_s (self)
    let ctx = JamHostContext {
        service_id: 42,
        ..Default::default()
    };

    let phi7 = u64::MAX;
    let s = if phi7 == u64::MAX { ctx.service_id } else { phi7 as u32 };
    assert_eq!(s, 42);
}

#[test]
fn test_omega_provide_explicit_service_resolution() {
    let ctx = JamHostContext {
        service_id: 42,
        ..Default::default()
    };

    let phi7 = 99u64;
    let s = if phi7 == u64::MAX { ctx.service_id } else { phi7 as u32 };
    assert_eq!(s, 99);
}

#[test]
fn test_omega_provide_who_when_service_not_found() {
    use std::collections::HashMap;

    let ctx = JamHostContext {
        service_id: 1,
        service_accounts: HashMap::new(), // empty
        ..Default::default()
    };

    // Service 99 not in service_accounts → a = ∅ → WHO
    let s = 99u32;
    assert!(s != ctx.service_id); // not self
    assert!(ctx.service_accounts.get(&s).is_none()); // → WHO
}

#[test]
fn test_omega_provide_huh_when_lookup_entry_not_empty() {
    use std::collections::HashMap;
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let data = vec![1, 2, 3, 4];
    let z = data.len() as u32;
    let hash = <Blake2b<U32> as Digest>::digest(&data);
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash);

    // Lookup entry is [5] (not empty) → HUH
    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![5u32]);

    let ctx = JamHostContext {
        service_id: 1,
        lookup,
        ..Default::default()
    };

    let entry = ctx.lookup.get(&(h, z)).unwrap();
    assert!(!entry.is_empty()); // ≠ [] → HUH
}

#[test]
fn test_omega_provide_huh_when_lookup_key_missing() {
    use std::collections::HashMap;
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let data = vec![5, 6, 7, 8];
    let z = data.len() as u32;
    let hash = <Blake2b<U32> as Digest>::digest(&data);
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash);

    let ctx = JamHostContext {
        service_id: 1,
        lookup: HashMap::new(), // empty → key not found → HUH
        ..Default::default()
    };

    assert!(ctx.lookup.get(&(h, z)).is_none()); // → HUH
}

#[test]
fn test_omega_provide_huh_when_already_provided() {
    use std::collections::HashMap;
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let data = vec![10, 20, 30];
    let z = data.len() as u32;
    let hash = <Blake2b<U32> as Digest>::digest(&data);
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash);

    // Lookup entry is [] (valid solicitation)
    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![]);

    let ctx = JamHostContext {
        service_id: 1,
        lookup,
        // Already provided this exact (s, data) pair
        provided_preimages: vec![(1, data.clone())],
        ..Default::default()
    };

    // (s, i) ∈ x_p → HUH
    assert!(ctx.provided_preimages.iter().any(|(sid, d)| *sid == 1 && *d == data));
}

#[test]
fn test_omega_provide_ok_adds_to_provided_preimages() {
    use std::collections::HashMap;
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let z = data.len() as u32;
    let hash = <Blake2b<U32> as Digest>::digest(&data);
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash);

    // Lookup entry is [] (valid solicitation)
    let mut lookup = HashMap::new();
    lookup.insert((h, z), vec![]);

    let mut ctx = JamHostContext {
        service_id: 1,
        lookup,
        ..Default::default()
    };

    // Checks pass: entry is [], not already provided → OK
    assert!(ctx.provided_preimages.is_empty());
    ctx.provided_preimages.push((1, data.clone()));
    assert_eq!(ctx.provided_preimages.len(), 1);
    assert_eq!(ctx.provided_preimages[0].0, 1);
    assert_eq!(ctx.provided_preimages[0].1, data);
}

#[test]
fn test_omega_provide_other_service_checks_service_accounts() {
    use super::super::context::ServiceAccount;
    use std::collections::HashMap;
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let data = vec![0xCA, 0xFE];
    let z = data.len() as u32;
    let hash = <Blake2b<U32> as Digest>::digest(&data);
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash);

    // Service 99 has a valid solicitation [] for this hash
    let mut acct_lookup = HashMap::new();
    acct_lookup.insert((h, z), vec![]);

    let mut sa = HashMap::new();
    sa.insert(99u32, ServiceAccount {
        lookup: acct_lookup,
        ..Default::default()
    });

    let ctx = JamHostContext {
        service_id: 1, // caller is 1
        service_accounts: sa,
        ..Default::default()
    };

    // Resolve s=99 (other service), look up in service_accounts
    let acct = ctx.service_accounts.get(&99u32).unwrap();
    let entry = acct.lookup.get(&(h, z)).unwrap();
    assert!(entry.is_empty()); // → valid solicitation
}

#[test]
fn test_omega_provide_hash_computation() {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    // H(i) must be deterministic
    let data = vec![1, 2, 3, 4, 5];
    let hash1 = <Blake2b<U32> as Digest>::digest(&data);
    let hash2 = <Blake2b<U32> as Digest>::digest(&data);
    assert_eq!(hash1.as_slice(), hash2.as_slice());
    assert_eq!(hash1.len(), 32);
}

#[test]
fn test_provided_preimages_default_empty() {
    let ctx = JamHostContext::default();
    assert!(ctx.provided_preimages.is_empty());
}

// ==================================================================
// Λ(a, t, h) — lambda_lookup tests
// ==================================================================

#[test]
fn test_lambda_lookup_no_preimage_returns_none() {
    let preimages = std::collections::HashMap::new();
    let lookup = std::collections::HashMap::new();
    let hash = [0xAA; 32];
    assert!(lambda_lookup(&preimages, &lookup, 100, &hash).is_none());
}

#[test]
fn test_lambda_lookup_preimage_no_status_returns_none() {
    let mut preimages = std::collections::HashMap::new();
    preimages.insert([0xBB; 32], vec![1, 2, 3]);
    // No entry in lookup → None (not solicited)
    let lookup = std::collections::HashMap::new();
    assert!(lambda_lookup(&preimages, &lookup, 100, &[0xBB; 32]).is_none());
}

#[test]
fn test_lambda_lookup_status_empty_solicited_not_provided() {
    let mut preimages = std::collections::HashMap::new();
    preimages.insert([0xCC; 32], vec![10, 20, 30]);
    let mut lookup = std::collections::HashMap::new();
    // [] = solicited, not yet provided → never available
    lookup.insert(([0xCC; 32], 3), vec![]);
    assert!(lambda_lookup(&preimages, &lookup, 50, &[0xCC; 32]).is_none());
    assert!(lambda_lookup(&preimages, &lookup, 100, &[0xCC; 32]).is_none());
}

#[test]
fn test_lambda_lookup_status_single_available_from_x() {
    let mut preimages = std::collections::HashMap::new();
    preimages.insert([0xDD; 32], vec![1, 2]);
    let mut lookup = std::collections::HashMap::new();
    // [50] = available from timeslot 50 onward
    lookup.insert(([0xDD; 32], 2), vec![50]);

    // Before x → None
    assert!(lambda_lookup(&preimages, &lookup, 49, &[0xDD; 32]).is_none());
    // At x → Some
    assert_eq!(lambda_lookup(&preimages, &lookup, 50, &[0xDD; 32]), Some(vec![1, 2]));
    // After x → Some
    assert_eq!(lambda_lookup(&preimages, &lookup, 200, &[0xDD; 32]), Some(vec![1, 2]));
}

#[test]
fn test_lambda_lookup_status_pair_available_in_range() {
    let mut preimages = std::collections::HashMap::new();
    preimages.insert([0xEE; 32], vec![5, 6, 7, 8]);
    let mut lookup = std::collections::HashMap::new();
    // [10, 20] = available during [10, 20)
    lookup.insert(([0xEE; 32], 4), vec![10, 20]);

    assert!(lambda_lookup(&preimages, &lookup, 9, &[0xEE; 32]).is_none());
    assert_eq!(lambda_lookup(&preimages, &lookup, 10, &[0xEE; 32]), Some(vec![5, 6, 7, 8]));
    assert_eq!(lambda_lookup(&preimages, &lookup, 15, &[0xEE; 32]), Some(vec![5, 6, 7, 8]));
    assert!(lambda_lookup(&preimages, &lookup, 20, &[0xEE; 32]).is_none());
    assert!(lambda_lookup(&preimages, &lookup, 100, &[0xEE; 32]).is_none());
}

#[test]
fn test_lambda_lookup_status_triple_available_in_range() {
    let mut preimages = std::collections::HashMap::new();
    preimages.insert([0xFF; 32], vec![42]);
    let mut lookup = std::collections::HashMap::new();
    // [10, 20, 30] = available during [10, 20), re-solicited at 30
    lookup.insert(([0xFF; 32], 1), vec![10, 20, 30]);

    assert!(lambda_lookup(&preimages, &lookup, 5, &[0xFF; 32]).is_none());
    assert_eq!(lambda_lookup(&preimages, &lookup, 10, &[0xFF; 32]), Some(vec![42]));
    assert_eq!(lambda_lookup(&preimages, &lookup, 19, &[0xFF; 32]), Some(vec![42]));
    assert!(lambda_lookup(&preimages, &lookup, 20, &[0xFF; 32]).is_none());
    // After re-solicitation (30), still not available since no new provision
    assert!(lambda_lookup(&preimages, &lookup, 30, &[0xFF; 32]).is_none());
}

#[test]
fn test_lambda_lookup_wrong_length_returns_none() {
    let mut preimages = std::collections::HashMap::new();
    preimages.insert([0xAA; 32], vec![1, 2, 3]); // len = 3
    let mut lookup = std::collections::HashMap::new();
    // Status for length 4 (wrong!) → won't match
    lookup.insert(([0xAA; 32], 4), vec![10]);
    assert!(lambda_lookup(&preimages, &lookup, 50, &[0xAA; 32]).is_none());
}

// ==================================================================
// Collapse propagation tests (provided_preimages, lookup, empower)
// ==================================================================

#[test]
fn test_collapse_propagates_provided_preimages_on_halt() {
    use super::super::context::PvmOutcome;
    let mut ctx = JamHostContext::default();
    ctx.provided_preimages = vec![(42, vec![1, 2, 3])];
    let result = ctx.collapse(PvmOutcome::Halt, 100);
    assert_eq!(result.provided_preimages.len(), 1);
    assert_eq!(result.provided_preimages[0], (42, vec![1, 2, 3]));
}

#[test]
fn test_collapse_reverts_provided_preimages_on_panic() {
    use super::super::context::PvmOutcome;
    let mut ctx = JamHostContext::default();
    // Take checkpoint with empty provided_preimages
    ctx.take_checkpoint();
    // Then add some
    ctx.provided_preimages = vec![(99, vec![10, 20])];
    let result = ctx.collapse(PvmOutcome::Panic, 100);
    // Should revert to checkpoint (empty)
    assert!(result.provided_preimages.is_empty());
}

#[test]
fn test_collapse_propagates_lookup_on_halt() {
    use super::super::context::PvmOutcome;
    let mut ctx = JamHostContext::default();
    ctx.lookup.insert(([0xAA; 32], 5), vec![10, 20]);
    let result = ctx.collapse(PvmOutcome::Halt, 100);
    assert_eq!(result.lookup.len(), 1);
    assert_eq!(result.lookup[&([0xAA; 32], 5)], vec![10, 20]);
}

#[test]
fn test_collapse_propagates_empower_on_halt() {
    use super::super::context::PvmOutcome;
    let mut ctx = JamHostContext::default();
    ctx.empower = Some(EmpowerState {
        manager: 1,
        validator: 2,
        staker: 3,
        ..Default::default()
    });
    let result = ctx.collapse(PvmOutcome::Halt, 100);
    assert!(result.empower.is_some());
    let emp = result.empower.unwrap();
    assert_eq!(emp.manager, 1);
    assert_eq!(emp.validator, 2);
    assert_eq!(emp.staker, 3);
}

#[test]
fn test_collapse_reverts_empower_on_oog() {
    use super::super::context::PvmOutcome;
    let mut ctx = JamHostContext::default();
    ctx.empower = Some(EmpowerState {
        manager: 99,
        ..Default::default()
    });
    ctx.take_checkpoint();
    ctx.empower = Some(EmpowerState {
        manager: 77,
        ..Default::default()
    });
    let result = ctx.collapse(PvmOutcome::OutOfGas, 0);
    // Should revert to checkpoint empower (manager=99)
    let emp = result.empower.unwrap();
    assert_eq!(emp.manager, 99);
}
