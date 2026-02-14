//! C-FFI accessors for JAM instance state.
//!
//! Functions for populating a [`JamInstance`]'s context before execution
//! (storage, preimages, entropy, etc.) and reading side-effects after
//! execution (transfers, logs, ejections, yield output, etc.).

use super::context::{JamInstance, InvocationContext, PvmOutcome};

// ============================================================================
// Invocation context (before execution)
// ============================================================================

/// Set the invocation context for a JAM instance.
///
/// Values: 0=IsAuthorized, 1=Refine, 2=Accumulate (default), 3=OnTransfer
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_set_invocation_context(
    instance: *mut JamInstance,
    context: u32,
) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let ctx = &mut (*instance).context;
    ctx.invocation = match context {
        0 => InvocationContext::IsAuthorized,
        1 => InvocationContext::Refine,
        2 => InvocationContext::Accumulate,
        3 => InvocationContext::OnTransfer,
        _ => return u32::MAX,
    };
    0
}

/// Get the current invocation context.
///
/// Returns: 0=IsAuthorized, 1=Refine, 2=Accumulate, 3=OnTransfer, MAX=error
#[no_mangle]
pub unsafe extern "C" fn jam_get_invocation_context(instance: *mut JamInstance) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    match (*instance).context.invocation {
        InvocationContext::IsAuthorized => 0,
        InvocationContext::Refine => 1,
        InvocationContext::Accumulate => 2,
        InvocationContext::OnTransfer => 3,
    }
}

// ============================================================================
// Refine-specific context (before execution)
// ============================================================================

/// Set the core index for IsAuthorized/Refine context.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_set_core_index(instance: *mut JamInstance, core_index: u16) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    (*instance).context.core_index = core_index;
    0
}

/// Set the work item payload for Refine context.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_payload(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) {
        return 1;
    }
    let ctx = &mut (*instance).context;
    ctx.payload = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    0
}

/// Set the work package hash H(p) for Refine context.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `hash` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_package_hash(
    instance: *mut JamInstance,
    hash: *const u8,
) -> u32 {
    if instance.is_null() || hash.is_null() {
        return 1;
    }
    let ctx = &mut (*instance).context;
    ctx.package_hash.copy_from_slice(std::slice::from_raw_parts(hash, 32));
    0
}

/// Add an import segment for Refine context (ΩY / ΩH).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_import_segment(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) {
        return 1;
    }
    let ctx = &mut (*instance).context;
    let segment = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    ctx.import_segments.push(segment);
    0
}

/// Set the authorizer trace for Refine context.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_authorizer_trace(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) {
        return 1;
    }
    let ctx = &mut (*instance).context;
    ctx.authorizer_trace = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    0
}

/// Set the current work item index for Refine context.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_set_work_item_index(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    (*instance).context.work_item_index = index;
    0
}

/// Set the lookup anchor hash for Refine context (ℍ₀).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `hash` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_lookup_anchor(
    instance: *mut JamInstance,
    hash: *const u8,
) -> u32 {
    if instance.is_null() || hash.is_null() {
        return 1;
    }
    let ctx = &mut (*instance).context;
    ctx.lookup_anchor_hash.copy_from_slice(std::slice::from_raw_parts(hash, 32));
    0
}

/// Add an extrinsic segment group (x̄[j]) for Refine context.
///
/// Each call adds the extrinsic segments for one work item.
/// Call repeatedly (once per work item) to build the full `extrinsics` vec.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes (or null if empty).
#[no_mangle]
pub unsafe extern "C" fn jam_instance_begin_extrinsic_group(
    instance: *mut JamInstance,
) -> u32 {
    if instance.is_null() { return 1; }
    (*instance).context.extrinsics.push(Vec::new());
    0
}

/// Add a segment to the current extrinsic group.
///
/// Must call `jam_instance_begin_extrinsic_group` first.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes (or null if empty).
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_extrinsic_segment(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() { return 1; }
    let ctx = &mut (*instance).context;
    if ctx.extrinsics.is_empty() { return 2; }
    let seg = if data_len > 0 && !data.is_null() {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    ctx.extrinsics.last_mut().unwrap().push(seg);
    0
}

/// Set the authorizer code (p_f) for Refine context.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_authorizer_code(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) { return 1; }
    let ctx = &mut (*instance).context;
    ctx.authorizer_code = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else { Vec::new() };
    0
}

/// Set the justification / authorization token (p_j) for Refine context.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_justification(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) { return 1; }
    let ctx = &mut (*instance).context;
    ctx.justification = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else { Vec::new() };
    0
}

/// Set the pre-encoded work-package context E(p_c) for Refine context.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_work_package_context(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) { return 1; }
    let ctx = &mut (*instance).context;
    ctx.work_package_context = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else { Vec::new() };
    0
}

/// Add a work item info entry for S(w) encoding (kinds 11/12/13).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `code_hash` must point to 32 bytes.
/// - `payload` must point to `payload_len` bytes (or null if empty).
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_work_item_info(
    instance: *mut JamInstance,
    service_id: u32,
    code_hash: *const u8,
    gas_limit: u64,
    gas_limit_accum: u64,
    payload: *const u8,
    payload_len: usize,
) -> u32 {
    use super::context::WorkItemInfo;

    if instance.is_null() || code_hash.is_null() { return 1; }
    let ctx = &mut (*instance).context;
    let mut ch = [0u8; 32];
    ch.copy_from_slice(std::slice::from_raw_parts(code_hash, 32));
    let pl = if payload_len > 0 && !payload.is_null() {
        std::slice::from_raw_parts(payload, payload_len).to_vec()
    } else { Vec::new() };
    ctx.work_items.push(WorkItemInfo {
        service_id,
        code_hash: ch,
        gas_limit,
        gas_limit_accum,
        payload: pl,
    });
    0
}

/// Set the header hash (H_T) for Accumulate context.
/// Needed by ΩN, ΩJ, ΩS, ΩF (GP B.11).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `hash` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_header_hash(
    instance: *mut JamInstance,
    hash: *const u8,
) -> u32 {
    if instance.is_null() || hash.is_null() {
        return 1;
    }
    let ctx = &mut (*instance).context;
    ctx.header_hash.copy_from_slice(std::slice::from_raw_parts(hash, 32));
    0
}

/// Compute and set the initial `next_service_id` per GP B.10.
///
/// `i = E₄⁻¹(H(E(s, η'₀, H_T))) mod (2³² − S − 2⁸) + S`
///
/// Must be called **after** setting `service_id`, `entropy`, and `header_hash`.
/// Returns the computed service ID, or `u32::MAX` on error.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_compute_initial_service_id(
    instance: *mut JamInstance,
) -> u32 {
    use super::context::compute_next_service_id;

    if instance.is_null() {
        return u32::MAX;
    }
    let ctx = &mut (*instance).context;
    let sid = compute_next_service_id(
        ctx.service_id,
        &ctx.entropy[0],
        &ctx.header_hash,
        &ctx.existing_services,
        &ctx.created_services,
    );
    ctx.next_service_id = sid;
    sid
}

/// Add an existing service ID to K(e_d) for B.14 collision checking.
///
/// Call this for each service ID in δ before PVM execution begins.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_add_existing_service(
    instance: *mut JamInstance,
    service_id: u32,
) -> u32 {
    if instance.is_null() {
        return 1;
    }
    (*instance).context.existing_services.insert(service_id);
    0
}

/// Get the number of export segments produced during Refine execution.
#[no_mangle]
pub unsafe extern "C" fn jam_get_export_segment_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.export_segments.len() as u32
}

/// Get export segment at `index`. Returns segment length or `u32::MAX`.
///
/// # Safety
/// `out` must point to `out_len` writable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn jam_get_export_segment(
    instance: *mut JamInstance,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.export_segments.len() { return u32::MAX; }
    let seg = &ctx.export_segments[i];
    if !out.is_null() {
        let n = std::cmp::min(seg.len(), out_len);
        if n > 0 { std::ptr::copy_nonoverlapping(seg.as_ptr(), out, n); }
    }
    seg.len() as u32
}

// ============================================================================
// Cross-service accounts (d) — for Ω_L, Ω_R, Ω_I
// ============================================================================

/// Add a storage entry to another service's account (d[service_id]).
///
/// Used by Ω_R (read-storage) and Ω_L (lookup-preimage) for cross-service lookups.
/// Call before PVM execution to populate the service account database.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `key` must point to `key_len` valid bytes.
/// - `value` must point to `value_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_service_storage(
    instance: *mut JamInstance,
    service_id: u32,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) -> u32 {
    if instance.is_null() || key.is_null() || value.is_null() { return 1; }
    let ctx = &mut (*instance).context;
    let k = std::slice::from_raw_parts(key, key_len).to_vec();
    let v = std::slice::from_raw_parts(value, value_len).to_vec();
    ctx.service_accounts.entry(service_id).or_default().storage.insert(k, v);
    0
}

/// Add a preimage to another service's account (d[service_id]).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `hash` must point to 32 bytes.
/// - `blob` must point to `blob_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_service_preimage(
    instance: *mut JamInstance,
    service_id: u32,
    hash: *const u8,
    blob: *const u8,
    blob_len: usize,
) -> u32 {
    if instance.is_null() || hash.is_null() || blob.is_null() { return 1; }
    let ctx = &mut (*instance).context;
    let mut h = [0u8; 32];
    h.copy_from_slice(std::slice::from_raw_parts(hash, 32));
    let data = std::slice::from_raw_parts(blob, blob_len).to_vec();
    ctx.service_accounts.entry(service_id).or_default().preimages.insert(h, data);
    0
}

/// Set the balance for another service's account (d[service_id]).
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_service_balance(
    instance: *mut JamInstance,
    service_id: u32,
    balance: u64,
) -> u32 {
    if instance.is_null() { return 1; }
    let ctx = &mut (*instance).context;
    ctx.service_accounts.entry(service_id).or_default().balance = balance;
    0
}

/// Set full info fields for another service's account (d[service_id]).
///
/// These fields are needed for Ω_I (information-on-service) and Ω_W FULL check.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `code_hash` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_service_info(
    instance: *mut JamInstance,
    service_id: u32,
    code_hash: *const u8,
    balance: u64,
    threshold: u64,
    min_accum_gas: u64,
    min_item_gas: u64,
    min_on_transfer_gas: u64,
    items_count: u32,
    footprint: u64,
    recent_count: u32,
    accum_gas_limit: u32,
    preimage_pages: u32,
) -> u32 {
    if instance.is_null() || code_hash.is_null() { return 1; }
    let ctx = &mut (*instance).context;
    let acct = ctx.service_accounts.entry(service_id).or_default();
    acct.code_hash.copy_from_slice(std::slice::from_raw_parts(code_hash, 32));
    acct.balance = balance;
    acct.threshold = threshold;
    acct.min_accum_gas = min_accum_gas;
    acct.min_item_gas = min_item_gas;
    acct.min_on_transfer_gas = min_on_transfer_gas;
    acct.items_count = items_count;
    acct.footprint = footprint;
    acct.recent_count = recent_count;
    acct.accum_gas_limit = accum_gas_limit;
    acct.preimage_pages = preimage_pages;
    0
}

// ============================================================================
// Context setup (before execution)
// ============================================================================

/// Add a storage entry to a JAM instance.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `key` must point to `key_len` valid bytes.
/// - `value` must point to `value_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_storage(
    instance: *mut JamInstance,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) -> u32 {
    if instance.is_null() || key.is_null() || value.is_null() {
        return 1;
    }
    let ctx = &mut (*instance).context;
    let k = std::slice::from_raw_parts(key, key_len).to_vec();
    let v = std::slice::from_raw_parts(value, value_len).to_vec();
    ctx.storage.insert(k, v);
    0
}

/// Add a preimage to a JAM instance.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `hash` must point to 32 bytes.
/// - `blob` must point to `blob_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_preimage(
    instance: *mut JamInstance,
    hash: *const u8,
    blob: *const u8,
    blob_len: usize,
) -> u32 {
    if instance.is_null() || hash.is_null() || blob.is_null() {
        return 1;
    }
    let ctx = &mut (*instance).context;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(std::slice::from_raw_parts(hash, 32));
    let data = std::slice::from_raw_parts(blob, blob_len).to_vec();
    ctx.preimages.insert(hash_arr, data);
    0
}

/// Set entropy for a JAM instance.
///
/// Can be 32 bytes (η₀' for accumulate) or 128 bytes (full pool).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `entropy` must point to `entropy_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_entropy(
    instance: *mut JamInstance,
    entropy: *const u8,
    entropy_len: usize,
) -> u32 {
    if instance.is_null() || entropy.is_null() {
        return 1;
    }
    let ctx = &mut (*instance).context;
    let data = std::slice::from_raw_parts(entropy, entropy_len);
    ctx.entropy_raw = data.to_vec();

    // Also fill the 4×32 array
    if entropy_len >= 128 {
        for i in 0..4 {
            ctx.entropy[i].copy_from_slice(&data[i * 32..(i + 1) * 32]);
        }
    } else if entropy_len >= 32 {
        ctx.entropy[0].copy_from_slice(&data[0..32]);
    }
    0
}

/// Add an accumulate item (pre-encoded) to a JAM instance.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `item` must point to `item_len` bytes (or null if `item_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_accumulate_item(
    instance: *mut JamInstance,
    item: *const u8,
    item_len: usize,
) -> u32 {
    if instance.is_null() || (item.is_null() && item_len > 0) {
        return 1;
    }
    let ctx = &mut (*instance).context;
    let data = if item_len > 0 {
        std::slice::from_raw_parts(item, item_len).to_vec()
    } else {
        Vec::new()
    };
    ctx.accumulate_items.push(data);
    0
}

/// Set the work package for a JAM instance.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_work_package(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) {
        return 1;
    }
    let ctx = &mut (*instance).context;
    ctx.work_package = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    0
}

/// Set protocol parameters for a JAM instance.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_protocol_params(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) {
        return 1;
    }
    let ctx = &mut (*instance).context;
    ctx.protocol_params = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    0
}

/// Set next service ID for `new()` host calls.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_set_next_service_id(instance: *mut JamInstance, next_id: u32) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    (*instance).context.next_service_id = next_id;
    0
}

/// Set our own service's info fields (for Ω_I self-lookup and Ω_W FULL check).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `code_hash` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_own_service_info(
    instance: *mut JamInstance,
    code_hash: *const u8,
    threshold: u64,
    min_accum_gas: u64,
    min_item_gas: u64,
    min_on_transfer_gas: u64,
    items_count: u32,
    footprint: u64,
    recent_count: u32,
    accum_gas_limit: u32,
    preimage_pages: u32,
) -> u32 {
    if instance.is_null() || code_hash.is_null() { return 1; }
    let ctx = &mut (*instance).context;
    ctx.code_hash.copy_from_slice(std::slice::from_raw_parts(code_hash, 32));
    ctx.threshold = threshold;
    ctx.min_accum_gas = min_accum_gas;
    ctx.min_item_gas = min_item_gas;
    ctx.min_on_transfer_gas = min_on_transfer_gas;
    ctx.items_count = items_count;
    ctx.footprint = footprint;
    ctx.recent_count = recent_count;
    ctx.accum_gas_limit = accum_gas_limit;
    ctx.preimage_pages = preimage_pages;
    0
}

/// Set the storage threshold (a_t) for our own service.
/// Used by Ω_W to check `a_t > a_b` → FULL.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_threshold(
    instance: *mut JamInstance,
    threshold: u64,
) -> u32 {
    if instance.is_null() { return 1; }
    (*instance).context.threshold = threshold;
    0
}

/// Set the segment size (W_G) for Ω_E export.
/// Default is 4104 bytes (GP §I.4).
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_segment_size(
    instance: *mut JamInstance,
    size: u32,
) -> u32 {
    if instance.is_null() { return 1; }
    (*instance).context.segment_size = size;
    0
}

/// Set the max export count (W_X) for Ω_E FULL check.
/// Default is 3072 (GP §I.4).
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_max_exports(
    instance: *mut JamInstance,
    max: u32,
) -> u32 {
    if instance.is_null() { return 1; }
    (*instance).context.max_exports = max;
    0
}

/// Set the export base (ς) — count of already-existing segments before
/// this refine invocation. Used by Ω_E return value and FULL check.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_export_base(
    instance: *mut JamInstance,
    base: u32,
) -> u32 {
    if instance.is_null() { return 1; }
    (*instance).context.export_base = base;
    0
}

/// Set the current timeslot (t) for Ω_H historical lookup.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_timeslot(
    instance: *mut JamInstance,
    timeslot: u32,
) -> u32 {
    if instance.is_null() { return 1; }
    (*instance).context.timeslot = timeslot;
    0
}

// ============================================================================
// Accessors — transfers
// ============================================================================

/// Get number of transfers made during execution.
#[no_mangle]
pub unsafe extern "C" fn jam_get_transfer_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.transfers.len() as u32
}

/// Get transfer at `index`. Writes `amount` and `memo` to out pointers.
/// Returns the `to_service_id`, or `u32::MAX` on error.
///
/// # Safety
/// All pointers must be valid or null.
#[no_mangle]
pub unsafe extern "C" fn jam_get_transfer(
    instance: *mut JamInstance,
    index: u32,
    amount_out: *mut u64,
    memo_out: *mut u8,
    memo_len: usize,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.transfers.len() { return u32::MAX; }
    let t = &ctx.transfers[i];
    if !amount_out.is_null() { *amount_out = t.amount; }
    if !memo_out.is_null() {
        let n = std::cmp::min(t.memo.len(), memo_len);
        if n > 0 { std::ptr::copy_nonoverlapping(t.memo.as_ptr(), memo_out, n); }
    }
    t.to_service
}

/// Get transfer memo length at `index`.
#[no_mangle]
pub unsafe extern "C" fn jam_get_transfer_memo_len(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.transfers.len() { return u32::MAX; }
    ctx.transfers[i].memo.len() as u32
}

// ============================================================================
// Accessors — logs
// ============================================================================

/// Get number of log entries.
#[no_mangle]
pub unsafe extern "C" fn jam_get_log_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.logs.len() as u32
}

/// Get log entry at `index`. Writes to `out`. Returns log length or `u32::MAX`.
///
/// # Safety
/// `out` must point to `out_len` writable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn jam_get_log(
    instance: *mut JamInstance,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.logs.len() { return u32::MAX; }
    let log = &ctx.logs[i];
    if !out.is_null() {
        let n = std::cmp::min(log.len(), out_len);
        if n > 0 { std::ptr::copy_nonoverlapping(log.as_ptr(), out, n); }
    }
    log.len() as u32
}

// ============================================================================
// Accessors — balance
// ============================================================================

/// Get service balance after execution.
#[no_mangle]
pub unsafe extern "C" fn jam_get_balance(instance: *mut JamInstance) -> u64 {
    if instance.is_null() { return 0; }
    (*instance).context.balance
}

// ============================================================================
// Accessors — storage iteration
// ============================================================================

/// Get number of storage entries.
#[no_mangle]
pub unsafe extern "C" fn jam_get_storage_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.storage.len() as u32
}

/// Get storage key at `index`. Returns key length or `u32::MAX`.
///
/// # Safety
/// `out` must point to `out_len` writable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn jam_get_storage_key(
    instance: *mut JamInstance,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let keys: Vec<&Vec<u8>> = (*instance).context.storage.keys().collect();
    let i = index as usize;
    if i >= keys.len() { return u32::MAX; }
    let key = keys[i];
    if !out.is_null() {
        let n = std::cmp::min(key.len(), out_len);
        if n > 0 { std::ptr::copy_nonoverlapping(key.as_ptr(), out, n); }
    }
    key.len() as u32
}

/// Get storage value at `index`. Returns value length or `u32::MAX`.
///
/// # Safety
/// `out` must point to `out_len` writable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn jam_get_storage_value(
    instance: *mut JamInstance,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let entries: Vec<(&Vec<u8>, &Vec<u8>)> = (*instance).context.storage.iter().collect();
    let i = index as usize;
    if i >= entries.len() { return u32::MAX; }
    let (_, value) = entries[i];
    if !out.is_null() {
        let n = std::cmp::min(value.len(), out_len);
        if n > 0 { std::ptr::copy_nonoverlapping(value.as_ptr(), out, n); }
    }
    value.len() as u32
}

// ============================================================================
// Accessors — ejected services
// ============================================================================

/// Get number of services ejected during execution.
#[no_mangle]
pub unsafe extern "C" fn jam_get_ejected_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.ejected_services.len() as u32
}

/// Get ejected service ID (target) at `index`.
#[no_mangle]
pub unsafe extern "C" fn jam_get_ejected_service(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.ejected_services.len() { return u32::MAX; }
    ctx.ejected_services[i].0
}

/// Get ejector service ID (caller) at `index`.
#[no_mangle]
pub unsafe extern "C" fn jam_get_ejector_service(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.ejected_services.len() { return u32::MAX; }
    ctx.ejected_services[i].1
}

// ============================================================================
// Accessors — yield output
// ============================================================================

/// Check if `yield_hash` was called during execution. Returns 1 if yes, 0 if no.
#[no_mangle]
pub unsafe extern "C" fn jam_has_yield_output(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    if (*instance).context.yield_output.is_some() { 1 } else { 0 }
}

/// Get the yield output hash (32 bytes). Returns 0 on success, `u32::MAX` on error.
///
/// # Safety
/// `out_buf` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_get_yield_output(
    instance: *mut JamInstance,
    out_buf: *mut u8,
) -> u32 {
    if instance.is_null() || out_buf.is_null() { return u32::MAX; }
    match &(*instance).context.yield_output {
        Some(hash) => {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, 32);
            0
        }
        None => u32::MAX,
    }
}

// ============================================================================
// Accessors — created services
// ============================================================================

/// Get number of services created during execution.
#[no_mangle]
pub unsafe extern "C" fn jam_get_created_service_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.created_services.len() as u32
}

/// Get created service ID at `index`.
#[no_mangle]
pub unsafe extern "C" fn jam_get_created_service_id(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.created_services.len() { return u32::MAX; }
    ctx.created_services[i].0
}

/// Get created service code hash at `index`.
///
/// # Safety
/// `out_buf` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_get_created_service_code_hash(
    instance: *mut JamInstance,
    index: u32,
    out_buf: *mut u8,
) -> u32 {
    if instance.is_null() || out_buf.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.created_services.len() { return u32::MAX; }
    let hash = &ctx.created_services[i].1;
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, 32);
    0
}

// ============================================================================
// B.13 — Collapse (after Accumulate execution)
// ============================================================================

/// Perform collapse C (GP B.13) after accumulate execution.
///
/// `outcome`: 0=Halt, 1=Panic, 2=OutOfGas, 3=HaltWithYield
///
/// When `outcome == 3` (HaltWithYield), `yield_hash` must point to 32 bytes.
/// Otherwise `yield_hash` may be null.
///
/// After this call, the instance's context is replaced with the collapsed
/// state (checkpoint on panic/OOG, regular otherwise).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - When `outcome == 3`, `yield_hash` must point to 32 readable bytes.
///
/// # Returns
/// 0 = success, 1 = null pointer, 2 = invalid outcome.
#[no_mangle]
pub unsafe extern "C" fn jam_accumulate_collapse(
    instance: *mut JamInstance,
    outcome: u32,
    yield_hash: *const u8,
) -> u32 {
    if instance.is_null() {
        return 1;
    }
    let jam = &mut (*instance);

    let pvm_outcome = match outcome {
        0 => PvmOutcome::Halt,
        1 => PvmOutcome::Panic,
        2 => PvmOutcome::OutOfGas,
        3 => {
            if yield_hash.is_null() { return 1; }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(std::slice::from_raw_parts(yield_hash, 32));
            PvmOutcome::HaltWithYield(hash)
        }
        _ => return 2,
    };

    let gas = jam.instance.gas();
    let result = jam.context.collapse(pvm_outcome, gas);

    // Apply collapsed state back into context
    jam.context.transfers = result.transfers;
    jam.context.ejected_services = result.ejected_services;
    jam.context.created_services = result.created_services;
    jam.context.upgrades = result.upgrades;
    jam.context.yield_output = result.yield_output;
    jam.context.provided_preimages = result.provided_preimages;
    jam.context.storage = result.storage;
    jam.context.lookup = result.lookup;
    jam.context.preimages = result.preimages;
    jam.context.empower = result.empower;
    jam.context.items_count = result.items_count;
    jam.context.footprint = result.footprint;
    jam.instance.set_gas(result.gas_remaining);

    0
}

// ============================================================================
// Diagnostic: host-call tracing (zero-cost when disabled)
// ============================================================================

/// Enable host-call tracing on this instance.
#[no_mangle]
pub unsafe extern "C" fn jam_debug_trace_enable(instance: *mut JamInstance) {
    if !instance.is_null() {
        (*instance).context.debug_trace = true;
        (*instance).context.host_call_log.clear();
    }
}

/// Get the number of recorded host calls.
#[no_mangle]
pub unsafe extern "C" fn jam_debug_trace_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.host_call_log.len() as u32
}

/// Read one host-call trace entry: (id, gas_before, gas_after, return_a0, storage_count).
/// Writes into caller-provided pointers. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn jam_debug_trace_entry(
    instance: *mut JamInstance,
    index: u32,
    out_id: *mut u32,
    out_gas_before: *mut i64,
    out_gas_after: *mut i64,
    out_a0: *mut u64,
    out_sc: *mut u32,
) -> u32 {
    if instance.is_null() || out_id.is_null() { return 1; }
    let log = &(*instance).context.host_call_log;
    let i = index as usize;
    if i >= log.len() { return 2; }
    let (id, gb, ga, a0, sc) = log[i];
    *out_id = id;
    *out_gas_before = gb;
    *out_gas_after = ga;
    if !out_a0.is_null() { *out_a0 = a0; }
    if !out_sc.is_null() { *out_sc = sc; }
    0
}

// ============================================================================
// Inner PVM engine (ΩM deblob support)
// ============================================================================

/// Ensure a JAM instance has an inner-PVM engine for deblob (ΩM).
///
/// Creates a fresh interpreter-backend engine and stores it in the context.
/// Safe to call multiple times (no-op if already set).
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_ensure_engine(instance: *mut JamInstance) {
    if instance.is_null() {
        return;
    }
    (*instance).context.ensure_engine();
}

// ============================================================================
// Accessors — upgrades (ΩU side-effects)
// ============================================================================

/// Get number of code upgrades recorded during execution.
#[no_mangle]
pub unsafe extern "C" fn jam_get_upgrade_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.upgrades.len() as u32
}

/// Get upgraded service ID at `index`.
#[no_mangle]
pub unsafe extern "C" fn jam_get_upgrade_service(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.upgrades.len() { return u32::MAX; }
    ctx.upgrades[i].0
}

/// Get upgraded service code hash at `index`.
///
/// # Safety
/// `out_buf` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn jam_get_upgrade_code_hash(
    instance: *mut JamInstance,
    index: u32,
    out_buf: *mut u8,
) -> u32 {
    if instance.is_null() || out_buf.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.upgrades.len() { return u32::MAX; }
    let hash = &ctx.upgrades[i].1;
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, 32);
    0
}

// ============================================================================
// Accessors — empower state (ΩB / ΩA / ΩD side-effects)
// ============================================================================

/// Check if empower state (x_e) was set during execution.
/// Returns 1 if set, 0 if None.
#[no_mangle]
pub unsafe extern "C" fn jam_has_empower(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    if (*instance).context.empower.is_some() { 1 } else { 0 }
}

/// Get empower manager service index. Returns `u32::MAX` if no empower.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_manager(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return u32::MAX; }
    match &(*instance).context.empower {
        Some(e) => e.manager,
        None => u32::MAX,
    }
}

/// Get empower validator service index. Returns `u32::MAX` if no empower.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_validator(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return u32::MAX; }
    match &(*instance).context.empower {
        Some(e) => e.validator,
        None => u32::MAX,
    }
}

/// Get empower staker service index. Returns `u32::MAX` if no empower.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_staker(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return u32::MAX; }
    match &(*instance).context.empower {
        Some(e) => e.staker,
        None => u32::MAX,
    }
}

/// Get number of authorization agents in empower state.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_auth_agent_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    match &(*instance).context.empower {
        Some(e) => e.auth_agents.len() as u32,
        None => 0,
    }
}

/// Get authorization agent at `index`. Returns `u32::MAX` if out of bounds or no empower.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_auth_agent(
    instance: *mut JamInstance,
    index: u32,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    match &(*instance).context.empower {
        Some(e) => {
            let i = index as usize;
            if i >= e.auth_agents.len() { u32::MAX } else { e.auth_agents[i] }
        }
        None => u32::MAX,
    }
}

/// Get number of entries in the empower gas map.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_gas_map_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    match &(*instance).context.empower {
        Some(e) => e.gas_map.len() as u32,
        None => 0,
    }
}

/// Get gas map entry at `index` (iteration order).
///
/// # Safety
/// `out_service` and `out_gas` must point to writable u32/u64 respectively.
///
/// Returns 0 on success, `u32::MAX` on error.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_gas_map_entry(
    instance: *mut JamInstance,
    index: u32,
    out_service: *mut u32,
    out_gas: *mut u64,
) -> u32 {
    if instance.is_null() || out_service.is_null() || out_gas.is_null() {
        return u32::MAX;
    }
    match &(*instance).context.empower {
        Some(e) => {
            let i = index as usize;
            if let Some((&sid, &gas)) = e.gas_map.iter().nth(i) {
                *out_service = sid;
                *out_gas = gas;
                0
            } else {
                u32::MAX
            }
        }
        None => u32::MAX,
    }
}

/// Get number of core authorization queues in empower state.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_queue_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    match &(*instance).context.empower {
        Some(e) => e.queues.len() as u32,
        None => 0,
    }
}

/// Get authorization queue hash at `(core, slot)`.
///
/// # Safety
/// `out_buf` must point to at least 32 writable bytes.
///
/// Returns 0 on success, `u32::MAX` on error.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_queue_entry(
    instance: *mut JamInstance,
    core: u32,
    slot: u32,
    out_buf: *mut u8,
) -> u32 {
    if instance.is_null() || out_buf.is_null() { return u32::MAX; }
    match &(*instance).context.empower {
        Some(e) => {
            let c = core as usize;
            let s = slot as usize;
            if c >= e.queues.len() { return u32::MAX; }
            if s >= e.queues[c].len() { return u32::MAX; }
            std::ptr::copy_nonoverlapping(e.queues[c][s].as_ptr(), out_buf, 32);
            0
        }
        None => u32::MAX,
    }
}

/// Get queue length for a specific core.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_queue_len(
    instance: *mut JamInstance,
    core: u32,
) -> u32 {
    if instance.is_null() { return 0; }
    match &(*instance).context.empower {
        Some(e) => {
            let c = core as usize;
            if c >= e.queues.len() { 0 } else { e.queues[c].len() as u32 }
        }
        None => 0,
    }
}

/// Get number of designated validator keys in empower state.
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_validator_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    match &(*instance).context.empower {
        Some(e) => e.validators.len() as u32,
        None => 0,
    }
}

/// Get designated validator key at `index`.
///
/// If `out_buf` is null or `out_len` is 0, returns the key length without writing.
/// Otherwise writes min(key_len, out_len) bytes and returns key_len.
///
/// # Safety
/// `out_buf` must point to at least `out_len` writable bytes (when non-null).
#[no_mangle]
pub unsafe extern "C" fn jam_get_empower_validator_key(
    instance: *mut JamInstance,
    index: u32,
    out_buf: *mut u8,
    out_len: u32,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    match &(*instance).context.empower {
        Some(e) => {
            let i = index as usize;
            if i >= e.validators.len() { return u32::MAX; }
            let key = &e.validators[i];
            let key_len = key.len() as u32;
            if !out_buf.is_null() && out_len > 0 {
                let copy_len = std::cmp::min(key_len, out_len) as usize;
                std::ptr::copy_nonoverlapping(key.as_ptr(), out_buf, copy_len);
            }
            key_len
        }
        None => u32::MAX,
    }
}

// ============================================================================
// Accessors — provided preimages (Ωψ side-effects)
// ============================================================================

/// Get number of provided preimages recorded during execution.
#[no_mangle]
pub unsafe extern "C" fn jam_get_provided_preimage_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.provided_preimages.len() as u32
}

/// Get provided preimage service ID at `index`.
#[no_mangle]
pub unsafe extern "C" fn jam_get_provided_preimage_service(
    instance: *mut JamInstance,
    index: u32,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.provided_preimages.len() { return u32::MAX; }
    ctx.provided_preimages[i].0
}

/// Get provided preimage data at `index`.
///
/// If `out_buf` is null or `out_len` is 0, returns the data length without writing.
/// Otherwise writes min(data_len, out_len) bytes and returns data_len.
///
/// # Safety
/// `out_buf` must point to at least `out_len` writable bytes (when non-null).
#[no_mangle]
pub unsafe extern "C" fn jam_get_provided_preimage_data(
    instance: *mut JamInstance,
    index: u32,
    out_buf: *mut u8,
    out_len: u32,
) -> u32 {
    if instance.is_null() { return u32::MAX; }
    let ctx = &(*instance).context;
    let i = index as usize;
    if i >= ctx.provided_preimages.len() { return u32::MAX; }
    let data = &ctx.provided_preimages[i].1;
    let data_len = data.len() as u32;
    if !out_buf.is_null() && out_len > 0 {
        let copy_len = std::cmp::min(data_len, out_len) as usize;
        std::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, copy_len);
    }
    data_len
}

// ============================================================================
// Setter + Getter — lookup table a_l (preimage metadata)
// ============================================================================

/// Add an entry to the lookup table `a_l` before execution.
///
/// # Safety
/// - `hash_ptr` must point to 32 readable bytes.
/// - `status_ptr` must point to `status_count` readable u32 values.
///
/// Returns 0 on success, `u32::MAX` on error.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_lookup_entry(
    instance: *mut JamInstance,
    hash_ptr: *const u8,
    length: u32,
    status_ptr: *const u32,
    status_count: u32,
) -> u32 {
    if instance.is_null() || hash_ptr.is_null() { return u32::MAX; }
    if status_count > 3 { return u32::MAX; }
    if status_count > 0 && status_ptr.is_null() { return u32::MAX; }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(std::slice::from_raw_parts(hash_ptr, 32));

    let status: Vec<u32> = if status_count > 0 {
        std::slice::from_raw_parts(status_ptr, status_count as usize).to_vec()
    } else {
        Vec::new()
    };

    (*instance).context.lookup.insert((hash, length), status);
    0
}

/// Get number of entries in the lookup table `a_l`.
#[no_mangle]
pub unsafe extern "C" fn jam_get_lookup_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() { return 0; }
    (*instance).context.lookup.len() as u32
}

/// Get lookup table entry at `index` (iteration order).
///
/// Writes the 32-byte hash to `out_hash`, the preimage length to `out_length`,
/// and the status tuple (0–3 u32 values) to `out_status`.
///
/// Returns the number of status values written, or `u32::MAX` on error.
///
/// # Safety
/// - `out_hash` must point to at least 32 writable bytes.
/// - `out_length` must point to a writable u32.
/// - `out_status` must point to at least `max_status` writable u32 values.
#[no_mangle]
pub unsafe extern "C" fn jam_get_lookup_entry(
    instance: *mut JamInstance,
    index: u32,
    out_hash: *mut u8,
    out_length: *mut u32,
    out_status: *mut u32,
    max_status: u32,
) -> u32 {
    if instance.is_null() || out_hash.is_null() || out_length.is_null() || out_status.is_null() {
        return u32::MAX;
    }
    let ctx = &(*instance).context;
    let i = index as usize;
    if let Some(((hash, length), status)) = ctx.lookup.iter().nth(i) {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
        *out_length = *length;
        let copy_count = std::cmp::min(status.len(), max_status as usize);
        if copy_count > 0 {
            std::ptr::copy_nonoverlapping(status.as_ptr(), out_status, copy_count);
        }
        status.len() as u32
    } else {
        u32::MAX
    }
}
