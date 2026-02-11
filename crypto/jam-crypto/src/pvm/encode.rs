//! AccumulateItem encoding and GP constants (GP Appendix B)
//!
//! Provides FFI functions for encoding work items into the format
//! expected by PVM accumulate, and encoding protocol parameters.

use jam_types::{
    AccumulateItem, WorkItemRecord, WorkPackageHash, SegmentTreeRoot,
    AuthorizerHash, PayloadHash, WorkOutput, AuthTrace, Encode, ProtocolParameters,
};

// ============================================================================
// GP Constants encoding
// ============================================================================

/// Encode [`ProtocolParameters`] as GP constants for `fetch(kind=0)`.
///
/// Format: 136 bytes, all little-endian.
pub fn encode_gp_constants(params: &ProtocolParameters) -> Vec<u8> {
    let mut buf = Vec::with_capacity(136);

    // B_I, B_L, B_S (u64)
    buf.extend_from_slice(&(params.deposit_per_item as u64).to_le_bytes());
    buf.extend_from_slice(&(params.deposit_per_byte as u64).to_le_bytes());
    buf.extend_from_slice(&(params.deposit_per_account as u64).to_le_bytes());
    // C (u16), D (u32), E (u32)
    buf.extend_from_slice(&(params.core_count as u16).to_le_bytes());
    buf.extend_from_slice(&(params.min_turnaround_period as u32).to_le_bytes());
    buf.extend_from_slice(&(params.epoch_period as u32).to_le_bytes());
    // G_A, G_I, G_R, G_T (u64)
    buf.extend_from_slice(&(params.max_accumulate_gas as u64).to_le_bytes());
    buf.extend_from_slice(&(params.max_is_authorized_gas as u64).to_le_bytes());
    buf.extend_from_slice(&(params.max_refine_gas as u64).to_le_bytes());
    buf.extend_from_slice(&(params.block_gas_limit as u64).to_le_bytes());
    // H, I, J, K (u16), L (u32), N, O (u16)
    buf.extend_from_slice(&(params.recent_block_count as u16).to_le_bytes());
    buf.extend_from_slice(&(params.max_work_items as u16).to_le_bytes());
    buf.extend_from_slice(&(params.max_dependencies as u16).to_le_bytes());
    buf.extend_from_slice(&(params.max_tickets_per_block as u16).to_le_bytes());
    buf.extend_from_slice(&(params.max_lookup_anchor_age as u32).to_le_bytes());
    buf.extend_from_slice(&(params.tickets_attempts_number as u16).to_le_bytes());
    buf.extend_from_slice(&(params.auth_window as u16).to_le_bytes());
    // P, Q, R, T, U, V (u16)
    buf.extend_from_slice(&(params.slot_period_sec as u16).to_le_bytes());
    buf.extend_from_slice(&(params.auth_queue_len as u16).to_le_bytes());
    buf.extend_from_slice(&(params.rotation_period as u16).to_le_bytes());
    buf.extend_from_slice(&(params.max_extrinsics as u16).to_le_bytes());
    buf.extend_from_slice(&(params.availability_timeout as u16).to_le_bytes());
    buf.extend_from_slice(&(params.val_count as u16).to_le_bytes());
    // W_A, W_B, W_C, W_E, W_M, W_P, W_R, W_T, W_X (u32)
    buf.extend_from_slice(&(params.max_authorizer_code_size as u32).to_le_bytes());
    buf.extend_from_slice(&(params.max_input as u32).to_le_bytes());
    buf.extend_from_slice(&(params.max_service_code_size as u32).to_le_bytes());
    buf.extend_from_slice(&(params.basic_piece_len as u32).to_le_bytes());
    buf.extend_from_slice(&(params.max_imports as u32).to_le_bytes());
    buf.extend_from_slice(&(params.segment_piece_count as u32).to_le_bytes());
    buf.extend_from_slice(&(params.max_report_elective_data as u32).to_le_bytes());
    buf.extend_from_slice(&(params.transfer_memo_size as u32).to_le_bytes());
    buf.extend_from_slice(&(params.max_exports as u32).to_le_bytes());
    // Y (u32)
    buf.extend_from_slice(&(params.epoch_tail_start as u32).to_le_bytes());

    buf
}

// ============================================================================
// Compact encoding helper
// ============================================================================

/// Encode a compact integer using `jam_codec`.
fn encode_compact_to(buf: &mut Vec<u8>, value: u64) {
    use jam_codec::Compact;
    Compact(value).encode_to(buf);
}

// ============================================================================
// FFI: v0.1.21 format (struct AccumulateItem)
// ============================================================================

/// Encode a work item in v0.1.21 format (flat struct, no enum tag).
///
/// Field order: package, exports_root, authorizer_hash, auth_output, payload, result.
///
/// # Safety
/// All `*const u8` pointers must point to 32 bytes. `out_buf` must be `out_capacity` bytes.
///
/// Returns actual encoded length, or 0 on error.
#[no_mangle]
pub unsafe extern "C" fn jam_encode_work_item_v21(
    package_hash: *const u8,
    exports_root: *const u8,
    auth_hash: *const u8,
    payload_hash: *const u8,
    result_data: *const u8,
    result_len: u32,
    auth_output_data: *const u8,
    auth_output_len: u32,
    out_buf: *mut u8,
    out_capacity: u32,
) -> u32 {
    if package_hash.is_null() || out_buf.is_null() {
        return 0;
    }

    let mut enc = Vec::with_capacity(256);

    // package: [u8; 32]
    enc.extend_from_slice(std::slice::from_raw_parts(package_hash, 32));

    // exports_root: [u8; 32]
    copy_hash_or_zero(&mut enc, exports_root);

    // authorizer_hash: [u8; 32]
    copy_hash_or_zero(&mut enc, auth_hash);

    // auth_output: Vec<u8> (compact len + data) — BEFORE payload in v0.1.21
    if auth_output_data.is_null() || auth_output_len == 0 {
        enc.push(0);
    } else {
        let data = std::slice::from_raw_parts(auth_output_data, auth_output_len as usize);
        encode_compact_to(&mut enc, auth_output_len as u64);
        enc.extend_from_slice(data);
    }

    // payload: [u8; 32]
    copy_hash_or_zero(&mut enc, payload_hash);

    // result: Ok(data) = 0x00 + compact(len) + data
    enc.push(0x00);
    if result_data.is_null() || result_len == 0 {
        enc.push(0x00);
    } else {
        let data = std::slice::from_raw_parts(result_data, result_len as usize);
        encode_compact_to(&mut enc, result_len as u64);
        enc.extend_from_slice(data);
    }

    write_to_out_buf(&enc, out_buf, out_capacity)
}

// ============================================================================
// FFI: v0.1.26 format (enum AccumulateItem::WorkItem)
// ============================================================================

/// Encode a work item using `jam-types` v0.1.26 format (enum `AccumulateItem::WorkItem`).
///
/// # Safety
/// All `*const u8` hash pointers must point to 32 bytes.
///
/// Returns actual encoded length, or 0 on error.
#[no_mangle]
pub unsafe extern "C" fn jam_encode_work_item_record(
    package_hash: *const u8,
    exports_root: *const u8,
    auth_hash: *const u8,
    payload_hash: *const u8,
    gas_limit: u64,
    result_data: *const u8,
    result_len: u32,
    auth_output_data: *const u8,
    auth_output_len: u32,
    out_buf: *mut u8,
    out_capacity: u32,
) -> u32 {
    if package_hash.is_null() || out_buf.is_null() {
        return 0;
    }

    let package = read_hash(package_hash);
    let exports = read_hash_or_zero(exports_root);
    let auth = read_hash_or_zero(auth_hash);
    let payload = read_hash_or_zero(payload_hash);

    let result = if result_data.is_null() || result_len == 0 {
        Ok(WorkOutput(vec![]))
    } else {
        Ok(WorkOutput(std::slice::from_raw_parts(result_data, result_len as usize).to_vec()))
    };

    let auth_trace = if auth_output_data.is_null() || auth_output_len == 0 {
        AuthTrace(vec![])
    } else {
        AuthTrace(std::slice::from_raw_parts(auth_output_data, auth_output_len as usize).to_vec())
    };

    let record = WorkItemRecord {
        package: WorkPackageHash(package),
        exports_root: SegmentTreeRoot(exports),
        authorizer_hash: AuthorizerHash(auth),
        payload: PayloadHash(payload),
        gas_limit,
        result,
        auth_output: auth_trace,
    };

    let item = AccumulateItem::WorkItem(record);
    let encoded = item.encode();

    write_to_out_buf(&encoded, out_buf, out_capacity)
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn read_hash(ptr: *const u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(std::slice::from_raw_parts(ptr, 32));
    h
}

unsafe fn read_hash_or_zero(ptr: *const u8) -> [u8; 32] {
    if ptr.is_null() {
        [0u8; 32]
    } else {
        read_hash(ptr)
    }
}

unsafe fn copy_hash_or_zero(buf: &mut Vec<u8>, ptr: *const u8) {
    if ptr.is_null() {
        buf.extend_from_slice(&[0u8; 32]);
    } else {
        buf.extend_from_slice(std::slice::from_raw_parts(ptr, 32));
    }
}

unsafe fn write_to_out_buf(data: &[u8], out_buf: *mut u8, out_capacity: u32) -> u32 {
    if data.len() > out_capacity as usize {
        log::debug!("encode: buffer too small ({} > {})", data.len(), out_capacity);
        return 0;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, data.len());
    data.len() as u32
}

// ============================================================================
// Tests
// ============================================================================

// Tests — extracted to pvm/tests/test_encode.rs
#[cfg(test)]
#[path = "tests/test_encode.rs"]
mod tests;
