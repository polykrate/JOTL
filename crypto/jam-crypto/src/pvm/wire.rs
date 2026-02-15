//! JAM-codec wire format for PVM FFI boundary.
//!
//! Replaces 60+ individual getter/setter FFI functions with 2 blob-based
//! functions: `jam_pvm_configure` (input) and `jam_pvm_collect` (output).
//!
//! Wire format uses JAM codec (GP Appendix C):
//! - Fixed-width LE integers (u8, u16, u32, u64, i64)
//! - JAM compact-prefixed sequences
//! - Sequential tuple layout (no separators)
//! - Option: 0x00 = None, 0x01 + T = Some(T)

use jam_codec::Compact;
use jam_types::Encode as JamEncode;

use super::context::{
    JamHostContext, JamInstance, EmpowerState,
    InvocationContext, ServiceAccount, WorkItemInfo,
};

// ============================================================================
// JAM compact encoding helpers
// ============================================================================

/// Encode a JAM compact integer into `buf`.
fn compact_to(buf: &mut Vec<u8>, value: u64) {
    Compact(value).encode_to(buf);
}

/// Encode a JAM compact-prefixed byte sequence (compact(len) + bytes).
fn bytes_to(buf: &mut Vec<u8>, data: &[u8]) {
    compact_to(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Decode a JAM compact integer from `data[pos..]`.
/// Returns `(value, bytes_consumed)` or `None` on underflow.
fn compact_from(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= data.len() {
        return None;
    }
    let first = data[pos];
    let leading_ones = first.leading_ones() as usize;
    let total = leading_ones + 1;
    if pos + total > data.len() {
        return None;
    }
    if leading_ones == 8 {
        // 0xFF prefix: pure 8-byte LE
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[pos + 1..pos + 9]);
        return Some((u64::from_le_bytes(bytes), 9));
    }
    let data_bits = 7usize.saturating_sub(leading_ones);
    let mask = (1u64 << data_bits) - 1;
    let rem = (first as u64) & mask;
    let mut low: u64 = 0;
    for i in 1..total {
        low |= (data[pos + i] as u64) << (8 * (i - 1));
    }
    Some((low + (rem << (8 * leading_ones)), total))
}

/// Read a fixed-size LE integer from `data[pos..]`.
fn read_u8(data: &[u8], pos: usize) -> Option<(u8, usize)> {
    data.get(pos).map(|&v| (v, 1))
}
fn read_u16(data: &[u8], pos: usize) -> Option<(u16, usize)> {
    if pos + 2 > data.len() { return None; }
    Some((u16::from_le_bytes([data[pos], data[pos + 1]]), 2))
}
fn read_u32(data: &[u8], pos: usize) -> Option<(u32, usize)> {
    if pos + 4 > data.len() { return None; }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[pos..pos + 4]);
    Some((u32::from_le_bytes(b), 4))
}
fn read_u64(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos + 8 > data.len() { return None; }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[pos..pos + 8]);
    Some((u64::from_le_bytes(b), 8))
}
fn read_i64(data: &[u8], pos: usize) -> Option<(i64, usize)> {
    if pos + 8 > data.len() { return None; }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[pos..pos + 8]);
    Some((i64::from_le_bytes(b), 8))
}
fn read_bytes32(data: &[u8], pos: usize) -> Option<([u8; 32], usize)> {
    if pos + 32 > data.len() { return None; }
    let mut b = [0u8; 32];
    b.copy_from_slice(&data[pos..pos + 32]);
    Some((b, 32))
}
fn read_bytes128(data: &[u8], pos: usize) -> Option<([u8; 128], usize)> {
    if pos + 128 > data.len() { return None; }
    let mut b = [0u8; 128];
    b.copy_from_slice(&data[pos..pos + 128]);
    Some((b, 128))
}

/// Read a compact-prefixed byte sequence from `data[pos..]`.
fn read_blob(data: &[u8], pos: usize) -> Option<(Vec<u8>, usize)> {
    let (len, hdr) = compact_from(data, pos)?;
    let len = len as usize;
    if pos + hdr + len > data.len() { return None; }
    Some((data[pos + hdr..pos + hdr + len].to_vec(), hdr + len))
}

// ============================================================================
// Phase 1: encode_side_effects (collect output)
// ============================================================================

/// Encode all PVM side-effects as a JAM tuple blob.
///
/// Layout:
/// ```text
/// u64-LE: balance
/// i64-LE: gas_remaining
/// seq[(blob, blob)]: storage
/// seq[(u32, u64, [u8;128], u32, u64)]: transfers
/// seq[(u32, u32)]: ejected
/// seq[(u32, [u8;32])]: created
/// seq[(u32, [u8;32])]: upgrades
/// option(empower_tuple): empower
/// seq[(u32, blob)]: provided_preimages
/// seq[([u8;32], u32, seq[u32])]: lookup
/// seq[([u8;32], blob)]: preimages (a_P blob store)
/// option([u8;32]): yield_output
/// ```
pub fn encode_side_effects(ctx: &JamHostContext, gas: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // balance: u64-LE
    buf.extend_from_slice(&ctx.balance.to_le_bytes());
    // gas_remaining: i64-LE
    buf.extend_from_slice(&gas.to_le_bytes());

    // storage: seq[(blob, blob)]
    compact_to(&mut buf, ctx.storage.len() as u64);
    for (k, v) in &ctx.storage {
        bytes_to(&mut buf, k);
        bytes_to(&mut buf, v);
    }

    // transfers: seq[(u32, u64, [u8;W_T], u32, u64)]
    compact_to(&mut buf, ctx.transfers.len() as u64);
    for t in &ctx.transfers {
        buf.extend_from_slice(&t.to_service.to_le_bytes());
        buf.extend_from_slice(&t.amount.to_le_bytes());
        // memo: pad or truncate to 128 bytes
        let mut memo = [0u8; 128];
        let copy_len = t.memo.len().min(128);
        memo[..copy_len].copy_from_slice(&t.memo[..copy_len]);
        buf.extend_from_slice(&memo);
        buf.extend_from_slice(&t.from_service.to_le_bytes());
        buf.extend_from_slice(&t.gas_limit.to_le_bytes());
    }

    // ejected: seq[(u32, u32)]
    compact_to(&mut buf, ctx.ejected_services.len() as u64);
    for &(target, ejector) in &ctx.ejected_services {
        buf.extend_from_slice(&target.to_le_bytes());
        buf.extend_from_slice(&ejector.to_le_bytes());
    }

    // created: seq[(u32, [u8;32])]
    compact_to(&mut buf, ctx.created_services.len() as u64);
    for &(id, ref hash) in &ctx.created_services {
        buf.extend_from_slice(&id.to_le_bytes());
        buf.extend_from_slice(hash);
    }

    // upgrades: seq[(u32, [u8;32])]
    compact_to(&mut buf, ctx.upgrades.len() as u64);
    for &(id, ref hash) in &ctx.upgrades {
        buf.extend_from_slice(&id.to_le_bytes());
        buf.extend_from_slice(hash);
    }

    // empower: option(empower_tuple)
    encode_empower_option(&mut buf, &ctx.empower);

    // provided_preimages: seq[(u32, blob)]
    compact_to(&mut buf, ctx.provided_preimages.len() as u64);
    for (service_id, data) in &ctx.provided_preimages {
        buf.extend_from_slice(&service_id.to_le_bytes());
        bytes_to(&mut buf, data);
    }

    // lookup: seq[([u8;32], u32, seq[u32])]
    compact_to(&mut buf, ctx.lookup.len() as u64);
    for ((hash, length), status) in &ctx.lookup {
        buf.extend_from_slice(hash);
        buf.extend_from_slice(&length.to_le_bytes());
        compact_to(&mut buf, status.len() as u64);
        for &s in status {
            buf.extend_from_slice(&s.to_le_bytes());
        }
    }

    // preimages: seq[([u8;32], blob)] — final preimage blob store (a_P)
    // Needed so Lisp merge can detect blobs removed by ΩF.
    compact_to(&mut buf, ctx.preimages.len() as u64);
    for (hash, data) in &ctx.preimages {
        buf.extend_from_slice(hash);
        bytes_to(&mut buf, data);
    }

    // yield_output: option([u8;32])
    match &ctx.yield_output {
        Some(h) => {
            buf.push(0x01);
            buf.extend_from_slice(h);
        }
        None => buf.push(0x00),
    }

    // items_count & footprint: tracked incrementally from initial metadata values.
    // Each host call (ΩW/ΩS/ΩF) adjusts them per GP §9.3:
    //   a_i = 2·|a_l| + |a_s|  (items)
    //   a_o = Σ_{(h,z)∈K(a_l)} (81+z) + Σ_{(x,y)∈a_s} (34+|y|+|x|)  (footprint)
    buf.extend_from_slice(&ctx.items_count.to_le_bytes());
    buf.extend_from_slice(&ctx.footprint.to_le_bytes());

    buf
}

/// Encode Option<EmpowerState> as a JAM option tuple.
fn encode_empower_option(buf: &mut Vec<u8>, empower: &Option<EmpowerState>) {
    match empower {
        None => buf.push(0x00),
        Some(e) => {
            buf.push(0x01);
            // manager: u32
            buf.extend_from_slice(&e.manager.to_le_bytes());
            // auth_agents: seq[u32]
            compact_to(buf, e.auth_agents.len() as u64);
            for &a in &e.auth_agents {
                buf.extend_from_slice(&a.to_le_bytes());
            }
            // validator: u32
            buf.extend_from_slice(&e.validator.to_le_bytes());
            // staker: u32
            buf.extend_from_slice(&e.staker.to_le_bytes());
            // gas_map: seq[(u32, u64)]
            compact_to(buf, e.gas_map.len() as u64);
            for (&sid, &gas) in &e.gas_map {
                buf.extend_from_slice(&sid.to_le_bytes());
                buf.extend_from_slice(&gas.to_le_bytes());
            }
            // queues: seq[seq[[u8;32]]]
            compact_to(buf, e.queues.len() as u64);
            for queue in &e.queues {
                compact_to(buf, queue.len() as u64);
                for hash in queue {
                    buf.extend_from_slice(hash);
                }
            }
            // validators: seq[blob]
            compact_to(buf, e.validators.len() as u64);
            for key in &e.validators {
                bytes_to(buf, key);
            }
        }
    }
}

// ============================================================================
// Phase 2: decode_pvm_config (configure input)
// ============================================================================

/// Decode a JAM-encoded PVM configuration blob into a JamHostContext.
///
/// Layout:
/// ```text
/// u8: invocation_context (0-3)
/// u32-LE: service_id
/// u64-LE: balance
/// u32-LE: timeslot
/// [u8;128]: entropy (4 × 32)
/// [u8;32]: header_hash
/// [u8;32]: code_hash
/// u64-LE: threshold
/// u64-LE: min_accum_gas
/// u64-LE: min_memo_gas
/// u32-LE: items_count
/// u64-LE: footprint
/// u32-LE: recent_count
/// u32-LE: accum_gas_limit
/// u32-LE: preimage_pages
/// i64-LE: gas
/// seq[(blob, blob)]: own storage
/// seq[([u8;32], blob)]: own preimages
/// seq[([u8;32], u32, seq[u32])]: own lookup
/// seq[(u32, service_account_blob)]: cross-service accounts
/// seq[u32]: existing_services
/// seq[blob]: accumulate_items
/// seq[work_item_blob]: work_items
/// u16-LE: core_count
/// u16-LE: auth_queue_len
/// u16-LE: val_count
/// ```
pub fn decode_pvm_config(data: &[u8], ctx: &mut JamHostContext) -> Result<usize, &'static str> {
    let mut pos = 0;

    // invocation_context: u8
    let (inv, n) = read_u8(data, pos).ok_or("invocation")?;
    pos += n;
    ctx.invocation = match inv {
        0 => InvocationContext::IsAuthorized,
        1 => InvocationContext::Refine,
        2 => InvocationContext::Accumulate,
        3 => InvocationContext::OnTransfer,
        _ => return Err("bad invocation context"),
    };

    // service_id: u32
    let (v, n) = read_u32(data, pos).ok_or("service_id")?;
    pos += n; ctx.service_id = v;

    // balance: u64
    let (v, n) = read_u64(data, pos).ok_or("balance")?;
    pos += n; ctx.balance = v;

    // timeslot: u32
    let (v, n) = read_u32(data, pos).ok_or("timeslot")?;
    pos += n; ctx.timeslot = v; ctx.slot = v;

    // entropy: [u8; 128]
    let (raw, n) = read_bytes128(data, pos).ok_or("entropy")?;
    pos += n;
    ctx.entropy_raw = raw.to_vec();
    for i in 0..4 {
        ctx.entropy[i].copy_from_slice(&raw[i * 32..(i + 1) * 32]);
    }

    // header_hash: [u8;32]
    let (v, n) = read_bytes32(data, pos).ok_or("header_hash")?;
    pos += n; ctx.header_hash = v;

    // code_hash: [u8;32]
    let (v, n) = read_bytes32(data, pos).ok_or("code_hash")?;
    pos += n; ctx.code_hash = v;

    // threshold: u64
    let (v, n) = read_u64(data, pos).ok_or("threshold")?;
    pos += n; ctx.threshold = v;

    // min_accum_gas: u64
    let (v, n) = read_u64(data, pos).ok_or("min_accum_gas")?;
    pos += n; ctx.min_accum_gas = v;

    // min_memo_gas: u64 (a_m)
    let (v, n) = read_u64(data, pos).ok_or("min_memo_gas")?;
    pos += n; ctx.min_memo_gas = v;

    // items_count: u32
    let (v, n) = read_u32(data, pos).ok_or("items_count")?;
    pos += n; ctx.items_count = v;

    // footprint: u64
    let (v, n) = read_u64(data, pos).ok_or("footprint")?;
    pos += n; ctx.footprint = v;

    // recent_count: u32
    let (v, n) = read_u32(data, pos).ok_or("recent_count")?;
    pos += n; ctx.recent_count = v;

    // accum_gas_limit: u32
    let (v, n) = read_u32(data, pos).ok_or("accum_gas_limit")?;
    pos += n; ctx.accum_gas_limit = v;

    // preimage_pages: u32
    let (v, n) = read_u32(data, pos).ok_or("preimage_pages")?;
    pos += n; ctx.preimage_pages = v;

    // gas: i64
    let (gas_val, n) = read_i64(data, pos).ok_or("gas")?;
    pos += n;
    // Gas is set on the polkavm instance, not the context.
    // Store it in the context temporarily so jam_pvm_configure can set it.
    ctx.gas_from_config = gas_val;

    // own storage: seq[(blob, blob)]
    let (count, n) = compact_from(data, pos).ok_or("storage count")?;
    pos += n;
    ctx.storage.clear();
    for _ in 0..count {
        let (k, n) = read_blob(data, pos).ok_or("storage key")?;
        pos += n;
        let (v, n) = read_blob(data, pos).ok_or("storage value")?;
        pos += n;
        ctx.storage.insert(k, v);
    }

    // own preimages: seq[([u8;32], blob)]
    let (count, n) = compact_from(data, pos).ok_or("preimages count")?;
    pos += n;
    ctx.preimages.clear();
    for _ in 0..count {
        let (h, n) = read_bytes32(data, pos).ok_or("preimage hash")?;
        pos += n;
        let (d, n) = read_blob(data, pos).ok_or("preimage data")?;
        pos += n;
        ctx.preimages.insert(h, d);
    }

    // own lookup: seq[([u8;32], u32, seq[u32])]
    let (count, n) = compact_from(data, pos).ok_or("lookup count")?;
    pos += n;
    ctx.lookup.clear();
    for _ in 0..count {
        let (h, n) = read_bytes32(data, pos).ok_or("lookup hash")?;
        pos += n;
        let (length, n) = read_u32(data, pos).ok_or("lookup length")?;
        pos += n;
        let (status_count, n) = compact_from(data, pos).ok_or("lookup status count")?;
        pos += n;
        let mut status = Vec::with_capacity(status_count as usize);
        for _ in 0..status_count {
            let (s, n) = read_u32(data, pos).ok_or("lookup status val")?;
            pos += n;
            status.push(s);
        }
        ctx.lookup.insert((h, length), status);
    }

    // cross-service accounts: seq[(u32, service_account_blob)]
    let (count, n) = compact_from(data, pos).ok_or("accounts count")?;
    pos += n;
    ctx.service_accounts.clear();
    for _ in 0..count {
        let (sid, n) = read_u32(data, pos).ok_or("account sid")?;
        pos += n;
        let (acct, n) = decode_service_account(data, pos)?;
        pos += n;
        ctx.service_accounts.insert(sid, acct);
    }

    // existing_services: seq[u32]
    let (count, n) = compact_from(data, pos).ok_or("existing count")?;
    pos += n;
    ctx.existing_services.clear();
    for _ in 0..count {
        let (sid, n) = read_u32(data, pos).ok_or("existing sid")?;
        pos += n;
        ctx.existing_services.insert(sid);
    }

    // accumulate_items: seq[blob]
    let (count, n) = compact_from(data, pos).ok_or("items count")?;
    pos += n;
    ctx.accumulate_items.clear();
    for _ in 0..count {
        let (item, n) = read_blob(data, pos).ok_or("item blob")?;
        pos += n;
        ctx.accumulate_items.push(item);
    }

    // work_items: seq[work_item_blob]
    let (count, n) = compact_from(data, pos).ok_or("work_items count")?;
    pos += n;
    ctx.work_items.clear();
    for _ in 0..count {
        let (wi, n) = decode_work_item_info(data, pos)?;
        pos += n;
        ctx.work_items.push(wi);
    }

    // core_count: u16
    let (v, n) = read_u16(data, pos).ok_or("core_count")?;
    pos += n; ctx.core_count = v;

    // auth_queue_len: u16
    let (v, n) = read_u16(data, pos).ok_or("auth_queue_len")?;
    pos += n; ctx.auth_queue_len = v;

    // val_count: u16
    let (v, n) = read_u16(data, pos).ok_or("val_count")?;
    pos += n; ctx.val_count = v;

    Ok(pos)
}

/// Decode a ServiceAccount from a JAM blob at position `pos`.
///
/// Layout: same as encode but in-line:
/// ```text
/// [u8;32]: code_hash
/// u64: balance, threshold, min_accum_gas, min_memo_gas
/// u32: items_count
/// u64: footprint
/// u32: recent_count, accum_gas_limit, preimage_pages
/// seq[(blob, blob)]: storage
/// seq[([u8;32], blob)]: preimages
/// seq[([u8;32], u32, seq[u32])]: lookup
/// ```
fn decode_service_account(data: &[u8], start: usize) -> Result<(ServiceAccount, usize), &'static str> {
    let mut pos = start;
    let mut acct = ServiceAccount::default();

    let (v, n) = read_bytes32(data, pos).ok_or("acct code_hash")?;
    pos += n; acct.code_hash = v;

    let (v, n) = read_u64(data, pos).ok_or("acct balance")?;
    pos += n; acct.balance = v;
    let (v, n) = read_u64(data, pos).ok_or("acct threshold")?;
    pos += n; acct.threshold = v;
    let (v, n) = read_u64(data, pos).ok_or("acct min_accum_gas")?;
    pos += n; acct.min_accum_gas = v;
    let (v, n) = read_u64(data, pos).ok_or("acct min_memo_gas")?;
    pos += n; acct.min_memo_gas = v;

    let (v, n) = read_u32(data, pos).ok_or("acct items_count")?;
    pos += n; acct.items_count = v;
    let (v, n) = read_u64(data, pos).ok_or("acct footprint")?;
    pos += n; acct.footprint = v;
    let (v, n) = read_u32(data, pos).ok_or("acct recent_count")?;
    pos += n; acct.recent_count = v;
    let (v, n) = read_u32(data, pos).ok_or("acct accum_gas_limit")?;
    pos += n; acct.accum_gas_limit = v;
    let (v, n) = read_u32(data, pos).ok_or("acct preimage_pages")?;
    pos += n; acct.preimage_pages = v;

    // storage: seq[(blob, blob)]
    let (count, n) = compact_from(data, pos).ok_or("acct storage count")?;
    pos += n;
    for _ in 0..count {
        let (k, n) = read_blob(data, pos).ok_or("acct storage key")?;
        pos += n;
        let (v, n) = read_blob(data, pos).ok_or("acct storage value")?;
        pos += n;
        acct.storage.insert(k, v);
    }

    // preimages: seq[([u8;32], blob)]
    let (count, n) = compact_from(data, pos).ok_or("acct preimages count")?;
    pos += n;
    for _ in 0..count {
        let (h, n) = read_bytes32(data, pos).ok_or("acct preimage hash")?;
        pos += n;
        let (d, n) = read_blob(data, pos).ok_or("acct preimage data")?;
        pos += n;
        acct.preimages.insert(h, d);
    }

    // lookup: seq[([u8;32], u32, seq[u32])]
    let (count, n) = compact_from(data, pos).ok_or("acct lookup count")?;
    pos += n;
    for _ in 0..count {
        let (h, n) = read_bytes32(data, pos).ok_or("acct lookup hash")?;
        pos += n;
        let (length, n) = read_u32(data, pos).ok_or("acct lookup length")?;
        pos += n;
        let (sc, n) = compact_from(data, pos).ok_or("acct lookup status count")?;
        pos += n;
        let mut status = Vec::with_capacity(sc as usize);
        for _ in 0..sc {
            let (s, n) = read_u32(data, pos).ok_or("acct lookup status")?;
            pos += n;
            status.push(s);
        }
        acct.lookup.insert((h, length), status);
    }

    Ok((acct, pos - start))
}

/// Decode a WorkItemInfo from a JAM blob.
///
/// Layout:
/// ```text
/// u32: service_id
/// [u8;32]: code_hash
/// u64: gas_limit
/// u64: gas_limit_accum
/// blob: payload (compact-prefixed)
/// ```
fn decode_work_item_info(data: &[u8], start: usize) -> Result<(WorkItemInfo, usize), &'static str> {
    let mut pos = start;
    let mut wi = WorkItemInfo::default();

    let (v, n) = read_u32(data, pos).ok_or("wi service_id")?;
    pos += n; wi.service_id = v;
    let (v, n) = read_bytes32(data, pos).ok_or("wi code_hash")?;
    pos += n; wi.code_hash = v;
    let (v, n) = read_u64(data, pos).ok_or("wi gas_limit")?;
    pos += n; wi.gas_limit = v;
    let (v, n) = read_u64(data, pos).ok_or("wi gas_limit_accum")?;
    pos += n; wi.gas_limit_accum = v;
    let (p, n) = read_blob(data, pos).ok_or("wi payload")?;
    pos += n; wi.payload = p;

    Ok((wi, pos - start))
}

// ============================================================================
// Phase 3: Lifecycle — jam_pvm_new / jam_pvm_free
// ============================================================================

use polkavm::{Config, Engine, Module, ModuleConfig, Linker};
use jam_program_blob_common::ProgramBlob as JamProgramBlob;
use super::context::JamHostError;
use super::encode::encode_gp_constants;

/// Create a new JAM PVM instance from a service code blob.
///
/// Combines engine + module_load_jam + pre_new + instance_new into one call.
///
/// # Safety
/// `code` must point to `code_len` valid bytes.
///
/// # Returns
/// Pointer to a `JamInstance`, or null on failure.
#[no_mangle]
pub unsafe extern "C" fn jam_pvm_new(
    code: *const u8,
    code_len: usize,
    service_id: u32,
    balance: u64,
    slot: u32,
) -> *mut JamInstance {
    if code.is_null() || code_len == 0 {
        return std::ptr::null_mut();
    }
    let blob_bytes = std::slice::from_raw_parts(code, code_len);

    // Create engine (interpreter backend for determinism)
    let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
    config.set_backend(Some(polkavm::BackendKind::Interpreter));
    let engine = match Engine::new(&config) {
        Ok(e) => e,
        Err(e) => {
            log::debug!("jam_pvm_new: engine failed: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    // Parse JAM blob
    let jam_blob = match JamProgramBlob::from_bytes(blob_bytes) {
        Some(b) => b,
        None => {
            log::debug!("jam_pvm_new: failed to parse JAM blob");
            return std::ptr::null_mut();
        }
    };
    let parts: polkavm::ProgramParts = jam_blob.into();
    let program_blob = match polkavm::ProgramBlob::from_parts(parts) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("jam_pvm_new: blob from parts failed: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    // Module with gas metering
    let mut module_config = ModuleConfig::new();
    module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    let module = match Module::from_blob(&engine, &module_config, program_blob) {
        Ok(m) => m,
        Err(e) => {
            log::debug!("jam_pvm_new: module failed: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    // Pre-instantiate with empty linker (host calls via execution loop)
    let linker = Linker::<JamHostContext, JamHostError>::new();
    let instance_pre = match linker.instantiate_pre(&module) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("jam_pvm_new: pre failed: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    // Instantiate
    let instance = match instance_pre.instantiate() {
        Ok(i) => i,
        Err(e) => {
            log::debug!("jam_pvm_new: instance failed: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    // Default protocol parameters (TINY)
    let params = jam_types::ProtocolParameters::tiny();
    let encoded_params = encode_gp_constants(&params);

    let context = JamHostContext {
        service_id,
        balance,
        slot,
        protocol_params: encoded_params,
        min_turnaround_period: params.min_turnaround_period,
        ..Default::default()
    };

    Box::into_raw(Box::new(JamInstance { instance, context }))
}

/// Free a JAM PVM instance created by `jam_pvm_new`.
///
/// # Safety
/// `instance` must be a valid pointer from `jam_pvm_new`, or null.
#[no_mangle]
pub unsafe extern "C" fn jam_pvm_free(instance: *mut JamInstance) {
    if !instance.is_null() {
        drop(Box::from_raw(instance));
    }
}

// ============================================================================
// FFI: jam_pvm_configure
// ============================================================================

/// Configure a JAM PVM instance from a JAM-encoded configuration blob.
///
/// # Safety
/// - `instance` must be a valid JamInstance pointer.
/// - `blob` must point to `blob_len` valid bytes.
///
/// # Returns
/// 0 on success, non-zero on failure.
#[no_mangle]
pub unsafe extern "C" fn jam_pvm_configure(
    instance: *mut JamInstance,
    blob: *const u8,
    blob_len: usize,
) -> u32 {
    if instance.is_null() || blob.is_null() {
        return 1;
    }
    let data = std::slice::from_raw_parts(blob, blob_len);
    let jam = &mut (*instance);

    match decode_pvm_config(data, &mut jam.context) {
        Ok(_) => {
            // Set gas on the PVM instance from the config blob
            let gas = jam.context.gas_from_config;
            if gas > 0 {
                jam.instance.set_gas(gas);
            }
            0
        }
        Err(e) => {
            log::debug!("jam_pvm_configure: decode error: {}", e);
            2
        }
    }
}

// ============================================================================
// FFI: jam_pvm_collect
// ============================================================================

/// Collect all PVM side-effects as a JAM-encoded blob.
///
/// # Safety
/// - `instance` must be a valid JamInstance pointer.
/// - `out_buf` must point to `out_cap` writable bytes.
///
/// # Returns
/// Number of bytes written, or 0 if buffer too small or error.
#[no_mangle]
pub unsafe extern "C" fn jam_pvm_collect(
    instance: *mut JamInstance,
    out_buf: *mut u8,
    out_cap: u32,
) -> u32 {
    if instance.is_null() || out_buf.is_null() {
        return 0;
    }
    let jam = &(*instance);
    let gas = jam.instance.gas();
    let encoded = encode_side_effects(&jam.context, gas);

    if encoded.len() > out_cap as usize {
        log::debug!(
            "jam_pvm_collect: buffer too small ({} > {})",
            encoded.len(),
            out_cap
        );
        return 0;
    }
    std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_buf, encoded.len());
    encoded.len() as u32
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests/test_wire.rs"]
mod tests;
