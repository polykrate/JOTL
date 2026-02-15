//! Ω — Virtual machine host-call functions (GP Appendix B)
//!
//! Single canonical dispatch table mapping ecalli indices to GP host calls.
//! Each function implements one Ω from the Gray Paper.
//!
//! Index table verified against:
//!   `jam-pvm-common` 0.1.26 — `src/imports.rs`
//!
//! ## Convention
//!
//! Every `omega_*` function reads arguments from registers A0–A5,
//! writes its result to A0 (and sometimes A1), and returns
//! `Ok(OmegaResult::Continue)` or `Ok(OmegaResult::Fault)`.
//! Errors are signalled in-band via A0 = HC_NONE/HC_WHO/HC_CASH/… (GP B.1).

use polkavm::Reg;
use super::context::{
    JamHostContext, JamHostError, JamTransfer, FetchKind, InnerMachine, EmpowerState,
    HC_NONE, HC_WHAT, HC_OK, HC_OOB, HC_WHO, HC_HUH, HC_CASH, HC_FULL, HC_CORE, HC_LOW,
    PVM_HALT, PVM_PANIC, PVM_FAULT, PVM_HOST, PVM_OOG,
    ServiceAccount, PAGE_SIZE,
    compute_threshold,
};

/// Concrete instance type used throughout the PVM module.
type Inst = polkavm::Instance<JamHostContext, JamHostError>;

// ============================================================================
// Storage key hashing — GP Appendix D
// ============================================================================

/// Compute the 27-byte trie sub-key hash for a storage entry.
///
/// GP D.1: `H(E₄(2³²−1) ⌢ k)[0:27]`
///
/// Implementations are free to use this hash as the canonical storage key
/// (GP §D: "the key values themselves are not required to be known").
fn storage_hash_key(raw_key: &[u8]) -> Vec<u8> {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let prefix = 0xFFFF_FFFFu32.to_le_bytes(); // E₄(2³²−1)
    let mut input = Vec::with_capacity(4 + raw_key.len());
    input.extend_from_slice(&prefix);
    input.extend_from_slice(raw_key);
    let hash = <Blake2b<U32> as Digest>::digest(&input);
    hash[..27].to_vec()
}

/// Result of an individual omega function (internal to dispatch).
enum OmegaResult {
    /// (▸) Host call succeeded, continue execution.
    Continue,
    /// (♯) Page fault — bad memory access.
    Fault,
    /// (∞) Out of gas discovered mid–host-call (ΩT only).
    /// Dispatch already charged 10; the omega deducted the extra cost itself.
    OutOfGas,
}

// ============================================================================
// Helper: safe guest memory access
// ============================================================================

fn read_guest(inst: &Inst, addr: u32, len: u32) -> Option<Vec<u8>> {
    inst.read_memory(addr, len).ok()
}

// ============================================================================
// Λ(a, t, h) — Historical preimage lookup (GP §9.2)
// ============================================================================

/// Historical preimage lookup `Λ(a, t, h)`.
///
/// Returns `Some(data)` if the preimage for `hash` was available in account `a`
/// at timeslot `t`, based on the `a_l` status tuple semantics:
///
/// - `[]`        — solicited, not yet provided → NOT available at any timeslot
/// - `[x]`      — available from timeslot x onward (currently provided)
/// - `[x, y]`   — was available during `[x, y)` but then marked unavailable
/// - `[x, y, z]` — was available during `[x, y)`, then re-solicited at z
///
/// The preimage data comes from `a_P[h]` (the preimages map).
///
/// # GP Definition
/// ```text
/// Λ(a, t, h) =
///   a_P[h]   if (h, |a_P[h]|) ∈ K(a_l) and preimage was available at t
///   ∅        otherwise
/// ```
pub(crate) fn lambda_lookup(
    preimages: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    lookup: &std::collections::HashMap<([u8; 32], u32), Vec<u32>>,
    timeslot: u32,
    hash: &[u8; 32],
) -> Option<Vec<u8>> {
    // Step 1: get the preimage data
    let data = preimages.get(hash)?;
    let data_len = data.len() as u32;

    // Step 2: get the status tuple from a_l
    let status = lookup.get(&(*hash, data_len))?;

    // Step 3: check availability at timeslot t
    let available = match status.as_slice() {
        // [] — solicited, not yet provided → never available
        [] => false,
        // [x] — provided, available from timeslot x onward
        [x] => timeslot >= *x,
        // [x, y] — available during [x, y)
        [x, y] => timeslot >= *x && timeslot < *y,
        // [x, y, z] — available during [x, y), re-solicited at z
        // (z is just re-solicitation, preimage was available in [x, y))
        [x, y, _z] => timeslot >= *x && timeslot < *y,
        // Unexpected — treat as unavailable
        _ => false,
    };

    if available { Some(data.clone()) } else { None }
}

// ============================================================================
// Dispatch — THE canonical table
// ============================================================================

/// Result of host-call dispatch (GP B.16).
///
/// The execution loop uses this to decide whether to continue or halt.
pub enum DispatchResult {
    /// (▸) Continue execution normally.
    Continue,
    /// (∞) Out of gas — host call was NOT executed.
    OutOfGas,
    /// (♯) Page fault during host call — halt with fault.
    Fault,
}

/// Dispatch a host call by its ecalli index.
///
/// **GP B.15**: `ϱ' = ϱ − g` (g = 10 for all host calls).
/// **GP B.16**: if `ϱ < g` → `(∞, φ, μ, s)` — OOG, no mutations.
///
/// Context gating: if the host call is not allowed in the current
/// [`InvocationContext`], we charge gas but leave registers untouched
/// (GP B.2/B.6: "otherwise → (▸, ρ', φ', μ)").
///
/// Called by the execution loop on [`polkavm::InterruptKind::Ecalli`].
pub fn dispatch(
    inst: &mut Inst,
    ctx: &mut JamHostContext,
    id: u32,
) -> Result<DispatchResult, JamHostError> {
    let gas = inst.gas();

    // ── Compute gas cost g per GP B.15 ────────────────────────
    // Default: g = 10 for all host calls.
    // Exception: ΩT (transfer, id=20): g = 10 + t where t depends on outcome
    //   (t = 0 on error, t = l on OK). The base 10 is charged here; the extra
    //   l is charged inside omega_t on success.
    let cost: i64 = 10;

    // ── B.16: OOG gating ──────────────────────────────────────
    // If ϱ < g: return (∞, φ, μ, s) — NO mutations.
    if gas < cost {
        inst.set_gas(gas - cost); // go negative to signal OOG
        log::debug!("dispatch: OOG (gas={} < {}) for ecalli {}", gas, cost, id);
        return Ok(DispatchResult::OutOfGas);
    }

    // B.15: ϱ' = ϱ − g
    inst.set_gas(gas - cost);

    // ── Context gating ─────────────────────────────────────────
    // GP B.2/B.6: calls not in the allowed set → continue with
    // registers unchanged (only gas is decremented).
    if !ctx.invocation.allows(id) {
        log::debug!(
            "dispatch: host call {} blocked in {:?} context — noop",
            id, ctx.invocation
        );
        if ctx.debug_trace {
            ctx.host_call_log.push((id, gas, gas - cost, inst.reg(Reg::A0), ctx.storage.len() as u32));
        }
        return Ok(DispatchResult::Continue);
    }

    // ── Dispatch to the correct Ω function ─────────────────────
    // Each omega returns Ok(OmegaResult) or Err(JamHostError).
    // OmegaResult::Continue = (▸), OmegaResult::Fault = (♯).
    let omega_res = match id {
        //  idx | GP     | Name
        // -----|--------|-------------------------------
        0  => omega_g(inst, ctx),  // ΩG  Gas-remaining
        1  => omega_y(inst, ctx),  // ΩY  Fetch data
        2  => omega_l(inst, ctx),  // ΩL  Lookup-preimage
        3  => omega_r(inst, ctx),  // ΩR  Read-storage
        4  => omega_w(inst, ctx),  // ΩW  Write-storage
        5  => omega_i(inst, ctx),  // ΩI  Information-on-service
        6  => omega_h(inst, ctx),  // ΩH  Historical-lookup-preimage
        7  => omega_e(inst, ctx),  // ΩE  Export segment
        8  => omega_m(inst, ctx),  // ΩM  Make-pvm
        9  => omega_p(inst, ctx),  // ΩP  Peek-pvm
        10 => omega_o(inst, ctx),  // ΩO  Poke-pvm
        11 => omega_z(inst, ctx),  // ΩZ  Pages inner-pvm memory
        12 => omega_k(inst, ctx),  // ΩK  Kickoff-pvm (invoke)
        13 => omega_x(inst, ctx),  // ΩX  Expunge-pvm
        14 => omega_b(inst, ctx),  // ΩB  Empower-service (bless)
        15 => omega_a(inst, ctx),  // ΩA  Assign-core
        16 => omega_d(inst, ctx),  // ΩD  Designate-validators
        17 => omega_c(inst, ctx),  // ΩC  Checkpoint
        18 => omega_n(inst, ctx),  // ΩN  New-service
        19 => omega_u(inst, ctx),  // ΩU  Upgrade-service
        20 => omega_t(inst, ctx),  // ΩT  Transfer
        21 => omega_j(inst, ctx),  // ΩJ  Eject-service
        22 => omega_q(inst, ctx),  // ΩQ  Query-preimage
        23 => omega_s(inst, ctx),  // ΩS  Solicit-preimage
        24 => omega_f(inst, ctx),  // ΩF  Forget-preimage
        25 => omega_yield(inst, ctx), // Yield accumulation trie result
        26 => omega_provide(inst, ctx), // Provide preimage
        100 => ext_log(inst, ctx), // Extension: log (not GP)
        _ => {
            // B.11 fallback: φ'₇ = WHAT, ϱ' = ϱ − 10 (gas already charged above).
            log::debug!("dispatch: unknown ecalli {} → WHAT", id);
            inst.set_reg(Reg::A0, HC_WHAT);
            Ok(OmegaResult::Continue)
        }
    };

    // ── Debug trace AFTER dispatch (captures return A0 + storage count) ──
    if ctx.debug_trace {
        let a0 = inst.reg(Reg::A0);
        let sc = ctx.storage.len() as u32;
        ctx.host_call_log.push((id, gas, gas - cost, a0, sc));
    }

    match omega_res {
        Ok(OmegaResult::Continue) => Ok(DispatchResult::Continue),
        Ok(OmegaResult::Fault) => Ok(DispatchResult::Fault),
        Ok(OmegaResult::OutOfGas) => Ok(DispatchResult::OutOfGas),
        Err(e) => Err(e),
    }
}

// ============================================================================
// 0 — ΩG  Gas-remaining
// ============================================================================

/// `gas() -> remaining_gas`
fn omega_g(inst: &mut Inst, _ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let gas = inst.gas() as u64;
    inst.set_reg(Reg::A0, gas);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 1 — ΩY  Fetch data
// ============================================================================

/// `fetch(buffer, offset, buffer_len, kind, a, b) -> data_len`
///
/// Registers: A0=buffer_ptr, A1=offset, A2=buffer_len, A3=kind, A4=a, A5=b
fn omega_y(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let buffer_ptr = inst.reg(Reg::A0) as u32;
    let offset     = inst.reg(Reg::A1) as usize;
    let buffer_len = inst.reg(Reg::A2) as usize;
    let kind       = inst.reg(Reg::A3);
    let a          = inst.reg(Reg::A4) as usize;
    let b          = inst.reg(Reg::A5) as usize;

    // Build the data to return (owned, to avoid borrow issues)
    let data: Option<Vec<u8>> = match FetchKind::try_from(kind) {
        // ── Shared across all contexts ──────────────────────────
        Ok(FetchKind::ProtocolParameters) => {
            if ctx.protocol_params.is_empty() { None }
            else { Some(ctx.protocol_params.clone()) }
        }
        Ok(FetchKind::Entropy) => {
            if !ctx.entropy_raw.is_empty() {
                Some(ctx.entropy_raw.clone())
            } else {
                let flat: Vec<u8> = ctx.entropy.iter().flat_map(|h| h.iter().copied()).collect();
                Some(flat)
            }
        }
        // ── Refine context (B.6): Ω_Y(ρ,φ,μ,p,ℍ₀,r,i,ī,x̄,∅,(m,e)) ──
        Ok(FetchKind::AuthTrace) => {
            // r — authorizer trace output
            if ctx.authorizer_trace.is_empty() { None }
            else { Some(ctx.authorizer_trace.clone()) }
        }
        Ok(FetchKind::AnyExtrinsic) => {
            // GP B.6: x̄[a][b] — extrinsic segment `b` of work item `a`
            ctx.extrinsics.get(a)
                .and_then(|segs| segs.get(b))
                .cloned()
        }
        Ok(FetchKind::OurExtrinsic) => {
            // GP B.6: x̄[i][a] — extrinsic segment `a` of current work item
            ctx.extrinsics.get(ctx.work_item_index as usize)
                .and_then(|segs| segs.get(a))
                .cloned()
        }
        Ok(FetchKind::AnyImport) => {
            // GP B.6: ī[a] — import segment at index `a`
            ctx.import_segments.get(a).cloned()
        }
        Ok(FetchKind::OurImport) => {
            // GP B.6: ī[i] — import segment for current work item index
            ctx.import_segments.get(ctx.work_item_index as usize).cloned()
        }
        Ok(FetchKind::WorkPackage) => {
            // p — full work package bytes
            if ctx.work_package.is_empty() { None }
            else { Some(ctx.work_package.clone()) }
        }
        Ok(FetchKind::Authorizer) => {
            // GP B.6: p_f — authorizer code blob
            if ctx.authorizer_code.is_empty() { None }
            else { Some(ctx.authorizer_code.clone()) }
        }
        Ok(FetchKind::AuthToken) => {
            // GP B.6: p_j — justification / authorization token
            if ctx.justification.is_empty() { None }
            else { Some(ctx.justification.clone()) }
        }
        Ok(FetchKind::RefineContext) => {
            // GP B.6: E(p_c) — pre-encoded work package context
            if ctx.work_package_context.is_empty() { None }
            else { Some(ctx.work_package_context.clone()) }
        }
        // ── Accumulate context (B.11) ───────────────────────────
        Ok(FetchKind::ItemsSummary) => {
            // GP: E({S(w)...}) — SCALE-encoded list of all work item summaries
            if ctx.work_items.is_empty() { None }
            else { Some(encode_items_summary_list(&ctx.work_items)) }
        }
        Ok(FetchKind::AnyItemSummary) => {
            // GP: S(p_w[a]) — summary of work item at index `a`
            ctx.work_items.get(a).map(encode_item_summary)
        }
        Ok(FetchKind::AnyPayload) => {
            // GP: p_w[a].y — payload of work item at index `a`
            ctx.work_items.get(a).map(|w| w.payload.clone())
        }
        Ok(FetchKind::AccumulateItems) => {
            Some(encode_accumulate_items_list(&ctx.accumulate_items))
        }
        Ok(FetchKind::AnyAccumulateItem) => {
            ctx.accumulate_items.get(a).cloned()
        }
        Err(_) => {
            log::debug!("fetch: unknown kind {}", kind);
            None
        }
    };

    // Write result to guest memory
    match data {
        Some(ref data) => {
            let data_len = data.len();
            if buffer_ptr != 0 && buffer_len > 0 {
                let available = data_len.saturating_sub(offset);
                let copy_len = std::cmp::min(available, buffer_len);
                if copy_len > 0 && offset < data_len {
                    // GP: if N_{o..+l} is not in writable pages → (♯, φ₇, μ)
                    if inst.write_memory(buffer_ptr, &data[offset..offset + copy_len]).is_err() {
                        log::debug!("ΩY (fetch): write_memory fault at 0x{:08x}", buffer_ptr);
                        return Ok(OmegaResult::Fault);
                    }
                }
            }
            if ctx.debug_trace {
                // For AccumulateItems (kind=14), log first 256 bytes hex
                let hex_preview = if kind == 14 {
                    let preview_len = std::cmp::min(256, data.len());
                    format!(" hex={}", data[..preview_len].iter()
                        .map(|b| format!("{:02x}", b)).collect::<String>())
                } else {
                    String::new()
                };
                // Log buffer parameters so we can see how much data the guest receives
                let available = data_len.saturating_sub(offset);
                let copy_len = std::cmp::min(available, buffer_len);
                ctx.debug_log.push(format!(
                    "omega_y: kind={} buf_ptr=0x{:08x} buf_len={} offset={} → data_len={} copied={} a={} b={}{}",
                    kind, buffer_ptr, buffer_len, offset, data_len, copy_len, a, b, hex_preview
                ));
            }
            inst.set_reg(Reg::A0, data_len as u64);
        }
        None => {
            if ctx.debug_trace {
                ctx.debug_log.push(format!(
                    "omega_y: kind={} a={} b={} → NONE",
                    kind, a, b
                ));
            }
            // GP: v = ∅ → φ'₇ = NONE
            inst.set_reg(Reg::A0, HC_NONE);
        }
    }
    Ok(OmegaResult::Continue)
}

/// Encode `Vec<AccumulateItem>` as JAM compact-prefixed list.
pub(crate) fn encode_accumulate_items_list(items: &[Vec<u8>]) -> Vec<u8> {
    use jam_codec::Compact;
    use jam_types::Encode;

    let mut buf = Vec::new();
    Compact(items.len() as u32).encode_to(&mut buf);
    for item in items {
        buf.extend_from_slice(item);
    }
    buf
}

/// Encode `S(w)` for a single work item (GP B.6).
///
/// `S(w) = E(w_s, w_c, w_g, w_g_a)` = (service_id ++ code_hash ++ gas_limit ++ gas_limit_accum)
fn encode_item_summary(w: &super::context::WorkItemInfo) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 32 + 8 + 8);
    buf.extend_from_slice(&w.service_id.to_le_bytes());
    buf.extend_from_slice(&w.code_hash);
    buf.extend_from_slice(&w.gas_limit.to_le_bytes());
    buf.extend_from_slice(&w.gas_limit_accum.to_le_bytes());
    buf
}

/// Encode `E({S(w)...})` — compact-prefixed list of all work item summaries.
fn encode_items_summary_list(items: &[super::context::WorkItemInfo]) -> Vec<u8> {
    use jam_codec::Compact;
    use jam_types::Encode;

    let mut buf = Vec::new();
    Compact(items.len() as u32).encode_to(&mut buf);
    for w in items {
        buf.extend_from_slice(&encode_item_summary(w));
    }
    buf
}

// ============================================================================
// 2 — ΩL  Lookup-preimage
// ============================================================================

/// `lookup(service, hash_ptr, out, offset, out_len) -> preimage_len | HC_NONE`
///
/// GP spec:
/// ```text
/// let a = s           if φ₇ ∈ {s, 2⁶⁴−1}
///         d[φ₇]       otherwise if φ₇ ∈ K(d)
///         ∅            otherwise
/// let [h, o] = φ_{8…+2}
/// let v = ∇            if N_{h…+32} ∉ V_μ
///         ∅            otherwise if a = ∅ ∨ μ_{h…+32} ∉ K(a_P)
///         a_P[μ_{h…+32}]  otherwise
/// let f = min(φ₁₀, |v|)
/// let l = min(φ₁₁, |v| − f)
/// (ε', φ'₇, μ'_{o…+l}) =
///   (↯, φ₇, μ_{o…+l})     if v = ∇ ∨ N_{o…+l} ∉ V*_μ
///   (▸, NONE, μ_{o…+l})    otherwise if v = ∅
///   (▸, |v|, v_{f…+l})     otherwise
/// ```
///
/// Registers: A0=service(φ₇), A1=hash_ptr(h), A2=out_ptr(o), A3=offset(φ₁₀), A4=out_len(φ₁₁)
fn omega_l(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let service_raw = inst.reg(Reg::A0);     // φ₇ — 64-bit
    let hash_ptr    = inst.reg(Reg::A1) as u32; // h
    let out_ptr     = inst.reg(Reg::A2) as u32; // o
    let offset      = inst.reg(Reg::A3) as usize; // φ₁₀
    let out_len     = inst.reg(Reg::A4) as usize; // φ₁₁

    // ── Resolve service account a ──────────────────────────
    // a = s if φ₇ ∈ {s, 2⁶⁴−1}, d[φ₇] if φ₇ ∈ K(d), ∅ otherwise
    let is_self = service_raw == ctx.service_id as u64
               || service_raw == u64::MAX;

    // ── Read hash from guest memory ────────────────────────
    // v = ∇ if N_{h…+32} ∉ V_μ
    let hash_bytes = match read_guest(inst, hash_ptr, 32) {
        Some(h) if h.len() == 32 => h,
        _ => {
            // ∇ — page fault on reading hash
            return Ok(OmegaResult::Fault);
        }
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    // ── Look up preimage v ─────────────────────────────────
    // v = ∅ if a = ∅ ∨ μ_{h…+32} ∉ K(a_P), else a_P[hash]
    let preimage: Option<Vec<u8>> = if is_self {
        ctx.preimages.get(&hash).cloned()
    } else {
        let sid = service_raw as u32;
        ctx.service_accounts.get(&sid)
            .and_then(|acct| acct.preimages.get(&hash).cloned())
    };

    match preimage {
        None => {
            // v = ∅ → (▸, NONE, μ_{o…+l})
            inst.set_reg(Reg::A0, HC_NONE);
            Ok(OmegaResult::Continue)
        }
        Some(data) => {
            let data_len = data.len();
            let f = std::cmp::min(offset, data_len);
            let l = std::cmp::min(out_len, data_len - f);

            // Write v_{f…+l} to guest at o — fault if not writable
            if l > 0 {
                if inst.write_memory(out_ptr, &data[f..f + l]).is_err() {
                    // N_{o…+l} ∉ V*_μ → (↯, φ₇, μ)
                    return Ok(OmegaResult::Fault);
                }
            }

            inst.set_reg(Reg::A0, data_len as u64);
            Ok(OmegaResult::Continue)
        }
    }
}

// ============================================================================
// 3 — ΩR  Read-storage
// ============================================================================

/// `read(service, key_ptr, key_len, out, offset, out_len) -> value_len | HC_NONE`
///
/// GP spec:
/// ```text
/// let s* = s       if φ₇ = 2⁶⁴−1
///          φ₇      otherwise
/// let a  = s       if s* = s
///          d[s*]   otherwise if s* ∈ K(d)
///          ∅       otherwise
/// let [k_O, k_Z, o] = φ_{8…+3}
/// let v = ∇            if N_{k_O…+k_Z} ∉ V_μ
///         a_s[k]       otherwise if a ≠ ∅ ∧ k ∈ K(a_s), where k = μ_{k_O…+k_Z}
///         ∅            otherwise
/// let f = min(φ₁₁, |v|)
/// let l = min(φ₁₂, |v| − f)
/// (ε', φ'₇, μ'_{o…+l}) =
///   (↯, φ₇, μ_{o…+l})     if v = ∇ ∨ N_{o…+l} ∉ V*_μ
///   (▸, NONE, μ_{o…+l})    otherwise if v = ∅
///   (▸, |v|, v_{f…+l})     otherwise
/// ```
///
/// Registers: A0=service(φ₇), A1=key_ptr(k_O), A2=key_len(k_Z),
///            A3=out_ptr(o), A4=offset(φ₁₁), A5=out_len(φ₁₂)
fn omega_r(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let service_raw = inst.reg(Reg::A0);        // φ₇ — 64-bit
    let key_ptr     = inst.reg(Reg::A1) as u32; // k_O
    let key_len     = inst.reg(Reg::A2) as u32; // k_Z
    let out_ptr     = inst.reg(Reg::A3) as u32; // o
    let offset      = inst.reg(Reg::A4) as usize; // φ₁₁
    let out_len     = inst.reg(Reg::A5) as usize; // φ₁₂

    // ── Resolve s* ─────────────────────────────────────────
    // s* = s if φ₇ = 2⁶⁴−1, else φ₇
    let s_star: u64 = if service_raw == u64::MAX {
        ctx.service_id as u64
    } else {
        service_raw
    };

    // ── Resolve account a ──────────────────────────────────
    let is_self = s_star == ctx.service_id as u64;

    // ── Read key from guest memory ─────────────────────────
    // v = ∇ if N_{k_O…+k_Z} ∉ V_μ
    let key = match read_guest(inst, key_ptr, key_len) {
        Some(k) => k,
        None => {
            // ∇ — page fault on reading key
            return Ok(OmegaResult::Fault);
        }
    };

    // ── Look up value v ────────────────────────────────────
    // GP D: storage is keyed by h27 = H(E₄(2³²−1) ⌢ k)[0:27].
    // Implementations need not store raw keys (GP Appendix D).
    let h27 = storage_hash_key(&key);
    let value: Option<Vec<u8>> = if is_self {
        ctx.storage.get(&h27).cloned()
    } else {
        let sid = s_star as u32;
        ctx.service_accounts.get(&sid)
            .and_then(|acct| acct.storage.get(&h27).cloned())
    };

    match value {
        None => {
            // v = ∅ → (▸, NONE, μ_{o…+l})
            if ctx.debug_trace {
                let key_hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
                ctx.debug_log.push(format!(
                    "omega_r: svc={} key_len={} raw_key={} h27={} → NONE",
                    s_star, key_len, key_hex,
                    h27.iter().map(|b| format!("{:02X}", b)).collect::<String>()
                ));
            }
            inst.set_reg(Reg::A0, HC_NONE);
            Ok(OmegaResult::Continue)
        }
        Some(data) => {
            let data_len = data.len();
            let f = std::cmp::min(offset, data_len);
            let l = std::cmp::min(out_len, data_len - f);

            // Write v_{f…+l} to guest at o — fault if not writable
            if l > 0 {
                if inst.write_memory(out_ptr, &data[f..f + l]).is_err() {
                    // N_{o…+l} ∉ V*_μ → (↯, φ₇, μ)
                    return Ok(OmegaResult::Fault);
                }
            }

            if ctx.debug_trace {
                // Log value hex (first 32 bytes max for readability)
                let val_preview: String = data.iter().take(32)
                    .map(|b| format!("{:02x}", b)).collect();
                let key_hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
                ctx.debug_log.push(format!(
                    "omega_r: svc={} key_len={} raw_key={} h27={} → len={} val={}{}",
                    s_star, key_len, key_hex,
                    h27.iter().map(|b| format!("{:02X}", b)).collect::<String>(),
                    data_len,
                    val_preview,
                    if data_len > 32 { "..." } else { "" }
                ));
            }
            inst.set_reg(Reg::A0, data_len as u64);
            Ok(OmegaResult::Continue)
        }
    }
}

// ============================================================================
// 4 — ΩW  Write-storage
// ============================================================================

/// `write(key_ptr, key_len, value_ptr, value_len) -> old_len | HC_NONE | HC_FULL`
///
/// GP spec:
/// ```text
/// let [k_O, k_Z, v_O, v_Z] = φ_{7…+4}
/// let k = μ_{k_O…+k_Z}                                if N_{k_O…+k_Z} ⊆ V_μ
///         ∇                                            otherwise
/// let a = s, except K(a_s) = K(a_s) \ {k}             if v_Z = 0
///         s, except a_s[k] = μ_{v_O…+v_Z}             otherwise if N_{v_O…+v_Z} ⊆ V_μ
///         ∇                                            otherwise
/// let l = |s_s[k]|   if k ∈ K(s_s)
///         NONE       otherwise
///
/// (ε', φ'_7, s') = (↯, φ_7, s)    if k = ∇ ∨ a = ∇
///                   (▸, FULL, s)    otherwise if a_t > a_b
///                   (▸, l, a)       otherwise
/// ```
///
/// Registers: A0=key_ptr(k_O), A1=key_len(k_Z), A2=value_ptr(v_O), A3=value_len(v_Z)
fn omega_w(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let key_ptr   = inst.reg(Reg::A0) as u32;   // k_O
    let key_len   = inst.reg(Reg::A1) as u32;   // k_Z
    let value_ptr = inst.reg(Reg::A2) as u32;   // v_O
    let value_len = inst.reg(Reg::A3) as u32;   // v_Z

    // ── Read key k from guest memory ───────────────────────
    // k = ∇ if N_{k_O…+k_Z} ∉ V_μ
    let key = match read_guest(inst, key_ptr, key_len) {
        Some(k) => k,
        None => return Ok(OmegaResult::Fault), // k = ∇ → (↯, φ₇, s)
    };

    // ── Compute new account state a ────────────────────────
    // If v_Z = 0: delete key (K(a_s) \ {k})
    // If v_Z > 0: read value, set a_s[k] = value
    let new_value: Option<Vec<u8>> = if value_len == 0 {
        // v_Z = 0 → delete: no value to insert, key will be removed
        None
    } else {
        // Read value from guest — ∇ if not readable
        match read_guest(inst, value_ptr, value_len) {
            Some(v) => Some(v),
            None => return Ok(OmegaResult::Fault), // a = ∇ → (↯, φ₇, s)
        }
    };

    // ── Hash key to h27 (GP Appendix D) ──────────────────────
    // Storage is keyed by h27 = H(E₄(2³²−1) ⌢ k)[0:27].
    let h27 = storage_hash_key(&key);

    // Helper: format h27 as uppercase hex for debug logs
    let h27_hex = if ctx.debug_trace {
        h27.iter().map(|b| format!("{:02X}", b)).collect::<String>()
    } else {
        String::new()
    };
    let raw_hex = if ctx.debug_trace {
        key.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    } else {
        String::new()
    };

    // ── l = old length or NONE ─────────────────────────────
    let old_len = ctx.storage.get(&h27).map(|v| v.len() as u64).unwrap_or(HC_NONE);

    // ── FULL check: a_t > a_b → (▸, FULL, s) ──────────────
    // a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f) where a_f = ctx.threshold
    let a_t = compute_threshold(ctx.items_count, ctx.footprint, ctx.threshold);
    if a_t > ctx.balance {
        inst.set_reg(Reg::A0, HC_FULL);
        return Ok(OmegaResult::Continue);
    }

    // ── Apply mutation + incremental items/footprint tracking ──
    // GP §9.3: storage contributes 1 item and (34+|key|+|value|) to footprint.
    // |key| uses the RAW key length (not h27) per GP spec.
    let key_sz = key.len() as u64;
    let pre_items = ctx.items_count;
    let pre_footprint = ctx.footprint;
    match new_value {
        None => {
            // v_Z = 0 → remove key from storage
            if let Some(old_val) = ctx.storage.remove(&h27) {
                // Removed: items -1, footprint -(34+|key|+|old_val|)
                ctx.items_count = ctx.items_count.saturating_sub(1);
                ctx.footprint = ctx.footprint.saturating_sub(34 + key_sz + old_val.len() as u64);
                if ctx.debug_trace {
                    ctx.debug_log.push(format!(
                        "omega_w: DELETE key_len={} old_val_len={} h27={} raw={} items={}→{} footprint={}→{} storage_count={}",
                        key_sz, old_val.len(), h27_hex, raw_hex, pre_items, ctx.items_count,
                        pre_footprint, ctx.footprint, ctx.storage.len()
                    ));
                }
            } else if ctx.debug_trace {
                ctx.debug_log.push(format!(
                    "omega_w: DELETE_NOOP key_len={} h27={} raw={} (key not found) items={} footprint={} storage_count={}",
                    key_sz, h27_hex, raw_hex, ctx.items_count, ctx.footprint, ctx.storage.len()
                ));
            }
        }
        Some(v) => {
            let new_val_len = v.len() as u64;
            if let Some(old_val) = ctx.storage.insert(h27, v) {
                // Update: footprint delta = new_len - old_len
                let old_val_len = old_val.len() as u64;
                if new_val_len >= old_val_len {
                    ctx.footprint += new_val_len - old_val_len;
                } else {
                    ctx.footprint = ctx.footprint.saturating_sub(old_val_len - new_val_len);
                }
                if ctx.debug_trace {
                    ctx.debug_log.push(format!(
                        "omega_w: UPDATE key_len={} h27={} raw={} old_val_len={} new_val_len={} items={} footprint={}→{} storage_count={}",
                        key_sz, h27_hex, raw_hex, old_val_len, new_val_len, ctx.items_count,
                        pre_footprint, ctx.footprint, ctx.storage.len()
                    ));
                }
            } else {
                // New entry: items +1, footprint +(34+|key|+|val|)
                ctx.items_count += 1;
                ctx.footprint += 34 + key_sz + new_val_len;
                if ctx.debug_trace {
                    ctx.debug_log.push(format!(
                        "omega_w: CREATE key_len={} h27={} raw={} val_len={} items={}→{} footprint={}→{} storage_count={}",
                        key_sz, h27_hex, raw_hex, new_val_len, pre_items, ctx.items_count,
                        pre_footprint, ctx.footprint, ctx.storage.len()
                    ));
                }
            }
        }
    }

    inst.set_reg(Reg::A0, old_len);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 5 — ΩI  Information-on-service
// ============================================================================

/// `info(service, out_ptr, offset, out_len) -> data_len | HC_NONE`
///
/// GP spec:
/// ```text
/// let a = d[s]     if φ₇ = 2⁶⁴ − 1
///         d[φ₇]   otherwise
/// let o = φ₈
/// let v = E(a_c, E_8(a_b, a_t, a_g, a_m, a_o), E_4(a_i), E_8(a_f), E_4(a_r, a_a, a_p))
///                                                           if a ≠ ∅
///         ∅                                                 otherwise
/// let f = min(φ₉, |v|)
/// let l = min(φ₁₀, |v| − f)
/// (ε', φ'₇, μ'_{o…+l}) =
///   (↯, φ₇, μ_{o…+l})     if v = ∇ ∨ N_{o…+l} ∉ V*_μ
///   (▸, NONE, μ_{o…+l})    otherwise if v = ∅
///   (▸, |v|, v_{f…+l})     otherwise
/// ```
///
/// Registers: A0=service(φ₇), A1=out_ptr(o), A2=offset(φ₉), A3=out_len(φ₁₀)
fn omega_i(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let service_raw = inst.reg(Reg::A0);        // φ₇
    let out_ptr     = inst.reg(Reg::A1) as u32; // o
    let offset      = inst.reg(Reg::A2) as usize; // φ₉
    let out_len     = inst.reg(Reg::A3) as usize; // φ₁₀

    // ── Resolve service account a ───────────────────────────
    let is_self = service_raw == u64::MAX
               || service_raw == ctx.service_id as u64;

    let account: Option<ServiceAccount> = if is_self {
        // d[s] — build from our own fields
        Some(ctx.self_account_info())
    } else {
        let sid = service_raw as u32;
        ctx.service_accounts.get(&sid).cloned()
    };

    match account {
        None => {
            // a = ∅ → (▸, NONE, μ)
            inst.set_reg(Reg::A0, HC_NONE);
            Ok(OmegaResult::Continue)
        }
        Some(acct) => {
            // v = E(a_c, ...) — 96-byte encoding
            let v = acct.encode_info();
            let data_len = v.len(); // always SERVICE_INFO_SIZE = 96

            // ── Debug: log full ΩI encoding ──────────────────────
            if ctx.debug_trace {
                let hex: String = v.iter().map(|b| format!("{:02x}", b)).collect();
                ctx.debug_log.push(format!(
                    "omega_i: svc={} is_self={} items={} footprint={} threshold={} balance={} info_hex={}",
                    service_raw, is_self, acct.items_count, acct.footprint,
                    acct.threshold, acct.balance, hex
                ));
            }

            let f = std::cmp::min(offset, data_len);
            let l = std::cmp::min(out_len, data_len - f);

            // Write v_{f…+l} to guest at o — fault if not writable
            if l > 0 {
                if inst.write_memory(out_ptr, &v[f..f + l]).is_err() {
                    return Ok(OmegaResult::Fault);
                }
            }

            inst.set_reg(Reg::A0, data_len as u64);
            Ok(OmegaResult::Continue)
        }
    }
}

// ============================================================================
// 6 — ΩH  Historical-lookup-preimage
// ============================================================================

/// `historical_lookup(service, hash_ptr, out_ptr, offset, out_len) -> len | HC_NONE`
///
/// GP B.6 spec:
/// ```text
/// let a = d[s]      if φ₇ = 2⁶⁴−1 ∧ s ∈ K(d)
///         d[φ₇]     otherwise if φ₇ ∈ K(d)
///         ∅          otherwise
/// let [h, o] = φ_{8…+2}
/// let v = ∇                              if N_{h…+32} ∉ V_μ
///         ∅                              otherwise if a = ∅ ∨ Λ(a, t, μ_{h…+32}) = ∅
///         Λ(a, t, μ_{h…+32})            otherwise
/// let f = min(φ₁₀, |v|)
/// let l = min(φ₁₁, |v| − f)
/// (ε', φ'₇, μ'_{o…+l}) =
///   (↯, φ₇, μ_{o…+l})                  if v = ∇ ∨ N_{o…+l} ∉ V*_μ
///   (▸, NONE, μ_{o…+l})                 otherwise if v = ∅
///   (▸, |v|, v_{f…+l})                  otherwise
/// ```
///
/// `Λ(a, t, h)` — historical preimage lookup using the `a_l` status table.
/// See [`lambda_lookup`] for the availability logic.
///
/// Registers: A0=service(φ₇), A1=hash_ptr(h), A2=out_ptr(o),
///            A3=offset(φ₁₀), A4=out_len(φ₁₁)
fn omega_h(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let service_raw = inst.reg(Reg::A0);        // φ₇
    let hash_ptr    = inst.reg(Reg::A1) as u32; // h
    let out_ptr     = inst.reg(Reg::A2) as u32; // o
    let offset      = inst.reg(Reg::A3) as usize; // φ₁₀
    let out_len     = inst.reg(Reg::A4) as usize; // φ₁₁

    // ── Resolve service account a ──────────────────────────
    let is_self = service_raw == u64::MAX
               || service_raw == ctx.service_id as u64;

    // ── Read hash from guest memory (32 bytes) ─────────────
    let hash_bytes = match read_guest(inst, hash_ptr, 32) {
        Some(h) if h.len() == 32 => h,
        _ => return Ok(OmegaResult::Fault), // ∇ — page fault
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    // ── Look up preimage via Λ(a, t, hash) ─────────────────
    let t = ctx.timeslot;
    let preimage: Option<Vec<u8>> = if is_self {
        lambda_lookup(&ctx.preimages, &ctx.lookup, t, &hash)
    } else {
        let sid = service_raw as u32;
        ctx.service_accounts.get(&sid)
            .and_then(|acct| lambda_lookup(&acct.preimages, &acct.lookup, t, &hash))
    };

    match preimage {
        None => {
            // v = ∅ → (▸, NONE, μ)
            inst.set_reg(Reg::A0, HC_NONE);
            Ok(OmegaResult::Continue)
        }
        Some(data) => {
            let data_len = data.len();
            let f = std::cmp::min(offset, data_len);
            let l = std::cmp::min(out_len, data_len - f);

            // Write v_{f…+l} to guest at o — fault if not writable
            if l > 0 {
                if inst.write_memory(out_ptr, &data[f..f + l]).is_err() {
                    return Ok(OmegaResult::Fault);
                }
            }

            log::trace!("ΩH (historical_lookup): Λ found preimage, len={}", data_len);
            inst.set_reg(Reg::A0, data_len as u64);
            Ok(OmegaResult::Continue)
        }
    }
}

// ============================================================================
// 7 — ΩE  Export segment
// ============================================================================

/// `export(ptr, len) -> export_count | HC_FULL`
///
/// GP B.6 spec:
/// ```text
/// let p = φ₇                          (A0 = data pointer)
/// let z = min(φ₈, W_G)                (A1 = length, capped at W_G)
/// let x = P_{W_G}(μ_{p…+z})           (read z bytes, pad to W_G)
///       = ∇                            if N_{p…+z} ∉ V_μ  (fault)
///
/// (ε', φ'₇, e') =
///   (↯, φ₇, e)                        if x = ∇
///   (▸, FULL, e)                       if ς + |e| ≥ W_X
///   (▸, ς + |e ⌢ [x]|, e ⌢ [x])      otherwise
/// ```
///
/// Registers: A0=ptr(p), A1=len(φ₈)
fn omega_e(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let ptr = inst.reg(Reg::A0) as u32;     // p
    let raw_len = inst.reg(Reg::A1) as u32; // φ₈

    let w_g = ctx.segment_size;              // W_G (default 4104)
    let w_x = ctx.max_exports;              // W_X (default 3072)
    let z = std::cmp::min(raw_len, w_g);    // z = min(φ₈, W_G)

    // ── Read z bytes from guest at p ─────────────────────
    // x = ∇ if N_{p…+z} ∉ V_μ
    let data = match read_guest(inst, ptr, z) {
        Some(d) => d,
        None => return Ok(OmegaResult::Fault), // (↯, φ₇, e)
    };

    // ── FULL check: ς + |e| ≥ W_X ───────────────────────
    let total_before = ctx.export_base + ctx.export_segments.len() as u32;
    if total_before >= w_x {
        inst.set_reg(Reg::A0, HC_FULL);
        return Ok(OmegaResult::Continue);
    }

    // ── Pad to W_G bytes: P_{W_G}(data) ─────────────────
    let mut segment = vec![0u8; w_g as usize];
    segment[..data.len()].copy_from_slice(&data);

    // ── Append and return new count ──────────────────────
    ctx.export_segments.push(segment);
    let total_after = ctx.export_base + ctx.export_segments.len() as u32;
    log::trace!("ΩE (export): segment added, total={}", total_after);

    inst.set_reg(Reg::A0, total_after as u64);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 8 — ΩM  Make-pvm
// ============================================================================

/// `machine(p_O, p_Z, i) -> n | HUH`
///
/// GP spec:
/// ```text
/// let [p_O, p_Z, i] = φ_{7…+3}
/// let p = μ_{p_O…+p_Z}    if N_{p_O…+p_Z} ⊆ V_μ
///         ∇                otherwise
/// let n = min(n ∈ ℕ, n ∉ K(m))
/// let u = (v: [0,0,…], a: [∅,∅,…])
/// (ε', φ'_7, m) =
///   (♯, φ_7, m)                    if p = ∇
///   (▸, HUH, m)                    if deblob(p) = ∇
///   (▸, n, m ∪ {n ↦ (p, u, i)})   otherwise
/// ```
///
/// Registers: A0=p_O, A1=p_Z, A2=i
fn omega_m(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let p_o = inst.reg(Reg::A0) as u32;  // blob address
    let p_z = inst.reg(Reg::A1) as u32;  // blob length
    let pc_i = inst.reg(Reg::A2) as u32; // initial program counter

    // ── Read program blob from outer guest memory ──────────
    // p = ∇ if N_{p_O…+p_Z} ∉ V_μ → fault
    let blob = match read_guest(inst, p_o, p_z) {
        Some(b) => b,
        None => {
            return Ok(OmegaResult::Fault);
        }
    };

    // ── deblob(p) — parse + compile + instantiate ──────────
    let inner_instance = match ctx.deblob(&blob) {
        Some(instance) => instance,
        None => {
            // deblob(p) = ∇ → (▸, HUH, m)
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    };

    // ── Allocate machine index n ───────────────────────────
    let n = ctx.next_machine_id();

    log::trace!("ΩM (machine): deblob OK, n={}, pc_i={}", n, pc_i);

    // Insert into m: n ↦ (p, u, i)
    // u = (v: [0,0,…], a: [∅,∅,…]) — polkavm Instance starts zeroed.
    ctx.inner_machines.insert(n, InnerMachine {
        instance: inner_instance,
        initial_pc: pc_i,
    });

    inst.set_reg(Reg::A0, n as u64);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 9 — ΩP  Peek-pvm
// ============================================================================

/// `peek(n, o, s, z) -> OK | WHO | OOB`
///
/// GP spec:
/// ```text
/// let [n, o, s, z] = φ_{7…+4}
/// (ε', φ'_7, μ') =
///   (♯, φ_7, μ)       if N_{o…+z} ∉ V*_μ
///   (▸, WHO, μ)        if n ∉ K(m)
///   (▸, OOB, μ)        if N_{s…+z} ∉ V_{m[n]_u}
///   (▸, OK, μ')        otherwise
///   where μ' = μ except μ_{o…+z} = (m[n]_u)_{s…+z}
/// ```
///
/// Registers: A0=n, A1=o, A2=s, A3=z
fn omega_p(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let n = inst.reg(Reg::A0) as u32;  // machine index
    let o = inst.reg(Reg::A1) as u32;  // outer dest address
    let s = inst.reg(Reg::A2) as u32;  // inner src address
    let z = inst.reg(Reg::A3) as u32;  // length

    // ── n ∉ K(m) → WHO ────────────────────────────────────
    let inner = match ctx.inner_machines.get(&n) {
        Some(m) => m,
        None => {
            inst.set_reg(Reg::A0, HC_WHO);
            return Ok(OmegaResult::Continue);
        }
    };

    // ── Read from inner machine memory: N_{s…+z} ∉ V_{m[n]_u} → OOB ──
    let data = match inner.instance.read_memory(s, z) {
        Ok(d) => d,
        Err(_) => {
            inst.set_reg(Reg::A0, HC_OOB);
            return Ok(OmegaResult::Continue);
        }
    };

    // ── Write to outer guest: N_{o…+z} ∉ V*_μ → fault ────
    if z > 0 {
        if inst.write_memory(o, &data).is_err() {
            return Ok(OmegaResult::Fault);
        }
    }

    log::trace!("ΩP (peek): n={}, s=0x{:x}, o=0x{:x}, z={}", n, s, o, z);
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 10 — ΩO  Poke-pvm
// ============================================================================

/// `poke(n, s, o, z) -> OK | WHO | OOB`
///
/// GP spec:
/// ```text
/// let [n, s, o, z] = φ_{7…+4}
/// (ε', φ'_7, m') =
///   (♯, φ_7, m)       if N_{s…+z} ∉ V_μ
///   (▸, WHO, m)        if n ∉ K(m)
///   (▸, OOB, m)        if N_{o…+z} ∉ V*_{m[n]_u}
///   (▸, OK, m')        otherwise
///   where m' = m except (m'[n]_u)_{o…+z} = μ_{s…+z}
/// ```
///
/// Registers: A0=n, A1=s, A2=o, A3=z
fn omega_o(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let n = inst.reg(Reg::A0) as u32;  // machine index
    let s = inst.reg(Reg::A1) as u32;  // outer src address
    let o = inst.reg(Reg::A2) as u32;  // inner dest address
    let z = inst.reg(Reg::A3) as u32;  // length

    // ── Read from outer guest: N_{s…+z} ∉ V_μ → fault ────
    let data = match read_guest(inst, s, z) {
        Some(d) => d,
        None => {
            return Ok(OmegaResult::Fault);
        }
    };

    // ── n ∉ K(m) → WHO ────────────────────────────────────
    let inner = match ctx.inner_machines.get_mut(&n) {
        Some(m) => m,
        None => {
            inst.set_reg(Reg::A0, HC_WHO);
            return Ok(OmegaResult::Continue);
        }
    };

    // ── Write to inner machine memory: N_{o…+z} ∉ V*_{m[n]_u} → OOB ──
    if z > 0 {
        if inner.instance.write_memory(o, &data).is_err() {
            inst.set_reg(Reg::A0, HC_OOB);
            return Ok(OmegaResult::Continue);
        }
    }

    log::trace!("ΩO (poke): n={}, s=0x{:x}, o=0x{:x}, z={}", n, s, o, z);
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 11 — ΩZ  Pages inner-pvm memory
// ============================================================================

/// `pages(n, p, c, r) -> OK | WHO | HUH`
///
/// GP spec:
/// ```text
/// let [n, p, c, r] = φ_{7…+4}
/// let u = m[n]_u       if n ∈ K(m)
///         ∇            otherwise
///
/// let u' = u except {
///   (u'_v)_{p·Z_P…+c·Z_P} = [0,0,…]           if r < 3
///                             (u_v)_{p·Z_P…+c·Z_P}  otherwise
///   (u'_a)_{p…+c}          = [∅,∅,…]           if r = 0
///                             [R,R,…]           if r = 1 ∨ r = 3
///                             [W,W,…]           if r = 2 ∨ r = 4
/// }
///
/// (φ'_7, m') =
///   (WHO, m)    if u = ∇
///   (HUH, m)    otherwise if r > 4 ∨ p < 16 ∨ p + c ≥ 2³²/Z_P
///   (HUH, m)    otherwise if r > 2 ∧ (u_a)_{p…+c} ∋ ∅
///   (OK, m')     otherwise, where m' = m except m'[n]_u = u'
/// ```
///
/// Registers: A0=n, A1=p, A2=c, A3=r
fn omega_z(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let n = inst.reg(Reg::A0) as u32;  // machine index
    let p = inst.reg(Reg::A1) as u32;  // start page number
    let c = inst.reg(Reg::A2) as u32;  // page count
    let r = inst.reg(Reg::A3) as u32;  // protection mode

    // ── u = ∇ if n ∉ K(m) → WHO ──────────────────────────
    if !ctx.inner_machines.contains_key(&n) {
        inst.set_reg(Reg::A0, HC_WHO);
        return Ok(OmegaResult::Continue);
    }

    // ── Parameter validation → HUH ───────────────────────
    // r > 4 ∨ p < 16 ∨ p + c ≥ 2³²/Z_P
    let max_pages = u32::MAX / PAGE_SIZE; // 2³²/Z_P (rounds down, but close enough)
    if r > 4 || p < 16 || p.saturating_add(c) >= max_pages {
        inst.set_reg(Reg::A0, HC_HUH);
        return Ok(OmegaResult::Continue);
    }

    let addr = p.wrapping_mul(PAGE_SIZE);
    let byte_len = c.wrapping_mul(PAGE_SIZE);

    // ── r > 2 ∧ (u_a)_{p…+c} ∋ ∅ → HUH ─────────────────
    // For r=3 or r=4 (keep data), the pages must already be accessible.
    // If any page in the range is inaccessible, return HUH.
    if r > 2 {
        let inner = ctx.inner_machines.get(&n).unwrap();
        // is_memory_accessible(addr, size, is_writable=false) → at least readable
        if c > 0 && !inner.instance.is_memory_accessible(addr, byte_len, false) {
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    }

    // ── Apply page changes ───────────────────────────────
    let inner = ctx.inner_machines.get_mut(&n).unwrap();

    let ok = if c == 0 {
        true // zero-length operation always succeeds
    } else {
        match r {
            // r=0: make inaccessible (free pages), data zeroed implicitly
            0 => inner.instance.free_pages(addr, byte_len).is_ok(),

            // r=1: zero + read-only
            // Write zeros (allocates pages as RW in dynamic paging), then protect.
            1 => {
                let zeros = vec![0u8; byte_len as usize];
                inner.instance.write_memory(addr, &zeros).is_ok()
                    && inner.instance.protect_memory(addr, byte_len).is_ok()
            }

            // r=2: zero + read-write
            // Write zeros (allocates pages as RW in dynamic paging).
            2 => {
                let zeros = vec![0u8; byte_len as usize];
                inner.instance.write_memory(addr, &zeros).is_ok()
            }

            // r=3: keep data + read-only
            3 => inner.instance.protect_memory(addr, byte_len).is_ok(),

            // r=4: keep data + read-write (unprotect)
            // polkavm 0.29 has no unprotect_memory, so: read, free, re-write.
            4 => {
                match inner.instance.read_memory(addr, byte_len) {
                    Ok(data) => {
                        let _ = inner.instance.free_pages(addr, byte_len);
                        inner.instance.write_memory(addr, &data).is_ok()
                    }
                    Err(_) => false,
                }
            }

            _ => unreachable!(), // already checked r > 4 above
        }
    };

    if ok {
        log::trace!("ΩZ (pages): n={}, p={}, c={}, r={} → OK", n, p, c, r);
        inst.set_reg(Reg::A0, HC_OK);
    } else {
        // polkavm rejected the operation — treat as HUH
        log::trace!("ΩZ (pages): n={}, p={}, c={}, r={} → HUH (polkavm rejected)", n, p, c, r);
        inst.set_reg(Reg::A0, HC_HUH);
    }
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 12 — ΩK  Kickoff-pvm (invoke)
// ============================================================================

/// `invoke(n, o) -> HALT | HOST h | FAULT x | OOG | PANIC | WHO`
///
/// GP spec:
/// ```text
/// let [n, o] = φ_{7,8}
/// let (g, w) = {
///   (g, w) : E_8(g) ~ E_8(w) = μ_{o…+112}    if N_{o…+112} ∈ V*_μ
///   (∇, ∇)                                     otherwise
/// }
///
/// let (c, i', g', w', u') = Ψ(m[n]_p, m[n]_i, g, w, m[n]_u)
/// let μ* = μ except μ*_{o…+112} = E_8(g') ~ E_8(w')
///
/// m*[n]_u = u'
/// m*[n]_i = i' + skip(i') + 1    if c ∈ {ℏ} × ℕ_R
///           i'                     otherwise
///
/// (ε', φ'_7, φ'_8, μ', m') ≡
///   (♯, φ_7, φ_8, μ, m)          if g = ∇
///   (▸, WHO, φ_8, μ, m)           if n ∉ m
///   (▸, HOST, h, μ*, m*)          if c = ℏ × h
///   (▸, FAULT, x, μ*, m*)         if c = ⊥ × x
///   (▸, OOG, φ_8, μ*, m*)         if c = ∞
///   (▸, PANIC, φ_8, μ*, m*)       if c = ♯
///   (▸, HALT, φ_8, μ*, m*)        if c = ■
/// ```
///
/// Registers: A0=n, A1=o
fn omega_k(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    use polkavm::{InterruptKind, ProgramCounter};

    let n = inst.reg(Reg::A0) as u32;  // machine index
    let o = inst.reg(Reg::A1) as u32;  // memory offset for (g, w) I/O

    // ── (1) Read 112 bytes: E_8(g) ~ E_8(w) from μ_{o…+112} ──
    // 8 bytes gas + 13×8 bytes registers = 112
    const IO_SIZE: u32 = 8 + 13 * 8; // 112
    let io_buf = match read_guest(inst, o, IO_SIZE) {
        Some(buf) => buf,
        None => {
            // g = ∇ → (♯, φ_7, φ_8, μ, m) — fault, leave regs unchanged
            return Ok(OmegaResult::Fault);
        }
    };

    // ── Parse g and w ──
    let g = i64::from_le_bytes(io_buf[0..8].try_into().unwrap());
    let mut w = [0u64; 13];
    for i in 0..13 {
        let start = 8 + i * 8;
        w[i] = u64::from_le_bytes(io_buf[start..start + 8].try_into().unwrap());
    }

    // ── (2) n ∉ K(m) → WHO ──
    if !ctx.inner_machines.contains_key(&n) {
        inst.set_reg(Reg::A0, HC_WHO);
        return Ok(OmegaResult::Continue);
    }

    // ── (3) Set up inner PVM and run: Ψ(m[n]_p, m[n]_i, g, w, m[n]_u) ──
    let inner = ctx.inner_machines.get_mut(&n).unwrap();
    inner.instance.set_gas(g);
    for (i, &reg) in Reg::ALL.iter().enumerate() {
        inner.instance.set_reg(reg, w[i]);
    }
    inner.instance.set_next_program_counter(ProgramCounter(inner.initial_pc));

    let interrupt = inner.instance.run();

    // ── (4) Read back g' and w' ──
    let g_prime = inner.instance.gas();
    let mut w_prime = [0u64; 13];
    for (i, &reg) in Reg::ALL.iter().enumerate() {
        w_prime[i] = inner.instance.reg(reg);
    }

    // ── (5) Write E_8(g') ~ E_8(w') back to μ_{o…+112} ──
    let mut out_buf = [0u8; IO_SIZE as usize];
    out_buf[0..8].copy_from_slice(&g_prime.to_le_bytes());
    for i in 0..13 {
        let start = 8 + i * 8;
        out_buf[start..start + 8].copy_from_slice(&w_prime[i].to_le_bytes());
    }
    // The GP says μ* is always computed when we reach this point,
    // and we already validated N_{o…+112} ∈ V*_μ above.
    let _ = inst.write_memory(o, &out_buf);

    // ── (6) Map interrupt to GP outcome c and update m*[n]_i ──
    match interrupt {
        Ok(InterruptKind::Finished) => {
            // c = ■ (HALT) — normal completion
            // m*[n]_i = i' (not Ecalli, so keep program_counter)
            if let Some(pc) = inner.instance.program_counter() {
                inner.initial_pc = pc.0;
            }
            log::trace!("ΩK (invoke): n={} → HALT", n);
            inst.set_reg(Reg::A0, PVM_HALT as u64);
            Ok(OmegaResult::Continue)
        }

        Ok(InterruptKind::Ecalli(h)) => {
            // c = ℏ × h (HOST) — inner PVM made an ecalli
            // m*[n]_i = i' + skip(i') + 1 → next_program_counter() (already past ecalli)
            if let Some(npc) = inner.instance.next_program_counter() {
                inner.initial_pc = npc.0;
            }
            log::trace!("ΩK (invoke): n={} → HOST h={}", n, h);
            inst.set_reg(Reg::A0, PVM_HOST as u64);
            inst.set_reg(Reg::A1, h as u64);
            Ok(OmegaResult::Continue)
        }

        Ok(InterruptKind::Segfault(seg)) => {
            // c = ⊥ × x (FAULT) — page fault at address x
            if let Some(pc) = inner.instance.program_counter() {
                inner.initial_pc = pc.0;
            }
            log::trace!("ΩK (invoke): n={} → FAULT addr=0x{:x}", n, seg.page_address);
            inst.set_reg(Reg::A0, PVM_FAULT as u64);
            inst.set_reg(Reg::A1, seg.page_address as u64);
            Ok(OmegaResult::Continue)
        }

        Ok(InterruptKind::NotEnoughGas) => {
            // c = ∞ (OOG)
            if let Some(pc) = inner.instance.program_counter() {
                inner.initial_pc = pc.0;
            }
            log::trace!("ΩK (invoke): n={} → OOG", n);
            inst.set_reg(Reg::A0, PVM_OOG as u64);
            Ok(OmegaResult::Continue)
        }

        Ok(InterruptKind::Trap) | Err(_) => {
            // c = ♯ (PANIC)
            if let Some(pc) = inner.instance.program_counter() {
                inner.initial_pc = pc.0;
            }
            log::trace!("ΩK (invoke): n={} → PANIC", n);
            inst.set_reg(Reg::A0, PVM_PANIC as u64);
            Ok(OmegaResult::Continue)
        }

        Ok(InterruptKind::Step) => {
            // Step tracing — shouldn't happen in normal execution; treat as PANIC
            if let Some(pc) = inner.instance.program_counter() {
                inner.initial_pc = pc.0;
            }
            inst.set_reg(Reg::A0, PVM_PANIC as u64);
            Ok(OmegaResult::Continue)
        }
    }
}

// ============================================================================
// 13 — ΩX  Expunge-pvm
// ============================================================================

/// `expunge(n) -> initial_pc | WHO`
///
/// GP spec:
/// ```text
/// let n = φ_7
///
/// (φ'_7, m') =
///   (WHO, m)              if n ∉ K(m)
///   (m[n]_i, m \ n)       otherwise
/// ```
///
/// Returns the inner machine's instruction pointer and removes it.
///
/// Registers: A0=n
fn omega_x(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let n = inst.reg(Reg::A0) as u32; // machine index

    match ctx.inner_machines.remove(&n) {
        None => {
            // n ∉ K(m) → WHO
            inst.set_reg(Reg::A0, HC_WHO);
        }
        Some(machine) => {
            // Return m[n]_i (the stored initial_pc) and remove from map
            let pc_val = machine.initial_pc;
            log::trace!("ΩX (expunge): n={} → initial_pc={}", n, pc_val);
            inst.set_reg(Reg::A0, pc_val as u64);
        }
    }
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 14 — ΩB  Empower-service (bless)
// ============================================================================

/// `bless(m, a_ptr, v, r, o, n) -> OK | WHO | ♯(fault)`
///
/// GP B.7:
/// ```text
/// let [m, a, v, r, o, n] = φ_{7…+6}
/// let a = E_4⁻¹(μ_{a…+4c})            — c = core_count authorization agents
/// let z = { s ↦ g : E_4(s)~E_8(g) = μ_{o+12i…+12} | i ∈ N_n }
///
/// (ε', φ'_7, x'_e) =
///   (♯, φ_7, x_e)                   if {z, a} ∋ ∇
///   (▸, WHO, x_e)                    if (m, v, r) ∉ N_S³
///   (▸, OK, (m, a, v, r, z))        otherwise
/// ```
///
/// Registers: A0=m, A1=a_ptr, A2=v, A3=r, A4=o, A5=n
fn omega_b(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let m     = inst.reg(Reg::A0) as u32;  // manager service
    let a_ptr = inst.reg(Reg::A1) as u32;  // pointer to auth agents array
    let v     = inst.reg(Reg::A2) as u32;  // validator service
    let r     = inst.reg(Reg::A3) as u32;  // staking service
    let o     = inst.reg(Reg::A4) as u32;  // pointer to gas map entries
    let n     = inst.reg(Reg::A5) as u32;  // number of gas map entries

    // ── Read a: c authorization agents (c = core_count) ──
    let c = ctx.core_count as u32;
    let a_bytes = 4u32.checked_mul(c).unwrap_or(u32::MAX);
    let auth_agents_raw = match read_guest(inst, a_ptr, a_bytes) {
        Some(buf) => buf,
        None => {
            // a = ∇ → fault
            return Ok(OmegaResult::Fault);
        }
    };
    let mut auth_agents = Vec::with_capacity(c as usize);
    for i in 0..c as usize {
        let start = i * 4;
        auth_agents.push(u32::from_le_bytes(
            auth_agents_raw[start..start + 4].try_into().unwrap(),
        ));
    }

    // ── Read z: n entries of 12 bytes (E_4(s) ~ E_8(g)) ──
    let z_total = 12u32.checked_mul(n).unwrap_or(u32::MAX);
    let z_raw = match read_guest(inst, o, z_total) {
        Some(buf) => buf,
        None => {
            // z = ∇ → fault
            return Ok(OmegaResult::Fault);
        }
    };
    let mut gas_map = std::collections::HashMap::with_capacity(n as usize);
    for i in 0..n as usize {
        let base = i * 12;
        let sid = u32::from_le_bytes(z_raw[base..base + 4].try_into().unwrap());
        let gas = u64::from_le_bytes(z_raw[base + 4..base + 12].try_into().unwrap());
        gas_map.insert(sid, gas);
    }

    // ── (m, v, r) ∈ N_S³ check — all must be existing services ──
    if !ctx.existing_services.contains(&m)
        || !ctx.existing_services.contains(&v)
        || !ctx.existing_services.contains(&r)
    {
        inst.set_reg(Reg::A0, HC_WHO);
        return Ok(OmegaResult::Continue);
    }

    // ── OK: set x_e = (m, a, v, r, z) ──
    // Preserve existing q and l if empower was already set (ΩB re-invocation),
    // otherwise start with empty queues and validators.
    let (prev_queues, prev_validators) = ctx.empower.as_ref()
        .map(|e| (e.queues.clone(), e.validators.clone()))
        .unwrap_or_default();
    ctx.empower = Some(EmpowerState {
        manager: m,
        auth_agents,
        validator: v,
        staker: r,
        gas_map,
        queues: prev_queues,
        validators: prev_validators,
    });

    log::debug!("ΩB (bless): m={}, v={}, r={}, agents={}, gas_map_entries={}", m, v, r, c, n);
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 15 — ΩA  Assign-core
// ============================================================================

/// `assign(c, o, a) -> OK | CORE | HUH | WHO | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [c, o, a] = φ_{7…+3}
/// let q = [μ_{o+32i…+32} | i ∈ N_Q]    if N_{o…+32Q} ⊆ V_μ
///         ∇                              otherwise
///
/// (ε', φ'_7, (x_e).q[c], (x_e)'.a[c]) =
///   (♯, φ_7, (x_e).q[c], (x_e).a[c])      if q = ∇
///   (▸, CORE, (x_e).q[c], (x_e).a[c])     if c ≥ C
///   (▸, HUH, (x_e).q[c], (x_e).a[c])      if x_s ≠ (x_e).a[c]
///   (▸, WHO, (x_e).q[c], (x_e).a[c])       if a ∉ N_S
///   (▸, OK, q, a)                            otherwise
/// ```
///
/// Registers: A0=c, A1=o, A2=a
fn omega_a(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let c = inst.reg(Reg::A0) as u32;  // core index
    let o = inst.reg(Reg::A1) as u32;  // memory offset for Q hashes
    let a = inst.reg(Reg::A2) as u32;  // new auth agent service ID

    // ── Read q: Q authorization hashes (32 bytes each) from memory ──
    let q_count = ctx.auth_queue_len as u32;  // Q
    let q_total = q_count.checked_mul(32).unwrap_or(u32::MAX);
    let q_raw = match read_guest(inst, o, q_total) {
        Some(buf) => buf,
        None => {
            // q = ∇ → (♯, φ_7, ...) — fault
            return Ok(OmegaResult::Fault);
        }
    };
    let mut q: Vec<[u8; 32]> = Vec::with_capacity(q_count as usize);
    for i in 0..q_count as usize {
        let start = i * 32;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&q_raw[start..start + 32]);
        q.push(hash);
    }

    // ── c ≥ C → CORE ──
    if c >= ctx.core_count as u32 {
        inst.set_reg(Reg::A0, HC_CORE);
        return Ok(OmegaResult::Continue);
    }

    // ── x_s ≠ (x_e).a[c] → HUH ──
    match &ctx.empower {
        Some(emp) if c < emp.auth_agents.len() as u32
            && ctx.service_id == emp.auth_agents[c as usize] =>
        {
            // Authorized — current service is the auth agent for core c
        }
        _ => {
            // No empower state, or c out of range, or not the auth agent → HUH
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    }

    // ── a ∉ N_S → WHO ──
    if !ctx.existing_services.contains(&a) {
        inst.set_reg(Reg::A0, HC_WHO);
        return Ok(OmegaResult::Continue);
    }

    // ── OK: set (x_e).q[c] = q, (x_e).a[c] = a ──
    if let Some(ref mut emp) = ctx.empower {
        // Ensure queues vector is large enough for core index c
        while emp.queues.len() <= c as usize {
            emp.queues.push(Vec::new());
        }
        emp.queues[c as usize] = q;
        emp.auth_agents[c as usize] = a;
    }

    log::debug!("ΩA (assign): core={}, new_agent={}, Q={}", c, a, q_count);
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 16 — ΩD  Designate-validators
// ============================================================================

/// `designate(o) -> OK | HUH | ♯(fault)`
///
/// GP spec:
/// ```text
/// let o = φ_7
/// let v = [μ_{o+336i…+336} | i < N_V]    if N_{o…+336V} ⊆ V_μ
///         ∇                                otherwise
///
/// (ε', φ'_7, (x_e)_l) =
///   (♯, φ_7, (x_e)_l)             if v = ∇
///   (▸, HUH, (x_e)_l)             if x_s ≠ (x_e)_v
///   (▸, OK, v)                     otherwise
/// ```
///
/// Registers: A0=o
fn omega_d(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let o = inst.reg(Reg::A0) as u32;  // memory offset for V validator keys

    // ── Read v: V validator keys (336 bytes each) from memory ──
    let v_count = ctx.val_count as u32;  // V
    let v_total = v_count.checked_mul(336).unwrap_or(u32::MAX);
    let v_raw = match read_guest(inst, o, v_total) {
        Some(buf) => buf,
        None => {
            // v = ∇ → (♯, φ_7, ...) — fault
            return Ok(OmegaResult::Fault);
        }
    };
    let mut v: Vec<Vec<u8>> = Vec::with_capacity(v_count as usize);
    for i in 0..v_count as usize {
        let start = i * 336;
        v.push(v_raw[start..start + 336].to_vec());
    }

    // ── x_s ≠ (x_e)_v → HUH ──
    match &ctx.empower {
        Some(emp) if ctx.service_id == emp.validator => {
            // Authorized — current service is the validator service
        }
        _ => {
            // No empower state or not the validator service → HUH
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    }

    // ── OK: set (x_e)_l = v ──
    if let Some(ref mut emp) = ctx.empower {
        emp.validators = v;
    }

    log::debug!("ΩD (designate): V={} validators designated", v_count);
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 17 — ΩC  Checkpoint
// ============================================================================

/// `checkpoint() -> gas_remaining`
///
/// GP B.13: Snapshot the current side-effect state into the checkpoint
/// context (the "y" half of the dual context `(x, y)`).
/// On panic/OOG, execution reverts to this snapshot.
///
/// Returns the gas remaining at the time of the checkpoint.
fn omega_c(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    ctx.take_checkpoint();
    let gas = inst.gas();
    log::debug!("ΩC (checkpoint): snapshot taken, gas={}", gas);
    inst.set_reg(Reg::A0, gas as u64);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 18 — ΩN  New-service
// ============================================================================

/// `new(o, l, g, m, f, ĩ) -> new_id | HUH | CASH | FULL | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [o, l, g, m, f, ĩ] = φ_{7…+6}
/// let c = μ_{o…+32}                if N_{o…+32} ⊆ V_μ ∧ l ∈ N_{2³²}
///         ∇                         otherwise
///
/// let a ∈ A ∪ {∇} = {
///   (c, s:{}, l:{((c,l)↦[])}, b:a_t, g, m, p:{}, r:t, f, a:0, p:x_s)   if c ≠ ∇
///   ∇                                                                     otherwise
/// }
///
/// let s = x_s except s_b = (x_s)_b − a_t
///
/// (ε', φ'_7, x'_i, (x'_e)_d) =
///   (♯, φ_7, x_i, (x_e)_d)                           if c = ∇
///   (▸, HUH, x_i, (x_e)_d)                           if f ≠ 0 ∧ x_s ≠ (x_e)_m
///   (▸, CASH, x_i, (x_e)_d)                          if s_b < (x_s)_t
///   (▸, FULL, x_i, (x_e)_d)                          if x_s=(x_e)_r ∧ ĩ<S ∧ ĩ∈K((x_e)_d)
///   (▸, ĩ, x_i, (x_e)_d ∪ d)                        if x_s=(x_e)_r ∧ ĩ<S
///     where d = {(ĩ↦a), (x_s↦s)}
///   (▸, x_i, i*, (x_e)_d ∪ d)                        otherwise
///     where i* = check(S + (x_i−S+42) mod (2³²−S−2⁸))
///     and   d = {(x_i↦a), (x_s↦s)}
/// ```
///
/// Registers: A0=o (code hash ptr), A1=l (code length), A2=g (min accum gas),
///            A3=m (min item gas), A4=f (min on_transfer gas / privilege flag),
///            A5=ĩ (target index for privileged creation)
fn omega_n(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    use super::context::advance_service_id;

    let o       = inst.reg(Reg::A0) as u32;   // code hash pointer
    let l       = inst.reg(Reg::A1);           // code length
    let g       = inst.reg(Reg::A2);           // min accumulate gas (a_g)
    let m       = inst.reg(Reg::A3);           // min memo gas (a_m)
    let f       = inst.reg(Reg::A4);           // balance offset (a_f) + privilege flag
    let i_tilde = inst.reg(Reg::A5) as u32;   // target index (privileged creation)

    // S = 2^16 = 65536 — minimum public service index
    const S: u32 = 1 << 16;

    // ── Read code hash c from guest memory (32 bytes) ──
    // c = ∇ if N_{o…+32} ∉ V_μ ∨ l ∉ N_{2³²}
    if l > u32::MAX as u64 {
        return Ok(OmegaResult::Fault);
    }
    let c_bytes = match read_guest(inst, o, 32) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(OmegaResult::Fault), // c = ∇ → (♯, φ_7, ...)
    };
    let mut c = [0u8; 32];
    c.copy_from_slice(&c_bytes);

    // ── f ≠ 0 ∧ x_s ≠ (x_e)_m → HUH ──
    // If f (balance offset a_f) is non-zero, caller must be the manager service.
    if f != 0 {
        let is_manager = ctx.empower.as_ref()
            .map(|e| ctx.service_id == e.manager)
            .unwrap_or(false);
        if !is_manager {
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    }

    // ── s_b = (x_s)_b − a_t   (deduct deposit from caller's balance) ──
    // a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f) where a_f = ctx.threshold
    let a_t_new = compute_threshold(ctx.items_count, ctx.footprint, ctx.threshold);
    let s_b = match ctx.balance.checked_sub(a_t_new) {
        Some(b) => b,
        None => {
            // Underflow → insufficient funds
            inst.set_reg(Reg::A0, HC_CASH);
            return Ok(OmegaResult::Continue);
        }
    };

    // ── s_b < (x_s)_t → CASH ──
    // After deduction, remaining balance must be ≥ caller's threshold.
    if s_b < a_t_new {
        inst.set_reg(Reg::A0, HC_CASH);
        return Ok(OmegaResult::Continue);
    }

    // ── Build new service account a ──
    // GP: (c, s:{}, l:{((c,l)↦[])}, b:a_t, g, m, p:{}, r:t, f, a:0, p:x_s)
    let a = ServiceAccount {
        code_hash: c,
        balance: a_t_new,                // a_b = a_t (deposit = computed threshold)
        min_accum_gas: g,                // a_g
        min_memo_gas: m,                 // a_m
        threshold: f,                    // a_f (balance offset)
        recent_count: ctx.timeslot,      // a_r = t (current timeslot)
        // All other fields: empty storage, 0 items, 0 footprint, etc.
        ..Default::default()
    };

    // ── Helper: check if ID is already taken in K((x_e)_d) ──
    let id_taken = |id: u32| -> bool {
        ctx.existing_services.contains(&id)
            || ctx.created_services.iter().any(|(sid, _)| *sid == id)
    };

    // ── Determine creation path ──
    let is_staker = ctx.empower.as_ref()
        .map(|e| ctx.service_id == e.staker)
        .unwrap_or(false);

    if is_staker && i_tilde < S {
        // ── Privileged creation path: x_s = (x_e)_r ∧ ĩ < S ──

        if id_taken(i_tilde) {
            // ĩ ∈ K((x_e)_d) → FULL
            inst.set_reg(Reg::A0, HC_FULL);
            return Ok(OmegaResult::Continue);
        }

        // OK: create at privileged index ĩ, x_i unchanged
        // d = { (ĩ ↦ a), (x_s ↦ s) }
        ctx.created_services.push((i_tilde, c));
        ctx.service_accounts.insert(i_tilde, a);
        ctx.balance = s_b;  // deduct deposit from caller

        log::debug!("ΩN (new): privileged service {} (staker path)", i_tilde);
        inst.set_reg(Reg::A0, i_tilde as u64);
    } else {
        // ── Non-privileged creation path ──
        // Use current x_i (next_service_id), then advance
        let new_sid = ctx.next_service_id;

        // d = { (x_i ↦ a), (x_s ↦ s) }
        ctx.created_services.push((new_sid, c));
        ctx.service_accounts.insert(new_sid, a);
        ctx.balance = s_b;  // deduct deposit from caller

        // Advance: i* = check(S + (x_i − S + 42) mod (2³² − S − 2⁸))
        ctx.next_service_id = advance_service_id(
            new_sid,
            &ctx.existing_services,
            &ctx.created_services,
        );

        log::debug!("ΩN (new): service {} (next: {})", new_sid, ctx.next_service_id);
        inst.set_reg(Reg::A0, new_sid as u64);
    }

    Ok(OmegaResult::Continue)
}

// ============================================================================
// 19 — ΩU  Upgrade-service
// ============================================================================

/// `upgrade(o, g, m) -> OK | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [o, g, m] = φ_{7…+3}
/// let c = μ_{o…+32}                   if N_{o…+32} ⊆ V_μ
///         ∇                            otherwise
///
/// (ε', φ'_7, (x'_s)_c, (x'_s)_g, (x'_s)_m) =
///   (♯, φ_7, (x_s)_c, (x_s)_g, (x_s)_m)   if c = ∇
///   (▸, OK, c, g, m)                         otherwise
/// ```
///
/// Registers: A0=o (code hash ptr), A1=g (min accumulate gas), A2=m (min item gas)
fn omega_u(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let o = inst.reg(Reg::A0) as u32;  // code hash pointer
    let g = inst.reg(Reg::A1);          // min accumulate gas
    let m = inst.reg(Reg::A2);          // min item gas

    // ── Read code hash c from guest memory (32 bytes) ──
    let c_bytes = match read_guest(inst, o, 32) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(OmegaResult::Fault), // c = ∇ → (♯, φ_7, ...)
    };
    let mut c = [0u8; 32];
    c.copy_from_slice(&c_bytes);

    // ── OK: mutate (x_s)_c, (x_s)_g, (x_s)_m ──
    ctx.code_hash = c;
    ctx.min_accum_gas = g;
    ctx.min_memo_gas = m;

    // Also push to upgrades list for external tracking / collapse output.
    ctx.upgrades.push((ctx.service_id, c));

    log::debug!("ΩU (upgrade): service {} -> {:02x?}… g={} m={}", ctx.service_id, &c[..8], g, m);
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 20 — ΩT  Transfer
// ============================================================================

/// `transfer(d, a, l, o) -> (OK, l) | WHO | LOW | CASH | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [d, a, l, o] = φ_{7…+4}
/// let d = (x_e)_d
/// let t ∈ X ∪ {∇} = (s: x_s, d, a, m: μ_{o…+W_T}, g: l)  if N_{o…+W_T} ⊆ V_μ
///                     ∇                                      otherwise
///
/// let b = (x_s)_b − a
///
/// let (c, t) =
///   (♯, 0)         if t = ∇
///   (WHO, 0)       if d ∉ K(d)
///   (LOW, 0)       if l < d[d]_m
///   (CASH, 0)      if b < (x_s)_t
///   (OK, l)        otherwise
///
/// (ε', φ'_7, x_t, (x'_s)_b) =
///   (♯, φ_7, x_t, (x_s)_b)          if c = ♯
///   (▸, c, x_t, (x_s)_b)            if c ≠ OK
///   (▸, OK, x_t ⊕ t, b)             otherwise
/// ```
///
/// Registers: A0=d (destination), A1=a (amount), A2=l (gas limit), A3=o (memo ptr)
///
/// W_T = 128 (transfer memo size).
fn omega_t(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    const W_T: u32 = 128; // transfer memo size

    let d = inst.reg(Reg::A0) as u32;   // destination service ID
    let a = inst.reg(Reg::A1);           // amount
    let l = inst.reg(Reg::A2);           // gas limit
    let o = inst.reg(Reg::A3) as u32;   // memo pointer

    // ── Read memo: t = (s, d, a, m: μ_{o…+W_T}, g: l) ──
    // If N_{o…+W_T} ∉ V_μ → t = ∇ → fault
    let memo = match read_guest(inst, o, W_T) {
        Some(m) => m,
        None => return Ok(OmegaResult::Fault), // t = ∇ → (♯, 0)
    };

    // ── d ∉ K(d) → WHO ──
    // Destination must be a known service (in existing or created services).
    let dest_known = ctx.existing_services.contains(&d)
        || ctx.created_services.iter().any(|(sid, _)| *sid == d)
        || d == ctx.service_id;  // self-transfer allowed
    if !dest_known {
        inst.set_reg(Reg::A0, HC_WHO);
        return Ok(OmegaResult::Continue);
    }

    // ── l < d[d]_m → LOW ──
    // Gas limit must be ≥ destination's min memo gas (a_m).
    let dest_min_memo = if d == ctx.service_id {
        ctx.min_memo_gas
    } else {
        ctx.service_accounts.get(&d)
            .map(|acct| acct.min_memo_gas)
            .unwrap_or(0)
    };
    if l < dest_min_memo {
        inst.set_reg(Reg::A0, HC_LOW);
        return Ok(OmegaResult::Continue);
    }

    // ── b = (x_s)_b − a; b < (x_s)_t → CASH ──
    // a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f) where a_f = ctx.threshold
    let b = match ctx.balance.checked_sub(a) {
        Some(b) => b,
        None => {
            inst.set_reg(Reg::A0, HC_CASH);
            return Ok(OmegaResult::Continue);
        }
    };
    let a_t_transfer = compute_threshold(ctx.items_count, ctx.footprint, ctx.threshold);
    if b < a_t_transfer {
        inst.set_reg(Reg::A0, HC_CASH);
        return Ok(OmegaResult::Continue);
    }

    // ── OK: g = 10 + l (GP B.15). Base 10 already charged by dispatch.
    //    Deduct the extra l now. If insufficient gas → OOG, no mutations.
    let remaining = inst.gas();
    if remaining < l as i64 {
        inst.set_gas(remaining - l as i64); // go negative → OOG signal
        log::debug!("ΩT (transfer): OOG after OK (remaining={} < l={})", remaining, l);
        return Ok(OmegaResult::OutOfGas);
    }
    inst.set_gas(remaining - l as i64);

    // ── Apply side-effects: x_t ⊕ t, (x'_s)_b = b ──
    ctx.balance = b;
    ctx.transfers.push(JamTransfer {
        from_service: ctx.service_id,
        to_service: d,
        amount: a,
        memo,
        gas_limit: l,
    });

    log::debug!("ΩT (transfer): {} -> {} amount={} gas_cost=10+{}", ctx.service_id, d, a, l);
    inst.set_reg(Reg::A0, HC_OK);
    inst.set_reg(Reg::A1, l);  // return (OK, l)
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 21 — ΩJ  Eject-service
// ============================================================================

/// `eject(d, o) -> OK | WHO | HUH | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [d, o] = φ_{7,8}
/// let h = μ_{o…+32}                           if N_{o…+32} ⊆ V_μ
///         ∇                                    otherwise
/// let d = (x_e)_d[d]                          if d ≠ x_s ∧ d ∈ K((x_e)_d)
///         ∇                                    otherwise
/// let l = max(81, d_o) − 81
/// let s' = x_s except s'_b = (x_s)_b + d_b
///
/// (ε', φ'_7, (x'_e)_d) =
///   (♯, φ_7, (x_e)_d)                         if h = ∇
///   (▸, WHO, (x_e)_d)                         if d = ∇ ∨ d_c ≠ E₃₂(x_s)
///   (▸, HUH, (x_e)_d)                         if d_i ≠ 2 ∨ (h, l) ∉ d_l
///   (▸, OK, (x_e)_d \ {d} ∪ {(x_s ↦ s')})   if d_l[h,l] = [x,y], y < t − D
///   (▸, HUH, (x_e)_d)                         otherwise
/// ```
///
/// D = min_turnaround_period (GP §I.4.4). Tiny=32, Full=19200.
///
/// Registers: A0=d (target service ID), A1=o (code hash ptr)
fn omega_j(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let d = ctx.min_turnaround_period;

    let d_id = inst.reg(Reg::A0) as u32;  // target service ID
    let o    = inst.reg(Reg::A1) as u32;   // code hash pointer

    // ── Read hash h from guest memory (32 bytes) ──
    let h_bytes = match read_guest(inst, o, 32) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(OmegaResult::Fault), // h = ∇ → (♯, φ_7, ...)
    };
    let mut h = [0u8; 32];
    h.copy_from_slice(&h_bytes);

    // ── Look up target account d ──
    // d = (x_e)_d[d] if d ≠ x_s ∧ d ∈ K((x_e)_d), else ∇
    let target_acct = if d_id != ctx.service_id {
        ctx.service_accounts.get(&d_id)
    } else {
        None // d = x_s → ∇ (can't eject self)
    };

    // ── E₃₂(x_s): 32-byte LE encoding of calling service ID ──
    let mut e32_xs = [0u8; 32];
    e32_xs[..4].copy_from_slice(&ctx.service_id.to_le_bytes());

    // ── d = ∇ ∨ d_c ≠ E₃₂(x_s) → WHO ──
    let acct = match target_acct {
        Some(a) if a.code_hash == e32_xs => a,
        _ => {
            inst.set_reg(Reg::A0, HC_WHO);
            return Ok(OmegaResult::Continue);
        }
    };

    // ── l = max(81, d_o) − 81 ──
    // d_o = target's footprint (a_o = total octets)
    // GP: d_o refers to the target service's total byte footprint field.
    let d_o = acct.footprint;
    let l = (d_o.max(81) - 81) as u32;

    // ── d_i ≠ 2 ∨ (h, l) ∉ d_l → HUH ──
    if acct.items_count != 2 {
        inst.set_reg(Reg::A0, HC_HUH);
        return Ok(OmegaResult::Continue);
    }
    let entry = match acct.lookup.get(&(h, l)) {
        Some(e) => e,
        None => {
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    };

    // ── d_l[h, l] = [x, y], y < t − D → OK ──
    // Entry must be exactly 2 elements, and y (provision timeslot) < t − D
    if entry.len() == 2 {
        let y = entry[1];
        if ctx.timeslot >= d && y < ctx.timeslot - d {
            // OK: remove target, credit balance to caller
            let target_balance = acct.balance;
            ctx.service_accounts.remove(&d_id);
            ctx.existing_services.remove(&d_id);
            ctx.balance += target_balance;
            ctx.ejected_services.push((d_id, ctx.service_id));

            log::debug!("ΩJ (eject): service {} ejected target {}, +{} balance",
                         ctx.service_id, d_id, target_balance);
            inst.set_reg(Reg::A0, HC_OK);
            return Ok(OmegaResult::Continue);
        }
    }

    // ── otherwise → HUH (entry format wrong or preimage too recent) ──
    inst.set_reg(Reg::A0, HC_HUH);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 22 — ΩQ  Query-preimage
// ============================================================================

/// `query(o, z) -> (status, extra) | NONE | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [o, z] = φ_{7,8}
/// let h = μ_{o…+32}                 if N_{o…+32} ⊆ V_μ
///         ∇                          otherwise
/// let a = (x_s)_l[h, z]             if (h, z) ∈ K((x_s)_l)
///         ∇                          otherwise
///
/// (ε', φ'_7, φ'_8) =
///   (♯, φ_7, φ_8)                   if h = ∇
///   (▸, NONE, 0)                     if a = ∇
///   (▸, 0, 0)                        if a = []
///   (▸, 1 + 2³²·x, 0)              if a = [x]
///   (▸, 2 + 2³²·x, y)              if a = [x, y]
///   (▸, 3 + 2³²·x, y + 2³²·z)     if a = [x, y, z]
/// ```
///
/// Registers: A0=o (hash ptr), A1=z (expected length)
fn omega_q(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let o = inst.reg(Reg::A0) as u32;   // hash pointer
    let z = inst.reg(Reg::A1) as u32;   // expected length

    // ── Read hash h from guest memory (32 bytes) ──
    let h_bytes = match read_guest(inst, o, 32) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(OmegaResult::Fault), // h = ∇
    };
    let mut h = [0u8; 32];
    h.copy_from_slice(&h_bytes);

    // ── Look up (h, z) in own service's lookup table ──
    let entry = ctx.lookup.get(&(h, z));

    match entry {
        None => {
            // a = ∇ → (NONE, 0)
            inst.set_reg(Reg::A0, HC_NONE);
            inst.set_reg(Reg::A1, 0);
        }
        Some(a) => {
            match a.len() {
                0 => {
                    // a = [] → (0, 0)
                    inst.set_reg(Reg::A0, 0);
                    inst.set_reg(Reg::A1, 0);
                }
                1 => {
                    // a = [x] → (1 + 2³²·x, 0)
                    let x = a[0] as u64;
                    inst.set_reg(Reg::A0, 1 + (x << 32));
                    inst.set_reg(Reg::A1, 0);
                }
                2 => {
                    // a = [x, y] → (2 + 2³²·x, y)
                    let x = a[0] as u64;
                    let y = a[1] as u64;
                    inst.set_reg(Reg::A0, 2 + (x << 32));
                    inst.set_reg(Reg::A1, y);
                }
                _ => {
                    // a = [x, y, z] → (3 + 2³²·x, y + 2³²·z)
                    let x = a[0] as u64;
                    let y = a[1] as u64;
                    let z_val = a[2] as u64;
                    inst.set_reg(Reg::A0, 3 + (x << 32));
                    inst.set_reg(Reg::A1, y + (z_val << 32));
                }
            }
        }
    }

    log::debug!("ΩQ (query): h={:02x?}… z={}", &h[..8], z);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 23 — ΩS  Solicit-preimage
// ============================================================================

/// `solicit(o, z) -> OK | HUH | FULL | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [o, z] = φ_{7,8}
/// let h = μ_{o…+32}                       if N_{o…+32} ⊆ V_μ
///         ∇                                otherwise
/// let a = x_s except:
///   a_l[(h,z)] = []                        if h ≠ ∇ ∧ (h,z) ∉ K((x_s)_l)
///   a_l[(h,z)] = (x_s)_l[(h,z)] ++ t      if (x_s)_l[(h,z)] = [x, y]
///   ∇                                      otherwise
///
/// (ε', φ'_7, x'_s) =
///   (♯, φ_7, x_s)          if h = ∇
///   (▸, HUH, x_s)          if a = ∇
///   (▸, FULL, x_s)          if a_b < a_t
///   (▸, OK, a)              otherwise
/// ```
///
/// Registers: A0=o (hash ptr), A1=z (expected length)
fn omega_s(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let o = inst.reg(Reg::A0) as u32;   // hash pointer
    let z = inst.reg(Reg::A1) as u32;   // expected length

    // ── Read hash h from guest memory (32 bytes) ──
    let h_bytes = match read_guest(inst, o, 32) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(OmegaResult::Fault), // h = ∇
    };
    let mut h = [0u8; 32];
    h.copy_from_slice(&h_bytes);

    // ── Compute mutation a + incremental items/footprint tracking ──
    // GP §9.3: each lookup contributes 2 items and (81+z) to footprint.
    let key = (h, z);
    // a_t = max(0, B_S + B_I·a_i + B_L·a_o − a_f) where a_f = ctx.threshold
    let a_t_solicit = compute_threshold(ctx.items_count, ctx.footprint, ctx.threshold);
    match ctx.lookup.get(&key) {
        None => {
            // (h, z) ∉ K((x_s)_l) → create new entry a_l[(h,z)] = []
            // FULL check: a_b < a_t
            if ctx.balance < a_t_solicit {
                inst.set_reg(Reg::A0, HC_FULL);
                return Ok(OmegaResult::Continue);
            }
            ctx.lookup.insert(key, vec![]);
            // New lookup: items +2, footprint +(81+z)
            ctx.items_count += 2;
            ctx.footprint += 81 + z as u64;
            log::debug!("ΩS (solicit): new entry ({:02x?}…, {}) -> []", &h[..8], z);
        }
        Some(entry) if entry.len() == 2 => {
            // (x_s)_l[(h,z)] = [x, y] → append timeslot t → [x, y, t]
            // FULL check: a_b < a_t
            if ctx.balance < a_t_solicit {
                inst.set_reg(Reg::A0, HC_FULL);
                return Ok(OmegaResult::Continue);
            }
            let mut new_entry = entry.clone();
            new_entry.push(ctx.timeslot);
            ctx.lookup.insert(key, new_entry);
            log::debug!("ΩS (solicit): append t={} to ({:02x?}…, {})", ctx.timeslot, &h[..8], z);
        }
        _ => {
            // a = ∇ → HUH (entry exists but wrong length: [x], [x,y,z], or [])
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    }

    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 24 — ΩF  Forget-preimage
// ============================================================================

/// `forget(o, z) -> OK | HUH | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [o, z] = φ_{7,8}
/// let h = μ_{o…+32}                       if N_{o…+32} ⊆ V_μ
///         ∇                                otherwise
/// let a = x_s except:
///   K(a_l) = K((x_s)_l) \ {(h,z)},
///   K(a_p) = K((x_s)_p) \ {h}             if (x_s)_l[h,z] ∈ {[], [x,y]}, y < t − D
///   a_l[h,z] = [x, t]                     if (x_s)_l[h,z] = [x]
///   a_l[h,z] = [w, t]                     if (x_s)_l[h,z] = [x,y,w], y < t − D
///   ∇                                      otherwise
///
/// (ε', φ'_7, x'_s) =
///   (♯, φ_7, x_s)          if h = ∇
///   (▸, HUH, x_s)          if a = ∇
///   (▸, OK, a)              otherwise
/// ```
///
/// D = min_turnaround_period (GP §I.4.4). Tiny=32, Full=19200.
///
/// Registers: A0=o (hash ptr), A1=z (expected length)
fn omega_f(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let d = ctx.min_turnaround_period;

    let o = inst.reg(Reg::A0) as u32;   // hash pointer
    let z = inst.reg(Reg::A1) as u32;   // expected length

    // ── Read hash h from guest memory (32 bytes) ──
    let h_bytes = match read_guest(inst, o, 32) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(OmegaResult::Fault), // h = ∇
    };
    let mut h = [0u8; 32];
    h.copy_from_slice(&h_bytes);

    // ── Look up (h, z) in own service's lookup table ──
    let key = (h, z);
    let entry = match ctx.lookup.get(&key) {
        Some(e) => e.clone(),
        None => {
            // (h, z) ∉ K((x_s)_l) → a = ∇ → HUH
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
    };

    // GP: ΩF modifies a_l and a_P. Items/footprint tracked incrementally.
    // GP §9.3: removing a lookup = items -2, footprint -(81+z).
    match entry.len() {
        0 => {
            // Entry = [] (empty solicitation) → full removal of lookup + preimage
            ctx.lookup.remove(&key);
            ctx.preimages.remove(&h); // no-op if no blob
            // Removed lookup: items -2, footprint -(81+z)
            ctx.items_count = ctx.items_count.saturating_sub(2);
            ctx.footprint = ctx.footprint.saturating_sub(81 + z as u64);
            log::debug!("ΩF (forget): removed [] entry ({:02x?}…, {})", &h[..8], z);
        }
        1 => {
            // Entry = [x] → transform to [x, t]
            // Lookup still exists → no items/footprint change
            let x = entry[0];
            ctx.lookup.insert(key, vec![x, ctx.timeslot]);
            log::debug!("ΩF (forget): [{}] -> [{}, {}] for ({:02x?}…, {})", x, x, ctx.timeslot, &h[..8], z);
        }
        2 => {
            // Entry = [x, y] → full removal if y < t − D
            // Removes BOTH the lookup entry AND the preimage blob.
            let y = entry[1];
            if ctx.timeslot >= d && y < ctx.timeslot - d {
                ctx.lookup.remove(&key);
                ctx.preimages.remove(&h);
                // Removed lookup: items -2, footprint -(81+z)
                ctx.items_count = ctx.items_count.saturating_sub(2);
                ctx.footprint = ctx.footprint.saturating_sub(81 + z as u64);
                log::debug!("ΩF (forget): removed [x,y] entry ({:02x?}…, {}) y={} < t−D={}", &h[..8], z, y, ctx.timeslot - d);
            } else {
                // y >= t − D → too recent → a = ∇ → HUH
                inst.set_reg(Reg::A0, HC_HUH);
                return Ok(OmegaResult::Continue);
            }
        }
        _ => {
            // Entry = [x, y, w] (3+ elements) → transform to [w, t] if y < t − D
            // GP: K(a_P) is NOT modified — preimage blob stays!
            // Lookup still exists → no items/footprint change
            let y = entry[1];
            let w = entry[2];
            if ctx.timeslot >= d && y < ctx.timeslot - d {
                ctx.lookup.insert(key, vec![w, ctx.timeslot]);
                log::debug!("ΩF (forget): [x,y,w] -> [{}, {}] for ({:02x?}…, {})", w, ctx.timeslot, &h[..8], z);
            } else {
                // y >= t − D → too recent → a = ∇ → HUH
                inst.set_reg(Reg::A0, HC_HUH);
                return Ok(OmegaResult::Continue);
            }
        }
    }

    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 25 — Ωδ  Yield accumulation trie result
// ============================================================================

/// `yield(o) -> OK | ♯(fault)`
///
/// GP spec:
/// ```text
/// let o = φ_7
/// let h = μ_{o…+32}    if N_{o…+32} ⊆ V_μ
///         ∇             otherwise
/// (ε', φ'_7, x'_y) =
///   (♯, φ_7, x_y)      if h = ∇
///   (▸, OK, h)          otherwise
/// ```
///
/// Registers: A0=o (hash ptr)
fn omega_yield(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let o = inst.reg(Reg::A0) as u32;

    // ── Read hash h from guest memory (32 bytes) ──
    let h_bytes = match read_guest(inst, o, 32) {
        Some(b) if b.len() == 32 => b,
        _ => return Ok(OmegaResult::Fault), // h = ∇ → ♯
    };
    let mut h = [0u8; 32];
    h.copy_from_slice(&h_bytes);

    ctx.yield_output = Some(h);
    log::debug!("Ωδ (yield): {:02x?}…", &h[..8]);
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 26 — Ωψ  Provide preimage
// ============================================================================

/// `provide(s, o, z) -> OK | WHO | HUH | ♯(fault)`
///
/// GP spec:
/// ```text
/// let [o, z] = φ_{8,9}
/// let d = (x_e)_d
/// let s = x_s          if φ_7 = 2⁶⁴ − 1
///         φ_7           otherwise
/// let i = μ_{o…+z}     if N_{o…+z} ⊆ V_μ
///         ∇             otherwise
/// let a = d[s]          if s ∈ K(d)
///         ∅             otherwise
///
/// (ε', φ'_7, x'_p) =
///   (♯, φ_7, x_p)                      if i = ∇
///   (▸, WHO, x_p)                      if a = ∅
///   (▸, HUH, x_p)                      if a_l[(H(i), z)] ≠ []
///   (▸, HUH, x_p)                      if (s, i) ∈ x_p
///   (▸, OK, x_p ∪ {(s, i)})            otherwise
/// ```
///
/// Registers: A0=φ_7 (service), A1=o (data ptr), A2=z (data length)
fn omega_provide(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let phi7 = inst.reg(Reg::A0);        // service selector
    let o    = inst.reg(Reg::A1) as u32;  // data pointer
    let z    = inst.reg(Reg::A2) as u32;  // data length

    // ── Resolve service s ──
    let s = if phi7 == u64::MAX {
        ctx.service_id
    } else {
        phi7 as u32
    };

    // ── Read preimage data i from guest memory ──
    let data = match read_guest(inst, o, z) {
        Some(d) if d.len() == z as usize => d,
        _ => return Ok(OmegaResult::Fault), // i = ∇
    };

    // ── Look up service account a = d[s] ──
    // For self, use ctx.lookup directly; for others, use service_accounts
    let is_self = s == ctx.service_id;

    let lookup_entry = if is_self {
        // Self-service: use ctx.lookup
        let hash = <Blake2b<U32> as Digest>::digest(&data);
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);
        ctx.lookup.get(&(h, z)).cloned()
    } else {
        // Other service: look up in service_accounts
        match ctx.service_accounts.get(&s) {
            Some(acct) => {
                let hash = <Blake2b<U32> as Digest>::digest(&data);
                let mut h = [0u8; 32];
                h.copy_from_slice(&hash);
                acct.lookup.get(&(h, z)).cloned()
            }
            None => {
                // a = ∅ → WHO
                inst.set_reg(Reg::A0, HC_WHO);
                return Ok(OmegaResult::Continue);
            }
        }
    };

    // If not self-service and service not found, we already returned WHO above.
    // If self-service, we always have the account — no WHO check needed.

    // ── a_l[(H(i), z)] must be exactly [] ──
    match &lookup_entry {
        None => {
            // Key not in lookup → HUH (no solicitation exists)
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
        Some(entry) if !entry.is_empty() => {
            // Entry exists but ≠ [] → HUH
            inst.set_reg(Reg::A0, HC_HUH);
            return Ok(OmegaResult::Continue);
        }
        _ => {} // entry == [] → proceed
    }

    // ── (s, i) ∈ x_p → HUH (already provided) ──
    if ctx.provided_preimages.iter().any(|(sid, d)| *sid == s && *d == data) {
        inst.set_reg(Reg::A0, HC_HUH);
        return Ok(OmegaResult::Continue);
    }

    // ── OK: x_p ∪ {(s, i)} ──
    log::debug!("Ωψ (provide): service={}, {} bytes", s, z);
    ctx.provided_preimages.push((s, data));
    inst.set_reg(Reg::A0, HC_OK);
    Ok(OmegaResult::Continue)
}

// ============================================================================
// 100 — Log (extension, not GP)
// ============================================================================

/// `log(level, target_ptr, target_len, text_ptr, text_len)`
///
/// Registers: A0=level, A1=target_ptr, A2=target_len, A3=text_ptr, A4=text_len
fn ext_log(inst: &mut Inst, ctx: &mut JamHostContext) -> Result<OmegaResult, JamHostError> {
    let level    = inst.reg(Reg::A0);
    let _tgt_ptr = inst.reg(Reg::A1) as u32;
    let _tgt_len = inst.reg(Reg::A2) as u32;
    let text_ptr = inst.reg(Reg::A3) as u32;
    let text_len = inst.reg(Reg::A4) as u32;

    if let Some(text) = read_guest(inst, text_ptr, text_len) {
        if let Ok(s) = std::str::from_utf8(&text) {
            let tag = match level { 0 => "ERROR", 1 => "WARN", 2 => "INFO", 3 => "DEBUG", _ => "TRACE" };
            log::debug!("[PVM {}] {}", tag, s);
        }
        ctx.logs.push(text);
    }
    Ok(OmegaResult::Continue)
}

// ============================================================================
// Tests — extracted to pvm/tests/test_host_calls.rs
// ============================================================================

#[cfg(test)]
#[path = "tests/test_host_calls.rs"]
mod tests;
