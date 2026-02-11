//! JAM PVM execution context types (GP Appendix B)
//!
//! All types shared across the PVM module: host context, errors, fetch kinds,
//! invocation contexts, and the opaque JAM instance handles.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// ============================================================================
// InvocationContext — determines which host calls are available (GP B.1–B.8)
// ============================================================================

/// Which PVM invocation we're running in.
///
/// Each context enables a **disjoint** subset of host calls (Ω),
/// per GP Appendix B dispatch tables:
///
/// | Context       | GP      | Available Ω (by ecalli index)                    |
/// |---------------|---------|--------------------------------------------------|
/// | IsAuthorized  | B.1–B.2 | 0(gas), 1(fetch)                                 |
/// | Refine        | B.5–B.6 | 0(gas), 1(fetch), 6(hist), 7(export), 8–13(iPVM) |
/// | Accumulate    | B.9–B.11| 0(gas), 1(fetch), 2(lookup), 3(read), 4(write),  |
/// |               |         | 5(info), 14–26(priv+svc+preimg+yield+provide)    |
/// | OnTransfer    | B.8     | same as Accumulate minus 14(bless), 15(assign),   |
/// |               |         | 16(designate)                                    |
///
/// **Key insight from B.6 vs B.11**: inner-PVM calls (8–13) are Refine-only.
/// Accumulate does NOT have them.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum InvocationContext {
    IsAuthorized,
    Refine,
    #[default]
    Accumulate,
    OnTransfer,
}

impl InvocationContext {
    /// Returns `true` if host call at `id` is allowed in this context.
    ///
    /// Unknown IDs (not in the table at all) follow the GP default:
    /// charge 10 gas, don't touch registers, continue.
    pub fn allows(&self, id: u32) -> bool {
        match self {
            // B.2: F only dispatches gas (0) and fetch (1)
            Self::IsAuthorized => matches!(id, 0 | 1 | 100),

            // B.6: gas, fetch, historical_lookup, export, inner-PVM (8–13)
            Self::Refine => matches!(id, 0 | 1 | 6 | 7 | 8..=13 | 100),

            // B.11: gas, fetch, lookup, read, write, info,
            //       privileged (14–17), svc-mgmt (18–21),
            //       preimage-mgmt (22–24), yield (25), provide (26)
            //       NO inner-PVM (8–13), NO hist_lookup (6), NO export (7)
            Self::Accumulate => matches!(id,
                0..=5 | 14..=26 | 100
            ),

            // B.8: same as Accumulate but without bless(14), assign(15), designate(16)
            Self::OnTransfer => matches!(id,
                0..=5 | 17..=26 | 100
            ),
        }
    }
}

// ============================================================================
// FetchKind (GP Appendix B.5 — ΩY)
// ============================================================================

/// Data kinds for the fetch host call (ΩY).
/// Maps to `jam-pvm-common/src/imports.rs` `fetch(kind)` parameter.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u64)]
pub enum FetchKind {
    ProtocolParameters = 0,
    Entropy = 1,
    AuthTrace = 2,
    AnyExtrinsic = 3,
    OurExtrinsic = 4,
    AnyImport = 5,
    OurImport = 6,
    WorkPackage = 7,
    Authorizer = 8,
    AuthToken = 9,
    RefineContext = 10,
    ItemsSummary = 11,
    AnyItemSummary = 12,
    AnyPayload = 13,
    AccumulateItems = 14,
    AnyAccumulateItem = 15,
}

impl TryFrom<u64> for FetchKind {
    type Error = ();
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ProtocolParameters),
            1 => Ok(Self::Entropy),
            2 => Ok(Self::AuthTrace),
            3 => Ok(Self::AnyExtrinsic),
            4 => Ok(Self::OurExtrinsic),
            5 => Ok(Self::AnyImport),
            6 => Ok(Self::OurImport),
            7 => Ok(Self::WorkPackage),
            8 => Ok(Self::Authorizer),
            9 => Ok(Self::AuthToken),
            10 => Ok(Self::RefineContext),
            11 => Ok(Self::ItemsSummary),
            12 => Ok(Self::AnyItemSummary),
            13 => Ok(Self::AnyPayload),
            14 => Ok(Self::AccumulateItems),
            15 => Ok(Self::AnyAccumulateItem),
            _ => Err(()),
        }
    }
}

// ============================================================================
// B.1 — Host-Call Result Constants (GP Appendix B.1)
// ============================================================================
//
// These are the u64 values returned in register A0 to the guest PVM.
// They live near 2^64 so they cannot be confused with valid lengths/indices.

/// OK = 0: general success.
pub const HC_OK:   u64 = 0;
/// NONE = 2^64 − 1: item does not exist.
pub const HC_NONE: u64 = u64::MAX;        // 0xFFFF_FFFF_FFFF_FFFF
/// WHAT = 2^64 − 2: name unknown.
pub const HC_WHAT: u64 = u64::MAX - 1;
/// OOB = 2^64 − 3: inner PVM memory index not accessible.
pub const HC_OOB:  u64 = u64::MAX - 2;
/// WHO = 2^64 − 4: index unknown.
pub const HC_WHO:  u64 = u64::MAX - 3;
/// FULL = 2^64 − 5: storage full or resource already allocated.
pub const HC_FULL: u64 = u64::MAX - 4;
/// CORE = 2^64 − 6: core index unknown.
pub const HC_CORE: u64 = u64::MAX - 5;
/// CASH = 2^64 − 7: insufficient funds.
pub const HC_CASH: u64 = u64::MAX - 6;
/// LOW = 2^64 − 8: gas limit too low.
pub const HC_LOW:  u64 = u64::MAX - 7;
/// HUH = 2^64 − 9: already solicited, cannot be forgotten,
/// or operation invalid due to privilege level.
pub const HC_HUH:  u64 = u64::MAX - 8;

// Inner PVM result codes (used by ΩK invoke, not A0 return values)
/// HALT = 0: invocation completed normally.
pub const PVM_HALT:  u32 = 0;
/// PANIC = 1: invocation completed with a panic.
pub const PVM_PANIC: u32 = 1;
/// FAULT = 2: invocation completed with a page fault.
pub const PVM_FAULT: u32 = 2;
/// HOST = 3: invocation completed with a host-call fault.
pub const PVM_HOST:  u32 = 3;
/// OOG = 4: invocation ran out of gas.
pub const PVM_OOG:   u32 = 4;

// ============================================================================
// Error types (Rust-level, for polkavm::Instance<Ctx, Error>)
// ============================================================================

/// Rust-level error type for the polkavm instance.
///
/// This is NOT the same as B.1 result constants — those are u64 values
/// written to register A0.  This enum is for Rust error propagation only.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum JamHostError {
    /// A host call encountered an unrecoverable internal error.
    InternalError,
}

/// A token transfer record (ΩT side-effect)
#[derive(Clone, Debug)]
pub struct JamTransfer {
    /// Source service ID (x_s — the sender).
    pub from_service: u32,
    /// Destination service ID (d).
    pub to_service: u32,
    /// Amount transferred (a).
    pub amount: u64,
    /// Memo bytes (W_T = 128 bytes from guest memory).
    pub memo: Vec<u8>,
    /// Gas limit for the destination's on_transfer invocation (l).
    pub gas_limit: u64,
}

/// Service account view (d[s]) for cross-service lookups and Ω_I encoding.
///
/// GP: Ω_L needs `a_P` (preimages), Ω_R needs `a_s` (storage),
/// Ω_I needs the full info record, and Ω_W needs `a_t` for FULL check.
/// Populated before PVM execution for any service the guest may query.
///
/// Ω_I encoding: `E(a_c, E_8(a_b, a_t, a_g, a_m, a_o), E_4(a_i), E_8(a_f), E_4(a_r, a_a, a_p))`
/// = 32 + 40 + 4 + 8 + 12 = **96 bytes**.
#[derive(Clone, Debug, Default)]
pub struct ServiceAccount {
    /// a_s — storage map
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
    /// a_P — preimage lookup (hash → data)
    pub preimages: HashMap<[u8; 32], Vec<u8>>,
    /// a_l — preimage metadata / lookup table.
    ///
    /// Maps `(hash, length)` → status tuple of 0–3 u32 values:
    /// - `[]` = solicited, not yet provided
    /// - `[x]` = provided (x = solicitation timeslot)
    /// - `[x, y]` = provided with history (x = solicitation, y = provision timeslot)
    /// - `[x, y, z]` = full record
    ///
    /// Used by Ω_Q (query) and Ω_J (eject).
    pub lookup: HashMap<([u8; 32], u32), Vec<u32>>,
    /// a_b — balance
    pub balance: u64,
    /// a_c — code hash (32 bytes)
    pub code_hash: [u8; 32],
    /// a_t — storage item count threshold (u64). Ω_W returns FULL if a_t > a_b.
    pub threshold: u64,
    /// a_g — minimum gas for accumulate (u64)
    pub min_accum_gas: u64,
    /// a_m — minimum gas per item in accumulate (u64)
    pub min_item_gas: u64,
    /// a_o — minimum gas for on_transfer (u64)
    pub min_on_transfer_gas: u64,
    /// a_i — number of items (preimages/solicitations) (u32)
    pub items_count: u32,
    /// a_f — total footprint in bytes (u64)
    pub footprint: u64,
    /// a_r — number of recent history entries (u32)
    pub recent_count: u32,
    /// a_a — accumulate-gas-limit (u32)
    pub accum_gas_limit: u32,
    /// a_p — preimage-pages count (u32)
    pub preimage_pages: u32,
}

/// Size of the Ω_I encoded service info record (bytes).
pub const SERVICE_INFO_SIZE: usize = 96;

impl ServiceAccount {
    /// Encode service account info for Ω_I (GP Appendix B).
    ///
    /// `E(a_c, E_8(a_b, a_t, a_g, a_m, a_o), E_4(a_i), E_8(a_f), E_4(a_r, a_a, a_p))`
    pub fn encode_info(&self) -> [u8; SERVICE_INFO_SIZE] {
        let mut buf = [0u8; SERVICE_INFO_SIZE];
        let mut off = 0;

        // a_c — 32 bytes
        buf[off..off + 32].copy_from_slice(&self.code_hash);
        off += 32;

        // E_8(a_b, a_t, a_g, a_m, a_o) — 5 × 8 = 40 bytes
        buf[off..off + 8].copy_from_slice(&self.balance.to_le_bytes());       off += 8;
        buf[off..off + 8].copy_from_slice(&self.threshold.to_le_bytes());     off += 8;
        buf[off..off + 8].copy_from_slice(&self.min_accum_gas.to_le_bytes()); off += 8;
        buf[off..off + 8].copy_from_slice(&self.min_item_gas.to_le_bytes());  off += 8;
        buf[off..off + 8].copy_from_slice(&self.min_on_transfer_gas.to_le_bytes()); off += 8;

        // E_4(a_i) — 4 bytes
        buf[off..off + 4].copy_from_slice(&self.items_count.to_le_bytes());   off += 4;

        // E_8(a_f) — 8 bytes
        buf[off..off + 8].copy_from_slice(&self.footprint.to_le_bytes());     off += 8;

        // E_4(a_r, a_a, a_p) — 3 × 4 = 12 bytes
        buf[off..off + 4].copy_from_slice(&self.recent_count.to_le_bytes());  off += 4;
        buf[off..off + 4].copy_from_slice(&self.accum_gas_limit.to_le_bytes()); off += 4;
        buf[off..off + 4].copy_from_slice(&self.preimage_pages.to_le_bytes()); // off += 4;
        debug_assert_eq!(off + 4, SERVICE_INFO_SIZE);

        buf
    }
}

// ============================================================================
// JamHostContext — state available during PVM execution
// ============================================================================

/// Host context for JAM service execution (GP Appendix B).
///
/// Contains all state available to host calls during PVM execution:
/// invocation context, storage, preimages, balance, transfers, and
/// fetch-able context data.
pub struct JamHostContext {
    // ── Invocation context ──────────────────────────────
    /// Which PVM invocation we're in — gates available host calls.
    pub invocation: InvocationContext,

    // ── Service identity ────────────────────────────────
    pub service_id: u32,
    pub balance: u64,
    pub slot: u32,
    pub next_service_id: u32,
    /// Core index (c) — used by IsAuthorized and Refine.
    pub core_index: u16,

    // ── Own-service info (for Ω_I self-lookup and Ω_W FULL check) ──
    /// a_c — code hash
    pub code_hash: [u8; 32],
    /// a_t — storage threshold. Ω_W returns FULL if a_t > a_b.
    pub threshold: u64,
    /// a_g — minimum gas for accumulate
    pub min_accum_gas: u64,
    /// a_m — minimum gas per item
    pub min_item_gas: u64,
    /// a_o — minimum gas for on_transfer
    pub min_on_transfer_gas: u64,
    /// a_i — number of items
    pub items_count: u32,
    /// a_f — total footprint in bytes
    pub footprint: u64,
    /// a_r — recent history entries
    pub recent_count: u32,
    /// a_a — accumulate gas limit
    pub accum_gas_limit: u32,
    /// a_p — preimage pages count
    pub preimage_pages: u32,

    // ── Storage (ΩR / ΩW) ──────────────────────────────
    pub storage: HashMap<Vec<u8>, Vec<u8>>,

    // ── Preimages (ΩL) ─────────────────────────────────
    pub preimages: HashMap<[u8; 32], Vec<u8>>,

    // ── Preimage lookup table (ΩQ / ΩJ) ──────────────
    /// a_l — own service's preimage metadata lookup table.
    /// Maps `(hash, length)` → status tuple (0–3 u32 values).
    pub lookup: HashMap<([u8; 32], u32), Vec<u32>>,

    // ── Side-effects ────────────────────────────────────
    pub logs: Vec<Vec<u8>>,
    pub transfers: Vec<JamTransfer>,
    pub ejected_services: Vec<(u32, u32)>,
    pub created_services: Vec<(u32, [u8; 32])>,
    pub upgrades: Vec<(u32, [u8; 32])>,
    pub yield_output: Option<[u8; 32]>,
    /// x_p — provided preimages set: (service_id, preimage_data).
    /// Accumulated by Ω_provide (index 26); included in collapse result.
    pub provided_preimages: Vec<(u32, Vec<u8>)>,
    pub error: Option<JamHostError>,

    // ── Checkpoint (B.13 dual-context y) ─────────────
    /// Checkpoint snapshot — the "y" context in B.13's `(x, y)` pair.
    /// Created by ΩC (checkpoint), consumed by `collapse()`.
    pub checkpoint: Option<AccumulateCheckpoint>,

    // ── Fetch data (ΩY) ────────────────────────────────
    pub entropy_raw: Vec<u8>,
    pub entropy: [[u8; 32]; 4],
    pub accumulate_items: Vec<Vec<u8>>,
    pub work_package: Vec<u8>,
    pub protocol_params: Vec<u8>,

    // ── Block context (shared across Accumulate/Refine) ──
    /// Header hash H_T — needed by ΩN, ΩJ, ΩS, ΩF in B.11.
    pub header_hash: [u8; 32],

    // ── Service registry (B.14 check) ────────────────────
    /// K(e_d) — set of existing service IDs from δ.
    /// Used by `check()` (B.14) to skip already-used IDs when creating services.
    pub existing_services: HashSet<u32>,

    // ── Other service accounts (d) — for cross-service lookups ──
    /// d — service account database, keyed by service ID.
    /// Populated before execution with accounts the guest may query
    /// via Ω_L (lookup), Ω_R (read), Ω_I (info).
    /// Our own service (service_id) is NOT stored here — use
    /// `storage`/`preimages`/`balance` directly.
    pub service_accounts: HashMap<u32, ServiceAccount>,

    // ── Protocol constants (GP §I.4) ─────────────────────
    /// W_G — segment size in bytes (default 4104). Used by Ω_E for padding/cap.
    pub segment_size: u32,
    /// W_X — max export segments (default 3072). Used by Ω_E FULL check.
    pub max_exports: u32,
    /// ς (varsigma) — base export count passed into the refine context.
    pub export_base: u32,
    /// t — current timeslot. Used by Ω_H (historical lookup) for Λ.
    pub timeslot: u32,

    // ── Refine-specific data (ΩY / ΩH in Ψ_R) ─────────
    /// Work item payload (w.y) — the payload bytes for the current refine.
    pub payload: Vec<u8>,
    /// Work package hash H(p) — hash of the whole work package.
    pub package_hash: [u8; 32],
    /// Import segments (ī) — shared across all work items.
    pub import_segments: Vec<Vec<u8>>,
    /// Authorizer trace (r) — output of is_authorized.
    pub authorizer_trace: Vec<u8>,
    /// Export segment accumulator (ΩE side-effect).
    pub export_segments: Vec<Vec<u8>>,
    /// Current work item index (i) within the work package.
    pub work_item_index: u32,
    /// Lookup anchor block hash (ℍ₀).
    pub lookup_anchor_hash: [u8; 32],
    /// Extrinsic segments (x̄) — x̄[j][k] = extrinsic segment k of work item j.
    pub extrinsics: Vec<Vec<Vec<u8>>>,
    /// Authorizer code (p_f) — raw code blob.
    pub authorizer_code: Vec<u8>,
    /// Justification / authorization token (p_j).
    pub justification: Vec<u8>,
    /// Pre-encoded work-package context E(p_c).
    pub work_package_context: Vec<u8>,
    /// Structured work items — for S(w) encoding (kinds 11/12/13).
    pub work_items: Vec<WorkItemInfo>,

    // ── Inner PVM machines (ΩM / ΩP / ΩO) ───────────────
    /// `m` — map of inner PVM machines, keyed by allocation index n.
    pub inner_machines: HashMap<u32, InnerMachine>,
    /// Shared engine reference for creating inner PVM modules (deblob).
    pub engine: Option<Arc<polkavm::Engine>>,

    // ── Protocol parameters (GP §I.4) — core/validator/queue ──
    /// C — number of cores. Used by ΩB to read `c` authorization agents.
    /// Default: 2 (TINY chainspec).
    pub core_count: u16,
    /// Q — authorization queue length per core. Used by ΩA to read Q × 32 bytes.
    /// Default: 80 (same for full and tiny chainspec).
    pub auth_queue_len: u16,
    /// V — validator count. Used by ΩD to read V × 336-byte validator keys.
    /// Default: 6 (TINY chainspec).
    pub val_count: u16,

    // ── Accumulate privileged outputs (ΩB / ΩA / ΩD) ─────
    /// x_e — empower state, set by ΩB (bless), mutated by ΩA and ΩD.
    pub empower: Option<EmpowerState>,
}

/// GP §I.4 default for W_G (segment size in bytes).
pub const DEFAULT_SEGMENT_SIZE: u32 = 4104;
/// GP §I.4 default for W_X (max export segments).
pub const DEFAULT_MAX_EXPORTS: u32 = 3072;
/// Z_P — PVM page size in bytes (GP §A / jam-types).
pub const PAGE_SIZE: u32 = 4096;

impl Default for JamHostContext {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            max_exports: DEFAULT_MAX_EXPORTS,
            // All other fields use their type's default (0, empty, false, None)
            invocation: Default::default(),
            service_id: 0,
            balance: 0,
            slot: 0,
            next_service_id: 0,
            core_index: 0,
            code_hash: [0u8; 32],
            threshold: 0,
            min_accum_gas: 0,
            min_item_gas: 0,
            min_on_transfer_gas: 0,
            items_count: 0,
            footprint: 0,
            recent_count: 0,
            accum_gas_limit: 0,
            preimage_pages: 0,
            storage: Default::default(),
            preimages: Default::default(),
            lookup: Default::default(),
            logs: Default::default(),
            transfers: Default::default(),
            ejected_services: Default::default(),
            created_services: Default::default(),
            upgrades: Default::default(),
            yield_output: None,
            provided_preimages: Default::default(),
            error: None,
            checkpoint: None,
            entropy_raw: Default::default(),
            entropy: Default::default(),
            accumulate_items: Default::default(),
            work_package: Default::default(),
            protocol_params: Default::default(),
            header_hash: [0u8; 32],
            existing_services: Default::default(),
            service_accounts: Default::default(),
            export_base: 0,
            timeslot: 0,
            payload: Default::default(),
            package_hash: [0u8; 32],
            import_segments: Default::default(),
            authorizer_trace: Default::default(),
            export_segments: Default::default(),
            work_item_index: 0,
            lookup_anchor_hash: [0u8; 32],
            extrinsics: Default::default(),
            authorizer_code: Default::default(),
            justification: Default::default(),
            work_package_context: Default::default(),
            work_items: Default::default(),
            inner_machines: Default::default(),
            engine: None,
            core_count: 2,        // TINY chainspec default (C)
            auth_queue_len: 80,   // GP Q — same for full and tiny
            val_count: 6,         // TINY chainspec default (V)
            empower: None,
        }
    }
}

/// Structured info for one work item, used for S(w) encoding (GP B.6).
///
/// `S(w) = (w_s, w_c, w_g, w_g_a)` — service ID, code hash, gas limit, accumulate gas limit.
/// Plus the payload (w_y) for kind=13 (AnyPayload).
#[derive(Clone, Debug, Default)]
pub struct WorkItemInfo {
    /// w_s — target service ID
    pub service_id: u32,
    /// w_c — code hash
    pub code_hash: [u8; 32],
    /// w_g — gas limit for refine
    pub gas_limit: u64,
    /// w_g_a — gas limit for accumulate
    pub gas_limit_accum: u64,
    /// w_y — payload bytes
    pub payload: Vec<u8>,
}

// ============================================================================
// B.7 — Accumulate privileged outputs (ΩB / ΩA / ΩD)
// ============================================================================

/// Empower state `x_e = (m, a, v, r, z, q, l)` set by ΩB (bless), ΩA (assign), ΩD (designate).
///
/// Captures the privileged service configuration:
/// - `m` — manager service index
/// - `a` — authorization agents (one per core, length = C)
/// - `v` — validator service index
/// - `r` — staking service index
/// - `z` — per-service gas authorization map
/// - `q` — per-core authorization queues (set by ΩA)
/// - `l` — designated validator keys (set by ΩD)
#[derive(Clone, Debug, Default)]
pub struct EmpowerState {
    /// m — manager service index.
    pub manager: u32,
    /// a — authorization agent per core (length = C = core_count).
    pub auth_agents: Vec<u32>,
    /// v — validator service index.
    pub validator: u32,
    /// r — staking service index.
    pub staker: u32,
    /// z — per-service gas authorization: service_id → gas.
    pub gas_map: HashMap<u32, u64>,
    /// q — per-core authorization queues (C entries, each with Q hashes of 32 bytes).
    /// Set by ΩA (assign-core).
    pub queues: Vec<Vec<[u8; 32]>>,
    /// l — designated validator keys (V entries, each 336 bytes).
    /// Set by ΩD (designate-validators).
    pub validators: Vec<Vec<u8>>,
}

// ============================================================================
// Inner PVM machines (GP B.6 — ΩM / ΩP / ΩO / ΩZ / ΩK / ΩX)
// ============================================================================

/// An inner (child) PVM machine created by ΩM during Refine.
///
/// Inner PVMs have no host call support — they can only be peeked/poked/invoked.
/// The `m` map in the GP is `HashMap<u32, InnerMachine>`.
pub struct InnerMachine {
    /// The polkavm instance (basic, no host functions).
    pub instance: polkavm::Instance<()>,
    /// Initial program counter `i` passed to ΩM.
    pub initial_pc: u32,
}

// ============================================================================
// B.13 — Accumulate Checkpoint & Collapse
// ============================================================================

/// Snapshot of accumulate side-effects for checkpoint/rollback (GP B.13).
///
/// Captures the "y" half of the dual context `(x, y)` used during accumulation.
/// When ΩC (checkpoint) is called, the current state is snapshotted here.
/// On panic/OOG, execution reverts to this snapshot.
#[derive(Clone, Default, Debug)]
pub struct AccumulateCheckpoint {
    pub transfers: Vec<JamTransfer>,
    pub ejected_services: Vec<(u32, u32)>,
    pub created_services: Vec<(u32, [u8; 32])>,
    pub upgrades: Vec<(u32, [u8; 32])>,
    pub yield_output: Option<[u8; 32]>,
    pub provided_preimages: Vec<(u32, Vec<u8>)>,
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
    /// Snapshotted preimage lookup table for rollback.
    pub lookup: HashMap<([u8; 32], u32), Vec<u32>>,
    /// Snapshotted empower state (x_e) for rollback.
    pub empower: Option<EmpowerState>,
}

/// Outcome of PVM execution, used as input `o` to collapse C (GP B.13).
#[derive(Clone, Debug, PartialEq)]
pub enum PvmOutcome {
    /// Normal halt (▸) — no yield hash.
    Halt,
    /// Normal halt with yield hash (o ∈ ℍ).
    HaltWithYield([u8; 32]),
    /// Panic (■).
    Panic,
    /// Out of gas (∞).
    OutOfGas,
}

/// Result of accumulate collapse C (GP B.13).
///
/// Contains the final side-effects after resolving the dual context.
#[derive(Clone, Debug, Default)]
pub struct CollapseResult {
    pub transfers: Vec<JamTransfer>,
    pub ejected_services: Vec<(u32, u32)>,
    pub created_services: Vec<(u32, [u8; 32])>,
    pub upgrades: Vec<(u32, [u8; 32])>,
    pub yield_output: Option<[u8; 32]>,
    pub provided_preimages: Vec<(u32, Vec<u8>)>,
    pub gas_remaining: i64,
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
    /// Final preimage lookup table after collapse.
    pub lookup: HashMap<([u8; 32], u32), Vec<u32>>,
    /// Final empower state (x_e) after collapse.
    pub empower: Option<EmpowerState>,
}

impl JamHostContext {
    /// Build a [`ServiceAccount`] view of our own service for Ω_I self-lookup.
    pub fn self_account_info(&self) -> ServiceAccount {
        ServiceAccount {
            storage: self.storage.clone(),
            preimages: self.preimages.clone(),
            lookup: self.lookup.clone(),
            balance: self.balance,
            code_hash: self.code_hash,
            threshold: self.threshold,
            min_accum_gas: self.min_accum_gas,
            min_item_gas: self.min_item_gas,
            min_on_transfer_gas: self.min_on_transfer_gas,
            items_count: self.items_count,
            footprint: self.footprint,
            recent_count: self.recent_count,
            accum_gas_limit: self.accum_gas_limit,
            preimage_pages: self.preimage_pages,
        }
    }

    // ── Inner PVM helpers ──────────────────────────────────────

    /// Find `min(n ∈ ℕ, n ∉ K(m))` — the smallest unused machine index.
    pub fn next_machine_id(&self) -> u32 {
        let mut n: u32 = 0;
        while self.inner_machines.contains_key(&n) {
            n = n.checked_add(1).expect("inner machine index overflow");
        }
        n
    }

    /// Ensure the inner engine is available, creating one lazily if needed.
    ///
    /// The engine is configured with interpreter backend and dynamic paging
    /// enabled (required by ΩZ for `protect_memory`/`free_pages`).
    pub fn ensure_engine(&mut self) -> &Arc<polkavm::Engine> {
        if self.engine.is_none() {
            let mut config = polkavm::Config::new();
            config.set_backend(Some(polkavm::BackendKind::Interpreter));
            config.set_allow_dynamic_paging(true);
            let engine = polkavm::Engine::new(&config)
                .expect("failed to create interpreter engine");
            self.engine = Some(Arc::new(engine));
        }
        self.engine.as_ref().unwrap()
    }

    /// `deblob(p)` — attempt to parse a PVM blob into a runnable inner instance.
    ///
    /// Returns `None` if blob parsing, module compilation, or instantiation fails
    /// (i.e. `deblob(p) = ∇`).
    ///
    /// Inner PVM modules are compiled with gas metering and dynamic paging
    /// so that ΩZ (pages) can manipulate page permissions.
    pub fn deblob(&mut self, blob: &[u8]) -> Option<polkavm::Instance<()>> {
        let engine = self.ensure_engine().clone();

        // Try JAM format first (jam-program-blob-common), fall back to raw PVM
        let program_blob = {
            use jam_program_blob_common::ProgramBlob as JamProgramBlob;

            if let Some(jam_blob) = JamProgramBlob::from_bytes(blob) {
                let parts: polkavm::ProgramParts = jam_blob.into();
                polkavm::ProgramBlob::from_parts(parts).ok()?
            } else {
                polkavm::ProgramBlob::parse(blob.into()).ok()?
            }
        };

        let mut module_config = polkavm::ModuleConfig::new();
        module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
        module_config.set_dynamic_paging(true);

        let module = polkavm::Module::from_blob(&engine, &module_config, program_blob).ok()?;
        let linker = polkavm::Linker::<()>::new();
        let pre = linker.instantiate_pre(&module).ok()?;
        pre.instantiate().ok()
    }

    /// Take a checkpoint snapshot of current side-effect state.
    ///
    /// Called by ΩC (checkpoint, ecalli 17). Saves the "y" context.
    pub fn take_checkpoint(&mut self) {
        self.checkpoint = Some(AccumulateCheckpoint {
            transfers: self.transfers.clone(),
            ejected_services: self.ejected_services.clone(),
            created_services: self.created_services.clone(),
            upgrades: self.upgrades.clone(),
            yield_output: self.yield_output,
            provided_preimages: self.provided_preimages.clone(),
            storage: self.storage.clone(),
            lookup: self.lookup.clone(),
            empower: self.empower.clone(),
        });
    }

    /// Collapse C per GP B.13.
    ///
    /// ```text
    /// C: (u, o, (x,y)) ↦
    ///   (e: y_e, t: y_t, y: y_y, u, p: y_p)         if o ∈ {∞, ♯}
    ///   (e: x_e, t: x_t, y: o,  u, p: (x,y)_p)      otherwise if o ∈ ℍ
    ///   (e: x_e, t: x_t, y: x_y, u, p: x_p)         otherwise
    /// ```
    ///
    /// - `x` = current (regular) context = `self`
    /// - `y` = checkpoint context = `self.checkpoint`
    pub fn collapse(&self, outcome: PvmOutcome, gas_remaining: i64) -> CollapseResult {
        match outcome {
            // ── o ∈ {∞, ♯}: revert to checkpoint (y) ────────────
            PvmOutcome::OutOfGas | PvmOutcome::Panic => {
                if let Some(ref cp) = self.checkpoint {
                    CollapseResult {
                        transfers: cp.transfers.clone(),
                        ejected_services: cp.ejected_services.clone(),
                        created_services: cp.created_services.clone(),
                        upgrades: cp.upgrades.clone(),
                        yield_output: cp.yield_output,
                        provided_preimages: cp.provided_preimages.clone(),
                        gas_remaining,
                        storage: cp.storage.clone(),
                        lookup: cp.lookup.clone(),
                        empower: cp.empower.clone(),
                    }
                } else {
                    // No checkpoint taken → empty side-effects
                    CollapseResult {
                        gas_remaining,
                        ..Default::default()
                    }
                }
            }

            // ── o ∈ ℍ: regular state, yield = hash ──────────────
            PvmOutcome::HaltWithYield(hash) => {
                CollapseResult {
                    transfers: self.transfers.clone(),
                    ejected_services: self.ejected_services.clone(),
                    created_services: self.created_services.clone(),
                    upgrades: self.upgrades.clone(),
                    yield_output: Some(hash),
                    provided_preimages: self.provided_preimages.clone(),
                    gas_remaining,
                    storage: self.storage.clone(),
                    lookup: self.lookup.clone(),
                    empower: self.empower.clone(),
                }
            }

            // ── otherwise: regular state as-is ──────────────────
            PvmOutcome::Halt => {
                CollapseResult {
                    transfers: self.transfers.clone(),
                    ejected_services: self.ejected_services.clone(),
                    created_services: self.created_services.clone(),
                    upgrades: self.upgrades.clone(),
                    yield_output: self.yield_output,
                    provided_preimages: self.provided_preimages.clone(),
                    gas_remaining,
                    storage: self.storage.clone(),
                    lookup: self.lookup.clone(),
                    empower: self.empower.clone(),
                }
            }
        }
    }
}

// ============================================================================
// B.10 — Deterministic next_service_id
// B.14 — check() collision avoidance
// ============================================================================

/// Minimum public service index (GP I.4.4): S = 2^16 = 65536.
const SERVICE_INDEX_MIN: u32 = 1 << 16;

/// Modulus for service ID space: 2³² − S − 2⁸ = 4294901504.
const SERVICE_ID_MODULUS: u32 = u32::MAX - SERVICE_INDEX_MIN - 255;

/// Compute the raw (unchecked) deterministic service ID per GP B.10.
///
/// ```text
/// i = E₄⁻¹(H(E(s, η'₀, H_T))) mod (2³² − S − 2⁸) + S
/// ```
///
/// This returns the hash-derived candidate before collision checking.
/// Call [`check_service_id`] on the result to skip already-used IDs.
fn raw_next_service_id(
    service_id: u32,
    entropy_0: &[u8; 32],
    header_hash: &[u8; 32],
) -> u32 {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    // E(s, η'₀, H_T) = LE32(s) ++ η'₀ ++ H_T  (4 + 32 + 32 = 68 bytes)
    let mut preimage = Vec::with_capacity(68);
    preimage.extend_from_slice(&service_id.to_le_bytes());
    preimage.extend_from_slice(entropy_0);
    preimage.extend_from_slice(header_hash);

    // H(...) = blake2b-256
    let hash = <Blake2b<U32> as Digest>::digest(&preimage);

    // E₄⁻¹(...) = first 4 bytes as u32 little-endian
    let raw = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);

    (raw % SERVICE_ID_MODULUS) + SERVICE_INDEX_MIN
}

/// GP B.14 — find the first unused service ID starting from `candidate`.
///
/// ```text
/// check(i) = i                                              if i ∉ K(e_d)
///            check((i − S + 1) mod (2³² − 2⁸ − S) + S)    otherwise
/// ```
///
/// Walks the ID ring [S, 2³² − 2⁸ − 1] until it finds an ID not in
/// `existing`. Also skips IDs in `created` (services created in the
/// current accumulation, not yet in δ).
///
/// # Panics
/// Panics if the entire ID space is exhausted (impossibly unlikely with
/// 2³² − S − 2⁸ ≈ 4.3 billion slots).
pub fn check_service_id(
    candidate: u32,
    existing: &HashSet<u32>,
    created: &[(u32, [u8; 32])],
) -> u32 {
    let mut i = candidate;
    let max_iters = SERVICE_ID_MODULUS; // worst case: full ring scan
    for _ in 0..max_iters {
        // B.14: i ∉ K(e_d)
        let used = existing.contains(&i)
            || created.iter().any(|(sid, _)| *sid == i);
        if !used {
            return i;
        }
        // B.14: (i − S + 1) mod (2³² − 2⁸ − S) + S
        i = ((i - SERVICE_INDEX_MIN) + 1) % SERVICE_ID_MODULUS + SERVICE_INDEX_MIN;
    }
    panic!("check_service_id: entire ID space exhausted");
}

/// Compute the deterministic initial `next_service_id` per GP B.10 + B.14.
///
/// Combines the hash-derived candidate (B.10) with collision checking (B.14).
/// Used **once** before accumulation starts to seed `x_i`.
pub fn compute_next_service_id(
    service_id: u32,
    entropy_0: &[u8; 32],
    header_hash: &[u8; 32],
    existing: &HashSet<u32>,
    created: &[(u32, [u8; 32])],
) -> u32 {
    let candidate = raw_next_service_id(service_id, entropy_0, header_hash);
    check_service_id(candidate, existing, created)
}

/// Advance `next_service_id` after a non-privileged creation (GP Ω_N).
///
/// ```text
/// i* = check(S + (x_i − S + 42) mod (2³² − S − 2⁸))
/// ```
///
/// This is a simple `+42` modular step through the public ID ring,
/// followed by collision checking.  It is NOT the hash-based formula
/// used for the initial seed — that is [`compute_next_service_id`].
pub fn advance_service_id(
    current: u32,
    existing: &HashSet<u32>,
    created: &[(u32, [u8; 32])],
) -> u32 {
    let candidate = SERVICE_INDEX_MIN
        + ((current.wrapping_sub(SERVICE_INDEX_MIN).wrapping_add(42)) % SERVICE_ID_MODULUS);
    check_service_id(candidate, existing, created)
}

// ============================================================================
// Opaque handles for FFI
// ============================================================================

// ============================================================================
// Tests — extracted to pvm/tests/test_context.rs
// ============================================================================

#[cfg(test)]
#[path = "tests/test_context.rs"]
mod tests;

/// Opaque handle to a JAM-enabled pre-instance (with host function support)
pub struct JamInstancePre {
    pub(crate) instance_pre: polkavm::InstancePre<JamHostContext, JamHostError>,
}

/// Opaque handle to a JAM-enabled instance (with host function support)
pub struct JamInstance {
    pub(crate) instance: polkavm::Instance<JamHostContext, JamHostError>,
    pub(crate) context: JamHostContext,
}
