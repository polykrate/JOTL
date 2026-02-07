//! PolkaVM FFI for JAM PVM (GP Section 14)
//!
//! Provides C-compatible functions for executing RISC-V programs in PolkaVM.
//! Used for work package refinement and accumulation in JAM.
//!
//! Host Functions (GP Section 14.5):
//! - read/write: Storage access
//! - lookup: Preimage lookup  
//! - transfer: Token transfer
//! - log: Journalisation (gas = 0)
//!
//! ## Defensive Coding (FRAME-style)
//! - No unwrap() or expect() in production paths
//! - All errors logged with context
//! - Saturating arithmetic to prevent overflow
//! - Explicit handling of all edge cases

use polkavm::{Config, Engine, Module, ModuleConfig, Instance, InstancePre, Linker, ProgramBlob, Caller};
use std::ffi::c_char;
use std::collections::HashMap;

// JAM codec (NOT SCALE!) for JAM types
// Removed: was SCALE, now using jam-codec via jam_types
use jam_types::{AccumulateItem, WorkItemRecord, WorkPackageHash, SegmentTreeRoot, 
                AuthorizerHash, PayloadHash, WorkOutput, AuthTrace, Encode};
// Removed: was SCALE

// ============================================================================
// Defensive Coding Macros (FRAME-style)
// ============================================================================

/// Log and return error code on condition failure
macro_rules! ensure_or_return {
    ($cond:expr, $code:expr, $($arg:tt)*) => {
        if !($cond) {
            log::warn!($($arg)*);
            return $code;
        }
    };
}

/// Try operation, log error and return code on failure
macro_rules! try_or_return {
    ($expr:expr, $code:expr, $($arg:tt)*) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                log::warn!($($arg)*, e);
                return $code;
            }
        }
    };
}

/// Safe memory read with logging
macro_rules! read_guest_memory {
    ($inst:expr, $addr:expr, $len:expr) => {{
        match $inst.read_memory($addr, $len) {
            Ok(data) => Some(data),
            Err(e) => {
                log::debug!("Guest memory read failed at 0x{:x} len {}: {:?}", $addr, $len, e);
                None
            }
        }
    }};
}

/// Safe memory write with logging  
macro_rules! write_guest_memory {
    ($inst:expr, $addr:expr, $data:expr) => {{
        match $inst.write_memory($addr, $data) {
            Ok(_) => true,
            Err(e) => {
                log::debug!("Guest memory write failed at 0x{:x}: {:?}", $addr, e);
                false
            }
        }
    }};
}

// Use jam-program-blob-common for parsing JAM blobs
use jam_program_blob_common::ProgramBlob as JamProgramBlob;

// JAM types and codec for protocol parameters
use jam_types::ProtocolParameters;

// ============================================================================
// SPI (Standard Program Image) Decoder - GP Section 14
// ============================================================================

/// JAM memory layout constants (GP Section 14)
mod jam_memory {
    pub const PAGE_SIZE: u32 = 4096;
    pub const SEGMENT_SIZE: u32 = 0x10000; // 64KB
    pub const STACK_SEGMENT: u32 = 0xFFFF0000;
    pub const ARGS_SEGMENT: u32 = 0xFFFE0000;
    pub const LAST_PAGE: u32 = 0xFFFFFFFF;
    
    /// Align value to page boundary
    pub fn align_to_page(size: u32) -> u32 {
        (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }
    
    /// Align value to segment boundary
    pub fn align_to_segment(size: u32) -> u32 {
        (size + SEGMENT_SIZE - 1) & !(SEGMENT_SIZE - 1)
    }
}

/// Decoded SPI (Standard Program Image)
/// Format: E_3(|o|) ++ E_3(|w|) ++ E_2(z) ++ E_3(s) ++ o ++ w ++ E_4(|c|) ++ c
pub struct SpiProgram {
    pub ro_data: Vec<u8>,
    pub rw_data: Vec<u8>,
    pub heap_padding_pages: u16,
    pub stack_size: u32,
    pub code: Vec<u8>,
}


impl SpiProgram {
    /// Decode SPI format from raw bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 11 {
            return None;
        }
        
        let mut pos = 0;
        
        // Read header
        let ro_data_len = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], 0]) as usize;
        pos += 3;
        
        let rw_data_len = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], 0]) as usize;
        pos += 3;
        
        let heap_padding_pages = u16::from_le_bytes([data[pos], data[pos+1]]);
        pos += 2;
        
        let stack_size = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], 0]);
        pos += 3;
        
        // Read data sections
        if data.len() < pos + ro_data_len + rw_data_len + 4 {
            return None;
        }
        
        let ro_data = data[pos..pos + ro_data_len].to_vec();
        pos += ro_data_len;
        
        let rw_data = data[pos..pos + rw_data_len].to_vec();
        pos += rw_data_len;
        
        // Read code
        if data.len() < pos + 4 {
            return None;
        }
        
        let code_len = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        pos += 4;
        
        if data.len() < pos + code_len {
            return None;
        }
        
        let code = data[pos..pos + code_len].to_vec();
        
        Some(SpiProgram {
            ro_data,
            rw_data,
            heap_padding_pages,
            stack_size,
            code,
        })
    }
    
    /// Calculate memory regions for JAM execution
    pub fn memory_layout(&self) -> SpiMemoryLayout {
        use jam_memory::*;
        
        let ro_start = SEGMENT_SIZE;
        let ro_end = ro_start + align_to_page(self.ro_data.len() as u32);
        
        let heap_start = 2 * SEGMENT_SIZE + align_to_segment(self.ro_data.len() as u32);
        let heap_data_end = heap_start + align_to_page(self.rw_data.len() as u32);
        let heap_end = heap_data_end + (self.heap_padding_pages as u32) * PAGE_SIZE;
        
        let stack_start = STACK_SEGMENT - align_to_page(self.stack_size);
        let stack_end = STACK_SEGMENT;
        
        SpiMemoryLayout {
            ro_start,
            ro_end,
            heap_start,
            heap_data_end,
            heap_end,
            stack_start,
            stack_end,
        }
    }
}

/// Memory layout calculated from SPI
pub struct SpiMemoryLayout {
    pub ro_start: u32,
    pub ro_end: u32,
    pub heap_start: u32,
    pub heap_data_end: u32,
    pub heap_end: u32,
    pub stack_start: u32,
    pub stack_end: u32,
}

/// Extract metadata and SPI code from a full JAM blob
/// JAM blob = compact(metadata_len) + metadata + SPI
pub fn extract_spi_from_jam_blob(blob: &[u8]) -> Option<(Vec<u8>, SpiProgram)> {
    if blob.is_empty() {
        return None;
    }
    
    // Read JAM compact encoded metadata length
    let (metadata_len, pos) = read_jam_compact(blob)?;
    
    if blob.len() < pos + metadata_len as usize {
        return None;
    }
    
    let metadata = blob[pos..pos + metadata_len as usize].to_vec();
    let spi_bytes = &blob[pos + metadata_len as usize..];
    
    let spi = SpiProgram::decode(spi_bytes)?;
    
    Some((metadata, spi))
}

/// Read JAM compact encoded u32
/// Different from SCALE: uses leading 1-bits to indicate extra bytes
fn read_jam_compact(bytes: &[u8]) -> Option<(u32, usize)> {
    if bytes.is_empty() {
        return None;
    }
    
    let first = bytes[0];
    
    match first {
        0 => Some((0, 1)),
        0xff => {
            if bytes.len() < 9 {
                return None;
            }
            let value = u64::from_le_bytes([
                bytes[1], bytes[2], bytes[3], bytes[4],
                bytes[5], bytes[6], bytes[7], bytes[8]
            ]);
            Some((value as u32, 9))
        }
        b => {
            // Find number of leading 1 bits
            let leading_ones = (0..8).find(|&i| (b & (0x80 >> i)) == 0).unwrap_or(8);
            
            if leading_ones == 0 {
                // No extra bytes, value in bits 0-6
                Some(((b & 0x7f) as u32, 1))
            } else {
                // leading_ones extra bytes follow
                if bytes.len() < 1 + leading_ones {
                    return None;
                }
                let mut buf = [0u8; 8];
                buf[..leading_ones].copy_from_slice(&bytes[1..1 + leading_ones]);
                
                let rem = (b & ((1 << (7 - leading_ones)) - 1)) as u64;
                let value = u64::from_le_bytes(buf) + (rem << (8 * leading_ones));
                Some((value as u32, 1 + leading_ones))
            }
        }
    }
}

// ============================================================================
// GP Constants Encoding (GP Appendix)
// ============================================================================

/// Encode ProtocolParameters as GP constants for fetch(kind=0)
/// 
/// Format (136 bytes total):
/// B_I: u64, B_L: u64, B_S: u64, C: u16, D: u32, E: u32,
/// G_A: u64, G_I: u64, G_R: u64, G_T: u64,
/// H: u16, I: u16, J: u16, K: u16, L: u32, N: u16, O: u16,
/// P: u16, Q: u16, R: u16, T: u16, U: u16, V: u16,
/// W_A: u32, W_B: u32, W_C: u32, W_E: u32, W_M: u32, W_P: u32, W_R: u32, W_T: u32, W_X: u32,
/// Y: u32
fn encode_gp_constants(params: &ProtocolParameters) -> Vec<u8> {
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
// JAM Host Context (GP Section 14.5)
// ============================================================================

/// FetchKind values from jam-types (GP Section 14.5.1)
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
            0 => Ok(FetchKind::ProtocolParameters),
            1 => Ok(FetchKind::Entropy),
            2 => Ok(FetchKind::AuthTrace),
            3 => Ok(FetchKind::AnyExtrinsic),
            4 => Ok(FetchKind::OurExtrinsic),
            5 => Ok(FetchKind::AnyImport),
            6 => Ok(FetchKind::OurImport),
            7 => Ok(FetchKind::WorkPackage),
            8 => Ok(FetchKind::Authorizer),
            9 => Ok(FetchKind::AuthToken),
            10 => Ok(FetchKind::RefineContext),
            11 => Ok(FetchKind::ItemsSummary),
            12 => Ok(FetchKind::AnyItemSummary),
            13 => Ok(FetchKind::AnyPayload),
            14 => Ok(FetchKind::AccumulateItems),
            15 => Ok(FetchKind::AnyAccumulateItem),
            _ => Err(()),
        }
    }
}

/// Host context for JAM service execution
/// Contains storage, preimages, and service state
#[derive(Default)]
pub struct JamHostContext {
    /// Service ID being executed
    pub service_id: u32,
    /// Service storage (key -> value)
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
    /// Preimages (hash -> blob)
    pub preimages: HashMap<[u8; 32], Vec<u8>>,
    /// Service balance
    pub balance: u64,
    /// Accumulated log output
    pub logs: Vec<Vec<u8>>,
    /// Transfers made during execution
    pub transfers: Vec<JamTransfer>,
    /// Services ejected during execution (GP 14.5.10)
    /// Each entry is (target_service_id, ejector_service_id)
    pub ejected_services: Vec<(u32, u32)>,
    /// Yield output hash (GP 14.5.11 - yield_hash host call)
    /// This is the actual output for θ calculation, not logs
    pub yield_output: Option<[u8; 32]>,
    /// Current slot
    pub slot: u32,
    /// Next service ID for new() host call
    pub next_service_id: u32,
    /// Services created during execution (GP 14.5.8 - new host call)
    /// Each entry is (new_service_id, code_hash)
    pub created_services: Vec<(u32, [u8; 32])>,
    /// Code upgrades during execution (GP 14.5.9 - upgrade host call)  
    /// Each entry is (service_id, new_code_hash)
    pub upgrades: Vec<(u32, [u8; 32])>,
    /// Error code if any
    pub error: Option<JamHostError>,
    
    // === Data for fetch() host call ===
    
    /// Raw entropy bytes (32 for accumulate, 128 for full pool)
    pub entropy_raw: Vec<u8>,
    
    /// Entropy pool (4 × 32 bytes = 128 bytes)
    /// Used by fetch(kind=1)
    pub entropy: [[u8; 32]; 4],
    
    /// Accumulate items (encoded work results)
    /// Used by fetch(kind=14) and fetch(kind=15, index)
    pub accumulate_items: Vec<Vec<u8>>,
    
    /// Work package (encoded)
    /// Used by fetch(kind=7)
    pub work_package: Vec<u8>,
    
    /// Protocol parameters (encoded)
    /// Used by fetch(kind=0)
    pub protocol_params: Vec<u8>,
}

/// A token transfer record
#[derive(Clone, Debug)]
pub struct JamTransfer {
    pub to_service: u32,
    pub amount: u64,
    pub memo: Vec<u8>,
}

/// Host function error codes (GP Section 14.5)
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum JamHostError {
    None = 0,
    OutOfBounds = 1,
    UnknownService = 2,
    StorageFull = 3,
    BadCore = 4,
    NoCash = 5,
    GasLimitTooLow = 6,
    ActionInvalid = 7,
}

// ============================================================================
// Opaque handles for FFI
// ============================================================================

/// Opaque handle to a PVM Engine
pub struct PvmEngine {
    engine: Engine,
}

/// Opaque handle to a PVM Module (compiled program)
pub struct PvmModule {
    module: Module,
}

/// Opaque handle to a pre-instantiated module (basic, no host functions)
pub struct PvmInstancePre {
    instance_pre: InstancePre<()>,
}

/// Opaque handle to a PVM Instance (basic, no host functions)
pub struct PvmInstance {
    instance: Instance<()>,
}

/// Opaque handle to a JAM-enabled pre-instance (with host functions)
pub struct JamInstancePre {
    instance_pre: InstancePre<JamHostContext, JamHostError>,
}

/// Opaque handle to a JAM-enabled instance (with host functions)
pub struct JamInstance {
    instance: Instance<JamHostContext, JamHostError>,
    /// User context (storage, preimages, etc.)
    context: JamHostContext,
}

// Note: Global engine removed - callers should manage their own engines

// ============================================================================
// SCALE Compact Encoding Helpers
// ============================================================================

/// Encode a u32 value in SCALE compact format
/// Used for GP invocation arguments E(τ, s, |o|)
fn encode_compact_u32(buf: &mut Vec<u8>, value: u32) {
    if value < 64 {
        // Single byte mode: value << 2
        buf.push((value << 2) as u8);
    } else if value < 16384 {
        // Two byte mode: value << 2 | 0b01
        buf.push(((value << 2) | 0b01) as u8);
        buf.push((value >> 6) as u8);
    } else if value < 1073741824 {
        // Four byte mode: value << 2 | 0b10
        buf.push(((value << 2) | 0b10) as u8);
        buf.push((value >> 6) as u8);
        buf.push((value >> 14) as u8);
        buf.push((value >> 22) as u8);
    } else {
        // Big integer mode: 0b11 + 4 bytes LE
        buf.push(0b11);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

// ============================================================================
// Engine Management
// ============================================================================

/// Create a new PVM engine with default configuration
///
/// Returns: pointer to engine, or null on failure
#[no_mangle]
pub extern "C" fn pvm_engine_new() -> *mut PvmEngine {
    let config = Config::from_env().unwrap_or_default();
    
    match Engine::new(&config) {
        Ok(engine) => {
            let boxed = Box::new(PvmEngine { engine });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("pvm_engine_new failed: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Create a new PVM engine configured for JAM
///
/// Returns: pointer to engine, or null on failure
#[no_mangle]
pub extern "C" fn pvm_engine_new_jam() -> *mut PvmEngine {
    let mut config = Config::from_env().unwrap_or_default();
    
    // JAM-specific configuration
    // Use interpreter backend for maximum compatibility
    config.set_backend(Some(polkavm::BackendKind::Interpreter));
    
    match Engine::new(&config) {
        Ok(engine) => {
            let boxed = Box::new(PvmEngine { engine });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("pvm_engine_new_jam failed: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a PVM engine
///
/// # Safety
/// - `engine` must be a valid pointer from `pvm_engine_new`
#[no_mangle]
pub unsafe extern "C" fn pvm_engine_free(engine: *mut PvmEngine) {
    if !engine.is_null() {
        drop(Box::from_raw(engine));
    }
}

// ============================================================================
// Module Management
// ============================================================================

/// Load a PVM module from a raw .polkavm blob (PVM\0 magic)
///
/// # Safety
/// - `engine` must be a valid engine pointer
/// - `blob` must point to `blob_len` valid bytes
///
/// # Returns
/// Pointer to module, or null on failure
#[no_mangle]
pub unsafe extern "C" fn pvm_module_load(
    engine: *mut PvmEngine,
    blob: *const u8,
    blob_len: usize,
) -> *mut PvmModule {
    if engine.is_null() || blob.is_null() {
        return std::ptr::null_mut();
    }
    
    let engine = &(*engine).engine;
    let blob_bytes = std::slice::from_raw_parts(blob, blob_len);
    
    // Parse the program blob
    let program_blob = match ProgramBlob::parse(blob_bytes.into()) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("pvm_module_load: failed to parse blob: {:?}", e);
            return std::ptr::null_mut();
        }
    };
    
    // Configure module
    let module_config = ModuleConfig::default();
    
    // Compile/load module
    match Module::from_blob(engine, &module_config, program_blob) {
        Ok(module) => {
            let boxed = Box::new(PvmModule { module });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("pvm_module_load: failed to create module: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Load a PVM module from a JAM service blob (jam-pvm-build format)
///
/// JAM blobs have a structure with:
/// - metadata (JAM compact length + encoded)
/// - ro_data, rw_data sections
/// - the actual PolkaVM code blob
///
/// # Safety
/// - `engine` must be a valid engine pointer
/// - `blob` must point to `blob_len` valid bytes
///
/// # Returns
/// Pointer to module, or null on failure
#[no_mangle]
pub unsafe extern "C" fn pvm_module_load_jam(
    engine: *mut PvmEngine,
    blob: *const u8,
    blob_len: usize,
) -> *mut PvmModule {
    if engine.is_null() || blob.is_null() {
        return std::ptr::null_mut();
    }
    
    let engine = &(*engine).engine;
    let blob_bytes = std::slice::from_raw_parts(blob, blob_len);
    
    // Parse the JAM program blob format using jam-program-blob-common
    let jam_blob = match JamProgramBlob::from_bytes(blob_bytes) {
        Some(b) => b,
        None => {
            log::debug!("pvm_module_load_jam: failed to parse JAM blob format");
            return std::ptr::null_mut();
        }
    };
    
    // Convert to PolkaVM ProgramParts
    let parts: polkavm::ProgramParts = jam_blob.into();
    
    // Create ProgramBlob from parts
    // Note: JAM blobs don't include exports, they use dispatch table indices
    let program_blob = match ProgramBlob::from_parts(parts) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("pvm_module_load_jam: failed to create program blob from parts: {:?}", e);
            return std::ptr::null_mut();
        }
    };
    
    // Configure module with gas metering  
    let mut module_config = ModuleConfig::new();
    module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    
    // Compile/load module
    match Module::from_blob(engine, &module_config, program_blob) {
        Ok(module) => {
            let boxed = Box::new(PvmModule { module });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("pvm_module_load_jam: failed to create module: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a PVM module
///
/// # Safety
/// - `module` must be a valid pointer from `pvm_module_load`
#[no_mangle]
pub unsafe extern "C" fn pvm_module_free(module: *mut PvmModule) {
    if !module.is_null() {
        drop(Box::from_raw(module));
    }
}

// ============================================================================
// Instance Management
// ============================================================================

/// Create a pre-instantiated module (for repeated instantiation)
///
/// # Safety
/// - `module` must be a valid module pointer
///
/// # Returns
/// Pointer to pre-instance, or null on failure
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_pre_new(
    module: *mut PvmModule,
) -> *mut PvmInstancePre {
    if module.is_null() {
        return std::ptr::null_mut();
    }
    
    let module = &(*module).module;
    
    // Create linker (no host functions for basic test)
    let linker = Linker::<()>::new();
    
    // Create pre-instance
    match linker.instantiate_pre(module) {
        Ok(instance_pre) => {
            let boxed = Box::new(PvmInstancePre { instance_pre });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("pvm_instance_pre_new: failed: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a pre-instance
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_pre_free(pre: *mut PvmInstancePre) {
    if !pre.is_null() {
        drop(Box::from_raw(pre));
    }
}

/// Create a new PVM instance from a pre-instance
///
/// # Safety
/// - `pre` must be a valid pre-instance pointer
///
/// # Returns
/// Pointer to instance, or null on failure
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_new(
    pre: *mut PvmInstancePre,
) -> *mut PvmInstance {
    if pre.is_null() {
        return std::ptr::null_mut();
    }
    
    let pre = &(*pre).instance_pre;
    
    // Instantiate with empty state
    match pre.instantiate() {
        Ok(instance) => {
            let boxed = Box::new(PvmInstance { instance });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("pvm_instance_new: failed to instantiate: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a PVM instance
///
/// # Safety
/// - `instance` must be a valid pointer from `pvm_instance_new`
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_free(instance: *mut PvmInstance) {
    if !instance.is_null() {
        drop(Box::from_raw(instance));
    }
}

// ============================================================================
// Execution
// ============================================================================

/// Call the entry point of a program
///
/// PolkaVM uses a single entry point model. The program is executed from
/// its entry point until it returns or traps.
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `result` must point to a valid u64
///
/// # Returns
/// - 0 on success (result contains return value)
/// - Non-zero error code on failure
#[no_mangle]
pub unsafe extern "C" fn pvm_run(
    instance: *mut PvmInstance,
    result: *mut u64,
) -> u32 {
    if instance.is_null() || result.is_null() {
        return 1; // Null pointer error
    }
    
    let instance = &mut (*instance).instance;
    
    // Run the program
    match instance.run() {
        Ok(interrupt) => {
            // Get return value from register a0 (x10)
            *result = instance.reg(polkavm::Reg::A0);
            match interrupt {
                polkavm::InterruptKind::Finished => 0, // Success
                polkavm::InterruptKind::Trap => 5,     // Trap
                polkavm::InterruptKind::Ecalli(_) => 6, // Host call
                _ => 7, // Other interrupt
            }
        }
        Err(e) => {
            log::debug!("pvm_run: execution failed: {:?}", e);
            4 // Execution error
        }
    }
}

/// Set an argument register before running
///
/// # Safety
/// - `instance` must be a valid instance pointer
#[no_mangle]
pub unsafe extern "C" fn pvm_set_reg(
    instance: *mut PvmInstance,
    reg: u32,
    value: u64,
) {
    if instance.is_null() {
        return;
    }
    
    let instance = &mut (*instance).instance;
    
    // Map register number to polkavm Reg enum
    let reg = match reg {
        0 => polkavm::Reg::RA,
        1 => polkavm::Reg::SP,
        2 => polkavm::Reg::T0,
        3 => polkavm::Reg::T1,
        4 => polkavm::Reg::T2,
        5 => polkavm::Reg::S0,
        6 => polkavm::Reg::S1,
        7 => polkavm::Reg::A0,
        8 => polkavm::Reg::A1,
        9 => polkavm::Reg::A2,
        10 => polkavm::Reg::A3,
        11 => polkavm::Reg::A4,
        12 => polkavm::Reg::A5,
        _ => return,
    };
    
    instance.set_reg(reg, value);
}

/// Get a register value
#[no_mangle]
pub unsafe extern "C" fn pvm_get_reg(
    instance: *mut PvmInstance,
    reg: u32,
) -> u64 {
    if instance.is_null() {
        return 0;
    }
    
    let instance = &(*instance).instance;
    
    let reg = match reg {
        0 => polkavm::Reg::RA,
        1 => polkavm::Reg::SP,
        2 => polkavm::Reg::T0,
        3 => polkavm::Reg::T1,
        4 => polkavm::Reg::T2,
        5 => polkavm::Reg::S0,
        6 => polkavm::Reg::S1,
        7 => polkavm::Reg::A0,
        8 => polkavm::Reg::A1,
        9 => polkavm::Reg::A2,
        10 => polkavm::Reg::A3,
        11 => polkavm::Reg::A4,
        12 => polkavm::Reg::A5,
        _ => return 0,
    };
    
    instance.reg(reg)
}

// ============================================================================
// Memory Access
// ============================================================================

/// Read memory from a PVM instance
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `output` must point to `len` writable bytes
///
/// # Returns
/// - 0 on success, non-zero on failure
#[no_mangle]
pub unsafe extern "C" fn pvm_memory_read(
    instance: *mut PvmInstance,
    address: u32,
    output: *mut u8,
    len: usize,
) -> u32 {
    if instance.is_null() || output.is_null() {
        return 1;
    }
    
    let instance = &(*instance).instance;
    let output_slice = std::slice::from_raw_parts_mut(output, len);
    
    match instance.read_memory_into(address, output_slice) {
        Ok(_) => 0,
        Err(e) => {
            log::debug!("pvm_memory_read: failed: {:?}", e);
            2
        }
    }
}

/// Write memory to a PVM instance
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `data` must point to `len` valid bytes
///
/// # Returns
/// - 0 on success, non-zero on failure
#[no_mangle]
pub unsafe extern "C" fn pvm_memory_write(
    instance: *mut PvmInstance,
    address: u32,
    data: *const u8,
    len: usize,
) -> u32 {
    if instance.is_null() || data.is_null() {
        return 1;
    }
    
    let instance = &mut (*instance).instance;
    let data_slice = std::slice::from_raw_parts(data, len);
    
    match instance.write_memory(address, data_slice) {
        Ok(()) => 0,
        Err(e) => {
            log::debug!("pvm_memory_write: failed: {:?}", e);
            2
        }
    }
}

// ============================================================================
// Gas Metering (JAM-specific)
// ============================================================================

/// Set gas limit for execution
///
/// # Safety
/// - `instance` must be a valid instance pointer
#[no_mangle]
pub unsafe extern "C" fn pvm_set_gas(instance: *mut PvmInstance, gas: i64) {
    if instance.is_null() {
        return;
    }
    
    let instance = &mut (*instance).instance;
    instance.set_gas(gas);
}

/// Get remaining gas
///
/// # Safety
/// - `instance` must be a valid instance pointer
#[no_mangle]
pub unsafe extern "C" fn pvm_get_gas(instance: *mut PvmInstance) -> i64 {
    if instance.is_null() {
        return 0;
    }
    
    let instance = &(*instance).instance;
    instance.gas()
}

// ============================================================================
// Utility
// ============================================================================

/// Get the last error message (for debugging)
///
/// Returns a static string, do not free.
#[no_mangle]
pub extern "C" fn pvm_version() -> *const c_char {
    static VERSION: &[u8] = b"polkavm-0.30\0";
    VERSION.as_ptr() as *const c_char
}

// ============================================================================
// JAM Host Functions (GP Section 14.5)
// ============================================================================

/// JAM Host Function IDs (GP Section 14.5)
/// These are the ecalli numbers used by JAM programs
#[repr(u32)]
pub enum JamHostCall {
    /// Read from storage
    Read = 0,
    /// Write to storage
    Write = 1,
    /// Lookup preimage
    Lookup = 2,
    /// Get gas remaining
    Gas = 10,
    /// Get service info
    Info = 11,
    /// Transfer tokens
    Transfer = 12,
    /// Log output (gas = 0)
    Log = 18,
}

/// Handle a JAM host call (ecalli)
/// 
/// This is called when the PVM encounters an ecalli instruction.
/// Arguments are passed via registers A0-A5, result returned in A0.
/// 
/// **GP Appendix B**: All host calls cost 10 gas (g = 10)
fn handle_jam_hostcall(
    caller: &mut Caller<JamHostContext>,
    hostcall_id: u32,
) -> Result<(), JamHostError> {
    use polkavm::Reg;
    
    // GP Appendix B: All host calls cost 10 gas (g = 10)
    // Subtract gas BEFORE executing the host call
    // PolkaVM will handle out-of-gas condition naturally
    let current_gas = caller.instance.gas();
    caller.instance.set_gas(current_gas.saturating_sub(10));
    
    match hostcall_id {
        // read(key_ptr, key_len, value_ptr, value_capacity) -> value_len
        0 => {
            let key_ptr = caller.instance.reg(Reg::A0) as u32;
            let key_len = caller.instance.reg(Reg::A1) as u32;
            let value_ptr = caller.instance.reg(Reg::A2) as u32;
            let value_capacity = caller.instance.reg(Reg::A3) as u32;
            
            // Read key from guest memory
            let key = caller.instance.read_memory(key_ptr, key_len)
                .map_err(|_| JamHostError::OutOfBounds)?;
            
            // Lookup in storage
            let result = if let Some(value) = caller.user_data.storage.get(&key) {
                let copy_len = std::cmp::min(value.len(), value_capacity as usize);
                caller.instance.write_memory(value_ptr, &value[..copy_len])
                    .map_err(|_| JamHostError::OutOfBounds)?;
                value.len() as u64
            } else {
                0 // Not found
            };
            
            caller.instance.set_reg(Reg::A0, result);
            Ok(())
        }
        
        // write(key_ptr, key_len, value_ptr, value_len) -> 0 on success
        1 => {
            let key_ptr = caller.instance.reg(Reg::A0) as u32;
            let key_len = caller.instance.reg(Reg::A1) as u32;
            let value_ptr = caller.instance.reg(Reg::A2) as u32;
            let value_len = caller.instance.reg(Reg::A3) as u32;
            
            // Read key and value from guest memory
            let key = caller.instance.read_memory(key_ptr, key_len)
                .map_err(|_| JamHostError::OutOfBounds)?;
            let value = caller.instance.read_memory(value_ptr, value_len)
                .map_err(|_| JamHostError::OutOfBounds)?;
            
            // Store in storage
            caller.user_data.storage.insert(key, value);
            
            caller.instance.set_reg(Reg::A0, 0);
            Ok(())
        }
        
        // lookup(hash_ptr, value_ptr, value_capacity) -> preimage_len or u32::MAX
        2 => {
            let hash_ptr = caller.instance.reg(Reg::A0) as u32;
            let value_ptr = caller.instance.reg(Reg::A1) as u32;
            let value_capacity = caller.instance.reg(Reg::A2) as u32;
            
            // Read hash from guest memory
            let hash_vec = caller.instance.read_memory(hash_ptr, 32)
                .map_err(|_| JamHostError::OutOfBounds)?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_vec);
            
            // Lookup preimage
            let result = if let Some(preimage) = caller.user_data.preimages.get(&hash) {
                let copy_len = std::cmp::min(preimage.len(), value_capacity as usize);
                caller.instance.write_memory(value_ptr, &preimage[..copy_len])
                    .map_err(|_| JamHostError::OutOfBounds)?;
                preimage.len() as u64
            } else {
                u32::MAX as u64 // Not found
            };
            
            caller.instance.set_reg(Reg::A0, result);
            Ok(())
        }
        
        // gas() -> remaining gas
        10 => {
            let gas = caller.instance.gas();
            caller.instance.set_reg(Reg::A0, gas as u64);
            Ok(())
        }
        
        // transfer(to_service, amount, memo_ptr, memo_len) -> 0 on success
        12 => {
            let to_service = caller.instance.reg(Reg::A0) as u32;
            let amount = caller.instance.reg(Reg::A1);
            let memo_ptr = caller.instance.reg(Reg::A2) as u32;
            let memo_len = caller.instance.reg(Reg::A3) as u32;
            
            // Read memo from guest memory
            let memo = if memo_len > 0 {
                caller.instance.read_memory(memo_ptr, memo_len)
                    .map_err(|_| JamHostError::OutOfBounds)?
            } else {
                Vec::new()
            };
            
            // Check balance
            if caller.user_data.balance < amount {
                caller.instance.set_reg(Reg::A0, JamHostError::NoCash as u64);
                return Ok(());
            }
            
            // Record transfer
            caller.user_data.balance -= amount;
            caller.user_data.transfers.push(JamTransfer {
                to_service,
                amount,
                memo,
            });
            
            caller.instance.set_reg(Reg::A0, 0);
            Ok(())
        }
        
        // log(data_ptr, data_len) -> 0
        18 => {
            let data_ptr = caller.instance.reg(Reg::A0) as u32;
            let data_len = caller.instance.reg(Reg::A1) as u32;
            
            // Read data from guest memory
            let data = caller.instance.read_memory(data_ptr, data_len)
                .map_err(|_| JamHostError::OutOfBounds)?;
            
            // Store log
            caller.user_data.logs.push(data);
            
            caller.instance.set_reg(Reg::A0, 0);
            Ok(())
        }
        
        // Unknown hostcall
        _ => {
            log::debug!("JAM: Unknown hostcall {}", hostcall_id);
            caller.instance.set_reg(Reg::A0, JamHostError::ActionInvalid as u64);
            Ok(())
        }
    }
}

/// Create a JAM-enabled linker with host functions using define_fallback
fn create_jam_linker() -> Linker<JamHostContext, JamHostError> {
    let mut linker = Linker::<JamHostContext, JamHostError>::new();
    
    // Use define_fallback to handle all ecalli instructions
    linker.define_fallback(|mut caller: Caller<JamHostContext>, hostcall_id: u32| {
        handle_jam_hostcall(&mut caller, hostcall_id)
    });
    
    linker
}

// ============================================================================
// JAM Instance Management (with host functions)
// ============================================================================

/// Create a JAM-enabled pre-instance with host functions
///
/// # Safety
/// - `module` must be a valid module pointer
#[no_mangle]
pub unsafe extern "C" fn jam_instance_pre_new(
    module: *mut PvmModule,
) -> *mut JamInstancePre {
    if module.is_null() {
        return std::ptr::null_mut();
    }
    
    let module_ref = &(*module).module;
    
    // Create linker with JAM host functions
    let linker = create_jam_linker();
    
    // Create pre-instance
    match linker.instantiate_pre(module_ref) {
        Ok(instance_pre) => {
            let boxed = Box::new(JamInstancePre { instance_pre });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("jam_instance_pre_new: failed: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a JAM pre-instance
#[no_mangle]
pub unsafe extern "C" fn jam_instance_pre_free(pre: *mut JamInstancePre) {
    if !pre.is_null() {
        drop(Box::from_raw(pre));
    }
}

/// Create a new JAM instance from a pre-instance with initial context
///
/// # Safety
/// - `pre` must be a valid pre-instance pointer
/// - `service_id`: the service being executed
/// - `balance`: initial service balance
/// - `slot`: current slot
#[no_mangle]
pub unsafe extern "C" fn jam_instance_new(
    pre: *mut JamInstancePre,
    service_id: u32,
    balance: u64,
    slot: u32,
) -> *mut JamInstance {
    if pre.is_null() {
        return std::ptr::null_mut();
    }
    
    let pre_ref = &(*pre).instance_pre;
    
    // Generate default protocol parameters (TINY chainspec)
    let params = ProtocolParameters::tiny();
    let encoded_params = encode_gp_constants(&params);
    
    // Create context with default protocol parameters
    let context = JamHostContext {
        service_id,
        balance,
        slot,
        protocol_params: encoded_params,
        ..Default::default()
    };
    
    // Instantiate
    match pre_ref.instantiate() {
        Ok(instance) => {
            let boxed = Box::new(JamInstance { instance, context });
            Box::into_raw(boxed)
        }
        Err(e) => {
            log::debug!("jam_instance_new: failed to instantiate: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a JAM instance
#[no_mangle]
pub unsafe extern "C" fn jam_instance_free(instance: *mut JamInstance) {
    if !instance.is_null() {
        drop(Box::from_raw(instance));
    }
}

/// Add a storage entry to a JAM instance
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `key` and `value` must point to valid memory
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
    
    let jam_instance = &mut (*instance);
    let key_slice = std::slice::from_raw_parts(key, key_len);
    let value_slice = std::slice::from_raw_parts(value, value_len);
    
    jam_instance.context.storage.insert(key_slice.to_vec(), value_slice.to_vec());
    0
}

/// Add a preimage to a JAM instance
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `hash` must point to 32 bytes
/// - `blob` must point to `blob_len` bytes
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
    
    let jam_instance = &mut (*instance);
    let hash_slice = std::slice::from_raw_parts(hash, 32);
    let blob_slice = std::slice::from_raw_parts(blob, blob_len);
    
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_slice);
    
    jam_instance.context.preimages.insert(hash_arr, blob_slice.to_vec());
    0
}

/// Set entropy for JAM instance
///
/// Sets entropy used by fetch(kind=Entropy)
/// Can be 32 bytes (η₀' only for accumulate) or 128 bytes (full pool)
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `entropy` must point to `entropy_len` bytes
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_entropy(
    instance: *mut JamInstance,
    entropy: *const u8,
    entropy_len: usize,
) -> u32 {
    if instance.is_null() || entropy.is_null() {
        return 1;
    }
    
    let jam_instance = &mut (*instance);
    let entropy_slice = std::slice::from_raw_parts(entropy, entropy_len);
    
    // Store as raw bytes (32 for accumulate, 128 for full pool)
    jam_instance.context.entropy_raw = entropy_slice.to_vec();
    
    // Also fill the 4×32 array for backward compatibility
    if entropy_len >= 128 {
        for i in 0..4 {
            jam_instance.context.entropy[i].copy_from_slice(&entropy_slice[i*32..(i+1)*32]);
        }
    } else if entropy_len >= 32 {
        jam_instance.context.entropy[0].copy_from_slice(&entropy_slice[0..32]);
    }
    0
}

/// Add an accumulate item to JAM instance
///
/// Adds an encoded accumulate item for fetch(kind=AccumulateItems/AnyAccumulateItem)
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `item` must point to `item_len` bytes
#[no_mangle]
pub unsafe extern "C" fn jam_instance_add_accumulate_item(
    instance: *mut JamInstance,
    item: *const u8,
    item_len: usize,
) -> u32 {
    if instance.is_null() || (item.is_null() && item_len > 0) {
        return 1;
    }
    
    let jam_instance = &mut (*instance);
    let item_slice = if item_len > 0 {
        std::slice::from_raw_parts(item, item_len).to_vec()
    } else {
        Vec::new()
    };
    
    jam_instance.context.accumulate_items.push(item_slice);
    0
}

/// Set work package for JAM instance
///
/// Sets the encoded work package for fetch(kind=WorkPackage)
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `data` must point to `data_len` bytes
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_work_package(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) {
        return 1;
    }
    
    let jam_instance = &mut (*instance);
    jam_instance.context.work_package = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    0
}

/// Set protocol parameters for JAM instance
///
/// Sets the encoded protocol parameters for fetch(kind=ProtocolParameters)
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `data` must point to `data_len` bytes
#[no_mangle]
pub unsafe extern "C" fn jam_instance_set_protocol_params(
    instance: *mut JamInstance,
    data: *const u8,
    data_len: usize,
) -> u32 {
    if instance.is_null() || (data.is_null() && data_len > 0) {
        return 1;
    }
    
    let jam_instance = &mut (*instance);
    jam_instance.context.protocol_params = if data_len > 0 {
        std::slice::from_raw_parts(data, data_len).to_vec()
    } else {
        Vec::new()
    };
    0
}

/// Run a JAM instance from entry point
///
/// Executes the program from the given entry point name.
/// Host functions (ecalli) are handled automatically via the fallback handler.
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `result` must point to a valid u64
/// - `entry_point` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn jam_run(
    instance: *mut JamInstance,
    entry_point: *const c_char,
    result: *mut u64,
) -> u32 {
    use polkavm::Reg;
    
    if instance.is_null() || result.is_null() {
        return 1;
    }
    
    let jam_instance = &mut (*instance);
    
    // Get entry point name
    let entry_name = if entry_point.is_null() {
        "main" // Default entry point
    } else {
        match std::ffi::CStr::from_ptr(entry_point).to_str() {
            Ok(s) => s,
            Err(_) => return 2, // Invalid UTF-8
        }
    };
    
    // JAM services use fixed ProgramCounter offsets instead of named exports:
    // - IS_AUTHORIZED / REFINE = PC(0)
    // - ACCUMULATE = PC(5)  
    // - ON_TRANSFER = PC(10)
    // Reference: typeberry pvm-executor.ts
    
    let pc = match entry_name {
        "is_authorized_ext" | "refine_ext" => 0,
        "accumulate_ext" => 5,
        "on_transfer_ext" => 10,
        _ => {
            // Try named export first
            match jam_instance.instance.call_typed(&mut jam_instance.context, entry_name, ()) {
                Ok(()) => {
                    *result = jam_instance.instance.reg(Reg::A0);
                    return 0;
                }
                Err(polkavm::CallError::Error(e)) if e.to_string().contains("export not found") => {
                    log::debug!("jam_run: unknown entry point '{}', trying PC=0", entry_name);
                    0 // Fallback to PC=0
                }
                Err(e) => {
                    // Return the error
                    match e {
                        polkavm::CallError::Trap => { *result = jam_instance.instance.reg(Reg::A0); return 5; }
                        polkavm::CallError::NotEnoughGas => { *result = 0; return 6; }
                        polkavm::CallError::User(h) => { *result = h as u64; return 7; }
                        polkavm::CallError::Error(err) => { log::debug!("jam_run: {:?}", err); return 4; }
                        polkavm::CallError::Step => { *result = jam_instance.instance.reg(Reg::A0); return 8; }
                    }
                }
            }
        }
    };
    
    log::debug!("jam_run: using PC={} for entry point '{}'", pc, entry_name);
    
    // GP Memory Layout Constants (GP Section 14 / A.39)
    // Note: PolkaVM doesn't automatically map the args segment at 0xFEFF0000
    // We need to use sbrk to allocate memory and write args there
    
    // Prepare accumulate arguments using jam_types::AccumulateParams with jam-codec
    // GP B.10: E(t, s, |o|) where t=timeslot, s=service_id, o=operands
    let args_data: Vec<u8> = if entry_name == "accumulate_ext" {
        use jam_types::AccumulateParams;
        
        let slot = jam_instance.context.slot;
        let service_id = jam_instance.context.service_id;
        let items_count = jam_instance.context.accumulate_items.len() as u32;
        
        // Use jam-codec via jam_types::Encode
        let params = AccumulateParams {
            slot,
            service_id,
            item_count: items_count,
        };
        let args = params.encode();
        
        eprintln!("jam_run: accumulate args: slot={}, service_id={}, items={}, {} bytes, data={:02x?}", 
                   slot, service_id, items_count, args.len(), args);
        args
    } else {
        Vec::new()
    };
    
    // Allocate memory for arguments using sbrk
    // This gives us a valid address in the heap region
    let args_addr: u32 = if !args_data.is_empty() {
        // Align args size to 8 bytes
        let args_size = ((args_data.len() + 7) & !7) as u32;
        
        // Allocate memory with sbrk
        match jam_instance.instance.sbrk(args_size) {
            Ok(Some(heap_top)) => {
                // heap_top is the new heap end, args start at heap_top - args_size
                let args_start = heap_top.saturating_sub(args_size);
                
                // Write arguments to allocated memory
                match jam_instance.instance.write_memory(args_start, &args_data) {
                    Ok(_) => {
                        log::debug!("jam_run: wrote {} bytes args to heap at 0x{:x}", args_data.len(), args_start);
                        args_start
                    }
                    Err(e) => {
                        log::warn!("jam_run: failed to write args to heap: {:?}", e);
                        0
                    }
                }
            }
            Ok(None) => {
                log::warn!("jam_run: sbrk returned None (heap exhausted)");
                0
            }
            Err(e) => {
                log::warn!("jam_run: sbrk failed: {:?}", e);
                0
            }
        }
    } else {
        0
    };
    
    // Execute from fixed PC with arguments passed via ARG registers
    // prepare_call_untyped clears all regs, sets SP/RA, then sets A0..A5 from args
    // GP A.43: A0=args_addr, A1=args_len
    use polkavm::ProgramCounter;
    jam_instance.instance.prepare_call_untyped(
        ProgramCounter(pc), 
        &[args_addr as u64, args_data.len() as u64]
    );
    
    eprintln!("jam_run: prepared call PC={} A0=0x{:x} A1={}", pc, args_addr, args_data.len());
    
    // Debug: Log initial register state
    eprintln!("=== PVM EXECUTION START ===");
    eprintln!("  PC={}, Gas={}", pc, jam_instance.instance.gas());
    eprintln!("  RA=0x{:016x} SP=0x{:016x}", 
              jam_instance.instance.reg(Reg::RA),
              jam_instance.instance.reg(Reg::SP));
    eprintln!("  A0=0x{:016x} A1=0x{:016x} A2=0x{:016x}", 
              jam_instance.instance.reg(Reg::A0),
              jam_instance.instance.reg(Reg::A1),
              jam_instance.instance.reg(Reg::A2));
    
    // Main execution loop - handle host calls until completion
    // Wrap in catch_unwind to handle panics from jam-pvm-common defensively
    use std::panic::{catch_unwind, AssertUnwindSafe};
    
    let mut step_count = 0u64;
    let run_result: Result<(), polkavm::CallError<JamHostError>> = loop {
        step_count += 1;
        
        // Log state on first 10 steps to debug early trap
        if step_count <= 10 {
            let gas_now = jam_instance.instance.gas();
            let pc_now = jam_instance.instance.program_counter().map(|p| p.0).unwrap_or(0);
            eprintln!("[step {:3}] PC={:5} gas={:7} SP=0x{:08x} A0=0x{:08x}", 
                      step_count, pc_now, gas_now,
                      jam_instance.instance.reg(Reg::SP) as u32,
                      jam_instance.instance.reg(Reg::A0) as u32);
        }
        
        // Catch any panics from the PVM execution (e.g., from jam-pvm-common)
        let run_step = catch_unwind(AssertUnwindSafe(|| {
            jam_instance.instance.run()
        }));
        
        let step_result = match run_step {
            Ok(r) => r,
            Err(panic_info) => {
                // Log the panic and return a trap error
                eprintln!("PVM execution panicked at step {}: {:?}", step_count, panic_info);
                // Return trap error - guest code caused a panic
                break Err(polkavm::CallError::Trap);
            }
        };
        
        match step_result {
            Ok(polkavm::InterruptKind::Finished) => {
                eprintln!("=== PVM FINISHED after {} steps ===", step_count);
                break Ok(());
            }
            Ok(polkavm::InterruptKind::Trap) => {
                let pc_now = jam_instance.instance.program_counter().map(|p| p.0).unwrap_or(0);
                let gas_now = jam_instance.instance.gas();
                eprintln!("=== PVM TRAP at step {} ===", step_count);
                eprintln!("  PC={} gas={}", pc_now, gas_now);
                eprintln!("  RA=0x{:016x} SP=0x{:016x}", 
                          jam_instance.instance.reg(Reg::RA),
                          jam_instance.instance.reg(Reg::SP));
                eprintln!("  A0=0x{:016x} A1=0x{:016x} A2=0x{:016x} A3=0x{:016x}", 
                          jam_instance.instance.reg(Reg::A0),
                          jam_instance.instance.reg(Reg::A1),
                          jam_instance.instance.reg(Reg::A2),
                          jam_instance.instance.reg(Reg::A3));
                eprintln!("  T0=0x{:016x} T1=0x{:016x} T2=0x{:016x}",
                          jam_instance.instance.reg(Reg::T0),
                          jam_instance.instance.reg(Reg::T1),
                          jam_instance.instance.reg(Reg::T2));
                
                // Try to read memory near A0 to see what it points to
                let a0 = jam_instance.instance.reg(Reg::A0) as u32;
                if a0 > 0 && a0 < 0xFFFF0000 {
                    let mut buf = [0u8; 16];
                    if jam_instance.instance.read_memory_into(a0, &mut buf).is_ok() {
                        eprintln!("  Memory@A0: {:02x?}", buf);
                    }
                }
                
                break Err(polkavm::CallError::Trap);
            }
            Ok(polkavm::InterruptKind::NotEnoughGas) => {
                eprintln!("=== PVM OUT OF GAS at step {} ===", step_count);
                break Err(polkavm::CallError::NotEnoughGas);
            }
            Ok(polkavm::InterruptKind::Ecalli(hostcall_id)) => {
                eprintln!("[step {:3}] ECALLI id={} A0={} A1={} A2={} A3={}", 
                         step_count, hostcall_id,
                         jam_instance.instance.reg(Reg::A0),
                         jam_instance.instance.reg(Reg::A1),
                         jam_instance.instance.reg(Reg::A2),
                         jam_instance.instance.reg(Reg::A3));
                // Handle host call - create a pseudo-Caller to access instance and context
                // This is a workaround since we're not using the Linker's fallback handler
                let hostcall_result = {
                    let ctx = &mut jam_instance.context;
                    let inst = &mut jam_instance.instance;
                    
                    // GP Appendix B: All host calls cost 10 gas (g = 10)
                    // Subtract gas BEFORE executing the host call
                    // PolkaVM will handle out-of-gas condition naturally
                    let current_gas = inst.gas();
                    inst.set_gas(current_gas.saturating_sub(10));
                    eprintln!("  [hostcall {}] Gas: {} -> {} (charged 10)", hostcall_id, current_gas, inst.gas());
                    
                    // JAM Host Calls (GP Section 14.5 + jam-pvm-common/src/imports.rs)
                    // Index 0-26 are GP standard, 100 is extended log
                    log::debug!("  [hostcall {}] A0={} A1={} A2={} A3={}", 
                        hostcall_id, 
                        inst.reg(Reg::A0), inst.reg(Reg::A1), 
                        inst.reg(Reg::A2), inst.reg(Reg::A3));
                    match hostcall_id {
                        // gas() -> remaining gas (index 0)
                        0 => {
                            let gas = inst.gas() as u64;
                            inst.set_reg(Reg::A0, gas);
                            Ok(())
                        }
                        
                        // fetch(buffer, offset, buffer_len, kind, a, b) -> data_len (index 1)
                        // GP Section 14.5.1 - Fetch various context data
                        1 => {
                            let buffer_ptr = inst.reg(Reg::A0) as u32;
                            let offset = inst.reg(Reg::A1) as usize;
                            let buffer_len = inst.reg(Reg::A2) as usize;
                            let kind = inst.reg(Reg::A3);
                            let a = inst.reg(Reg::A4) as usize;
                            let _b = inst.reg(Reg::A5);
                            
                            // Get the data based on kind
                            let data: Option<&[u8]> = match FetchKind::try_from(kind) {
                                Ok(FetchKind::ProtocolParameters) => {
                                    if ctx.protocol_params.is_empty() { None }
                                    else { Some(&ctx.protocol_params) }
                                }
                                Ok(FetchKind::Entropy) => {
                                    // Use entropy_raw which can be 32 or 128 bytes
                                    if ctx.entropy_raw.is_empty() {
                                        // Fallback to fixed array if raw not set
                                        Some(unsafe {
                                            std::slice::from_raw_parts(
                                                ctx.entropy.as_ptr() as *const u8,
                                                128
                                            )
                                        })
                                    } else {
                                        Some(&ctx.entropy_raw)
                                    }
                                }
                                Ok(FetchKind::WorkPackage) => {
                                    if ctx.work_package.is_empty() { None }
                                    else { Some(&ctx.work_package) }
                                }
                                Ok(FetchKind::AccumulateItems) => {
                                    // GP B.5: fetch(kind=14) returns E(↕i) - JAM encoded list
                                    // Format: compact(count) + concatenated items
                                    if ctx.accumulate_items.is_empty() { 
                                        eprintln!("    fetch AccumulateItems: empty");
                                        // Return empty list = compact(0) = [0]
                                        Some(&[0u8][..])
                                    } else {
                                        // Build encoded Vec<AccumulateItem> using JAM codec
                                        // The service expects Vec<AccumulateItem> format
                                        thread_local! {
                                            static ACC_LIST_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::new());
                                        }
                                        ACC_LIST_BUF.with(|buf| {
                                            let mut buf = buf.borrow_mut();
                                            buf.clear();
                                            
                                            // Use jam-codec Compact for count
                                            use jam_codec::Compact;
                                            let count = ctx.accumulate_items.len() as u32;
                                            Compact(count).encode_to(&mut *buf);
                                            
                                            // Concatenate all items (already JAM-encoded AccumulateItem)
                                            for item in &ctx.accumulate_items {
                                                buf.extend_from_slice(item);
                                            }
                                            
                                            eprintln!("    fetch AccumulateItems: {} items, {} bytes, prefix={:02x?}, first_item={:02x?}", 
                                                     count, buf.len(), 
                                                     &buf[..std::cmp::min(4, buf.len())],
                                                     &buf[1..std::cmp::min(33, buf.len())]);
                                            
                                            // TEST: Try to decode to catch any encoding errors
                                            use jam_codec::Decode;
                                            match Vec::<AccumulateItem>::decode(&mut buf.as_slice()) {
                                                Ok(items) => eprintln!("    [DECODE TEST] Success: {} items decoded", items.len()),
                                                Err(e) => eprintln!("    [DECODE TEST] FAILED: {:?}", e),
                                            }
                                        });
                                        
                                        ACC_LIST_BUF.with(|buf| {
                                            let buf = buf.borrow();
                                            // SAFETY: we return a reference that will be copied immediately
                                            Some(unsafe { std::slice::from_raw_parts(buf.as_ptr(), buf.len()) })
                                        })
                                    }
                                }
                                Ok(FetchKind::AnyAccumulateItem) => {
                                    // GP B.5: fetch(kind=15, a) returns E(i[a]) - single item
                                    // Items are already encoded, return as-is
                                    log::debug!("    fetch AnyAccumulateItem: index={}, total={}", 
                                               a, ctx.accumulate_items.len());
                                    ctx.accumulate_items.get(a).map(|v| v.as_slice())
                                }
                                _ => {
                                    log::debug!("    fetch: unhandled kind {}", kind);
                                    None
                                }
                            };
                            
                            match data {
                                Some(data) => {
                                    let data_len = data.len();
                                    // If buffer is null or length is 0, just return data length
                                    if buffer_ptr == 0 || buffer_len == 0 {
                                        inst.set_reg(Reg::A0, data_len as u64);
                                    } else {
                                        // Copy data[offset..] to buffer
                                        let available = data_len.saturating_sub(offset);
                                        let copy_len = std::cmp::min(available, buffer_len);
                                        if copy_len > 0 && offset < data_len {
                                            match inst.write_memory(buffer_ptr, &data[offset..offset+copy_len]) {
                                                Ok(_) => eprintln!("    fetch: wrote {} bytes to 0x{:x}", copy_len, buffer_ptr),
                                                Err(e) => eprintln!("    fetch: WRITE FAILED to 0x{:x}: {:?}", buffer_ptr, e),
                                            }
                                        }
                                        inst.set_reg(Reg::A0, data_len as u64);
                                    }
                                }
                                None => {
                                    // No data available - return 0 (empty) rather than error
                                    // This prevents guest panic when context is incomplete
                                    // The guest should handle empty data gracefully
                                    log::debug!("    fetch kind {}: no data, returning 0 (empty)", kind);
                                    inst.set_reg(Reg::A0, 0);
                                }
                            }
                            Ok(())
                        }
                        
                        // lookup(service, hash_ptr, out, offset, out_len) -> preimage_len (index 2)
                        // GP Section 14.5.2: Preimage lookup
                        2 => {
                            let service = inst.reg(Reg::A0) as u32;
                            let hash_ptr = inst.reg(Reg::A1) as u32;
                            let out_ptr = inst.reg(Reg::A2) as u32;
                            let offset = inst.reg(Reg::A3) as usize;
                            let out_len = inst.reg(Reg::A4) as usize;
                            
                            // Defensive: read hash from guest memory
                            let hash_result = read_guest_memory!(inst, hash_ptr, 32);
                            let result = match hash_result {
                                Some(hash_vec) if hash_vec.len() == 32 => {
                                let mut hash = [0u8; 32];
                                hash.copy_from_slice(&hash_vec);
                                
                                    match ctx.preimages.get(&hash) {
                                        Some(preimage) => {
                                            // Saturating arithmetic to prevent overflow
                                    let available = preimage.len().saturating_sub(offset);
                                    let copy_len = std::cmp::min(available, out_len);
                                            
                                    if copy_len > 0 && offset < preimage.len() {
                                                write_guest_memory!(inst, out_ptr, &preimage[offset..offset.saturating_add(copy_len)]);
                                    }
                                            preimage.len() as u64
                                        }
                                        None => {
                                            log::trace!("lookup: preimage not found for service {} hash {:?}", service, &hash[..8]);
                                            u64::MAX
                                }
                                    }
                                }
                                _ => {
                                    log::debug!("lookup: failed to read hash from guest at 0x{:x}", hash_ptr);
                                    u64::MAX
                                }
                            };
                            inst.set_reg(Reg::A0, result);
                            Ok(())
                        }
                        
                        // read(service, key_ptr, key_len, out, offset, out_len) -> value_len (index 3)
                        // GP Section 14.5.3: Storage read
                        3 => {
                            let service = inst.reg(Reg::A0) as u32;
                            let key_ptr = inst.reg(Reg::A1) as u32;
                            let key_len = inst.reg(Reg::A2) as u32;
                            let out_ptr = inst.reg(Reg::A3) as u32;
                            let offset = inst.reg(Reg::A4) as usize;
                            let out_len = inst.reg(Reg::A5) as usize;
                            
                            // Defensive: validate key length (max 1MB)
                            let key_len_usize = key_len as usize;
                            if key_len_usize > 1024 * 1024 {
                                log::warn!("read: key length {} exceeds limit", key_len_usize);
                                inst.set_reg(Reg::A0, u64::MAX);
                                // Continue to Ok(()) at end of match arm
                            } else {
                                let result = match read_guest_memory!(inst, key_ptr, key_len) {
                                    Some(key) => {
                                        match ctx.storage.get(&key) {
                                            Some(value) => {
                                    let available = value.len().saturating_sub(offset);
                                    let copy_len = std::cmp::min(available, out_len);
                                                
                                    if copy_len > 0 && offset < value.len() {
                                                    write_guest_memory!(inst, out_ptr, &value[offset..offset.saturating_add(copy_len)]);
                                    }
                                                value.len() as u64
                                            }
                                            None => {
                                                log::trace!("read: key not found for service {} key_len {}", service, key_len);
                                                u64::MAX
                                }
                                        }
                                    }
                                    None => {
                                        log::debug!("read: failed to read key from guest at 0x{:x}", key_ptr);
                                        u64::MAX
                                    }
                                };
                                inst.set_reg(Reg::A0, result);
                            }
                            Ok(())
                        }
                        
                        // write(key_ptr, key_len, value_ptr, value_len) -> old_len (index 4)
                        4 => {
                            let key_ptr = inst.reg(Reg::A0) as u32;
                            let key_len = inst.reg(Reg::A1) as u32;
                            let value_ptr = inst.reg(Reg::A2) as u32;
                            let value_len = inst.reg(Reg::A3) as u32;
                            
                            if let (Ok(key), Ok(value)) = (
                                inst.read_memory(key_ptr, key_len),
                                inst.read_memory(value_ptr, value_len)
                            ) {
                                let old_len = ctx.storage.get(&key).map(|v| v.len() as u64).unwrap_or(u64::MAX);
                                ctx.storage.insert(key, value);
                                inst.set_reg(Reg::A0, old_len);
                            } else {
                                inst.set_reg(Reg::A0, u64::MAX);
                            }
                            Ok(())
                        }
                        
                        // info(service, ptr, offset, len) -> len (index 5)
                        5 => {
                            // Return service info - simplified
                            inst.set_reg(Reg::A0, 0);
                            Ok(())
                        }
                        
                        // transfer(dest, amount, gas_limit, memo_ptr) -> result (index 20)
                        20 => {
                            let to_service = inst.reg(Reg::A0) as u32;
                            let amount = inst.reg(Reg::A1);
                            let _gas_limit = inst.reg(Reg::A2);
                            let memo_ptr = inst.reg(Reg::A3) as u32;
                            
                            if amount <= ctx.balance {
                                // Read 128-byte memo if ptr is not 0
                                let memo = if memo_ptr != 0 {
                                    inst.read_memory(memo_ptr, 128).unwrap_or_default()
                                } else {
                                    vec![]
                                };
                                
                                ctx.balance -= amount;
                                ctx.transfers.push(JamTransfer { to_service, amount, memo });
                                inst.set_reg(Reg::A0, 0); // Success
                            } else {
                                inst.set_reg(Reg::A0, 5); // NoCash error
                            }
                            Ok(())
                        }
                        
                        // eject(target, code_hash_ptr) -> result (index 21)
                        // GP Section 14.5.10: Eject a zombie service
                        // The target service must have nominated the caller as its ejector via zombify()
                        // The ejected service's balance is transferred to the caller
                        21 => {
                            let target = inst.reg(Reg::A0) as u32;
                            let code_hash_ptr = inst.reg(Reg::A1) as u32;
                            let caller = ctx.service_id;
                            
                            // Read the expected code hash (32 bytes)
                            let code_hash_result = if code_hash_ptr != 0 {
                                read_guest_memory!(inst, code_hash_ptr, 32)
                            } else {
                                None
                            };
                            
                            // For now, we accept any eject request
                            // In a full implementation, we would verify:
                            // 1. Target service exists
                            // 2. Target has nominated caller as ejector (zombify)
                            // 3. Code hash matches
                            
                            eprintln!("    [eject] caller={}, target={}, code_hash={:02x?}", 
                                     caller, target, 
                                     code_hash_result.as_ref().map(|h| &h[..8]));
                            
                            // Record the ejection with caller info for balance transfer
                            if !ctx.ejected_services.iter().any(|(t, _)| *t == target) {
                                ctx.ejected_services.push((target, caller));
                            }
                            
                            inst.set_reg(Reg::A0, 0); // Success
                            Ok(())
                        }
                        
                        // new(code_hash_ptr, balance, min_item_gas, min_memo_gas) -> service_id (index 22)
                        // GP Section 14.5.8: Create a new service
                        22 => {
                            let code_hash_ptr = inst.reg(Reg::A0) as u32;
                            let _balance = inst.reg(Reg::A1);
                            let _min_item_gas = inst.reg(Reg::A2);
                            let _min_memo_gas = inst.reg(Reg::A3);
                            
                            if let Some(code_hash_bytes) = read_guest_memory!(inst, code_hash_ptr, 32) {
                                let mut code_hash = [0u8; 32];
                                code_hash.copy_from_slice(&code_hash_bytes);
                                
                                // Generate new service ID based on caller and counter
                                let new_sid = ctx.next_service_id;
                                ctx.next_service_id += 1;
                                
                                // Record the created service
                                ctx.created_services.push((new_sid, code_hash));
                                eprintln!("    [new] created service {} with code_hash={:02x?}...", 
                                         new_sid, &code_hash[..8]);
                                
                                inst.set_reg(Reg::A0, new_sid as u64);
                            } else {
                                inst.set_reg(Reg::A0, u64::MAX); // Error
                            }
                            Ok(())
                        }
                        
                        // upgrade(code_hash_ptr, min_item_gas, min_memo_gas) -> result (index 23)
                        // GP Section 14.5.9: Upgrade service code
                        23 => {
                            let code_hash_ptr = inst.reg(Reg::A0) as u32;
                            let _min_item_gas = inst.reg(Reg::A1);
                            let _min_memo_gas = inst.reg(Reg::A2);
                            
                            if let Some(code_hash_bytes) = read_guest_memory!(inst, code_hash_ptr, 32) {
                                let mut code_hash = [0u8; 32];
                                code_hash.copy_from_slice(&code_hash_bytes);
                                
                                // Record the upgrade
                                ctx.upgrades.push((ctx.service_id, code_hash));
                                eprintln!("    [upgrade] service {} to code_hash={:02x?}...", 
                                         ctx.service_id, &code_hash[..8]);
                                
                                inst.set_reg(Reg::A0, 0); // Success
                            } else {
                                inst.set_reg(Reg::A0, u64::MAX); // Error
                            }
                            Ok(())
                        }
                        
                        // yield_hash(hash_ptr) -> result (index 25)
                        // GP Section 14.5.11: Set the output hash for this accumulation
                        // This is used for θ calculation in accumulation output
                        25 => {
                            let hash_ptr = inst.reg(Reg::A0) as u32;
                            
                            if let Some(hash_bytes) = read_guest_memory!(inst, hash_ptr, 32) {
                                let mut hash = [0u8; 32];
                                hash.copy_from_slice(&hash_bytes);
                                ctx.yield_output = Some(hash);
                                eprintln!("    [yield_hash] hash={:02x?}...", &hash[..8]);
                                inst.set_reg(Reg::A0, 0); // Success
                            } else {
                                inst.set_reg(Reg::A0, u64::MAX); // Error
                            }
                            Ok(())
                        }
                        
                        // log(level, target_ptr, target_len, text_ptr, text_len) (index 100)
                        // This is NOT part of GP but used for debugging
                        100 => {
                            let level = inst.reg(Reg::A0);
                            let _target_ptr = inst.reg(Reg::A1) as u32;
                            let _target_len = inst.reg(Reg::A2) as u32;
                            let text_ptr = inst.reg(Reg::A3) as u32;
                            let text_len = inst.reg(Reg::A4) as u32;
                            
                            if let Ok(text) = inst.read_memory(text_ptr, text_len) {
                                if let Ok(s) = std::str::from_utf8(&text) {
                                    let level_str = match level {
                                        0 => "ERROR",
                                        1 => "WARN",
                                        2 => "INFO",
                                        3 => "DEBUG",
                                        _ => "TRACE",
                                    };
                                    eprintln!("    [PVM {}] {}", level_str, s);
                                }
                                ctx.logs.push(text);
                            }
                            // No return value for log
                            Ok(())
                        }
                        
                        _ => {
                            log::debug!("jam_run: unimplemented host call {}", hostcall_id);
                            // Return error but don't trap - some host calls may be optional
                            inst.set_reg(Reg::A0, u64::MAX);
                            Ok::<(), JamHostError>(())
                        }
                    }
                };
                
                if hostcall_result.is_err() {
                    break Err(polkavm::CallError::Trap);
                }
                // Continue execution after host call
            }
            Ok(polkavm::InterruptKind::Segfault(addr)) => {
                log::debug!("jam_run: segfault at {:?}", addr);
                break Err(polkavm::CallError::Trap);
            }
            Ok(polkavm::InterruptKind::Step) => break Err(polkavm::CallError::Step),
            Err(e) => break Err(polkavm::CallError::Error(e)),
        }
    };
    
    match run_result {
        Ok(()) => {
            // Get result from A0 register
            *result = jam_instance.instance.reg(Reg::A0);
            0 // Success
        }
        Err(e) => {
            match e {
                polkavm::CallError::Trap => {
                    *result = jam_instance.instance.reg(Reg::A0);
                    5 // Trap
                }
                polkavm::CallError::NotEnoughGas => {
                    *result = 0;
                    6 // Out of gas
                }
                polkavm::CallError::User(host_err) => {
                    *result = host_err as u64;
                    7 // Host function error
                }
                polkavm::CallError::Error(err) => {
                    log::debug!("jam_run: execution error: {:?}", err);
                    4 // General error
                }
                polkavm::CallError::Step => {
                    *result = jam_instance.instance.reg(Reg::A0);
                    8 // Step (step tracing)
                }
            }
        }
    }
}

/// Continue execution of a JAM instance after a host call
///
/// This is used when the host needs to perform async operations
/// and then resume execution.
///
/// # Safety
/// - `instance` must be a valid instance pointer
/// - `result` must point to a valid u64
#[no_mangle]
pub unsafe extern "C" fn jam_continue(
    instance: *mut JamInstance,
    result: *mut u64,
) -> u32 {
    use polkavm::Reg;
    
    if instance.is_null() || result.is_null() {
        return 1;
    }
    
    let jam_instance = &mut (*instance);
    
    match jam_instance.instance.continue_execution(&mut jam_instance.context) {
        Ok(()) => {
            *result = jam_instance.instance.reg(Reg::A0);
            0
        }
        Err(e) => {
            match e {
                polkavm::CallError::Trap => 5,
                polkavm::CallError::NotEnoughGas => 6,
                polkavm::CallError::User(host_err) => {
                    *result = host_err as u64;
                    7
                }
                polkavm::CallError::Error(_) => 4,
                polkavm::CallError::Step => 8,
            }
        }
    }
}

/// Set gas limit for JAM instance
///
/// # Safety
/// - `instance` must be a valid instance pointer
#[no_mangle]
pub unsafe extern "C" fn jam_set_gas(instance: *mut JamInstance, gas: i64) {
    if instance.is_null() {
        return;
    }
    let jam_instance = &mut (*instance);
    // Instance implements DerefMut to RawInstance
    use std::ops::DerefMut;
    jam_instance.instance.deref_mut().set_gas(gas);
}

/// Get remaining gas from JAM instance
///
/// # Safety
/// - `instance` must be a valid instance pointer
#[no_mangle]
pub unsafe extern "C" fn jam_get_gas(instance: *mut JamInstance) -> i64 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    // Instance implements Deref to RawInstance
    use std::ops::Deref;
    jam_instance.instance.deref().gas()
}

/// Get number of transfers made during execution
#[no_mangle]
pub unsafe extern "C" fn jam_get_transfer_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    jam_instance.context.transfers.len() as u32
}

/// Get number of log entries
#[no_mangle]
pub unsafe extern "C" fn jam_get_log_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    jam_instance.context.logs.len() as u32
}

/// Get service balance after execution
#[no_mangle]
pub unsafe extern "C" fn jam_get_balance(instance: *mut JamInstance) -> u64 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    jam_instance.context.balance
}

// ============================================================================
// Storage Iteration (for retrieving state changes after execution)
// ============================================================================

/// Get number of storage entries
#[no_mangle]
pub unsafe extern "C" fn jam_get_storage_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    jam_instance.context.storage.len() as u32
}

/// Get storage key at index (returns key length, writes to out buffer)
/// Returns 0 on success, key length; returns u32::MAX on error
#[no_mangle]
pub unsafe extern "C" fn jam_get_storage_key(
    instance: *mut JamInstance,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    // Get key at index
    let keys: Vec<&Vec<u8>> = jam_instance.context.storage.keys().collect();
    if (index as usize) >= keys.len() {
        return u32::MAX;
    }
    
    let key = keys[index as usize];
    let copy_len = std::cmp::min(key.len(), out_len);
    
    if !out.is_null() && copy_len > 0 {
        std::ptr::copy_nonoverlapping(key.as_ptr(), out, copy_len);
    }
    
    key.len() as u32
}

/// Get storage value at index (returns value length, writes to out buffer)
#[no_mangle]
pub unsafe extern "C" fn jam_get_storage_value(
    instance: *mut JamInstance,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    // Get value at index
    let entries: Vec<(&Vec<u8>, &Vec<u8>)> = jam_instance.context.storage.iter().collect();
    if (index as usize) >= entries.len() {
        return u32::MAX;
    }
    
    let (_, value) = entries[index as usize];
    let copy_len = std::cmp::min(value.len(), out_len);
    
    if !out.is_null() && copy_len > 0 {
        std::ptr::copy_nonoverlapping(value.as_ptr(), out, copy_len);
    }
    
    value.len() as u32
}

/// Get log entry at index (returns log length, writes to out buffer)
#[no_mangle]
pub unsafe extern "C" fn jam_get_log(
    instance: *mut JamInstance,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    if (index as usize) >= jam_instance.context.logs.len() {
        return u32::MAX;
    }
    
    let log = &jam_instance.context.logs[index as usize];
    let copy_len = std::cmp::min(log.len(), out_len);
    
    if !out.is_null() && copy_len > 0 {
        std::ptr::copy_nonoverlapping(log.as_ptr(), out, copy_len);
    }
    
    log.len() as u32
}

/// Get transfer at index
/// Returns: to_service_id, or u32::MAX on error
/// Writes amount and memo to out pointers
#[no_mangle]
pub unsafe extern "C" fn jam_get_transfer(
    instance: *mut JamInstance,
    index: u32,
    amount_out: *mut u64,
    memo_out: *mut u8,
    memo_len: usize,
) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    if (index as usize) >= jam_instance.context.transfers.len() {
        return u32::MAX;
    }
    
    let transfer = &jam_instance.context.transfers[index as usize];
    
    if !amount_out.is_null() {
        *amount_out = transfer.amount;
    }
    
    if !memo_out.is_null() {
        let copy_len = std::cmp::min(transfer.memo.len(), memo_len);
        if copy_len > 0 {
            std::ptr::copy_nonoverlapping(transfer.memo.as_ptr(), memo_out, copy_len);
        }
    }
    
    transfer.to_service
}

/// Get transfer memo length at index
#[no_mangle]
pub unsafe extern "C" fn jam_get_transfer_memo_len(
    instance: *mut JamInstance,
    index: u32,
) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    if (index as usize) >= jam_instance.context.transfers.len() {
        return u32::MAX;
    }
    
    jam_instance.context.transfers[index as usize].memo.len() as u32
}

// ============================================================================
// Ejected Services (GP 14.5.10)
// ============================================================================

/// Get number of services ejected during execution
#[no_mangle]
pub unsafe extern "C" fn jam_get_ejected_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    jam_instance.context.ejected_services.len() as u32
}

/// Get ejected service ID at index (target)
#[no_mangle]
pub unsafe extern "C" fn jam_get_ejected_service(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    if (index as usize) >= jam_instance.context.ejected_services.len() {
        return u32::MAX;
    }
    
    jam_instance.context.ejected_services[index as usize].0
}

/// Get ejector service ID at index (who called eject)
#[no_mangle]
pub unsafe extern "C" fn jam_get_ejector_service(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    if (index as usize) >= jam_instance.context.ejected_services.len() {
        return u32::MAX;
    }
    
    jam_instance.context.ejected_services[index as usize].1
}

// ============================================================================
// Yield Output (GP 14.5.11)
// ============================================================================

/// Check if yield_hash was called during execution
#[no_mangle]
pub unsafe extern "C" fn jam_has_yield_output(instance: *mut JamInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    if jam_instance.context.yield_output.is_some() { 1 } else { 0 }
}

/// Get the yield output hash (32 bytes)
/// Returns 0 on success, non-zero on error
#[no_mangle]
pub unsafe extern "C" fn jam_get_yield_output(
    instance: *mut JamInstance,
    out_buf: *mut u8,
) -> u32 {
    if instance.is_null() || out_buf.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    match &jam_instance.context.yield_output {
        Some(hash) => {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, 32);
            0
        }
        None => u32::MAX
    }
}

// ============================================================================
// Created Services (GP 14.5.8 - new host call)
// ============================================================================

/// Get number of services created during execution
#[no_mangle]
pub unsafe extern "C" fn jam_get_created_service_count(instance: *mut JamInstance) -> u32 {
    if instance.is_null() {
        return 0;
    }
    let jam_instance = &(*instance);
    jam_instance.context.created_services.len() as u32
}

/// Get created service ID at index
#[no_mangle]
pub unsafe extern "C" fn jam_get_created_service_id(instance: *mut JamInstance, index: u32) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    if (index as usize) >= jam_instance.context.created_services.len() {
        return u32::MAX;
    }
    
    jam_instance.context.created_services[index as usize].0
}

/// Get created service code hash at index
#[no_mangle]
pub unsafe extern "C" fn jam_get_created_service_code_hash(
    instance: *mut JamInstance,
    index: u32,
    out_buf: *mut u8,
) -> u32 {
    if instance.is_null() || out_buf.is_null() {
        return u32::MAX;
    }
    let jam_instance = &(*instance);
    
    if (index as usize) >= jam_instance.context.created_services.len() {
        return u32::MAX;
    }
    
    let hash = &jam_instance.context.created_services[index as usize].1;
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, 32);
    0
}

/// Set next service ID for new() calls
/// This should be set before execution based on current state
#[no_mangle]
pub unsafe extern "C" fn jam_set_next_service_id(instance: *mut JamInstance, next_id: u32) -> u32 {
    if instance.is_null() {
        return u32::MAX;
    }
    let jam_instance = &mut (*instance);
    jam_instance.context.next_service_id = next_id;
    0
}

// ============================================================================
// AccumulateItem Encoding
// ============================================================================

/// Encode a WorkItemRecord as AccumulateItem for PVM accumulation
/// 
/// Parameters:
/// Encode AccumulateItem in v0.1.21 format (for compatibility with old service blobs)
/// 
/// v0.1.21 AccumulateItem is a STRUCT (not enum), with fields in this order:
/// - package: [u8; 32]
/// - exports_root: [u8; 32]  
/// - authorizer_hash: [u8; 32]
/// - auth_output: Vec<u8> (compact len + data) <-- BEFORE payload in v0.1.21!
/// - payload: [u8; 32]
/// - result: Result<WorkOutput, WorkError> (CompactRefineResult encoding)
///
/// Note: v0.1.26 has enum discriminant + gas_limit + different field order
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
    
    let mut encoded = Vec::with_capacity(256);
    
    // package: [u8; 32]
    let package = std::slice::from_raw_parts(package_hash, 32);
    encoded.extend_from_slice(package);
    
    // exports_root: [u8; 32]
    if exports_root.is_null() {
        encoded.extend_from_slice(&[0u8; 32]);
    } else {
        encoded.extend_from_slice(std::slice::from_raw_parts(exports_root, 32));
    }
    
    // authorizer_hash: [u8; 32]
    if auth_hash.is_null() {
        encoded.extend_from_slice(&[0u8; 32]);
    } else {
        encoded.extend_from_slice(std::slice::from_raw_parts(auth_hash, 32));
    }
    
    // auth_output: Vec<u8> with compact length (BEFORE payload in v0.1.21!)
    if auth_output_data.is_null() || auth_output_len == 0 {
        encoded.push(0); // compact(0) = single byte 0
    } else {
        let auth_data = std::slice::from_raw_parts(auth_output_data, auth_output_len as usize);
        // Encode compact length
        encode_compact_to(&mut encoded, auth_output_len as u64);
        encoded.extend_from_slice(auth_data);
    }
    
    // payload: [u8; 32]
    if payload_hash.is_null() {
        encoded.extend_from_slice(&[0u8; 32]);
    } else {
        encoded.extend_from_slice(std::slice::from_raw_parts(payload_hash, 32));
    }
    
    // result: CompactRefineResult encoding
    // For Ok(data): 0x00 + compact(len) + data
    // For errors: 0x01-0x05 etc.
    if result_data.is_null() || result_len == 0 {
        // Ok with empty data
        encoded.push(0x00); // Ok tag
        encoded.push(0x00); // compact(0)
    } else {
        let result = std::slice::from_raw_parts(result_data, result_len as usize);
        encoded.push(0x00); // Ok tag
        encode_compact_to(&mut encoded, result_len as u64);
        encoded.extend_from_slice(result);
    }
    
    if encoded.len() > out_capacity as usize {
        eprintln!("jam_encode_work_item_v21: buffer too small ({} > {})", encoded.len(), out_capacity);
        return 0;
    }
    
    std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_buf, encoded.len());
    
    eprintln!("jam_encode_work_item_v21: {} bytes, first 32: {:02x?}", 
             encoded.len(), &encoded[..std::cmp::min(32, encoded.len())]);
    
    encoded.len() as u32
}

/// Helper to encode SCALE compact integer to a Vec
fn encode_compact_to(buf: &mut Vec<u8>, value: u64) {
    use jam_codec::Compact;
    Compact(value).encode_to(buf);
}

/// Encode WorkItemRecord using jam-types v0.1.26 format (enum AccumulateItem::WorkItem)
///
/// - package_hash: 32-byte work package hash
/// - exports_root: 32-byte segment tree root  
/// - auth_hash: 32-byte authorizer hash
/// - payload_hash: 32-byte payload hash
/// - gas_limit: gas limit for accumulation
/// - result_data: refine result (Ok bytes)
/// - result_len: length of result_data
/// - out_buf: output buffer for encoded data
/// - out_capacity: capacity of output buffer
/// 
/// Returns: actual encoded length, or 0 on error
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
    
    // Read input data
    let package = std::slice::from_raw_parts(package_hash, 32);
    let exports = if exports_root.is_null() {
        [0u8; 32]
    } else {
        std::slice::from_raw_parts(exports_root, 32).try_into().unwrap_or([0u8; 32])
    };
    let auth = if auth_hash.is_null() {
        [0u8; 32]
    } else {
        std::slice::from_raw_parts(auth_hash, 32).try_into().unwrap_or([0u8; 32])
    };
    let payload = if payload_hash.is_null() {
        [0u8; 32]
    } else {
        std::slice::from_raw_parts(payload_hash, 32).try_into().unwrap_or([0u8; 32])
    };
    
    let result = if result_data.is_null() || result_len == 0 {
        Ok(WorkOutput(vec![]))
    } else {
        let data = std::slice::from_raw_parts(result_data, result_len as usize);
        Ok(WorkOutput(data.to_vec()))
    };
    
    let auth_trace = if auth_output_data.is_null() || auth_output_len == 0 {
        AuthTrace(vec![])
    } else {
        let data = std::slice::from_raw_parts(auth_output_data, auth_output_len as usize);
        AuthTrace(data.to_vec())
    };
    
    // Build WorkItemRecord
    let record = WorkItemRecord {
        package: WorkPackageHash(package.try_into().unwrap_or([0u8; 32])),
        exports_root: SegmentTreeRoot(exports),
        authorizer_hash: AuthorizerHash(auth),
        payload: PayloadHash(payload),
        gas_limit,
        result,
        auth_output: auth_trace,
    };
    
    // Encode as AccumulateItem
    let item = AccumulateItem::WorkItem(record);
    let encoded = item.encode();
    
    if encoded.len() > out_capacity as usize {
        eprintln!("jam_encode_work_item_record: buffer too small ({} > {})", encoded.len(), out_capacity);
        return 0;
    }
    
    std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_buf, encoded.len());
    
    eprintln!("jam_encode_work_item_record: {} bytes, first 32: {:02x?}", 
             encoded.len(), &encoded[..std::cmp::min(32, encoded.len())]);
    if encoded.len() > 145 {
        eprintln!("  bytes 129-145 (after hashes): {:02x?}", &encoded[129..145]);
    }
    
    encoded.len() as u32
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_engine_creation() {
        let engine = pvm_engine_new();
        assert!(!engine.is_null());
        unsafe { pvm_engine_free(engine); }
    }
    
    #[test]
    fn test_version() {
        let version = pvm_version();
        let s = unsafe { std::ffi::CStr::from_ptr(version) };
        assert!(s.to_str().unwrap().contains("polkavm"));
    }
}


#[cfg(test)]
mod blob_tests {
    use super::*;
    
    #[test]
    fn test_jam_blob_parsing() {
        let blob = std::fs::read("/tmp/test_blob.bin").expect("read blob");
        println!("Blob size: {}", blob.len());
        
        let pb = JamProgramBlob::from_bytes(&blob).expect("parse blob");
        println!("metadata len: {}", pb.metadata.len());
        println!("ro_data len: {}", pb.ro_data.len());
        println!("rw_data len: {}", pb.rw_data.len());
        println!("rw_data_padding_pages: {}", pb.rw_data_padding_pages);
        println!("stack_size: {}", pb.stack_size);
        println!("code_blob len: {}", pb.code_blob.len());
        
        // Convert to polkavm::ProgramParts
        let parts: polkavm::ProgramParts = pb.into();
        println!("\nProgramParts:");
        println!("  is_64_bit: {}", parts.is_64_bit);
        println!("  ro_data_size: {}", parts.ro_data_size);
        println!("  rw_data_size: {}", parts.rw_data_size);
        println!("  stack_size: {}", parts.stack_size);
        println!("  exports len: {}", parts.exports.len());
        
        // Create ProgramBlob
        let program_blob = polkavm::ProgramBlob::from_parts(parts).expect("create blob");
        println!("\n✓ ProgramBlob created!");
        println!("  code len: {}", program_blob.code().len());
        
        // Create engine and module
        let config = Config::new();
        let engine = Engine::new(&config).expect("create engine");
        
        let mut module_config = ModuleConfig::new();
        module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
        
        let module = Module::from_blob(&engine, &module_config, program_blob).expect("create module");
        println!("✓ Module created!");
        println!("  memory_map ro_data: 0x{:x}", module.memory_map().ro_data_address());
        println!("  memory_map rw_data: 0x{:x}", module.memory_map().rw_data_address());
        println!("  memory_map stack: 0x{:x}-0x{:x}", 
            module.memory_map().stack_address_low(),
            module.memory_map().stack_address_high());
        println!("  default_sp: 0x{:x}", module.default_sp());
        
        // Create instance
        let linker = Linker::<()>::new();
        let instance_pre = linker.instantiate_pre(&module).expect("instantiate_pre");
        let mut instance = instance_pre.instantiate().expect("instantiate");
        
        println!("✓ Instance created!");
        
        // Set initial gas
        instance.set_gas(1_000_000);
        
        // Try to run from PC=5 (accumulate)
        println!("\nTrying to run from PC=5 (accumulate)...");
        instance.prepare_call_untyped(polkavm::ProgramCounter(5), &[]);
        
        match instance.run() {
            Ok(interrupt) => {
                println!("  Result: {:?}", interrupt);
                println!("  Gas remaining: {}", instance.gas());
                println!("  A0 (result): 0x{:x}", instance.reg(polkavm::Reg::A0));
            }
            Err(e) => {
                println!("  Error: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod jam_codec_tests {
    use super::*;
    use jam_codec::Decode;
    
    #[test]
    fn test_accumulate_item_roundtrip() {
        // Create a test WorkItemRecord
        let record = WorkItemRecord {
            package: WorkPackageHash([1u8; 32]),
            exports_root: SegmentTreeRoot([2u8; 32]),
            authorizer_hash: AuthorizerHash([3u8; 32]),
            payload: PayloadHash([4u8; 32]),
            gas_limit: 1000,
            result: Ok(WorkOutput(vec![0xaa, 0xbb, 0xcc])),
            auth_output: AuthTrace(vec![0xdd, 0xee]),
        };
        
        let item = AccumulateItem::WorkItem(record);
        let encoded = item.encode();
        
        eprintln!("Encoded AccumulateItem: {} bytes", encoded.len());
        eprintln!("First 50 bytes: {:02x?}", &encoded[..std::cmp::min(50, encoded.len())]);
        
        // Try to decode
        let decoded = AccumulateItem::decode(&mut &encoded[..]);
        assert!(decoded.is_ok(), "Failed to decode: {:?}", decoded.err());
        
        // Test Vec<AccumulateItem> - create new item since no Clone
        let record2 = WorkItemRecord {
            package: WorkPackageHash([1u8; 32]),
            exports_root: SegmentTreeRoot([2u8; 32]),
            authorizer_hash: AuthorizerHash([3u8; 32]),
            payload: PayloadHash([4u8; 32]),
            gas_limit: 1000,
            result: Ok(WorkOutput(vec![0xaa, 0xbb, 0xcc])),
            auth_output: AuthTrace(vec![0xdd, 0xee]),
        };
        let item2 = AccumulateItem::WorkItem(record2);
        let items = vec![item2];
        let encoded_vec = items.encode();
        eprintln!("Encoded Vec<AccumulateItem>: {} bytes", encoded_vec.len());
        eprintln!("First 50 bytes: {:02x?}", &encoded_vec[..std::cmp::min(50, encoded_vec.len())]);
        
        let decoded_vec = Vec::<AccumulateItem>::decode(&mut &encoded_vec[..]);
        assert!(decoded_vec.is_ok(), "Failed to decode Vec: {:?}", decoded_vec.err());
    }
}

#[cfg(test)]
mod test_real_data {
    use super::*;
    use jam_codec::Decode;
    
    #[test]
    fn test_real_accumulate_item() {
        // Real data from trace: gas_limit = 10000000, result = 132 bytes OK
        let record = WorkItemRecord {
            package: WorkPackageHash([0xcd, 0x49, 0xf9, 0x88, 0xa7, 0x08, 0x33, 0x3a,
                                      0x27, 0x70, 0x49, 0x7a, 0x37, 0x78, 0x16, 0x98,
                                      0x89, 0x24, 0xd8, 0xb8, 0x76, 0x1d, 0x2e, 0x90,
                                      0x75, 0xdf, 0x8a, 0x59, 0x27, 0xae, 0x7f, 0x00]),
            exports_root: SegmentTreeRoot([0u8; 32]),
            authorizer_hash: AuthorizerHash([0u8; 32]),
            payload: PayloadHash([0u8; 32]),
            gas_limit: 10000000,  // Real value
            result: Ok(WorkOutput(vec![0xaa; 132])),  // 132 bytes like real data
            auth_output: AuthTrace(vec![0xbb; 7]),   // 7 bytes
        };
        
        let item = AccumulateItem::WorkItem(record);
        let encoded = item.encode();
        
        eprintln!("Real-data AccumulateItem: {} bytes", encoded.len());
        eprintln!("First 130 bytes: {:02x?}", &encoded[..std::cmp::min(130, encoded.len())]);
        eprintln!("After hashes (128+1): bytes 129-145: {:02x?}", &encoded[129..std::cmp::min(145, encoded.len())]);
        
        // Try to decode
        let decoded = AccumulateItem::decode(&mut &encoded[..]);
        match decoded {
            Ok(_) => eprintln!("Decode: SUCCESS"),
            Err(e) => eprintln!("Decode: FAILED - {:?}", e),
        }
        
        // Test Vec
        let record2 = WorkItemRecord {
            package: WorkPackageHash([0xcd; 32]),
            exports_root: SegmentTreeRoot([0u8; 32]),
            authorizer_hash: AuthorizerHash([0u8; 32]),
            payload: PayloadHash([0u8; 32]),
            gas_limit: 10000000,
            result: Ok(WorkOutput(vec![0xaa; 132])),
            auth_output: AuthTrace(vec![0xbb; 7]),
        };
        let items = vec![AccumulateItem::WorkItem(record2)];
        let encoded_vec = items.encode();
        eprintln!("\nVec<AccumulateItem>: {} bytes", encoded_vec.len());
        eprintln!("First 10 bytes: {:02x?}", &encoded_vec[..10]);
        
        let decoded_vec = Vec::<AccumulateItem>::decode(&mut &encoded_vec[..]);
        match decoded_vec {
            Ok(_) => eprintln!("Vec decode: SUCCESS"),
            Err(e) => eprintln!("Vec decode: FAILED - {:?}", e),
        }
    }
}
