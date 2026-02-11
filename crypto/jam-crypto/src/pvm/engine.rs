//! PolkaVM Engine / Module / Instance lifecycle (basic, no host functions)
//!
//! Provides C-FFI for creating engines, loading modules, and running programs
//! without JAM host call support. Used for generic PolkaVM execution and testing.

use polkavm::{Config, Engine, Module, ModuleConfig, ProgramBlob, Linker};
use jam_program_blob_common::ProgramBlob as JamProgramBlob;
use std::ffi::c_char;

// ============================================================================
// Opaque handles
// ============================================================================

/// Opaque handle to a PVM Engine
pub struct PvmEngine {
    pub(crate) engine: Engine,
}

/// Opaque handle to a PVM Module (compiled program)
pub struct PvmModule {
    pub(crate) module: Module,
}

/// Opaque handle to a pre-instantiated module (basic, no host functions)
pub struct PvmInstancePre {
    instance_pre: polkavm::InstancePre<()>,
}

/// Opaque handle to a PVM Instance (basic, no host functions)
pub struct PvmInstance {
    instance: polkavm::Instance<()>,
}

// ============================================================================
// Engine management
// ============================================================================

/// Create a new PVM engine with default configuration.
///
/// Returns pointer to engine, or null on failure.
#[no_mangle]
pub extern "C" fn pvm_engine_new() -> *mut PvmEngine {
    let config = Config::from_env().unwrap_or_else(|_| Config::new());
    match Engine::new(&config) {
        Ok(engine) => Box::into_raw(Box::new(PvmEngine { engine })),
        Err(e) => {
            log::debug!("pvm_engine_new: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Create a new PVM engine configured for JAM (interpreter backend).
///
/// Returns pointer to engine, or null on failure.
#[no_mangle]
pub extern "C" fn pvm_engine_new_jam() -> *mut PvmEngine {
    let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
    config.set_backend(Some(polkavm::BackendKind::Interpreter));
    match Engine::new(&config) {
        Ok(engine) => Box::into_raw(Box::new(PvmEngine { engine })),
        Err(e) => {
            log::debug!("pvm_engine_new_jam: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a PVM engine.
///
/// # Safety
/// `engine` must be a valid pointer from `pvm_engine_new*`, or null.
#[no_mangle]
pub unsafe extern "C" fn pvm_engine_free(engine: *mut PvmEngine) {
    if !engine.is_null() {
        drop(Box::from_raw(engine));
    }
}

// ============================================================================
// Module management
// ============================================================================

/// Load a PVM module from a raw `.polkavm` blob (PVM\0 magic).
///
/// # Safety
/// - `engine` must be a valid engine pointer.
/// - `blob` must point to `blob_len` valid bytes.
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

    let program_blob = match ProgramBlob::parse(blob_bytes.into()) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("pvm_module_load: parse failed: {:?}", e);
            return std::ptr::null_mut();
        }
    };
    let module_config = ModuleConfig::default();
    match Module::from_blob(engine, &module_config, program_blob) {
        Ok(module) => Box::into_raw(Box::new(PvmModule { module })),
        Err(e) => {
            log::debug!("pvm_module_load: module failed: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Load a PVM module from a JAM service blob (jam-pvm-build format).
///
/// # Safety
/// - `engine` must be a valid engine pointer.
/// - `blob` must point to `blob_len` valid bytes.
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

    let jam_blob = match JamProgramBlob::from_bytes(blob_bytes) {
        Some(b) => b,
        None => {
            log::debug!("pvm_module_load_jam: failed to parse JAM blob");
            return std::ptr::null_mut();
        }
    };

    let parts: polkavm::ProgramParts = jam_blob.into();
    let program_blob = match ProgramBlob::from_parts(parts) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("pvm_module_load_jam: blob from parts failed: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    let mut module_config = ModuleConfig::new();
    module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));

    match Module::from_blob(engine, &module_config, program_blob) {
        Ok(module) => Box::into_raw(Box::new(PvmModule { module })),
        Err(e) => {
            log::debug!("pvm_module_load_jam: module failed: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a PVM module.
///
/// # Safety
/// `module` must be a valid pointer from `pvm_module_load*`, or null.
#[no_mangle]
pub unsafe extern "C" fn pvm_module_free(module: *mut PvmModule) {
    if !module.is_null() {
        drop(Box::from_raw(module));
    }
}

// ============================================================================
// Basic Instance management (no host functions)
// ============================================================================

/// Create a pre-instantiated module (basic, no host functions).
///
/// # Safety
/// `module` must be a valid module pointer.
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_pre_new(module: *mut PvmModule) -> *mut PvmInstancePre {
    if module.is_null() {
        return std::ptr::null_mut();
    }
    let module = &(*module).module;
    let linker = Linker::<()>::new();
    match linker.instantiate_pre(module) {
        Ok(instance_pre) => Box::into_raw(Box::new(PvmInstancePre { instance_pre })),
        Err(e) => {
            log::debug!("pvm_instance_pre_new: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a pre-instance.
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_pre_free(pre: *mut PvmInstancePre) {
    if !pre.is_null() {
        drop(Box::from_raw(pre));
    }
}

/// Create a new PVM instance from a pre-instance.
///
/// # Safety
/// `pre` must be a valid pre-instance pointer.
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_new(pre: *mut PvmInstancePre) -> *mut PvmInstance {
    if pre.is_null() {
        return std::ptr::null_mut();
    }
    let pre = &(*pre).instance_pre;
    match pre.instantiate() {
        Ok(instance) => Box::into_raw(Box::new(PvmInstance { instance })),
        Err(e) => {
            log::debug!("pvm_instance_new: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a PVM instance.
///
/// # Safety
/// `instance` must be a valid pointer from `pvm_instance_new`, or null.
#[no_mangle]
pub unsafe extern "C" fn pvm_instance_free(instance: *mut PvmInstance) {
    if !instance.is_null() {
        drop(Box::from_raw(instance));
    }
}

// ============================================================================
// Basic execution
// ============================================================================

/// Run a PVM instance to completion (no host call handling).
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `result` must point to a valid u64.
///
/// # Returns
/// 0=success, 1=null, 4=error, 5=trap, 6=ecalli, 7=other
#[no_mangle]
pub unsafe extern "C" fn pvm_run(instance: *mut PvmInstance, result: *mut u64) -> u32 {
    if instance.is_null() || result.is_null() {
        return 1;
    }
    let instance = &mut (*instance).instance;
    match instance.run() {
        Ok(interrupt) => {
            *result = instance.reg(polkavm::Reg::A0);
            match interrupt {
                polkavm::InterruptKind::Finished => 0,
                polkavm::InterruptKind::Trap => 5,
                polkavm::InterruptKind::Ecalli(_) => 6,
                _ => 7,
            }
        }
        Err(e) => {
            log::debug!("pvm_run: {:?}", e);
            4
        }
    }
}

// ============================================================================
// Register access
// ============================================================================

fn map_reg(reg: u32) -> Option<polkavm::Reg> {
    match reg {
        0 => Some(polkavm::Reg::RA),
        1 => Some(polkavm::Reg::SP),
        2 => Some(polkavm::Reg::T0),
        3 => Some(polkavm::Reg::T1),
        4 => Some(polkavm::Reg::T2),
        5 => Some(polkavm::Reg::S0),
        6 => Some(polkavm::Reg::S1),
        7 => Some(polkavm::Reg::A0),
        8 => Some(polkavm::Reg::A1),
        9 => Some(polkavm::Reg::A2),
        10 => Some(polkavm::Reg::A3),
        11 => Some(polkavm::Reg::A4),
        12 => Some(polkavm::Reg::A5),
        _ => None,
    }
}

/// Set a register value.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn pvm_set_reg(instance: *mut PvmInstance, reg: u32, value: u64) {
    if instance.is_null() {
        return;
    }
    if let Some(r) = map_reg(reg) {
        (*instance).instance.set_reg(r, value);
    }
}

/// Get a register value.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn pvm_get_reg(instance: *mut PvmInstance, reg: u32) -> u64 {
    if instance.is_null() {
        return 0;
    }
    match map_reg(reg) {
        Some(r) => (*instance).instance.reg(r),
        None => 0,
    }
}

// ============================================================================
// Memory access
// ============================================================================

/// Read memory from a PVM instance.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `output` must point to `len` writable bytes.
///
/// Returns 0 on success, non-zero on failure.
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
    let inst = &(*instance).instance;
    let out = std::slice::from_raw_parts_mut(output, len);
    match inst.read_memory_into(address, out) {
        Ok(_) => 0,
        Err(_) => 2,
    }
}

/// Write memory to a PVM instance.
///
/// # Safety
/// - `instance` must be a valid instance pointer.
/// - `data` must point to `len` valid bytes.
///
/// Returns 0 on success, non-zero on failure.
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
    let inst = &mut (*instance).instance;
    let data = std::slice::from_raw_parts(data, len);
    match inst.write_memory(address, data) {
        Ok(()) => 0,
        Err(_) => 2,
    }
}

// ============================================================================
// Gas metering (basic)
// ============================================================================

/// Set gas limit for a basic PVM instance.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn pvm_set_gas(instance: *mut PvmInstance, gas: i64) {
    if !instance.is_null() {
        (*instance).instance.set_gas(gas);
    }
}

/// Get remaining gas from a basic PVM instance.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn pvm_get_gas(instance: *mut PvmInstance) -> i64 {
    if instance.is_null() {
        return 0;
    }
    (*instance).instance.gas()
}

// ============================================================================
// Utility
// ============================================================================

/// Get the PVM version string. Returns a static string, do not free.
#[no_mangle]
pub extern "C" fn pvm_version() -> *const c_char {
    static VERSION: &[u8] = b"polkavm-0.29\0";
    VERSION.as_ptr() as *const c_char
}

// ============================================================================
// Tests
// ============================================================================

// Tests — extracted to pvm/tests/test_engine.rs
#[cfg(test)]
#[path = "tests/test_engine.rs"]
mod tests;
