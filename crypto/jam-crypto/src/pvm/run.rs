//! JAM execution loop — `jam_run` / `jam_continue` (GP Appendix A)
//!
//! Manages JAM instance lifecycle (pre-instance, instance) and the main
//! PVM execution loop that dispatches host calls via [`super::host_calls::dispatch`].

use polkavm::{Linker, Reg, ProgramCounter};
use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::context::{JamHostContext, JamHostError, JamInstancePre, JamInstance, InvocationContext};
use super::engine::PvmModule;
use super::encode::encode_gp_constants;
use super::host_calls;

use jam_types::ProtocolParameters;

// ============================================================================
// JAM Instance lifecycle
// ============================================================================

/// Create a JAM-enabled pre-instance with host function support.
///
/// # Safety
/// `module` must be a valid module pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_pre_new(module: *mut PvmModule) -> *mut JamInstancePre {
    if module.is_null() {
        return std::ptr::null_mut();
    }
    let module_ref = &(*module).module;

    // Empty linker — all host calls dispatched manually in the run loop.
    let linker = Linker::<JamHostContext, JamHostError>::new();

    match linker.instantiate_pre(module_ref) {
        Ok(instance_pre) => Box::into_raw(Box::new(JamInstancePre { instance_pre })),
        Err(e) => {
            log::debug!("jam_instance_pre_new: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a JAM pre-instance.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_pre_free(pre: *mut JamInstancePre) {
    if !pre.is_null() {
        drop(Box::from_raw(pre));
    }
}

/// Create a new JAM instance with initial context.
///
/// # Safety
/// `pre` must be a valid pre-instance pointer.
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

    // Default protocol parameters (TINY chainspec)
    let params = ProtocolParameters::tiny();
    let encoded_params = encode_gp_constants(&params);

    let context = JamHostContext {
        service_id,
        balance,
        slot,
        protocol_params: encoded_params,
        min_turnaround_period: params.min_turnaround_period,
        ..Default::default()
    };

    match pre_ref.instantiate() {
        Ok(instance) => Box::into_raw(Box::new(JamInstance { instance, context })),
        Err(e) => {
            log::debug!("jam_instance_new: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free a JAM instance.
#[no_mangle]
pub unsafe extern "C" fn jam_instance_free(instance: *mut JamInstance) {
    if !instance.is_null() {
        drop(Box::from_raw(instance));
    }
}

// ============================================================================
// Gas metering (JAM)
// ============================================================================

/// Set gas limit for a JAM instance.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_set_gas(instance: *mut JamInstance, gas: i64) {
    if !instance.is_null() {
        (*instance).instance.set_gas(gas);
    }
}

/// Get remaining gas from a JAM instance.
///
/// # Safety
/// `instance` must be a valid instance pointer.
#[no_mangle]
pub unsafe extern "C" fn jam_get_gas(instance: *mut JamInstance) -> i64 {
    if instance.is_null() {
        return 0;
    }
    (*instance).instance.gas()
}

// ============================================================================
// Execution
// ============================================================================

/// Run a JAM instance from the given entry point.
///
/// Entry points map to fixed ProgramCounter offsets:
/// - `is_authorized_ext` / `refine_ext` → PC(0)
/// - `accumulate_ext` → PC(5)
/// - `on_transfer_ext` → PC(10)
///
/// Host calls (ecalli) are dispatched via [`host_calls::dispatch`].
///
/// # Safety
/// - `instance` must be a valid JAM instance pointer.
/// - `result` must point to a valid u64.
/// - `entry_point` must be a valid null-terminated C string, or null.
///
/// # Returns
/// 0=success, 1=null, 2=bad-utf8, 4=error, 5=trap, 6=oog, 7=host-err, 8=step
#[no_mangle]
pub unsafe extern "C" fn jam_run(
    instance: *mut JamInstance,
    entry_point: *const c_char,
    result: *mut u64,
) -> u32 {
    if instance.is_null() || result.is_null() {
        return 1;
    }
    let jam = &mut (*instance);

    // ── Parse entry point name ──────────────────────────────────
    let entry_name = if entry_point.is_null() {
        "main"
    } else {
        match std::ffi::CStr::from_ptr(entry_point).to_str() {
            Ok(s) => s,
            Err(_) => return 2,
        }
    };

    // ── Map entry point → (PC, InvocationContext) ──────────────
    let (pc, invocation): (u32, InvocationContext) = match entry_name {
        "is_authorized_ext" => (0, InvocationContext::IsAuthorized),
        "refine_ext"        => (0, InvocationContext::Refine),
        "accumulate_ext"    => (5, InvocationContext::Accumulate),
        "on_transfer_ext"   => (10, InvocationContext::OnTransfer),
        _ => {
            // Try named export
            match jam.instance.call_typed(&mut jam.context, entry_name, ()) {
                Ok(()) => {
                    *result = jam.instance.reg(Reg::A0);
                    return 0;
                }
                Err(polkavm::CallError::Error(e)) if e.to_string().contains("export not found") => {
                    log::debug!("jam_run: unknown '{}', fallback PC=0", entry_name);
                    (0, InvocationContext::Accumulate)
                }
                Err(e) => return call_error_to_code(&jam.instance, e, result),
            }
        }
    };

    // Set the invocation context BEFORE execution begins
    jam.context.invocation = invocation;
    log::debug!("jam_run: PC={} ctx={:?} for '{}'", pc, invocation, entry_name);

    // ── Prepare arguments per GP B.1/B.5/B.9 ────────────────────
    let args_data: Vec<u8> = {
        use jam_types::Encode;
        match invocation {
            InvocationContext::IsAuthorized => {
                // B.1: is_authorized_ext(c) — just the core index
                let params = jam_types::IsAuthorizedParams {
                    core: jam.context.core_index,
                };
                params.encode()
            }
            InvocationContext::Refine => {
                // B.5: refine_ext(c, i, w_s, payload, H(p))
                let params = jam_types::RefineParams {
                    core_index: jam.context.core_index,
                    item_index: jam.context.work_item_index,
                    service_id: jam.context.service_id,
                    payload: jam_types::WorkPayload(jam.context.payload.clone()),
                    package_hash: jam_types::WorkPackageHash(jam.context.package_hash),
                };
                params.encode()
            }
            InvocationContext::Accumulate | InvocationContext::OnTransfer => {
                // B.9: accumulate_ext(slot, service_id, item_count)
                let item_count = jam.context.accumulate_items.len() as u32;
                eprintln!(
                    "[JOTL-PVM] accumulate_ext: slot={} sid={} item_count={} items_sizes={:?}",
                    jam.context.slot, jam.context.service_id, item_count,
                    jam.context.accumulate_items.iter().map(|i| i.len()).collect::<Vec<_>>()
                );
                let params = jam_types::AccumulateParams {
                    slot: jam.context.slot,
                    service_id: jam.context.service_id,
                    item_count,
                };
                let encoded = params.encode();
                eprintln!("[JOTL-PVM] AccumulateParams encoded ({} bytes): {:02x?}", encoded.len(), &encoded);
                encoded
            }
        }
    };

    // Allocate via sbrk and write args
    let args_addr: u32 = if !args_data.is_empty() {
        let aligned = ((args_data.len() + 7) & !7) as u32;
        match jam.instance.sbrk(aligned) {
            Ok(Some(heap_top)) => {
                let start = heap_top.saturating_sub(aligned);
                if jam.instance.write_memory(start, &args_data).is_ok() {
                    log::debug!("jam_run: args {} bytes @ 0x{:x}", args_data.len(), start);
                    start
                } else {
                    log::warn!("jam_run: failed to write args");
                    0
                }
            }
            _ => {
                log::warn!("jam_run: sbrk failed");
                0
            }
        }
    } else {
        0
    };

    // ── Set up registers and start execution ────────────────────
    jam.instance.prepare_call_untyped(
        ProgramCounter(pc),
        &[args_addr as u64, args_data.len() as u64],
    );

    // ── Main execution loop ─────────────────────────────────────
    let run_result = execution_loop(jam);

    match run_result {
        Ok(()) => {
            *result = jam.instance.reg(Reg::A0);
            0
        }
        Err(e) => call_error_to_code(&jam.instance, e, result),
    }
}

/// Continue execution of a JAM instance (resume after interrupt).
///
/// # Safety
/// - `instance` must be a valid JAM instance pointer.
/// - `result` must point to a valid u64.
///
/// # Returns
/// Same codes as `jam_run`.
#[no_mangle]
pub unsafe extern "C" fn jam_continue(instance: *mut JamInstance, result: *mut u64) -> u32 {
    if instance.is_null() || result.is_null() {
        return 1;
    }
    let jam = &mut (*instance);

    let run_result = execution_loop(jam);

    match run_result {
        Ok(()) => {
            *result = jam.instance.reg(Reg::A0);
            0
        }
        Err(e) => call_error_to_code(&jam.instance, e, result),
    }
}

// ============================================================================
// Internal
// ============================================================================

/// The core execution loop: run → dispatch ecalli → repeat until done/trap/oog.
fn execution_loop(
    jam: &mut JamInstance,
) -> Result<(), polkavm::CallError<JamHostError>> {
    loop {
        let step = catch_unwind(AssertUnwindSafe(|| jam.instance.run()));

        match step {
            Ok(Ok(polkavm::InterruptKind::Finished)) => break Ok(()),
            Ok(Ok(polkavm::InterruptKind::Trap)) => break Err(polkavm::CallError::Trap),
            Ok(Ok(polkavm::InterruptKind::NotEnoughGas)) => {
                break Err(polkavm::CallError::NotEnoughGas)
            }
            Ok(Ok(polkavm::InterruptKind::Ecalli(id))) => {
                match host_calls::dispatch(
                    &mut jam.instance,
                    &mut jam.context,
                    id,
                ) {
                    Ok(host_calls::DispatchResult::Continue) => {
                        // resume execution after the ecalli
                    }
                    Ok(host_calls::DispatchResult::OutOfGas) => {
                        // B.16: ϱ < g → (∞, φ, μ, s) — no mutations
                        break Err(polkavm::CallError::NotEnoughGas);
                    }
                    Ok(host_calls::DispatchResult::Fault) => {
                        // (♯) page fault during host call
                        break Err(polkavm::CallError::Trap);
                    }
                    Err(_) => {
                        break Err(polkavm::CallError::Trap);
                    }
                }
            }
            Ok(Ok(polkavm::InterruptKind::Segfault(addr))) => {
                log::debug!("jam_run: segfault at {:?}", addr);
                break Err(polkavm::CallError::Trap);
            }
            Ok(Ok(polkavm::InterruptKind::Step)) => break Err(polkavm::CallError::Step),
            Ok(Err(e)) => break Err(polkavm::CallError::Error(e)),
            Err(_panic) => {
                log::warn!("PVM execution panicked");
                break Err(polkavm::CallError::Trap);
            }
        }
    }
}

/// Convert a polkavm `CallError` to a u32 FFI return code.
unsafe fn call_error_to_code(
    inst: &polkavm::Instance<JamHostContext, JamHostError>,
    e: polkavm::CallError<JamHostError>,
    result: *mut u64,
) -> u32 {
    match e {
        polkavm::CallError::Trap => {
            *result = inst.reg(Reg::A0);
            5
        }
        polkavm::CallError::NotEnoughGas => {
            *result = 0;
            6
        }
        polkavm::CallError::User(h) => {
            *result = h as u64;
            7
        }
        polkavm::CallError::Error(err) => {
            log::debug!("jam_run: {:?}", err);
            4
        }
        polkavm::CallError::Step => {
            *result = inst.reg(Reg::A0);
            8
        }
    }
}
