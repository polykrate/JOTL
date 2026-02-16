//! PolkaVM FFI for JAM PVM (GP Appendix A)
//!
//! Module structure (from general to particular):
//! - [`context`]: Types — JamHostContext, InvocationContext, errors, FetchKind
//! - [`host_calls`]: Ω — The canonical host-call dispatch table (GP Appendix B)
//! - [`engine`]: PolkaVM Engine / Module / Instance lifecycle
//! - [`run`]: JAM execution loop (`jam_run`, `jam_continue`)
//! - [`ffi`]: C-FFI accessors for JAM instance state
//! - [`encode`]: AccumulateItem encoding helpers

pub mod context;
pub mod host_calls;
pub mod engine;
pub mod run;
pub mod ffi;
pub mod encode;
pub mod wire;


// Re-export all public FFI symbols so `pub use pvm::*` in lib.rs works.
pub use engine::*;
pub use run::*;
pub use ffi::*;
pub use encode::*;
pub use wire::*;

// Re-export key types for external use.
pub use context::{
    InvocationContext, PvmOutcome, CollapseResult, AccumulateCheckpoint,
    ServiceAccount, WorkItemInfo,
    DEFAULT_SEGMENT_SIZE, DEFAULT_MAX_EXPORTS,
};
