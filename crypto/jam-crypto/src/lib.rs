//! JAM FFI Library for JOTL
//!
//! This is the main entry point for the FFI library.
//! All cryptographic, erasure coding, and PVM functions are re-exported here.
//!
//! Modules:
//! - `crypto`: Blake2b, Keccak, Bandersnatch VRF, Ed25519, BLS12-381
//! - `erasure`: Erasure coding (GP Appendix H)
//! - `pvm`: PolkaVM execution engine (GP Section 14)

pub mod crypto;
pub mod erasure;
pub mod pvm;

// Re-export all public FFI functions
pub use crypto::*;
pub use pvm::*;
