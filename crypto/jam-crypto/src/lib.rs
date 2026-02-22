//! JAM Crypto FFI Library for JOTL
//!
//! Pure cryptographic primitives used by the Lisp JAM client.
//! The PVM (PolkaVM) is now implemented in Lisp — see src/jamvm/.
//!
//! Modules:
//! - `crypto`: Blake2b, Keccak, Bandersnatch VRF, Ed25519, BLS12-381
//! - `erasure`: Erasure coding (GP Appendix H)

pub mod crypto;
pub mod erasure;

// Re-export all public FFI functions
pub use crypto::*;
