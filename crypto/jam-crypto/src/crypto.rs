//! JAM Crypto FFI
//!
//! Provides C-compatible functions for cryptographic operations required by JAM M1:
//! - Blake2b-256 (hashing)
//! - Bandersnatch VRF (block sealing, tickets) via ark-vrf
//! - Ed25519 (validator signatures)
//! - Erasure coding (GP Appendix H)
//!
//! Build: cargo build --release
//! Output: target/release/libjam_crypto.so (or .dylib on macOS)

use crate::erasure;


use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
use sha3::Keccak256;

type Blake2b256 = Blake2b<U32>;

// ============================================================================
// Blake2b-256 (GP Appendix A.1)
// ============================================================================

/// Blake2b-256 hash function
///
/// # Safety
/// - `input` must point to `len` valid bytes
/// - `output` must point to 32 writable bytes
#[no_mangle]
pub unsafe extern "C" fn blake2b_256(input: *const u8, len: usize, output: *mut u8) {
    if input.is_null() || output.is_null() {
        return;
    }

    let data = std::slice::from_raw_parts(input, len);
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let result = hasher.finalize();

    std::ptr::copy_nonoverlapping(result.as_ptr(), output, 32);
}

// ============================================================================
// Keccak-256 (Legacy Ethereum-style, for MMR - GP Appendix E)
// ============================================================================

/// Keccak-256 hash function (legacy Ethereum-style, NOT SHA3-256)
///
/// Used for MMR peak merging in JAM (GP Appendix E.10).
/// This is the original Keccak algorithm before SHA3 standardization.
///
/// # Safety
/// - `input` must point to `len` valid bytes
/// - `output` must point to 32 writable bytes
#[no_mangle]
pub unsafe extern "C" fn keccak_256(input: *const u8, len: usize, output: *mut u8) {
    if input.is_null() || output.is_null() {
        return;
    }

    let data = std::slice::from_raw_parts(input, len);
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();

    std::ptr::copy_nonoverlapping(result.as_ptr(), output, 32);
}

// ============================================================================
// Bandersnatch VRF (GP Appendix A.2) - via ark-vrf
// ============================================================================

use ark_vrf::suites::bandersnatch::{
    AffinePoint, Input, Output, Public, IetfProof, BandersnatchSha512Ell2,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[cfg(feature = "ring")]
use ark_vrf::suites::bandersnatch::RingProof;
#[cfg(feature = "ring")]
use ark_vrf::ring::RingProofParams;

/// Ring VRF signature structure matching the spec
#[cfg(feature = "ring")]
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    proof: RingProof,
}

/// Verify a Bandersnatch IETF VRF proof (used for block sealing)
///
/// GP Appendix G.1: V̂ₖᵐᴮ(c) — verify(k, c, m, x) = T
///   k = public key, c = VRF input, m = additional data, x = signature
///
/// # Safety
/// - `public_key`: 32 bytes (compressed Bandersnatch point)
/// - `vrf_input`: arbitrary bytes that will be hashed to curve
/// - `vrf_input_len`: length of vrf_input
/// - `vrf_output`: 32 bytes (compressed curve point)
/// - `proof`: IETF VRF proof (variable size, typically ~64 bytes)
/// - `proof_len`: length of proof
/// - `ad`: additional data bytes (GP §6.4: header serialization without seal)
/// - `ad_len`: length of ad
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_verify_vrf(
    public_key: *const u8,
    vrf_input: *const u8,
    vrf_input_len: usize,
    vrf_output: *const u8,
    proof: *const u8,
    proof_len: usize,
    ad: *const u8,
    ad_len: usize,
) -> bool {
    if public_key.is_null() || vrf_input.is_null() || vrf_output.is_null() || proof.is_null() {
        return false;
    }

    let pk_bytes = std::slice::from_raw_parts(public_key, 32);
    let input_bytes = std::slice::from_raw_parts(vrf_input, vrf_input_len);
    let output_bytes = std::slice::from_raw_parts(vrf_output, 32);
    let proof_bytes = std::slice::from_raw_parts(proof, proof_len);
    let ad_bytes = if ad.is_null() || ad_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ad, ad_len)
    };

    // Deserialize public key
    let public = match Public::deserialize_compressed(&pk_bytes[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Create VRF input from bytes (returns Option)
    let input = match Input::new(input_bytes) {
        Some(i) => i,
        None => return false,
    };

    // Deserialize expected output
    let output = match Output::deserialize_compressed(&output_bytes[..]) {
        Ok(o) => o,
        Err(_) => return false,
    };

    // Deserialize proof
    let proof = match IetfProof::deserialize_compressed(&proof_bytes[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Verify using IETF VRF trait — ad is the additional data (GP §G.1: m parameter)
    use ark_vrf::ietf::Verifier;
    public.verify(input, output, ad_bytes, &proof).is_ok()
}

/// Extract VRF output hash (Y function) from a Bandersnatch VRF signature
///
/// This implements the Y function from Gray Paper Appendix G.2:
/// Y(s) ≡ output(s)...32
///
/// Used for entropy accumulation (GP 6.22):
/// η0' ≡ H(η0 ⌢ Y(HV))
///
/// # Safety
/// - `vrf_signature`: 96 bytes (Bandersnatch VRF signature, typically block seal or VRF signature)
/// - `output_hash`: 32 bytes (output buffer for the VRF output hash)
///
/// # Returns
/// - true if successful, false if the signature is invalid
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_output_hash(
    vrf_signature: *const u8,
    vrf_signature_len: usize,
    output_hash: *mut u8,
) -> bool {
    if vrf_signature.is_null() || output_hash.is_null() {
        return false;
    }

    let sig_bytes = std::slice::from_raw_parts(vrf_signature, vrf_signature_len);
    let out_buf = std::slice::from_raw_parts_mut(output_hash, 32);

    // Try to deserialize as IETF VRF signature (variable length, typically ~80 bytes)
    // The signature contains the output and proof
    // We can extract the output point and hash it
    
    // For Bandersnatch VRF, the signature format includes the output
    // Try to extract the first 32 bytes as the output point
    if vrf_signature_len < 32 {
        return false;
    }

    // Deserialize the output point from the signature
    // The signature typically starts with the output point (32 bytes compressed)
    let output_bytes = &sig_bytes[0..32];
    let output = match Output::deserialize_compressed(&output_bytes[..]) {
        Ok(o) => o,
        Err(_) => {
            // If direct deserialization fails, the signature might be in a different format
            // For block seals, the full signature is 96 bytes
            // Try alternative extraction methods
            return false;
        }
    };

    // Compute the output hash using the VRF's hash function
    // This corresponds to the Y function in the Gray Paper
    let vrf_hash = output.hash();
    let vrf_hash_bytes: &[u8] = vrf_hash.as_ref();
    
    // Copy the hash to output buffer (first 32 bytes)
    let copy_len = std::cmp::min(32, vrf_hash_bytes.len());
    out_buf[..copy_len].copy_from_slice(&vrf_hash_bytes[..copy_len]);
    
    true
}

/// Verify a Bandersnatch Ring VRF proof (anonymous validator ticket)
///
/// Ring VRF allows proving membership in a set without revealing which member.
/// Used for anonymous ticket submission in JAM/Safrole.
///
/// # Safety
/// - `ring_params`: Serialized RingProofParams (from SRS)
/// - `ring_pks`: V * 32 bytes (V compressed Bandersnatch points)
/// - `vrf_input`: 32 bytes
/// - `vrf_output`: 32 bytes
/// - `ring_proof`: Ring proof bytes (variable size)
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_verify_ring_vrf(
    ring_params: *const u8,
    ring_params_len: usize,
    ring_pks: *const u8,
    num_validators: usize,
    vrf_input: *const u8,
    vrf_output: *const u8,
    ring_proof: *const u8,
    proof_len: usize,
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (ring_params, ring_params_len, ring_pks, num_validators, vrf_input, vrf_output, ring_proof, proof_len);
        eprintln!("Ring VRF not enabled (compile with --features ring)");
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        if ring_params.is_null()
            || ring_pks.is_null()
            || vrf_input.is_null()
            || vrf_output.is_null()
            || ring_proof.is_null()
        {
            return false;
        }

        let params_bytes = std::slice::from_raw_parts(ring_params, ring_params_len);
        let pks_bytes = std::slice::from_raw_parts(ring_pks, num_validators * 32);
        let input_bytes = std::slice::from_raw_parts(vrf_input, 32);
        let output_bytes = std::slice::from_raw_parts(vrf_output, 32);
        let proof_bytes = std::slice::from_raw_parts(ring_proof, proof_len);

        // Deserialize ring params (SRS)
        let params: RingProofParams<ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2> = 
            match RingProofParams::deserialize_compressed(&params_bytes[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };

        // Deserialize all public keys into ring
        let mut ring: Vec<AffinePoint> = Vec::with_capacity(num_validators);
        for i in 0..num_validators {
            let pk_slice = &pks_bytes[i * 32..(i + 1) * 32];
            match Public::deserialize_compressed(&pk_slice[..]) {
                Ok(pk) => ring.push(pk.0),
                Err(_) => return false,
            }
        }

        // Create VRF input
        let input = match Input::new(input_bytes) {
            Some(i) => i,
            None => return false,
        };

        // Deserialize output
        let output = match Output::deserialize_compressed(&output_bytes[..]) {
            Ok(o) => o,
            Err(_) => return false,
        };

        // Deserialize ring proof
        let proof = match RingProof::deserialize_compressed(&proof_bytes[..]) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Construct verifier key from ring
        let verifier_key = params.verifier_key(&ring);
        let verifier = params.verifier(verifier_key);

        // Verify ring VRF
        use ark_vrf::ring::Verifier;
        Public::verify(input, output, &[], &proof, &verifier).is_ok()
    }
}

/// Verify a Bandersnatch Ring VRF signature using pre-computed ring commitment (gamma_z)
///
/// The signature format is: [VRF output: 32] [Pedersen proof: 160] [Ring proof: 592]
///
/// # Safety
/// - `srs_data`: Zcash SRS file contents (590KB for domain 2^11)
/// - `ring_size`: The ring size (6 for tiny, 1023 for full)
/// - `ring_commitment`: gamma_z (144 bytes pre-computed ring commitment)
/// - `vrf_input`: arbitrary bytes for VRF input (will be hashed to curve)
/// - `aux_data`: additional data that is signed but doesn't affect output
/// - `signature`: 784 bytes ring VRF signature
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_verify_ring_vrf_with_commitment(
    srs_data: *const u8,
    srs_len: usize,
    ring_size: usize,  // ADDED: ring size parameter
    ring_commitment: *const u8,  // 144 bytes gamma_z
    vrf_input: *const u8,
    vrf_input_len: usize,
    aux_data: *const u8,
    aux_data_len: usize,
    signature: *const u8,  // 784 bytes
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_size, ring_commitment, vrf_input, vrf_input_len, aux_data, aux_data_len, signature);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        use ark_vrf::suites::bandersnatch::PcsParams;
        
        if srs_data.is_null() || ring_commitment.is_null() || vrf_input.is_null() || signature.is_null() {
            return false;
        }
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let commitment_bytes = std::slice::from_raw_parts(ring_commitment, 144);
        let input_bytes = std::slice::from_raw_parts(vrf_input, vrf_input_len);
        let aux_bytes = if aux_data.is_null() { &[] } else { std::slice::from_raw_parts(aux_data, aux_data_len) };
        let sig_bytes = std::slice::from_raw_parts(signature, 784);
        
        // JAM signature format: [output: 32] [proof: 752]
        let output_bytes = &sig_bytes[0..32];
        let proof_bytes = &sig_bytes[32..784];
        
        // CORRECT: First deserialize PcsParams, then create RingProofParams with ring_size
        let pcs_params: PcsParams = 
            match PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..]) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to deserialize PCS params: {:?}", e);
                    return false;
                }
            };
        
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::from_pcs_params(ring_size, pcs_params) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to create RingProofParams: {:?}", e);
                    return false;
                }
            };
        
        // Deserialize ring commitment (gamma_z)
        // Try compressed first, then uncompressed (JAM may use different serialization)
        let commitment: ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2> = 
            match ark_vrf::ring::RingCommitment::<BandersnatchSha512Ell2>::deserialize_compressed(&commitment_bytes[..]) {
                Ok(c) => c,
                Err(_e1) => {
                    // Try uncompressed format
                    match ark_vrf::ring::RingCommitment::<BandersnatchSha512Ell2>::deserialize_uncompressed(&commitment_bytes[..]) {
                        Ok(c) => c,
                        Err(_e2) => {
                            // Try unchecked as last resort
                            match ark_vrf::ring::RingCommitment::<BandersnatchSha512Ell2>::deserialize_uncompressed_unchecked(&commitment_bytes[..]) {
                                Ok(c) => c,
                                Err(e3) => {
                                    eprintln!("Failed to deserialize ring commitment: {:?}", e3);
                    return false;
                                }
                            }
                        }
                    }
                }
            };
        
        // Build verifier from commitment
        let verifier_key = params.verifier_key_from_commitment(commitment);
        let verifier = params.verifier(verifier_key);
        
        // Deserialize VRF output
        let output = match Output::deserialize_compressed(&output_bytes[..]) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Failed to deserialize VRF output: {:?}", e);
                return false;
            }
        };
        
        // Deserialize proof
        let proof = match RingProof::deserialize_compressed(&proof_bytes[..]) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to deserialize proof: {:?}", e);
                return false;
            }
        };
        
        // Create VRF input (hash to curve)
        let input = match Input::new(input_bytes) {
            Some(i) => i,
            None => {
                eprintln!("Failed to create VRF input");
                return false;
            }
        };
        
        
        // Verify
        use ark_vrf::ring::Verifier;
        match Public::verify(input, output, aux_bytes, &proof, &verifier) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}

/// Verify a Bandersnatch Ring VRF signature and return the VRF output hash (ticket ID)
///
/// Unlike `bandersnatch_verify_ring_vrf_with_commitment`, this function also returns
/// the computed VRF output hash (32 bytes) which is used as the ticket ID for sorting
/// and duplicate detection.
///
/// # Returns
/// - 0 if verification succeeds, non-zero error code otherwise
/// - The VRF output hash is written to `vrf_output_hash` (32 bytes)
///
/// # Safety
/// - `vrf_output_hash`: pointer to 32 bytes buffer for the output hash
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_verify_ring_vrf_with_output(
    srs_data: *const u8,
    srs_len: usize,
    ring_size: usize,
    ring_commitment: *const u8,  // 144 bytes gamma_z
    vrf_input: *const u8,
    vrf_input_len: usize,
    aux_data: *const u8,
    aux_data_len: usize,
    signature: *const u8,  // 784 bytes
    vrf_output_hash: *mut u8,  // OUTPUT: 32 bytes for ticket ID
) -> u32 {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_size, ring_commitment, vrf_input, vrf_input_len, aux_data, aux_data_len, signature, vrf_output_hash);
        return 1; // Ring VRF not enabled
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        use ark_vrf::suites::bandersnatch::PcsParams;
        if srs_data.is_null() || ring_commitment.is_null() || vrf_input.is_null() || signature.is_null() || vrf_output_hash.is_null() {
            return 2; // Null pointer
        }
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let commitment_bytes = std::slice::from_raw_parts(ring_commitment, 144);
        let input_bytes = std::slice::from_raw_parts(vrf_input, vrf_input_len);
        let aux_bytes = if aux_data.is_null() { &[] } else { std::slice::from_raw_parts(aux_data, aux_data_len) };
        let sig_bytes = std::slice::from_raw_parts(signature, 784);
        let output_hash_buf = std::slice::from_raw_parts_mut(vrf_output_hash, 32);
        
        // JAM signature format: [output: 32] [proof: 752]
        let output_bytes = &sig_bytes[0..32];
        let proof_bytes = &sig_bytes[32..784];
        
        // Deserialize PCS params
        let pcs_params: PcsParams = 
            match PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..]) {
                Ok(p) => p,
                Err(_) => return 3, // PCS params error
            };
        
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::from_pcs_params(ring_size, pcs_params) {
                Ok(p) => p,
                Err(_) => return 4, // Ring params error
            };
        
        // Deserialize ring commitment (gamma_z)
        let commitment: ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2> = 
            match ark_vrf::ring::RingCommitment::<BandersnatchSha512Ell2>::deserialize_compressed(&commitment_bytes[..]) {
                Ok(c) => c,
                Err(_) => return 5, // Commitment error
            };
        
        let verifier_key = params.verifier_key_from_commitment(commitment);
        let verifier = params.verifier(verifier_key);
        
        // Deserialize VRF output
        let output = match Output::deserialize_compressed(&output_bytes[..]) {
            Ok(o) => o,
            Err(_) => return 6, // Output error
        };
        
        // Deserialize proof
        let proof = match RingProof::deserialize_compressed(&proof_bytes[..]) {
            Ok(p) => p,
            Err(_) => return 7, // Proof error
        };
        
        // Create VRF input (hash to curve)
        let input = match Input::new(input_bytes) {
            Some(i) => i,
            None => return 8, // Input error
        };
        
        // Verify
        use ark_vrf::ring::Verifier;
        match Public::verify(input, output.clone(), aux_bytes, &proof, &verifier) {
            Ok(()) => {
                // Compute ticket ID using RFC 9381 point_to_hash
                // This matches GP Appendix G: Y(p) = output(...)...32
                let vrf_hash = output.hash();
                let vrf_hash_bytes: &[u8] = vrf_hash.as_ref();
                let copy_len = std::cmp::min(32, vrf_hash_bytes.len());
                output_hash_buf[..copy_len].copy_from_slice(&vrf_hash_bytes[..copy_len]);
                0 // Success
            },
            Err(_) => 9, // Verification failed
        }
    }
}

/// Debug: Compute ring commitment from keys and compare with expected
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_debug_ring_commitment(
    srs_data: *const u8,
    srs_len: usize,
    ring_pks: *const u8,  // V * 32 bytes
    num_validators: usize,
    expected_commitment: *const u8,  // 144 bytes
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_pks, num_validators, expected_commitment);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        use ark_vrf::suites::bandersnatch::PcsParams;
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let pks_bytes = std::slice::from_raw_parts(ring_pks, num_validators * 32);
        let expected_bytes = std::slice::from_raw_parts(expected_commitment, 144);
        
        // CORRECT: First load PcsParams, then create RingProofParams with ring_size
        let pcs_params: PcsParams = 
            match PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..]) {
                Ok(p) => p,
                Err(_) => {
                    return false;
                }
            };
        
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::from_pcs_params(num_validators, pcs_params) {
                Ok(p) => p,
                Err(_) => {
                    return false;
                }
            };
        
        // Build ring from public keys
        let mut ring = Vec::with_capacity(num_validators);
        for i in 0..num_validators {
            let pk_bytes = &pks_bytes[i*32..(i+1)*32];
            match Public::deserialize_compressed(&pk_bytes[..]) {
                Ok(pk) => ring.push(pk.0),
                Err(_e) => {
                    return false;
                }
            }
        }
        
        // Compute ring commitment
        let verifier_key = params.verifier_key(&ring);
        let computed = verifier_key.commitment();
        
        // Serialize computed commitment
        let mut computed_bytes = Vec::new();
        computed.serialize_compressed(&mut computed_bytes).unwrap();
        
        // Compare
        computed_bytes == expected_bytes
    }
}

/// Compute ring commitment (γz) from validator public keys
///
/// # Safety
/// - `srs_data`: Zcash SRS file contents
/// - `ring_pks`: V * 32 bytes (V compressed Bandersnatch points)
/// - `output`: Buffer for 144-byte ring commitment
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_compute_ring_commitment(
    srs_data: *const u8,
    srs_len: usize,
    ring_pks: *const u8,
    num_validators: usize,
    output: *mut u8,
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_pks, num_validators, output);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        use ark_vrf::suites::bandersnatch::PcsParams;
        
        if srs_data.is_null() || ring_pks.is_null() || output.is_null() {
            return false;
        }
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let pks_bytes = std::slice::from_raw_parts(ring_pks, num_validators * 32);
        
        // Load PCS params from SRS
        let pcs_params: PcsParams = 
            match PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };
        
        // Create ring proof params
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::from_pcs_params(num_validators, pcs_params) {
                Ok(p) => p,
                Err(_) => return false,
            };
        
        // Build ring from public keys
        // GP Appendix G: "Note that in the case a key H has no corresponding 
        // Bandersnatch point when constructing the ring, then the Bandersnatch
        // padding point as stated by Hosseini and Galassi 2024 should be substituted."
        //
        // IMPORTANT: Use deserialize_compressed_unchecked to skip the subgroup check.
        // Keys that are valid curve points but not in the prime-order subgroup should
        // still be used as-is in the ring (they CAN participate in VRF proofs).
        // Only truly invalid keys (not on the curve at all) get the padding point.
        //
        // TODO: Verify GP vs polkajam divergence — the GP says "no corresponding
        // Bandersnatch point" which could mean either (a) not on the curve at all,
        // or (b) not in the prime-order subgroup. polkajam uses unchecked deser
        // (accepts curve points outside the subgroup). If the GP intended strict
        // subgroup membership, polkajam's test vectors may need updating.
        // Ref: GP Appendix G, Hosseini & Galassi 2024.
        let mut ring = Vec::with_capacity(num_validators);
        for i in 0..num_validators {
            let pk_bytes = &pks_bytes[i*32..(i+1)*32];
            
            // Check if key is all zeros (offender zeroed per GP 6.14)
            let is_zero_key = pk_bytes.iter().all(|&b| b == 0);
            
            let padding = RingProofParams::<BandersnatchSha512Ell2>::padding_point();
            
            if is_zero_key {
                // Zero key = offender filtered by Φ(ι) per GP 6.14
                ring.push(padding);
            } else {
                // Use unchecked deserialization: skip subgroup check.
                // A key may be a valid curve point without being in the
                // prime-order subgroup — it should still be included in
                // the ring commitment per GP Appendix G.
                match Public::deserialize_compressed_unchecked(&pk_bytes[..]) {
                    Ok(pk) => ring.push(pk.0),
                    Err(_) => {
                        // Truly invalid (not on curve) - use padding point
                        ring.push(padding);
                    }
                }
            }
        }
        
        // Compute ring commitment
        let verifier_key = params.verifier_key(&ring);
        let commitment = verifier_key.commitment();
        
        // Serialize to output
        let mut commitment_bytes = Vec::new();
        if commitment.serialize_compressed(&mut commitment_bytes).is_err() {
            return false;
        }
        
        if commitment_bytes.len() != 144 {
            return false;
        }
        
        std::ptr::copy_nonoverlapping(commitment_bytes.as_ptr(), output, 144);
        true
    }
}

/// Compute ring commitment with explicit ring_size (may differ from num_validators)
/// If ring_size > num_validators, the ring is padded with padding points.
///
/// # Safety
/// - `srs_data`: Zcash SRS file contents
/// - `ring_pks`: V * 32 bytes (V compressed Bandersnatch points)
/// - `ring_size`: Domain size for KZG (may be > num_validators)
/// - `output`: Buffer for 144-byte ring commitment
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_compute_ring_commitment_padded(
    srs_data: *const u8,
    srs_len: usize,
    ring_pks: *const u8,
    num_validators: usize,
    ring_size: usize,
    output: *mut u8,
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_pks, num_validators, ring_size, output);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        use ark_vrf::suites::bandersnatch::PcsParams;
        
        if srs_data.is_null() || ring_pks.is_null() || output.is_null() {
            return false;
        }
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let pks_bytes = std::slice::from_raw_parts(ring_pks, num_validators * 32);
        
        // Load PCS params from SRS
        let pcs_params: PcsParams = 
            match PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..]) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("PCS params error: {:?}", e);
                    return false;
                }
            };
        
        // Create ring proof params with explicit ring_size
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::from_pcs_params(ring_size, pcs_params) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("RingProofParams error for ring_size={}: {:?}", ring_size, e);
                    return false;
                }
            };
        
        let padding = RingProofParams::<BandersnatchSha512Ell2>::padding_point();
        
        // Build ring from public keys + pad to ring_size
        // Use unchecked deserialization (skip subgroup check) per GP Appendix G
        let mut ring = Vec::with_capacity(ring_size);
        for i in 0..num_validators {
            let pk_bytes = &pks_bytes[i*32..(i+1)*32];
            let is_zero_key = pk_bytes.iter().all(|&b| b == 0);
            
            if is_zero_key {
                ring.push(padding);
            } else {
                match Public::deserialize_compressed_unchecked(&pk_bytes[..]) {
                    Ok(pk) => ring.push(pk.0),
                    Err(_) => ring.push(padding),
                }
            }
        }
        
        // Pad remaining slots with padding point
        for _ in num_validators..ring_size {
            ring.push(padding);
        }
        
        // Compute ring commitment
        let verifier_key = params.verifier_key(&ring);
        let commitment = verifier_key.commitment();
        
        // Serialize to output
        let mut commitment_bytes = Vec::new();
        if commitment.serialize_compressed(&mut commitment_bytes).is_err() {
            return false;
        }
        
        if commitment_bytes.len() != 144 {
            eprintln!("Unexpected commitment size: {}", commitment_bytes.len());
            return false;
        }
        
        std::ptr::copy_nonoverlapping(commitment_bytes.as_ptr(), output, 144);
        true
    }
}

/// Verify a complete Bandersnatch Ring VRF signature (784 bytes format)
///
/// The signature format is: [VRF output: 32] [Pedersen proof: 160] [Ring proof: 592]
///
/// # Safety
/// - `srs_data`: Zcash SRS file contents (590KB for domain 2^11)
/// - `ring_pks`: V * 32 bytes (V compressed Bandersnatch points)
/// - `vrf_input`: arbitrary bytes for VRF input (will be hashed to curve)
/// - `signature`: 784 bytes ring VRF signature
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_verify_ring_vrf_signature(
    srs_data: *const u8,
    srs_len: usize,
    ring_pks: *const u8,
    num_validators: usize,
    vrf_input: *const u8,
    vrf_input_len: usize,
    signature: *const u8,  // 784 bytes
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_pks, num_validators, vrf_input, vrf_input_len, signature);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        
        if srs_data.is_null() || ring_pks.is_null() || vrf_input.is_null() || signature.is_null() {
            return false;
        }
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let pks_bytes = std::slice::from_raw_parts(ring_pks, num_validators * 32);
        let input_bytes = std::slice::from_raw_parts(vrf_input, vrf_input_len);
        let sig_bytes = std::slice::from_raw_parts(signature, 784);
        
        // Deserialize signature as RingVrfSignature (output + proof bundled)
        let sig = match RingVrfSignature::deserialize_compressed(&sig_bytes[..]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to deserialize RingVrfSignature: {:?}", e);
                return false;
            }
        };
        
        // Deserialize SRS into RingProofParams (UNCOMPRESSED format from Zcash ceremony)
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::deserialize_uncompressed(&srs_bytes[..]) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to deserialize SRS: {:?}", e);
                    return false;
                }
            };
        
        // Deserialize ring public keys
        let mut ring: Vec<AffinePoint> = Vec::with_capacity(num_validators);
        for i in 0..num_validators {
            let pk_slice = &pks_bytes[i * 32..(i + 1) * 32];
            match Public::deserialize_compressed(&pk_slice[..]) {
                Ok(pk) => ring.push(pk.0),
                Err(e) => {
                    eprintln!("Failed to deserialize public key {}: {:?}", i, e);
                    return false;
                }
            }
        }
        
        // Build verifier
        let verifier_key = params.verifier_key(&ring);
        
        let verifier = params.verifier(verifier_key);
        
        // Split input: [domain_prefix + eta2] goes to vrf_input, [attempt] goes to aux_data
        // Format: "jam_ticket_seal" (15) + eta2 (32) + attempt (1) = 48 bytes
        let (vrf_input_bytes, aux_data) = if input_bytes.len() == 48 {
            (&input_bytes[0..47], &input_bytes[47..48])
        } else {
            (input_bytes, &[][..])
        };
        
        // Create VRF input (hash to curve)
        let input = match Input::new(vrf_input_bytes) {
            Some(i) => i,
            None => {
                eprintln!("Failed to hash VRF input to curve");
                return false;
            }
        };
        
        // Verify with attempt as auxiliary data
        use ark_vrf::ring::Verifier;
        match Public::verify(input, sig.output, aux_data, &sig.proof, &verifier) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}

/// Check if a 32-byte key is a valid Bandersnatch curve point
///
/// Returns:
/// - 0: valid point
/// - 1: all zeros (offender/null key)
/// - 2: deserialization failed (not on curve)
/// - 3: null pointer
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_check_key(
    key: *const u8,
) -> u32 {
    if key.is_null() {
        return 3;
    }
    let key_bytes = std::slice::from_raw_parts(key, 32);
    if key_bytes.iter().all(|&b| b == 0) {
        return 1; // all zeros
    }
    match Public::deserialize_compressed(&key_bytes[..]) {
        Ok(_) => 0,  // valid
        Err(_) => 2, // invalid
    }
}

/// Compute ring commitment with verbose per-key diagnostics
///
/// Returns commitment in output (144 bytes) and per-key status in key_status (num_validators bytes)
/// key_status[i]: 0=valid, 1=zero, 2=invalid(padding used)
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_compute_ring_commitment_verbose(
    srs_data: *const u8,
    srs_len: usize,
    ring_pks: *const u8,
    num_validators: usize,
    output: *mut u8,
    key_status: *mut u8,
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_pks, num_validators, output, key_status);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        use ark_vrf::suites::bandersnatch::PcsParams;
        
        if srs_data.is_null() || ring_pks.is_null() || output.is_null() || key_status.is_null() {
            return false;
        }
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let pks_bytes = std::slice::from_raw_parts(ring_pks, num_validators * 32);
        let status = std::slice::from_raw_parts_mut(key_status, num_validators);
        
        let pcs_params: PcsParams = 
            match PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };
        
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::from_pcs_params(num_validators, pcs_params) {
                Ok(p) => p,
                Err(_) => return false,
            };
        
        let padding = RingProofParams::<BandersnatchSha512Ell2>::padding_point();
        
        // Print padding point for reference
        let mut padding_bytes = Vec::new();
        padding.serialize_compressed(&mut padding_bytes).unwrap();
        eprintln!("Padding point ({} bytes): {:02x?}", padding_bytes.len(), &padding_bytes[..]);
        
        let mut ring = Vec::with_capacity(num_validators);
        for i in 0..num_validators {
            let pk_bytes = &pks_bytes[i*32..(i+1)*32];
            let is_zero_key = pk_bytes.iter().all(|&b| b == 0);
            
            if is_zero_key {
                ring.push(padding);
                status[i] = 1; // zero key
                eprintln!("Key {}: ZERO → padding", i);
            } else {
                match Public::deserialize_compressed(&pk_bytes[..]) {
                    Ok(pk) => {
                        ring.push(pk.0);
                        status[i] = 0; // valid
                        eprintln!("Key {}: VALID {:02x}{:02x}{:02x}{:02x}...", 
                                  i, pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]);
                    },
                    Err(e) => {
                        ring.push(padding);
                        status[i] = 2; // invalid
                        eprintln!("Key {}: INVALID {:02x}{:02x}{:02x}{:02x}... error={:?} → padding", 
                                  i, pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], e);
                    }
                }
            }
        }
        
        let verifier_key = params.verifier_key(&ring);
        let commitment = verifier_key.commitment();
        
        let mut commitment_bytes = Vec::new();
        if commitment.serialize_compressed(&mut commitment_bytes).is_err() {
            return false;
        }
        
        if commitment_bytes.len() != 144 {
            return false;
        }
        
        std::ptr::copy_nonoverlapping(commitment_bytes.as_ptr(), output, 144);
        true
    }
}

/// Compute ring commitment using unchecked deserialization.
/// Tries deserialize_compressed_unchecked instead of deserialize_compressed.
/// This is for diagnosing whether polkajam skips the subgroup check.
///
/// # Safety
/// Same as bandersnatch_compute_ring_commitment
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_compute_ring_commitment_unchecked(
    srs_data: *const u8,
    srs_len: usize,
    ring_pks: *const u8,
    num_validators: usize,
    output: *mut u8,
    key_status: *mut u8,
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (srs_data, srs_len, ring_pks, num_validators, output, key_status);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        use ark_vrf::ring::RingProofParams;
        use ark_vrf::suites::bandersnatch::PcsParams;
        use ark_serialize::CanonicalDeserialize;
        
        if srs_data.is_null() || ring_pks.is_null() || output.is_null() || key_status.is_null() {
            return false;
        }
        
        let srs_bytes = std::slice::from_raw_parts(srs_data, srs_len);
        let pks_bytes = std::slice::from_raw_parts(ring_pks, num_validators * 32);
        let status = std::slice::from_raw_parts_mut(key_status, num_validators);
        
        let pcs_params: PcsParams = 
            match PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };
        
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            match RingProofParams::from_pcs_params(num_validators, pcs_params) {
                Ok(p) => p,
                Err(_) => return false,
            };
        
        let padding = RingProofParams::<BandersnatchSha512Ell2>::padding_point();
        
        let mut ring = Vec::with_capacity(num_validators);
        for i in 0..num_validators {
            let pk_bytes = &pks_bytes[i*32..(i+1)*32];
            let is_zero_key = pk_bytes.iter().all(|&b| b == 0);
            
            if is_zero_key {
                ring.push(padding);
                status[i] = 1; // zero key
                eprintln!("  unchecked key {}: ZERO → padding", i);
            } else {
                // Try unchecked deserialization first
                match Public::deserialize_compressed_unchecked(&pk_bytes[..]) {
                    Ok(pk) => {
                        ring.push(pk.0);
                        // Also check if normal deserialization would fail
                        match Public::deserialize_compressed(&pk_bytes[..]) {
                            Ok(_) => {
                                status[i] = 0; // valid (both checked and unchecked)
                                eprintln!("  unchecked key {}: VALID (checked also OK)", i);
                            },
                            Err(_) => {
                                status[i] = 3; // unchecked OK but checked fails
                                eprintln!("  unchecked key {}: UNCHECKED-ONLY (checked FAILS) → using as-is", i);
                            }
                        }
                    },
                    Err(e) => {
                        // Even unchecked fails — truly invalid bytes
                        ring.push(padding);
                        status[i] = 2; // invalid even unchecked
                        eprintln!("  unchecked key {}: INVALID-EVEN-UNCHECKED error={:?} → padding", i, e);
                    }
                }
            }
        }
        
        let verifier_key = params.verifier_key(&ring);
        let commitment = verifier_key.commitment();
        
        let mut commitment_bytes = Vec::new();
        if commitment.serialize_compressed(&mut commitment_bytes).is_err() {
            return false;
        }
        
        if commitment_bytes.len() != 144 {
            return false;
        }
        
        std::ptr::copy_nonoverlapping(commitment_bytes.as_ptr(), output, 144);
        true
    }
}

/// Initialize ring proof params from seed (for testing)
///
/// For production, use `bandersnatch_load_ring_params` with Zcash SRS.
///
/// # Safety  
/// - `output`: Buffer for serialized RingProofParams
/// - `output_len`: Set to actual size written
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_init_ring_params(
    ring_size: usize,
    seed: *const u8,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> bool {
    #[cfg(not(feature = "ring"))]
    {
        let _ = (ring_size, seed, output, output_capacity, output_len);
        return false;
    }
    
    #[cfg(feature = "ring")]
    {
        if seed.is_null() || output.is_null() || output_len.is_null() {
            return false;
        }

        let seed_bytes: [u8; 32] = std::slice::from_raw_parts(seed, 32).try_into().unwrap();
        
        // Create ring params from seed
        let params: RingProofParams<ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2> = 
            RingProofParams::from_seed(ring_size, seed_bytes);

        // Serialize
        let mut serialized = Vec::new();
        if params.serialize_compressed(&mut serialized).is_err() {
            return false;
        }

        if serialized.len() > output_capacity {
            return false;
        }

        std::ptr::copy_nonoverlapping(serialized.as_ptr(), output, serialized.len());
        *output_len = serialized.len();

        true
    }
}

// ============================================================================
// BLS12-381 (GP 6.8-6.11)
// ============================================================================

use ark_bls12_381::{G1Affine, G1Projective, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;

/// Hash arbitrary bytes to BLS12-381 G1 point (simplified for M1)
///
/// GP 6.8-6.11: BLS validator keys use hash-to-curve (hash_to_G1).
/// 
/// NOTE: This is a PLACEHOLDER implementation for M1.
/// For M1, we only need the structure (48-byte keys), not real BLS crypto.
/// Production JAM would use proper RFC 9380 hash-to-curve.
///
/// This function generates a deterministic G1 point from input bytes
/// by hashing and using try-and-increment.
///
/// # Safety
/// - `input`: Arbitrary bytes to hash
/// - `len`: Length of input
/// - `output`: 48 bytes (compressed G1 point)
#[no_mangle]
pub unsafe extern "C" fn bls_hash_to_g1(
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> bool {
    if input.is_null() || output.is_null() {
        return false;
    }

    let data = std::slice::from_raw_parts(input, len);
    
    // SIMPLIFIED: Just hash to a G1 point using scalar multiplication
    // This is NOT secure for production, but OK for M1 structure testing
    
    // Hash input to get a scalar
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let hash_result = hasher.finalize();
    
    // Pad to 64 bytes for field element
    let mut bytes_64 = [0u8; 64];
    bytes_64[..32].copy_from_slice(&hash_result);
    
    // Convert to scalar (will be reduced mod curve order)
    let scalar = Fr::from_be_bytes_mod_order(&bytes_64);
    
    // Multiply generator by scalar
    let generator = G1Affine::generator();
    let point = G1Projective::from(generator) * scalar;
    
    // Serialize point (compressed, 48 bytes)
    let affine = point.into_affine();
    let mut serialized = Vec::new();
    if affine.serialize_compressed(&mut serialized).is_err() {
        return false;
    }
    
    if serialized.len() != 48 {
        return false;
    }
    
    std::ptr::copy_nonoverlapping(serialized.as_ptr(), output, 48);
    true
}

/// Verify BLS12-381 signature (simplified placeholder)
///
/// For M1, we only need the key generation (hash_to_g1).
/// Full signature verification would require pairing checks.
///
/// # Safety
/// - `pubkey`: 48 bytes (compressed G1 point)
/// - `message`: Arbitrary bytes
/// - `signature`: 96 bytes (compressed G2 point)
#[no_mangle]
pub unsafe extern "C" fn bls_verify_signature(
    pubkey: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> bool {
    // Placeholder: M1 doesn't require signature verification
    // Real implementation would use pairings:
    // e(H(m), pk) == e(sig, G2::generator())
    
    if pubkey.is_null() || message.is_null() || signature.is_null() {
        return false;
    }
    
    // For now, just validate that inputs are well-formed
    let pk_bytes = std::slice::from_raw_parts(pubkey, 48);
    let _msg = std::slice::from_raw_parts(message, message_len);
    let sig_bytes = std::slice::from_raw_parts(signature, 96);
    
    // Try to deserialize pubkey
    if G1Affine::deserialize_compressed(&pk_bytes[..]).is_err() {
        return false;
    }
    
    // Signature deserialization would use G2Affine
    // For M1 placeholder, just check length
    sig_bytes.len() == 96
}

/// Aggregate BLS public keys
///
/// Used for computing ring commitments from validator keys.
///
/// # Safety
/// - `pubkeys`: N * 48 bytes (compressed G1 points)
/// - `count`: Number of keys
/// - `output`: 48 bytes (aggregated key)
#[no_mangle]
pub unsafe extern "C" fn bls_aggregate_pubkeys(
    pubkeys: *const u8,
    count: usize,
    output: *mut u8,
) -> bool {
    if pubkeys.is_null() || output.is_null() || count == 0 {
        return false;
    }
    
    let all_bytes = std::slice::from_raw_parts(pubkeys, count * 48);
    
    // Deserialize and aggregate
    let mut aggregate = G1Projective::default(); // Identity element
    
    for i in 0..count {
        let pk_bytes = &all_bytes[i * 48..(i + 1) * 48];
        
        match G1Affine::deserialize_compressed(&pk_bytes[..]) {
            Ok(pk) => {
                aggregate += G1Projective::from(pk);
            },
            Err(_) => return false,
        }
    }
    
    // Serialize result
    let affine = aggregate.into_affine();
    let mut serialized = Vec::new();
    if affine.serialize_compressed(&mut serialized).is_err() {
        return false;
    }
    
    if serialized.len() != 48 {
        return false;
    }
    
    std::ptr::copy_nonoverlapping(serialized.as_ptr(), output, 48);
    true
}

// ============================================================================
// Ed25519 (GP Appendix A.3)
// ============================================================================

/// Verify Ed25519 signature (strict RFC 8032 per GP §3.8.2)
///
/// # Safety
/// - `public_key` must point to 32 bytes
/// - `message` must point to `message_len` bytes
/// - `signature` must point to 64 bytes
///
/// Uses ed25519-dalek verify_strict (RFC 8032):
/// - Non-cofactored single-scalar equation: [s]B = R + [k]A
/// - Rejects non-canonical point encodings
/// - Rejects s >= L (group order)
#[no_mangle]
pub unsafe extern "C" fn ed25519_verify(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    if public_key.is_null() || message.is_null() || signature.is_null() {
        return false;
    }

    let pk_bytes: [u8; 32] = match std::slice::from_raw_parts(public_key, 32).try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig_bytes: [u8; 64] = match std::slice::from_raw_parts(signature, 64).try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let msg = std::slice::from_raw_parts(message, message_len);

    verifying_key.verify_strict(msg, &sig).is_ok()
}

// Erasure coding FFI functions are defined below (after tests)

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_vrf::suites::bandersnatch::*;

    #[test]
    fn test_ring_vrf_sizes() {
        use ark_vrf::ring::{Prover, RingProofParams};
        
        // Create ring params for tiny (V=6)
        let params: RingProofParams<BandersnatchSha512Ell2> = 
            RingProofParams::from_seed(6, [0u8; 32]);
        
        // Create test keys
        let secrets: Vec<_> = (0u64..6)
            .map(|i| Secret::from_seed(&i.to_le_bytes()))
            .collect();
        let ring: Vec<AffinePoint> = secrets.iter().map(|s| s.public().0).collect();
        
        // Create prover for index 0
        let prover_key = params.prover_key(&ring);
        let prover = params.prover(prover_key, 0);
        
        // Create a proof
        let input = Input::new(b"test input").unwrap();
        let output = secrets[0].output(input);
        let proof = secrets[0].prove(input, output, &[], &prover);
        
        // Serialize and check sizes
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        
        let mut output_bytes = Vec::new();
        output.serialize_compressed(&mut output_bytes).unwrap();
        
        println!("=== Ring VRF Sizes (V=6) ===");
        println!("Ring proof total: {} bytes", proof_bytes.len());
        println!("VRF output: {} bytes", output_bytes.len());
        
        // Decompose proof
        let mut pedersen_bytes = Vec::new();
        proof.pedersen_proof.serialize_compressed(&mut pedersen_bytes).unwrap();
        
        let mut ring_proof_bytes = Vec::new();
        proof.ring_proof.serialize_compressed(&mut ring_proof_bytes).unwrap();
        
        println!("Pedersen proof: {} bytes", pedersen_bytes.len());
        println!("Ring proof: {} bytes", ring_proof_bytes.len());
        println!("Total (pedersen + ring): {} bytes", pedersen_bytes.len() + ring_proof_bytes.len());
        
        // The signature format is: output (32) + proof (752) = 784 bytes
        // Or: pedersen (?) + ring_proof (?)
        assert_eq!(proof_bytes.len(), 784 - 32, "Proof should be 752 bytes (784 - 32 output)");
    }

    #[test]
    fn test_blake2b_256() {
        let input = b"hello world";
        let mut output = [0u8; 32];

        unsafe {
            blake2b_256(input.as_ptr(), input.len(), output.as_mut_ptr());
        }

        // Expected: blake2b-256("hello world")
        let expected = hex::decode(
            "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610",
        )
        .unwrap();

        assert_eq!(&output[..], &expected[..]);
    }

    #[test]
    fn test_bandersnatch_ietf_vrf_roundtrip() {
        use ark_vrf::suites::bandersnatch::Secret;
        use ark_vrf::ietf::{Prover, Verifier};
        
        // Generate a test keypair
        let secret = Secret::from_seed(b"test seed for jam crypto");
        let public = secret.public();
        
        // Create input and compute output
        let vrf_input_data = b"test vrf input";
        let input = Input::new(vrf_input_data).unwrap();
        let output = secret.output(input);
        
        // Create proof
        let proof = secret.prove(input, output, &[]);
        
        // Verify directly first
        assert!(public.verify(input, output, &[], &proof).is_ok());
        
        // Serialize everything
        let mut pk_bytes = Vec::new();
        let mut output_bytes = Vec::new();
        let mut proof_bytes = Vec::new();
        
        public.serialize_compressed(&mut pk_bytes).unwrap();
        output.serialize_compressed(&mut output_bytes).unwrap();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        
        println!("Public key size: {}", pk_bytes.len());
        println!("Output size: {}", output_bytes.len());
        println!("Proof size: {}", proof_bytes.len());
        
        // Verify via FFI - must pass the SAME input data (not the curve point)
        // FFI will hash-to-curve internally
        let result = unsafe {
            bandersnatch_verify_vrf(
                pk_bytes.as_ptr(),
                vrf_input_data.as_ptr(),  // Raw bytes, will be hashed to curve
                vrf_input_data.len(),
                output_bytes.as_ptr(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                std::ptr::null(),  // ad = empty (matches prove(&[]))
                0,
            )
        };
        
        assert!(result, "VRF verification should succeed via FFI");
    }

    #[test]
    fn test_bandersnatch_spec_vector1() {
        // From bandersnatch-vrf-spec Vector 1 (no input, no ad)
        let pk_hex = "a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b";
        let gamma_hex = "e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f";
        let proof_c_hex = "439fd9495643314fa623f2581f4b3d7d6037394468084f4ad7d8031479d9d101";
        let proof_s_hex = "828bedd2ad95380b11f67a05ea0a76f0c3fef2bee9f043f4dffdddde09f55c01";
        
        let pk = hex::decode(pk_hex).unwrap();
        let gamma = hex::decode(gamma_hex).unwrap();
        let proof_c = hex::decode(proof_c_hex).unwrap();
        let proof_s = hex::decode(proof_s_hex).unwrap();
        
        // proof = c || s (64 bytes)
        let mut proof = proof_c.clone();
        proof.extend_from_slice(&proof_s);
        
        // VRF input is empty for Vector 1
        let vrf_input: &[u8] = b"";
        
        println!("PK: {} bytes, Gamma: {} bytes, Proof: {} bytes",
                 pk.len(), gamma.len(), proof.len());
        
        // Try via FFI
        let result = unsafe {
            bandersnatch_verify_vrf(
                pk.as_ptr(),
                vrf_input.as_ptr(),
                vrf_input.len(),
                gamma.as_ptr(),
                proof.as_ptr(),
                proof.len(),
                std::ptr::null(),
                0,
            )
        };
        println!("FFI verify result (no input, no ad): {}", result);
        assert!(result, "Spec vector 1 should verify");
    }

    #[test]
    fn test_bandersnatch_spec_vector3_with_ad() {
        // From bandersnatch-vrf-spec Vector 3 (no input, ad = 0x0b8c)
        let pk_hex = "9d97151298a5339866ddd3539d16696e19e6b68ac731562c807fe63a1ca49506";
        let gamma_hex = "67a348e256d908eb695d15ee0d869efef2bcf9f0fea646e788f967abbc0464dd";
        let proof_c_hex = "aec4d1cf308cb4cb400190350e69f4fb309255aa738fff5a6ac4ced7538fce03";
        let proof_s_hex = "54e5d38a76f309ce63ca82465160abd8d75b78805a0b499e60c26436de4a8e01";
        
        let pk = hex::decode(pk_hex).unwrap();
        let gamma = hex::decode(gamma_hex).unwrap();
        let proof_c = hex::decode(proof_c_hex).unwrap();
        let proof_s = hex::decode(proof_s_hex).unwrap();
        
        let mut proof = proof_c.clone();
        proof.extend_from_slice(&proof_s);
        
        // VRF input is empty for Vector 3
        let vrf_input: &[u8] = b"";
        let ad = hex::decode("0b8c").unwrap();
        
        // Try with correct ad
        let result = unsafe {
            bandersnatch_verify_vrf(
                pk.as_ptr(),
                vrf_input.as_ptr(),
                vrf_input.len(),
                gamma.as_ptr(),
                proof.as_ptr(),
                proof.len(),
                ad.as_ptr(),
                ad.len(),
            )
        };
        println!("FFI verify result (no input, ad=0b8c): {}", result);
        assert!(result, "Spec vector 3 should verify with correct ad");
        
        // Try with wrong ad — should fail
        let result_wrong = unsafe {
            bandersnatch_verify_vrf(
                pk.as_ptr(),
                vrf_input.as_ptr(),
                vrf_input.len(),
                gamma.as_ptr(),
                proof.as_ptr(),
                proof.len(),
                std::ptr::null(),
                0,
            )
        };
        println!("FFI verify result (no input, no ad): {}", result_wrong);
        assert!(!result_wrong, "Spec vector 3 should fail with no ad");
    }

    #[test]
    fn test_jam_fallback_block1() {
        // Real data from JAM test vector: fallback trace, block 1
        let pk = hex::decode("2105650944FCD101621FD5BB3124C9FD191D114B7AD936C1D79D734F9F21392E").unwrap();
        let inp = hex::decode("6A616D5F66616C6C6261636B5F7365616C5710C5F909ACECAEC8AFE31F4EDDD93C495BAC0618E715A3F22ABC90670E5AAB").unwrap();
        let out = hex::decode("39CA45236C96EAE24D57127288F16BF6E64DFBBF8D1D693E660474A4D43A424A").unwrap();
        let prf = hex::decode("C558311581B4DEA4F1D1842430A7556E73F418C59281708F90A06849B09C8C009F95D145FDE8E323FEF5B3C935BB7A75DA9403C668631D0A6CE718CF4C968A11").unwrap();
        let ad = hex::decode("2BF11DC5E1C7B9BBAAFC2C8533017ABC12DAEB0BAF22C92509AD50F7875E5716BAFD5B0B2668FEF3611D9B856CB879483A4BC3C0428DD523CB95D2021C320029189D15AF832DFE4F67744008B62C334B569FCBB4C261E0F065655697306CA252010000000000000062BC9D2311DA8DB52DA45C5785333B39DA3F1464B0D0341D12E2EE2987DA6595463487A2D903C169560A90521CE06ECC99E466AFEAA04F766E4E6FD3BF3677170282A54709E0E92A1A37C853F8C83053C9746E53581366BF1AAEDD621BD4A71300").unwrap();
        
        println!("PK: {} bytes, INP: {} bytes, OUT: {} bytes, PRF: {} bytes, AD: {} bytes",
                 pk.len(), inp.len(), out.len(), prf.len(), ad.len());
        
        // Try via FFI with no ad
        let r1 = unsafe {
            bandersnatch_verify_vrf(
                pk.as_ptr(), inp.as_ptr(), inp.len(),
                out.as_ptr(), prf.as_ptr(), prf.len(),
                std::ptr::null(), 0,
            )
        };
        println!("FFI (no ad): {}", r1);
        
        // Try via FFI with ad = EU(H) 
        let r2 = unsafe {
            bandersnatch_verify_vrf(
                pk.as_ptr(), inp.as_ptr(), inp.len(),
                out.as_ptr(), prf.as_ptr(), prf.len(),
                ad.as_ptr(), ad.len(),
            )
        };
        println!("FFI (ad=EU(H)): {}", r2);
        
        // Try direct to see error details
        use ark_serialize::CanonicalDeserialize;
        use ark_vrf::ietf::Verifier;
        
        let public = Public::deserialize_compressed(&pk[..]).unwrap();
        let output = Output::deserialize_compressed(&out[..]).unwrap();
        let proof = ark_vrf::ietf::Proof::<BandersnatchSha512Ell2>::deserialize_compressed(&prf[..]).unwrap();
        let input = Input::new(&inp).unwrap();
        
        let r3 = public.verify(input, output, &[], &proof);
        println!("Direct (no ad): {:?}", r3);
        let r4 = public.verify(input, output, &ad, &proof);
        println!("Direct (ad=EU(H)): {:?}", r4);
    }

    #[test]
    fn test_bandersnatch_ietf_vrf_with_ad() {
        use ark_vrf::ietf::{Prover, Verifier};
        
        let secret = Secret::from_seed(b"test seed for jam crypto ad");
        let public = secret.public();
        
        let vrf_input_data = b"jam_fallback_seal\x00\x00\x00test_eta3";
        let ad_data = b"this is the unsealed header EU(H) bytes for test";
        
        let input = Input::new(vrf_input_data).unwrap();
        let output = secret.output(input);
        
        // Sign WITH ad
        let proof = secret.prove(input, output, ad_data);
        
        // Verify with correct ad
        assert!(public.verify(input, output, ad_data, &proof).is_ok(),
                "Direct verify with ad should succeed");
        
        // Verify with wrong ad should FAIL
        assert!(public.verify(input, output, b"wrong ad", &proof).is_err(),
                "Verify with wrong ad should fail");
        
        // Verify with empty ad should FAIL (ad was non-empty during proving)
        assert!(public.verify(input, output, &[], &proof).is_err(),
                "Verify with empty ad should fail when prove used non-empty ad");
        
        // Now test via FFI with the 96-byte seal format [output:32][proof:64]
        let mut pk_bytes = Vec::new();
        let mut output_bytes = Vec::new();
        let mut proof_bytes = Vec::new();
        
        public.serialize_compressed(&mut pk_bytes).unwrap();
        output.serialize_compressed(&mut output_bytes).unwrap();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        
        println!("PK: {} bytes, Output: {} bytes, Proof: {} bytes",
                 pk_bytes.len(), output_bytes.len(), proof_bytes.len());
        
        // FFI verify with correct ad
        let result = unsafe {
            bandersnatch_verify_vrf(
                pk_bytes.as_ptr(),
                vrf_input_data.as_ptr(),
                vrf_input_data.len(),
                output_bytes.as_ptr(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                ad_data.as_ptr(),
                ad_data.len(),
            )
        };
        assert!(result, "FFI verify with correct ad should succeed");
        
        // FFI verify with empty ad should fail
        let result_no_ad = unsafe {
            bandersnatch_verify_vrf(
                pk_bytes.as_ptr(),
                vrf_input_data.as_ptr(),
                vrf_input_data.len(),
                output_bytes.as_ptr(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                std::ptr::null(),
                0,
            )
        };
        assert!(!result_no_ad, "FFI verify with empty ad should fail when prove used ad");
    }

    #[test]
    fn test_y_function_output_hash() {
        // From bandersnatch_sha-512_ell2_ietf.json vector-1
        let gamma_hex = "e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f";
        let proof_c_hex = "439fd9495643314fa623f2581f4b3d7d6037394468084f4ad7d8031479d9d101";
        let proof_s_hex = "828bedd2ad95380b11f67a05ea0a76f0c3fef2bee9f043f4dffdddde09f55c01";
        let beta_hex = "fdeb377a4ffd7f95ebe48e5b43a88d069ce62188e49493500315ad55ee04d7442b93c4c91d5475370e9380496f4bc0b838c2483bce4e133c6f18b0adbb9e4722";
        
        let gamma = hex::decode(gamma_hex).unwrap();
        let proof_c = hex::decode(proof_c_hex).unwrap();
        let proof_s = hex::decode(proof_s_hex).unwrap();
        let beta = hex::decode(beta_hex).unwrap();
        
        // Construct 96-byte signature: [gamma(32)][proof_c(32)][proof_s(32)]
        let mut sig = Vec::with_capacity(96);
        sig.extend_from_slice(&gamma);
        sig.extend_from_slice(&proof_c);
        sig.extend_from_slice(&proof_s);
        assert_eq!(sig.len(), 96);
        
        let mut output = [0u8; 32];
        let result = unsafe {
            bandersnatch_vrf_output_hash(sig.as_ptr(), sig.len(), output.as_mut_ptr())
        };
        
        println!("Y function success: {}", result);
        println!("Y output:   {}", hex::encode(&output));
        println!("beta[0:32]: {}", hex::encode(&beta[..32]));
        
        assert!(result, "Y function should succeed on valid output point");
        assert_eq!(&output[..], &beta[..32], 
                   "Y(sig) should equal first 32 bytes of beta (VRF hash)");
    }
}

// ============================================================================
// Erasure Coding FFI (GP Appendix H)
// ============================================================================

/// Get required output buffer size for erasure encoding
#[no_mangle]
pub extern "C" fn erasure_output_size(data_len: usize, k: usize, n: usize) -> usize {
    if k == 0 || n == 0 {
        return 0;
    }
    let shard_size = ((data_len + k - 1) / k + 1) / 2 * 2;
    let shard_size = if shard_size == 0 { 2 } else { shard_size };
    n * shard_size
}

/// Encode data into erasure-coded shards (GP Appendix H)
///
/// # Parameters
/// - `data`: pointer to input data
/// - `data_len`: length of input data
/// - `k`: number of original shards (2 for TINY, 342 for FULL)
/// - `n`: total number of output shards (6 for TINY, 1023 for FULL)
/// - `output`: pointer to output buffer (must be at least n * shard_size bytes)
/// - `output_len`: pointer to receive actual output length
///
/// # Returns
/// - Shard size on success, 0 on failure
///
/// # Safety
/// - `data` must point to `data_len` valid bytes
/// - `output` must point to sufficient writable space
#[no_mangle]
pub unsafe extern "C" fn erasure_encode(
    data: *const u8,
    data_len: usize,
    k: usize,
    n: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> usize {
    if data.is_null() || output.is_null() || output_len.is_null() || k == 0 || n == 0 {
        return 0;
    }
    
    let data_slice = std::slice::from_raw_parts(data, data_len);
    // For FULL mode (k=342), use simd with stride hack
    // For TINY mode (k=2), use Lagrange interpolation
    let shards = if k == 342 {
        erasure::encode_bytes_simd_strided(data_slice, k, n)
    } else {
        erasure::encode_bytes_lagrange(data_slice, k, n)
    };
    
    if shards.is_empty() {
        return 0;
    }
    
    let shard_size = shards[0].len();
    let total_size = shards.len() * shard_size;
    
    // Copy shards to output buffer sequentially
    let mut offset = 0;
    for shard in &shards {
        std::ptr::copy_nonoverlapping(shard.as_ptr(), output.add(offset), shard_size);
        offset += shard_size;
    }
    
    *output_len = total_size;
    shard_size
}

/// Encode for JAM TINY mode (k=2, n=6)
#[no_mangle]
pub unsafe extern "C" fn erasure_encode_tiny(
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> usize {
    erasure_encode(data, data_len, 2, 6, output, output_len)
}

/// Encode for JAM FULL mode (k=342, n=1023)
#[no_mangle]
pub unsafe extern "C" fn erasure_encode_full(
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> usize {
    erasure_encode(data, data_len, 342, 1023, output, output_len)
}

// ============================================================================
// PolkaVM (GP Section 14 - PVM)
// ============================================================================
