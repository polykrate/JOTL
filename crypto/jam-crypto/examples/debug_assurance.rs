use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn try_verify(name: &str, message: &[u8], key: &[u8; 32], sig: &[u8; 64]) {
    let verifying_key = VerifyingKey::from_bytes(key).unwrap();
    let signature = Signature::from_bytes(sig);
    let valid = verifying_key.verify(message, &signature).is_ok();
    println!("  {}: {} (msg len={})", name, if valid { "✅" } else { "❌" }, message.len());
}

fn main() {
    let key_hex = "0x4418fb8c85bb3985394a8c2756d3643457ce614546202a2f50b093d762499ace";
    let anchor_hex = "0xd61a38a0f73beda90e8c1dfba731f65003742539f4260694f44e22cabef24a8e";
    let sig_hex = "0xf23ddcfb8239e6b9fe943b085b5661b587d3cee9a5db2d3098ed69a1debc621ef17fc6960b39fb90a7e6675a1c7ad1c0eed37894f3ba240f918620a597075e0d";
    
    let key: [u8; 32] = hex_to_bytes(key_hex).try_into().unwrap();
    let sig: [u8; 64] = hex_to_bytes(sig_hex).try_into().unwrap();
    let anchor = hex_to_bytes(anchor_hex);
    let bitfield: u8 = 0x02;  // From test: 0x02
    
    println!("Testing strawberry format (jam_available + H(E(HP, af))):");
    
    // Strawberry format: jam_available + H(parent_hash || bitfield)
    let mut encoded = anchor.clone();
    encoded.push(bitfield);  // 1 byte for tiny config (2 cores)
    let hash: [u8; 32] = Blake2b::<U32>::digest(&encoded).into();
    let mut msg = b"jam_available".to_vec();
    msg.extend(&hash);
    try_verify("jam_available + H(HP||bf)", &msg, &key, &sig);
    
    // With $ prefix
    let mut msg2 = b"$jam_available".to_vec();
    msg2.extend(&hash);
    try_verify("$jam_available + H(HP||bf)", &msg2, &key, &sig);
    
    // Maybe SCALE encoding adds something?
    // For fixed-size arrays, SCALE = raw bytes
    // For dynamic arrays, SCALE = length prefix + bytes
    // Let's try with explicit length for bitfield
    let mut encoded2 = anchor.clone();
    encoded2.push(1);  // length prefix for 1-byte bitfield
    encoded2.push(bitfield);
    let hash2: [u8; 32] = Blake2b::<U32>::digest(&encoded2).into();
    let mut msg3 = b"jam_available".to_vec();
    msg3.extend(&hash2);
    try_verify("jam_available + H(HP||len||bf)", &msg3, &key, &sig);
    
    println!("\nEncoded (HP||bf) = {} bytes", encoded.len());
    println!("Hash = {:?}", hex::encode(&hash));
}
