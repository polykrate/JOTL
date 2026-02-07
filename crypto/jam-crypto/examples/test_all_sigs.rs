use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use std::fs;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn test_judgements(test_name: &str, validators_json: &Value, verdict_json: &Value) {
    let votes = verdict_json["votes"].as_array().unwrap();
    let target = verdict_json["target"].as_str().unwrap();
    let target_bytes = hex_to_bytes(target);
    
    println!("\n  JUDGEMENTS (votes):");
    let mut valid_count = 0;
    
    for vote in votes {
        let vote_val = vote["vote"].as_bool().unwrap();
        let index = vote["index"].as_u64().unwrap() as usize;
        let sig_hex = vote["signature"].as_str().unwrap();
        
        let validator = &validators_json[index];
        let key_hex = validator["ed25519"].as_str().unwrap();
        
        let key_bytes: [u8; 32] = hex_to_bytes(key_hex).try_into().unwrap();
        let sig_bytes: [u8; 64] = hex_to_bytes(sig_hex).try_into().unwrap();
        
        let context = if vote_val { "$jam_valid" } else { "$jam_invalid" };
        let mut message = Vec::new();
        message.extend_from_slice(context.as_bytes());
        message.extend_from_slice(&target_bytes);
        
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        
        let valid = verifying_key.verify(&message, &signature).is_ok();
        if valid { valid_count += 1; }
        
        println!("    [{}] vote={}, sig={}", index, vote_val, if valid { "✅ VALID" } else { "❌ INVALID" });
    }
    
    println!("  → {}/{} judgements avec signatures VALIDES", valid_count, votes.len());
}

fn test_culprits(culprits_json: &Value) {
    println!("\n  CULPRITS:");
    let mut valid_count = 0;
    
    for culprit in culprits_json.as_array().unwrap() {
        let target_hex = culprit["target"].as_str().unwrap();
        let key_hex = culprit["key"].as_str().unwrap();
        let sig_hex = culprit["signature"].as_str().unwrap();
        
        let target_bytes = hex_to_bytes(target_hex);
        let key_bytes: [u8; 32] = hex_to_bytes(key_hex).try_into().unwrap();
        let sig_bytes: [u8; 64] = hex_to_bytes(sig_hex).try_into().unwrap();
        
        let context = "$jam_guarantee";
        let mut message = Vec::new();
        message.extend_from_slice(context.as_bytes());
        message.extend_from_slice(&target_bytes);
        
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        
        let valid = verifying_key.verify(&message, &signature).is_ok();
        if valid { valid_count += 1; }
        
        println!("    key={}, sig={}", &key_hex[..20], if valid { "✅ VALID" } else { "❌ INVALID" });
    }
    
    println!("  → {}/{} culprits avec signatures VALIDES", valid_count, culprits_json.as_array().unwrap().len());
}

fn main() {
    let base = "/home/polycrate/Projets/lisp/jamtestvectors/stf/disputes/tiny";
    
    let tests = vec![
        ("progress_with_culprits-4", "OK"),
        ("progress_with_bad_signatures-1", "bad_signature (judgements)"),
        ("progress_with_bad_signatures-2", "bad_signature (culprits)"),
    ];
    
    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║           SIGNATURES VALIDES: JUDGEMENTS vs CULPRITS             ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    
    for (test_name, expected) in tests {
        let path = format!("{}/{}.json", base, test_name);
        let contents = fs::read_to_string(&path).unwrap();
        let test: Value = serde_json::from_str(&contents).unwrap();
        
        println!("\n{}:", test_name);
        println!("  Expected: {}", expected);
        
        let disputes = &test["input"]["disputes"];
        let validators = &test["pre_state"]["kappa"];
        let verdict = &disputes["verdicts"][0];
        let culprits = &disputes["culprits"];
        
        test_judgements(test_name, validators, verdict);
        test_culprits(culprits);
    }
    
    println!("\n╚═══════════════════════════════════════════════════════════════════╝");
}
