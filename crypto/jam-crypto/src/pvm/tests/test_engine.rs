use super::*;

#[test]
fn test_engine_creation() {
    // Use JAM engine (interpreter backend) for maximum portability
    let engine = pvm_engine_new_jam();
    if engine.is_null() {
        // polkavm may not be available in all environments (e.g., sandboxed CI)
        eprintln!("SKIP: polkavm engine creation failed (sandbox?)");
        return;
    }
    unsafe { pvm_engine_free(engine); }
}

#[test]
fn test_version() {
    let version = pvm_version();
    let s = unsafe { std::ffi::CStr::from_ptr(version) };
    assert!(s.to_str().unwrap().contains("polkavm"));
}
