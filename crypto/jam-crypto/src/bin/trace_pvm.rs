//! trace_pvm — Phase 3: Rust reference PVM instruction tracer
//!
//! Loads a JAM code blob, sets up the PVM with step tracing,
//! and produces an instruction trace in the same format as the Lisp tracer:
//!   step# PC opcode gas R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12
//!
//! Usage:
//!   cargo run --bin trace_pvm -- <blob-file> [--pc 5] [--gas 20000000]
//!                                [--args-hex DEADBEEF] [--out /tmp/trace.txt]

use polkavm::{Config, Engine, Module, ModuleConfig, ProgramBlob, Linker, Reg, ProgramCounter};
use jam_program_blob_common::ProgramBlob as JamProgramBlob;
use std::io::{Write, BufWriter};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse CLI args
    let blob_path = args.get(1).expect("Usage: trace_pvm <blob-file> [--pc N] [--gas N] [--args-hex HEX] [--out FILE]");
    let mut pc_val: u32 = 5;      // default: accumulate entry point
    let mut gas_val: i64 = 20_000_000;
    let mut args_hex: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--pc" => { pc_val = args[i+1].parse().unwrap(); i += 2; }
            "--gas" => { gas_val = args[i+1].parse().unwrap(); i += 2; }
            "--args-hex" => { args_hex = Some(args[i+1].clone()); i += 2; }
            "--out" => { out_path = Some(args[i+1].clone()); i += 2; }
            _ => { i += 1; }
        }
    }

    // Read blob
    let blob_bytes = std::fs::read(blob_path).expect("Failed to read blob file");

    // Create engine (interpreter backend for deterministic tracing)
    let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
    config.set_backend(Some(polkavm::BackendKind::Interpreter));
    let engine = Engine::new(&config).expect("Failed to create engine");

    // Load module with step tracing + gas metering
    let jam_blob = JamProgramBlob::from_bytes(&blob_bytes)
        .expect("Failed to parse JAM blob");
    let parts: polkavm::ProgramParts = jam_blob.into();
    let program_blob = ProgramBlob::from_parts(parts)
        .expect("Failed to create program blob");

    let mut module_config = ModuleConfig::new();
    module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    module_config.set_step_tracing(true);

    let module = Module::from_blob(&engine, &module_config, program_blob)
        .expect("Failed to compile module");

    // Create instance
    let linker = Linker::<()>::new();
    let instance_pre = linker.instantiate_pre(&module).expect("Failed to instantiate_pre");
    let mut instance = instance_pre.instantiate().expect("Failed to instantiate");

    // Set gas
    instance.set_gas(gas_val);

    // Allocate args via sbrk if provided
    let mut args_addr: u32 = 0;
    let mut args_len: usize = 0;
    if let Some(hex) = args_hex {
        let data = hex::decode(&hex).expect("Invalid hex for --args-hex");
        args_len = data.len();
        let aligned = ((data.len() + 7) & !7) as u32;
        if let Ok(Some(heap_top)) = instance.sbrk(aligned) {
            let start = heap_top.saturating_sub(aligned);
            instance.write_memory(start, &data).expect("Failed to write args");
            args_addr = start;
        }
    }

    // Set up entry: prepare_call_untyped(PC, [args_addr, args_len])
    instance.prepare_call_untyped(
        ProgramCounter(pc_val),
        &[args_addr as u64, args_len as u64],
    );

    // Open output
    let out: Box<dyn Write> = if let Some(ref path) = out_path {
        Box::new(std::fs::File::create(path).expect("Failed to create output file"))
    } else {
        Box::new(std::io::stdout())
    };
    let mut out = BufWriter::new(out);

    writeln!(out, "# step PC opcode gas RA SP T0 T1 T2 S0 S1 A0 A1 A2 A3 A4 A5").unwrap();

    let all_regs = [
        Reg::RA, Reg::SP, Reg::T0, Reg::T1, Reg::T2,
        Reg::S0, Reg::S1, Reg::A0, Reg::A1, Reg::A2,
        Reg::A3, Reg::A4, Reg::A5,
    ];

    let mut step: u64 = 0;

    loop {
        // Log state BEFORE this step executes
        let pc = instance.program_counter().unwrap_or(ProgramCounter(0));
        let gas = instance.gas();

        step += 1;

        // We can't easily read the opcode byte from the polkaVM instance,
        // but we can read code bytes from the blob. Since we parsed the blob
        // into a module, we don't have easy byte access. We'll output PC only.
        // The opcode column will be 0 (not available in Rust tracer).
        write!(out, "{} {} 0 {}", step, pc.0, gas).unwrap();
        for &reg in &all_regs {
            write!(out, " {}", instance.reg(reg)).unwrap();
        }
        writeln!(out).unwrap();

        // Execute one step
        match instance.run() {
            Ok(polkavm::InterruptKind::Step) => {
                // Continue — single step completed
            }
            Ok(polkavm::InterruptKind::Finished) => {
                eprintln!("HALT at step {} PC={}", step, pc.0);
                break;
            }
            Ok(polkavm::InterruptKind::Trap) => {
                eprintln!("TRAP/PANIC at step {} PC={}", step, pc.0);
                break;
            }
            Ok(polkavm::InterruptKind::NotEnoughGas) => {
                eprintln!("OOG at step {} PC={}", step, pc.0);
                break;
            }
            Ok(polkavm::InterruptKind::Ecalli(id)) => {
                // Log ecalli and stop (no host call handling in this tracer)
                eprintln!("ECALLI({}) at step {} PC={} — stopping (no host dispatch)", id, step, pc.0);
                break;
            }
            Ok(polkavm::InterruptKind::Segfault(addr)) => {
                eprintln!("SEGFAULT at step {} PC={} addr={:?}", step, pc.0, addr);
                break;
            }
            #[allow(unreachable_patterns)]
            Ok(other) => {
                eprintln!("UNKNOWN INTERRUPT {:?} at step {} PC={}", other, step, pc.0);
                break;
            }
            Err(e) => {
                eprintln!("ERROR at step {} PC={}: {:?}", step, pc.0, e);
                break;
            }
        }
    }

    out.flush().unwrap();
    eprintln!("Traced {} steps", step);
}
