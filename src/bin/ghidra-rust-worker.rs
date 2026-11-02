fn main() {
    if let Err(error) = ghidra_decompiler::ghidra_worker::run_stdio() {
        eprintln!("ghidra-rust-worker: {error}");
        std::process::exit(1);
    }
}
