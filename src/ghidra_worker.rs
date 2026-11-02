//! Persistent out-of-process worker for the Ghidra Java host adapter.
//!
//! The worker accepts bounded JSON-lines requests on stdin and writes one
//! response per request on stdout. Diagnostics are kept on stderr so stdout
//! remains a machine-readable transport.

use std::io::{self, BufReader, BufWriter};

use serde_json::json;

use crate::ghidra_host::{
    read_frame, write_frame, FunctionDescriptor, HostCommand, HostRequest, HostResponse,
    MemoryBlock, ProgramSnapshot,
};
use crate::{Program, PseudocodeDecompiler};

struct LoadedBlock {
    start: u64,
    end: u64,
    program: Program,
}

/// Stateful worker. A program snapshot is retained across requests and each
/// executable memory block is decoded lazily, then reused for later functions.
pub struct GhidraWorker {
    snapshot: Option<ProgramSnapshot>,
    loaded_blocks: Vec<LoadedBlock>,
    shutdown: bool,
}

impl Default for GhidraWorker {
    fn default() -> Self {
        Self { snapshot: None, loaded_blocks: Vec::new(), shutdown: false }
    }
}

impl GhidraWorker {
    pub fn is_shutdown(&self) -> bool { self.shutdown }

    pub fn handle(&mut self, request: HostRequest) -> HostResponse {
        let id = request.request_id;
        let result = match request.command {
            HostCommand::Ping => Ok(json!({
                "status": "ready",
                "worker": "ghidra-rust-worker",
                "protocol_version": request.protocol_version,
                "engine": env!("CARGO_PKG_VERSION"),
            })),
            HostCommand::OpenProgram(snapshot) => self.open_program(snapshot),
            HostCommand::Decompile { function_address } => self.decompile(function_address),
            HostCommand::Cancel { target_request_id } => Ok(json!({
                "accepted": false,
                "target_request_id": target_request_id,
                "reason": "requests are currently processed serially; concurrent cancellation is not available",
            })),
            HostCommand::Shutdown => {
                self.shutdown = true;
                Ok(json!({ "status": "shutting_down" }))
            }
        };
        match result {
            Ok(payload) => HostResponse::success(id, payload),
            Err(error) => HostResponse::failure(id, error),
        }
    }

    fn open_program(&mut self, snapshot: ProgramSnapshot) -> Result<serde_json::Value, String> {
        let executable_blocks = snapshot.memory_blocks.iter()
            .filter(|block| block.executable && !block.bytes.is_empty()).count();
        if executable_blocks == 0 {
            return Err("program snapshot contains no initialized executable memory blocks".into());
        }
        let function_count = snapshot.functions.len();
        let symbol_count = snapshot.symbols.len();
        let relocation_count = snapshot.relocations.len();
        let name = snapshot.name.clone();
        let language_id = snapshot.language_id.clone();
        self.snapshot = Some(snapshot);
        self.loaded_blocks.clear();
        Ok(json!({
            "status": "opened",
            "name": name,
            "language_id": language_id,
            "executable_blocks": executable_blocks,
            "functions": function_count,
            "symbols_received": symbol_count,
            "relocations_received": relocation_count,
            "note": "memory and function metadata are retained; symbols and relocations are currently transport metadata, not yet applied to the Rust Program database",
        }))
    }

    fn decompile(&mut self, address: u64) -> Result<serde_json::Value, String> {
        let snapshot = self.snapshot.as_ref()
            .ok_or_else(|| "no program is open; send open_program first".to_string())?;
        let function: FunctionDescriptor = snapshot.functions.iter()
            .find(|function| function.entry == address)
            .cloned()
            .ok_or_else(|| format!("function {address:#x} is not present in the host snapshot"))?;
        let block_index = snapshot.memory_blocks.iter().position(|block: &MemoryBlock| {
            if !block.executable || block.bytes.is_empty() { return false; }
            let end = block.start.saturating_add(block.bytes.len() as u64);
            address >= block.start && address < end
        }).ok_or_else(|| format!("function {address:#x} is not inside an initialized executable memory block"))?;
        let block = &snapshot.memory_blocks[block_index];
        let end = block.start.checked_add(block.bytes.len() as u64)
            .ok_or_else(|| "executable memory range overflow".to_string())?;
        let loaded_index = match self.loaded_blocks.iter().position(|loaded| loaded.start == block.start && loaded.end == end) {
            Some(index) => index,
            None => {
                let program = Program::from_raw_bytes(block.bytes.clone(), &snapshot.language_id, block.start)
                    .map_err(|error| format!("could not initialize Rust architecture for {}: {error}", snapshot.language_id))?;
                self.loaded_blocks.push(LoadedBlock { start: block.start, end, program });
                self.loaded_blocks.len() - 1
            }
        };
        let loaded = &mut self.loaded_blocks[loaded_index];
        loaded.program.ensure_function_at(address, Some(&function.name))
            .map_err(|error| format!("could not register function {} at {address:#x}: {error}", function.name))?;
        let pseudocode = PseudocodeDecompiler::default()
            .decompile(&mut loaded.program, address)
            .map_err(|error| format!("decompilation failed for {} at {address:#x}: {error}", function.name))?;
        let lines: Vec<_> = pseudocode.lines.iter().map(|line| json!({
            "number": line.number,
            "text": line.text,
        })).collect();
        Ok(json!({
            "address": format!("0x{address:x}"),
            "name": pseudocode.name,
            "symbol": pseudocode.symbol,
            "source": pseudocode.source,
            "lines": lines,
            "truncated": pseudocode.truncated,
            "body_size_hint": function.body_size,
            "source_of_memory": "Ghidra memory snapshot",
        }))
    }
}

/// Run until EOF, a shutdown command, or an unrecoverable framing error.
pub fn run_stdio() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = BufWriter::new(stdout.lock());
    let mut worker = GhidraWorker::default();
    while let Some(frame) = read_frame(&mut input)? {
        let response = match HostRequest::parse_frame(&frame) {
            Ok(request) => worker.handle(request),
            Err(error) => HostResponse::failure("", error),
        };
        write_frame(&mut output, &response)?;
        if worker.is_shutdown() { break; }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra_host::HOST_PROTOCOL_VERSION;

    #[test]
    fn ping_reports_worker_protocol_and_version() {
        let request = HostRequest {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id: "ping-1".into(),
            command: HostCommand::Ping,
        };
        let response = GhidraWorker::default().handle(request);
        assert!(response.ok);
        assert_eq!(response.payload["status"], "ready");
        assert_eq!(response.payload["worker"], "ghidra-rust-worker");
    }

    #[test]
    fn decompile_requires_an_open_program() {
        let request = HostRequest {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id: "decompile-1".into(),
            command: HostCommand::Decompile { function_address: 0x1000 },
        };
        let response = GhidraWorker::default().handle(request);
        assert!(!response.ok);
        assert!(response.error.unwrap().contains("open_program"));
    }

    #[test]
    fn shutdown_changes_worker_state() {
        let request = HostRequest {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id: "stop".into(),
            command: HostCommand::Shutdown,
        };
        let mut worker = GhidraWorker::default();
        let response = worker.handle(request);
        assert!(response.ok);
        assert!(worker.is_shutdown());
    }
}
