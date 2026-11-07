//! Persistent out-of-process worker for the Ghidra Java host adapter.
//!
//! The worker accepts bounded JSON-lines requests on stdin and writes one
//! response per request on stdout. Diagnostics are kept on stderr so stdout
//! remains a machine-readable transport.

use std::io::{self, BufReader, BufWriter};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use serde_json::json;

use crate::ghidra_host::{
    FunctionDescriptor, HostCommand, HostRequest, HostResponse, MemoryBlock, MemoryBlockChunk, ProgramSnapshot,
    read_frame, write_frame,
};
use crate::{Program, PseudocodeDecompiler};

const MAX_WORKER_PCODE_CACHE_BYTES: usize = 8 * 1024 * 1024;

struct PendingBlock {
    total_size: usize,
    bytes: Vec<u8>,
    readable: bool,
    writable: bool,
    executable: bool,
}

struct LoadedBlock {
    start: u64,
    end: u64,
    executable: bool,
    program: Program,
}

#[derive(Default)]
struct HydrationCounters {
    memory_blocks_loaded: usize,
    executable_blocks_loaded: usize,
    functions_applied: usize,
    function_signatures_applied: usize,
    function_symbols_applied: usize,
    data_symbols_applied: usize,
    comments_applied: usize,
    duplicate_comments: usize,
    references_applied: usize,
    relocations_recorded: usize,
    data_types_recorded: usize,
    context_values_applied: usize,
    relocations_deferred: usize,
    references_deferred: usize,
    data_types_deferred: usize,
    context_values_deferred: usize,
    symbols_outside_loaded_blocks: usize,
}

impl HydrationCounters {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "memory_blocks_loaded": self.memory_blocks_loaded,
            "executable_blocks_loaded": self.executable_blocks_loaded,
            "functions_applied": self.functions_applied,
            "function_signatures_applied": self.function_signatures_applied,
            "function_symbols_applied": self.function_symbols_applied,
            "data_symbols_applied": self.data_symbols_applied,
            "comments_applied": self.comments_applied,
            "duplicate_comments": self.duplicate_comments,
            "references_applied": self.references_applied,
            "relocations_recorded": self.relocations_recorded,
            "data_types_recorded": self.data_types_recorded,
            "context_values_applied": self.context_values_applied,
            "relocations_deferred": self.relocations_deferred,
            "references_deferred": self.references_deferred,
            "data_types_deferred": self.data_types_deferred,
            "context_values_deferred": self.context_values_deferred,
            "symbols_outside_loaded_blocks": self.symbols_outside_loaded_blocks,
        })
    }
}

/// Stateful worker. A program snapshot is retained across requests and each
/// executable memory block is decoded lazily, then reused for later functions.
pub struct GhidraWorker {
    snapshot: Option<ProgramSnapshot>,
    pending_snapshot: Option<ProgramSnapshot>,
    pending_blocks: std::collections::BTreeMap<u64, PendingBlock>,
    pending_memory_bytes: usize,
    loaded_blocks: Vec<LoadedBlock>,
    hydration_report: serde_json::Value,
    shutdown: bool,
}

impl Default for GhidraWorker {
    fn default() -> Self {
        Self {
            snapshot: None,
            pending_snapshot: None,
            pending_blocks: std::collections::BTreeMap::new(),
            pending_memory_bytes: 0,
            loaded_blocks: Vec::new(),
            hydration_report: json!({}),
            shutdown: false,
        }
    }
}

fn items_in_range<T, F>(items: &[T], start: u64, end: u64, address: F) -> &[T]
where
    F: Fn(&T) -> u64,
{
    let first = items.partition_point(|item| address(item) < start);
    let last = items.partition_point(|item| address(item) < end);
    &items[first..last]
}

impl GhidraWorker {
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

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
            HostCommand::BeginProgram(snapshot) => self.begin_program(snapshot),
            HostCommand::AddMemoryBlockChunk(chunk) => self.add_memory_block_chunk(chunk),
            HostCommand::FinishProgram => self.finish_program(),
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

    fn begin_program(&mut self, snapshot: ProgramSnapshot) -> Result<serde_json::Value, String> {
        if !snapshot.memory_blocks.is_empty() {
            return Err("begin_program metadata must not include inline memory_blocks".into());
        }
        self.pending_snapshot = Some(snapshot);
        self.pending_blocks.clear();
        self.pending_memory_bytes = 0;
        Ok(
            json!({"status":"receiving_memory","protocol":"chunked","max_block_bytes":8*1024*1024,"max_total_memory_bytes":64*1024*1024}),
        )
    }

    fn add_memory_block_chunk(&mut self, chunk: MemoryBlockChunk) -> Result<serde_json::Value, String> {
        if self.pending_snapshot.is_none() {
            return Err("send begin_program before memory block chunks".into());
        }
        if chunk.offset == 0 {
            if self.pending_blocks.contains_key(&chunk.start) {
                return Err(format!("duplicate memory block start {:#x}", chunk.start));
            }
            self.pending_memory_bytes = self
                .pending_memory_bytes
                .checked_add(chunk.total_size)
                .ok_or_else(|| "total memory size overflow".to_string())?;
            if self.pending_memory_bytes > 64 * 1024 * 1024 {
                return Err("streamed memory snapshot exceeds 64 MiB".into());
            }
            self.pending_blocks.insert(
                chunk.start,
                PendingBlock {
                    total_size: chunk.total_size,
                    bytes: Vec::with_capacity(chunk.total_size),
                    readable: chunk.readable,
                    writable: chunk.writable,
                    executable: chunk.executable,
                },
            );
        }
        let block = self
            .pending_blocks
            .get_mut(&chunk.start)
            .ok_or_else(|| format!("memory block {:#x} must begin with offset zero", chunk.start))?;
        if block.total_size != chunk.total_size
            || block.bytes.len() != chunk.offset
            || block.readable != chunk.readable
            || block.writable != chunk.writable
            || block.executable != chunk.executable
        {
            return Err(format!(
                "non-contiguous or inconsistent chunk for memory block {:#x}",
                chunk.start
            ));
        }
        block.bytes.extend_from_slice(&chunk.bytes);
        if block.bytes.len() != block.total_size && chunk.final_chunk {
            return Err("memory block marked final before all bytes arrived".into());
        }
        if block.bytes.len() == block.total_size && !chunk.final_chunk {
            return Err("completed memory block must set final_chunk".into());
        }
        Ok(
            json!({"status":"chunk_accepted","start":format!("{:#x}",chunk.start),"received":block.bytes.len(),"total":block.total_size,"complete":chunk.final_chunk}),
        )
    }

    fn finish_program(&mut self) -> Result<serde_json::Value, String> {
        let mut snapshot = self
            .pending_snapshot
            .take()
            .ok_or_else(|| "send begin_program before finish_program".to_string())?;
        if self.pending_blocks.is_empty() {
            return Err("streamed snapshot contains no memory blocks".into());
        }
        let mut blocks = Vec::with_capacity(self.pending_blocks.len());
        for (start, pending) in std::mem::take(&mut self.pending_blocks) {
            if pending.bytes.len() != pending.total_size {
                return Err(format!(
                    "memory block {start:#x} is incomplete: {} of {} bytes",
                    pending.bytes.len(),
                    pending.total_size
                ));
            }
            blocks.push(MemoryBlock {
                start,
                bytes: pending.bytes,
                readable: pending.readable,
                writable: pending.writable,
                executable: pending.executable,
            });
        }
        self.pending_memory_bytes = 0;
        snapshot.memory_blocks = blocks;
        self.open_program(snapshot)
    }

    fn open_program(&mut self, mut snapshot: ProgramSnapshot) -> Result<serde_json::Value, String> {
        if snapshot.memory_blocks.is_empty() {
            return Err("program snapshot contains no initialized memory blocks".into());
        }
        let mut loaded_blocks = Vec::with_capacity(snapshot.memory_blocks.len());
        let mut report = HydrationCounters::default();
        let mut failures = Vec::new();
        snapshot.functions.sort_unstable_by_key(|item| item.entry);
        snapshot.symbols.sort_unstable_by_key(|item| item.address);
        snapshot.comments.sort_unstable_by_key(|item| item.address);
        snapshot.references.sort_unstable_by_key(|item| item.from);
        snapshot.relocations.sort_unstable_by_key(|item| item.address);
        snapshot.context_values.sort_unstable_by_key(|item| item.address);
        let had_executable_memory = snapshot
            .memory_blocks
            .iter()
            .any(|block| block.executable && !block.bytes.is_empty());
        let memory_blocks = std::mem::take(&mut snapshot.memory_blocks);
        let per_program_cache_budget = MAX_WORKER_PCODE_CACHE_BYTES / memory_blocks.len().max(1);
        for block in memory_blocks {
            if block.bytes.is_empty() {
                continue;
            }
            let block_start = block.start;
            let block_executable = block.executable;
            let end = block_start
                .checked_add(block.bytes.len() as u64)
                .ok_or_else(|| "memory block address range overflow".to_string())?;
            let shared_bytes = Arc::new(block.bytes);
            let mut program = match Program::from_raw_shared_bytes(shared_bytes, &snapshot.language_id, block_start) {
                Ok(program) => program,
                Err(error) => {
                    failures.push(format!("memory block {:#x}: {error}", block_start));
                    continue;
                }
            };
            program.set_pcode_cache_limit(per_program_cache_budget);
            report.memory_blocks_loaded += 1;
            if block_executable {
                report.executable_blocks_loaded += 1;
            }

            for function in items_in_range(&snapshot.functions, block_start, end, |item| item.entry) {
                let qualified_name = function
                    .namespace
                    .as_ref()
                    .map(|namespace| format!("{namespace}::{}", function.name))
                    .unwrap_or_else(|| function.name.clone());
                match program.ensure_function_at(function.entry, Some(&qualified_name)) {
                    Ok(_) => report.functions_applied += 1,
                    Err(error) => {
                        failures.push(format!("function {} at {:#x}: {error}", qualified_name, function.entry))
                    }
                }
                let parameters = function
                    .parameters
                    .iter()
                    .map(|parameter| crate::ImportedParameter {
                        ordinal: parameter.ordinal,
                        name: parameter.name.clone(),
                        type_name: parameter.type_name.clone(),
                        storage: parameter.storage.clone(),
                    })
                    .collect();
                match program.import_function_signature(
                    function.entry,
                    function.calling_convention.as_deref(),
                    function.return_type.as_deref(),
                    parameters,
                ) {
                    Ok(()) => report.function_signatures_applied += 1,
                    Err(error) => failures.push(format!("function prototype at {:#x}: {error}", function.entry)),
                }
            }
            for symbol in items_in_range(&snapshot.symbols, block_start, end, |item| item.address) {
                let is_function = matches!(symbol.kind.to_ascii_lowercase().as_str(), "function" | "func" | "code")
                    || snapshot
                        .functions
                        .binary_search_by_key(&symbol.address, |function| function.entry)
                        .is_ok();
                if is_function {
                    let qualified_name = snapshot
                        .functions
                        .binary_search_by_key(&symbol.address, |function| function.entry)
                        .ok()
                        .map(|index| &snapshot.functions[index])
                        .map(|function| {
                            function
                                .namespace
                                .as_ref()
                                .map(|namespace| format!("{namespace}::{}", function.name))
                                .unwrap_or_else(|| function.name.clone())
                        })
                        .unwrap_or_else(|| symbol.name.clone());
                    match program.ensure_function_at(symbol.address, Some(&qualified_name)) {
                        Ok(_) => report.function_symbols_applied += 1,
                        Err(error) => failures.push(format!(
                            "function symbol {} at {:#x}: {error}",
                            symbol.name, symbol.address
                        )),
                    }
                } else {
                    let qualified_name = symbol
                        .namespace
                        .as_ref()
                        .map(|namespace| format!("{namespace}::{}", symbol.name))
                        .unwrap_or_else(|| symbol.name.clone());
                    match program.import_typed_data_symbol(
                        symbol.address,
                        &qualified_name,
                        symbol.size,
                        symbol.type_name.as_deref(),
                    ) {
                        Ok(()) => report.data_symbols_applied += 1,
                        Err(error) => {
                            failures.push(format!("data symbol {} at {:#x}: {error}", symbol.name, symbol.address))
                        }
                    }
                }
            }
            for comment in items_in_range(&snapshot.comments, block_start, end, |item| item.address) {
                let function_entry = comment.function_entry.unwrap_or(comment.address);
                match program.import_comment(function_entry, comment.address, &comment.kind, &comment.text) {
                    Ok(inserted) => {
                        if inserted {
                            report.comments_applied += 1;
                        } else {
                            report.duplicate_comments += 1;
                        }
                    }
                    Err(error) => failures.push(format!("comment at {:#x}: {error}", comment.address)),
                }
            }
            for reference in items_in_range(&snapshot.references, block_start, end, |item| item.from) {
                match program.import_reference(reference.from, reference.to, &reference.kind, reference.is_primary) {
                    Ok(inserted) => {
                        if inserted {
                            report.references_applied += 1;
                        }
                    }
                    Err(error) => {
                        failures.push(format!("reference {:#x}->{:#x}: {error}", reference.from, reference.to))
                    }
                }
            }
            for relocation in items_in_range(&snapshot.relocations, block_start, end, |item| item.address) {
                match program.import_relocation(
                    relocation.address,
                    &relocation.kind,
                    relocation.symbol.as_deref(),
                    relocation.addend,
                ) {
                    Ok(()) => report.relocations_recorded += 1,
                    Err(error) => failures.push(format!("relocation at {:#x}: {error}", relocation.address)),
                }
            }
            for data_type in &snapshot.data_types {
                match program.import_data_type(
                    &data_type.name,
                    &data_type.kind,
                    data_type.size,
                    data_type.signed,
                    data_type.encoding.as_deref(),
                ) {
                    Ok(()) => {
                        if report.memory_blocks_loaded == 1 {
                            report.data_types_recorded += 1;
                        }
                    }
                    Err(error) => failures.push(format!("datatype {}: {error}", data_type.name)),
                }
            }
            for context in items_in_range(&snapshot.context_values, block_start, end, |item| item.address) {
                match program.import_context_value(context.address, &context.register, context.value) {
                    Ok(()) => report.context_values_applied += 1,
                    Err(error) => failures.push(format!(
                        "context {} at {:#x}: {error}",
                        context.register, context.address
                    )),
                }
            }
            loaded_blocks.push(LoadedBlock {
                start: block.start,
                end,
                executable: block.executable,
                program,
            });
        }
        if !had_executable_memory {
            return Err("program snapshot contains no initialized executable memory blocks".into());
        }
        if !loaded_blocks.iter().any(|block| block.executable) {
            return Err(format!(
                "no executable memory blocks could be initialized: {}",
                failures.join("; ")
            ));
        }
        report.relocations_deferred = snapshot.relocations.len().saturating_sub(report.relocations_recorded);
        report.references_deferred = snapshot.references.len().saturating_sub(report.references_applied);
        report.data_types_deferred = snapshot.data_types.len().saturating_sub(report.data_types_recorded);
        report.context_values_deferred = snapshot
            .context_values
            .len()
            .saturating_sub(report.context_values_applied);
        report.symbols_outside_loaded_blocks = snapshot
            .symbols
            .iter()
            .filter(|symbol| {
                !loaded_blocks
                    .iter()
                    .any(|block| symbol.address >= block.start && symbol.address < block.end)
            })
            .count();
        let name = snapshot.name.clone();
        let language_id = snapshot.language_id.clone();
        let compiler_spec_id = snapshot.compiler_spec_id.clone();
        let summary = report.to_json();
        self.pending_snapshot = None;
        self.pending_blocks.clear();
        self.pending_memory_bytes = 0;
        self.snapshot = Some(snapshot);
        self.loaded_blocks = loaded_blocks;
        self.hydration_report = summary.clone();
        Ok(json!({
            "status": "opened",
            "name": name,
            "language_id": language_id,
            "compiler_spec_id": compiler_spec_id,
            "hydration": summary,
            "hydration_warnings": failures,
            "metadata_policy": "functions, symbols, comments, references, relocation descriptors, datatype descriptors and supported SLEIGH context values are imported into per-block Program state; relocation arithmetic and full datatype graph binding remain loader/type-factory work",
        }))
    }

    fn decompile(&mut self, address: u64) -> Result<serde_json::Value, String> {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| "no program is open; send open_program first".to_string())?;
        let function: FunctionDescriptor = snapshot
            .functions
            .iter()
            .find(|function| function.entry == address)
            .cloned()
            .ok_or_else(|| format!("function {address:#x} is not present in the host snapshot"))?;
        let loaded_index = self
            .loaded_blocks
            .iter()
            .position(|loaded| loaded.executable && address >= loaded.start && address < loaded.end)
            .ok_or_else(|| format!("function {address:#x} is not inside an initialized executable memory block"))?;
        let loaded = &mut self.loaded_blocks[loaded_index];
        let qualified_name = function
            .namespace
            .as_ref()
            .map(|namespace| format!("{namespace}::{}", function.name))
            .unwrap_or_else(|| function.name.clone());
        loaded
            .program
            .ensure_function_at(address, Some(&qualified_name))
            .map_err(|error| {
                format!(
                    "could not register function {} at {address:#x}: {error}",
                    qualified_name
                )
            })?;
        let pseudocode = PseudocodeDecompiler::resource_bounded()
            .decompile(&mut loaded.program, address)
            .map_err(|error| format!("decompilation failed for {} at {address:#x}: {error}", function.name))?;
        let lines: Vec<_> = pseudocode
            .lines
            .iter()
            .map(|line| {
                json!({
                    "number": line.number,
                    "text": line.text,
                })
            })
            .collect();
        Ok(json!({
            "address": format!("0x{address:x}"),
            "name": pseudocode.name,
            "symbol": pseudocode.symbol,
            "source": pseudocode.source,
            "lines": lines,
            "truncated": pseudocode.truncated,
            "body_size_hint": function.body_size,
            "source_of_memory": "Ghidra memory snapshot",
            "database_hydration": self.hydration_report,
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
            Ok(request) => {
                let request_id = request.request_id.clone();
                match catch_unwind(AssertUnwindSafe(|| worker.handle(request))) {
                    Ok(response) => response,
                    Err(_) => {
                        // A panic must not take down the host's worker process.
                        // Reset potentially inconsistent state before accepting another request.
                        worker = GhidraWorker::default();
                        HostResponse::failure(
                            request_id,
                            "internal worker error; session state was reset, please reopen the program",
                        )
                    }
                }
            }
            Err(error) => HostResponse::failure("", error),
        };
        write_frame(&mut output, &response)?;
        if worker.is_shutdown() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra_host::HOST_PROTOCOL_VERSION;

    #[test]
    fn metadata_range_lookup_skips_unrelated_entries() {
        let values = [(0x1000u64, "a"), (0x2000, "b"), (0x3000, "c"), (0x4000, "d")];
        let selected = items_in_range(&values, 0x2000, 0x4000, |item| item.0);
        assert_eq!(selected.iter().map(|item| item.1).collect::<Vec<_>>(), vec!["b", "c"]);
    }

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
            command: HostCommand::Decompile {
                function_address: 0x1000,
            },
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
