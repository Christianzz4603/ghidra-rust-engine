use std::collections::BTreeSet;
use std::ops::Range;

use super::{FunctionSource, Program};
use crate::address::Address;
use crate::database::SymbolId;
use crate::error::Result;
use crate::op::PcodeOp;
use crate::oplist::LinkedNode;
use crate::space::SpaceRef;

const MAX_DISCOVERED_FUNCTIONS: usize = 100_000;
const MAX_ARM64_PROLOGUE_CANDIDATES: usize = 50_000;
const MAX_ARM64_SCAN_BYTES: u64 = 128 * 1024 * 1024;

pub(super) struct FlowFacts {
    pub(super) call_targets: Vec<u64>,
    pub(super) constants: BTreeSet<u64>,
    pub(super) body: Range<u64>,
}

impl Program {
    pub(super) fn flow_facts(&mut self, sym: SymbolId) -> Result<Option<FlowFacts>> {
        self.architecture.with_function(sym, |function, architecture| {
            if function.has_no_code() {
                return Ok(None);
            }
            architecture.clear_analysis(function);
            let space: Option<SpaceRef> = function.get_address().get_space().cloned();
            let highest = space.as_ref().map(|space| space.get_highest()).unwrap_or(u64::MAX);
            let start = Address::from_parts(space.clone(), 0);
            let end = Address::from_parts(space, highest);
            if function.follow_flow(&start, &end, architecture).is_err() {
                architecture.clear_analysis(function);
                return Ok(None);
            }
            let entry = function.get_address().get_offset();
            let mut facts = FlowFacts {
                call_targets: Vec::new(),
                constants: BTreeSet::new(),
                body: entry..entry.saturating_add(1),
            };
            let mut position = function.begin_op_alive();
            while let Some(op) = position {
                let operation = function.op(op);
                let address = operation.get_addr().get_offset();
                facts.body = facts.body.start.min(address)..facts.body.end.max(address.saturating_add(1));
                for slot in 0..operation.num_input() {
                    let input = function.vn(operation.get_in(slot));
                    if input.is_constant() {
                        facts.constants.insert(input.get_offset());
                    }
                }
                position = operation.links(PcodeOp::INSERT_LIST).next;
            }
            for index in 0..function.num_calls() {
                let target = function.call_spec(function.get_call_specs(index)).get_entry_address();
                if !target.is_invalid() {
                    facts.call_targets.push(target.get_offset());
                }
            }
            architecture.clear_analysis(function);
            Ok(Some(facts))
        })
    }

    pub fn discover_functions(&mut self) -> Result<()> {
        let mut seeds = Vec::new();
        if let Some(entry) = self.entry.take() {
            seeds.push(entry);
        }
        let known_symbols: Vec<SymbolId> = self.functions.keys().copied().collect();
        for sym in known_symbols {
            if let Ok(address) = self.function_address(sym) {
                seeds.push(address);
            }
        }

        // Stripped ARM64 shared libraries often have few or no function symbols.
        // Supplement entry-point/call-graph discovery with conservative prologue
        // scanning across executable sections so otherwise-unreferenced functions
        // can still be recovered.
        seeds.extend(self.arm64_prologue_seeds()?);
        seeds.sort_unstable();
        seeds.dedup();
        seeds.truncate(MAX_DISCOVERED_FUNCTIONS);
        super::panic_guard(|| self.discover_from(seeds))
    }

    fn arm64_prologue_seeds(&self) -> Result<Vec<u64>> {
        let language = self.language_id().to_ascii_uppercase();
        if !language.contains("AARCH64") && !language.contains("ARM64") {
            return Ok(Vec::new());
        }

        const CHUNK_SIZE: u64 = 64 * 1024;
        const STP_FP_LR_PREINDEX_MASK: u32 = 0xFFC0_7FFF;
        const STP_FP_LR_PREINDEX: u32 = 0xA980_7BFD;
        const PACIASP: u32 = 0xD503_233F;
        const BTI_C: u32 = 0xD503_245F;

        let mut candidates = Vec::new();
        let mut scanned_bytes = 0u64;
        for section in &self.code_sections {
            if scanned_bytes >= MAX_ARM64_SCAN_BYTES {
                break;
            }
            let Some(aligned_start) = section.start.checked_add(3).map(|value| value & !3) else {
                continue;
            };
            let mut chunk_start = aligned_start;
            while chunk_start < section.end && scanned_bytes < MAX_ARM64_SCAN_BYTES {
                let chunk_end = chunk_start
                    .saturating_add(CHUNK_SIZE + 12)
                    .min(section.end)
                    .min(chunk_start.saturating_add(MAX_ARM64_SCAN_BYTES - scanned_bytes));
                let Ok(bytes) = self.read_code(chunk_start, chunk_end - chunk_start) else {
                    chunk_start = chunk_start.saturating_add(CHUNK_SIZE) & !3;
                    continue;
                };
                scanned_bytes = scanned_bytes.saturating_add(bytes.len() as u64);
                let words = bytes.len() / 4;
                for index in 0..words {
                    let offset = index * 4;
                    let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    if word & STP_FP_LR_PREINDEX_MASK == STP_FP_LR_PREINDEX {
                        if candidates.len() < MAX_ARM64_PROLOGUE_CANDIDATES {
                            candidates.push(chunk_start + offset as u64);
                        }
                        continue;
                    }
                    if word != PACIASP && word != BTI_C {
                        continue;
                    }
                    // PAC/BTI may precede the frame setup. Only accept the
                    // sequence when an FP/LR save follows within three instructions.
                    let has_frame_setup = (1..=3).any(|lookahead| {
                        let next = index + lookahead;
                        if next >= words {
                            return false;
                        }
                        let start = next * 4;
                        let following = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
                        following & STP_FP_LR_PREINDEX_MASK == STP_FP_LR_PREINDEX
                    });
                    if has_frame_setup {
                        if candidates.len() < MAX_ARM64_PROLOGUE_CANDIDATES {
                            candidates.push(chunk_start + offset as u64);
                        }
                    }
                }
                chunk_start = (chunk_start + CHUNK_SIZE) & !3;
            }
        }
        Ok(candidates)
    }

    fn discover_from(&mut self, seeds: Vec<u64>) -> Result<()> {
        let mut pending = seeds;
        let mut visited = BTreeSet::new();
        while let Some(address) = pending.pop() {
            if visited.len() >= MAX_DISCOVERED_FUNCTIONS {
                break;
            }
            if !visited.insert(address) || !self.is_code_address(address) {
                continue;
            }
            let sym = self.discovered_function(address)?;
            let Some(facts) = self.flow_facts(sym)? else {
                continue;
            };
            pending.extend(facts.call_targets);
            pending.extend(
                facts
                    .constants
                    .into_iter()
                    .filter(|constant| !facts.body.contains(constant)),
            );
        }
        Ok(())
    }

    fn discovered_function(&mut self, address: u64) -> Result<SymbolId> {
        let code_address = self.code_address(address)?;
        let scope = self.global_scope()?;
        if let Some(sym) = self.symbol_table()?.scope_query_function(scope, &code_address) {
            return Ok(sym);
        }
        let mut name = String::new();
        self.architecture.name_function(&code_address, &mut name);
        self.add_named_function(&name, None, &code_address, FunctionSource::Discovered)
    }
}
