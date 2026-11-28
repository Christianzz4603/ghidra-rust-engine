//! Memory probe: how many bytes does each per-function structure cost? Used by the scale harness
//! (`REVERSEPP_MEM_PROBE=1`) to find what dominates memory when a library has hundreds of
//! thousands of functions.

use std::any::Any;

use super::Program;
use crate::address::Address;
use crate::funcdata::Funcdata;
use crate::fspec::FuncProto;
use crate::heritage::Heritage;
use crate::merge::Merge;
use crate::op::PcodeOpBank;
use crate::overrides::Override;
use crate::varnode::VarnodeBank;

const SAMPLES: usize = 20_000;

fn resident_bytes() -> usize {
    // Exact live heap bytes when a counting allocator is installed; otherwise resident set size,
    // which also includes allocator fragmentation.
    let live = crate::ifacedecomp::LIVE_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    if live > 0 {
        return live;
    }
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<usize>().ok())
        })
        .map_or(0, |kb| kb * 1024)
}

impl Program {
    /// Approximate resident bytes per instance of each structure a function owns. Instances are
    /// all kept alive until the end so later samples cannot reuse earlier freed memory.
    pub fn probe_function_footprint(&mut self) -> Vec<(&'static str, usize)> {
        let mut rows = Vec::new();
        let mut keep: Vec<Box<dyn Any>> = Vec::new();
        {
            let glb = &*self.architecture;
            let Some(trans) = glb.translate.as_deref() else {
                return rows;
            };
            let mut sample = |label: &'static str, make: &mut dyn FnMut() -> Box<dyn Any>| {
                let before = resident_bytes();
                let held: Vec<Box<dyn Any>> = (0..SAMPLES).map(|_| make()).collect();
                let after = resident_bytes();
                rows.push((label, after.saturating_sub(before) / SAMPLES));
                keep.push(Box::new(held));
            };
            sample("VarnodeBank", &mut || Box::new(VarnodeBank::new(&glb.manager, trans)));
            sample("PcodeOpBank", &mut || Box::new(PcodeOpBank::new()));
            sample("Heritage", &mut || Box::new(Heritage::new()));
            sample("Merge", &mut || Box::new(Merge::new()));
            sample("FuncProto", &mut || Box::new(FuncProto::new()));
            sample("Override", &mut || Box::new(Override::new()));
        }
        let before = resident_bytes();
        let mut funcs = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            match Funcdata::new("", "", None, &Address::invalid(), None, 0, &mut self.architecture) {
                Ok(fd) => funcs.push(Box::new(fd)),
                Err(_) => break,
            }
        }
        let count = funcs.len().max(1);
        rows.push((
            "Funcdata (no scope)",
            resident_bytes().saturating_sub(before) / count,
        ));
        keep.push(Box::new(funcs));

        // Real discovery path: create function symbols for known starts, then lift each one.
        let hints: Vec<u64> = self.start_hints.iter().copied().take(5_000).collect();
        if !hints.is_empty() {
            let before = resident_bytes();
            let mut symbols = Vec::new();
            for &address in &hints {
                if let Ok(symbol) = self.discovered_function(address) {
                    symbols.push(symbol);
                }
            }
            let count = symbols.len().max(1);
            rows.push((
                "function symbol + Funcdata + local scope (real)",
                resident_bytes().saturating_sub(before) / count,
            ));
            let before = resident_bytes();
            let started = std::time::Instant::now();
            let mut lifted = 0usize;
            for &symbol in &symbols {
                if matches!(self.flow_facts(symbol), Ok(Some(_))) {
                    lifted += 1;
                }
            }
            rows.push((
                "retained after flow_facts, per lifted function",
                resident_bytes().saturating_sub(before) / lifted.max(1),
            ));
            rows.push((
                "flow_facts microseconds per lifted function",
                started.elapsed().as_micros() as usize / lifted.max(1),
            ));
            let counts = |program: &Program| {
                program
                    .architecture
                    .symboltab
                    .as_deref()
                    .map_or((0, 0), |db| (db.scopes.len(), db.symbols.len()))
            };
            let type_count = |program: &Program| program.architecture.types.as_deref().map_or(0, |types| types.arena.len());
            rows.push(("types after first flow pass", type_count(self)));
            let (scopes_after_first, symbols_after_first) = counts(self);
            rows.push(("scopes after first flow pass", scopes_after_first));
            rows.push(("symbols after first flow pass", symbols_after_first));
            // A second pass over the same functions: if memory stops growing, the retention is a
            // one-time artifact of the first lift (new symbols, types, caches), not a per-call leak.
            let before = resident_bytes();
            crate::ifacedecomp::track(1);
            for &symbol in &symbols {
                let _ = self.flow_facts(symbol);
            }
            crate::ifacedecomp::track(2);
            rows.push((
                "retained by second flow pass, per function",
                resident_bytes().saturating_sub(before) / symbols.len().max(1),
            ));
            rows.push(("types after second flow pass", type_count(self)));
            let (scopes_after_second, symbols_after_second) = counts(self);
            rows.push(("scopes after second flow pass", scopes_after_second));
            rows.push(("symbols after second flow pass", symbols_after_second));
            // Which global store holds the leftovers? Clear each and see how much live heap is freed.
            let before = resident_bytes();
            if let Some(comments) = self.architecture.commentdb.as_deref_mut() {
                comments.clear();
            }
            rows.push((
                "freed by clearing all comments, per function",
                before.saturating_sub(resident_bytes()) / symbols.len().max(1),
            ));
            let before = resident_bytes();
            {
                let mut cache = self.pcode_cache.borrow_mut();
                cache.entries.clear();
                cache.order.clear();
                cache.estimated_bytes = 0;
            }
            rows.push((
                "freed by clearing the P-code cache, per function",
                before.saturating_sub(resident_bytes()) / symbols.len().max(1),
            ));
            // Bisect which step of flow_facts keeps memory: clearing alone, or flow plus clearing.
            let sample: Vec<_> = symbols.iter().copied().take(1_000).collect();
            let n = sample.len().max(1);
            let before = resident_bytes();
            for &symbol in &sample {
                let _ = self.architecture.with_function(symbol, |function, architecture| {
                    if !function.has_no_code() {
                        architecture.clear_analysis(function);
                    }
                    Ok(())
                });
            }
            rows.push(("A: clear_analysis only, per function", resident_bytes().saturating_sub(before) / n));
            for label in ["B1: follow_flow + clear (first)", "B2: follow_flow + clear (repeat)"] {
                let before = resident_bytes();
                for &symbol in &sample {
                    let _ = self.architecture.with_function(symbol, |function, architecture| {
                        if function.has_no_code() {
                            return Ok(());
                        }
                        architecture.clear_analysis(function);
                        let space = function.get_address().get_space().cloned();
                        let highest = space.as_ref().map_or(u64::MAX, |space| space.get_highest());
                        let start = Address::from_parts(space.clone(), 0);
                        let end = Address::from_parts(space, highest);
                        let _ = function.follow_flow(&start, &end, architecture);
                        architecture.clear_analysis(function);
                        Ok(())
                    });
                }
                rows.push((label, resident_bytes().saturating_sub(before) / n));
            }
        }
        drop(keep);
        rows
    }
}
