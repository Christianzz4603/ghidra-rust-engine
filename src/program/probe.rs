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
        drop(keep);
        rows
    }
}
