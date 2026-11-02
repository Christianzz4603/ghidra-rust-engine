//! Cross-platform pseudocode facade for interactive decompiler clients.
//!
//! This module provides a stable, presentation-oriented API over the native
//! decompilation pipeline. It is an independent implementation layer and does
//! not contain or depend on Hex-Rays proprietary code.

use crate::{Error, FunctionEntry, Program, Result};

/// Controls pseudocode generation and batch analysis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PseudocodeOptions {
    /// Include blank lines in the returned line model.
    pub include_empty_lines: bool,
    /// Maximum number of functions processed by a batch. `None` means all.
    pub max_functions: Option<usize>,
    /// Maximum UTF-8 bytes retained for one function. `None` means unlimited.
    pub max_output_bytes: Option<usize>,
    /// Discover reachable functions before a batch run.
    pub discover_functions: bool,
}

impl PseudocodeOptions {
    /// Conservative defaults for desktop and mobile hosts processing large binaries.
    /// Call `unbounded` explicitly when the caller can afford whole-program output.
    pub fn resource_bounded() -> Self {
        Self {
            include_empty_lines: true,
            max_functions: Some(1_000),
            max_output_bytes: Some(128 * 1024),
            discover_functions: true,
        }
    }

    /// Restore the legacy unlimited batch and output behavior.
    pub fn unbounded() -> Self {
        Self {
            include_empty_lines: true,
            max_functions: None,
            max_output_bytes: None,
            discover_functions: true,
        }
    }
}

impl Default for PseudocodeOptions {
    fn default() -> Self {
        Self::resource_bounded()
    }
}

/// One display line of decompiled pseudocode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PseudocodeLine {
    /// One-based line number in the returned pseudocode.
    pub number: usize,
    /// Source text without the trailing newline.
    pub text: String,
}

/// Pseudocode and metadata for one recovered function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionPseudocode {
    pub address: u64,
    pub name: String,
    pub symbol: Option<String>,
    pub source: String,
    pub lines: Vec<PseudocodeLine>,
    pub truncated: bool,
}

/// A function that could not be decompiled during a batch run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecompileFailure {
    pub address: u64,
    pub name: String,
    pub message: String,
}

/// Result of a multi-function pseudocode pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecompileBatch {
    pub functions: Vec<FunctionPseudocode>,
    pub failures: Vec<DecompileFailure>,
    pub considered: usize,
}

impl DecompileBatch {
    pub fn succeeded(&self) -> usize {
        self.functions.len()
    }

    pub fn failed(&self) -> usize {
        self.failures.len()
    }

    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Stateful configuration wrapper around the program's native decompiler.
///
/// The wrapper is intentionally backend-agnostic: callers can use the same
/// API on Android, Linux, Windows, and macOS wherever the Rust target builds.
#[derive(Clone, Debug, Default)]
pub struct PseudocodeDecompiler {
    options: PseudocodeOptions,
}

impl PseudocodeDecompiler {
    pub fn new(options: PseudocodeOptions) -> Self {
        Self { options }
    }

    pub fn resource_bounded() -> Self {
        Self::new(PseudocodeOptions::resource_bounded())
    }

    pub fn options(&self) -> &PseudocodeOptions {
        &self.options
    }

    /// Decompile one function by its entry address.
    pub fn decompile(&self, program: &mut Program, address: u64) -> Result<FunctionPseudocode> {
        let function = program
            .functions()?
            .into_iter()
            .find(|function| function.address == address)
            .ok_or_else(|| Error::Lowlevel(format!("no function found at {address:#x}")))?;
        self.decompile_entry(program, function)
    }

    /// Decompile recovered functions, retaining per-function failures instead
    /// of aborting the entire batch when one function is unsupported.
    pub fn decompile_all(&self, program: &mut Program) -> Result<DecompileBatch> {
        if self.options.discover_functions {
            program.discover_functions()?;
        }

        let mut entries = program.functions()?;
        entries.sort_by_key(|function| function.address);
        if let Some(limit) = self.options.max_functions {
            entries.truncate(limit);
        }

        let mut batch = DecompileBatch {
            considered: entries.len(),
            ..DecompileBatch::default()
        };

        for entry in entries {
            match self.decompile_entry(program, entry.clone()) {
                Ok(result) => batch.functions.push(result),
                Err(error) => batch.failures.push(DecompileFailure {
                    address: entry.address,
                    name: entry.name,
                    message: error.to_string(),
                }),
            }
        }
        Ok(batch)
    }

    fn decompile_entry(&self, program: &mut Program, entry: FunctionEntry) -> Result<FunctionPseudocode> {
        let mut source = program.decompile(entry.address)?;
        let mut truncated = false;

        if let Some(max_bytes) = self.options.max_output_bytes {
            if source.len() > max_bytes {
                let mut boundary = max_bytes.min(source.len());
                while !source.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                source.truncate(boundary);
                truncated = true;
            }
        }

        let lines = source
            .lines()
            .enumerate()
            .filter(|(_, line)| self.options.include_empty_lines || !line.trim().is_empty())
            .map(|(index, line)| PseudocodeLine {
                number: index + 1,
                text: line.to_string(),
            })
            .collect();

        Ok(FunctionPseudocode {
            address: entry.address,
            name: entry.name,
            symbol: entry.symbol,
            source,
            lines,
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_bounded_profile_caps_batch_size_and_output() {
        let options = PseudocodeOptions::resource_bounded();
        assert_eq!(options.max_functions, Some(1_000));
        assert_eq!(options.max_output_bytes, Some(128 * 1024));
        assert!(options.discover_functions);
    }

    #[test]
    fn defaults_are_resource_bounded() {
        let options = PseudocodeOptions::default();
        assert_eq!(options.max_functions, Some(1_000));
        assert_eq!(options.max_output_bytes, Some(128 * 1024));
        assert!(options.discover_functions);
        assert!(options.include_empty_lines);
    }

    #[test]
    fn unbounded_profile_preserves_legacy_behavior() {
        let options = PseudocodeOptions::unbounded();
        assert!(options.max_functions.is_none());
        assert!(options.max_output_bytes.is_none());
    }

    #[test]
    fn batch_counts_are_consistent() {
        let batch = DecompileBatch {
            considered: 2,
            functions: Vec::new(),
            failures: vec![
                DecompileFailure { address: 1, name: "a".into(), message: "x".into() },
                DecompileFailure { address: 2, name: "b".into(), message: "y".into() },
            ],
        };
        assert_eq!(batch.succeeded(), 0);
        assert_eq!(batch.failed(), 2);
        assert!(!batch.is_complete());
    }
}
