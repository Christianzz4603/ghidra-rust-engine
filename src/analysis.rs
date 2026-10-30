//! High-level, reusable binary-analysis API.
//!
//! This module is independent of the console and output-file layout. Applications
//! can consume progress events and decide how to display or persist each result.

use std::path::Path;

use crate::error::Result;
use crate::program::{CallEdge, DataEntry, FunctionEntry, Instruction, Program, StringEntry};

/// Controls which analysis passes are run by [`AnalysisEngine::analyze`].
#[derive(Clone, Debug)]
pub struct AnalysisOptions {
    /// Discover additional functions from the entry point and reachable code.
    pub discover_functions: bool,
    /// Decode machine instructions for each discovered function.
    pub disassemble: bool,
    /// Produce C-like pseudocode for each discovered function.
    pub decompile: bool,
    /// Extract printable UTF-8 strings from recognized string sections.
    pub extract_strings: bool,
    /// Include recognized global data symbols.
    pub collect_data_symbols: bool,
    /// Build direct call-graph edges.
    pub build_call_graph: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            discover_functions: true,
            disassemble: true,
            decompile: true,
            extract_strings: true,
            collect_data_symbols: true,
            build_call_graph: true,
        }
    }
}

/// Results for one function. Errors are local to this function and do not abort
/// analysis of the remaining functions.
#[derive(Clone, Debug)]
pub struct FunctionAnalysis {
    pub function: FunctionEntry,
    pub size: Option<u64>,
    pub instructions: Vec<Instruction>,
    pub pseudocode: Option<String>,
    pub errors: Vec<String>,
}

/// Progress notifications emitted while an analysis is running.
#[derive(Debug)]
#[non_exhaustive]
pub enum AnalysisEvent {
    Started { total_functions: usize },
    FunctionStarted { index: usize, total: usize, address: u64, name: String },
    FunctionCompleted { index: usize, total: usize, result: FunctionAnalysis },
    Finished { analyzed: usize, with_errors: usize, total: usize },
}

/// Metadata and aggregate counts from a completed analysis.
#[derive(Clone, Debug)]
pub struct AnalysisReport {
    pub functions: Vec<FunctionEntry>,
    pub data_symbols: Vec<DataEntry>,
    pub strings: Vec<StringEntry>,
    pub call_edges: Vec<CallEdge>,
    pub analyzed_functions: usize,
    pub functions_with_errors: usize,
}

/// Reusable analysis session around the decompiler's architecture and program model.
///
/// The engine does not write files, print to stdout, or depend on a UI framework.
/// Consume [`AnalysisEvent`] values to update a UI or stream results to storage.
pub struct AnalysisEngine {
    program: Program,
}

impl AnalysisEngine {
    /// Open an ELF, PE, or Mach-O executable or shared library.
    pub fn open(path: &Path, language: Option<&str>) -> Result<Self> {
        Ok(Self { program: Program::open(path, language)? })
    }

    /// Create an analysis session from executable image bytes.
    pub fn from_image(name: &str, bytes: Vec<u8>, language: Option<&str>) -> Result<Self> {
        Ok(Self { program: Program::from_image(name, bytes, language)? })
    }

    /// Wrap an already configured [`Program`].
    pub fn from_program(program: Program) -> Self {
        Self { program }
    }

    /// Access the underlying program for advanced architecture-specific features.
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// Access the underlying program mutably for advanced architecture-specific features.
    pub fn program_mut(&mut self) -> &mut Program {
        &mut self.program
    }

    /// Run configured analysis passes and emit one owned result per function.
    ///
    /// The callback is invoked synchronously on the calling thread. It can forward
    /// events to an application channel, update a progress display, or stream each
    /// function's output to disk without retaining the entire binary's pseudocode.
    pub fn analyze(
        &mut self,
        options: &AnalysisOptions,
        mut on_event: impl FnMut(AnalysisEvent),
    ) -> Result<AnalysisReport> {
        if options.discover_functions {
            self.program.discover_functions()?;
        }

        let functions = self.program.functions()?;
        let data_symbols = if options.collect_data_symbols {
            self.program.data_symbols()?
        } else {
            Vec::new()
        };
        let strings = if options.extract_strings {
            self.program.strings()?
        } else {
            Vec::new()
        };
        let call_edges = if options.build_call_graph {
            self.program.call_graph()?
        } else {
            Vec::new()
        };

        let total = functions.len();
        on_event(AnalysisEvent::Started { total_functions: total });
        let mut analyzed = 0usize;
        let mut with_errors = 0usize;

        for (offset, function) in functions.iter().enumerate() {
            let index = offset + 1;
            on_event(AnalysisEvent::FunctionStarted {
                index,
                total,
                address: function.address,
                name: function.name.clone(),
            });

            let mut result = FunctionAnalysis {
                function: function.clone(),
                size: None,
                instructions: Vec::new(),
                pseudocode: None,
                errors: Vec::new(),
            };

            if options.disassemble {
                match self.program.function_size(function.address) {
                    Ok(size) if size > 0 => {
                        result.size = Some(size);
                        match self.program.disassemble_range(function.address, size) {
                            Ok(instructions) => result.instructions = instructions,
                            Err(error) => result.errors.push(format!("disassembly: {}", error.explain())),
                        }
                    }
                    Ok(_) => result.errors.push("function has no measurable body".to_string()),
                    Err(error) => result.errors.push(format!("function size: {}", error.explain())),
                }
            }

            if options.decompile {
                match self.program.decompile(function.address) {
                    Ok(pseudocode) => result.pseudocode = Some(pseudocode),
                    Err(error) => result.errors.push(format!("decompilation: {}", error.explain())),
                }
            }

            if result.errors.is_empty() {
                analyzed += 1;
            } else {
                with_errors += 1;
            }
            on_event(AnalysisEvent::FunctionCompleted { index, total, result });
        }

        on_event(AnalysisEvent::Finished { analyzed, with_errors, total });
        Ok(AnalysisReport {
            functions,
            data_symbols,
            strings,
            call_edges,
            analyzed_functions: analyzed,
            functions_with_errors: with_errors,
        })
    }
}
