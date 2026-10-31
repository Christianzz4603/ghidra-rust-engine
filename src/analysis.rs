use std::path::Path;

use crate::error::{Error, Result};
use crate::program::{CallEdge, DataEntry, FunctionEntry, Instruction, Program, StringEntry, SymbolLoading};

#[derive(Clone, Debug)]
pub struct AnalysisOptions {
    pub discover_functions: bool,

    pub disassemble: bool,

    pub decompile: bool,

    pub extract_strings: bool,

    pub collect_data_symbols: bool,

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

impl AnalysisOptions {
    pub fn low_memory() -> Self {
        Self {
            discover_functions: true,
            disassemble: false,
            decompile: true,
            extract_strings: false,
            collect_data_symbols: false,
            build_call_graph: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AnalysisSelection {
    pub function_addresses: Option<Vec<u64>>,
    pub start_address: Option<u64>,
    pub end_address: Option<u64>,
    pub max_functions: Option<usize>,
}

impl AnalysisSelection {
    pub fn with_function_addresses(mut self, addresses: impl IntoIterator<Item = u64>) -> Self {
        self.function_addresses = Some(addresses.into_iter().collect());
        self
    }

    pub fn with_address_range(mut self, start: u64, end: u64) -> Self {
        self.start_address = Some(start);
        self.end_address = Some(end);
        self
    }

    pub fn with_max_functions(mut self, maximum: usize) -> Self {
        self.max_functions = Some(maximum);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if let (Some(start), Some(end)) = (self.start_address, self.end_address) {
            if start >= end {
                return Err(Error::Lowlevel(format!(
                    "invalid analysis range: start {start:#x} must be below end {end:#x}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FunctionAnalysis {
    pub function: FunctionEntry,
    pub size: Option<u64>,
    pub instructions: Vec<Instruction>,
    pub pseudocode: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum AnalysisEvent {
    Started {
        total_functions: usize,
    },
    FunctionStarted {
        index: usize,
        total: usize,
        address: u64,
        name: String,
    },
    FunctionCompleted {
        index: usize,
        total: usize,
        result: FunctionAnalysis,
    },
    Finished {
        analyzed: usize,
        with_errors: usize,
        total: usize,
    },
}

#[derive(Clone, Debug)]
pub struct AnalysisReport {
    pub functions: Vec<FunctionEntry>,
    pub data_symbols: Vec<DataEntry>,
    pub strings: Vec<StringEntry>,
    pub call_edges: Vec<CallEdge>,
    pub analyzed_functions: usize,
    pub functions_with_errors: usize,
}

pub struct AnalysisEngine {
    program: Program,
}

impl AnalysisEngine {
    pub fn open(path: &Path, language: Option<&str>) -> Result<Self> {
        Ok(Self {
            program: Program::open(path, language)?,
        })
    }

    pub fn from_image(name: &str, bytes: Vec<u8>, language: Option<&str>) -> Result<Self> {
        Ok(Self {
            program: Program::from_image(name, bytes, language)?,
        })
    }

    pub fn open_with(path: &Path, language: Option<&str>, loading: SymbolLoading) -> Result<Self> {
        Ok(Self {
            program: Program::open_with(path, language, loading)?,
        })
    }

    pub fn from_image_with(name: &str, bytes: Vec<u8>, language: Option<&str>, loading: SymbolLoading) -> Result<Self> {
        Ok(Self {
            program: Program::from_image_with(name, bytes, language, loading)?,
        })
    }

    pub fn from_raw_bytes(bytes: Vec<u8>, language: &str, base_address: u64) -> Result<Self> {
        Ok(Self {
            program: Program::from_raw_bytes(bytes, language, base_address)?,
        })
    }

    pub fn from_program(program: Program) -> Self {
        Self { program }
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    pub fn program_mut(&mut self) -> &mut Program {
        &mut self.program
    }

    pub fn analyze_function(&mut self, address: u64, options: &AnalysisOptions) -> Result<FunctionAnalysis> {
        let function = self.program.ensure_function_at(address, None)?;
        Ok(analyze_one(&mut self.program, &function, options))
    }

    pub fn analyze_function_by_name(&mut self, name: &str, options: &AnalysisOptions) -> Result<FunctionAnalysis> {
        let function = self
            .program
            .find_function_by_name(name)?
            .ok_or_else(|| Error::Lowlevel(format!("function not found: {name}")))?;
        Ok(analyze_one(&mut self.program, &function, options))
    }

    pub fn analyze(
        &mut self,
        options: &AnalysisOptions,
        on_event: impl FnMut(AnalysisEvent),
    ) -> Result<AnalysisReport> {
        self.analyze_selected(options, &AnalysisSelection::default(), on_event)
    }

    pub fn analyze_selected(
        &mut self,
        options: &AnalysisOptions,
        selection: &AnalysisSelection,
        mut on_event: impl FnMut(AnalysisEvent),
    ) -> Result<AnalysisReport> {
        selection.validate()?;
        if options.discover_functions {
            self.program.discover_functions()?;
        }

        let mut functions = self.program.functions()?;
        if let Some(addresses) = &selection.function_addresses {
            functions.retain(|function| addresses.contains(&function.address));
        }
        if let Some(start) = selection.start_address {
            functions.retain(|function| function.address >= start);
        }
        if let Some(end) = selection.end_address {
            functions.retain(|function| function.address < end);
        }
        if let Some(maximum) = selection.max_functions {
            functions.truncate(maximum);
        }
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

            let result = analyze_one(&mut self.program, function, options);
            if result.errors.is_empty() {
                analyzed += 1;
            } else {
                with_errors += 1;
            }
            on_event(AnalysisEvent::FunctionCompleted { index, total, result });
        }

        on_event(AnalysisEvent::Finished {
            analyzed,
            with_errors,
            total,
        });
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

fn analyze_one(program: &mut Program, function: &FunctionEntry, options: &AnalysisOptions) -> FunctionAnalysis {
    let mut result = FunctionAnalysis {
        function: function.clone(),
        size: None,
        instructions: Vec::new(),
        pseudocode: None,
        errors: Vec::new(),
    };
    if options.disassemble {
        match program.function_size(function.address) {
            Ok(size) if size > 0 => {
                result.size = Some(size);
                match program.disassemble_range(function.address, size) {
                    Ok(instructions) => result.instructions = instructions,
                    Err(error) => result.errors.push(format!("disassembly: {}", error.explain())),
                }
            }
            Ok(_) => result.errors.push("function has no measurable body".to_string()),
            Err(error) => result.errors.push(format!("function size: {}", error.explain())),
        }
    }
    if options.decompile {
        match program.decompile(function.address) {
            Ok(pseudocode) => result.pseudocode = Some(pseudocode),
            Err(error) => result.errors.push(format!("decompilation: {}", error.explain())),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::AnalysisOptions;

    #[test]
    fn low_memory_profile_keeps_decompilation_and_skips_optional_passes() {
        let options = AnalysisOptions::low_memory();
        assert!(options.discover_functions);
        assert!(options.decompile);
        assert!(!options.disassemble);
        assert!(!options.extract_strings);
        assert!(!options.collect_data_symbols);
        assert!(!options.build_call_graph);
    }

    #[test]
    fn selection_builders_compose_address_and_count_filters() {
        let selection = super::AnalysisSelection::default()
            .with_function_addresses([0x100, 0x200])
            .with_address_range(0x80, 0x300)
            .with_max_functions(1);
        assert_eq!(selection.function_addresses, Some(vec![0x100, 0x200]));
        assert_eq!(selection.start_address, Some(0x80));
        assert_eq!(selection.end_address, Some(0x300));
        assert_eq!(selection.max_functions, Some(1));
    }

    #[test]
    fn invalid_address_range_is_rejected() {
        let selection = super::AnalysisSelection::default().with_address_range(0x300, 0x100);
        assert!(selection.validate().is_err());
        assert!(
            super::AnalysisSelection::default()
                .with_address_range(0x100, 0x300)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn default_profile_keeps_all_analysis_passes_enabled() {
        let options = AnalysisOptions::default();
        assert!(options.discover_functions);
        assert!(options.disassemble);
        assert!(options.decompile);
        assert!(options.extract_strings);
        assert!(options.collect_data_symbols);
        assert!(options.build_call_graph);
    }
}
