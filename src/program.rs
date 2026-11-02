mod demangle;
mod discovery;
mod stubs;
mod symbols;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::address::Address;
use crate::architecture::{Architecture, ArchitectureBuilder};
use crate::callgraph::CallGraph;
use crate::comment::{Comment, CommentDatabase};
use crate::database::{Database, ScopeId, SymbolId};
use crate::error::{Error, Result};
use crate::globalcontext::ContextDatabase;
use crate::loadimage::LoadImageFunc;
use crate::object_arch::{ObjectArchitecture, is_object_file};
use crate::opcodes::{OpCode, get_opname};
use crate::pcoderaw::VarnodeData;
use crate::raw_arch::RawBinaryArchitecture;
use crate::space::SpaceRef;
use crate::translate::{AddrSpaceManager, AssemblyEmit, PcodeEmit};
use crate::types::TypeMetatype;
use crate::xml::DocumentStorage;

const MAX_PCODE_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct PcodeCache {
    entries: HashMap<(u64, u64), Arc<Vec<InstructionPcode>>>,
    estimated_bytes: usize,
}

pub struct Program {
    architecture: Box<Architecture>,
    functions: BTreeMap<SymbolId, FunctionRecord>,
    data: BTreeMap<u64, DataRecord>,
    references: BTreeMap<u64, Vec<ProgramReference>>,
    relocations: BTreeMap<u64, ProgramRelocation>,
    imported_types: BTreeMap<String, ImportedDataType>,
    data_symbol_types: BTreeMap<u64, String>,
    function_signatures: BTreeMap<u64, ImportedFunctionSignature>,
    string_sections: Vec<std::ops::Range<u64>>,
    code_sections: Vec<std::ops::Range<u64>>,
    entry: Option<u64>,
    // Translation is immutable for a loaded image. Shared cached streams let
    // intelligence, SSA, and reconstruction reuse expensive P-code decoding.
    pcode_cache: RefCell<PcodeCache>,
}

const MIN_STRING_LENGTH: usize = 4;
const MAX_STRING_LENGTH: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolLoading {
    Loader,
    Full,
}

enum SymbolInput {
    None,
    Loader,
    Full(Box<symbols::ImageSymbols>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionSource {
    SymbolTable,
    DynamicSymbol,
    ImportStub,
    Discovered,
    Requested,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FunctionEntry {
    pub name: String,
    pub symbol: Option<String>,
    pub address: u64,
    pub source: FunctionSource,
}

struct FunctionRecord {
    name: String,
    loaded_name: String,
    symbol: Option<String>,
    source: FunctionSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataEntry {
    pub name: String,
    pub symbol: Option<String>,
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct StringEntry {
    pub address: u64,
    pub value: String,
}

struct DataRecord {
    sym: SymbolId,
    name: String,
    loaded_name: String,
    symbol: Option<String>,
    size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Instruction {
    pub address: u64,
    pub length: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcodeVarnode {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcodeOperation {
    pub opcode: OpCode,
    pub output: Option<PcodeVarnode>,
    pub inputs: Vec<PcodeVarnode>,
    pub space: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisassemblyGap {
    pub address: u64,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisassemblyReport {
    pub instructions: Vec<Instruction>,
    pub gaps: Vec<DisassemblyGap>,
    pub requested_bytes: u64,
    pub decoded_bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeSectionSummary {
    pub start: u64,
    pub end: u64,
    pub requested_bytes: u64,
    pub decoded_bytes: u64,
    pub undecoded_bytes: u64,
    pub instruction_count: u64,
    pub gap_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeScanSummary {
    pub sections: Vec<CodeSectionSummary>,
    pub requested_bytes: u64,
    pub decoded_bytes: u64,
    pub undecoded_bytes: u64,
    pub instruction_count: u64,
    pub gap_count: u64,
}

#[derive(Clone, Debug)]
pub struct InstructionPcode {
    pub address: u64,
    pub length: usize,
    pub operations: Vec<PcodeOperation>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallEdge {
    pub caller: u64,
    pub callee: u64,
    pub call_site: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProgramReference {
    pub from: u64,
    pub to: u64,
    pub kind: String,
    pub is_primary: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramRelocation {
    pub address: u64,
    pub kind: String,
    pub symbol: Option<String>,
    pub addend: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedParameter {
    pub ordinal: u32,
    pub name: String,
    pub type_name: String,
    pub storage: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedFunctionSignature {
    pub entry: u64,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    pub parameters: Vec<ImportedParameter>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedDataType {
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub signed: Option<bool>,
    pub encoding: Option<String>,
}

impl fmt::Display for PcodeVarnode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "({},{:#x},{})", self.space, self.offset, self.size)
    }
}

impl fmt::Display for PcodeOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(output) = &self.output {
            write!(formatter, "{output} = ")?;
        }
        formatter.write_str(get_opname(self.opcode))?;
        for (slot, input) in self.inputs.iter().enumerate() {
            match (&self.space, slot) {
                (Some(space), 0) => write!(formatter, " ({},space:{space},{})", input.space, input.size)?,
                _ => write!(formatter, " {input}")?,
            }
        }
        Ok(())
    }
}

struct InstructionText {
    mnemonic: String,
    operands: String,
}

impl AssemblyEmit for InstructionText {
    fn dump(&mut self, _addr: &Address, mnem: &str, body: &str) {
        self.mnemonic = mnem.to_string();
        self.operands = body.to_string();
    }
}

/// Sink used by analysis passes that only need instruction boundaries.
struct NullAssemblyEmit;

impl AssemblyEmit for NullAssemblyEmit {
    #[inline]
    fn dump(&mut self, _addr: &Address, _mnem: &str, _body: &str) {}
}

struct OperationCollector<'a> {
    manager: &'a AddrSpaceManager,
    operations: Vec<PcodeOperation>,
}

fn pcode_varnode(data: &VarnodeData) -> PcodeVarnode {
    PcodeVarnode {
        space: data
            .space
            .as_ref()
            .map(|space| space.get_name().to_string())
            .unwrap_or_default(),
        offset: data.offset,
        size: data.size,
    }
}

impl PcodeEmit for OperationCollector<'_> {
    fn dump(&mut self, _addr: &Address, opc: OpCode, outvar: Option<&VarnodeData>, vars: &[VarnodeData]) -> Result<()> {
        let space = match (opc, vars.first()) {
            (OpCode::Load | OpCode::Store, Some(space_operand)) => self
                .manager
                .get_space(space_operand.offset as i32)
                .map(|space| space.get_name().to_string()),
            _ => None,
        };
        self.operations.push(PcodeOperation {
            opcode: opc,
            output: outvar.map(pcode_varnode),
            inputs: vars.iter().map(pcode_varnode).collect(),
            space,
        });
        Ok(())
    }
}

fn string_label(text: &str) -> String {
    text.chars()
        .take(16)
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn panic_guard<R>(run: impl FnOnce() -> Result<R>) -> Result<R> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|payload| {
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
            .unwrap_or_else(|| "unknown panic".to_string());
        Err(Error::Lowlevel(format!("internal decompiler error: {message}")))
    })
}

fn estimate_pcode_bytes(instructions: &[InstructionPcode]) -> usize {
    instructions.iter().fold(0usize, |total, instruction| {
        let operations = instruction.operations.iter().fold(0usize, |sum, operation| {
            let varnodes = operation.inputs.iter().map(|input| {
                std::mem::size_of::<PcodeVarnode>() + input.space.len()
            }).sum::<usize>();
            let output = operation.output.as_ref().map_or(0, |value| {
                std::mem::size_of::<PcodeVarnode>() + value.space.len()
            });
            sum.saturating_add(std::mem::size_of::<PcodeOperation>())
                .saturating_add(varnodes).saturating_add(output)
                .saturating_add(operation.space.as_ref().map_or(0, String::len))
        });
        total.saturating_add(std::mem::size_of::<InstructionPcode>())
            .saturating_add(operations)
    })
}

impl Program {
    pub fn open(path: &Path, language: Option<&str>) -> Result<Program> {
        Program::open_with(path, language, SymbolLoading::Full)
    }

    pub fn open_with(path: &Path, language: Option<&str>, loading: SymbolLoading) -> Result<Program> {
        let bytes = std::fs::read(path)
            .map_err(|error| Error::Lowlevel(format!("failed to read '{}': {error}", path.display())))?;
        Program::from_image_with(&path.to_string_lossy(), bytes, language, loading)
    }

    pub fn from_image(name: &str, bytes: Vec<u8>, language: Option<&str>) -> Result<Program> {
        Program::from_image_with(name, bytes, language, SymbolLoading::Full)
    }

    pub fn from_image_with(
        name: &str,
        bytes: Vec<u8>,
        language: Option<&str>,
        loading: SymbolLoading,
    ) -> Result<Program> {
        if !is_object_file(&bytes) {
            return Err(Error::Lowlevel(format!("unrecognized executable format: {name}")));
        }
        let symbols = match loading {
            SymbolLoading::Loader => SymbolInput::Loader,
            SymbolLoading::Full => SymbolInput::Full(Box::new(symbols::image_symbols(&bytes))),
        };
        let builder = ObjectArchitecture::with_bytes(name, language.unwrap_or("default"), bytes);
        Program::initialize(Arc::new(builder), symbols)
    }

    pub fn from_raw_bytes(bytes: Vec<u8>, language: &str, base_address: u64) -> Result<Program> {
        let code_end = base_address.saturating_add(bytes.len() as u64);
        let builder = RawBinaryArchitecture::with_bytes("raw", language, bytes, base_address);
        let mut program = Program::initialize(Arc::new(builder), SymbolInput::None)?;
        program.code_sections = std::iter::once(base_address..code_end).collect();
        program.entry = Some(base_address);
        Ok(program)
    }

    fn initialize(builder: Arc<dyn ArchitectureBuilder>, symbols: SymbolInput) -> Result<Program> {
        panic_guard(|| Program::initialize_unguarded(builder, symbols))
    }

    fn initialize_unguarded(builder: Arc<dyn ArchitectureBuilder>, symbols: SymbolInput) -> Result<Program> {
        let mut architecture = Box::new(Architecture::new());
        architecture.builder = Some(builder);
        let mut store = DocumentStorage::new();
        architecture.init(&mut store)?;
        let mut program = Program {
            architecture,
            functions: BTreeMap::new(),
            data: BTreeMap::new(),
            references: BTreeMap::new(),
            relocations: BTreeMap::new(),
            imported_types: BTreeMap::new(),
            data_symbol_types: BTreeMap::new(),
            function_signatures: BTreeMap::new(),
            string_sections: Vec::new(),
            code_sections: Vec::new(),
            entry: None,
            pcode_cache: RefCell::new(PcodeCache::default()),
        };
        match symbols {
            SymbolInput::None => {}
            SymbolInput::Loader => program.architecture.read_loader_symbols()?,
            SymbolInput::Full(image) => program.add_symbols(*image)?,
        }
        Ok(program)
    }

    fn add_symbols(&mut self, image: symbols::ImageSymbols) -> Result<()> {
        self.string_sections = image.string_sections.clone();
        self.code_sections = image.code_sections.clone();
        let loader = self
            .architecture
            .loader
            .clone()
            .ok_or_else(|| Error::Lowlevel("missing load image".to_string()))?;
        self.architecture.loadersymbols_parsed = true;
        let mut named_addresses = BTreeSet::new();
        let mut record = LoadImageFunc::default();
        loader.open_symbols();
        while loader.get_next_symbol(&mut record) {
            if image.undefined_names.contains(&record.name) {
                continue;
            }
            named_addresses.insert(record.address.get_offset());
            self.add_function_symbol(&record.name, &record.address, FunctionSource::SymbolTable)?;
        }
        loader.close_symbols();
        for function in &image.dynamic_functions {
            if named_addresses.insert(function.address) {
                let address = self.code_address(function.address)?;
                self.add_function_symbol(&function.name, &address, FunctionSource::DynamicSymbol)?;
            }
        }
        for data in &image.data_symbols {
            match demangle::demangled_name(&data.name) {
                Some(name) => self.add_data_symbol(&name, Some(&data.name), data.address, data.size),
                None => self.add_data_symbol(&data.name, None, data.address, data.size),
            }
        }
        for (slot, symbol) in &image.got_slot_symbols {
            let name = demangle::demangled_name(symbol).unwrap_or_else(|| symbol.clone());
            self.add_data_symbol(&format!("{name}@got"), Some(symbol), *slot, image.got_slot_size);
        }
        let defined_names: BTreeSet<String> = self.functions.values().map(|record| record.name.clone()).collect();
        for stub in stubs::import_stubs(self, &image) {
            if named_addresses.insert(stub.address) {
                let demangled = demangle::demangled_name(&stub.name).unwrap_or_else(|| stub.name.clone());
                let name = if defined_names.contains(&demangled) {
                    format!("{demangled}@plt")
                } else {
                    demangled
                };
                let symbol = (name != stub.name).then_some(stub.name.as_str());
                let address = self.code_address(stub.address)?;
                self.add_named_function(&name, symbol, &address, FunctionSource::ImportStub)?;
            }
        }
        self.entry = image.entry;
        Ok(())
    }

    fn add_data_symbol(&mut self, name: &str, symbol: Option<&str>, address: u64, size: u64) {
        if let Err(error) = self.add_typed_data_symbol(name, symbol, address, size) {
            self.architecture
                .print_warning(&format!("Data symbol {name} is not added: {}", error.explain()));
        }
    }

    fn add_typed_data_symbol(&mut self, name: &str, symbol: Option<&str>, address: u64, size: u64) -> Result<()> {
        let type_size = i32::try_from(size).map_err(|_| Error::Lowlevel(format!("data symbol too large: {name}")))?;
        let types = self.architecture.types_mut()?;
        let data_type = match type_size {
            1 | 2 | 4 | 8 => types.get_base(type_size, TypeMetatype::Unknown)?,
            _ => {
                let byte = types.get_base(1, TypeMetatype::Unknown)?;
                types.get_type_array(type_size, byte)?
            }
        };
        let scope = self.global_scope()?;
        let data_address = self.data_address(address)?;
        let entry = Database::scope_add_symbol_at(
            &mut self.architecture,
            scope,
            name,
            Some(data_type),
            &data_address,
            &Address::invalid(),
        )?;
        let sym = self.symbol_table()?.entry(entry).get_symbol();
        self.data.insert(
            address,
            DataRecord {
                sym,
                name: name.to_string(),
                loaded_name: name.to_string(),
                symbol: symbol.map(str::to_string),
                size,
            },
        );
        Ok(())
    }

    fn add_referenced_strings(&mut self, sym: SymbolId) -> Result<()> {
        if self.string_sections.is_empty() {
            return Ok(());
        }
        let constants = self.flow_facts(sym)?.map(|facts| facts.constants).unwrap_or_default();
        for constant in constants {
            if self.string_sections.iter().any(|section| section.contains(&constant)) {
                self.add_string_symbol(constant)?;
            }
        }
        Ok(())
    }

    fn add_string_symbol(&mut self, address: u64) -> Result<()> {
        let scope = self.global_scope()?;
        let data_address = self.data_address(address)?;
        if self
            .symbol_table()?
            .scope_query_container(scope, &data_address, 1, &Address::invalid())
            .is_some()
        {
            return Ok(());
        }
        let Some(text) = self.string_at(address) else {
            return Ok(());
        };
        let length = i32::try_from(text.len() + 1).map_err(|_| Error::Lowlevel("string too long".to_string()))?;
        let types = self.architecture.types_mut()?;
        let character = types.get_base(1, TypeMetatype::Int)?;
        let array = types.get_type_array(length, character)?;
        let name = format!("s_{}_{address:08x}", string_label(&text));
        Database::scope_add_symbol_at(
            &mut self.architecture,
            scope,
            &name,
            Some(array),
            &data_address,
            &Address::invalid(),
        )?;
        Ok(())
    }

    fn string_at(&self, address: u64) -> Option<String> {
        let loader = self.architecture.loader.as_ref()?;
        let data_address = self.data_address(address).ok()?;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 64];
        while bytes.len() < MAX_STRING_LENGTH {
            let chunk_address = data_address.add(bytes.len() as i64);
            loader.load_fill(&mut chunk, &chunk_address).ok()?;
            match chunk.iter().position(|byte| *byte == 0) {
                Some(end) => {
                    bytes.extend_from_slice(&chunk[..end]);
                    let text = String::from_utf8(bytes).ok()?;
                    let is_printable = text
                        .chars()
                        .all(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'));
                    return (text.chars().count() >= MIN_STRING_LENGTH && is_printable).then_some(text);
                }
                None => bytes.extend_from_slice(&chunk),
            }
        }
        None
    }

    pub fn entry_point(&self) -> Option<u64> {
        self.entry
    }

    pub fn find_function_by_name(&self, name: &str) -> Result<Option<FunctionEntry>> {
        Ok(self.functions()?.into_iter().find(|function| function.name == name))
    }

    pub fn find_function_at(&self, address: u64) -> Result<Option<FunctionEntry>> {
        Ok(self
            .functions()?
            .into_iter()
            .find(|function| function.address == address))
    }

    pub fn ensure_function_at(&mut self, address: u64, name: Option<&str>) -> Result<FunctionEntry> {
        self.function_at(address)?;
        if let Some(name) = name.filter(|name| !name.is_empty()) {
            self.set_function_name(address, name)?;
        }
        self.find_function_at(address)?
            .ok_or_else(|| Error::Lowlevel(format!("function at {address:#x} was not registered")))
    }

    pub fn read_memory(&self, address: u64, length: u64) -> Result<Vec<u8>> {
        let length =
            usize::try_from(length).map_err(|_| Error::Lowlevel("requested memory range is too large".to_string()))?;
        let loader = self
            .architecture
            .loader
            .as_ref()
            .ok_or_else(|| Error::Lowlevel("missing load image".to_string()))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|error| Error::Lowlevel(format!("unable to allocate memory buffer: {error}")))?;
        bytes.resize(length, 0);
        loader.load_fill(&mut bytes, &self.data_address(address)?)?;
        Ok(bytes)
    }

    pub fn read_code(&self, address: u64, length: u64) -> Result<Vec<u8>> {
        let length =
            usize::try_from(length).map_err(|_| Error::Lowlevel("requested code range is too large".to_string()))?;
        let loader = self
            .architecture
            .loader
            .as_ref()
            .ok_or_else(|| Error::Lowlevel("missing load image".to_string()))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|error| Error::Lowlevel(format!("unable to allocate code buffer: {error}")))?;
        bytes.resize(length, 0);
        loader.load_fill(&mut bytes, &self.code_address(address)?)?;
        Ok(bytes)
    }

    pub fn register_info(&self, name: &str) -> Result<PcodeVarnode> {
        let register = self.architecture.translator()?.get_register(name)?;
        Ok(pcode_varnode(&register))
    }

    pub fn set_print_language(&mut self, name: &str) -> Result<()> {
        self.architecture.set_print_language(name)
    }

    pub fn data_symbols(&self) -> Result<Vec<DataEntry>> {
        Ok(self
            .data
            .iter()
            .map(|(address, record)| DataEntry {
                name: record.name.clone(),
                symbol: record.symbol.clone(),
                address: *address,
                size: record.size,
            })
            .collect())
    }

    pub fn strings(&self) -> Result<Vec<StringEntry>> {
        const CHUNK_SIZE: usize = 64 * 1024;
        let loader = self
            .architecture
            .loader
            .as_ref()
            .ok_or_else(|| Error::Lowlevel("missing load image".to_string()))?;
        let mut result = Vec::new();
        for section in &self.string_sections {
            let mut offset = section.start;
            let mut pending = Vec::new();
            let mut pending_address = offset;
            while offset < section.end {
                let length = (section.end - offset).min(CHUNK_SIZE as u64) as usize;
                let mut chunk = vec![0u8; length];
                loader.load_fill(&mut chunk, &self.data_address(offset)?)?;
                for (index, byte) in chunk.into_iter().enumerate() {
                    let address = offset + index as u64;
                    if byte == 0 {
                        if pending.len() >= MIN_STRING_LENGTH
                            && let Ok(value) = std::str::from_utf8(&pending)
                            && value
                                .chars()
                                .all(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'))
                        {
                            result.push(StringEntry {
                                address: pending_address,
                                value: value.to_string(),
                            });
                        }
                        pending.clear();
                        pending_address = address + 1;
                    } else if pending.len() < MAX_STRING_LENGTH {
                        pending.push(byte);
                    } else {
                        pending.clear();
                        pending_address = address + 1;
                    }
                }
                offset += length as u64;
            }
        }
        result.sort_by_key(|entry| entry.address);
        result.dedup_by_key(|entry| entry.address);
        Ok(result)
    }

    /// Store the prototype recovered by Ghidra's Function/Parameter database.
    pub fn import_function_signature(&mut self, entry: u64, calling_convention: Option<&str>, return_type: Option<&str>, parameters: Vec<ImportedParameter>) -> Result<()> {
        if parameters.len() > 1024 { return Err(Error::Lowlevel("function prototype exceeds parameter limit".to_string())); }
        for value in calling_convention.iter().chain(return_type.iter()) {
            if value.len() > 1024 || value.contains('\0') { return Err(Error::Lowlevel("invalid function prototype metadata".to_string())); }
        }
        if parameters.iter().any(|parameter| parameter.name.len() > 1024 || parameter.type_name.len() > 1024 || parameter.name.contains('\0') || parameter.type_name.contains('\0')) {
            return Err(Error::Lowlevel("invalid imported parameter metadata".to_string()));
        }
        self.function_signatures.insert(entry, ImportedFunctionSignature { entry, calling_convention: calling_convention.map(str::to_string), return_type: return_type.map(str::to_string), parameters });
        Ok(())
    }

    pub fn function_signature(&self, entry: u64) -> Option<&ImportedFunctionSignature> { self.function_signatures.get(&entry) }

    /// Add an external program-database cross-reference to the native Program model.
    pub fn import_reference(&mut self, from: u64, to: u64, kind: &str, is_primary: bool) -> Result<bool> {
        if kind.is_empty() || kind.len() > 128 || kind.contains('\0') { return Err(Error::Lowlevel("invalid reference kind".to_string())); }
        let reference = ProgramReference { from, to, kind: kind.to_string(), is_primary };
        let entries = self.references.entry(from).or_default();
        if entries.contains(&reference) { return Ok(false); }
        entries.push(reference);
        entries.sort();
        Ok(true)
    }

    pub fn references_from(&self, address: u64) -> &[ProgramReference] {
        self.references.get(&address).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Preserve relocation semantics in the Program model. Applying machine-specific
    /// relocation arithmetic to raw bytes is deliberately handled by the loader layer.
    pub fn import_relocation(&mut self, address: u64, kind: &str, symbol: Option<&str>, addend: i64) -> Result<()> {
        if kind.is_empty() || kind.len() > 128 || kind.contains('\0') { return Err(Error::Lowlevel("invalid relocation kind".to_string())); }
        self.relocations.insert(address, ProgramRelocation { address, kind: kind.to_string(), symbol: symbol.map(str::to_string), addend });
        Ok(())
    }

    pub fn relocations(&self) -> impl Iterator<Item = &ProgramRelocation> { self.relocations.values() }

    /// Keep imported datatype definitions available to later type-graph binding.
    pub fn import_data_type(&mut self, name: &str, kind: &str, size: u64, signed: Option<bool>, encoding: Option<&str>) -> Result<()> {
        if name.is_empty() || name.len() > 1024 || name.contains('\0') || kind.is_empty() || kind.len() > 128 || kind.contains('\0') {
            return Err(Error::Lowlevel("invalid imported datatype descriptor".to_string()));
        }
        if size > 16 * 1024 * 1024 { return Err(Error::Lowlevel("imported datatype exceeds size limit".to_string())); }
        self.imported_types.insert(name.to_string(), ImportedDataType { name: name.to_string(), kind: kind.to_string(), size, signed, encoding: encoding.map(str::to_string) });
        Ok(())
    }

    pub fn imported_data_types(&self) -> impl Iterator<Item = &ImportedDataType> { self.imported_types.values() }

    /// Apply a SLEIGH-defined processor context variable at an address.
    pub fn import_context_value(&mut self, address: u64, register: &str, value: u64) -> Result<()> {
        let value = u32::try_from(value).map_err(|_| Error::Lowlevel(format!("context value for {register} exceeds 32 bits")))?;
        let location = self.code_address(address)?;
        let shared = self.architecture.context.as_ref().ok_or_else(|| Error::Lowlevel("architecture has no processor context database".to_string()))?;
        let mut context = shared.lock().map_err(|_| Error::Lowlevel("processor context database lock poisoned".to_string()))?;
        context.set_variable(register, &location, value)
    }

    /// Import a sized data symbol from an external program database.
    pub fn import_data_symbol(&mut self, address: u64, name: &str, size: u64) -> Result<()> {
        if name.is_empty() || name.len() > 1024 || name.contains('\0') { return Err(Error::Lowlevel("invalid imported data symbol name".to_string())); }
        if size == 0 || size > 1024 * 1024 { return Err(Error::Lowlevel(format!("unsupported imported data symbol size {size}"))); }
        if self.data.contains_key(&address) { self.set_data_name(address, name)?; return Ok(()); }
        self.add_typed_data_symbol(name, None, address, size)
    }

    /// Import a data symbol and bind its Ghidra datatype name in Program metadata.
    pub fn import_typed_data_symbol(&mut self, address: u64, name: &str, size: u64, type_name: Option<&str>) -> Result<()> {
        self.import_data_symbol(address, name, size)?;
        if let Some(type_name) = type_name {
            if type_name.is_empty() || type_name.len() > 1024 || type_name.contains('\0') { return Err(Error::Lowlevel("invalid data symbol datatype name".to_string())); }
            self.data_symbol_types.insert(address, type_name.to_string());
        }
        Ok(())
    }

    pub fn data_symbol_type(&self, address: u64) -> Option<&str> { self.data_symbol_types.get(&address).map(String::as_str) }

    /// Import a code-unit comment into the native decompiler comment database.
    pub fn import_comment(&mut self, function_entry: u64, address: u64, kind: &str, text: &str) -> Result<bool> {
        if text.len() > 64 * 1024 || text.contains('\0') { return Err(Error::Lowlevel("invalid imported comment text".to_string())); }
        let comment_type = match kind.to_ascii_lowercase().as_str() {
            "plate" | "header" => Comment::HEADER,
            "pre" | "pre_comment" | "eol" | "end_of_line" => Comment::USER1,
            "post" | "post_comment" => Comment::USER2,
            "repeatable" => Comment::USER3,
            other => return Err(Error::Lowlevel(format!("unsupported comment kind {other}"))),
        };
        let function_address = self.code_address(function_entry)?;
        let comment_address = self.code_address(address)?;
        let database = self.architecture.commentdb.as_deref_mut().ok_or_else(|| Error::Lowlevel("architecture has no comment database".to_string()))?;
        Ok(database.add_comment_no_duplicate(comment_type, &function_address, &comment_address, text))
    }

    pub fn set_symbol_name(&mut self, address: u64, name: &str) -> Result<()> {
        panic_guard(|| {
            if self.function_starting_at(address)?.is_some() {
                self.set_function_name_unguarded(address, name)
            } else if self.data.contains_key(&address) {
                self.set_data_name_unguarded(address, name)
            } else {
                Err(Error::Lowlevel(format!(
                    "no function or data symbol starts at {address:#x}"
                )))
            }
        })
    }

    pub fn set_function_name(&mut self, address: u64, name: &str) -> Result<()> {
        panic_guard(|| self.set_function_name_unguarded(address, name))
    }

    pub fn set_data_name(&mut self, address: u64, name: &str) -> Result<()> {
        panic_guard(|| self.set_data_name_unguarded(address, name))
    }

    fn function_starting_at(&self, address: u64) -> Result<Option<SymbolId>> {
        let scope = self.global_scope()?;
        Ok(self
            .symbol_table()?
            .scope_query_function(scope, &self.code_address(address)?)
            .filter(|sym| self.function_address(*sym).is_ok_and(|entry| entry == address)))
    }

    fn set_function_name_unguarded(&mut self, address: u64, name: &str) -> Result<()> {
        let sym = match self.function_starting_at(address)? {
            Some(sym) => sym,
            None => self.function_at(address)?,
        };
        let loaded_name = match self.functions.get(&sym) {
            Some(record) => record.loaded_name.clone(),
            None => self.symbol_table()?.symbol(sym).get_name().to_string(),
        };
        let new_name = if name.is_empty() {
            loaded_name.clone()
        } else {
            name.to_string()
        };
        self.check_unused_name(&new_name, Some(sym), None)?;
        let scope = self.global_scope()?;
        self.architecture
            .symboltab_mut()?
            .scope_rename_symbol(scope, sym, &new_name)?;
        match self.functions.get_mut(&sym) {
            Some(record) => record.name = new_name,
            None => {
                self.functions.insert(
                    sym,
                    FunctionRecord {
                        name: new_name,
                        loaded_name,
                        symbol: None,
                        source: FunctionSource::SymbolTable,
                    },
                );
            }
        }
        Ok(())
    }

    pub fn is_code_address(&self, address: u64) -> bool {
        self.code_sections.iter().any(|section| section.contains(&address))
    }

    fn set_data_name_unguarded(&mut self, address: u64, name: &str) -> Result<()> {
        if !self.data.contains_key(&address) {
            self.add_data_label(address)?;
        }
        let (sym, loaded_name) = match self.data.get(&address) {
            Some(record) => (record.sym, record.loaded_name.clone()),
            None => return Err(Error::Lowlevel(format!("no data symbol starts at {address:#x}"))),
        };
        let new_name = if name.is_empty() { loaded_name } else { name.to_string() };
        self.check_unused_name(&new_name, None, Some(address))?;
        let scope = self.global_scope()?;
        self.architecture
            .symboltab_mut()?
            .scope_rename_symbol(scope, sym, &new_name)?;
        if let Some(record) = self.data.get_mut(&address) {
            record.name = new_name;
        }
        Ok(())
    }

    fn add_data_label(&mut self, address: u64) -> Result<()> {
        let scope = self.global_scope()?;
        let data_address = self.data_address(address)?;
        if self
            .symbol_table()?
            .scope_query_container(scope, &data_address, 1, &Address::invalid())
            .is_some()
        {
            return Err(Error::Lowlevel(format!(
                "{address:#x} is inside another symbol; name the symbol at its start"
            )));
        }
        self.add_typed_data_symbol(&format!("DAT_{address:08x}"), None, address, 1)
    }

    fn check_unused_name(&self, name: &str, function: Option<SymbolId>, data_address: Option<u64>) -> Result<()> {
        let is_function_name = self
            .functions
            .iter()
            .any(|(sym, record)| Some(*sym) != function && record.name == name);
        let is_data_name = self
            .data
            .iter()
            .any(|(address, record)| Some(*address) != data_address && record.name == name);
        if is_function_name || is_data_name {
            return Err(Error::Lowlevel(format!("the name {name} is in use")));
        }
        Ok(())
    }

    fn register(&self, name: &str) -> Option<PcodeVarnode> {
        let register = self.architecture.translator().ok()?.get_register(name).ok()?;
        Some(pcode_varnode(&register))
    }

    fn read_unsigned(&self, address: u64, size: u32) -> Option<u64> {
        if size == 0 || size > 8 {
            return None;
        }
        let loader = self.architecture.loader.as_ref()?;
        let mut bytes = vec![0u8; size as usize];
        loader.load_fill(&mut bytes, &self.code_address(address).ok()?).ok()?;
        let is_big_endian = self.architecture.translator().ok()?.is_big_endian();
        let fold = |value: u64, byte: &u8| (value << 8) | u64::from(*byte);
        Some(if is_big_endian {
            bytes.iter().fold(0, fold)
        } else {
            bytes.iter().rev().fold(0, fold)
        })
    }

    fn add_function_symbol(&mut self, symbol: &str, address: &Address, source: FunctionSource) -> Result<SymbolId> {
        match demangle::demangled_name(symbol) {
            Some(name) => self.add_named_function(&name, Some(symbol), address, source),
            None => self.add_named_function(symbol, None, address, source),
        }
    }

    fn add_named_function(
        &mut self,
        name: &str,
        symbol: Option<&str>,
        address: &Address,
        source: FunctionSource,
    ) -> Result<SymbolId> {
        let scope = self.global_scope()?;
        let sym = Database::scope_add_function(&mut self.architecture, scope, address, name)?;
        self.functions.insert(
            sym,
            FunctionRecord {
                name: name.to_string(),
                loaded_name: name.to_string(),
                symbol: symbol.map(str::to_string),
                source,
            },
        );
        Ok(sym)
    }

    pub fn language_id(&self) -> &str {
        &self.architecture.archid
    }

    pub fn description(&self) -> String {
        self.architecture.get_description()
    }

    pub fn architecture(&mut self) -> &mut Architecture {
        &mut self.architecture
    }

    fn code_address(&self, offset: u64) -> Result<Address> {
        let space = self
            .architecture
            .manager
            .get_default_code_space()
            .ok_or_else(|| Error::Lowlevel("missing default code space".to_string()))?;
        Ok(Address::new(space, offset))
    }

    fn data_address(&self, offset: u64) -> Result<Address> {
        let space = self
            .architecture
            .manager
            .get_default_data_space()
            .ok_or_else(|| Error::Lowlevel("missing default data space".to_string()))?;
        Ok(Address::new(space, offset))
    }

    fn symbol_table(&self) -> Result<&Database> {
        self.architecture
            .symboltab
            .as_deref()
            .ok_or_else(|| Error::Lowlevel("missing symbol table".to_string()))
    }

    fn global_scope(&self) -> Result<ScopeId> {
        self.symbol_table()?
            .get_global_scope()
            .ok_or_else(|| Error::Lowlevel("missing global scope".to_string()))
    }

    fn function_address(&self, sym: SymbolId) -> Result<u64> {
        let symboltab = self.symbol_table()?;
        let entry = symboltab.symbol_get_first_whole_map(sym)?;
        Ok(symboltab.entry(entry).get_addr().get_offset())
    }

    pub fn functions(&self) -> Result<Vec<FunctionEntry>> {
        let symboltab = self.symbol_table()?;
        self.architecture
            .function_symbols_address_order()?
            .into_iter()
            .map(|sym| {
                let address = self.function_address(sym)?;
                Ok(match self.functions.get(&sym) {
                    Some(record) => FunctionEntry {
                        name: record.name.clone(),
                        symbol: record.symbol.clone(),
                        address,
                        source: record.source,
                    },
                    None => FunctionEntry {
                        name: symboltab.symbol(sym).get_name().to_string(),
                        symbol: None,
                        address,
                        source: FunctionSource::SymbolTable,
                    },
                })
            })
            .collect()
    }

    pub fn disassemble(&self, address: u64, instruction_count: usize) -> Result<Vec<Instruction>> {
        panic_guard(|| self.disassemble_unguarded(address, instruction_count))
    }

    fn disassemble_unguarded(&self, address: u64, instruction_count: usize) -> Result<Vec<Instruction>> {
        let translate = self.architecture.translator()?;
        let mut current = self.code_address(address)?;
        let mut instructions = Vec::with_capacity(instruction_count);
        for _ in 0..instruction_count {
            let mut text = InstructionText {
                mnemonic: String::new(),
                operands: String::new(),
            };
            let length = translate.print_assembly(&mut text, &current)?;
            let mut bytes = vec![0u8; length as usize];
            if let Some(loader) = &self.architecture.loader {
                loader.load_fill(&mut bytes, &current)?;
            }
            instructions.push(Instruction {
                address: current.get_offset(),
                length: length as usize,
                bytes,
                mnemonic: text.mnemonic,
                operands: text.operands,
            });
            current = current.add(i64::from(length));
        }
        Ok(instructions)
    }

    /// Returns executable section ranges discovered by the object loader.
    /// These are image ranges, not guarantees that every byte contains an instruction.
    pub fn code_sections(&self) -> &[std::ops::Range<u64>] {
        &self.code_sections
    }

    /// Disassemble as much of a range as possible, recording undecodable bytes
    /// instead of abandoning the entire range at the first invalid instruction.
    ///
    /// AArch64 is resynchronized on four-byte boundaries. Other architectures
    /// use one-byte resynchronization because their instruction widths may vary.
    pub fn disassemble_range_recovering(&self, address: u64, byte_length: u64) -> Result<DisassemblyReport> {
        panic_guard(|| {
            let translate = self.architecture.translator()?;
            let mut current = self.code_address(address)?;
            let mut remaining = byte_length;
            let mut instructions = Vec::new();
            let mut gaps = Vec::new();
            let mut gap_start = None;
            let mut gap_length = 0u64;
            let mut decoded_bytes = 0u64;
            let alignment = if self.language_id().to_ascii_lowercase().contains("aarch64") {
                4u64
            } else {
                1u64
            };

            while remaining > 0 {
                let mut text = InstructionText {
                    mnemonic: String::new(),
                    operands: String::new(),
                };
                let decoded = translate.print_assembly(&mut text, &current);
                let length = decoded
                    .ok()
                    .filter(|length| *length > 0)
                    .map(|length| length as u64)
                    .filter(|length| *length <= remaining);

                if let Some(length) = length {
                    if let Some(start) = gap_start.take() {
                        gaps.push(DisassemblyGap {
                            address: start,
                            length: gap_length,
                        });
                        gap_length = 0;
                    }
                    let mut bytes = vec![0u8; length as usize];
                    if let Some(loader) = &self.architecture.loader {
                        loader.load_fill(&mut bytes, &current)?;
                    }
                    instructions.push(Instruction {
                        address: current.get_offset(),
                        length: length as usize,
                        bytes,
                        mnemonic: text.mnemonic,
                        operands: text.operands,
                    });
                    decoded_bytes += length;
                    current = current.add(length as i64);
                    remaining -= length;
                } else {
                    gap_start.get_or_insert(current.get_offset());
                    let step = alignment.min(remaining);
                    gap_length += step;
                    current = current.add(step as i64);
                    remaining -= step;
                }
            }
            if let Some(start) = gap_start {
                gaps.push(DisassemblyGap {
                    address: start,
                    length: gap_length,
                });
            }

            Ok(DisassemblyReport {
                instructions,
                gaps,
                requested_bytes: byte_length,
                decoded_bytes,
            })
        })
    }

    /// Sweep every executable section without retaining the complete instruction
    /// listing in memory. Undecodable spans are reported through the callback.
    pub fn scan_code_sections(&self, mut on_gap: impl FnMut(&DisassemblyGap) -> Result<()>) -> Result<CodeScanSummary> {
        panic_guard(|| {
            let translate = self.architecture.translator()?;
            let mut sink = NullAssemblyEmit;
            let alignment = if self.language_id().to_ascii_lowercase().contains("aarch64") {
                4u64
            } else {
                1u64
            };
            let mut summary = CodeScanSummary::default();
            for section in &self.code_sections {
                if section.start >= section.end {
                    continue;
                }
                let mut item = CodeSectionSummary {
                    start: section.start,
                    end: section.end,
                    requested_bytes: section.end - section.start,
                    ..Default::default()
                };
                let mut current = self.code_address(section.start)?;
                let mut remaining = item.requested_bytes;
                let mut gap_start = None;
                let mut gap_length = 0u64;
                while remaining > 0 {
                    let decoded = translate.print_assembly(&mut sink, &current);
                    let length = decoded
                        .ok()
                        .filter(|length| *length > 0)
                        .map(|length| length as u64)
                        .filter(|length| *length <= remaining);
                    if let Some(length) = length {
                        if let Some(start) = gap_start.take() {
                            on_gap(&DisassemblyGap {
                                address: start,
                                length: gap_length,
                            })?;
                            item.gap_count += 1;
                            item.undecoded_bytes += gap_length;
                            gap_length = 0;
                        }
                        item.instruction_count += 1;
                        item.decoded_bytes += length;
                        current = current.add(length as i64);
                        remaining -= length;
                    } else {
                        gap_start.get_or_insert(current.get_offset());
                        let step = alignment.min(remaining);
                        gap_length += step;
                        current = current.add(step as i64);
                        remaining -= step;
                    }
                }
                if let Some(start) = gap_start {
                    on_gap(&DisassemblyGap {
                        address: start,
                        length: gap_length,
                    })?;
                    item.gap_count += 1;
                    item.undecoded_bytes += gap_length;
                }
                summary.requested_bytes += item.requested_bytes;
                summary.decoded_bytes += item.decoded_bytes;
                summary.undecoded_bytes += item.undecoded_bytes;
                summary.instruction_count += item.instruction_count;
                summary.gap_count += item.gap_count;
                summary.sections.push(item);
            }
            Ok(summary)
        })
    }

    pub fn function_size(&mut self, address: u64) -> Result<u64> {
        let addr = self.code_address(address)?;
        let scope = self.global_scope()?;
        let sym = self
            .symbol_table()?
            .scope_query_function(scope, &addr)
            .ok_or_else(|| Error::Lowlevel(format!("no function starts at {address:#x}")))?;
        self.architecture
            .with_function(sym, |function, _architecture| Ok(function.get_size().max(0) as u64))
    }

    pub fn disassemble_range(&self, address: u64, byte_length: u64) -> Result<Vec<Instruction>> {
        panic_guard(|| {
            let translate = self.architecture.translator()?;
            let mut current = self.code_address(address)?;
            let mut remaining = byte_length;
            // Most supported targets use instructions of at least four bytes.
            // Cap the estimate to avoid huge speculative allocations on malformed inputs.
            let estimated = usize::try_from((byte_length / 4).min(1_000_000)).unwrap_or(0);
            let mut instructions = Vec::with_capacity(estimated);
            while remaining > 0 {
                let mut text = InstructionText {
                    mnemonic: String::new(),
                    operands: String::new(),
                };
                let length = translate.print_assembly(&mut text, &current)?;
                if length <= 0 {
                    return Err(Error::Lowlevel(format!(
                        "invalid instruction length at {:#x}",
                        current.get_offset()
                    )));
                }
                let mut bytes = vec![0u8; length as usize];
                if let Some(loader) = &self.architecture.loader {
                    loader.load_fill(&mut bytes, &current)?;
                }
                instructions.push(Instruction {
                    address: current.get_offset(),
                    length: length as usize,
                    bytes,
                    mnemonic: text.mnemonic,
                    operands: text.operands,
                });
                current = current.add(i64::from(length));
                remaining = remaining.saturating_sub(length as u64);
            }
            Ok(instructions)
        })
    }

    pub fn pcode(&self, address: u64, instruction_count: usize) -> Result<Vec<InstructionPcode>> {
        panic_guard(|| self.pcode_unguarded(address, instruction_count))
    }

    pub fn pcode_range(&self, address: u64, byte_length: u64) -> Result<Vec<InstructionPcode>> {
        Ok((*self.pcode_range_shared(address, byte_length)?).clone())
    }

    /// Return a shared translated P-code stream. Repeated analysis passes over
    /// the same function avoid translating every machine instruction again.
    pub fn pcode_range_shared(&self, address: u64, byte_length: u64) -> Result<Arc<Vec<InstructionPcode>>> {
        let key = (address, byte_length);
        if let Some(cached) = self.pcode_cache.borrow().entries.get(&key).cloned() {
            return Ok(cached);
        }
        let translated = panic_guard(|| {
            let translate = self.architecture.translator()?;
            let mut current = self.code_address(address)?;
            let mut remaining = byte_length;
            let estimated = usize::try_from((byte_length / 4).min(1_000_000)).unwrap_or(0);
            let mut instructions = Vec::with_capacity(estimated);
            while remaining > 0 {
                let mut collector = OperationCollector {
                    manager: &self.architecture.manager,
                    operations: Vec::new(),
                };
                let length = translate.one_instruction(&mut collector, &current)?;
                if length <= 0 {
                    return Err(Error::Lowlevel(format!(
                        "invalid instruction length at {:#x}",
                        current.get_offset()
                    )));
                }
                instructions.push(InstructionPcode {
                    address: current.get_offset(),
                    length: length as usize,
                    operations: collector.operations,
                });
                current = current.add(i64::from(length));
                remaining = remaining.saturating_sub(length as u64);
            }
            Ok(instructions)
        })?;
        let translated = Arc::new(translated);
        let entry_bytes = estimate_pcode_bytes(&translated);
        if entry_bytes <= MAX_PCODE_CACHE_BYTES {
            let mut cache = self.pcode_cache.borrow_mut();
            while cache.estimated_bytes.saturating_add(entry_bytes) > MAX_PCODE_CACHE_BYTES {
                let Some(old_key) = cache.entries.keys().next().copied() else { break };
                if let Some(old) = cache.entries.remove(&old_key) {
                    cache.estimated_bytes = cache.estimated_bytes.saturating_sub(estimate_pcode_bytes(&old));
                }
            }
            cache.estimated_bytes = cache.estimated_bytes.saturating_add(entry_bytes);
            cache.entries.insert(key, Arc::clone(&translated));
        }
        Ok(translated)
    }

    pub fn function_pcode(&mut self, address: u64) -> Result<Vec<InstructionPcode>> {
        Ok((*self.function_pcode_shared(address)?).clone())
    }

    pub fn function_pcode_shared(&mut self, address: u64) -> Result<Arc<Vec<InstructionPcode>>> {
        let length = self.function_size(address)?;
        self.pcode_range_shared(address, length)
    }

    fn pcode_unguarded(&self, address: u64, instruction_count: usize) -> Result<Vec<InstructionPcode>> {
        let translate = self.architecture.translator()?;
        let mut current = self.code_address(address)?;
        let mut instructions = Vec::with_capacity(instruction_count);
        for _ in 0..instruction_count {
            let mut collector = OperationCollector {
                manager: &self.architecture.manager,
                operations: Vec::new(),
            };
            let length = translate.one_instruction(&mut collector, &current)?;
            instructions.push(InstructionPcode {
                address: current.get_offset(),
                length: length as usize,
                operations: collector.operations,
            });
            current = current.add(i64::from(length));
        }
        Ok(instructions)
    }

    fn function_at(&mut self, address: u64) -> Result<SymbolId> {
        let addr = self.code_address(address)?;
        let scope = self.global_scope()?;
        if let Some(sym) = self.symbol_table()?.scope_query_function(scope, &addr) {
            return Ok(sym);
        }
        let mut name = String::new();
        self.architecture.name_function(&addr, &mut name);
        self.add_named_function(&name, None, &addr, FunctionSource::Requested)
    }

    pub fn decompile(&mut self, address: u64) -> Result<String> {
        panic_guard(|| self.decompile_unguarded(address))
    }

    fn decompile_unguarded(&mut self, address: u64) -> Result<String> {
        let sym = self.function_at(address)?;
        self.add_referenced_strings(sym)?;
        self.architecture.with_function(sym, |function, architecture| {
            if function.has_no_code() {
                return Err(Error::Lowlevel(format!("No code for {}", function.get_name())));
            }
            if function.is_proc_started() {
                architecture.clear_analysis(function);
            }
            let analysis = architecture.with_current_action(|action, architecture| {
                action.reset(function, architecture);
                action.perform(function, architecture)
            });
            let printed = analysis.and_then(|_| {
                architecture
                    .with_printer(Some(&mut *function), |printer, context| printer.doc_function(context))
                    .map(|((), text)| text)
            });
            architecture.clear_analysis(function);
            printed
        })
    }

    pub fn call_graph(&mut self) -> Result<Vec<CallEdge>> {
        panic_guard(|| self.call_graph_unguarded())
    }

    fn call_graph_unguarded(&mut self) -> Result<Vec<CallEdge>> {
        let mut graph = CallGraph::new();
        graph.build_all_nodes(&mut self.architecture)?;
        for sym in self.architecture.function_symbols_address_order()? {
            self.architecture.with_function(sym, |function, architecture| {
                if function.has_no_code() {
                    return Ok(());
                }
                architecture.clear_analysis(function);
                let space: Option<SpaceRef> = function.get_address().get_space().cloned();
                let highest = space.as_ref().map(|space| space.get_highest()).unwrap_or(u64::MAX);
                let start = Address::from_parts(space.clone(), 0);
                let end = Address::from_parts(space, highest);
                if function.follow_flow(&start, &end, architecture).is_ok() {
                    graph.build_edges(function, architecture)?;
                }
                architecture.clear_analysis(function);
                Ok(())
            })?;
        }
        let mut edges = Vec::new();
        for (caller, node) in graph.graph.iter() {
            for index in 0..node.num_out_edge() {
                edges.push(CallEdge {
                    caller: caller.get_offset(),
                    callee: node.get_out_node(index).get_offset(),
                    call_site: node.get_out_edge(index).get_call_site_addr().get_offset(),
                });
            }
        }
        edges.sort();
        Ok(edges)
    }
}
