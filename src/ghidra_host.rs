//! Bounded JSON-lines protocol for a Ghidra Java host and the Rust worker.
//!
//! The transport is deliberately independent of Ghidra classes. A Java adapter can
//! snapshot database-backed memory and metadata into this protocol without loading
//! Rust code into Ghidra's UI JVM. Frames and program snapshots are size-limited.

use std::io::{BufRead, Read, Write};

use serde_json::{Value, json};

pub const HOST_PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MEMORY_BLOCK_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MEMORY_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_MEMORY_BLOCKS: usize = 4096;
pub const MAX_FUNCTIONS: usize = 100_000;
pub const MAX_SYMBOLS: usize = 200_000;
pub const MAX_RELOCATIONS: usize = 200_000;
pub const MAX_COMMENTS: usize = 200_000;
pub const MAX_REFERENCES: usize = 500_000;
pub const MAX_DATA_TYPES: usize = 100_000;
pub const MAX_CONTEXT_VALUES: usize = 500_000;
const MAX_IDENTIFIER_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBlock {
    pub start: u64,
    pub bytes: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterDescriptor {
    pub ordinal: u32,
    pub name: String,
    pub type_name: String,
    pub storage: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionDescriptor {
    pub entry: u64,
    pub name: String,
    pub body_size: u64,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    pub namespace: Option<String>,
    pub parameters: Vec<ParameterDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolDescriptor {
    pub address: u64,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub namespace: Option<String>,
    pub type_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelocationDescriptor {
    pub address: u64,
    pub kind: String,
    pub symbol: Option<String>,
    pub addend: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommentDescriptor {
    pub address: u64,
    pub function_entry: Option<u64>,
    pub kind: String,
    pub text: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceDescriptor {
    pub from: u64,
    pub to: u64,
    pub kind: String,
    pub is_primary: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataTypeDescriptor {
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub signed: Option<bool>,
    pub encoding: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextValueDescriptor {
    pub address: u64,
    pub register: String,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramSnapshot {
    pub name: String,
    pub language_id: String,
    pub compiler_spec_id: String,
    pub endianness: Endianness,
    pub address_spaces: Vec<String>,
    pub memory_blocks: Vec<MemoryBlock>,
    pub functions: Vec<FunctionDescriptor>,
    pub symbols: Vec<SymbolDescriptor>,
    pub relocations: Vec<RelocationDescriptor>,
    pub comments: Vec<CommentDescriptor>,
    pub references: Vec<ReferenceDescriptor>,
    pub data_types: Vec<DataTypeDescriptor>,
    pub context_values: Vec<ContextValueDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBlockChunk {
    pub start: u64,
    pub total_size: usize,
    pub offset: usize,
    pub bytes: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub final_chunk: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostCommand {
    Ping,
    OpenProgram(ProgramSnapshot),
    BeginProgram(ProgramSnapshot),
    AddMemoryBlockChunk(MemoryBlockChunk),
    FinishProgram,
    Decompile { function_address: u64 },
    Cancel { target_request_id: String },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub command: HostCommand,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HostResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub ok: bool,
    pub error: Option<String>,
    pub payload: Value,
}

impl HostRequest {
    pub fn parse_frame(frame: &[u8]) -> Result<Self, String> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(format!("host frame exceeds {MAX_FRAME_BYTES} bytes"));
        }
        let root: Value = serde_json::from_slice(frame).map_err(|error| format!("invalid host JSON frame: {error}"))?;
        let version = root
            .get("protocol_version")
            .and_then(Value::as_u64)
            .ok_or("missing numeric protocol_version")?;
        if version != u64::from(HOST_PROTOCOL_VERSION) {
            return Err(format!("unsupported host protocol version {version}"));
        }
        let request_id = required_string(&root, "request_id")?.to_owned();
        if request_id.len() > 128 {
            return Err("request_id exceeds 128 bytes".into());
        }
        let command_name = required_string(&root, "command")?;
        let payload = root.get("payload").unwrap_or(&Value::Null);
        let command = match command_name {
            "ping" => HostCommand::Ping,
            "open_program" => HostCommand::OpenProgram(parse_snapshot(payload)?),
            "begin_program" => HostCommand::BeginProgram(parse_snapshot(payload)?),
            "add_memory_block_chunk" => {
                let total_size = usize::try_from(required_u64(payload, "total_size")?)
                    .map_err(|_| "memory block total_size does not fit usize")?;
                let offset = usize::try_from(required_u64(payload, "offset")?)
                    .map_err(|_| "memory block offset does not fit usize")?;
                if total_size == 0 || total_size > MAX_MEMORY_BLOCK_BYTES || offset > total_size {
                    return Err("invalid memory block chunk range".into());
                }
                let bytes = decode_hex(required_string(payload, "bytes_hex")?, MAX_MEMORY_CHUNK_BYTES)?;
                let end = offset.checked_add(bytes.len()).ok_or("memory chunk range overflow")?;
                if bytes.is_empty() || end > total_size {
                    return Err("memory block chunk exceeds declared block size".into());
                }
                let final_chunk = optional_bool(payload, "final_chunk", false)?;
                if final_chunk != (end == total_size) {
                    return Err("final_chunk must be true exactly when the declared block is complete".into());
                }
                HostCommand::AddMemoryBlockChunk(MemoryBlockChunk {
                    start: required_u64(payload, "start")?,
                    total_size,
                    offset,
                    bytes,
                    readable: optional_bool(payload, "readable", true)?,
                    writable: optional_bool(payload, "writable", false)?,
                    executable: optional_bool(payload, "executable", false)?,
                    final_chunk,
                })
            }
            "finish_program" => HostCommand::FinishProgram,
            "decompile" => HostCommand::Decompile {
                function_address: required_u64(payload, "function_address")?,
            },
            "cancel" => {
                let target_request_id = required_string(payload, "target_request_id")?.to_owned();
                if target_request_id.len() > 128 {
                    return Err("target_request_id exceeds 128 bytes".into());
                }
                HostCommand::Cancel { target_request_id }
            }
            "shutdown" => HostCommand::Shutdown,
            other => return Err(format!("unsupported host command {other}")),
        };
        Ok(Self {
            protocol_version: version as u16,
            request_id,
            command,
        })
    }
}

impl HostResponse {
    pub fn success(request_id: impl Into<String>, payload: Value) -> Self {
        Self {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id: request_id.into(),
            ok: true,
            error: None,
            payload,
        }
    }

    pub fn failure(request_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id: request_id.into(),
            ok: false,
            error: Some(message.into()),
            payload: Value::Null,
        }
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, String> {
        let value = json!({
            "protocol_version": self.protocol_version,
            "request_id": self.request_id,
            "ok": self.ok,
            "error": self.error,
            "payload": self.payload,
        });
        let mut frame =
            serde_json::to_vec(&value).map_err(|error| format!("could not encode host response: {error}"))?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(format!("host response exceeds {MAX_FRAME_BYTES} bytes"));
        }
        frame.push(b'\n');
        Ok(frame)
    }
}

/// Read exactly one bounded newline-delimited frame. An oversized frame is fatal
/// for the current connection; callers should close the worker transport.
pub fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut frame = Vec::new();
    let read = reader
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut frame)
        .map_err(|error| format!("failed reading host frame: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    if frame.len() > MAX_FRAME_BYTES {
        return Err(format!("host frame exceeds {MAX_FRAME_BYTES} bytes"));
    }
    if frame.last() == Some(&b'\n') {
        frame.pop();
        if frame.last() == Some(&b'\r') {
            frame.pop();
        }
    }
    Ok(Some(frame))
}

pub fn write_frame<W: Write>(writer: &mut W, response: &HostResponse) -> Result<(), String> {
    let frame = response.encode_frame()?;
    writer
        .write_all(&frame)
        .map_err(|error| format!("failed writing host frame: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("failed flushing host frame: {error}"))
}

fn parse_snapshot(value: &Value) -> Result<ProgramSnapshot, String> {
    let name = bounded_string(value, "name", MAX_IDENTIFIER_BYTES)?;
    let language_id = bounded_string(value, "language_id", MAX_IDENTIFIER_BYTES)?;
    let compiler_spec_id = bounded_string(value, "compiler_spec_id", MAX_IDENTIFIER_BYTES)?;
    let endianness = match required_string(value, "endianness")? {
        "little" => Endianness::Little,
        "big" => Endianness::Big,
        other => return Err(format!("unsupported endianness {other}")),
    };

    let address_spaces = optional_array(value, "address_spaces", 256)?
        .iter()
        .map(|entry| {
            let text = entry.as_str().ok_or("address space names must be strings")?;
            validate_string(text, MAX_IDENTIFIER_BYTES)?;
            Ok(text.to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;

    let raw_blocks = optional_array(value, "memory_blocks", MAX_MEMORY_BLOCKS)?;
    let mut memory_blocks = Vec::with_capacity(raw_blocks.len());
    let mut total_memory = 0usize;
    for raw in raw_blocks {
        let start = required_u64(raw, "start")?;
        let hex = required_string(raw, "bytes_hex")?;
        let bytes = decode_hex(hex, MAX_MEMORY_BLOCK_BYTES)?;
        total_memory = total_memory
            .checked_add(bytes.len())
            .ok_or("memory snapshot size overflow")?;
        if total_memory > MAX_TOTAL_MEMORY_BYTES {
            return Err(format!("memory snapshot exceeds {MAX_TOTAL_MEMORY_BYTES} bytes"));
        }
        let end = start
            .checked_add(bytes.len() as u64)
            .ok_or("memory block address overflow")?;
        memory_blocks.push(MemoryBlock {
            start,
            bytes,
            readable: optional_bool(raw, "readable", true)?,
            writable: optional_bool(raw, "writable", false)?,
            executable: optional_bool(raw, "executable", false)?,
        });
        if end < start {
            return Err("memory block address range overflow".into());
        }
    }
    memory_blocks.sort_unstable_by_key(|block| block.start);
    for pair in memory_blocks.windows(2) {
        let previous_end = pair[0]
            .start
            .checked_add(pair[0].bytes.len() as u64)
            .ok_or("memory block address overflow")?;
        if previous_end > pair[1].start {
            return Err("memory snapshot contains overlapping blocks".into());
        }
    }

    let raw_functions = optional_array(value, "functions", MAX_FUNCTIONS)?;
    let mut functions = Vec::with_capacity(raw_functions.len());
    for raw in raw_functions {
        let raw_parameters = optional_array(raw, "parameters", 1024)?;
        let mut parameters = Vec::with_capacity(raw_parameters.len());
        for (index, parameter) in raw_parameters.iter().enumerate() {
            let ordinal = match parameter.get("ordinal") {
                None | Some(Value::Null) => index as u32,
                Some(value) => value
                    .as_u64()
                    .and_then(|number| u32::try_from(number).ok())
                    .ok_or("parameter ordinal must fit u32")?,
            };
            parameters.push(ParameterDescriptor {
                ordinal,
                name: bounded_string(parameter, "name", MAX_IDENTIFIER_BYTES)?,
                type_name: bounded_string(parameter, "type_name", MAX_IDENTIFIER_BYTES)?,
                storage: optional_string(parameter, "storage", MAX_IDENTIFIER_BYTES)?,
            });
        }
        functions.push(FunctionDescriptor {
            entry: required_u64(raw, "entry")?,
            name: bounded_string(raw, "name", MAX_IDENTIFIER_BYTES)?,
            body_size: required_u64(raw, "body_size")?,
            calling_convention: optional_string(raw, "calling_convention", MAX_IDENTIFIER_BYTES)?,
            return_type: optional_string(raw, "return_type", MAX_IDENTIFIER_BYTES)?,
            namespace: optional_string(raw, "namespace", MAX_IDENTIFIER_BYTES)?,
            parameters,
        });
    }
    functions.sort_unstable_by_key(|function| function.entry);
    if functions.windows(2).any(|pair| pair[0].entry == pair[1].entry) {
        return Err("program snapshot contains duplicate function entries".into());
    }

    let raw_symbols = optional_array(value, "symbols", MAX_SYMBOLS)?;
    let mut symbols = Vec::with_capacity(raw_symbols.len());
    for raw in raw_symbols {
        symbols.push(SymbolDescriptor {
            address: required_u64(raw, "address")?,
            name: bounded_string(raw, "name", MAX_IDENTIFIER_BYTES)?,
            kind: bounded_string(raw, "kind", 128)?,
            size: match raw.get("size") {
                None | Some(Value::Null) => 1,
                Some(value) => value.as_u64().ok_or("symbol size must be an unsigned integer")?,
            },
            namespace: optional_string(raw, "namespace", MAX_IDENTIFIER_BYTES)?,
            type_name: optional_string(raw, "type_name", MAX_IDENTIFIER_BYTES)?,
        });
    }

    let raw_relocations = optional_array(value, "relocations", MAX_RELOCATIONS)?;
    let mut relocations = Vec::with_capacity(raw_relocations.len());
    for raw in raw_relocations {
        relocations.push(RelocationDescriptor {
            address: required_u64(raw, "address")?,
            kind: bounded_string(raw, "kind", 128)?,
            symbol: optional_string(raw, "symbol", MAX_IDENTIFIER_BYTES)?,
            addend: raw.get("addend").and_then(Value::as_i64).unwrap_or(0),
        });
    }

    let raw_comments = optional_array(value, "comments", MAX_COMMENTS)?;
    let mut comments = Vec::with_capacity(raw_comments.len());
    for raw in raw_comments {
        comments.push(CommentDescriptor {
            address: required_u64(raw, "address")?,
            function_entry: match raw.get("function_entry") {
                None | Some(Value::Null) => None,
                Some(_) => Some(required_u64(raw, "function_entry")?),
            },
            kind: bounded_string(raw, "kind", 64)?,
            text: bounded_string(raw, "text", MAX_FRAME_BYTES)?,
        });
    }
    let raw_references = optional_array(value, "references", MAX_REFERENCES)?;
    let mut references = Vec::with_capacity(raw_references.len());
    for raw in raw_references {
        references.push(ReferenceDescriptor {
            from: required_u64(raw, "from")?,
            to: required_u64(raw, "to")?,
            kind: bounded_string(raw, "kind", 128)?,
            is_primary: optional_bool(raw, "is_primary", false)?,
        });
    }
    let raw_types = optional_array(value, "data_types", MAX_DATA_TYPES)?;
    let mut data_types = Vec::with_capacity(raw_types.len());
    for raw in raw_types {
        data_types.push(DataTypeDescriptor {
            name: bounded_string(raw, "name", MAX_IDENTIFIER_BYTES)?,
            kind: bounded_string(raw, "kind", 128)?,
            size: required_u64(raw, "size")?,
            signed: match raw.get("signed") {
                None | Some(Value::Null) => None,
                Some(Value::Bool(value)) => Some(*value),
                Some(_) => return Err("datatype signed must be boolean".into()),
            },
            encoding: optional_string(raw, "encoding", 128)?,
        });
    }
    let raw_context = optional_array(value, "context_values", MAX_CONTEXT_VALUES)?;
    let mut context_values = Vec::with_capacity(raw_context.len());
    for raw in raw_context {
        context_values.push(ContextValueDescriptor {
            address: required_u64(raw, "address")?,
            register: bounded_string(raw, "register", MAX_IDENTIFIER_BYTES)?,
            value: required_u64(raw, "value")?,
        });
    }

    Ok(ProgramSnapshot {
        name,
        language_id,
        compiler_spec_id,
        endianness,
        address_spaces,
        memory_blocks,
        functions,
        symbols,
        relocations,
        comments,
        references,
        data_types,
        context_values,
    })
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}

fn bounded_string(value: &Value, key: &str, maximum: usize) -> Result<String, String> {
    let text = required_string(value, key)?;
    validate_string(text, maximum)?;
    if text.is_empty() {
        return Err(format!("field {key} must not be empty"));
    }
    Ok(text.to_owned())
}

fn validate_string(value: &str, maximum: usize) -> Result<(), String> {
    if value.len() > maximum {
        Err(format!("string exceeds {maximum} bytes"))
    } else if value.contains('\0') {
        Err("strings must not contain NUL bytes".into())
    } else {
        Ok(())
    }
}

fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    let field = value.get(key).ok_or_else(|| format!("missing numeric field {key}"))?;
    if let Some(number) = field.as_u64() {
        return Ok(number);
    }
    if let Some(text) = field.as_str() {
        return parse_address(text);
    }
    Err(format!("field {key} must be an unsigned integer or hexadecimal string"))
}

fn parse_address(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid address {value}"))
    } else {
        value.parse::<u64>().map_err(|_| format!("invalid address {value}"))
    }
}

fn optional_array<'a>(value: &'a Value, key: &str, maximum: usize) -> Result<&'a [Value], String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) if items.len() <= maximum => Ok(items),
        Some(Value::Array(_)) => Err(format!("array {key} exceeds its item limit")),
        Some(_) => Err(format!("field {key} must be an array")),
    }
}

fn optional_bool(value: &Value, key: &str, default: bool) -> Result<bool, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(format!("field {key} must be boolean")),
    }
}

fn optional_string(value: &Value, key: &str, maximum: usize) -> Result<Option<String>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            validate_string(text, maximum)?;
            Ok(Some(text.clone()))
        }
        Some(_) => Err(format!("field {key} must be a string or null")),
    }
}

fn decode_hex(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("memory block hex payload must have an even number of digits".into());
    }
    if value.len() / 2 > maximum_bytes {
        return Err(format!("memory block exceeds {maximum_bytes} bytes"));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0]).ok_or("memory block contains a non-hexadecimal digit")?;
        let low = hex_nibble(pair[1]).ok_or("memory block contains a non-hexadecimal digit")?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_ping_and_decompile_requests() {
        let ping = HostRequest::parse_frame(br#"{"protocol_version":1,"request_id":"p1","command":"ping"}"#).unwrap();
        assert_eq!(ping.command, HostCommand::Ping);
        let decompile = HostRequest::parse_frame(br#"{"protocol_version":1,"request_id":"d1","command":"decompile","payload":{"function_address":"0x401000"}}"#).unwrap();
        assert_eq!(
            decompile.command,
            HostCommand::Decompile {
                function_address: 0x401000
            }
        );
    }

    #[test]
    fn parses_program_snapshot_and_sorts_memory() {
        let frame = br#"{"protocol_version":1,"request_id":"open","command":"open_program","payload":{"name":"sample","language_id":"x86:LE:64:default","compiler_spec_id":"gcc","endianness":"little","memory_blocks":[{"start":"0x2000","bytes_hex":"aabb","executable":true},{"start":"0x1000","bytes_hex":"0102"}],"functions":[{"entry":"0x1000","name":"entry","body_size":8}],"symbols":[{"address":"0x1000","name":"entry","kind":"function"}]}}"#;
        let request = HostRequest::parse_frame(frame).unwrap();
        let HostCommand::OpenProgram(snapshot) = request.command else {
            panic!("expected open_program")
        };
        assert_eq!(snapshot.memory_blocks[0].start, 0x1000);
        assert_eq!(snapshot.memory_blocks[1].bytes, vec![0xaa, 0xbb]);
        assert_eq!(snapshot.functions[0].entry, 0x1000);
    }

    #[test]
    fn parses_extended_database_metadata() {
        let frame = br#"{"protocol_version":1,"request_id":"db","command":"open_program","payload":{"name":"db-snapshot","language_id":"x86:LE:64:default","compiler_spec_id":"gcc","endianness":"little","memory_blocks":[{"start":"0x1000","bytes_hex":"90c3","executable":true}],"functions":[{"entry":"0x1000","name":"entry","body_size":2}],"symbols":[{"address":"0x1000","name":"entry","kind":"function","size":1,"namespace":"root","type_name":"void ()"}],"relocations":[{"address":"0x1001","kind":"R_X86_64_PC32","symbol":"target","addend":-4}],"comments":[{"address":"0x1000","function_entry":"0x1000","kind":"plate","text":"entry point"}],"references":[{"from":"0x1000","to":"0x1001","kind":"call","is_primary":true}],"data_types":[{"name":"size_t","kind":"typedef","size":8,"signed":false}],"context_values":[{"address":"0x1000","register":"mode","value":1}]}}"#;
        let request = HostRequest::parse_frame(frame).unwrap();
        let HostCommand::OpenProgram(snapshot) = request.command else {
            panic!("expected open_program")
        };
        assert_eq!(snapshot.symbols[0].namespace.as_deref(), Some("root"));
        assert_eq!(snapshot.symbols[0].size, 1);
        assert_eq!(snapshot.comments[0].kind, "plate");
        assert_eq!(snapshot.references[0].to, 0x1001);
        assert_eq!(snapshot.data_types[0].name, "size_t");
        assert_eq!(snapshot.context_values[0].register, "mode");
    }

    #[test]
    fn parses_function_namespace_and_parameter_storage() {
        let frame = br#"{"protocol_version":1,"request_id":"sig","command":"open_program","payload":{"name":"p","language_id":"x86:LE:64:default","compiler_spec_id":"gcc","endianness":"little","functions":[{"entry":4096,"name":"worker","body_size":12,"namespace":"app::detail","calling_convention":"__cdecl","return_type":"int","parameters":[{"ordinal":0,"name":"value","type_name":"unsigned int","storage":"RDI:4"}]}]}}"#;
        let request = HostRequest::parse_frame(frame).unwrap();
        let HostCommand::OpenProgram(snapshot) = request.command else {
            panic!("expected open_program")
        };
        let function = &snapshot.functions[0];
        assert_eq!(function.namespace.as_deref(), Some("app::detail"));
        assert_eq!(function.calling_convention.as_deref(), Some("__cdecl"));
        assert_eq!(function.parameters[0].ordinal, 0);
        assert_eq!(function.parameters[0].name, "value");
        assert_eq!(function.parameters[0].type_name, "unsigned int");
        assert_eq!(function.parameters[0].storage.as_deref(), Some("RDI:4"));
    }

    #[test]
    fn parses_streamed_memory_block_chunks() {
        let frame = br#"{"protocol_version":1,"request_id":"chunk","command":"add_memory_block_chunk","payload":{"start":"0x1000","total_size":8,"offset":4,"bytes_hex":"aabbccdd","readable":true,"executable":true,"final_chunk":true}}"#;
        let request = HostRequest::parse_frame(frame).unwrap();
        let HostCommand::AddMemoryBlockChunk(chunk) = request.command else {
            panic!("expected chunk")
        };
        assert_eq!(chunk.start, 0x1000);
        assert_eq!(chunk.total_size, 8);
        assert_eq!(chunk.offset, 4);
        assert_eq!(chunk.bytes, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(chunk.final_chunk && chunk.executable);
    }

    #[test]
    fn rejects_inconsistent_final_memory_chunk() {
        let frame = br#"{"protocol_version":1,"request_id":"chunk","command":"add_memory_block_chunk","payload":{"start":4096,"total_size":8,"offset":0,"bytes_hex":"aabb","final_chunk":true}}"#;
        assert!(HostRequest::parse_frame(frame).unwrap_err().contains("final_chunk"));
    }

    #[test]
    fn rejects_overlapping_memory_blocks() {
        let frame = br#"{"protocol_version":1,"request_id":"open","command":"open_program","payload":{"name":"sample","language_id":"x","compiler_spec_id":"x","endianness":"little","memory_blocks":[{"start":4096,"bytes_hex":"010203"},{"start":4098,"bytes_hex":"04"}]}}"#;
        assert!(HostRequest::parse_frame(frame).unwrap_err().contains("overlapping"));
    }

    #[test]
    fn rejects_unsupported_versions_and_commands() {
        assert!(HostRequest::parse_frame(br#"{"protocol_version":2,"request_id":"x","command":"ping"}"#).is_err());
        assert!(
            HostRequest::parse_frame(br#"{"protocol_version":1,"request_id":"x","command":"execute_shell"}"#).is_err()
        );
    }

    #[test]
    fn frame_reader_strips_newline_and_handles_eof() {
        let mut reader = Cursor::new(b"{\"ok\":true}\r\n".to_vec());
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), br#"{"ok":true}"#);
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn response_is_json_lines_encoded() {
        let response = HostResponse::success("r1", json!({"status":"ready"}));
        let frame = response.encode_frame().unwrap();
        assert_eq!(frame.last(), Some(&b'\n'));
        let value: Value = serde_json::from_slice(&frame[..frame.len() - 1]).unwrap();
        assert_eq!(value["request_id"], "r1");
        assert_eq!(value["ok"], true);
    }

    #[test]
    fn rejects_bad_hex_and_oversized_blocks() {
        assert!(decode_hex("0x", 8).is_err());
        assert!(decode_hex("gg", 8).is_err());
        assert!(decode_hex("0011", 1).is_err());
    }
}
