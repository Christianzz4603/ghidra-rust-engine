//! CPython `.pyc` reader and bytecode disassembler (3.11, 3.12 and 3.13).
//!
//! Reads the pyc header, parses the `marshal` payload into [`Object`]s, and disassembles code
//! objects (instructions, inline caches, jump targets, location table, exception table). This is a
//! *disassembler and metadata reader*: it does not recover Python source. Versions other than the
//! three above are rejected rather than guessed at, because their bytecode layouts differ and this
//! module is only checked against the matching CPython releases.

use std::rc::Rc;

use crate::error::{Error, Result};

mod tables;
use tables::{OPS_311, OPS_312, OPS_313, OpRow};

fn fail(message: impl Into<String>) -> Error {
    Error::Parse(format!("pyc: {}", message.into()))
}

/// Maximum nesting depth accepted while unmarshalling.
const MAX_DEPTH: usize = 1000;

/// Supported CPython versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PyVersion {
    V3_11,
    V3_12,
    V3_13,
}

impl PyVersion {
    /// The version for a final-release magic number (the first two header bytes, little-endian).
    pub fn from_magic_number(number: u16) -> Option<PyVersion> {
        match number {
            3495 => Some(PyVersion::V3_11),
            3531 => Some(PyVersion::V3_12),
            3571 => Some(PyVersion::V3_13),
            _ => None,
        }
    }

    pub fn magic_number(self) -> u16 {
        match self {
            PyVersion::V3_11 => 3495,
            PyVersion::V3_12 => 3531,
            PyVersion::V3_13 => 3571,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PyVersion::V3_11 => "3.11",
            PyVersion::V3_12 => "3.12",
            PyVersion::V3_13 => "3.13",
        }
    }

    fn ops(self) -> &'static [OpRow] {
        match self {
            PyVersion::V3_11 => &OPS_311,
            PyVersion::V3_12 => &OPS_312,
            PyVersion::V3_13 => &OPS_313,
        }
    }

    fn op_row(self, opcode: u8) -> Option<&'static OpRow> {
        let ops = self.ops();
        ops.binary_search_by_key(&opcode, |row| row.0).ok().map(|i| &ops[i])
    }
}

/// The 16-byte pyc header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PycHeader {
    pub version: PyVersion,
    pub flags: u32,
    /// Source modification time (timestamp-based pycs).
    pub mtime: Option<u32>,
    /// Source size (timestamp-based pycs).
    pub source_size: Option<u32>,
    /// Source hash (hash-based pycs).
    pub source_hash: Option<[u8; 8]>,
}

/// An arbitrary-precision integer too large for `i64`: sign and base-2^15 digits, least significant first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInt {
    pub negative: bool,
    pub digits: Vec<u16>,
}

impl BigInt {
    pub fn to_decimal(&self) -> String {
        // repeated division of the base-2^15 number by 10^9
        let mut limbs: Vec<u32> = self.digits.iter().rev().map(|&d| d as u32).collect(); // most significant first
        let mut chunks: Vec<u32> = Vec::new();
        while limbs.iter().any(|&l| l != 0) {
            let mut rem: u64 = 0;
            for limb in limbs.iter_mut() {
                let cur = (rem << 15) | *limb as u64;
                *limb = (cur / 1_000_000_000) as u32;
                rem = cur % 1_000_000_000;
            }
            chunks.push(rem as u32);
            while limbs.first() == Some(&0) {
                limbs.remove(0);
            }
        }
        let mut out = String::new();
        if self.negative && !chunks.is_empty() {
            out.push('-');
        }
        match chunks.pop() {
            None => out.push('0'),
            Some(top) => {
                out.push_str(&top.to_string());
                for c in chunks.iter().rev() {
                    out.push_str(&format!("{c:09}"));
                }
            }
        }
        out
    }
}

/// A shared marshal object.
pub type Obj = Rc<Object>;

/// A value read from a marshal stream.
#[derive(Clone, Debug, PartialEq)]
pub enum Object {
    None,
    Bool(bool),
    StopIteration,
    Ellipsis,
    Int(i64),
    BigInt(BigInt),
    Float(f64),
    Complex(f64, f64),
    Bytes(Vec<u8>),
    Str(String),
    Tuple(Vec<Obj>),
    List(Vec<Obj>),
    Dict(Vec<(Obj, Obj)>),
    Set(Vec<Obj>),
    FrozenSet(Vec<Obj>),
    Code(Box<CodeObject>),
}

/// A code object (CPython 3.11+ layout).
#[derive(Clone, Debug, PartialEq)]
pub struct CodeObject {
    pub argcount: i32,
    pub posonlyargcount: i32,
    pub kwonlyargcount: i32,
    pub stacksize: i32,
    pub flags: i32,
    pub code: Vec<u8>,
    pub consts: Vec<Obj>,
    pub names: Vec<String>,
    pub localsplusnames: Vec<String>,
    pub localspluskinds: Vec<u8>,
    pub filename: String,
    pub name: String,
    pub qualname: String,
    pub firstlineno: i32,
    pub linetable: Vec<u8>,
    pub exceptiontable: Vec<u8>,
}

/// One disassembled instruction (inline `CACHE` slots are folded into [`PyInstruction::caches`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyInstruction {
    pub offset: u32,
    pub opcode: u8,
    /// Mnemonic, or `<N>` for an opcode this version does not define.
    pub name: String,
    /// Argument including any `EXTENDED_ARG` prefixes; `None` for opcodes without an argument.
    pub arg: Option<u32>,
    /// Absolute byte offset of a jump target.
    pub target: Option<i64>,
    /// Number of inline cache entries (2 bytes each) that follow the instruction.
    pub caches: u8,
}

/// One row of the exception table, in byte offsets (`end` exclusive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PyExceptionEntry {
    pub start: u32,
    pub end: u32,
    pub target: u32,
    pub depth: u32,
    pub lasti: bool,
}

/// Source position of one location-table entry covering bytes `start..end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub start: u32,
    pub end: u32,
    pub line: Option<i32>,
    pub end_line: Option<i32>,
    pub col: Option<i32>,
    pub end_col: Option<i32>,
}

struct Marshal<'a> {
    data: &'a [u8],
    pos: usize,
    refs: Vec<Option<Obj>>,
}

impl<'a> Marshal<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| fail("length overflow"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| fail("unexpected end of marshal data"))?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(self.i32()? as u32)
    }
    fn f64(&mut self) -> Result<f64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(f64::from_le_bytes(a))
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    /// A length prefix that must be plausible given the bytes left (each item takes at least one byte).
    fn count(&mut self) -> Result<usize> {
        let n = self.i32()?;
        if n < 0 || n as usize > self.remaining() {
            return Err(fail(format!("implausible element count {n}")));
        }
        Ok(n as usize)
    }
    fn text_float(&mut self) -> Result<f64> {
        let len = self.u8()? as usize;
        let text = std::str::from_utf8(self.take(len)?).map_err(|_| fail("bad text float"))?;
        text.trim().parse::<f64>().map_err(|_| fail("bad text float"))
    }
    fn string(&mut self, len: usize) -> Result<String> {
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }

    fn object(&mut self, depth: usize) -> Result<Option<Obj>> {
        if depth > MAX_DEPTH {
            return Err(fail("marshal data nested too deeply"));
        }
        let byte = self.u8()?;
        let flag = byte & 0x80 != 0;
        let kind = byte & 0x7f;
        if kind == b'r' {
            let index = self.u32()? as usize;
            return match self.refs.get(index) {
                Some(Some(o)) => Ok(Some(o.clone())),
                _ => Err(fail(format!("bad back-reference {index}"))),
            };
        }
        let slot = if flag {
            self.refs.push(None);
            Some(self.refs.len() - 1)
        } else {
            None
        };
        let object = match kind {
            b'0' => return Ok(None),
            b'N' => Object::None,
            b'F' => Object::Bool(false),
            b'T' => Object::Bool(true),
            b'S' => Object::StopIteration,
            b'.' => Object::Ellipsis,
            b'i' => Object::Int(self.i32()? as i64),
            b'l' => self.long()?,
            b'g' => Object::Float(self.f64()?),
            b'f' => Object::Float(self.text_float()?),
            b'y' => Object::Complex(self.f64()?, self.f64()?),
            b'x' => Object::Complex(self.text_float()?, self.text_float()?),
            b's' => {
                let n = self.count()?;
                Object::Bytes(self.take(n)?.to_vec())
            }
            b'u' | b't' | b'a' | b'A' => {
                let n = self.count()?;
                Object::Str(self.string(n)?)
            }
            b'z' | b'Z' => {
                let n = self.u8()? as usize;
                Object::Str(self.string(n)?)
            }
            b'(' => {
                let n = self.count()?;
                Object::Tuple(self.items(n, depth)?)
            }
            b')' => {
                let n = self.u8()? as usize;
                Object::Tuple(self.items(n, depth)?)
            }
            b'[' => {
                let n = self.count()?;
                Object::List(self.items(n, depth)?)
            }
            b'<' => {
                let n = self.count()?;
                Object::Set(self.items(n, depth)?)
            }
            b'>' => {
                let n = self.count()?;
                Object::FrozenSet(self.items(n, depth)?)
            }
            b'{' => {
                let mut pairs = Vec::new();
                loop {
                    let Some(key) = self.object(depth + 1)? else { break };
                    let value = self.required(depth + 1)?;
                    pairs.push((key, value));
                }
                Object::Dict(pairs)
            }
            b'c' => Object::Code(Box::new(self.code(depth)?)),
            other => return Err(fail(format!("unsupported marshal type code {:?}", other as char))),
        };
        let object = Rc::new(object);
        if let Some(slot) = slot {
            self.refs[slot] = Some(object.clone());
        }
        Ok(Some(object))
    }

    fn required(&mut self, depth: usize) -> Result<Obj> {
        self.object(depth)?.ok_or_else(|| fail("unexpected NULL object"))
    }

    fn items(&mut self, n: usize, depth: usize) -> Result<Vec<Obj>> {
        let mut out = Vec::with_capacity(n.min(self.remaining()));
        for _ in 0..n {
            out.push(self.required(depth + 1)?);
        }
        Ok(out)
    }

    fn long(&mut self) -> Result<Object> {
        let n = self.i32()?;
        let count = n.unsigned_abs() as usize;
        if count.checked_mul(2).is_none_or(|bytes| bytes > self.remaining()) {
            return Err(fail("implausible long size"));
        }
        let mut digits = Vec::with_capacity(count);
        for _ in 0..count {
            let b = self.take(2)?;
            let d = u16::from_le_bytes([b[0], b[1]]);
            if d >= 1 << 15 {
                return Err(fail("long digit out of range"));
            }
            digits.push(d);
        }
        while digits.last() == Some(&0) {
            digits.pop();
        }
        if digits.len() <= 8 {
            let mut value: i128 = 0;
            for &d in digits.iter().rev() {
                value = (value << 15) | d as i128;
            }
            if n < 0 {
                value = -value;
            }
            if let Ok(v) = i64::try_from(value) {
                return Ok(Object::Int(v));
            }
        }
        Ok(Object::BigInt(BigInt {
            negative: n < 0,
            digits,
        }))
    }

    fn string_tuple(&mut self, depth: usize, what: &str) -> Result<Vec<String>> {
        match &*self.required(depth + 1)? {
            Object::Tuple(items) => items
                .iter()
                .map(|o| match &**o {
                    Object::Str(s) => Ok(s.clone()),
                    _ => Err(fail(format!("{what} contains a non-string"))),
                })
                .collect(),
            _ => Err(fail(format!("{what} is not a tuple"))),
        }
    }

    fn bytes_field(&mut self, depth: usize, what: &str) -> Result<Vec<u8>> {
        match &*self.required(depth + 1)? {
            Object::Bytes(b) => Ok(b.clone()),
            _ => Err(fail(format!("{what} is not bytes"))),
        }
    }

    fn str_field(&mut self, depth: usize, what: &str) -> Result<String> {
        match &*self.required(depth + 1)? {
            Object::Str(s) => Ok(s.clone()),
            _ => Err(fail(format!("{what} is not a string"))),
        }
    }

    fn code(&mut self, depth: usize) -> Result<CodeObject> {
        let argcount = self.i32()?;
        let posonlyargcount = self.i32()?;
        let kwonlyargcount = self.i32()?;
        let stacksize = self.i32()?;
        let flags = self.i32()?;
        let code = self.bytes_field(depth, "co_code")?;
        let consts = match &*self.required(depth + 1)? {
            Object::Tuple(items) => items.clone(),
            _ => return Err(fail("co_consts is not a tuple")),
        };
        let names = self.string_tuple(depth, "co_names")?;
        let localsplusnames = self.string_tuple(depth, "co_localsplusnames")?;
        let localspluskinds = self.bytes_field(depth, "co_localspluskinds")?;
        let filename = self.str_field(depth, "co_filename")?;
        let name = self.str_field(depth, "co_name")?;
        let qualname = self.str_field(depth, "co_qualname")?;
        let firstlineno = self.i32()?;
        let linetable = self.bytes_field(depth, "co_linetable")?;
        let exceptiontable = self.bytes_field(depth, "co_exceptiontable")?;
        Ok(CodeObject {
            argcount,
            posonlyargcount,
            kwonlyargcount,
            stacksize,
            flags,
            code,
            consts,
            names,
            localsplusnames,
            localspluskinds,
            filename,
            name,
            qualname,
            firstlineno,
            linetable,
            exceptiontable,
        })
    }
}

/// A parsed `.pyc` file.
#[derive(Clone, Debug, PartialEq)]
pub struct PycFile {
    pub header: PycHeader,
    pub code: CodeObject,
}

impl PycFile {
    pub fn parse(bytes: &[u8]) -> Result<PycFile> {
        let header = parse_header(bytes)?;
        let mut m = Marshal {
            data: bytes,
            pos: 16,
            refs: Vec::new(),
        };
        let root = m.required(0)?;
        if m.pos != bytes.len() {
            return Err(fail("trailing bytes after the marshalled code object"));
        }
        match &*root {
            Object::Code(code) => Ok(PycFile {
                header,
                code: (**code).clone(),
            }),
            _ => Err(fail("the marshalled root object is not a code object")),
        }
    }

    pub fn open(path: impl AsRef<std::path::Path>) -> Result<PycFile> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| fail(format!("cannot read file: {e}")))?;
        PycFile::parse(&bytes)
    }

    /// A text listing of the module code and every nested code object.
    pub fn disassembly(&self) -> Result<String> {
        let mut out = String::new();
        self.code.write_disassembly(self.header.version, &mut out)?;
        Ok(out)
    }
}

/// Parse only the 16-byte header.
pub fn parse_header(bytes: &[u8]) -> Result<PycHeader> {
    if bytes.len() < 16 {
        return Err(fail("file is shorter than the 16-byte header"));
    }
    if bytes[2] != b'\r' || bytes[3] != b'\n' {
        return Err(fail("bad magic number (missing \\r\\n)"));
    }
    let number = u16::from_le_bytes([bytes[0], bytes[1]]);
    let version = PyVersion::from_magic_number(number)
        .ok_or_else(|| fail(format!("unsupported Python magic number {number}")))?;
    let flags = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if flags & 1 != 0 {
        let mut hash = [0u8; 8];
        hash.copy_from_slice(&bytes[8..16]);
        Ok(PycHeader {
            version,
            flags,
            mtime: None,
            source_size: None,
            source_hash: Some(hash),
        })
    } else {
        Ok(PycHeader {
            version,
            flags,
            mtime: Some(u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]])),
            source_size: Some(u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]])),
            source_hash: None,
        })
    }
}

const FLAG_CONST: u8 = 1;
const FLAG_NAME: u8 = 2;
const FLAG_LOCAL: u8 = 4;
const FLAG_FREE: u8 = 8;
const FLAG_JREL: u8 = 16;
const FLAG_BACK: u8 = 32;
const FLAG_ARG: u8 = 128;

impl CodeObject {
    /// Disassemble the instruction stream, skipping inline cache entries.
    pub fn instructions(&self, version: PyVersion) -> Result<Vec<PyInstruction>> {
        if !self.code.len().is_multiple_of(2) {
            return Err(fail("odd bytecode length"));
        }
        let mut out = Vec::new();
        let mut extended: u32 = 0;
        let mut i = 0usize;
        while i < self.code.len() {
            let opcode = self.code[i];
            let raw = self.code[i + 1];
            let row = version.op_row(opcode);
            let (name, caches, flags) = match row {
                Some((_, n, c, f)) => ((*n).to_string(), *c, *f),
                None => (format!("<{opcode}>"), 0, 0),
            };
            let arg = if flags & FLAG_ARG != 0 {
                let value = raw as u32 | extended;
                extended = if name == "EXTENDED_ARG" { value << 8 } else { 0 };
                Some(value)
            } else {
                extended = 0;
                None
            };
            let target = match arg {
                Some(a) if flags & FLAG_JREL != 0 => {
                    let signed = if flags & FLAG_BACK != 0 { -(a as i64) } else { a as i64 };
                    let mut t = i as i64 + 2 + signed * 2;
                    if version != PyVersion::V3_11 {
                        t += 2 * caches as i64;
                    }
                    Some(t)
                }
                _ => None,
            };
            out.push(PyInstruction {
                offset: i as u32,
                opcode,
                name,
                arg,
                target,
                caches,
            });
            i += 2 + 2 * caches as usize;
        }
        Ok(out)
    }

    /// The exception table as byte-offset ranges.
    pub fn exception_table(&self) -> Result<Vec<PyExceptionEntry>> {
        let t = &self.exceptiontable;
        let mut pos = 0usize;
        let varint = |pos: &mut usize| -> Result<u32> {
            let mut b = *t.get(*pos).ok_or_else(|| fail("truncated exception table"))?;
            *pos += 1;
            let mut value = (b & 63) as u32;
            while b & 64 != 0 {
                b = *t.get(*pos).ok_or_else(|| fail("truncated exception table"))?;
                *pos += 1;
                value = value
                    .checked_shl(6)
                    .ok_or_else(|| fail("exception table value overflow"))?
                    | (b & 63) as u32;
            }
            Ok(value)
        };
        let mut out = Vec::new();
        while pos < t.len() {
            let start = varint(&mut pos)?.wrapping_mul(2);
            let length = varint(&mut pos)?.wrapping_mul(2);
            let target = varint(&mut pos)?.wrapping_mul(2);
            let depth_lasti = varint(&mut pos)?;
            out.push(PyExceptionEntry {
                start,
                end: start.wrapping_add(length),
                target,
                depth: depth_lasti >> 1,
                lasti: depth_lasti & 1 != 0,
            });
        }
        Ok(out)
    }

    /// The location table decoded into one [`Position`] per entry (entries cover inline caches too).
    pub fn positions(&self) -> Result<Vec<Position>> {
        let t = &self.linetable;
        let mut pos = 0usize;
        let mut line = self.firstlineno;
        let mut start = 0u32;
        let mut out = Vec::new();
        let byte = |pos: &mut usize| -> Result<u8> {
            let b = *t.get(*pos).ok_or_else(|| fail("truncated location table"))?;
            *pos += 1;
            Ok(b)
        };
        let read_varint = |pos: &mut usize| -> Result<u32> {
            let mut b = byte(pos)?;
            let mut value = (b & 63) as u32;
            let mut shift = 0u32;
            while b & 64 != 0 {
                b = byte(pos)?;
                shift += 6;
                if shift > 30 {
                    return Err(fail("location table varint too long"));
                }
                value |= ((b & 63) as u32) << shift;
            }
            Ok(value)
        };
        let read_svarint = |pos: &mut usize| -> Result<i32> {
            let v = read_varint(pos)?;
            Ok(if v & 1 != 0 {
                -((v >> 1) as i32)
            } else {
                (v >> 1) as i32
            })
        };
        while pos < t.len() {
            let first = byte(&mut pos)?;
            if first & 0x80 == 0 {
                return Err(fail("location table entry does not start with a marker bit"));
            }
            let code = (first >> 3) & 15;
            let length = ((first & 7) as u32 + 1) * 2;
            let (entry_line, end_line, col, end_col);
            match code {
                15 => {
                    entry_line = None;
                    end_line = None;
                    col = None;
                    end_col = None;
                }
                14 => {
                    line += read_svarint(&mut pos)?;
                    let end_delta = read_varint(&mut pos)? as i32;
                    let c = read_varint(&mut pos)? as i32 - 1;
                    let ec = read_varint(&mut pos)? as i32 - 1;
                    entry_line = Some(line);
                    end_line = Some(line + end_delta);
                    col = (c >= 0).then_some(c);
                    end_col = (ec >= 0).then_some(ec);
                }
                13 => {
                    line += read_svarint(&mut pos)?;
                    entry_line = Some(line);
                    end_line = Some(line);
                    col = None;
                    end_col = None;
                }
                10..=12 => {
                    line += code as i32 - 10;
                    let c = byte(&mut pos)? as i32;
                    let ec = byte(&mut pos)? as i32;
                    entry_line = Some(line);
                    end_line = Some(line);
                    col = Some(c);
                    end_col = Some(ec);
                }
                _ => {
                    let second = byte(&mut pos)? as i32;
                    let c = ((code as i32) << 3) | ((second >> 4) & 7);
                    entry_line = Some(line);
                    end_line = Some(line);
                    col = Some(c);
                    end_col = Some(c + (second & 15));
                }
            }
            // skip any remaining bytes of this entry (they have no marker bit)
            while t.get(pos).is_some_and(|b| b & 0x80 == 0) {
                pos += 1;
            }
            out.push(Position {
                start,
                end: start + length,
                line: entry_line,
                end_line,
                col,
                end_col,
            });
            start += length;
        }
        Ok(out)
    }

    /// Human-readable operand for an instruction (constant, name or variable), if it has one.
    pub fn describe_argument(&self, version: PyVersion, insn: &PyInstruction) -> Option<String> {
        let arg = insn.arg? as usize;
        let flags = version.op_row(insn.opcode).map(|r| r.3).unwrap_or(0);
        let name_index = match insn.name.as_str() {
            "LOAD_GLOBAL" | "LOAD_ATTR" if version != PyVersion::V3_11 || insn.name == "LOAD_GLOBAL" => arg >> 1,
            "LOAD_SUPER_ATTR" => arg >> 2,
            _ => arg,
        };
        if flags & FLAG_CONST != 0 {
            return self.consts.get(arg).map(|c| py_repr(c));
        }
        if flags & FLAG_NAME != 0 {
            return self.names.get(name_index).cloned();
        }
        if flags & (FLAG_LOCAL | FLAG_FREE) != 0 {
            return self.localsplusnames.get(arg).cloned();
        }
        None
    }

    fn write_disassembly(&self, version: PyVersion, out: &mut String) -> Result<()> {
        out.push_str(&format!(
            "Disassembly of <code object {} at line {}, file \"{}\">:\n",
            self.qualname, self.firstlineno, self.filename
        ));
        for insn in self.instructions(version)? {
            let arg = insn.arg.map(|a| a.to_string()).unwrap_or_default();
            let mut line = format!("{:>6}  {:<28}{:>6}", insn.offset, insn.name, arg);
            if let Some(t) = insn.target {
                line.push_str(&format!("  (to {t})"));
            } else if let Some(text) = self.describe_argument(version, &insn) {
                line.push_str(&format!("  ({text})"));
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        for entry in self.exception_table()? {
            out.push_str(&format!(
                "  ExceptionTable: {}..{} -> {} [{}]{}\n",
                entry.start,
                entry.end,
                entry.target,
                entry.depth,
                if entry.lasti { " lasti" } else { "" }
            ));
        }
        out.push('\n');
        for constant in &self.consts {
            if let Object::Code(nested) = &**constant {
                nested.write_disassembly(version, out)?;
            }
        }
        Ok(())
    }
}

/// Python's `repr()` for the marshal object kinds that appear as constants.
pub fn py_repr(object: &Object) -> String {
    match object {
        Object::None => "None".into(),
        Object::Bool(true) => "True".into(),
        Object::Bool(false) => "False".into(),
        Object::StopIteration => "StopIteration".into(),
        Object::Ellipsis => "Ellipsis".into(),
        Object::Int(v) => v.to_string(),
        Object::BigInt(b) => b.to_decimal(),
        Object::Float(v) => py_float_repr(*v),
        Object::Complex(re, im) => {
            if *re == 0.0 && re.is_sign_positive() {
                format!("{}j", py_float_repr_trim(*im))
            } else {
                let sign = if im.is_sign_negative() { "" } else { "+" };
                format!("({}{}{}j)", py_float_repr_trim(*re), sign, py_float_repr_trim(*im))
            }
        }
        Object::Bytes(b) => py_bytes_repr(b),
        Object::Str(s) => py_str_repr(s),
        Object::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(|o| py_repr(o)).collect();
            if parts.len() == 1 {
                format!("({},)", parts[0])
            } else {
                format!("({})", parts.join(", "))
            }
        }
        Object::List(items) => format!("[{}]", items.iter().map(|o| py_repr(o)).collect::<Vec<_>>().join(", ")),
        Object::Dict(pairs) => format!(
            "{{{}}}",
            pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Object::Set(items) => {
            if items.is_empty() {
                "set()".into()
            } else {
                format!(
                    "{{{}}}",
                    items.iter().map(|o| py_repr(o)).collect::<Vec<_>>().join(", ")
                )
            }
        }
        Object::FrozenSet(items) => {
            if items.is_empty() {
                "frozenset()".into()
            } else {
                format!(
                    "frozenset({{{}}})",
                    items.iter().map(|o| py_repr(o)).collect::<Vec<_>>().join(", ")
                )
            }
        }
        Object::Code(c) => format!("<code object {} at line {}>", c.name, c.firstlineno),
    }
}

/// `repr(float)`: shortest round-trip digits; scientific notation when the exponent is < -4 or >= 16.
pub fn py_float_repr(v: f64) -> String {
    if v.is_nan() {
        return "nan".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if v == 0.0 {
        return if v.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let sci = format!("{:e}", v.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    let exp: i32 = exp.parse().unwrap_or(0);
    let sign = if v < 0.0 { "-" } else { "" };
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let int_len = exp as usize + 1;
            let mut int_part: String = digits.chars().take(int_len).collect();
            while int_part.len() < int_len {
                int_part.push('0');
            }
            let frac: String = digits.chars().skip(int_len).collect();
            let frac = if frac.is_empty() { "0".to_string() } else { frac };
            format!("{sign}{int_part}.{frac}")
        } else {
            format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize))
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let mant = if rest.is_empty() {
            first.to_string()
        } else {
            format!("{first}.{rest}")
        };
        format!("{sign}{mant}e{}{:02}", if exp < 0 { "-" } else { "+" }, exp.abs())
    }
}

/// Float formatting inside complex numbers: integral values drop the trailing `.0`.
fn py_float_repr_trim(v: f64) -> String {
    let s = py_float_repr(v);
    s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
}

fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn py_bytes_repr(bytes: &[u8]) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from("b");
    out.push(quote);
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if c as char == quote => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_numbers_map_to_versions() {
        assert_eq!(PyVersion::from_magic_number(3495), Some(PyVersion::V3_11));
        assert_eq!(PyVersion::from_magic_number(3531), Some(PyVersion::V3_12));
        assert_eq!(PyVersion::from_magic_number(3571), Some(PyVersion::V3_13));
        assert_eq!(PyVersion::from_magic_number(3413), None);
        for v in [PyVersion::V3_11, PyVersion::V3_12, PyVersion::V3_13] {
            assert_eq!(PyVersion::from_magic_number(v.magic_number()), Some(v));
        }
    }

    #[test]
    fn header_variants() {
        let mut timestamp = vec![0xf3, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
        timestamp[0..2].copy_from_slice(&3571u16.to_le_bytes());
        let h = parse_header(&timestamp).unwrap();
        assert_eq!(h.version, PyVersion::V3_13);
        assert_eq!((h.mtime, h.source_size), (Some(1), Some(2)));
        let mut hashed = timestamp.clone();
        hashed[4] = 3;
        hashed[8..16].copy_from_slice(&[9; 8]);
        assert_eq!(parse_header(&hashed).unwrap().source_hash, Some([9; 8]));
        assert!(parse_header(&timestamp[..15]).is_err());
        timestamp[2] = 0;
        assert!(parse_header(&timestamp).is_err());
    }

    #[test]
    fn rejects_unsupported_magic() {
        let mut bytes = vec![0u8; 16];
        bytes[0..2].copy_from_slice(&3413u16.to_le_bytes());
        bytes[2] = b'\r';
        bytes[3] = b'\n';
        assert!(PycFile::parse(&bytes).is_err());
    }

    #[test]
    fn marshal_scalars_and_refs() {
        let mut data = vec![b'(', 3, 0, 0, 0];
        data.extend_from_slice(&[0xe9, 5, 0, 0, 0]); // 'i' with FLAG_REF: 5
        data.extend_from_slice(&[b'r', 0, 0, 0, 0]); // back-reference to slot 0
        data.extend_from_slice(&[b'z', 2, b'h', b'i']);
        let mut m = Marshal {
            data: &data,
            pos: 0,
            refs: Vec::new(),
        };
        let obj = m.required(0).unwrap();
        match &*obj {
            Object::Tuple(items) => {
                assert_eq!(*items[0], Object::Int(5));
                assert_eq!(*items[1], Object::Int(5));
                assert_eq!(*items[2], Object::Str("hi".into()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn marshal_long_and_bigint() {
        // 'l', 2 digits: 1 + 2*32768 = 65537
        let data = [b'l', 2, 0, 0, 0, 1, 0, 2, 0];
        let mut m = Marshal {
            data: &data,
            pos: 0,
            refs: Vec::new(),
        };
        assert_eq!(*m.required(0).unwrap(), Object::Int(65537));
        // 10 digits of value 1 in the top place => 2^135, negative
        let mut big = vec![b'l'];
        big.extend_from_slice(&(-10i32).to_le_bytes());
        for i in 0..10u16 {
            big.extend_from_slice(&(if i == 9 { 1u16 } else { 0 }).to_le_bytes());
        }
        let mut m = Marshal {
            data: &big,
            pos: 0,
            refs: Vec::new(),
        };
        match &*m.required(0).unwrap() {
            Object::BigInt(b) => assert_eq!(b.to_decimal(), "-43556142965880123323311949751266331066368"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn marshal_rejects_bad_input() {
        let mut m = Marshal {
            data: &[b'r', 9, 0, 0, 0],
            pos: 0,
            refs: Vec::new(),
        };
        assert!(m.required(0).is_err());
        let mut m = Marshal {
            data: &[b'(', 0xff, 0xff, 0xff, 0x7f],
            pos: 0,
            refs: Vec::new(),
        };
        assert!(m.required(0).is_err());
        let mut m = Marshal {
            data: b"?",
            pos: 0,
            refs: Vec::new(),
        };
        assert!(m.required(0).is_err());
    }

    #[test]
    fn float_repr_matches_python_rules() {
        assert_eq!(py_float_repr(1.0), "1.0");
        assert_eq!(py_float_repr(0.1), "0.1");
        assert_eq!(py_float_repr(1e16), "1e+16");
        assert_eq!(py_float_repr(1e15), "1000000000000000.0");
        assert_eq!(py_float_repr(0.0001), "0.0001");
        assert_eq!(py_float_repr(0.00001), "1e-05");
        assert_eq!(py_float_repr(1.5e300), "1.5e+300");
        assert_eq!(py_float_repr(-2.5), "-2.5");
    }

    #[test]
    fn extended_arg_and_jump_targets() {
        let code = CodeObject {
            argcount: 0,
            posonlyargcount: 0,
            kwonlyargcount: 0,
            stacksize: 1,
            flags: 0,
            // EXTENDED_ARG 1; LOAD_CONST 2 (=> 258); JUMP_BACKWARD 2 (3.12: target = 6 + 2 - 4 + caches 0)
            code: vec![144, 1, 100, 2, 140, 2],
            consts: vec![],
            names: vec![],
            localsplusnames: vec![],
            localspluskinds: vec![],
            filename: String::new(),
            name: String::new(),
            qualname: String::new(),
            firstlineno: 1,
            linetable: vec![],
            exceptiontable: vec![],
        };
        let insns = code.instructions(PyVersion::V3_12).unwrap();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[1].name, "LOAD_CONST");
        assert_eq!(insns[1].arg, Some(258));
        assert_eq!(insns[2].name, "JUMP_BACKWARD");
        assert_eq!(insns[2].target, Some(4 + 2 - 4 + 2 * insns[2].caches as i64));
    }
}
