//! Java `.class` file reader and bytecode disassembler.
//!
//! Parses the structure defined by the Java Virtual Machine Specification (chapter 4): the constant
//! pool, fields, methods and attributes, and disassembles method bytecode (chapter 6) into a
//! `javap -c`-style listing. This is a *disassembler and metadata reader*: it does not recover Java
//! source. Unknown attributes are preserved as raw bytes rather than guessed at.

use crate::error::{Error, Result};

fn fail(message: impl Into<String>) -> Error {
    Error::Parse(format!("class file: {}", message.into()))
}

/// Magic number every class file starts with.
pub const CLASS_MAGIC: u32 = 0xCAFE_BABE;

/// One entry of the constant pool. Index 0 and the second slot of `Long`/`Double` are `Unusable`.
#[derive(Clone, Debug, PartialEq)]
pub enum Constant {
    Unusable,
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    Class(u16),
    String(u16),
    Fieldref(u16, u16),
    Methodref(u16, u16),
    InterfaceMethodref(u16, u16),
    NameAndType(u16, u16),
    MethodHandle(u8, u16),
    MethodType(u16),
    Dynamic(u16, u16),
    InvokeDynamic(u16, u16),
    Module(u16),
    Package(u16),
}

/// A raw attribute: its name and uninterpreted payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub info: Vec<u8>,
}

/// A field or method.
#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub access_flags: u16,
    pub name: String,
    pub descriptor: String,
    pub attributes: Vec<Attribute>,
}

/// One row of a `Code` attribute's exception table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExceptionEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    /// Constant-pool index of the caught class, or 0 for "any".
    pub catch_type: u16,
}

/// A parsed `Code` attribute.
#[derive(Clone, Debug, PartialEq)]
pub struct Code {
    pub max_stack: u16,
    pub max_locals: u16,
    pub bytecode: Vec<u8>,
    pub exception_table: Vec<ExceptionEntry>,
    pub attributes: Vec<Attribute>,
}

/// A parsed class file.
#[derive(Clone, Debug, PartialEq)]
pub struct ClassFile {
    pub minor_version: u16,
    pub major_version: u16,
    pub constant_pool: Vec<Constant>,
    pub access_flags: u16,
    pub this_class: u16,
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<Member>,
    pub methods: Vec<Member>,
    pub attributes: Vec<Attribute>,
}

/// Decoded operands of one instruction. Branch targets are absolute code offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operands {
    None,
    /// `bipush` / `sipush` immediate.
    Immediate(i32),
    /// Local-variable slot (`iload`, `astore`, `ret`, ...).
    Local(u16),
    /// Constant-pool index (`ldc`, `getstatic`, `new`, ...).
    Pool(u16),
    Branch(i64),
    Iinc {
        local: u16,
        delta: i32,
    },
    InvokeInterface {
        index: u16,
        count: u8,
    },
    InvokeDynamic(u16),
    NewArray(u8),
    MultiANewArray {
        index: u16,
        dimensions: u8,
    },
    TableSwitch {
        default: i64,
        low: i32,
        high: i32,
        targets: Vec<i64>,
    },
    LookupSwitch {
        default: i64,
        pairs: Vec<(i32, i64)>,
    },
}

/// One disassembled instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub offset: u32,
    pub opcode: u8,
    /// True if this instruction was prefixed by `wide`.
    pub wide: bool,
    pub mnemonic: &'static str,
    pub operands: Operands,
    /// Total encoded length in bytes, including any `wide` prefix and switch padding.
    pub length: u32,
}

const MNEMONICS: [&str; 202] = [
    "nop",
    "aconst_null",
    "iconst_m1",
    "iconst_0",
    "iconst_1",
    "iconst_2",
    "iconst_3",
    "iconst_4",
    "iconst_5",
    "lconst_0",
    "lconst_1",
    "fconst_0",
    "fconst_1",
    "fconst_2",
    "dconst_0",
    "dconst_1",
    "bipush",
    "sipush",
    "ldc",
    "ldc_w",
    "ldc2_w",
    "iload",
    "lload",
    "fload",
    "dload",
    "aload",
    "iload_0",
    "iload_1",
    "iload_2",
    "iload_3",
    "lload_0",
    "lload_1",
    "lload_2",
    "lload_3",
    "fload_0",
    "fload_1",
    "fload_2",
    "fload_3",
    "dload_0",
    "dload_1",
    "dload_2",
    "dload_3",
    "aload_0",
    "aload_1",
    "aload_2",
    "aload_3",
    "iaload",
    "laload",
    "faload",
    "daload",
    "aaload",
    "baload",
    "caload",
    "saload",
    "istore",
    "lstore",
    "fstore",
    "dstore",
    "astore",
    "istore_0",
    "istore_1",
    "istore_2",
    "istore_3",
    "lstore_0",
    "lstore_1",
    "lstore_2",
    "lstore_3",
    "fstore_0",
    "fstore_1",
    "fstore_2",
    "fstore_3",
    "dstore_0",
    "dstore_1",
    "dstore_2",
    "dstore_3",
    "astore_0",
    "astore_1",
    "astore_2",
    "astore_3",
    "iastore",
    "lastore",
    "fastore",
    "dastore",
    "aastore",
    "bastore",
    "castore",
    "sastore",
    "pop",
    "pop2",
    "dup",
    "dup_x1",
    "dup_x2",
    "dup2",
    "dup2_x1",
    "dup2_x2",
    "swap",
    "iadd",
    "ladd",
    "fadd",
    "dadd",
    "isub",
    "lsub",
    "fsub",
    "dsub",
    "imul",
    "lmul",
    "fmul",
    "dmul",
    "idiv",
    "ldiv",
    "fdiv",
    "ddiv",
    "irem",
    "lrem",
    "frem",
    "drem",
    "ineg",
    "lneg",
    "fneg",
    "dneg",
    "ishl",
    "lshl",
    "ishr",
    "lshr",
    "iushr",
    "lushr",
    "iand",
    "land",
    "ior",
    "lor",
    "ixor",
    "lxor",
    "iinc",
    "i2l",
    "i2f",
    "i2d",
    "l2i",
    "l2f",
    "l2d",
    "f2i",
    "f2l",
    "f2d",
    "d2i",
    "d2l",
    "d2f",
    "i2b",
    "i2c",
    "i2s",
    "lcmp",
    "fcmpl",
    "fcmpg",
    "dcmpl",
    "dcmpg",
    "ifeq",
    "ifne",
    "iflt",
    "ifge",
    "ifgt",
    "ifle",
    "if_icmpeq",
    "if_icmpne",
    "if_icmplt",
    "if_icmpge",
    "if_icmpgt",
    "if_icmple",
    "if_acmpeq",
    "if_acmpne",
    "goto",
    "jsr",
    "ret",
    "tableswitch",
    "lookupswitch",
    "ireturn",
    "lreturn",
    "freturn",
    "dreturn",
    "areturn",
    "return",
    "getstatic",
    "putstatic",
    "getfield",
    "putfield",
    "invokevirtual",
    "invokespecial",
    "invokestatic",
    "invokeinterface",
    "invokedynamic",
    "new",
    "newarray",
    "anewarray",
    "arraylength",
    "athrow",
    "checkcast",
    "instanceof",
    "monitorenter",
    "monitorexit",
    "wide",
    "multianewarray",
    "ifnull",
    "ifnonnull",
    "goto_w",
    "jsr_w",
];

/// The mnemonic for an opcode, or `None` for an unassigned/reserved value.
pub fn mnemonic(opcode: u8) -> Option<&'static str> {
    MNEMONICS.get(opcode as usize).copied()
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| fail("length overflow"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| fail("unexpected end of data"))?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }
}

/// Decode the JVM's "modified UTF-8" (null as C0 80, supplementary characters as surrogate pairs).
pub fn decode_modified_utf8(bytes: &[u8]) -> Result<String> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            let b2 = *bytes.get(i + 1).ok_or_else(|| fail("truncated UTF-8 sequence"))?;
            if b2 & 0xC0 != 0x80 {
                return Err(fail("bad UTF-8 continuation byte"));
            }
            units.push((((b & 0x1F) as u16) << 6) | (b2 & 0x3F) as u16);
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            let (b2, b3) = match (bytes.get(i + 1), bytes.get(i + 2)) {
                (Some(&x), Some(&y)) => (x, y),
                _ => return Err(fail("truncated UTF-8 sequence")),
            };
            if b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                return Err(fail("bad UTF-8 continuation byte"));
            }
            units.push((((b & 0x0F) as u16) << 12) | (((b2 & 0x3F) as u16) << 6) | (b3 & 0x3F) as u16);
            i += 3;
        } else {
            return Err(fail("invalid modified UTF-8 lead byte"));
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

impl ClassFile {
    /// Parse a class file from its bytes.
    pub fn parse(bytes: &[u8]) -> Result<ClassFile> {
        let mut r = Reader::new(bytes);
        if r.u32()? != CLASS_MAGIC {
            return Err(fail("bad magic number"));
        }
        let minor_version = r.u16()?;
        let major_version = r.u16()?;
        let cp_count = r.u16()? as usize;
        let mut constant_pool = Vec::with_capacity(cp_count);
        constant_pool.push(Constant::Unusable);
        while constant_pool.len() < cp_count {
            let tag = r.u8()?;
            let constant = match tag {
                1 => {
                    let len = r.u16()? as usize;
                    Constant::Utf8(decode_modified_utf8(r.take(len)?)?)
                }
                3 => Constant::Integer(r.i32()?),
                4 => Constant::Float(f32::from_bits(r.u32()?)),
                5 => {
                    let hi = r.u32()? as u64;
                    let lo = r.u32()? as u64;
                    Constant::Long(((hi << 32) | lo) as i64)
                }
                6 => {
                    let hi = r.u32()? as u64;
                    let lo = r.u32()? as u64;
                    Constant::Double(f64::from_bits((hi << 32) | lo))
                }
                7 => Constant::Class(r.u16()?),
                8 => Constant::String(r.u16()?),
                9 => Constant::Fieldref(r.u16()?, r.u16()?),
                10 => Constant::Methodref(r.u16()?, r.u16()?),
                11 => Constant::InterfaceMethodref(r.u16()?, r.u16()?),
                12 => Constant::NameAndType(r.u16()?, r.u16()?),
                15 => Constant::MethodHandle(r.u8()?, r.u16()?),
                16 => Constant::MethodType(r.u16()?),
                17 => Constant::Dynamic(r.u16()?, r.u16()?),
                18 => Constant::InvokeDynamic(r.u16()?, r.u16()?),
                19 => Constant::Module(r.u16()?),
                20 => Constant::Package(r.u16()?),
                other => return Err(fail(format!("unknown constant pool tag {other}"))),
            };
            let wide = matches!(constant, Constant::Long(_) | Constant::Double(_));
            constant_pool.push(constant);
            if wide {
                constant_pool.push(Constant::Unusable);
            }
        }
        if constant_pool.len() != cp_count {
            return Err(fail("constant pool overruns its declared size"));
        }

        let mut class = ClassFile {
            minor_version,
            major_version,
            constant_pool,
            access_flags: r.u16()?,
            this_class: r.u16()?,
            super_class: r.u16()?,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let n = r.u16()? as usize;
        for _ in 0..n {
            class.interfaces.push(r.u16()?);
        }
        for is_method in [false, true] {
            let n = r.u16()? as usize;
            for _ in 0..n {
                let access_flags = r.u16()?;
                let name = class.utf8(r.u16()?)?.to_string();
                let descriptor = class.utf8(r.u16()?)?.to_string();
                let attributes = class.read_attributes(&mut r)?;
                let member = Member {
                    access_flags,
                    name,
                    descriptor,
                    attributes,
                };
                if is_method {
                    class.methods.push(member);
                } else {
                    class.fields.push(member);
                }
            }
        }
        class.attributes = class.read_attributes(&mut r)?;
        if r.pos != bytes.len() {
            return Err(fail("trailing bytes after class file"));
        }
        Ok(class)
    }

    fn read_attributes(&self, r: &mut Reader<'_>) -> Result<Vec<Attribute>> {
        let n = r.u16()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let name = self.utf8(r.u16()?)?.to_string();
            let len = r.u32()? as usize;
            out.push(Attribute {
                name,
                info: r.take(len)?.to_vec(),
            });
        }
        Ok(out)
    }

    /// The constant at `index`.
    pub fn constant(&self, index: u16) -> Result<&Constant> {
        match self.constant_pool.get(index as usize) {
            Some(Constant::Unusable) | None => Err(fail(format!("invalid constant pool index {index}"))),
            Some(c) => Ok(c),
        }
    }

    /// The string at a `Utf8` constant.
    pub fn utf8(&self, index: u16) -> Result<&str> {
        match self.constant(index)? {
            Constant::Utf8(s) => Ok(s),
            _ => Err(fail(format!("constant {index} is not Utf8"))),
        }
    }

    /// The internal name (`java/lang/Object`) of a `Class` constant.
    pub fn class_name(&self, index: u16) -> Result<&str> {
        match self.constant(index)? {
            Constant::Class(n) => self.utf8(*n),
            _ => Err(fail(format!("constant {index} is not a Class"))),
        }
    }

    /// Internal name of this class.
    pub fn this_class_name(&self) -> Result<&str> {
        self.class_name(self.this_class)
    }

    /// Internal name of the superclass, or `None` for `java/lang/Object`.
    pub fn super_class_name(&self) -> Result<Option<&str>> {
        if self.super_class == 0 {
            Ok(None)
        } else {
            self.class_name(self.super_class).map(Some)
        }
    }

    fn name_and_type(&self, index: u16) -> Result<(&str, &str)> {
        match self.constant(index)? {
            Constant::NameAndType(n, d) => Ok((self.utf8(*n)?, self.utf8(*d)?)),
            _ => Err(fail(format!("constant {index} is not a NameAndType"))),
        }
    }

    /// Parse the `Code` attribute of a method, if it has one.
    pub fn code(&self, method: &Member) -> Result<Option<Code>> {
        let Some(attr) = method.attributes.iter().find(|a| a.name == "Code") else {
            return Ok(None);
        };
        let mut r = Reader::new(&attr.info);
        let max_stack = r.u16()?;
        let max_locals = r.u16()?;
        let len = r.u32()? as usize;
        let bytecode = r.take(len)?.to_vec();
        let n = r.u16()? as usize;
        let mut exception_table = Vec::with_capacity(n);
        for _ in 0..n {
            exception_table.push(ExceptionEntry {
                start_pc: r.u16()?,
                end_pc: r.u16()?,
                handler_pc: r.u16()?,
                catch_type: r.u16()?,
            });
        }
        let attributes = self.read_attributes(&mut r)?;
        Ok(Some(Code {
            max_stack,
            max_locals,
            bytecode,
            exception_table,
            attributes,
        }))
    }

    /// `(start_pc, line)` pairs from a `LineNumberTable` attribute inside `code`.
    pub fn line_numbers(&self, code: &Code) -> Result<Vec<(u16, u16)>> {
        let mut out = Vec::new();
        for attr in code.attributes.iter().filter(|a| a.name == "LineNumberTable") {
            let mut r = Reader::new(&attr.info);
            let n = r.u16()? as usize;
            for _ in 0..n {
                out.push((r.u16()?, r.u16()?));
            }
        }
        Ok(out)
    }

    /// The `SourceFile` attribute value, if present.
    pub fn source_file(&self) -> Result<Option<String>> {
        match self.attributes.iter().find(|a| a.name == "SourceFile") {
            Some(a) if a.info.len() == 2 => {
                Ok(Some(self.utf8(u16::from_be_bytes([a.info[0], a.info[1]]))?.to_string()))
            }
            Some(_) => Err(fail("malformed SourceFile attribute")),
            None => Ok(None),
        }
    }

    /// Bootstrap methods as `(method_handle_index, argument_indices)`.
    pub fn bootstrap_methods(&self) -> Result<Vec<(u16, Vec<u16>)>> {
        let Some(attr) = self.attributes.iter().find(|a| a.name == "BootstrapMethods") else {
            return Ok(Vec::new());
        };
        let mut r = Reader::new(&attr.info);
        let n = r.u16()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let handle = r.u16()?;
            let argc = r.u16()? as usize;
            let mut args = Vec::with_capacity(argc);
            for _ in 0..argc {
                args.push(r.u16()?);
            }
            out.push((handle, args));
        }
        Ok(out)
    }

    /// Disassemble raw bytecode into instructions.
    pub fn disassemble(&self, bytecode: &[u8]) -> Result<Vec<Instruction>> {
        disassemble(bytecode)
    }

    /// `Class.name:descriptor` for a Field/Method/InterfaceMethod reference.
    fn member_ref_text(&self, index: u16) -> Result<String> {
        match self.constant(index)? {
            Constant::Fieldref(c, nt) | Constant::Methodref(c, nt) | Constant::InterfaceMethodref(c, nt) => {
                let (n, d) = self.name_and_type(*nt)?;
                let owner = self.class_name(*c)?;
                // javap leaves off the class name for members of the class being disassembled
                if self.this_class_name().is_ok_and(|me| me == owner) {
                    Ok(format!("{}:{}", quote_name(n), d))
                } else if owner.starts_with('[') {
                    // array "classes" (e.g. the clone() of an array) are quoted
                    Ok(format!("\"{}\".{}:{}", owner, quote_name(n), d))
                } else {
                    Ok(format!("{}.{}:{}", owner, quote_name(n), d))
                }
            }
            _ => Err(fail(format!("constant {index} is not a member reference"))),
        }
    }

    /// Render a constant the way `javap -c` does in its trailing `// comment`.
    pub fn describe_constant(&self, index: u16) -> Result<String> {
        Ok(match self.constant(index)? {
            Constant::Utf8(s) => format!("Utf8 {s}"),
            Constant::Integer(v) => format!("int {v}"),
            Constant::Float(v) => format!("float {}f", java_float_to_string(*v)),
            Constant::Long(v) => format!("long {v}l"),
            Constant::Double(v) => format!("double {}d", java_double_to_string(*v)),
            Constant::Class(n) => {
                let name = self.utf8(*n)?;
                if name.starts_with('[') {
                    format!("class \"{name}\"")
                } else {
                    format!("class {name}")
                }
            }
            Constant::String(n) => format!("String {}", escape_string(self.utf8(*n)?)),
            Constant::Fieldref(..) => format!("Field {}", self.member_ref_text(index)?),
            Constant::Methodref(..) => format!("Method {}", self.member_ref_text(index)?),
            Constant::InterfaceMethodref(..) => format!("InterfaceMethod {}", self.member_ref_text(index)?),
            Constant::NameAndType(n, d) => format!("NameAndType {}:{}", self.utf8(*n)?, self.utf8(*d)?),
            Constant::MethodHandle(kind, r) => {
                format!(
                    "MethodHandle {}:{}",
                    method_handle_kind(*kind),
                    self.member_ref_text(*r)?
                )
            }
            Constant::MethodType(d) => format!("MethodType {}", self.utf8(*d)?),
            Constant::Dynamic(b, nt) => {
                let (n, d) = self.name_and_type(*nt)?;
                format!("Dynamic #{b}:{n}:{d}")
            }
            Constant::InvokeDynamic(b, nt) => {
                let (n, d) = self.name_and_type(*nt)?;
                format!("InvokeDynamic #{b}:{n}:{d}")
            }
            Constant::Module(n) => format!("Module {}", self.utf8(*n)?),
            Constant::Package(n) => format!("Package {}", self.utf8(*n)?),
            Constant::Unusable => return Err(fail("invalid constant")),
        })
    }

    /// Render one instruction as a `javap -c` line (without the trailing newline).
    pub fn format_instruction(&self, insn: &Instruction) -> Result<String> {
        // javap spells wide forms with a "_w" suffix (iinc_w, iload_w, ...)
        let suffix = if insn.wide { "_w" } else { "" };
        let mut text = format!("{:>4}: {}{}", insn.offset, insn.mnemonic, suffix);
        // javap pads the mnemonic to 13 columns and always leaves at least one space before the operand
        let pad = |s: &mut String, operand: String| {
            while s.len() < 4 + 2 + 13 {
                s.push(' ');
            }
            s.push(' ');
            s.push_str(&operand);
        };
        match &insn.operands {
            Operands::None => {}
            Operands::Immediate(v) => pad(&mut text, v.to_string()),
            Operands::Local(v) => pad(&mut text, v.to_string()),
            Operands::Pool(i) => {
                pad(&mut text, format!("#{i}"));
                while text.len() < 4 + 2 + 13 + 1 + 19 {
                    text.push(' ');
                }
                text.push_str(&format!("// {}", self.describe_constant(*i)?));
            }
            Operands::Branch(t) => pad(&mut text, t.to_string()),
            Operands::Iinc { local, delta } => pad(&mut text, format!("{local}, {delta}")),
            Operands::InvokeInterface { index, count } => {
                pad(&mut text, format!("#{index},  {count}"));
                while text.len() < 4 + 2 + 13 + 1 + 19 {
                    text.push(' ');
                }
                text.push_str(&format!("// {}", self.describe_constant(*index)?));
            }
            Operands::InvokeDynamic(i) => {
                pad(&mut text, format!("#{i},  0"));
                while text.len() < 4 + 2 + 13 + 1 + 19 {
                    text.push(' ');
                }
                text.push_str(&format!("// {}", self.describe_constant(*i)?));
            }
            Operands::NewArray(t) => pad(&mut text, newarray_type(*t).to_string()),
            Operands::MultiANewArray { index, dimensions } => {
                pad(&mut text, format!("#{index},  {dimensions}"));
                while text.len() < 4 + 2 + 13 + 1 + 19 {
                    text.push(' ');
                }
                text.push_str(&format!("// {}", self.describe_constant(*index)?));
            }
            Operands::TableSwitch {
                default,
                low,
                high,
                targets,
            } => {
                pad(&mut text, format!("{{ // {low} to {high}"));
                for (i, t) in targets.iter().enumerate() {
                    text.push_str(&format!("\n{:>16}: {}", *low as i64 + i as i64, t));
                }
                text.push_str(&format!("\n{:>16}: {}\n           }}", "default", default));
            }
            Operands::LookupSwitch { default, pairs } => {
                pad(&mut text, format!("{{ // {}", pairs.len()));
                for (k, t) in pairs {
                    text.push_str(&format!("\n{:>16}: {}", k, t));
                }
                text.push_str(&format!("\n{:>16}: {}\n           }}", "default", default));
            }
        }
        Ok(text)
    }

    /// A `javap -c -p`-style listing of every method's bytecode.
    pub fn disassembly(&self) -> Result<String> {
        let mut out = String::new();
        for method in &self.methods {
            out.push_str(&format!("  {}{}\n", method.name, method.descriptor));
            if let Some(code) = self.code(method)? {
                out.push_str("    Code:\n");
                for insn in disassemble(&code.bytecode)? {
                    out.push_str("      ");
                    out.push_str(&self.format_instruction(&insn)?);
                    out.push('\n');
                }
            }
        }
        Ok(out)
    }
}

fn method_handle_kind(kind: u8) -> &'static str {
    match kind {
        1 => "REF_getField",
        2 => "REF_getStatic",
        3 => "REF_putField",
        4 => "REF_putStatic",
        5 => "REF_invokeVirtual",
        6 => "REF_invokeStatic",
        7 => "REF_invokeSpecial",
        8 => "REF_newInvokeSpecial",
        9 => "REF_invokeInterface",
        _ => "REF_unknown",
    }
}

fn newarray_type(t: u8) -> &'static str {
    match t {
        4 => "boolean",
        5 => "char",
        6 => "float",
        7 => "double",
        8 => "byte",
        9 => "short",
        10 => "int",
        11 => "long",
        _ => "?",
    }
}

fn quote_name(name: &str) -> String {
    if name.contains('<') {
        format!("\"{name}\"")
    } else {
        name.to_string()
    }
}

fn escape_string(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '\'' => out.push_str("\\'"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Shortest-round-trip digits and decimal exponent from Rust's `{:e}` formatting.
fn shortest_digits(sci: &str) -> (String, i32) {
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci, "0"));
    let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    (digits, exp.parse().unwrap_or(0))
}

fn java_format(negative: bool, digits: &str, exp: i32) -> String {
    let sign = if negative { "-" } else { "" };
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    if (-3..7).contains(&exp) {
        if exp >= 0 {
            let int_len = exp as usize + 1;
            let mut int_part = String::new();
            let mut frac_part = String::new();
            for (i, ch) in digits.chars().enumerate() {
                if i < int_len {
                    int_part.push(ch)
                } else {
                    frac_part.push(ch)
                }
            }
            while int_part.len() < int_len {
                int_part.push('0');
            }
            if frac_part.is_empty() {
                frac_part.push('0');
            }
            format!("{sign}{int_part}.{frac_part}")
        } else {
            format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize))
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() { "0" } else { rest };
        format!("{sign}{first}.{rest}E{exp}")
    }
}

/// Digits and exponent for `Double.toString`/`Float.toString`. Java renders at least two significant
/// digits, so when the shortest round-trip form has a single digit it picks the closest two-digit
/// decimal that still round-trips (this is why `Double.MIN_VALUE` prints as `4.9E-324`, not `5.0E-324`).
fn java_digits<T: std::fmt::LowerExp + std::str::FromStr + PartialEq + Copy>(v: T) -> (String, i32) {
    let (digits, exp) = shortest_digits(&format!("{:e}", v));
    if digits.len() == 1 {
        let two = format!("{:.1e}", v);
        if two.parse::<T>().is_ok_and(|back| back == v) {
            return shortest_digits(&two);
        }
    }
    (digits, exp)
}

/// `Double.toString` as implemented by JDK 19 and later (shortest round-trip digits).
pub fn java_double_to_string(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if v == 0.0 {
        return if v.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let (digits, exp) = java_digits(v.abs());
    java_format(v < 0.0, &digits, exp)
}

/// `Float.toString` as implemented by JDK 19 and later.
pub fn java_float_to_string(v: f32) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if v == 0.0 {
        return if v.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let (digits, exp) = java_digits(v.abs());
    java_format(v < 0.0, &digits, exp)
}

/// Disassemble a method body.
pub fn disassemble(code: &[u8]) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let start = pc;
        let mut r = Reader { data: code, pos: pc };
        let mut opcode = r.u8()?;
        let mut wide = false;
        if opcode == 196 {
            wide = true;
            opcode = r.u8()?;
            if !matches!(opcode, 21..=25 | 54..=58 | 169 | 132) {
                return Err(fail(format!("invalid opcode {opcode} after wide at offset {start}")));
            }
        }
        let name = mnemonic(opcode).ok_or_else(|| fail(format!("unknown opcode {opcode} at offset {start}")))?;
        let rel = |off: i64| start as i64 + off;
        let operands = match opcode {
            16 => Operands::Immediate(r.u8()? as i8 as i32),
            17 => Operands::Immediate(r.u16()? as i16 as i32),
            18 => Operands::Pool(r.u8()? as u16),
            19 | 20 | 178..=184 | 187 | 189 | 192 | 193 => Operands::Pool(r.u16()?),
            21..=25 | 54..=58 | 169 => Operands::Local(if wide { r.u16()? } else { r.u8()? as u16 }),
            132 => {
                if wide {
                    Operands::Iinc {
                        local: r.u16()?,
                        delta: r.u16()? as i16 as i32,
                    }
                } else {
                    Operands::Iinc {
                        local: r.u8()? as u16,
                        delta: r.u8()? as i8 as i32,
                    }
                }
            }
            153..=168 | 198 | 199 => Operands::Branch(rel(r.u16()? as i16 as i64)),
            200 | 201 => Operands::Branch(rel(r.i32()? as i64)),
            170 => {
                while !r.pos.is_multiple_of(4) {
                    r.u8()?;
                }
                let default = rel(r.i32()? as i64);
                let low = r.i32()?;
                let high = r.i32()?;
                if high < low {
                    return Err(fail(format!("tableswitch with high < low at offset {start}")));
                }
                let count = (high as i64 - low as i64 + 1) as usize;
                if count > code.len() {
                    return Err(fail(format!("tableswitch too large at offset {start}")));
                }
                let mut targets = Vec::with_capacity(count);
                for _ in 0..count {
                    targets.push(rel(r.i32()? as i64));
                }
                Operands::TableSwitch {
                    default,
                    low,
                    high,
                    targets,
                }
            }
            171 => {
                while !r.pos.is_multiple_of(4) {
                    r.u8()?;
                }
                let default = rel(r.i32()? as i64);
                let n = r.i32()?;
                if n < 0 || n as usize > code.len() {
                    return Err(fail(format!("lookupswitch with bad pair count at offset {start}")));
                }
                let mut pairs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let key = r.i32()?;
                    pairs.push((key, rel(r.i32()? as i64)));
                }
                Operands::LookupSwitch { default, pairs }
            }
            185 => {
                let index = r.u16()?;
                let count = r.u8()?;
                r.u8()?;
                Operands::InvokeInterface { index, count }
            }
            186 => {
                let index = r.u16()?;
                r.u16()?;
                Operands::InvokeDynamic(index)
            }
            188 => Operands::NewArray(r.u8()?),
            197 => Operands::MultiANewArray {
                index: r.u16()?,
                dimensions: r.u8()?,
            },
            _ => Operands::None,
        };
        pc = r.pos;
        out.push(Instruction {
            offset: start as u32,
            opcode,
            wide,
            mnemonic: name,
            operands,
            length: (pc - start) as u32,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_table_has_expected_anchors() {
        assert_eq!(mnemonic(0), Some("nop"));
        assert_eq!(mnemonic(42), Some("aload_0"));
        assert_eq!(mnemonic(170), Some("tableswitch"));
        assert_eq!(mnemonic(177), Some("return"));
        assert_eq!(mnemonic(186), Some("invokedynamic"));
        assert_eq!(mnemonic(201), Some("jsr_w"));
        assert_eq!(mnemonic(202), None);
    }

    #[test]
    fn modified_utf8_handles_null_and_surrogates() {
        assert_eq!(decode_modified_utf8(&[0xC0, 0x80]).unwrap(), "\u{0}");
        // U+1F600 as a surrogate pair, each encoded as 3 bytes
        let bytes = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_modified_utf8(&bytes).unwrap(), "\u{1F600}");
        assert!(decode_modified_utf8(&[0xC3]).is_err());
    }

    #[test]
    fn java_number_formatting() {
        assert_eq!(java_double_to_string(1.0), "1.0");
        assert_eq!(java_double_to_string(0.5), "0.5");
        assert_eq!(java_double_to_string(1.0e7), "1.0E7");
        assert_eq!(java_double_to_string(9999999.0), "9999999.0");
        assert_eq!(java_double_to_string(0.001), "0.001");
        assert_eq!(java_double_to_string(0.0001), "1.0E-4");
        assert_eq!(java_double_to_string(-123.456), "-123.456");
        assert_eq!(java_double_to_string(f64::NAN), "NaN");
        assert_eq!(java_float_to_string(6.25), "6.25");
        assert_eq!(java_float_to_string(1.0e10), "1.0E10");
        assert_eq!(java_float_to_string(f32::from_bits(1)), "1.4E-45");
        assert_eq!(java_double_to_string(f64::from_bits(1)), "4.9E-324");
        assert_eq!(java_double_to_string(f64::MAX), "1.7976931348623157E308");
        assert_eq!(java_float_to_string(f32::MAX), "3.4028235E38");
    }

    #[test]
    fn disassembles_simple_method() {
        // aload_0; invokespecial #1; return
        let insns = disassemble(&[0x2a, 0xb7, 0x00, 0x01, 0xb1]).unwrap();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[1].operands, Operands::Pool(1));
        assert_eq!(insns[2].offset, 4);
    }

    #[test]
    fn wide_iinc_and_branch_targets() {
        // wide iinc 300, 1000 (6 bytes); then a goto at offset 6 with relative offset -6 -> target 0
        let code = [0xc4, 0x84, 0x01, 0x2c, 0x03, 0xe8, 0xa7, 0xff, 0xfa];
        let insns = disassemble(&code).unwrap();
        assert_eq!(
            insns[0].operands,
            Operands::Iinc {
                local: 300,
                delta: 1000
            }
        );
        assert!(insns[0].wide);
        assert_eq!(insns[1].offset, 6);
        assert_eq!(insns[1].operands, Operands::Branch(0));
    }

    #[test]
    fn rejects_truncated_and_bad_input() {
        assert!(disassemble(&[0xb7, 0x00]).is_err());
        assert!(disassemble(&[0xcb]).is_err());
        assert!(ClassFile::parse(&[0, 1, 2, 3]).is_err());
    }
}
