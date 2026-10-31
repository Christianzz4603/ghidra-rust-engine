use std::io::{Cursor, Read};
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexMethod {
    pub index: u32,
    pub name: String,
    pub class_descriptor: String,
    pub return_type: String,
    pub parameters: Vec<String>,
    pub access_flags: u32,
    pub code_offset: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexClass {
    pub descriptor: String,
    pub access_flags: u32,
    pub superclass: Option<String>,
    pub source_file: Option<String>,
    pub methods: Vec<DexMethod>,
}

#[derive(Clone, Debug)]
pub struct DexFile {
    bytes: Vec<u8>,
    strings: Vec<String>,
    types: Vec<String>,
    methods: Vec<DexMethod>,
    classes: Vec<DexClass>,
    version: String,
}

#[derive(Clone, Debug)]
pub struct Apk {
    pub dex_files: Vec<DexFile>,
    pub entries: Vec<String>,
}

fn fail(message: impl Into<String>) -> Error {
    Error::Parse(format!("DEX: {}", message.into()))
}
fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    let s = b.get(o..o + 2).ok_or_else(|| fail("truncated u16"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    let s = b.get(o..o + 4).ok_or_else(|| fail("truncated u32"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn table(b: &[u8], count_off: usize, data_off: usize, width: usize) -> Result<Vec<usize>> {
    let count = u32_at(b, count_off)? as usize;
    let off = u32_at(b, data_off)? as usize;
    let end = off
        .checked_add(count.checked_mul(width).ok_or_else(|| fail("table overflow"))?)
        .ok_or_else(|| fail("table overflow"))?;
    if end > b.len() {
        return Err(fail("table outside file"));
    }
    Ok((0..count).map(|i| off + i * width).collect())
}
fn uleb(b: &[u8], p: &mut usize) -> Result<u32> {
    let mut out = 0u32;
    for shift in (0..35).step_by(7) {
        let x = *b.get(*p).ok_or_else(|| fail("truncated ULEB128"))?;
        *p += 1;
        out |= ((x & 0x7f) as u32)
            .checked_shl(shift)
            .ok_or_else(|| fail("ULEB128 overflow"))?;
        if x & 0x80 == 0 {
            return Ok(out);
        }
    }
    Err(fail("invalid ULEB128"))
}
fn access(flags: u32) -> String {
    let mut v = Vec::new();
    for (bit, name) in [
        (1, "public"),
        (2, "private"),
        (4, "protected"),
        (8, "static"),
        (16, "final"),
        (32, "synchronized"),
        (64, "bridge"),
        (128, "varargs"),
        (256, "native"),
        (512, "interface"),
        (1024, "abstract"),
        (2048, "strictfp"),
        (4096, "synthetic"),
        (8192, "annotation"),
        (16384, "enum"),
        (65536, "constructor"),
        (131072, "declared-synchronized"),
    ] {
        if flags & bit != 0 {
            v.push(name)
        }
    }
    v.join(" ")
}
impl DexFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let bytes =
            std::fs::read(path.as_ref()).map_err(|e| fail(format!("cannot read {}: {e}", path.as_ref().display())))?;
        Self::parse(bytes)
    }
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < 112 || !bytes.starts_with(b"dex\n") || bytes.get(7) != Some(&0) {
            return Err(fail("invalid DEX magic or truncated header"));
        }
        let version = String::from_utf8_lossy(&bytes[4..7]).to_string();
        let declared = u32_at(&bytes, 32)? as usize;
        if declared > bytes.len() || declared < 112 {
            return Err(fail("invalid declared file size"));
        }
        let string_ids = table(&bytes, 56, 60, 4)?;
        let type_ids = table(&bytes, 64, 68, 4)?;
        let proto_ids = table(&bytes, 72, 76, 12)?;
        let method_ids = table(&bytes, 88, 92, 8)?;
        let class_defs = table(&bytes, 96, 100, 32)?;
        let mut strings = Vec::with_capacity(string_ids.len());
        for off in string_ids {
            let mut p = u32_at(&bytes, off)? as usize;
            let _utf16 = uleb(&bytes, &mut p)?;
            let tail = bytes.get(p..).ok_or_else(|| fail("bad string offset"))?;
            let n = tail
                .iter()
                .position(|x| *x == 0)
                .ok_or_else(|| fail("unterminated string"))?;
            strings.push(String::from_utf8_lossy(&tail[..n]).into_owned());
        }
        let mut types = Vec::with_capacity(type_ids.len());
        for off in type_ids {
            let i = u32_at(&bytes, off)? as usize;
            types.push(
                strings
                    .get(i)
                    .ok_or_else(|| fail("type string index out of range"))?
                    .clone(),
            );
        }
        let type_at = |i: u32| -> Result<String> {
            types
                .get(i as usize)
                .cloned()
                .ok_or_else(|| fail("type index out of range"))
        };
        let mut method_meta = Vec::with_capacity(method_ids.len());
        for off in method_ids {
            let class = type_at(u16_at(&bytes, off)? as u32)?;
            let proto = u16_at(&bytes, off + 2)? as usize;
            let name_idx = u32_at(&bytes, off + 4)? as usize;
            let po = *proto_ids
                .get(proto)
                .ok_or_else(|| fail("prototype index out of range"))?;
            let ret = type_at(u32_at(&bytes, po + 4)?)?;
            let params_off = u32_at(&bytes, po + 8)? as usize;
            let mut params = Vec::new();
            if params_off != 0 {
                let count = u32_at(&bytes, params_off)? as usize;
                if count > 65535 {
                    return Err(fail("too many prototype parameters"));
                }
                for i in 0..count {
                    params.push(type_at(u16_at(&bytes, params_off + 4 + i * 2)? as u32)?);
                }
            }
            let name = strings
                .get(name_idx)
                .ok_or_else(|| fail("method name index out of range"))?
                .clone();
            method_meta.push((class, name, ret, params));
        }
        let mut classes = Vec::new();
        let mut all_methods = Vec::new();
        for off in class_defs {
            let class_idx = u32_at(&bytes, off)?;
            let flags = u32_at(&bytes, off + 4)?;
            let super_idx = u32_at(&bytes, off + 8)?;
            let source_idx = u32_at(&bytes, off + 16)?;
            let class_data = u32_at(&bytes, off + 24)? as usize;
            let descriptor = type_at(class_idx)?;
            let superclass = if super_idx == u32::MAX {
                None
            } else {
                Some(type_at(super_idx)?)
            };
            let source_file = if source_idx == u32::MAX {
                None
            } else {
                strings.get(source_idx as usize).cloned()
            };
            let mut methods = Vec::new();
            if class_data != 0 {
                let mut p = class_data;
                let sf = uleb(&bytes, &mut p)? as usize;
                let inf = uleb(&bytes, &mut p)? as usize;
                let dm = uleb(&bytes, &mut p)? as usize;
                let vm = uleb(&bytes, &mut p)? as usize;
                for _ in 0..sf + inf {
                    let _ = uleb(&bytes, &mut p)?;
                    let _ = uleb(&bytes, &mut p)?;
                }
                for _ in 0..dm + vm {
                    let mut idx = 0u32;
                    for _ in 0..2 {
                        idx = idx
                            .checked_add(uleb(&bytes, &mut p)?)
                            .ok_or_else(|| fail("method index overflow"))?;
                    }
                    let af = uleb(&bytes, &mut p)?;
                    let code = uleb(&bytes, &mut p)?;
                    let (owner, name, ret, params) = method_meta
                        .get(idx as usize)
                        .ok_or_else(|| fail("class method index out of range"))?
                        .clone();
                    if owner != descriptor {
                        return Err(fail("method owner does not match class"));
                    }
                    let m = DexMethod {
                        index: idx,
                        name,
                        class_descriptor: owner,
                        return_type: ret,
                        parameters: params,
                        access_flags: af,
                        code_offset: code,
                    };
                    methods.push(m.clone());
                    all_methods.push(m);
                }
            }
            classes.push(DexClass {
                descriptor,
                access_flags: flags,
                superclass,
                source_file,
                methods,
            });
        }
        Ok(Self {
            bytes,
            strings,
            types,
            methods: all_methods,
            classes,
            version,
        })
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn strings(&self) -> &[String] {
        &self.strings
    }
    pub fn types(&self) -> &[String] {
        &self.types
    }
    pub fn classes(&self) -> &[DexClass] {
        &self.classes
    }
    pub fn methods(&self) -> &[DexMethod] {
        &self.methods
    }
    pub fn smali(&self) -> Result<String> {
        let mut out = String::new();
        for c in &self.classes {
            out.push_str(&format!(
                ".class {} {}\n.super {}\n",
                access(c.access_flags),
                c.descriptor,
                c.superclass.as_deref().unwrap_or("Ljava/lang/Object;")
            ));
            if let Some(s) = &c.source_file {
                out.push_str(&format!(".source {:?}\n", s));
            }
            for m in &c.methods {
                let params = m.parameters.iter().map(|x| x.as_str()).collect::<Vec<_>>().join("");
                out.push_str(&format!(
                    "\n.method {} {}({}){}\n",
                    access(m.access_flags),
                    m.name,
                    params,
                    m.return_type
                ));
                if m.code_offset != 0 {
                    out.push_str(&self.method_code_smali(m)?);
                }
                out.push_str(".end method\n");
            }
            out.push('\n');
        }
        Ok(out)
    }
    fn method_code_smali(&self, m: &DexMethod) -> Result<String> {
        let o = m.code_offset as usize;
        let regs = u16_at(&self.bytes, o)?;
        let ins = u16_at(&self.bytes, o + 2)?;
        let outs = u16_at(&self.bytes, o + 4)?;
        let size = u32_at(&self.bytes, o + 12)? as usize;
        let start = o.checked_add(16).ok_or_else(|| fail("code offset overflow"))?;
        let end = start
            .checked_add(size.checked_mul(2).ok_or_else(|| fail("instruction size overflow"))?)
            .ok_or_else(|| fail("instruction offset overflow"))?;
        if end > self.bytes.len() {
            return Err(fail("code item outside DEX"));
        }
        let mut out = format!("    .registers {regs}\n    .ins {ins}\n    .outs {outs}\n");
        let mut pc = 0usize;
        while pc < size {
            let w = u16_at(&self.bytes, start + pc * 2)?;
            let op = (w & 0xff) as u8;
            let a = (w >> 8) as u8;
            let (name, fmt, len) = opcode(op);
            let line = match fmt {
                0 => name.to_string(),
                1 => format!("{name} v{}", a),
                2 => format!("{name} v{}, v{}", a & 15, a >> 4),
                3 => format!(
                    "{name} v{}, #{}",
                    a as u8,
                    u16_at(&self.bytes, start + (pc + 1) * 2)? as i16
                ),
                4 => format!(
                    "{name} v{}, v{}, v{}",
                    a & 15,
                    a >> 4,
                    u16_at(&self.bytes, start + (pc + 1) * 2)? & 255
                ),
                _ => format!(".opcode 0x{op:02x} // unsupported format"),
            };
            out.push_str(&format!("    {pc:04x}: {line}\n"));
            if len == 0 || pc + len > size {
                return Err(fail("invalid instruction width"));
            }
            pc += len;
        }
        Ok(out)
    }
}
impl DexMethod {
    /// Java-style signature, for example `java.lang.String com.example.Foo.bar(int, byte[])`.
    ///
    /// The raw DEX descriptors stay available in `return_type`, `parameters` and
    /// `class_descriptor`; this only renders them in a readable form.
    pub fn java_signature(&self) -> String {
        let parameters: Vec<String> = self
            .parameters
            .iter()
            .map(|parameter| smali_type(parameter.as_str()))
            .collect();
        format!(
            "{} {}.{}({})",
            smali_type(&self.return_type),
            smali_type(&self.class_descriptor),
            self.name,
            parameters.join(", ")
        )
    }
}

fn smali_type(descriptor: &str) -> String {
    let dimensions = descriptor.bytes().take_while(|byte| *byte == b'[').count();
    let base = &descriptor[dimensions..];
    let name = match base {
        "V" => "void".to_string(),
        "Z" => "boolean".to_string(),
        "B" => "byte".to_string(),
        "S" => "short".to_string(),
        "C" => "char".to_string(),
        "I" => "int".to_string(),
        "J" => "long".to_string(),
        "F" => "float".to_string(),
        "D" => "double".to_string(),
        value if value.starts_with('L') && value.ends_with(';') => value[1..value.len() - 1].replace('/', "."),
        value => value.to_string(),
    };
    format!("{name}{}", "[]".repeat(dimensions))
}

fn opcode(op: u8) -> (&'static str, u8, usize) {
    match op {
        0x00 => ("nop", 0, 1),
        0x01 => ("move", 2, 1),
        0x02 => ("move/from16", 3, 2),
        0x03 => ("move/16", 3, 3),
        0x04 => ("move-wide", 2, 1),
        0x07 => ("move-object", 2, 1),
        0x0a => ("move-result", 1, 1),
        0x0b => ("move-result-wide", 1, 1),
        0x0c => ("move-result-object", 1, 1),
        0x0d => ("move-exception", 1, 1),
        0x0e => ("return-void", 0, 1),
        0x0f => ("return", 1, 1),
        0x10 => ("return-wide", 1, 1),
        0x11 => ("return-object", 1, 1),
        0x12 => ("const/4", 2, 1),
        0x13 => ("const/16", 3, 2),
        0x14 => ("const", 3, 3),
        0x1a => ("const-string", 3, 2),
        0x1b => ("const-string/jumbo", 3, 3),
        0x1c => ("const-class", 3, 2),
        0x1f => ("check-cast", 3, 2),
        0x22 => ("new-instance", 3, 2),
        0x23 => ("new-array", 4, 2),
        0x27 => ("throw", 1, 1),
        0x28 => ("goto", 1, 1),
        0x29 => ("goto/16", 3, 2),
        0x2a => ("goto/32", 3, 3),
        0x32..=0x37 => ("if", 4, 2),
        0x38..=0x3d => ("ifz", 1, 2),
        0x44..=0x51 => ("array-op", 4, 2),
        0x52..=0x5f => ("field-op", 4, 2),
        0x60..=0x6d => ("static-field-op", 3, 2),
        0x6e..=0x72 => ("invoke", 0, 3),
        0x74..=0x78 => ("invoke/range", 0, 3),
        0x7b..=0x8f => ("unary-op", 4, 1),
        0x90..=0xaf => ("binary-op", 4, 2),
        0xb0..=0xcf => ("binary-op/2addr", 4, 1),
        0xd0..=0xe2 => ("literal-op", 3, 2),
        _ => (".opcode", 0, 1),
    }
}
impl Apk {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| fail(format!("cannot read APK: {e}")))?;
        Self::parse(bytes)
    }
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let mut archive =
            zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| fail(format!("invalid APK/ZIP: {e}")))?;
        let mut entries = Vec::new();
        let mut dex_files = Vec::new();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| fail(format!("ZIP entry error: {e}")))?;
            let name = file.name().to_string();
            entries.push(name.clone());
            if name == "classes.dex"
                || name
                    .strip_prefix("classes")
                    .and_then(|x| x.strip_suffix(".dex"))
                    .is_some_and(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
            {
                let mut data = Vec::new();
                file.read_to_end(&mut data)
                    .map_err(|e| fail(format!("cannot read {name}: {e}")))?;
                dex_files.push(DexFile::parse(data)?);
            }
        }
        if dex_files.is_empty() {
            return Err(fail("APK contains no classes.dex files"));
        }
        Ok(Self { dex_files, entries })
    }
    pub fn smali(&self) -> Result<Vec<String>> {
        self.dex_files.iter().map(DexFile::smali).collect()
    }
    pub fn write_smali(&self, dir: impl AsRef<Path>) -> Result<()> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(|e| fail(format!("cannot create output directory: {e}")))?;
        for (i, dex) in self.dex_files.iter().enumerate() {
            let path = dir.join(format!(
                "classes{}.smali",
                if i == 0 { String::new() } else { (i + 1).to_string() }
            ));
            std::fs::write(path, dex.smali()?).map_err(|e| fail(format!("cannot write Smali: {e}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_conversion() {
        assert_eq!(smali_type("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(smali_type("[[I"), "int[][]");
        assert_eq!(smali_type("V"), "void");
    }

    #[test]
    fn java_signature_renders_readable_types() {
        let method = DexMethod {
            index: 0,
            name: "bar".to_string(),
            class_descriptor: "Lcom/example/Foo;".to_string(),
            return_type: "Ljava/lang/String;".to_string(),
            parameters: vec!["I".to_string(), "[B".to_string()],
            access_flags: 0,
            code_offset: 0,
        };
        assert_eq!(method.java_signature(), "java.lang.String com.example.Foo.bar(int, byte[])");
    }
    #[test]
    fn rejects_short_dex() {
        assert!(DexFile::parse(b"dex\n".to_vec()).is_err());
    }
    #[test]
    fn rejects_bad_magic() {
        let mut b = vec![0u8; 112];
        b[32..36].copy_from_slice(&112u32.to_le_bytes());
        assert!(DexFile::parse(b).is_err());
    }
}
