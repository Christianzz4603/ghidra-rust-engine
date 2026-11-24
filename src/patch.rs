//! Binary patching for ELF, PE, Mach-O and raw images.
//!
//! A [`PatchableImage`] keeps the original file bytes, translates *virtual addresses* to file
//! offsets through the image's segment table, applies edits, and records every edit in a journal
//! so it can be listed, undone or replayed.
//!
//! What it does **not** do: it is not an assembler. Only a small fixed set of encodings is
//! produced ([`PatchableImage::jump`], [`PatchableImage::call`], [`PatchableImage::return_const`],
//! NOP fill, conditional-branch inversion); arbitrary new code must be supplied as bytes. Edits
//! are made in place, so a patch can only touch bytes that exist in the file (not zero-filled
//! `.bss`-style tails). No code signature (Authenticode, Mach-O) is re-signed; the PE header
//! checksum can be refreshed with [`PatchableImage::fix_pe_checksum`]. Thumb code is not handled.

use std::path::Path;

use crate::error::{Error, Result};

fn fail(message: impl Into<String>) -> Error {
    Error::Parse(format!("patch: {}", message.into()))
}

/// Container format of the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormat {
    Elf,
    Pe,
    MachO,
    Raw,
}

/// Instruction set, as far as patch helpers care.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchArch {
    X86,
    X86_64,
    Arm,
    AArch64,
    Unknown,
}

impl PatchArch {
    fn is_x86(self) -> bool {
        matches!(self, PatchArch::X86 | PatchArch::X86_64)
    }
}

/// One mapped region: virtual `[vaddr, vaddr+vsize)` backed by `file_size` bytes at `file_offset`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub file_offset: u64,
    pub file_size: u64,
}

/// One journal entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchRecord {
    pub address: u64,
    pub file_offset: usize,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub note: String,
}

/// A loaded image plus its patch journal.
#[derive(Clone, Debug)]
pub struct PatchableImage {
    pub format: ImageFormat,
    pub arch: PatchArch,
    pub segments: Vec<Segment>,
    bytes: Vec<u8>,
    journal: Vec<PatchRecord>,
    /// Offset of the PE optional-header checksum field, when `format == Pe`.
    pe_checksum_offset: Option<usize>,
}

fn rd16(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| fail("truncated header"))
}
fn rd32(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| fail("truncated header"))
}
fn rd64(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| fail("truncated header"))
}

fn parse_elf(b: &[u8]) -> Result<(PatchArch, Vec<Segment>)> {
    let is64 = match b.get(4) {
        Some(1) => false,
        Some(2) => true,
        _ => return Err(fail("bad ELF class")),
    };
    if b.get(5) != Some(&1) {
        return Err(fail("only little-endian ELF is supported"));
    }
    let machine = rd16(b, 18)?;
    let arch = match machine {
        3 => PatchArch::X86,
        62 => PatchArch::X86_64,
        40 => PatchArch::Arm,
        183 => PatchArch::AArch64,
        _ => PatchArch::Unknown,
    };
    let (phoff, phentsize, phnum) = if is64 {
        (rd64(b, 32)? as usize, rd16(b, 54)? as usize, rd16(b, 56)? as usize)
    } else {
        (rd32(b, 28)? as usize, rd16(b, 42)? as usize, rd16(b, 44)? as usize)
    };
    let mut segments = Vec::new();
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if rd32(b, p)? != 1 {
            continue; // PT_LOAD only
        }
        let (offset, vaddr, filesz, memsz) = if is64 {
            (rd64(b, p + 8)?, rd64(b, p + 16)?, rd64(b, p + 32)?, rd64(b, p + 40)?)
        } else {
            (
                rd32(b, p + 4)? as u64,
                rd32(b, p + 8)? as u64,
                rd32(b, p + 16)? as u64,
                rd32(b, p + 20)? as u64,
            )
        };
        segments.push(Segment {
            name: format!("LOAD{}", segments.len()),
            vaddr,
            vsize: memsz,
            file_offset: offset,
            file_size: filesz,
        });
    }
    if segments.is_empty() {
        return Err(fail("ELF has no PT_LOAD segments"));
    }
    Ok((arch, segments))
}

fn parse_pe(b: &[u8]) -> Result<(PatchArch, Vec<Segment>, usize)> {
    let pe = rd32(b, 0x3C)? as usize;
    if b.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err(fail("bad PE signature"));
    }
    let machine = rd16(b, pe + 4)?;
    let arch = match machine {
        0x14c => PatchArch::X86,
        0x8664 => PatchArch::X86_64,
        0x1c0 | 0x1c4 => PatchArch::Arm,
        0xaa64 => PatchArch::AArch64,
        _ => PatchArch::Unknown,
    };
    let nsec = rd16(b, pe + 6)? as usize;
    let opt_size = rd16(b, pe + 20)? as usize;
    let opt = pe + 24;
    let base = match rd16(b, opt)? {
        0x10b => rd32(b, opt + 28)? as u64,
        0x20b => rd64(b, opt + 24)?,
        _ => return Err(fail("bad PE optional header magic")),
    };
    let checksum_offset = opt + 64;
    let size_of_headers = rd32(b, opt + 60)? as u64;
    let mut segments = vec![Segment {
        name: "headers".to_string(),
        vaddr: base,
        vsize: size_of_headers,
        file_offset: 0,
        file_size: size_of_headers.min(b.len() as u64),
    }];
    let table = opt + opt_size;
    for i in 0..nsec {
        let s = table + i * 40;
        let raw_name = b.get(s..s + 8).ok_or_else(|| fail("truncated section table"))?;
        let end = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
        let vsize = rd32(b, s + 8)? as u64;
        let va = rd32(b, s + 12)? as u64;
        let raw_size = rd32(b, s + 16)? as u64;
        let raw_ptr = rd32(b, s + 20)? as u64;
        segments.push(Segment {
            name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
            vaddr: base + va,
            vsize: vsize.max(raw_size),
            file_offset: raw_ptr,
            file_size: raw_size.min(vsize.max(raw_size)),
        });
    }
    Ok((arch, segments, checksum_offset))
}

fn parse_macho(b: &[u8]) -> Result<(PatchArch, Vec<Segment>)> {
    let magic = rd32(b, 0)?;
    let is64 = match magic {
        0xFEED_FACF => true,
        0xFEED_FACE => false,
        _ => {
            return Err(fail(
                "unsupported Mach-O magic (fat or big-endian binaries are not supported)",
            ));
        }
    };
    let cputype = rd32(b, 4)?;
    let arch = match cputype {
        7 => PatchArch::X86,
        0x0100_0007 => PatchArch::X86_64,
        12 => PatchArch::Arm,
        0x0100_000C => PatchArch::AArch64,
        _ => PatchArch::Unknown,
    };
    let ncmds = rd32(b, 16)? as usize;
    let mut p = if is64 { 32 } else { 28 };
    let mut segments = Vec::new();
    for _ in 0..ncmds {
        let cmd = rd32(b, p)?;
        let size = rd32(b, p + 4)? as usize;
        if size < 8 {
            return Err(fail("corrupt Mach-O load command"));
        }
        let name_bytes = b.get(p + 8..p + 24).ok_or_else(|| fail("truncated load command"))?;
        let end = name_bytes.iter().position(|&c| c == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        if cmd == 0x19 && is64 {
            segments.push(Segment {
                name,
                vaddr: rd64(b, p + 24)?,
                vsize: rd64(b, p + 32)?,
                file_offset: rd64(b, p + 40)?,
                file_size: rd64(b, p + 48)?,
            });
        } else if cmd == 1 && !is64 {
            segments.push(Segment {
                name,
                vaddr: rd32(b, p + 24)? as u64,
                vsize: rd32(b, p + 28)? as u64,
                file_offset: rd32(b, p + 32)? as u64,
                file_size: rd32(b, p + 36)? as u64,
            });
        }
        p += size;
    }
    if segments.is_empty() {
        return Err(fail("Mach-O has no segments"));
    }
    Ok((arch, segments))
}

impl PatchableImage {
    /// Detects the container format from magic bytes and builds the segment map.
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let (format, arch, segments, pe_checksum_offset) = if bytes.starts_with(b"\x7fELF") {
            let (arch, segments) = parse_elf(&bytes)?;
            (ImageFormat::Elf, arch, segments, None)
        } else if bytes.starts_with(b"MZ") {
            let (arch, segments, checksum) = parse_pe(&bytes)?;
            (ImageFormat::Pe, arch, segments, Some(checksum))
        } else if matches!(rd32(&bytes, 0), Ok(0xFEED_FACF) | Ok(0xFEED_FACE)) {
            let (arch, segments) = parse_macho(&bytes)?;
            (ImageFormat::MachO, arch, segments, None)
        } else {
            return Err(fail(
                "unrecognized format; use PatchableImage::raw for headerless images",
            ));
        };
        Ok(PatchableImage {
            format,
            arch,
            segments,
            bytes,
            journal: Vec::new(),
            pe_checksum_offset,
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| fail(format!("cannot read file: {e}")))?;
        Self::parse(bytes)
    }

    /// A headerless image loaded at `base`.
    pub fn raw(bytes: Vec<u8>, base: u64, arch: PatchArch) -> Self {
        let len = bytes.len() as u64;
        PatchableImage {
            format: ImageFormat::Raw,
            arch,
            segments: vec![Segment {
                name: "raw".to_string(),
                vaddr: base,
                vsize: len,
                file_offset: 0,
                file_size: len,
            }],
            bytes,
            journal: Vec::new(),
            pe_checksum_offset: None,
        }
    }

    /// File offset of `[address, address+length)`, if it lies wholly inside one segment's
    /// file-backed bytes.
    pub fn file_offset(&self, address: u64, length: usize) -> Result<usize> {
        let end = address
            .checked_add(length as u64)
            .ok_or_else(|| fail("address overflow"))?;
        for s in &self.segments {
            if address >= s.vaddr && end <= s.vaddr + s.file_size {
                let offset = s.file_offset + (address - s.vaddr);
                let offset = usize::try_from(offset).map_err(|_| fail("offset too large"))?;
                if offset + length > self.bytes.len() {
                    return Err(fail(format!("{address:#x} maps beyond the end of the file")));
                }
                return Ok(offset);
            }
            if address >= s.vaddr && address < s.vaddr + s.vsize && end > s.vaddr + s.file_size {
                return Err(fail(format!(
                    "{address:#x}+{length} reaches memory with no file backing in {}",
                    s.name
                )));
            }
        }
        Err(fail(format!("{address:#x} is not inside any mapped segment")))
    }

    pub fn read(&self, address: u64, length: usize) -> Result<&[u8]> {
        let offset = self.file_offset(address, length)?;
        Ok(&self.bytes[offset..offset + length])
    }

    /// Current file bytes, including every applied patch.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn journal(&self) -> &[PatchRecord] {
        &self.journal
    }

    /// Overwrites bytes at a virtual address and journals the change.
    pub fn write(&mut self, address: u64, data: &[u8], note: &str) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let offset = self.file_offset(address, data.len())?;
        let original = self.bytes[offset..offset + data.len()].to_vec();
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        self.journal.push(PatchRecord {
            address,
            file_offset: offset,
            original,
            patched: data.to_vec(),
            note: note.to_string(),
        });
        Ok(())
    }

    /// Fills `length` bytes with no-ops for the image's architecture.
    pub fn nop(&mut self, address: u64, length: usize) -> Result<()> {
        let fill = match self.arch {
            PatchArch::X86 | PatchArch::X86_64 => vec![0x90; length],
            PatchArch::AArch64 => {
                if !length.is_multiple_of(4) {
                    return Err(fail("AArch64 NOP fill needs a multiple of 4 bytes"));
                }
                [0x1F, 0x20, 0x03, 0xD5].repeat(length / 4)
            }
            PatchArch::Arm => {
                if !length.is_multiple_of(4) {
                    return Err(fail(
                        "ARM NOP fill needs a multiple of 4 bytes (Thumb is not supported)",
                    ));
                }
                [0x00, 0xF0, 0x20, 0xE3].repeat(length / 4)
            }
            PatchArch::Unknown => return Err(fail("unknown architecture; write NOP bytes explicitly")),
        };
        self.write(address, &fill, &format!("nop x{length}"))
    }

    /// Flips a conditional branch to its opposite condition (`jz` <-> `jnz`, `b.eq` <-> `b.ne`,
    /// `cbz` <-> `cbnz`, `tbz` <-> `tbnz`).
    pub fn invert_branch(&mut self, address: u64) -> Result<()> {
        if self.arch.is_x86() {
            let first = self.read(address, 1)?[0];
            if (0x70..=0x7F).contains(&first) {
                return self.write(address, &[first ^ 1], "invert short jcc");
            }
            if first == 0x0F {
                let second = self.read(address + 1, 1)?[0];
                if (0x80..=0x8F).contains(&second) {
                    return self.write(address + 1, &[second ^ 1], "invert near jcc");
                }
            }
            return Err(fail(format!("{address:#x} is not a conditional jump")));
        }
        if self.arch == PatchArch::AArch64 {
            let word = u32::from_le_bytes(self.read(address, 4)?.try_into().unwrap());
            let new = if word & 0xFF00_0010 == 0x5400_0000 {
                word ^ 1 // B.cond: flip the low condition bit
            } else if matches!(word & 0x7F00_0000, 0x3400_0000 | 0x3600_0000) {
                word ^ (1 << 24) // CBZ/CBNZ, TBZ/TBNZ
            } else {
                return Err(fail(format!(
                    "{address:#x} is not a recognised AArch64 conditional branch"
                )));
            };
            return self.write(address, &new.to_le_bytes(), "invert conditional branch");
        }
        Err(fail("branch inversion is not implemented for this architecture"))
    }

    fn rel32(from: u64, length: u64, to: u64) -> Result<[u8; 4]> {
        let delta = to.wrapping_sub(from.wrapping_add(length)) as i64;
        i32::try_from(delta)
            .map(|d| d.to_le_bytes())
            .map_err(|_| fail("branch target out of rel32 range"))
    }

    /// Writes an unconditional jump to `target`, using `EB rel8` when it fits, else `E9 rel32`
    /// (x86), or `B imm26` (AArch64).
    pub fn jump(&mut self, address: u64, target: u64) -> Result<()> {
        if self.arch.is_x86() {
            let short = target.wrapping_sub(address.wrapping_add(2)) as i64;
            if let Ok(d) = i8::try_from(short) {
                return self.write(address, &[0xEB, d as u8], &format!("jmp {target:#x}"));
            }
            let d = Self::rel32(address, 5, target)?;
            return self.write(address, &[0xE9, d[0], d[1], d[2], d[3]], &format!("jmp {target:#x}"));
        }
        if self.arch == PatchArch::AArch64 {
            let word = Self::aarch64_branch(address, target, 0x1400_0000)?;
            return self.write(address, &word.to_le_bytes(), &format!("b {target:#x}"));
        }
        Err(fail("jump encoding is not implemented for this architecture"))
    }

    /// Writes a call to `target` (`E8 rel32` on x86, `BL` on AArch64).
    pub fn call(&mut self, address: u64, target: u64) -> Result<()> {
        if self.arch.is_x86() {
            let d = Self::rel32(address, 5, target)?;
            return self.write(address, &[0xE8, d[0], d[1], d[2], d[3]], &format!("call {target:#x}"));
        }
        if self.arch == PatchArch::AArch64 {
            let word = Self::aarch64_branch(address, target, 0x9400_0000)?;
            return self.write(address, &word.to_le_bytes(), &format!("bl {target:#x}"));
        }
        Err(fail("call encoding is not implemented for this architecture"))
    }

    fn aarch64_branch(from: u64, to: u64, opcode: u32) -> Result<u32> {
        let delta = to.wrapping_sub(from) as i64;
        if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
            return Err(fail("branch target out of range or misaligned"));
        }
        Ok(opcode | (((delta >> 2) as u32) & 0x03FF_FFFF))
    }

    /// Replaces the start of a function with code that returns `value` immediately.
    /// x86: `mov eax, imm32; ret` (6 bytes). AArch64: `movz/movk w0; ret` (8-12 bytes).
    pub fn return_const(&mut self, address: u64, value: u32) -> Result<()> {
        let code: Vec<u8> = if self.arch.is_x86() {
            let v = value.to_le_bytes();
            vec![0xB8, v[0], v[1], v[2], v[3], 0xC3]
        } else if self.arch == PatchArch::AArch64 {
            let mut words = vec![0x5280_0000 | ((value & 0xFFFF) << 5)]; // movz w0, #lo
            if value >> 16 != 0 {
                words.push(0x72A0_0000 | ((value >> 16) << 5)); // movk w0, #hi, lsl 16
            }
            words.push(0xD65F_03C0); // ret
            words.iter().flat_map(|w| w.to_le_bytes()).collect()
        } else {
            return Err(fail("return_const is not implemented for this architecture"));
        };
        self.write(address, &code, &format!("return {value:#x}"))
    }

    /// Reverts the most recent patch. Returns `false` if the journal is empty.
    pub fn undo(&mut self) -> bool {
        match self.journal.pop() {
            Some(r) => {
                self.bytes[r.file_offset..r.file_offset + r.original.len()].copy_from_slice(&r.original);
                true
            }
            None => false,
        }
    }

    /// Reverts every patch.
    pub fn revert_all(&mut self) {
        while self.undo() {}
    }

    /// Recomputes the PE optional-header checksum (no-op for other formats).
    pub fn fix_pe_checksum(&mut self) {
        let Some(at) = self.pe_checksum_offset else {
            return;
        };
        self.bytes[at..at + 4].fill(0);
        let mut sum: u64 = 0;
        for chunk in self.bytes.chunks(2) {
            let w = if chunk.len() == 2 {
                u16::from_le_bytes([chunk[0], chunk[1]]) as u64
            } else {
                chunk[0] as u64
            };
            sum += w;
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum = (sum & 0xFFFF) + (sum >> 16);
        let checksum = (sum as u32 & 0xFFFF).wrapping_add(self.bytes.len() as u32);
        self.bytes[at..at + 4].copy_from_slice(&checksum.to_le_bytes());
    }

    /// Writes the patched image to `path`.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        std::fs::write(path.as_ref(), &self.bytes).map_err(|e| fail(format!("cannot write file: {e}")))
    }

    /// Human-readable list of patches.
    pub fn report(&self) -> String {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ");
        let mut out = String::new();
        for r in &self.journal {
            out.push_str(&format!(
                "{:#x} (file +{:#x}): {} -> {}  ; {}\n",
                r.address,
                r.file_offset,
                hex(&r.original),
                hex(&r.patched),
                r.note
            ));
        }
        out
    }

    /// Applies a patch script, one command per line (`#` starts a comment):
    /// `ADDR bytes 90 90`, `ADDR nop N`, `ADDR invert`, `ADDR jmp TARGET`, `ADDR call TARGET`,
    /// `ADDR return VALUE`. Numbers are decimal or `0x` hex. Stops at the first error and reports
    /// the line; commands before it stay applied (use [`PatchableImage::undo`] to roll back).
    pub fn apply_script(&mut self, script: &str) -> Result<usize> {
        fn num(token: &str) -> Result<u64> {
            let parsed = match token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16),
                None => token.parse::<u64>(),
            };
            parsed.map_err(|_| fail(format!("bad number `{token}`")))
        }
        let mut applied = 0;
        for (index, raw) in script.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let at = |e: Error| fail(format!("line {}: {e}", index + 1));
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(fail(format!("line {}: expected `ADDR command ...`", index + 1)));
            }
            let address = num(parts[0]).map_err(at)?;
            let at = |e: Error| fail(format!("line {}: {e}", index + 1));
            let arg = |i: usize| -> Result<u64> {
                parts
                    .get(i)
                    .ok_or_else(|| fail("missing argument"))
                    .and_then(|t| num(t))
            };
            match parts[1] {
                "bytes" => {
                    let data: Result<Vec<u8>> = parts[2..]
                        .iter()
                        .map(|t| u8::from_str_radix(t, 16).map_err(|_| fail(format!("bad hex byte `{t}`"))))
                        .collect();
                    self.write(address, &data.map_err(at)?, "bytes").map_err(at)?;
                }
                "nop" => {
                    let n = arg(2).map_err(at)? as usize;
                    self.nop(address, n).map_err(at)?;
                }
                "invert" => self.invert_branch(address).map_err(at)?,
                "jmp" => {
                    let t = arg(2).map_err(at)?;
                    self.jump(address, t).map_err(at)?;
                }
                "call" => {
                    let t = arg(2).map_err(at)?;
                    self.call(address, t).map_err(at)?;
                }
                "return" => {
                    let v = arg(2).map_err(at)?;
                    self.return_const(address, v as u32).map_err(at)?;
                }
                other => return Err(fail(format!("line {}: unknown command `{other}`", index + 1))),
            }
            applied += 1;
        }
        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(b: &mut [u8], o: usize, v: u16) {
        b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// ELF64 x86-64: one PT_LOAD mapping file offset 0x100 at 0x401000, 0x20 file bytes, 0x40 memory.
    fn elf() -> Vec<u8> {
        let mut b = vec![0u8; 0x120];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        put16(&mut b, 18, 62);
        put64(&mut b, 32, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, 1);
        let p = 64;
        put32(&mut b, p, 1);
        put64(&mut b, p + 8, 0x100);
        put64(&mut b, p + 16, 0x401000);
        put64(&mut b, p + 32, 0x20);
        put64(&mut b, p + 40, 0x40);
        b[0x100..0x106].copy_from_slice(&[0x74, 0x05, 0x90, 0x90, 0x90, 0xC3]);
        b
    }

    #[test]
    fn elf_maps_addresses_and_patches() {
        let mut img = PatchableImage::parse(elf()).unwrap();
        assert_eq!((img.format, img.arch), (ImageFormat::Elf, PatchArch::X86_64));
        assert_eq!(img.file_offset(0x401000, 1).unwrap(), 0x100);
        assert_eq!(img.read(0x401005, 1).unwrap(), &[0xC3]);
        img.invert_branch(0x401000).unwrap();
        assert_eq!(img.bytes()[0x100], 0x75);
        img.nop(0x401002, 3).unwrap();
        img.return_const(0x401000, 7).unwrap();
        assert_eq!(&img.bytes()[0x100..0x106], &[0xB8, 7, 0, 0, 0, 0xC3]);
        assert_eq!(img.journal().len(), 3);
        assert!(img.report().contains("return 0x7"));
        img.revert_all();
        assert_eq!(img.bytes(), &elf()[..], "revert restores the original bytes exactly");
        assert!(!img.undo());
    }

    #[test]
    fn rejects_bss_and_unmapped_addresses() {
        let mut img = PatchableImage::parse(elf()).unwrap();
        assert!(
            img.write(0x401030, &[1], "x").is_err(),
            "memory beyond file_size has no bytes"
        );
        assert!(
            img.write(0x401018, &[0; 16], "x").is_err(),
            "range crossing into unbacked memory"
        );
        assert!(img.write(0x500000, &[1], "x").is_err());
        assert!(img.journal().is_empty());
    }

    #[test]
    fn jump_and_call_encoding() {
        let mut img = PatchableImage::parse(elf()).unwrap();
        img.jump(0x401000, 0x401010).unwrap();
        assert_eq!(&img.bytes()[0x100..0x102], &[0xEB, 0x0E]);
        img.undo();
        img.call(0x401000, 0x401010).unwrap();
        assert_eq!(&img.bytes()[0x100..0x105], &[0xE8, 0x0B, 0, 0, 0]);
    }

    #[test]
    fn script_applies_and_reports_line_numbers() {
        let mut img = PatchableImage::parse(elf()).unwrap();
        let n = img
            .apply_script("# comment\n0x401000 invert\n0x401002 bytes CC CC\n0x401004 nop 1\n")
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(&img.bytes()[0x100..0x105], &[0x75, 0x05, 0xCC, 0xCC, 0x90]);
        let err = img.apply_script("0x401000 bogus\n").unwrap_err().to_string();
        assert!(err.contains("line 1"), "{err}");
        let err = img.apply_script("0x401002 invert\n").unwrap_err().to_string();
        assert!(err.contains("not a conditional jump"), "{err}");
    }

    #[test]
    fn aarch64_helpers() {
        let mut bytes = vec![0u8; 16];
        bytes[..4].copy_from_slice(&0x5400_0040u32.to_le_bytes()); // b.eq +8
        let mut img = PatchableImage::raw(bytes, 0x1000, PatchArch::AArch64);
        img.invert_branch(0x1000).unwrap();
        assert_eq!(u32::from_le_bytes(img.bytes()[..4].try_into().unwrap()), 0x5400_0041);
        img.nop(0x1004, 4).unwrap();
        assert_eq!(&img.bytes()[4..8], &[0x1F, 0x20, 0x03, 0xD5]);
        img.jump(0x1000, 0x1010).unwrap();
        assert_eq!(u32::from_le_bytes(img.bytes()[..4].try_into().unwrap()), 0x1400_0004);
        img.return_const(0x1000, 5).unwrap();
        assert_eq!(u32::from_le_bytes(img.bytes()[..4].try_into().unwrap()), 0x5280_00A0);
        assert_eq!(u32::from_le_bytes(img.bytes()[4..8].try_into().unwrap()), 0xD65F_03C0);
        assert!(img.nop(0x1000, 3).is_err());
    }

    #[test]
    fn pe_sections_and_checksum() {
        let mut b = vec![0u8; 0x400];
        b[..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3C, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut b, 0x84, 0x8664);
        put16(&mut b, 0x86, 1);
        put16(&mut b, 0x94, 0xF0);
        let opt = 0x98;
        put16(&mut b, opt, 0x20b);
        put64(&mut b, opt + 24, 0x1_4000_0000);
        put32(&mut b, opt + 60, 0x200);
        let s = opt + 0xF0;
        b[s..s + 5].copy_from_slice(b".text");
        put32(&mut b, s + 8, 0x100);
        put32(&mut b, s + 12, 0x1000);
        put32(&mut b, s + 16, 0x200);
        put32(&mut b, s + 20, 0x200);
        b[0x200] = 0x74;
        let mut img = PatchableImage::parse(b).unwrap();
        assert_eq!((img.format, img.arch), (ImageFormat::Pe, PatchArch::X86_64));
        assert_eq!(img.file_offset(0x1_4000_1000, 1).unwrap(), 0x200);
        img.invert_branch(0x1_4000_1000).unwrap();
        assert_eq!(img.bytes()[0x200], 0x75);
        img.fix_pe_checksum();
        let stored = u32::from_le_bytes(img.bytes()[opt + 64..opt + 68].try_into().unwrap());
        assert_ne!(stored, 0);
        let before = stored;
        img.fix_pe_checksum();
        let again = u32::from_le_bytes(img.bytes()[opt + 64..opt + 68].try_into().unwrap());
        assert_eq!(before, again, "checksum is stable when recomputed");
    }

    #[test]
    fn macho64_segments() {
        let mut b = vec![0u8; 0x200];
        put32(&mut b, 0, 0xFEED_FACF);
        put32(&mut b, 4, 0x0100_000C);
        put32(&mut b, 16, 1);
        put32(&mut b, 32, 0x19);
        put32(&mut b, 36, 72);
        b[40..46].copy_from_slice(b"__TEXT");
        put64(&mut b, 56, 0x1_0000_0000);
        put64(&mut b, 64, 0x1000);
        put64(&mut b, 72, 0x100);
        put64(&mut b, 80, 0x100);
        let img = PatchableImage::parse(b).unwrap();
        assert_eq!((img.format, img.arch), (ImageFormat::MachO, PatchArch::AArch64));
        assert_eq!(img.file_offset(0x1_0000_0010, 4).unwrap(), 0x110);
        assert_eq!(img.segments[0].name, "__TEXT");
    }

    #[test]
    fn unknown_format_is_rejected() {
        assert!(PatchableImage::parse(vec![1, 2, 3, 4, 5, 6, 7, 8]).is_err());
    }
}
