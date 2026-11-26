//! Function-start recovery for stripped binaries.
//!
//! Symbols are only one source of function entry points. This module collects starts from data
//! that compilers and linkers emit anyway, and from byte patterns, so a stripped executable or
//! library still yields a useful function list:
//!
//! * ELF `.eh_frame` (through `PT_GNU_EH_FRAME`): every FDE names a function start and its length;
//! * PE x64 `.pdata` (exception directory) and the export table;
//! * Mach-O `LC_FUNCTION_STARTS`;
//! * x86 prologue patterns, accepted only at plausible function boundaries (after padding or a
//!   `ret`, or 16-byte aligned);
//! * `call rel32` targets that look like prologues;
//! * pointers stored in non-executable segments (vtables, callback tables) that hit a known or
//!   prologue-shaped start.
//!
//! Structured sources are reliable. The pattern-based sources are heuristics: they can miss
//! functions and can report data or mid-function addresses, which is why every hint carries a
//! source and a confidence, and [`seeds`] only returns hints at or above [`MIN_SEED_CONFIDENCE`].

use std::collections::{BTreeMap, BTreeSet};

use crate::patch::{ImageFormat, PatchArch, PatchableImage};

/// Where a hint came from, roughly from least to most reliable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StartSource {
    DataPointer,
    CallTarget,
    Prologue,
    Export,
    EhFrame,
    Pdata,
    FunctionStarts,
}

/// One recovered function start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartHint {
    pub address: u64,
    pub source: StartSource,
    /// 0-100. Structured sources are 95+, pattern sources 40-85.
    pub confidence: u8,
    /// Function length in bytes when the source records it (`.eh_frame`, `.pdata`).
    pub size: Option<u64>,
}

/// Hints below this confidence are not used as discovery seeds.
pub const MIN_SEED_CONFIDENCE: u8 = 60;

const MAX_ENTRIES: usize = 1 << 22;

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }
    fn uleb(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= u64::from(byte & 0x7F) << shift;
            }
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
            if shift > 70 {
                return None;
            }
        }
    }
    fn sleb(&mut self) -> Option<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= i64::from(byte & 0x7F) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Some(result);
            }
            if shift > 70 {
                return None;
            }
        }
    }
}

/// Decodes a DWARF exception-header pointer (`DW_EH_PE_*`). `field_vaddr` is the virtual address
/// of the encoded field (for `pcrel`), `datarel_base` the base for `datarel`.
fn decode_pointer(cur: &mut Cursor, enc: u8, field_vaddr: u64, datarel_base: u64, ptr_size: usize) -> Option<u64> {
    if enc == 0xFF {
        return None;
    }
    let raw: u64 = match enc & 0x0F {
        0x00 => {
            if ptr_size == 8 {
                cur.u64()?
            } else {
                u64::from(cur.u32()?)
            }
        }
        0x01 => cur.uleb()?,
        0x02 => u64::from(cur.u16()?),
        0x03 => u64::from(cur.u32()?),
        0x04 => cur.u64()?,
        0x09 => cur.sleb()? as u64,
        0x0A => i64::from(cur.u16()? as i16) as u64,
        0x0B => i64::from(cur.u32()? as i32) as u64,
        0x0C => cur.u64()?,
        _ => return None,
    };
    let base = match enc & 0x70 {
        0x00 => 0,
        0x10 => field_vaddr,
        0x30 => datarel_base,
        _ => return None,
    };
    Some(raw.wrapping_add(base))
}

/// File-backed bytes from `vaddr` to the end of its segment, with the segment-relative base.
fn slice_at(image: &PatchableImage, vaddr: u64) -> Option<(&[u8], u64)> {
    let segment = image
        .segments
        .iter()
        .find(|s| vaddr >= s.vaddr && vaddr < s.vaddr + s.file_size)?;
    let start = usize::try_from(segment.file_offset + (vaddr - segment.vaddr)).ok()?;
    let end = usize::try_from(segment.file_offset + segment.file_size)
        .ok()?
        .min(image.bytes().len());
    Some((image.bytes().get(start..end)?, vaddr))
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}
fn le16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn structured(address: u64, source: StartSource, size: Option<u64>) -> StartHint {
    StartHint {
        address,
        source,
        confidence: 95,
        size,
    }
}

// ---------------------------------------------------------------- ELF .eh_frame

/// Frame-description-entry encoding of the CIE at `pos`, or `None` if the CIE is unusable.
fn cie_fde_encoding(data: &[u8], pos: usize, ptr_size: usize) -> Option<u8> {
    let mut c = Cursor { data, pos };
    let mut len = u64::from(c.u32()?);
    if len == 0xFFFF_FFFF {
        len = c.u64()?;
    }
    let end = c.pos.checked_add(usize::try_from(len).ok()?)?;
    if end > data.len() {
        return None;
    }
    if c.u32()? != 0 {
        return None; // not a CIE
    }
    let version = c.u8()?;
    let mut augmentation = Vec::new();
    loop {
        let b = c.u8()?;
        if b == 0 {
            break;
        }
        augmentation.push(b);
        if augmentation.len() > 16 {
            return None;
        }
    }
    if version >= 4 {
        c.u8()?; // address size
        c.u8()?; // segment size
    }
    c.uleb()?; // code alignment
    c.sleb()?; // data alignment
    if version == 1 {
        c.u8()?;
    } else {
        c.uleb()?;
    }
    let mut encoding = 0u8;
    if augmentation.first() == Some(&b'z') {
        c.uleb()?; // augmentation data length
        for &ch in &augmentation[1..] {
            match ch {
                b'R' => encoding = c.u8()?,
                b'L' => {
                    c.u8()?;
                }
                b'P' => {
                    let enc = c.u8()?;
                    decode_pointer(&mut c, enc & 0x0F, 0, 0, ptr_size)?;
                }
                b'S' | b'B' => {}
                _ => break,
            }
        }
    }
    Some(encoding)
}

fn walk_eh_frame(image: &PatchableImage, vaddr: u64, ptr_size: usize) -> Vec<StartHint> {
    let Some((data, base)) = slice_at(image, vaddr) else {
        return Vec::new();
    };
    let mut cies: BTreeMap<usize, Option<u8>> = BTreeMap::new();
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= data.len() && out.len() < MAX_ENTRIES {
        let mut c = Cursor { data, pos };
        let Some(raw_len) = c.u32() else { break };
        let mut len = u64::from(raw_len);
        if raw_len == 0 {
            break; // terminator
        }
        if raw_len == 0xFFFF_FFFF {
            match c.u64() {
                Some(l) => len = l,
                None => break,
            }
        }
        let Some(end) = usize::try_from(len).ok().and_then(|l| c.pos.checked_add(l)) else {
            break;
        };
        if end > data.len() {
            break;
        }
        let id_pos = c.pos;
        let Some(id) = c.u32() else { break };
        if id != 0 {
            let cie_pos = id_pos.checked_sub(id as usize);
            let encoding = cie_pos.and_then(|p| *cies.entry(p).or_insert_with(|| cie_fde_encoding(data, p, ptr_size)));
            if let Some(enc) = encoding {
                let field_vaddr = base + c.pos as u64;
                if let Some(start) = decode_pointer(&mut c, enc, field_vaddr, 0, ptr_size) {
                    let size = decode_pointer(&mut c, enc & 0x0F, 0, 0, ptr_size);
                    if start != 0 {
                        out.push(structured(start, StartSource::EhFrame, size));
                    }
                }
            }
        }
        pos = end;
    }
    out
}

fn eh_frame_starts(image: &PatchableImage) -> Vec<StartHint> {
    let b = image.bytes();
    let is64 = b.get(4) == Some(&2);
    let ptr_size = if is64 { 8 } else { 4 };
    let (phoff, phentsize, phnum) = if is64 {
        (
            le64(b, 32).unwrap_or(0) as usize,
            le16(b, 54).unwrap_or(0) as usize,
            le16(b, 56).unwrap_or(0) as usize,
        )
    } else {
        (
            le32(b, 28).unwrap_or(0) as usize,
            le16(b, 42).unwrap_or(0) as usize,
            le16(b, 44).unwrap_or(0) as usize,
        )
    };
    let mut hdr_vaddr = None;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if le32(b, p) == Some(0x6474_E550) {
            hdr_vaddr = if is64 {
                le64(b, p + 16)
            } else {
                le32(b, p + 8).map(u64::from)
            };
        }
    }
    let Some(hdr_vaddr) = hdr_vaddr else {
        return Vec::new();
    };
    let Some((hdr, _)) = slice_at(image, hdr_vaddr) else {
        return Vec::new();
    };
    let mut cur = Cursor { data: hdr, pos: 0 };
    let (Some(version), Some(eh_enc), Some(count_enc), Some(table_enc)) = (cur.u8(), cur.u8(), cur.u8(), cur.u8())
    else {
        return Vec::new();
    };
    if version != 1 {
        return Vec::new();
    }
    let at = hdr_vaddr + cur.pos as u64;
    let Some(eh_frame) = decode_pointer(&mut cur, eh_enc, at, hdr_vaddr, ptr_size) else {
        return Vec::new();
    };
    let walked = walk_eh_frame(image, eh_frame, ptr_size);
    if !walked.is_empty() {
        return walked;
    }
    // Fall back to the binary-search table, which has starts but no sizes.
    let at = hdr_vaddr + cur.pos as u64;
    let count = decode_pointer(&mut cur, count_enc, at, hdr_vaddr, ptr_size).unwrap_or(0);
    let mut out = Vec::new();
    if table_enc != 0xFF {
        for _ in 0..count.min(MAX_ENTRIES as u64) {
            let at = hdr_vaddr + cur.pos as u64;
            let Some(start) = decode_pointer(&mut cur, table_enc, at, hdr_vaddr, ptr_size) else {
                break;
            };
            let at = hdr_vaddr + cur.pos as u64;
            if decode_pointer(&mut cur, table_enc, at, hdr_vaddr, ptr_size).is_none() {
                break;
            }
            out.push(structured(start, StartSource::EhFrame, None));
        }
    }
    out
}

// ---------------------------------------------------------------- PE

fn pe_starts(image: &PatchableImage) -> Vec<StartHint> {
    let b = image.bytes();
    let mut out = Vec::new();
    let Some(pe) = le32(b, 0x3C).map(|v| v as usize) else {
        return out;
    };
    let opt = pe + 24;
    if le16(b, opt) != Some(0x20B) {
        return out; // PE32+ only: .pdata layout differs on PE32
    }
    let Some(base) = image.segments.first().map(|s| s.vaddr) else {
        return out;
    };
    let dir = |index: usize| -> Option<(u32, u32)> {
        let at = opt + 112 + index * 8;
        Some((le32(b, at)?, le32(b, at + 4)?))
    };
    // exports
    if let Some((rva, size)) = dir(0)
        && rva != 0
        && let Ok(read) = image.read(base + u64::from(rva), 40)
    {
        let count = le32(read, 20).unwrap_or(0) as usize;
        let table = le32(read, 28).unwrap_or(0);
        for i in 0..count.min(MAX_ENTRIES) {
            let Ok(entry) = image.read(base + u64::from(table) + (i * 4) as u64, 4) else {
                break;
            };
            let target = le32(entry, 0).unwrap_or(0);
            let forwarder = target >= rva && target < rva.saturating_add(size);
            if target != 0 && !forwarder && is_executable(image, base + u64::from(target)) {
                out.push(StartHint {
                    address: base + u64::from(target),
                    source: StartSource::Export,
                    confidence: 90,
                    size: None,
                });
            }
        }
    }
    // exception directory (x64): RUNTIME_FUNCTION { begin, end, unwind } * n
    if let Some((rva, size)) = dir(3)
        && rva != 0
    {
        let entries = (size / 12) as usize;
        for i in 0..entries.min(MAX_ENTRIES) {
            let Ok(entry) = image.read(base + u64::from(rva) + (i * 12) as u64, 12) else {
                break;
            };
            let (begin, end, unwind) = (
                le32(entry, 0).unwrap_or(0),
                le32(entry, 4).unwrap_or(0),
                le32(entry, 8).unwrap_or(0),
            );
            if begin == 0 || end <= begin {
                continue;
            }
            // chained unwind info (UNW_FLAG_CHAININFO) marks a continuation, not a function start
            let chained = unwind & 1 == 0
                && image
                    .read(base + u64::from(unwind), 1)
                    .map(|v| (v[0] >> 3) & 0x04 != 0)
                    .unwrap_or(false);
            if chained {
                continue;
            }
            out.push(structured(
                base + u64::from(begin),
                StartSource::Pdata,
                Some(u64::from(end - begin)),
            ));
        }
    }
    out
}

fn is_executable(image: &PatchableImage, address: u64) -> bool {
    image
        .segments
        .iter()
        .any(|s| s.executable && address >= s.vaddr && address < s.vaddr + s.vsize)
}

// ---------------------------------------------------------------- Mach-O

fn macho_starts(image: &PatchableImage) -> Vec<StartHint> {
    let b = image.bytes();
    let mut out = Vec::new();
    let is64 = le32(b, 0) == Some(0xFEED_FACF);
    let ncmds = le32(b, 16).unwrap_or(0) as usize;
    let mut p = if is64 { 32 } else { 28 };
    let text_base = image
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .map(|s| s.vaddr)
        .unwrap_or(0);
    for _ in 0..ncmds {
        let (Some(cmd), Some(size)) = (le32(b, p), le32(b, p + 4)) else {
            break;
        };
        if size < 8 {
            break;
        }
        if cmd == 0x26 {
            let (Some(off), Some(len)) = (le32(b, p + 8), le32(b, p + 12)) else {
                break;
            };
            let Some(data) = b.get(off as usize..(off as usize).saturating_add(len as usize)) else {
                break;
            };
            let mut c = Cursor { data, pos: 0 };
            let mut address = text_base;
            while let Some(delta) = c.uleb() {
                if delta == 0 {
                    break;
                }
                address = address.wrapping_add(delta);
                out.push(structured(address, StartSource::FunctionStarts, None));
                if out.len() >= MAX_ENTRIES {
                    break;
                }
            }
        }
        p += size as usize;
    }
    out
}

/// Starts from the container's own metadata (`.eh_frame`, `.pdata`, exports, `LC_FUNCTION_STARTS`).
pub fn structured_starts(image: &PatchableImage) -> Vec<StartHint> {
    let mut hints = match image.format {
        ImageFormat::Elf => eh_frame_starts(image),
        ImageFormat::Pe if image.arch == PatchArch::X86_64 => pe_starts(image),
        ImageFormat::MachO => macho_starts(image),
        _ => Vec::new(),
    };
    hints.retain(|h| is_executable(image, h.address));
    hints
}

// ---------------------------------------------------------------- x86 patterns

const STRONG_PROLOGUES: &[&[u8]] = &[
    &[0xF3, 0x0F, 0x1E, 0xFA],       // endbr64
    &[0x55, 0x48, 0x89, 0xE5],       // push rbp; mov rbp, rsp
    &[0x55, 0x89, 0xE5],             // push ebp; mov ebp, esp
    &[0x55, 0x8B, 0xEC],             // push ebp; mov ebp, esp
    &[0x48, 0x89, 0x5C, 0x24],       // mov [rsp+x], rbx  (MSVC x64)
    &[0x48, 0x89, 0x4C, 0x24],       // mov [rsp+x], rcx
    &[0x40, 0x53, 0x48, 0x83, 0xEC], // push rbx; sub rsp, x
];

const WEAK_PROLOGUES: &[&[u8]] = &[
    &[0x48, 0x83, 0xEC],       // sub rsp, imm8
    &[0x48, 0x81, 0xEC],       // sub rsp, imm32
    &[0x4C, 0x8B, 0xDC],       // mov r11, rsp
    &[0x41, 0x57],             // push r15
    &[0x41, 0x56],             // push r14
    &[0x41, 0x55],             // push r13
    &[0x41, 0x54],             // push r12
    &[0x53, 0x48, 0x83, 0xEC], // push rbx; sub rsp, x
];

/// Confidence that `data[at..]` starts a function, judged from its first bytes and what
/// precedes it. 0 means no match.
fn x86_start_confidence(data: &[u8], base: u64, at: usize) -> u8 {
    let rest = &data[at..];
    let strong = STRONG_PROLOGUES.iter().any(|p| rest.starts_with(p));
    let weak = !strong && WEAK_PROLOGUES.iter().any(|p| rest.starts_with(p));
    if !strong && !weak {
        return 0;
    }
    let boundary = at > 0 && matches!(data[at - 1], 0xCC | 0x90 | 0xC3);
    let aligned = (base + at as u64).is_multiple_of(16);
    match (strong, weak, boundary, aligned) {
        (true, _, true, _) => 85,
        (true, _, false, true) => 65,
        (_, true, true, true) => 55,
        (_, true, true, false) => 40,
        _ => 0,
    }
}

fn x86_prologues(data: &[u8], base: u64) -> Vec<StartHint> {
    (0..data.len())
        .filter_map(|at| {
            let confidence = x86_start_confidence(data, base, at);
            (confidence > 0).then_some(StartHint {
                address: base + at as u64,
                source: StartSource::Prologue,
                confidence,
                size: None,
            })
        })
        .collect()
}

/// `call rel32` targets inside the same buffer that also look like a function start.
fn x86_call_targets(data: &[u8], base: u64) -> Vec<StartHint> {
    let mut out = Vec::new();
    if data.len() < 5 {
        return out;
    }
    for i in 0..data.len() - 4 {
        if data[i] != 0xE8 {
            continue;
        }
        let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
        let target = (base + i as u64 + 5).wrapping_add(rel as i64 as u64);
        if target < base || target >= base + data.len() as u64 {
            continue;
        }
        if x86_start_confidence(data, base, (target - base) as usize) > 0 {
            out.push(StartHint {
                address: target,
                source: StartSource::CallTarget,
                confidence: 70,
                size: None,
            });
        }
    }
    out
}

fn is_x86(arch: PatchArch) -> bool {
    matches!(arch, PatchArch::X86 | PatchArch::X86_64)
}

/// Pointer-sized words in non-executable segments that land on an address in `known`.
fn data_pointer_targets(image: &PatchableImage, known: &BTreeSet<u64>) -> Vec<StartHint> {
    let step = if image.arch == PatchArch::X86 || image.arch == PatchArch::Arm {
        4
    } else {
        8
    };
    let mut out = Vec::new();
    for segment in image.segments.iter().filter(|s| !s.executable) {
        let (Ok(start), Ok(len)) = (usize::try_from(segment.file_offset), usize::try_from(segment.file_size)) else {
            continue;
        };
        let Some(data) = image
            .bytes()
            .get(start..start.saturating_add(len).min(image.bytes().len()))
        else {
            continue;
        };
        for chunk in data.chunks_exact(step) {
            let value = if step == 8 {
                u64::from_le_bytes(chunk.try_into().unwrap())
            } else {
                u64::from(u32::from_le_bytes(chunk.try_into().unwrap()))
            };
            if known.contains(&value) {
                out.push(StartHint {
                    address: value,
                    source: StartSource::DataPointer,
                    confidence: 75,
                    size: None,
                });
            }
        }
    }
    out
}

fn merge(into: &mut BTreeMap<u64, StartHint>, hints: impl IntoIterator<Item = StartHint>) {
    for hint in hints {
        into.entry(hint.address)
            .and_modify(|existing| {
                let size = existing.size.or(hint.size);
                if hint.confidence > existing.confidence
                    || (hint.confidence == existing.confidence && hint.source > existing.source)
                {
                    *existing = hint;
                }
                existing.size = existing.size.or(size);
            })
            .or_insert(hint);
    }
}

/// Every function-start hint found in `image`, sorted by address.
pub fn recover(image: &PatchableImage) -> Vec<StartHint> {
    let mut all: BTreeMap<u64, StartHint> = BTreeMap::new();
    merge(&mut all, structured_starts(image));
    if is_x86(image.arch) {
        for segment in image.segments.iter().filter(|s| s.executable) {
            let (Ok(start), Ok(len)) = (usize::try_from(segment.file_offset), usize::try_from(segment.file_size))
            else {
                continue;
            };
            let Some(data) = image
                .bytes()
                .get(start..start.saturating_add(len).min(image.bytes().len()))
            else {
                continue;
            };
            merge(&mut all, x86_prologues(data, segment.vaddr));
            merge(&mut all, x86_call_targets(data, segment.vaddr));
        }
    }
    let known: BTreeSet<u64> = all
        .values()
        .filter(|h| h.confidence >= MIN_SEED_CONFIDENCE)
        .map(|h| h.address)
        .collect();
    merge(&mut all, data_pointer_targets(image, &known));
    all.into_values().collect()
}

/// Addresses worth seeding function discovery with (confidence >= [`MIN_SEED_CONFIDENCE`]).
pub fn seeds(image: &PatchableImage) -> Vec<u64> {
    recover(image)
        .into_iter()
        .filter(|h| h.confidence >= MIN_SEED_CONFIDENCE)
        .map(|h| h.address)
        .collect()
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

    /// ELF64 with one RX PT_LOAD for the whole file at 0x400000 and a PT_GNU_EH_FRAME.
    /// Layout: .text at 0x100 (0x40 bytes), eh_frame_hdr at 0x140, eh_frame at 0x160.
    fn elf_with_eh_frame() -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        put16(&mut b, 18, 62);
        put64(&mut b, 32, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, 2);
        // PT_LOAD, flags R+X
        put32(&mut b, 64, 1);
        put32(&mut b, 68, 5);
        put64(&mut b, 72, 0);
        put64(&mut b, 80, 0x400000);
        put64(&mut b, 96, 0x200);
        put64(&mut b, 104, 0x200);
        // PT_GNU_EH_FRAME -> 0x400140
        let p = 64 + 56;
        put32(&mut b, p, 0x6474_E550);
        put32(&mut b, p + 4, 4);
        put64(&mut b, p + 8, 0x140);
        put64(&mut b, p + 16, 0x400140);
        put64(&mut b, p + 32, 0x20);
        // eh_frame_hdr: version 1, eh_frame_ptr pcrel|sdata4, count omit, table omit
        b[0x140] = 1;
        b[0x141] = 0x1B;
        b[0x142] = 0xFF;
        b[0x143] = 0xFF;
        // eh_frame_ptr: target 0x400160, field at 0x400144 => 0x1C
        put32(&mut b, 0x144, 0x1C);
        // eh_frame at 0x160: CIE then two FDEs then terminator
        let mut e = Vec::new();
        let cie_body: Vec<u8> = vec![
            0, 0, 0, 0, // CIE id
            1, // version
            b'z', b'R', 0,    // augmentation
            1,    // code align
            0x78, // data align (-8)
            16,   // return register
            1,    // augmentation length
            0x1B, // FDE encoding pcrel|sdata4
        ];
        e.extend_from_slice(&(cie_body.len() as u32).to_le_bytes());
        e.extend_from_slice(&cie_body);
        let cie_start = 0usize;
        for (func_vaddr, range) in [(0x400100u64, 0x10u32), (0x400110u64, 0x20u32)] {
            let fde_pos = e.len();
            let id = (fde_pos + 4 - cie_start) as u32;
            let field_vaddr = 0x400160 + fde_pos as u64 + 8;
            let rel = (func_vaddr as i64 - field_vaddr as i64) as i32;
            let mut body = Vec::new();
            body.extend_from_slice(&id.to_le_bytes());
            body.extend_from_slice(&rel.to_le_bytes());
            body.extend_from_slice(&range.to_le_bytes());
            body.push(0); // augmentation length
            while (body.len() + 4) % 8 != 0 {
                body.push(0);
            }
            e.extend_from_slice(&(body.len() as u32).to_le_bytes());
            e.extend_from_slice(&body);
        }
        e.extend_from_slice(&[0, 0, 0, 0]);
        b[0x160..0x160 + e.len()].copy_from_slice(&e);
        b
    }

    #[test]
    fn eh_frame_yields_starts_and_sizes() {
        let image = PatchableImage::parse(elf_with_eh_frame()).unwrap();
        let hints = structured_starts(&image);
        let got: Vec<(u64, Option<u64>)> = hints.iter().map(|h| (h.address, h.size)).collect();
        assert_eq!(got, vec![(0x400100, Some(0x10)), (0x400110, Some(0x20))]);
        assert!(
            hints
                .iter()
                .all(|h| h.source == StartSource::EhFrame && h.confidence >= 90)
        );
    }

    #[test]
    fn eh_frame_hdr_table_is_the_fallback() {
        let mut bytes = elf_with_eh_frame();
        // break the eh_frame so the walk finds nothing, then provide a table
        bytes[0x164] = 0xFF;
        bytes[0x142] = 0x03; // count: udata4
        bytes[0x143] = 0x3B; // table: datarel|sdata4
        put32(&mut bytes, 0x148, 2);
        // entries are (start - hdr_vaddr, fde_vaddr - hdr_vaddr)
        put32(&mut bytes, 0x14C, (0x400100i64 - 0x400140) as u32);
        put32(&mut bytes, 0x150, 0x20);
        put32(&mut bytes, 0x154, (0x400118i64 - 0x400140) as u32);
        put32(&mut bytes, 0x158, 0x20);
        let image = PatchableImage::parse(bytes).unwrap();
        let got: Vec<u64> = structured_starts(&image).iter().map(|h| h.address).collect();
        assert_eq!(got, vec![0x400100, 0x400118]);
    }

    #[test]
    fn x86_prologues_need_a_boundary() {
        // 0x1000: padding, then endbr64 (strong, after padding), then ret, then a bare
        // `sub rsp` that is not aligned or preceded by padding.
        let mut data = vec![0xCCu8; 16];
        data.extend_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5, 0xC3]);
        data.extend_from_slice(&[0x48, 0x83, 0xEC, 0x08]);
        let hints = x86_prologues(&data, 0x1000);
        let at = |a: u64| hints.iter().find(|h| h.address == a).map(|h| h.confidence);
        assert_eq!(at(0x1010), Some(85), "endbr64 after padding");
        assert_eq!(at(0x1014), None, "push rbp right after endbr64 is mid-function");
        assert!(
            at(0x1019).is_none_or(|c| c < MIN_SEED_CONFIDENCE),
            "unaligned sub rsp is not a seed"
        );
    }

    #[test]
    fn call_targets_need_prologue_shaped_destinations() {
        let mut data = vec![0x90u8; 0x40];
        data[0] = 0xE8; // call +0x1B -> 0x20
        data[1..5].copy_from_slice(&(0x1Bi32).to_le_bytes());
        data[5] = 0xE8; // call to 0x30 which is not prologue-shaped
        data[6..10].copy_from_slice(&(0x25i32).to_le_bytes());
        data[0x1F] = 0xCC;
        data[0x20..0x24].copy_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA]);
        let hints = x86_call_targets(&data, 0x1000);
        assert_eq!(hints.iter().map(|h| h.address).collect::<Vec<_>>(), vec![0x1020]);
    }

    #[test]
    fn pe_pdata_and_chained_entries() {
        let mut b = vec![0u8; 0x600];
        b[..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3C, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut b, 0x84, 0x8664);
        put16(&mut b, 0x86, 2);
        put16(&mut b, 0x94, 0xF0);
        let opt = 0x98;
        put16(&mut b, opt, 0x20B);
        put64(&mut b, opt + 24, 0x1_4000_0000);
        put32(&mut b, opt + 60, 0x200);
        // data directory 3 (exception): rva 0x2000, 3 entries
        put32(&mut b, opt + 112 + 3 * 8, 0x2000);
        put32(&mut b, opt + 112 + 3 * 8 + 4, 36);
        let s = opt + 0xF0;
        b[s..s + 5].copy_from_slice(b".text");
        put32(&mut b, s + 8, 0x100);
        put32(&mut b, s + 12, 0x1000);
        put32(&mut b, s + 16, 0x200);
        put32(&mut b, s + 20, 0x200);
        put32(&mut b, s + 36, 0x6000_0020);
        let s2 = s + 40;
        b[s2..s2 + 6].copy_from_slice(b".pdata");
        put32(&mut b, s2 + 8, 0x100);
        put32(&mut b, s2 + 12, 0x2000);
        put32(&mut b, s2 + 16, 0x100);
        put32(&mut b, s2 + 20, 0x400);
        put32(&mut b, s2 + 36, 0x4000_0040);
        // unwind infos live in .pdata too: rva 0x2080 (plain), 0x2090 (chained, flags=4)
        b[0x400 + 0x80] = 0x01;
        b[0x400 + 0x90] = 0x01 | (4 << 3);
        let entries = [
            (0x1000u32, 0x1040u32, 0x2080u32),
            (0x1040, 0x1080, 0x2080),
            (0x1020, 0x1030, 0x2090),
        ];
        for (i, (begin, end, unwind)) in entries.iter().enumerate() {
            put32(&mut b, 0x400 + i * 12, *begin);
            put32(&mut b, 0x400 + i * 12 + 4, *end);
            put32(&mut b, 0x400 + i * 12 + 8, *unwind);
        }
        let image = PatchableImage::parse(b).unwrap();
        let got: Vec<(u64, Option<u64>)> = structured_starts(&image).iter().map(|h| (h.address, h.size)).collect();
        assert_eq!(
            got,
            vec![(0x1_4000_1000, Some(0x40)), (0x1_4000_1040, Some(0x40))],
            "the chained entry is a continuation, not a function"
        );
    }

    #[test]
    fn macho_function_starts() {
        let mut b = vec![0u8; 0x300];
        put32(&mut b, 0, 0xFEED_FACF);
        put32(&mut b, 4, 0x0100_000C);
        put32(&mut b, 16, 2);
        // __TEXT (executable)
        put32(&mut b, 32, 0x19);
        put32(&mut b, 36, 72);
        b[40..46].copy_from_slice(b"__TEXT");
        put64(&mut b, 56, 0x1_0000_0000);
        put64(&mut b, 64, 0x1000);
        put64(&mut b, 72, 0);
        put64(&mut b, 80, 0x300);
        put32(&mut b, 92, 5);
        // LC_FUNCTION_STARTS at 104
        put32(&mut b, 104, 0x26);
        put32(&mut b, 108, 16);
        put32(&mut b, 112, 0x200);
        put32(&mut b, 116, 8);
        b[0x200..0x205].copy_from_slice(&[0x80, 0x08, 0x20, 0x10, 0x00]);
        let image = PatchableImage::parse(b).unwrap();
        let got: Vec<u64> = structured_starts(&image).iter().map(|h| h.address).collect();
        assert_eq!(
            got,
            vec![0x1_0000_0000 + 0x400, 0x1_0000_0000 + 0x420, 0x1_0000_0000 + 0x430]
        );
    }

    #[test]
    fn data_pointers_need_a_known_target() {
        let mut data = vec![0xCCu8; 16];
        data.extend_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA, 0xC3]);
        data.resize(0x40, 0xCC);
        let mut bytes = data.clone();
        // data segment follows in the same raw buffer? use two segments via a hand-built image
        bytes.extend_from_slice(&0x1010u64.to_le_bytes());
        bytes.extend_from_slice(&0x1020u64.to_le_bytes());
        let mut image = PatchableImage::raw(bytes, 0x1000, PatchArch::X86_64);
        image.segments[0].file_size = 0x40;
        image.segments[0].vsize = 0x40;
        image.segments.push(crate::patch::Segment {
            name: "data".into(),
            vaddr: 0x2000,
            vsize: 16,
            file_offset: 0x40,
            file_size: 16,
            executable: false,
        });
        let all = recover(&image);
        let pointer = all.iter().find(|h| h.address == 0x1010).unwrap();
        assert!(pointer.confidence >= 85, "prologue evidence outranks the pointer");
        assert!(
            all.iter().all(|h| h.address != 0x1020),
            "unknown pointer target is ignored"
        );
        assert!(seeds(&image).contains(&0x1010));
    }
}
