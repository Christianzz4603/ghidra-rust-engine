//! Byte-level inspection tools that work on a [`PatchableImage`]: pattern search with wildcards,
//! string extraction, entropy / packing hints, hex dumps, and image diffing that can be turned
//! into a patch script.
//!
//! All addresses are virtual addresses taken from the image's segment table. Only file-backed
//! bytes are searched; zero-filled memory (`.bss`) is not.

use crate::error::{Error, Result};
use crate::patch::PatchableImage;

fn fail(message: impl Into<String>) -> Error {
    Error::Parse(format!("binscan: {}", message.into()))
}

/// A byte pattern with optional wildcard bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    /// Parses `48 89 ?? 24` style text. `?` and `??` are wildcards; bytes are two hex digits.
    pub fn parse_hex(text: &str) -> Result<Pattern> {
        let mut bytes = Vec::new();
        for token in text.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(None);
            } else if token.len() == 2 {
                let value = u8::from_str_radix(token, 16).map_err(|_| fail(format!("bad hex byte `{token}`")))?;
                bytes.push(Some(value));
            } else {
                return Err(fail(format!("bad pattern token `{token}`")));
            }
        }
        if bytes.is_empty() {
            return Err(fail("empty pattern"));
        }
        if bytes.iter().all(Option::is_none) {
            return Err(fail("pattern is all wildcards"));
        }
        Ok(Pattern { bytes })
    }

    /// A literal byte string (no wildcards).
    pub fn literal(data: &[u8]) -> Pattern {
        Pattern {
            bytes: data.iter().map(|b| Some(*b)).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn matches_at(&self, haystack: &[u8], at: usize) -> bool {
        self.bytes
            .iter()
            .enumerate()
            .all(|(i, want)| want.is_none_or(|w| haystack[at + i] == w))
    }
}

/// Addresses where `pattern` occurs, in ascending order per segment. A match never spans two
/// segments. Stops after `limit` hits.
pub fn find_all(image: &PatchableImage, pattern: &Pattern, limit: usize) -> Vec<u64> {
    let mut hits = Vec::new();
    let anchor = pattern.bytes.iter().position(Option::is_some).unwrap_or(0);
    let anchor_byte = pattern.bytes[anchor];
    for segment in &image.segments {
        let Some(data) = segment_bytes(image, segment.file_offset, segment.file_size) else {
            continue;
        };
        if data.len() < pattern.len() {
            continue;
        }
        let last = data.len() - pattern.len();
        let mut at = 0;
        while at <= last {
            if let Some(b) = anchor_byte
                && data[at + anchor] != b
            {
                at += 1;
                continue;
            }
            if pattern.matches_at(data, at) {
                hits.push(segment.vaddr + at as u64);
                if hits.len() >= limit {
                    return hits;
                }
            }
            at += 1;
        }
    }
    hits
}

fn segment_bytes(image: &PatchableImage, offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    image.bytes().get(start..end.min(image.bytes().len()))
}

/// A string found in the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundString {
    pub address: u64,
    pub text: String,
    /// `true` for UTF-16LE, `false` for single-byte ASCII.
    pub wide: bool,
}

fn is_text_byte(b: u8) -> bool {
    (0x20..0x7F).contains(&b) || b == b'\t'
}

/// Extracts printable ASCII and UTF-16LE (ASCII range) strings of at least `min_len` characters.
pub fn extract_strings(image: &PatchableImage, min_len: usize) -> Vec<FoundString> {
    let min_len = min_len.max(1);
    let mut found = Vec::new();
    for segment in &image.segments {
        let Some(data) = segment_bytes(image, segment.file_offset, segment.file_size) else {
            continue;
        };
        // ASCII
        let mut i = 0;
        while i < data.len() {
            if is_text_byte(data[i]) {
                let start = i;
                while i < data.len() && is_text_byte(data[i]) {
                    i += 1;
                }
                if i - start >= min_len {
                    found.push(FoundString {
                        address: segment.vaddr + start as u64,
                        text: String::from_utf8_lossy(&data[start..i]).into_owned(),
                        wide: false,
                    });
                }
            } else {
                i += 1;
            }
        }
        // UTF-16LE: printable byte followed by 0, repeated
        let mut i = 0;
        while i + 1 < data.len() {
            if is_text_byte(data[i]) && data[i + 1] == 0 {
                let start = i;
                let mut text = String::new();
                while i + 1 < data.len() && is_text_byte(data[i]) && data[i + 1] == 0 {
                    text.push(data[i] as char);
                    i += 2;
                }
                if text.len() >= min_len {
                    found.push(FoundString {
                        address: segment.vaddr + start as u64,
                        text,
                        wide: true,
                    });
                }
            } else {
                i += 1;
            }
        }
    }
    found.sort_by_key(|s| (s.address, s.wide));
    found
}

/// Shannon entropy in bits per byte (0.0 - 8.0).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of one segment with a plain-language hint. The hint is a heuristic, not a detection.
#[derive(Clone, Debug, PartialEq)]
pub struct SegmentEntropy {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub entropy: f64,
    pub hint: &'static str,
}

pub fn segment_entropy(image: &PatchableImage) -> Vec<SegmentEntropy> {
    image
        .segments
        .iter()
        .filter_map(|s| {
            let data = segment_bytes(image, s.file_offset, s.file_size)?;
            if data.is_empty() {
                return None;
            }
            let e = entropy(data);
            let hint = if e >= 7.2 {
                "very high entropy: compressed, encrypted or packed data"
            } else if e >= 6.5 {
                "high entropy: dense code or compressed resources"
            } else if e < 1.0 {
                "near-constant data"
            } else {
                "typical"
            };
            Some(SegmentEntropy {
                name: s.name.clone(),
                vaddr: s.vaddr,
                size: data.len() as u64,
                entropy: e,
                hint,
            })
        })
        .collect()
}

/// xxd-style dump of `[address, address+length)`: address, hex bytes, ASCII column.
pub fn hexdump(image: &PatchableImage, address: u64, length: usize, width: usize) -> Result<String> {
    let width = width.clamp(1, 64);
    let data = image.read(address, length).map_err(|e| fail(e.to_string()))?;
    let digits = if address > 0xFFFF_FFFF { 16 } else { 8 };
    let mut out = String::new();
    for (row, chunk) in data.chunks(width).enumerate() {
        let line_address = address + (row * width) as u64;
        out.push_str(&format!("{line_address:0digits$X}  "));
        for i in 0..width {
            match chunk.get(i) {
                Some(b) => out.push_str(&format!("{b:02X} ")),
                None => out.push_str("   "),
            }
        }
        out.push_str(" |");
        out.extend(
            chunk
                .iter()
                .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }),
        );
        out.push_str("|\n");
    }
    Ok(out)
}

/// A run of differing bytes between two images of equal length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffRange {
    pub file_offset: usize,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// Byte-for-byte comparison of two images. Fails if the lengths differ, because offsets would no
/// longer line up.
pub fn diff_images(before: &PatchableImage, after: &PatchableImage) -> Result<Vec<DiffRange>> {
    let (a, b) = (before.bytes(), after.bytes());
    if a.len() != b.len() {
        return Err(fail(format!(
            "images differ in length ({} vs {} bytes); only equal-length images can be diffed",
            a.len(),
            b.len()
        )));
    }
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < a.len() {
        if a[i] == b[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < a.len() && a[i] != b[i] {
            i += 1;
        }
        ranges.push(DiffRange {
            file_offset: start,
            before: a[start..i].to_vec(),
            after: b[start..i].to_vec(),
        });
    }
    Ok(ranges)
}

/// Virtual address of a file offset, if some segment maps it.
pub fn address_of_file_offset(image: &PatchableImage, offset: usize) -> Option<u64> {
    let offset = offset as u64;
    image
        .segments
        .iter()
        .find(|s| offset >= s.file_offset && offset < s.file_offset + s.file_size)
        .map(|s| s.vaddr + (offset - s.file_offset))
}

/// Renders diff ranges as a script for [`PatchableImage::apply_script`]. Ranges that no segment
/// maps (for example header bytes outside every section) are returned separately instead of being
/// silently dropped.
pub fn diff_to_script(image: &PatchableImage, ranges: &[DiffRange]) -> (String, Vec<DiffRange>) {
    let mut script = String::new();
    let mut unmapped = Vec::new();
    for r in ranges {
        match address_of_file_offset(image, r.file_offset) {
            Some(address) => {
                let hex: Vec<String> = r.after.iter().map(|b| format!("{b:02X}")).collect();
                script.push_str(&format!("{address:#x} bytes {}\n", hex.join(" ")));
            }
            None => unmapped.push(r.clone()),
        }
    }
    (script, unmapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::PatchArch;

    fn raw(bytes: &[u8]) -> PatchableImage {
        PatchableImage::raw(bytes.to_vec(), 0x1000, PatchArch::X86_64)
    }

    #[test]
    fn pattern_parsing_and_wildcards() {
        assert!(Pattern::parse_hex("").is_err());
        assert!(Pattern::parse_hex("?? ??").is_err());
        assert!(Pattern::parse_hex("4").is_err());
        assert!(Pattern::parse_hex("ZZ").is_err());
        let img = raw(&[0x90, 0x48, 0x89, 0xE5, 0x48, 0x89, 0xEC, 0xC3]);
        let p = Pattern::parse_hex("48 89 ??").unwrap();
        assert_eq!(find_all(&img, &p, 10), vec![0x1001, 0x1004]);
        assert_eq!(find_all(&img, &p, 1), vec![0x1001], "limit is honoured");
        let tail = Pattern::parse_hex("EC C3").unwrap();
        assert_eq!(find_all(&img, &tail, 10), vec![0x1006], "match at the very end");
        let none = Pattern::parse_hex("C3 C3").unwrap();
        assert!(find_all(&img, &none, 10).is_empty());
        let wild_first = Pattern::parse_hex("?? 89 E5").unwrap();
        assert_eq!(find_all(&img, &wild_first, 10), vec![0x1001]);
    }

    #[test]
    fn strings_ascii_and_utf16() {
        let mut data = vec![0u8, 0];
        data.extend_from_slice(b"hello world\0ab\0\x01");
        let wide_at = data.len();
        for c in b"wide!" {
            data.extend_from_slice(&[*c, 0]);
        }
        data.extend_from_slice(&[0xFF, 0xFF]);
        let img = raw(&data);
        let s = extract_strings(&img, 4);
        assert!(s.contains(&FoundString {
            address: 0x1002,
            text: "hello world".into(),
            wide: false
        }));
        assert!(
            s.contains(&FoundString {
                address: 0x1000 + wide_at as u64,
                text: "wide!".into(),
                wide: true
            }),
            "{s:?}"
        );
        assert!(!s.iter().any(|f| f.text == "ab"), "shorter than min_len is dropped");
    }

    #[test]
    fn entropy_extremes() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 100]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
        let img = raw(&all.repeat(4));
        let seg = segment_entropy(&img);
        assert_eq!(seg.len(), 1);
        assert!(seg[0].hint.starts_with("very high"));
        let flat = raw(&[0u8; 64]);
        assert_eq!(segment_entropy(&flat)[0].hint, "near-constant data");
    }

    #[test]
    fn hexdump_layout() {
        let img = raw(b"ABC\x00\x01xyz0123456789!");
        let text = hexdump(&img, 0x1000, 18, 16).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "00001000  41 42 43 00 01 78 79 7A 30 31 32 33 34 35 36 37  |ABC..xyz01234567|"
        );
        assert!(lines[1].starts_with("00001010  38 39 "));
        assert!(lines[1].ends_with("|89|"), "{}", lines[1]);
        assert!(hexdump(&img, 0x1000, 100, 16).is_err());
    }

    #[test]
    fn diff_roundtrips_through_a_patch_script() {
        let original = raw(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut patched = original.clone();
        patched.write(0x1001, &[0xAA, 0xBB], "a").unwrap();
        patched.write(0x1008, &[0xCC], "b").unwrap();
        let ranges = diff_images(&original, &patched).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].before, vec![2, 3]);
        let (script, unmapped) = diff_to_script(&original, &ranges);
        assert!(unmapped.is_empty());
        assert_eq!(script, "0x1001 bytes AA BB\n0x1008 bytes CC\n");
        let mut replay = original.clone();
        replay.apply_script(&script).unwrap();
        assert_eq!(replay.bytes(), patched.bytes());
        let shorter = raw(&[1, 2, 3]);
        assert!(diff_images(&original, &shorter).is_err());
    }
}
