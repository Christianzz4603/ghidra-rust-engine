//! IDA-style presentation of analysis results.
//!
//! This module only changes *how results are laid out*: a disassembly listing with
//! `.text:ADDRESS` prefixes, `S U B R O U T I N E` banners, `proc near` / `endp` pairs,
//! `loc_` labels, `CODE XREF` comments and IDA-like number formatting, plus a renamer that turns
//! Ghidra-style pseudocode identifiers (`FUN_`, `param_1`, `iVar1`, `undefined8`) into the
//! `sub_` / `a1` / `v1` / `__int64` style.
//!
//! It is an independent implementation of a text layout. It is **not** IDA Pro output and does not
//! make the analysis behind it equivalent to IDA's: the layout rules below are written from the
//! commonly seen shape of such listings and have not been compared against IDA itself. Known
//! simplifications: no stack-variable (`var_4`) naming, no `Attributes:` / type comment lines, no
//! data items, and the section name is supplied by the caller.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

/// Column (counted from the end of the `section:address ` prefix) where comments start.
const COMMENT_COLUMN: usize = 40;
/// Column where the mnemonic starts when no opcode bytes are shown.
const MNEMONIC_COLUMN: usize = 16;
/// Width of the name field in `name proc near` lines.
const NAME_WIDTH: usize = 16;

/// How a cross-reference reaches its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    Read,
    Write,
    /// Address taken as data (offset).
    Offset,
}

impl XrefKind {
    fn letter(self) -> char {
        match self {
            XrefKind::Call => 'p',
            XrefKind::Jump => 'j',
            XrefKind::Read => 'r',
            XrefKind::Write => 'w',
            XrefKind::Offset => 'o',
        }
    }
    fn is_code(self) -> bool {
        matches!(self, XrefKind::Call | XrefKind::Jump)
    }
}

/// One cross-reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListingXref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

/// One instruction as printed by the disassembler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

/// One function to list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingFunction {
    pub name: String,
    pub start: u64,
    pub instructions: Vec<ListingInsn>,
}

/// Layout options.
#[derive(Clone, Debug)]
pub struct ListingOptions {
    /// Section prefix such as `.text`.
    pub section: String,
    /// Hex digits in the address (16 for 64-bit images, 8 for 32-bit).
    pub address_digits: usize,
    /// Opcode bytes shown per instruction (0 hides them).
    pub opcode_bytes: usize,
    /// Cross-references listed per label before `...`.
    pub max_xrefs: usize,
    /// Use `^` / `v` instead of the arrows `↑` / `↓`.
    pub ascii_arrows: bool,
    /// Lower-case mnemonics and operands and rewrite numbers IDA-style (`0Ah`); meant for x86.
    pub intel_style: bool,
}

impl Default for ListingOptions {
    fn default() -> Self {
        ListingOptions {
            section: ".text".to_string(),
            address_digits: 16,
            opcode_bytes: 0,
            max_xrefs: 2,
            ascii_arrows: false,
            intel_style: true,
        }
    }
}

impl ListingOptions {
    /// Options derived from a SLEIGH language id such as `x86:LE:64:default`.
    pub fn for_language(language_id: &str) -> Self {
        let mut options = ListingOptions::default();
        let parts: Vec<&str> = language_id.split(':').collect();
        let bits = parts.get(2).and_then(|b| b.parse::<usize>().ok()).unwrap_or(64);
        options.address_digits = if bits <= 32 { 8 } else { 16 };
        options.intel_style = parts.first().is_some_and(|a| a.eq_ignore_ascii_case("x86"));
        options
    }
}

/// IDA-style number: decimal below 10, otherwise upper-case hex with an `h` suffix and a leading
/// `0` when the first digit is a letter.
pub fn ida_number(value: u64) -> String {
    if value < 10 {
        return value.to_string();
    }
    let hex = format!("{value:X}");
    if hex.starts_with(|c: char| c.is_ascii_alphabetic()) {
        format!("0{hex}h")
    } else {
        format!("{hex}h")
    }
}

fn parse_hex_token(token: &str) -> Option<u64> {
    let digits = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X"))?;
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// Rewrites Ghidra-style operand text (`EAX,dword ptr [RBP + -0x4]`) toward Intel/IDA style
/// (`eax, dword ptr [rbp-4]`). Numbers become IDA numbers; negative offsets stay decimal-free.
pub fn restyle_x86_operands(operands: &str, symbolize: &dyn Fn(u64) -> Option<String>) -> String {
    let mut out = String::new();
    let chars: Vec<char> = operands.chars().collect();
    let mut i = 0;
    let mut bracket_depth = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '[' {
            bracket_depth += 1;
            out.push(c);
            i += 1;
        } else if c == ']' {
            bracket_depth = bracket_depth.saturating_sub(1);
            out.push(c);
            i += 1;
        } else if c.is_ascii_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if let Some(value) = parse_hex_token(&word) {
                if bracket_depth == 0
                    && let Some(name) = symbolize(value)
                {
                    out.push_str(&name);
                } else {
                    out.push_str(&ida_number(value));
                }
            } else {
                out.push_str(&word.to_ascii_lowercase());
            }
        } else if c == ',' {
            out.push_str(", ");
            i += 1;
            while i < chars.len() && chars[i] == ' ' {
                i += 1;
            }
        } else if c == ' ' && bracket_depth > 0 {
            // drop spaces inside brackets: "[RBP + -0x4]" -> "[rbp-4]"
            i += 1;
        } else if c == '+' && bracket_depth > 0 {
            // "+ -" collapses to "-"; a following "-" is handled by the next iteration
            let mut j = i + 1;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            if j < chars.len() && chars[j] == '-' {
                i = j;
            } else {
                out.push('+');
                i += 1;
            }
        } else if c == '-' && bracket_depth > 0 {
            let mut j = i + 1;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            let start = j;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let word: String = chars[start..j].iter().collect();
            out.push('-');
            match parse_hex_token(&word) {
                Some(value) => out.push_str(&ida_number(value)),
                None => out.push_str(&word.to_ascii_lowercase()),
            }
            i = j;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

struct Layout<'a> {
    options: &'a ListingOptions,
    function_names: BTreeMap<u64, String>,
    /// Incoming cross-references per target, sorted by source address.
    incoming: BTreeMap<u64, Vec<ListingXref>>,
    /// `(start, end, name)` sorted by start for "which function contains this address" lookups.
    ranges: Vec<(u64, u64, String)>,
}

impl Layout<'_> {
    fn prefix(&self, address: u64) -> String {
        format!(
            "{}:{:0width$X}",
            self.options.section,
            address,
            width = self.options.address_digits
        )
    }

    fn name_at(&self, address: u64) -> Option<String> {
        if let Some(name) = self.function_names.get(&address) {
            return Some(name.clone());
        }
        if self.is_label(address) {
            return Some(format!("loc_{address:X}"));
        }
        None
    }

    /// Index of the function range containing `address`.
    fn containing(&self, address: u64) -> Option<usize> {
        let after = self.ranges.partition_point(|(start, _, _)| *start <= address);
        let index = after.checked_sub(1)?;
        (address < self.ranges[index].1).then_some(index)
    }

    /// A `loc_` label: the target of a jump that lands inside a listed function but not on its start.
    fn is_label(&self, address: u64) -> bool {
        !self.function_names.contains_key(&address)
            && self.containing(address).is_some()
            && self
                .incoming
                .get(&address)
                .is_some_and(|refs| refs.iter().any(|r| r.kind == XrefKind::Jump))
    }

    /// `function+offset` text for a reference source.
    fn location_text(&self, address: u64) -> String {
        match self.containing(address).map(|index| &self.ranges[index]) {
            Some((start, _, name)) if *start == address => name.clone(),
            Some((start, _, name)) => format!("{name}+{:X}", address - start),
            None => format!("loc_{address:X}"),
        }
    }

    fn xref_comment_lines(&self, target: u64, kinds_code: bool) -> Vec<String> {
        let Some(refs) = self.incoming.get(&target) else {
            return Vec::new();
        };
        let selected: Vec<&ListingXref> = refs.iter().filter(|r| r.kind.is_code() == kinds_code).collect();
        if selected.is_empty() {
            return Vec::new();
        }
        let shown = selected.len().min(self.options.max_xrefs.max(1));
        let mut lines = Vec::new();
        for (index, r) in selected.iter().take(shown).enumerate() {
            let arrow = match (r.from < target, self.options.ascii_arrows) {
                (true, false) => "\u{2191}",
                (false, false) => "\u{2193}",
                (true, true) => "^",
                (false, true) => "v",
            };
            let mut text = format!("{}{}{}", self.location_text(r.from), arrow, r.kind.letter());
            if index == 0 {
                text = format!("{} XREF: {}", if kinds_code { "CODE" } else { "DATA" }, text);
            }
            lines.push(text);
        }
        if selected.len() > shown
            && let Some(last) = lines.last_mut()
        {
            last.push_str(" ...");
        }
        lines
    }

    fn with_comment(&self, text: String, comment: &str) -> String {
        let mut line = text;
        // `text` is measured from the end of the "prefix " column
        while line.chars().count() < COMMENT_COLUMN {
            line.push(' ');
        }
        if line.chars().count() > COMMENT_COLUMN && !line.ends_with(' ') {
            line.push(' ');
        }
        line.push_str("; ");
        line.push_str(comment);
        line
    }

    fn emit(&self, out: &mut String, address: u64, text: &str) {
        let text = text.trim_end();
        if text.is_empty() {
            let _ = writeln!(out, "{}", self.prefix(address));
        } else {
            let _ = writeln!(out, "{} {}", self.prefix(address), text);
        }
    }

    fn instruction_text(&self, insn: &ListingInsn) -> String {
        let mnemonic_column = if self.options.opcode_bytes > 0 {
            MNEMONIC_COLUMN.max(3 * self.options.opcode_bytes + 1)
        } else {
            MNEMONIC_COLUMN
        };
        let mut text = String::new();
        if self.options.opcode_bytes > 0 {
            let shown: Vec<String> = insn
                .bytes
                .iter()
                .take(self.options.opcode_bytes)
                .map(|b| format!("{b:02X}"))
                .collect();
            text.push_str(&shown.join(" "));
        }
        while text.chars().count() < mnemonic_column {
            text.push(' ');
        }
        let intel = self.options.intel_style;
        let mnemonic = if intel {
            insn.mnemonic.to_ascii_lowercase()
        } else {
            insn.mnemonic.clone()
        };
        let operands = if intel {
            let lookup = |value: u64| self.name_at(value);
            restyle_x86_operands(&insn.operands, &lookup)
        } else {
            insn.operands.clone()
        };
        text.push_str(&mnemonic);
        if !operands.is_empty() {
            let width = mnemonic.chars().count();
            let pad = if width < 8 { 8 - width } else { 1 };
            text.push_str(&" ".repeat(pad));
            text.push_str(&operands);
        }
        text
    }
}

/// Everything needed to render one function at a time: function names and ranges plus the
/// incoming cross-references. Holds no instructions, so a whole binary can be listed with memory
/// proportional to the number of functions and references rather than to the code size.
pub struct ListingContext<'a> {
    layout: Layout<'a>,
}

impl<'a> ListingContext<'a> {
    /// `functions` is `(name, start, end)` per function; they need not be sorted.
    pub fn new(functions: &[(String, u64, u64)], xrefs: &[ListingXref], options: &'a ListingOptions) -> Self {
        let mut ranges: Vec<(u64, u64, String)> = functions
            .iter()
            .map(|(name, start, end)| (*start, (*end).max(*start + 1), name.clone()))
            .collect();
        ranges.sort_by_key(|r| r.0);
        ranges.dedup_by_key(|r| r.0);
        let function_names: BTreeMap<u64, String> = ranges.iter().map(|(s, _, n)| (*s, n.clone())).collect();
        let mut incoming: BTreeMap<u64, Vec<ListingXref>> = BTreeMap::new();
        for x in xrefs {
            incoming.entry(x.to).or_default().push(*x);
        }
        for list in incoming.values_mut() {
            list.sort_by_key(|x| (x.from, x.kind.letter()));
            list.dedup();
        }
        ListingContext {
            layout: Layout {
                options,
                function_names,
                incoming,
                ranges,
            },
        }
    }

    /// Appends the listing of one function to `out`.
    pub fn render_function(&self, f: &ListingFunction, out: &mut String) {
        let layout = &self.layout;
        let start = f.start;
        layout.emit(
            out,
            start,
            "; =============== S U B R O U T I N E =======================================",
        );
        layout.emit(out, start, "");
        let mut header = format!("{:<width$}", f.name, width = NAME_WIDTH);
        if f.name.chars().count() >= NAME_WIDTH {
            header.push(' ');
        }
        header.push_str("proc near");
        let mut comments = layout.xref_comment_lines(start, true);
        comments.extend(layout.xref_comment_lines(start, false));
        match comments.split_first() {
            Some((first, rest)) => {
                layout.emit(out, start, &layout.with_comment(header, first));
                for line in rest {
                    layout.emit(out, start, &layout.with_comment(String::new(), line));
                }
            }
            None => layout.emit(out, start, &header),
        }
        layout.emit(out, start, "");
        for insn in &f.instructions {
            if insn.address != start && layout.is_label(insn.address) {
                let label = format!("loc_{:X}:", insn.address);
                let comments = layout.xref_comment_lines(insn.address, true);
                match comments.split_first() {
                    Some((first, rest)) => {
                        layout.emit(out, insn.address, &layout.with_comment(label, first));
                        for line in rest {
                            layout.emit(out, insn.address, &layout.with_comment(String::new(), line));
                        }
                    }
                    None => layout.emit(out, insn.address, &label),
                }
            }
            let text = layout.instruction_text(insn);
            layout.emit(out, insn.address, &text);
        }
        let last_address = f.instructions.last().map(|i| i.address).unwrap_or(start);
        layout.emit(
            out,
            last_address,
            &format!(
                "{:<width$}{}",
                f.name,
                "endp",
                width = NAME_WIDTH.max(f.name.chars().count() + 1)
            ),
        );
        layout.emit(out, last_address, "");
    }
}

/// Renders functions as an IDA-style text listing. Functions are listed in address order.
pub fn render_listing(functions: &[ListingFunction], xrefs: &[ListingXref], options: &ListingOptions) -> String {
    let mut sorted: Vec<&ListingFunction> = functions.iter().collect();
    sorted.sort_by_key(|f| f.start);
    let ranges: Vec<(String, u64, u64)> = sorted
        .iter()
        .map(|f| {
            let end = f
                .instructions
                .last()
                .map(|i| i.address + i.bytes.len().max(1) as u64)
                .unwrap_or(f.start + 1);
            (f.name.clone(), f.start, end)
        })
        .collect();
    let context = ListingContext::new(&ranges, xrefs, options);
    let mut out = String::new();
    for f in sorted {
        context.render_function(f, &mut out);
    }
    out
}

/// Options for [`restyle_pseudocode`].
#[derive(Clone, Copy, Debug)]
pub struct PseudocodeStyle {
    /// Size of C `long` / pointers in bytes (8 or 4).
    pub word_size: u32,
}

impl PseudocodeStyle {
    /// Style derived from a SLEIGH language id such as `x86:LE:32:default`.
    pub fn for_language(language_id: &str) -> Self {
        let bits = language_id.split(':').nth(2).and_then(|b| b.parse::<u32>().ok());
        PseudocodeStyle {
            word_size: if bits.is_some_and(|b| b <= 32) { 4 } else { 8 },
        }
    }
}

impl Default for PseudocodeStyle {
    fn default() -> Self {
        PseudocodeStyle { word_size: 8 }
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn all_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_local_name(word: &str) -> bool {
    if let Some(rest) = word.strip_prefix("local_") {
        return all_hex(rest);
    }
    if let Some(index) = word.find("Stack_") {
        let (head, rest) = word.split_at(index);
        return head.chars().all(|c| c.is_ascii_lowercase()) && all_hex(&rest["Stack_".len()..]);
    }
    if let Some(index) = word.find("Var") {
        let (head, rest) = word.split_at(index);
        return !head.is_empty()
            && head.chars().all(|c| c.is_ascii_lowercase())
            && !rest["Var".len()..].is_empty()
            && rest["Var".len()..].chars().all(|c| c.is_ascii_digit());
    }
    false
}

struct Renamer {
    style: PseudocodeStyle,
    locals: HashMap<String, usize>,
    labels: HashMap<String, usize>,
}

impl Renamer {
    fn map(&mut self, word: &str) -> Option<String> {
        if let Some(rest) = word.strip_prefix("FUN_")
            && all_hex(rest)
        {
            return Some(format!("sub_{}", strip_zeros_upper(rest)));
        }
        if let Some(rest) = word.strip_prefix("DAT_")
            && all_hex(rest)
        {
            return Some(format!("unk_{}", strip_zeros_upper(rest)));
        }
        if let Some(rest) = word.strip_prefix("LAB_")
            && all_hex(rest)
        {
            let next = self.labels.len() + 1;
            let n = *self.labels.entry(word.to_string()).or_insert(next);
            return Some(format!("LABEL_{n}"));
        }
        if let Some(rest) = word.strip_prefix("param_")
            && !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_digit())
        {
            return Some(format!("a{rest}"));
        }
        if is_local_name(word) {
            let next = self.locals.len() + 1;
            let n = *self.locals.entry(word.to_string()).or_insert(next);
            return Some(format!("v{n}"));
        }
        let wide = self.style.word_size >= 8;
        let mapped = match word {
            "undefined8" => "__int64",
            "undefined4" => "int",
            "undefined2" => "__int16",
            "undefined1" | "undefined" => "char",
            "long" => {
                if wide {
                    "__int64"
                } else {
                    "int"
                }
            }
            "ulong" => {
                if wide {
                    "unsigned __int64"
                } else {
                    "unsigned int"
                }
            }
            "longlong" => "__int64",
            "ulonglong" => "unsigned __int64",
            "uint" => "unsigned int",
            "short" => "__int16",
            "ushort" => "unsigned __int16",
            "byte" | "uchar" => "unsigned __int8",
            _ => return None,
        };
        Some(mapped.to_string())
    }
}

fn strip_zeros_upper(hex: &str) -> String {
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_ascii_uppercase()
    }
}

/// Renames Ghidra-style identifiers in one function's pseudocode to the `sub_` / `a1` / `v1` /
/// `__int64` style. String literals, character literals and comments are left untouched. Local
/// variables and labels are numbered in order of first appearance, so pass one function at a time.
pub fn restyle_pseudocode(text: &str, style: PseudocodeStyle) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut renamer = Renamer {
        style,
        locals: HashMap::new(),
        labels: HashMap::new(),
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                i += 1;
                if chars[i - 1] == quote {
                    break;
                }
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            let start = i;
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            out.extend(&chars[start..i]);
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            let start = i;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            out.extend(&chars[start..i]);
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            out.extend(&chars[start..i]);
        } else if is_ident_start(c) {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            match renamer.map(&word) {
                Some(new) => out.push_str(&new),
                None => out.push_str(&word),
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    // an empty parameter list reads `()` rather than `(void)` in a definition or declaration
    out.replace("(void)\n{", "()\n{")
        .replace("(void) {", "() {")
        .replace("(void);", "();")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(address: u64, mnemonic: &str, operands: &str, len: usize) -> ListingInsn {
        ListingInsn {
            address,
            bytes: vec![0x90; len],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
        }
    }

    #[test]
    fn numbers_follow_ida_conventions() {
        assert_eq!(ida_number(0), "0");
        assert_eq!(ida_number(9), "9");
        assert_eq!(ida_number(10), "0Ah");
        assert_eq!(ida_number(16), "10h");
        assert_eq!(ida_number(0xFF), "0FFh");
        assert_eq!(ida_number(0x401000), "401000h");
    }

    #[test]
    fn operands_are_restyled() {
        let none = |_: u64| None;
        assert_eq!(restyle_x86_operands("EAX,0x1", &none), "eax, 1");
        assert_eq!(restyle_x86_operands("RBP,RSP", &none), "rbp, rsp");
        assert_eq!(
            restyle_x86_operands("dword ptr [RBP + -0x4],0xa", &none),
            "dword ptr [rbp-4], 0Ah"
        );
        assert_eq!(
            restyle_x86_operands("RAX,qword ptr [RDX + RAX*0x4 + 0x10]", &none),
            "rax, qword ptr [rdx+rax*4+10h]"
        );
        let sym = |v: u64| (v == 0x401200).then(|| "sub_401200".to_string());
        assert_eq!(restyle_x86_operands("0x401200", &sym), "sub_401200");
    }

    #[test]
    fn listing_has_banner_labels_and_xrefs() {
        let main = ListingFunction {
            name: "main".into(),
            start: 0x401000,
            instructions: vec![
                insn(0x401000, "PUSH", "RBP", 1),
                insn(0x401001, "TEST", "EAX,EAX", 2),
                insn(0x401003, "JZ", "0x401008", 2),
                insn(0x401005, "CALL", "0x401100", 3),
                insn(0x401008, "POP", "RBP", 1),
                insn(0x401009, "RET", "", 1),
            ],
        };
        let helper = ListingFunction {
            name: "sub_401100".into(),
            start: 0x401100,
            instructions: vec![insn(0x401100, "RET", "", 1)],
        };
        let xrefs = [
            ListingXref {
                from: 0x401003,
                to: 0x401008,
                kind: XrefKind::Jump,
            },
            ListingXref {
                from: 0x401005,
                to: 0x401100,
                kind: XrefKind::Call,
            },
        ];
        let text = render_listing(&[helper, main], &xrefs, &ListingOptions::default());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            ".text:0000000000401000 ; =============== S U B R O U T I N E ======================================="
        );
        assert_eq!(lines[1], ".text:0000000000401000");
        assert_eq!(lines[2], ".text:0000000000401000 main            proc near");
        assert_eq!(lines[4], ".text:0000000000401000                 push    rbp");
        assert!(
            text.contains(".text:0000000000401003                 jz      loc_401008"),
            "{text}"
        );
        assert!(
            text.contains(".text:0000000000401005                 call    sub_401100"),
            "{text}"
        );
        let label = lines.iter().find(|l| l.contains("loc_401008:")).expect("label line");
        assert!(label.ends_with("; CODE XREF: main+3\u{2191}j"), "{label}");
        let proc_line = lines
            .iter()
            .find(|l| l.contains("sub_401100  ") && l.contains("proc near"))
            .unwrap();
        assert!(proc_line.ends_with("; CODE XREF: main+5\u{2191}p"), "{proc_line}");
        assert!(text.contains("main            endp"));
        assert!(text.find("main            proc near").unwrap() < text.find("sub_401100      proc near").unwrap());
    }

    #[test]
    fn comment_column_and_xref_limit() {
        let f = ListingFunction {
            name: "f".into(),
            start: 0x10,
            instructions: vec![
                insn(0x10, "NOP", "", 1),
                insn(0x11, "NOP", "", 1),
                insn(0x12, "RET", "", 1),
            ],
        };
        let xrefs: Vec<ListingXref> = [1u64, 2, 3]
            .iter()
            .map(|n| ListingXref {
                from: 0x100 + n,
                to: 0x11,
                kind: XrefKind::Jump,
            })
            .collect();
        let mut options = ListingOptions::default();
        options.address_digits = 8;
        options.ascii_arrows = true;
        let text = render_listing(&[f], &xrefs, &options);
        let label_idx = text.lines().position(|l| l.contains("loc_11:")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let prefix_len = ".text:00000011 ".len();
        assert_eq!(lines[label_idx].find(';').unwrap(), prefix_len + COMMENT_COLUMN);
        assert!(
            lines[label_idx].ends_with("; CODE XREF: loc_101vj"),
            "{}",
            lines[label_idx]
        );
        assert!(
            lines[label_idx + 1].trim_end().ends_with("; loc_102vj ..."),
            "{}",
            lines[label_idx + 1]
        );
    }

    #[test]
    fn opcode_bytes_are_optional() {
        let f = ListingFunction {
            name: "f".into(),
            start: 0x10,
            instructions: vec![ListingInsn {
                address: 0x10,
                bytes: vec![0x48, 0x89, 0xE5],
                mnemonic: "MOV".into(),
                operands: "RBP,RSP".into(),
            }],
        };
        let mut options = ListingOptions::default();
        options.address_digits = 8;
        options.opcode_bytes = 4;
        let text = render_listing(&[f], &[], &options);
        assert!(
            text.contains(".text:00000010 48 89 E5        mov     rbp, rsp"),
            "{text}"
        );
    }

    #[test]
    fn language_id_selects_width_and_syntax() {
        let o = ListingOptions::for_language("x86:LE:32:default");
        assert_eq!((o.address_digits, o.intel_style), (8, true));
        let o = ListingOptions::for_language("AARCH64:LE:64:v8A");
        assert_eq!((o.address_digits, o.intel_style), (16, false));
    }

    #[test]
    fn pseudocode_is_renamed() {
        let src = "undefined8 FUN_00401130(long param_1,uint param_2)\n{\n  int iVar1;\n  long local_18;\n  iVar1 = FUN_00401200(param_1);\n  if (iVar1 == 0) goto LAB_00401150;\n  puts(\"param_1 FUN_00401130\"); /* iVar1 */\nLAB_00401150:\n  return local_18 + 0x10;\n}\n";
        let out = restyle_pseudocode(src, PseudocodeStyle::default());
        assert!(
            out.starts_with("__int64 sub_401130(__int64 a1,unsigned int a2)\n{\n  int v1;\n  __int64 v2;\n"),
            "{out}"
        );
        assert!(out.contains("v1 = sub_401200(a1);"));
        assert!(out.contains("goto LABEL_1;"));
        assert!(out.contains("\nLABEL_1:\n"));
        assert!(
            out.contains("puts(\"param_1 FUN_00401130\"); /* iVar1 */"),
            "strings and comments stay"
        );
        assert!(out.contains("return v2 + 0x10;"));
    }

    #[test]
    fn pseudocode_style_from_language() {
        assert_eq!(PseudocodeStyle::for_language("x86:LE:32:default").word_size, 4);
        assert_eq!(PseudocodeStyle::for_language("x86:LE:64:default").word_size, 8);
        assert_eq!(PseudocodeStyle::for_language("weird").word_size, 8);
    }

    #[test]
    fn pseudocode_word_size_and_void_params() {
        let src = "void FUN_00001000(void)\n{\n  ulong x;\n}\n";
        let out64 = restyle_pseudocode(src, PseudocodeStyle { word_size: 8 });
        assert!(
            out64.starts_with("void sub_1000()\n{\n  unsigned __int64 x;"),
            "{out64}"
        );
        let out32 = restyle_pseudocode(src, PseudocodeStyle { word_size: 4 });
        assert!(out32.contains("unsigned int x;"));
        assert_eq!(
            restyle_pseudocode("x = (void)0;", PseudocodeStyle::default()),
            "x = (void)0;"
        );
    }
}
