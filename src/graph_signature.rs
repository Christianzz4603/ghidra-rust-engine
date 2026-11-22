//! Graph-based function signatures: a faithful port of Ghidra's `signature.cc` / `signature.hh`.
//!
//! Unlike the linear [`crate::signature`] module (which hashes a flat instruction list), this
//! module works on the decompiler's SSA data-flow graph and basic-block control-flow graph held in
//! a [`Funcdata`]. It reproduces upstream's feature traversal, noise removal (COPY / INDIRECT /
//! MULTIEQUAL collapsing via a dominator tree), iterative neighbour hashing, per-block features and
//! XML encoding, so the resulting hashes are intended to be bit-identical to Ghidra's.
//!
//! Deviations from the C++ source (behaviour is otherwise unchanged):
//! * The global static `SigManager::settings` becomes an explicit constructor argument.
//! * Pointer-linked `SignatureEntry` overlays become indices into a `Vec`, and the `std::map`
//!   keyed by Varnode create-index becomes a `BTreeMap` (same iteration order).
//! * `Signature` and its subclasses are a single struct carrying a [`SignatureOrigin`].
//!
//! The function must already have been decompiled (heritage complete) before signatures are taken.

use std::collections::BTreeMap;

use crate::address::Address;
use crate::architecture::Architecture;
use crate::block::BlockId;
use crate::crc32::crc_update;
use crate::error::{Error, Result};
use crate::funcdata::Funcdata;
use crate::marshal::{ATTRIB_INDEX, ATTRIB_OFFSET, ATTRIB_SPACE, ATTRIB_VAL, AttributeId, ElementId, Encoder};
use crate::op::OpId;
use crate::opcodes::OpCode;
use crate::varnode::VarnodeId;

/// Data-type for containing hash information (upstream `hashword`).
pub type HashWord = u64;

pub const ATTRIB_BADDATA: AttributeId = AttributeId::new("baddata", 145);
pub const ATTRIB_HASH: AttributeId = AttributeId::new("hash", 146);
pub const ATTRIB_UNIMPL: AttributeId = AttributeId::new("unimpl", 147);

pub const ELEM_BLOCKSIG: ElementId = ElementId::new("blocksig", 258);
pub const ELEM_CALL: ElementId = ElementId::new("call", 259);
pub const ELEM_GENSIG: ElementId = ElementId::new("gensig", 260);
pub const ELEM_MAJOR: ElementId = ElementId::new("major", 261);
pub const ELEM_MINOR: ElementId = ElementId::new("minor", 262);
pub const ELEM_COPYSIG: ElementId = ElementId::new("copysig", 263);
pub const ELEM_SETTINGS: ElementId = ElementId::new("settings", 264);
pub const ELEM_SIG: ElementId = ElementId::new("sig", 265);
pub const ELEM_SIGNATUREDESC: ElementId = ElementId::new("signaturedesc", 266);
pub const ELEM_SIGNATURES: ElementId = ElementId::new("signatures", 267);
pub const ELEM_SIGSETTINGS: ElementId = ElementId::new("sigsettings", 268);
pub const ELEM_VARSIG: ElementId = ElementId::new("varsig", 269);

/// Signature generation settings (upstream `GraphSigManager::Mods`).
pub const SIG_COLLAPSE_SIZE: u32 = 0x1;
pub const SIG_COLLAPSE_INDNOISE: u32 = 0x2;
pub const SIG_DONOTUSE_CONST: u32 = 0x10;
pub const SIG_DONOTUSE_INPUT: u32 = 0x20;
pub const SIG_DONOTUSE_PERSIST: u32 = 0x40;

/// The settings value upstream suggests as a default: `((DONOTUSE_CONST | COLLAPSE_INDNOISE) << 2) | 1`.
pub const DEFAULT_SETTINGS: u32 = ((SIG_DONOTUSE_CONST | SIG_COLLAPSE_INDNOISE) << 2) | 1;

// SignatureEntry flags
const SIG_NODE_TERMINAL: u32 = 0x1;
const SIG_NODE_COMMUTATIVE: u32 = 0x2;
const SIG_NODE_NOT_EMITTED: u32 = 0x4;
const SIG_NODE_STANDALONE: u32 = 0x8;
const VISITED: u32 = 0x10;
const MARKER_ROOT: u32 = 0x20;

/// Mix two hash words together using a CRC-based construction (upstream `hash_mixin`).
pub fn hash_mixin(val1: HashWord, mut val2: HashWord) -> HashWord {
    let mut hashhi = (val1 >> 32) as u32;
    let mut hashlo = val1 as u32;
    for _ in 0..8 {
        let tmphi = hashhi;
        let tmplo = val2 as u32;
        val2 >>= 8;
        hashhi = crc_update(hashhi, tmplo);
        hashlo = crc_update(hashlo, tmphi);
    }
    ((hashhi as u64) << 32) | hashlo as u64
}

/// Hash describing the size of a Varnode (upstream `SignatureEntry::hashSize`).
fn hash_size(size: i32, modifiers: u32) -> HashWord {
    let mut val = size as HashWord;
    if (modifiers & SIG_COLLAPSE_SIZE) != 0 && val > 4 {
        val = 4;
    }
    val ^ (val << 7) ^ (val << 14) ^ (val << 21)
}

/// Where a feature came from; used for debug description and for the verbose XML encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureOrigin {
    /// A bare feature known only by its hash (upstream base `Signature`).
    Hash,
    /// A feature rooted at a Varnode of the data-flow graph (`VarnodeSignature`).
    Varnode(VarnodeId),
    /// A feature rooted in a basic block (`BlockSignature`). Form 2 carries the two ops in sequence.
    Block {
        block: BlockId,
        op1: Option<OpId>,
        op2: Option<OpId>,
    },
    /// A feature combining the stand-alone COPYs of a block (`CopySignature`).
    Copy(BlockId),
}

/// A single 32-bit feature of a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    sig: u32,
    origin: SignatureOrigin,
}

impl Signature {
    pub fn new(h: HashWord) -> Signature {
        Signature {
            sig: h as u32,
            origin: SignatureOrigin::Hash,
        }
    }

    fn with_origin(h: HashWord, origin: SignatureOrigin) -> Signature {
        Signature { sig: h as u32, origin }
    }

    /// The underlying 32-bit hash.
    pub fn get_hash(&self) -> u32 {
        self.sig
    }

    pub fn origin(&self) -> SignatureOrigin {
        self.origin
    }

    /// Compare two features by hash as unsigned values: -1, 0, or 1.
    pub fn compare(&self, op2: &Signature) -> i32 {
        if self.sig != op2.sig {
            return if self.sig < op2.sig { -1 } else { 1 };
        }
        0
    }

    /// One-line description in the style of upstream `Signature::print`.
    pub fn describe(&self, fd: &Funcdata) -> String {
        let origin = match self.origin {
            SignatureOrigin::Hash => format!("0x{:08x}", self.sig),
            SignatureOrigin::Varnode(v) => format!("varnode #{}", fd.vn(v).get_create_index()),
            SignatureOrigin::Block { block, .. } => format!("block {}", fd.block(block).get_index()),
            SignatureOrigin::Copy(block) => format!("Copies in block {}", fd.block(block).get_index()),
        };
        format!("*{} = 0x{:08x}", origin, self.sig)
    }

    /// Encode this feature, including any descriptive information about how it was formed.
    pub fn encode(&self, encoder: &mut dyn Encoder, fd: &Funcdata, glb: &Architecture) -> Result<()> {
        match self.origin {
            SignatureOrigin::Hash => {
                encoder.open_element(ELEM_GENSIG);
                encoder.write_unsigned_integer(ATTRIB_HASH, self.sig as u64);
                encoder.close_element(ELEM_GENSIG);
            }
            SignatureOrigin::Varnode(v) => {
                encoder.open_element(ELEM_VARSIG);
                encoder.write_unsigned_integer(ATTRIB_HASH, self.sig as u64);
                let vn = fd.vn(v);
                vn.encode(encoder, fd)?;
                if let Some(def) = vn.get_def() {
                    fd.op_encode(def, encoder, glb)?;
                }
                encoder.close_element(ELEM_VARSIG);
            }
            SignatureOrigin::Block { block, op1, op2 } => {
                encoder.open_element(ELEM_BLOCKSIG);
                encoder.write_unsigned_integer(ATTRIB_HASH, self.sig as u64);
                let bl = fd.block(block);
                encoder.write_signed_integer(ATTRIB_INDEX, bl.get_index() as i64);
                bl.get_start().encode(encoder)?;
                if let Some(op) = op2 {
                    fd.op_encode(op, encoder, glb)?;
                }
                if let Some(op) = op1 {
                    fd.op_encode(op, encoder, glb)?;
                }
                encoder.close_element(ELEM_BLOCKSIG);
            }
            SignatureOrigin::Copy(block) => {
                encoder.open_element(ELEM_COPYSIG);
                encoder.write_unsigned_integer(ATTRIB_HASH, self.sig as u64);
                encoder.write_signed_integer(ATTRIB_INDEX, fd.block(block).get_index() as i64);
                encoder.close_element(ELEM_COPYSIG);
            }
        }
        Ok(())
    }
}

/// Per-Varnode node for data-flow feature generation (upstream `SignatureEntry`).
#[derive(Clone, Debug)]
struct SigEntry {
    vn: Option<VarnodeId>,
    flags: u32,
    hash: [HashWord; 2],
    /// The effective defining op of the Varnode.
    op: Option<OpId>,
    startvn: i32,
    in_size: i32,
    /// Post-order index (noise graph).
    index: i32,
    /// If set, the entry (by position) that this one shadows.
    shadow: Option<usize>,
}

impl SigEntry {
    fn is_visited(&self) -> bool {
        (self.flags & VISITED) != 0
    }
    fn is_terminal(&self) -> bool {
        (self.flags & SIG_NODE_TERMINAL) != 0
    }
    fn is_not_emitted(&self) -> bool {
        (self.flags & SIG_NODE_NOT_EMITTED) != 0
    }
    fn is_commutative(&self) -> bool {
        (self.flags & SIG_NODE_COMMUTATIVE) != 0
    }
    fn is_standalone_copy(&self) -> bool {
        (self.flags & SIG_NODE_STANDALONE) != 0
    }
    fn marker_size_in(&self) -> i32 {
        if (self.flags & MARKER_ROOT) != 0 {
            1
        } else {
            self.in_size
        }
    }
}

/// The set of SignatureEntry overlays for one function.
struct Overlay<'a> {
    fd: &'a Funcdata,
    entries: Vec<SigEntry>,
    /// Varnode create-index -> position in `entries`.
    map: BTreeMap<u32, usize>,
}

impl<'a> Overlay<'a> {
    fn entry_of(&self, v: VarnodeId) -> Result<usize> {
        let ci = self.fd.vn(v).get_create_index();
        self.map
            .get(&ci)
            .copied()
            .ok_or_else(|| Error::Lowlevel("Varnode missing from signature map".to_string()))
    }

    /// `mapToEntryCollapse`: if the entry shadows another, return the shadowed entry.
    fn entry_of_collapse(&self, v: VarnodeId) -> Result<usize> {
        let idx = self.entry_of(v)?;
        Ok(self.entries[idx].shadow.unwrap_or(idx))
    }

    /// Port of the `SignatureEntry(Varnode *, modifiers)` constructor.
    fn build_entry(&self, v: VarnodeId) -> SigEntry {
        let fd = self.fd;
        let vn = fd.vn(v);
        let def = vn.get_def();
        let mut e = SigEntry {
            vn: Some(v),
            flags: 0,
            hash: [0, 0],
            op: def,
            startvn: 0,
            in_size: 0,
            index: -1,
            shadow: None,
        };
        let Some(defid) = def else {
            e.flags |= SIG_NODE_TERMINAL;
            return e;
        };
        let op = fd.op(defid);
        e.in_size = op.num_input();
        match op.code() {
            OpCode::Copy => {
                if self.test_standalone_copy(v) {
                    e.flags |= SIG_NODE_STANDALONE;
                }
            }
            OpCode::Indirect => {
                e.in_size -= 1;
                if self.test_standalone_copy(v) {
                    e.flags |= SIG_NODE_STANDALONE;
                }
            }
            OpCode::Multiequal => e.flags |= SIG_NODE_COMMUTATIVE,
            OpCode::Call | OpCode::Callind | OpCode::Callother | OpCode::Store | OpCode::Load => {
                e.startvn = 1;
                e.in_size -= 1;
            }
            OpCode::IntLeft | OpCode::IntRight | OpCode::IntSright | OpCode::Subpiece => {
                // If the shift/truncation amount is constant, don't even hash in the size of the constant
                if fd.vn(op.get_in(1)).is_constant() {
                    e.in_size = 1;
                }
            }
            OpCode::Cpoolref => e.in_size = 0, // Only hash-in first input
            _ => {
                if op.is_commutative() {
                    e.flags |= SIG_NODE_COMMUTATIVE;
                }
            }
        }
        e
    }

    /// A Varnode is a stand-alone COPY if it is defined by a COPY or INDIRECT whose input is a constant or
    /// an input, and the Varnode is not read directly by other operations (`testStandaloneCopy`).
    fn test_standalone_copy(&self, v: VarnodeId) -> bool {
        let fd = self.fd;
        let vn = fd.vn(v);
        let Some(defid) = vn.get_def() else { return false };
        let op = fd.op(defid);
        let invn = fd.vn(op.get_in(0));
        if invn.is_written() {
            return false;
        }
        if invn.get_addr() == vn.get_addr() {
            return false;
        }
        if vn.is_persist() && op.code() == OpCode::Indirect {
            return true;
        }
        let desc = vn.descend();
        let Some(&first) = desc.first() else { return true };
        if desc.len() > 1 {
            return false;
        }
        let desc_op = fd.op(first);
        let opc = desc_op.code();
        if vn.is_persist() && opc == OpCode::Indirect {
            return true;
        }
        // Account for COPY and INDIRECT placeholder conventions
        if opc != OpCode::Copy && opc != OpCode::Indirect {
            return false;
        }
        match desc_op.get_out() {
            Some(out) => fd.vn(out).has_no_descend(),
            None => false,
        }
    }

    /// `calculateShadow`: follow any chain of COPY / INDIRECT / CAST back to the shadowed Varnode.
    fn calculate_shadow(&mut self, idx: usize) -> Result<()> {
        let fd = self.fd;
        let Some(start) = self.entries[idx].vn else {
            return Ok(());
        };
        let mut shadow_vn = start;
        loop {
            let def = fd.vn(shadow_vn).get_def();
            self.entries[idx].op = def;
            let Some(defid) = def else { break };
            let op = fd.op(defid);
            let opc = op.code();
            if opc != OpCode::Copy && opc != OpCode::Indirect && opc != OpCode::Cast {
                break;
            }
            shadow_vn = op.get_in(0);
        }
        if shadow_vn != start {
            self.entries[idx].shadow = Some(self.entry_of(shadow_vn)?);
        }
        Ok(())
    }

    /// Hash of the effective defining op: normally its OpCode (`getOpHash`).
    fn op_hash(&self, idx: usize) -> HashWord {
        let Some(opid) = self.entries[idx].op else { return 0 };
        let op = self.fd.op(opid);
        let opc = op.code();
        let mut ophash = opc as u32 as HashWord;
        if opc == OpCode::Cpoolref {
            // Hash in the resolved tag type constant, which is the last input
            let last = self.fd.vn(op.get_in(op.num_input() - 1));
            ophash = ophash.wrapping_add(0xfeedface) ^ last.get_offset();
        }
        ophash
    }

    fn standalone_copy_hash(&mut self, idx: usize, modifiers: u32) {
        let fd = self.fd;
        let Some(v) = self.entries[idx].vn else { return };
        let vn = fd.vn(v);
        let mut val = hash_size(vn.get_size(), modifiers);
        val ^= 0xaf29e23b;
        if vn.is_persist() {
            val ^= 0x55055055;
        }
        if let Some(defid) = vn.get_def() {
            let invn = fd.vn(fd.op(defid).get_in(0));
            if invn.is_constant() {
                if (modifiers & SIG_DONOTUSE_CONST) == 0 {
                    val ^= vn.get_offset();
                } else {
                    val ^= 0xa0a0a0a0;
                }
            } else if invn.is_persist() {
                val ^= 0xd7651ec3;
            }
        }
        self.entries[idx].hash = [val, val];
    }

    /// `localHash`: initial hash from local properties of the Varnode.
    fn local_hash(&mut self, idx: usize, modifiers: u32) {
        let fd = self.fd;
        let Some(v) = self.entries[idx].vn else { return };
        let vn = fd.vn(v);

        if vn.is_annotation() {
            let e = &mut self.entries[idx];
            e.flags |= SIG_NODE_NOT_EMITTED | SIG_NODE_TERMINAL;
            e.hash = [0xb7b7b7b7, 0xb7b7b7b7];
            return;
        }
        if self.entries[idx].shadow.is_some() {
            self.entries[idx].flags |= SIG_NODE_NOT_EMITTED;
            if self.entries[idx].is_standalone_copy() {
                self.standalone_copy_hash(idx, modifiers);
            }
            return;
        }

        let mut localhash = hash_size(vn.get_size(), modifiers);
        if !vn.is_written() {
            // No tree above this varnode: don't emit as a feature, but still generate the hash
            self.entries[idx].flags |= SIG_NODE_NOT_EMITTED;
        }
        let ophash = self.op_hash(idx);

        if vn.is_constant() {
            if (modifiers & SIG_DONOTUSE_CONST) == 0 {
                localhash ^= vn.get_offset();
            } else {
                localhash ^= 0xa0a0a0a0;
            }
        }
        // A persist storage location may get propagated away, so make sure the varnode is an input.
        if (modifiers & SIG_DONOTUSE_PERSIST) == 0 && vn.is_persist() && vn.is_input() {
            localhash ^= 0x55055055;
        }
        if vn.is_input() {
            localhash ^= 0x10101;
        }
        if ophash != 0 {
            localhash ^= ophash ^ (ophash << 9) ^ (ophash << 18);
        }
        self.entries[idx].hash = [localhash, localhash];
    }

    /// `hashIn`: mix the previous hashes of the given neighbours into this entry's current hash.
    fn hash_in(&mut self, idx: usize, neigh: &[usize]) {
        let mut curhash = self.entries[idx].hash[1];
        if self.entries[idx].is_commutative() {
            let mut accum: HashWord = 0;
            for &n in neigh {
                let tmphash = hash_mixin(curhash, self.entries[n].hash[1]);
                accum = accum.wrapping_add(tmphash);
            }
            curhash = hash_mixin(curhash, accum);
        } else {
            for &n in neigh {
                curhash = hash_mixin(curhash, self.entries[n].hash[1]);
            }
        }
        self.entries[idx].hash[0] = curhash;
    }

    /// Entry feeding into `idx` through edge `i` in the *noise* graph (`getMarkerIn`).
    fn marker_in(&self, idx: usize, i: i32, virtual_root: usize) -> Result<usize> {
        let e = &self.entries[idx];
        if (e.flags & MARKER_ROOT) != 0 {
            return Ok(virtual_root);
        }
        let opid =
            e.op.ok_or_else(|| Error::Lowlevel("Noise node without defining op".to_string()))?;
        self.entry_of(self.fd.op(opid).get_in(i + e.startvn))
    }

    /// Post-order the noise graph, which only follows marker ops and COPYs (`noisePostOrder`).
    fn noise_post_order(&mut self, rootlist: &[usize], post_order: &mut Vec<usize>) -> Result<()> {
        let fd = self.fd;
        // Each stack frame is (entry, next descendant slot to examine)
        let mut stack: Vec<(usize, usize)> = Vec::new();
        for &root in rootlist {
            self.entries[root].flags |= VISITED;
            stack.push((root, 0));
            while let Some(&(entry, pos)) = stack.last() {
                let Some(vnid) = self.entries[entry].vn else {
                    stack.pop();
                    continue;
                };
                let desc = fd.vn(vnid).descend();
                if pos >= desc.len() {
                    // No more children to traverse
                    stack.pop();
                    self.entries[entry].index = post_order.len() as i32;
                    post_order.push(entry);
                } else {
                    if let Some(top) = stack.last_mut() {
                        top.1 = pos + 1;
                    }
                    let op = fd.op(desc[pos]);
                    if (op.is_marker() || op.code() == OpCode::Copy)
                        && let Some(out) = op.get_out()
                    {
                        let child = self.entry_of(out)?;
                        if !self.entries[child].is_visited() {
                            self.entries[child].flags |= VISITED;
                            stack.push((child, 0));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Immediate dominators of the noise graph, left in each node's `shadow` (`noiseDominator`).
    fn noise_dominator(&mut self, post_order: &[usize]) -> Result<()> {
        let Some(&virtual_root) = post_order.last() else {
            return Ok(());
        };
        self.entries[virtual_root].shadow = Some(virtual_root);
        let mut new_idom = virtual_root;
        let mut changed = true;
        while changed {
            changed = false;
            // For all nodes, in reverse post-order, except the root
            for i in (0..post_order.len() - 1).rev() {
                let b = post_order[i];
                if self.entries[b].shadow == Some(virtual_root) {
                    continue;
                }
                let size_in = self.entries[b].marker_size_in();
                if size_in <= 0 {
                    continue;
                }
                let mut j = 0;
                while j < size_in {
                    // Find first processed node
                    new_idom = self.marker_in(b, j, virtual_root)?;
                    if self.entries[new_idom].shadow.is_some() {
                        break;
                    }
                    j += 1;
                }
                j += 1;
                while j < size_in {
                    let rho = self.marker_in(b, j, virtual_root)?;
                    if self.entries[rho].shadow.is_some() {
                        // Here is the intersection routine
                        let mut finger1 = self.entries[rho].index;
                        let mut finger2 = self.entries[new_idom].index;
                        while finger1 != finger2 {
                            while finger1 < finger2 {
                                finger1 = self.dom_index(post_order, finger1)?;
                            }
                            while finger2 < finger1 {
                                finger2 = self.dom_index(post_order, finger2)?;
                            }
                        }
                        new_idom = post_order[finger1 as usize];
                    }
                    j += 1;
                }
                if self.entries[b].shadow != Some(new_idom) {
                    self.entries[b].shadow = Some(new_idom);
                    changed = true;
                }
            }
        }
        Ok(())
    }

    /// Post-order index of the immediate dominator of the node with post-order index `finger`.
    fn dom_index(&self, post_order: &[usize], finger: i32) -> Result<i32> {
        let node = *post_order
            .get(finger as usize)
            .ok_or_else(|| Error::Lowlevel("Bad post-order index in noise dominator".to_string()))?;
        let dom = self.entries[node]
            .shadow
            .ok_or_else(|| Error::Lowlevel("Unprocessed node in noise dominator".to_string()))?;
        Ok(self.entries[dom].index)
    }

    /// Collapse Varnodes that are indirect copies of each other (`removeNoise`).
    fn remove_noise(&mut self) -> Result<()> {
        let fd = self.fd;
        let mut rootlist: Vec<usize> = Vec::new();
        let order: Vec<usize> = self.map.values().copied().collect();
        for &idx in &order {
            let Some(v) = self.entries[idx].vn else { continue };
            let vn = fd.vn(v);
            if vn.is_input() || vn.is_constant() {
                rootlist.push(idx);
                self.entries[idx].flags |= MARKER_ROOT;
            } else if vn.is_written()
                && let Some(defid) = vn.get_def()
            {
                let op = fd.op(defid);
                if !op.is_marker() && op.code() != OpCode::Copy {
                    rootlist.push(idx);
                    self.entries[idx].flags |= MARKER_ROOT;
                }
            }
        }

        let mut post_order: Vec<usize> = Vec::new();
        self.noise_post_order(&rootlist, &mut post_order)?;

        // Construct a virtual root with out edges to every node in rootlist
        let virtual_root = self.entries.len();
        self.entries.push(SigEntry {
            vn: None,
            flags: 0,
            hash: [0, 0],
            op: None,
            startvn: 0,
            in_size: 0,
            index: post_order.len() as i32,
            shadow: None,
        });
        post_order.push(virtual_root);
        for &r in &rootlist {
            self.entries[r].shadow = Some(virtual_root);
        }

        self.noise_dominator(&post_order)?;
        post_order.pop(); // Pop off virtual root

        // Shadow bases are the nodes immediately dominated by the virtual root
        for &idx in &post_order {
            if self.entries[idx].shadow == Some(virtual_root) {
                self.entries[idx].shadow = None;
            }
        }
        // Collapse the dominator tree onto the shadow bases
        for &start in &post_order {
            let mut base = start;
            while let Some(next) = self.entries[base].shadow {
                base = next;
            }
            let mut entry = start;
            while let Some(next) = self.entries[entry].shadow {
                let tmp = entry;
                entry = next;
                self.entries[tmp].shadow = Some(base);
            }
        }
        self.entries.pop(); // Remove the virtual root entry
        Ok(())
    }
}

/// Per-block node for control-flow feature generation (upstream `BlockSignatureEntry`).
#[derive(Clone, Copy, Debug)]
struct BlockSigEntry {
    bl: BlockId,
    hash: [HashWord; 2],
}

/// Generates the feature vector of a function from its data-flow and control-flow graphs
/// (upstream `GraphSigManager`). The manager can be reused for multiple functions.
pub struct GraphSigManager<'a> {
    sigmods: u32,
    maxiter: i32,
    maxblockiter: i32,
    maxvarnode: i32,
    fd: Option<&'a Funcdata>,
    overlay: Option<Overlay<'a>>,
    sigs: Vec<Signature>,
}

impl<'a> GraphSigManager<'a> {
    /// Test for valid signature generation settings (`testSettings`).
    pub fn test_settings(val: u32) -> bool {
        if val == 0 {
            return false; // 0 setting is not allowed
        }
        let mut mask =
            SIG_COLLAPSE_SIZE | SIG_DONOTUSE_CONST | SIG_DONOTUSE_INPUT | SIG_DONOTUSE_PERSIST | SIG_COLLAPSE_INDNOISE;
        mask = (mask << 2) | 1; // Add the check bit
        (val & !mask) == 0 // Do not allow any other bit to be set
    }

    /// Create a manager from a settings value (see [`DEFAULT_SETTINGS`]).
    pub fn new(settings: u32) -> Result<GraphSigManager<'a>> {
        if !Self::test_settings(settings) {
            return Err(Error::Lowlevel("Bad signature settings".to_string()));
        }
        Ok(GraphSigManager {
            sigmods: settings >> 2,
            maxiter: 3,
            maxblockiter: 1,
            maxvarnode: 0,
            fd: None,
            overlay: None,
            sigs: Vec::new(),
        })
    }

    /// Override the default iterations used for Varnode features.
    pub fn set_max_iteration(&mut self, val: i32) {
        self.maxiter = val;
    }

    /// Override the default iterations used for block features.
    pub fn set_max_block_iteration(&mut self, val: i32) {
        self.maxblockiter = val;
    }

    /// Set a maximum threshold for Varnodes in a function (0 means unlimited).
    pub fn set_max_varnode(&mut self, val: i32) {
        self.maxvarnode = val;
    }

    /// Read configuration (a maximum iteration count) from a character stream (`initializeFromStream`).
    pub fn initialize_from_str(&mut self, text: &str) {
        let token = text.split_whitespace().next().unwrap_or("");
        let parsed = if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
            i32::from_str_radix(hex, 16).ok()
        } else if token.len() > 1 && token.starts_with('0') {
            i32::from_str_radix(&token[1..], 8).ok()
        } else {
            token.parse::<i32>().ok()
        };
        if let Some(v) = parsed
            && v != -1
        {
            self.maxiter = v;
        }
    }

    /// Clear all current features and any per-function resources.
    pub fn clear(&mut self) {
        self.overlay = None;
        self.sigs.clear();
    }

    /// Set the function used for (future) feature generation (`setCurrentFunction`).
    pub fn set_current_function(&mut self, f: &'a Funcdata) -> Result<()> {
        self.fd = Some(f);
        self.overlay = None;
        let size = f.num_varnodes();
        if self.maxvarnode != 0 && size > self.maxvarnode {
            return Err(Error::Lowlevel(format!(
                "{} exceeds size threshold for generating signatures",
                f.get_name()
            )));
        }

        let mut overlay = Overlay {
            fd: f,
            entries: Vec::new(),
            map: BTreeMap::new(),
        };
        let mut all: Vec<(u32, VarnodeId)> = f
            .vbank
            .varnodes
            .iter()
            .map(|(id, vn)| (vn.get_create_index(), id))
            .collect();
        all.sort_by_key(|&(ci, _)| ci);
        for (ci, id) in all {
            let entry = overlay.build_entry(id);
            overlay.map.insert(ci, overlay.entries.len());
            overlay.entries.push(entry);
        }
        if (self.sigmods & SIG_COLLAPSE_INDNOISE) != 0 {
            overlay.remove_noise()?;
        } else {
            let order: Vec<usize> = overlay.map.values().copied().collect();
            for idx in order {
                overlay.calculate_shadow(idx)?;
            }
        }
        let order: Vec<usize> = overlay.map.values().copied().collect();
        for idx in order {
            overlay.local_hash(idx, self.sigmods);
        }
        self.overlay = Some(overlay);
        Ok(())
    }

    /// One iteration of hashing on the Varnode overlays (`signatureIterate`).
    fn signature_iterate(&mut self) -> Result<()> {
        let overlay = self
            .overlay
            .as_mut()
            .ok_or_else(|| Error::Lowlevel("No current function".to_string()))?;
        for e in overlay.entries.iter_mut() {
            e.hash[1] = e.hash[0]; // flipVarnodes
        }
        let order: Vec<usize> = overlay.map.values().copied().collect();
        let mut neigh: Vec<usize> = Vec::new();
        for idx in order {
            let (skip, opid, startvn, num) = {
                let e = &overlay.entries[idx];
                (e.is_not_emitted() || e.is_terminal(), e.op, e.startvn, e.in_size)
            };
            if skip {
                continue;
            }
            let Some(opid) = opid else { continue };
            neigh.clear();
            for j in 0..num {
                let v = overlay.fd.op(opid).get_in(j + startvn);
                neigh.push(overlay.entry_of_collapse(v)?);
            }
            overlay.hash_in(idx, &neigh);
        }
        Ok(())
    }

    /// Generate all features for the current function (`generate`).
    pub fn generate(&mut self) -> Result<()> {
        let minusone = self.maxiter - 1;
        let firsthalf = minusone / 2;
        let secondhalf = minusone - firsthalf;
        self.signature_iterate()?;
        for _ in 0..firsthalf {
            self.signature_iterate()?;
        }

        // Do the block signatures incorporating varnode sigs halfway thru
        if self.maxblockiter >= 0 {
            let mut blockmap = self.initialize_blocks()?;
            for _ in 0..self.maxblockiter {
                self.signature_block_iterate(&mut blockmap)?;
            }
            self.collect_block_sigs(&blockmap)?;
        }

        for _ in 0..secondhalf {
            self.signature_iterate()?;
        }

        self.collect_varnode_sigs()?;
        self.overlay = None; // varnodeClear
        Ok(())
    }

    fn function(&self) -> Result<&'a Funcdata> {
        self.fd
            .ok_or_else(|| Error::Lowlevel("No current function".to_string()))
    }

    /// Allocate a BlockSigEntry for every basic block and compute its local hash (`initializeBlocks`).
    fn initialize_blocks(&self) -> Result<BTreeMap<i32, BlockSigEntry>> {
        let fd = self.function()?;
        let graph = fd.block(fd.get_basic_blocks());
        let mut blockmap = BTreeMap::new();
        for i in 0..graph.get_size() {
            let bid = graph.get_block(i);
            let bl = fd.block(bid);
            let mut localhash = bl.size_in() as HashWord;
            localhash <<= 8;
            localhash |= bl.size_out() as HashWord;
            blockmap.insert(
                bl.get_index(),
                BlockSigEntry {
                    bl: bid,
                    hash: [localhash, localhash],
                },
            );
        }
        Ok(blockmap)
    }

    /// One iteration of hashing on the block overlays (`signatureBlockIterate`).
    fn signature_block_iterate(&self, blockmap: &mut BTreeMap<i32, BlockSigEntry>) -> Result<()> {
        let fd = self.function()?;
        for e in blockmap.values_mut() {
            e.hash[1] = e.hash[0]; // flipBlocks
        }
        let keys: Vec<i32> = blockmap.keys().copied().collect();
        for key in keys {
            let bid = blockmap[&key].bl;
            let bl = fd.block(bid);
            let curhash = blockmap[&key].hash[1];
            let mut accum: HashWord = 0xbafabaca;
            for i in 0..bl.size_in() {
                // Make hash invariant on order of input blocks
                let inbid = bl.get_in(i);
                let inbl = fd.block(inbid);
                let inentry = blockmap
                    .get(&inbl.get_index())
                    .ok_or_else(|| Error::Lowlevel("Incoming block missing from signature map".to_string()))?;
                let mut tmphash = hash_mixin(curhash, inentry.hash[1]);
                if inbl.size_out() == 2 {
                    // The incoming block ends in a CBRANCH
                    if bl.get_in_rev_index(i) == 0 {
                        tmphash = hash_mixin(tmphash, 0x777 ^ 0x7abc7abc); // Incoming edge on FALSE condition
                    } else {
                        tmphash = hash_mixin(tmphash, 0x777); // Incoming edge on TRUE condition
                    }
                }
                accum = accum.wrapping_add(tmphash);
            }
            if let Some(e) = blockmap.get_mut(&key) {
                e.hash[0] = hash_mixin(curhash, accum);
            }
        }
        Ok(())
    }

    /// Emit the final hash of each Varnode as a VarnodeSignature feature (`collectVarnodeSigs`).
    fn collect_varnode_sigs(&mut self) -> Result<()> {
        let overlay = self
            .overlay
            .as_ref()
            .ok_or_else(|| Error::Lowlevel("No current function".to_string()))?;
        for &idx in overlay.map.values() {
            let e = &overlay.entries[idx];
            if e.is_not_emitted() {
                continue;
            }
            if let Some(v) = e.vn {
                self.sigs
                    .push(Signature::with_origin(e.hash[0], SignatureOrigin::Varnode(v)));
            }
        }
        Ok(())
    }

    /// Generate the block features: overlapping pairs of expression roots, a combined stand-alone COPY
    /// feature, and a pure control-flow feature per basic block (`collectBlockSigs`).
    fn collect_block_sigs(&mut self, blockmap: &BTreeMap<i32, BlockSigEntry>) -> Result<()> {
        let fd = self.function()?;
        let overlay = self
            .overlay
            .as_ref()
            .ok_or_else(|| Error::Lowlevel("No current function".to_string()))?;
        let mut out: Vec<Signature> = Vec::new();

        for entry in blockmap.values() {
            let bid = entry.bl;
            let mut lastop: Option<OpId> = None;
            let mut lasthash: HashWord = 0;
            let mut callhash: HashWord = 0;
            let mut copyhash: HashWord = 0;

            let ops: Vec<OpId> = fd.block(bid).basic().op.iter(&fd.obank.ops).collect();
            for opid in ops {
                let op = fd.op(opid);
                let (startind, stopind): (i32, i32);
                match op.code() {
                    OpCode::Call => {
                        // We don't care if the output is used or not, always include
                        callhash = callhash.wrapping_add(100001).wrapping_mul(0x78abbf);
                        startind = 1;
                        stopind = op.num_input();
                    }
                    OpCode::Callind => {
                        callhash = callhash.wrapping_add(123451).wrapping_mul(0x78abbf); // Slightly different than CALL
                        startind = 1;
                        stopind = op.num_input();
                    }
                    OpCode::Callother | OpCode::Store | OpCode::Return => {
                        startind = 1;
                        stopind = op.num_input();
                    }
                    OpCode::Cbranch => {
                        startind = 1;
                        stopind = 2;
                    }
                    OpCode::Branchind => {
                        startind = 0;
                        stopind = 1;
                    }
                    OpCode::Indirect | OpCode::Copy => {
                        if let Some(o) = op.get_out() {
                            let oe = &overlay.entries[overlay.entry_of(o)?];
                            if oe.is_standalone_copy() {
                                copyhash = copyhash.wrapping_add(oe.hash[0]);
                            }
                        }
                        continue;
                    }
                    _ => {
                        startind = 0; // Don't use
                        stopind = 0;
                    }
                }
                let outvn = op.get_out();
                if stopind == 0 {
                    match outvn {
                        Some(o) if fd.vn(o).has_no_descend() => {}
                        _ => continue,
                    }
                }
                let val: HashWord;
                if let Some(o) = outvn {
                    let oe = &overlay.entries[overlay.entry_of(o)?];
                    if oe.is_not_emitted() {
                        continue;
                    }
                    val = oe.hash[0];
                } else {
                    let mut v = op.code() as u32 as HashWord;
                    v = v ^ (v << 9) ^ (v << 18);
                    let mut accum: HashWord = 0;
                    for i in startind..stopind {
                        // Let hash be invariant under commutativity
                        let e = &overlay.entries[overlay.entry_of_collapse(op.get_in(i))?];
                        accum = accum.wrapping_add(hash_mixin(v, e.hash[0]));
                    }
                    v ^= accum; // Even if no inputs we still get hash of opcode
                    val = v;
                }
                let finalhash = if lastop.is_none() {
                    hash_mixin(val, entry.hash[0])
                } else {
                    hash_mixin(val, lasthash)
                };
                out.push(Signature::with_origin(
                    finalhash,
                    SignatureOrigin::Block {
                        block: bid,
                        op1: lastop,
                        op2: Some(opid),
                    },
                ));
                lastop = Some(opid);
                lasthash = val;
            }
            let mut finalhash = hash_mixin(entry.hash[0], 0x9b1c5f); // A hash with just block information
            if callhash != 0 {
                finalhash = hash_mixin(finalhash, callhash);
            }
            out.push(Signature::with_origin(
                finalhash,
                SignatureOrigin::Block {
                    block: bid,
                    op1: None,
                    op2: None,
                },
            ));
            if copyhash != 0 {
                copyhash = hash_mixin(copyhash, 0xa2de3c);
                out.push(Signature::with_origin(copyhash, SignatureOrigin::Copy(bid)));
            }
        }
        self.sigs.extend(out);
        Ok(())
    }

    /// The number of features currently generated.
    pub fn num_signatures(&self) -> usize {
        self.sigs.len()
    }

    /// The i-th feature.
    pub fn get_signature(&self, i: usize) -> Option<&Signature> {
        self.sigs.get(i)
    }

    /// The feature vector as a sorted array of hashes (`getSignatureVector`).
    pub fn get_signature_vector(&self) -> Vec<u32> {
        let mut feature: Vec<u32> = self.sigs.iter().map(|s| s.get_hash()).collect();
        feature.sort_unstable();
        feature
    }

    /// Combine all feature hashes into one overall hash (`getOverallHash`).
    pub fn get_overall_hash(&self) -> HashWord {
        let mut pool: HashWord = 0x12349876abacab;
        for f in self.get_signature_vector() {
            pool = hash_mixin(pool, f as HashWord);
        }
        pool
    }

    /// Sort all current features by hash.
    pub fn sort_by_hash(&mut self) {
        self.sigs.sort_by_key(|s| s.get_hash());
    }

    /// A brief description of every feature, one per line.
    pub fn print(&self) -> Result<String> {
        let fd = self.function()?;
        let mut s = String::new();
        for sig in &self.sigs {
            s.push_str(&sig.describe(fd));
            s.push('\n');
        }
        Ok(s)
    }

    /// Full details of all current features, encoded as `<signaturedesc>`.
    pub fn encode(&self, encoder: &mut dyn Encoder, glb: &Architecture) -> Result<()> {
        let fd = self.function()?;
        encoder.open_element(ELEM_SIGNATUREDESC);
        for sig in &self.sigs {
            sig.encode(encoder, fd, glb)?;
        }
        encoder.close_element(ELEM_SIGNATUREDESC);
        Ok(())
    }
}

/// Generate features for a single function and write them as a simple sequence of hashes
/// (upstream `simpleSignature`). The function must have been previously decompiled.
pub fn simple_signature(fd: &Funcdata, encoder: &mut dyn Encoder) -> Result<()> {
    let mut mgr = GraphSigManager::new(DEFAULT_SETTINGS)?;
    mgr.set_current_function(fd)?;
    mgr.generate()?;
    let feature = mgr.get_signature_vector();
    encoder.open_element(ELEM_SIGNATURES);
    if fd.has_unimplemented() {
        encoder.write_bool(ATTRIB_UNIMPL, true);
    }
    if fd.has_bad_data() {
        encoder.write_bool(ATTRIB_BADDATA, true);
    }
    for f in feature {
        encoder.open_element(ELEM_SIG);
        encoder.write_unsigned_integer(ATTRIB_VAL, f as u64);
        encoder.close_element(ELEM_SIG);
    }
    for i in 0..fd.num_calls() {
        let fc = &fd.callspecs[fd.get_call_specs(i)];
        let addr: &Address = fc.get_entry_address();
        if !addr.is_invalid()
            && let Some(spc) = addr.get_space()
        {
            encoder.open_element(ELEM_CALL);
            encoder.write_space(ATTRIB_SPACE, spc);
            encoder.write_unsigned_integer(ATTRIB_OFFSET, addr.get_offset());
            encoder.close_element(ELEM_CALL);
        }
    }
    encoder.close_element(ELEM_SIGNATURES);
    Ok(())
}

/// Generate features with a complete per-feature description (upstream `debugSignature`).
pub fn debug_signature(fd: &Funcdata, encoder: &mut dyn Encoder, glb: &Architecture) -> Result<()> {
    let mut mgr = GraphSigManager::new(DEFAULT_SETTINGS)?;
    mgr.set_current_function(fd)?;
    mgr.generate()?;
    mgr.sort_by_hash();
    mgr.encode(encoder, glb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_validation_matches_upstream() {
        assert!(!GraphSigManager::test_settings(0));
        assert!(GraphSigManager::test_settings(DEFAULT_SETTINGS));
        assert!(GraphSigManager::test_settings(1));
        // Check bit is required to be set only via mask; stray low bits above the mask are rejected
        assert!(!GraphSigManager::test_settings(0x2));
        assert!(!GraphSigManager::test_settings(1 | (1 << 20)));
    }

    #[test]
    fn hash_size_collapses_large_sizes() {
        assert_eq!(hash_size(1, 0), 1 ^ (1 << 7) ^ (1 << 14) ^ (1 << 21));
        assert_eq!(hash_size(8, SIG_COLLAPSE_SIZE), hash_size(4, 0));
        assert_ne!(hash_size(8, 0), hash_size(4, 0));
    }

    #[test]
    fn mixin_is_order_sensitive_and_deterministic() {
        let a = hash_mixin(0x1234, 0x5678);
        assert_eq!(a, hash_mixin(0x1234, 0x5678));
        assert_ne!(a, hash_mixin(0x5678, 0x1234));
    }

    /// Reference values produced by compiling upstream Ghidra's `crc32.cc` and `hash_mixin` from
    /// `signature.cc` (Ghidra master, tree 4718f50d) with g++ and printing the results.
    #[test]
    fn hash_mixin_matches_upstream_cpp() {
        let vectors: [(u64, u64, u64); 10] = [
            (0x0, 0x0, 0x0),
            (0x1, 0x1, 0xccaa009e416d38df),
            (0x1234, 0x5678, 0x3fb056a88338569f),
            (0x5678, 0x1234, 0xf1c6d0601369b098),
            (0x12349876abacab, 0xdeadbeef, 0x57aa4dadf01e2423),
            (u64::MAX, u64::MAX, 0xdebb20e3897004e9),
            (0x0123456789abcdef, 0xfedcba9876543210, 0x153a900f096d824b),
            (0xa0a0a0a0, 0x777 ^ 0x7abc7abc, 0x7419c1eaf7b543d4),
            (0x9b1c5f, 0xa2de3c, 0x7d4a8ecf57102b3a),
            (0xbafabaca, 0x777, 0x6332a607041b0604),
        ];
        for (a, b, expected) in vectors {
            assert_eq!(hash_mixin(a, b), expected, "hash_mixin({a:#x}, {b:#x})");
        }
    }

    /// `SigManager::getOverallHash` folds the sorted feature hashes into the pool `0x12349876abacab`.
    #[test]
    fn overall_hash_pool_matches_upstream_cpp() {
        let mut pool: HashWord = 0x12349876abacab;
        for f in [1u32, 2, 3, 0xdeadbeef] {
            pool = hash_mixin(pool, f as HashWord);
        }
        assert_eq!(pool, 0x761258bdfab397f1);
    }

    #[test]
    fn config_stream_parses_like_upstream() {
        let mut m = GraphSigManager::new(DEFAULT_SETTINGS).unwrap();
        m.initialize_from_str("  7 ");
        assert_eq!(m.maxiter, 7);
        m.initialize_from_str("0x10");
        assert_eq!(m.maxiter, 16);
        m.initialize_from_str("-1");
        assert_eq!(m.maxiter, 16);
        m.initialize_from_str("garbage");
        assert_eq!(m.maxiter, 16);
    }
}
