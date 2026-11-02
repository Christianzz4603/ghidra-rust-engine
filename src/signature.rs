//! Deterministic function-feature signatures inspired by Ghidra's graph-signature subsystem.
//!
//! This is an independent Rust implementation, not a byte-for-byte port of Ghidra's
//! internal signature format. It extracts normalized operation, block-shape, call,
//! constant-class and linear def-use features from the engine's P-code stream.

use std::collections::{BTreeMap, HashMap};

use crate::error::Result;
use crate::opcodes::get_opname;
use crate::program::{InstructionPcode, Program};

const MAGIC: &[u8; 4] = b"GHSG";
const FORMAT_VERSION: u16 = 1;
const MAX_DECODED_FEATURES: usize = 1_000_000;
const FEATURE_RECORD_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SignatureKind {
    Operation = 1,
    BlockShape = 2,
    CallShape = 3,
    ConstantClass = 4,
    DataFlow = 5,
}

impl TryFrom<u8> for SignatureKind {
    type Error = String;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Operation),
            2 => Ok(Self::BlockShape),
            3 => Ok(Self::CallShape),
            4 => Ok(Self::ConstantClass),
            5 => Ok(Self::DataFlow),
            _ => Err(format!("unknown signature feature kind {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureSettings {
    /// Replace literal constants with a bit-width class before hashing.
    pub normalize_constants: bool,
    /// Include call opcode and argument-shape features.
    pub include_calls: bool,
    /// Include linear P-code definition-to-use relationships.
    pub include_dataflow: bool,
    /// Hard upper bound on generated feature records.
    pub max_features: usize,
}

impl Default for SignatureSettings {
    fn default() -> Self {
        Self {
            normalize_constants: true,
            include_calls: true,
            include_dataflow: true,
            max_features: 100_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignatureFeature {
    pub kind: SignatureKind,
    pub hash: u32,
    pub weight: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionSignature {
    pub format_version: u16,
    pub settings: SignatureSettings,
    pub features: Vec<SignatureFeature>,
    pub overall_hash: u64,
}

impl FunctionSignature {
    /// Generate a signature from an already-decoded function P-code stream.
    pub fn generate(instructions: &[InstructionPcode], settings: SignatureSettings) -> Self {
        let mut features = Vec::new();
        let mut last_definition = HashMap::<(String, u64, u32), u32>::new();
        let mut block_ops = 0usize;
        let mut block_branches = 0usize;
        let mut block_calls = 0usize;

        for instruction in instructions {
            for operation in &instruction.operations {
                let opcode_name = get_opname(operation.opcode);
                let mut operation_hash = StableHash::new();
                operation_hash.bytes(b"operation");
                operation_hash.bytes(opcode_name.as_bytes());
                operation_hash.u64(operation.output.as_ref().map_or(0, |v| u64::from(v.size)));
                operation_hash.u64(operation.inputs.len() as u64);
                for input in &operation.inputs {
                    operation_hash.bytes(input.space.as_bytes());
                    operation_hash.u64(u64::from(input.size));
                }
                push_feature(&mut features, SignatureFeature {
                    kind: SignatureKind::Operation,
                    hash: operation_hash.finish32(),
                    weight: 1,
                });

                block_ops += 1;
                if is_branch(operation.opcode) {
                    block_branches += 1;
                }
                if is_call(operation.opcode) {
                    block_calls += 1;
                    if settings.include_calls {
                        let mut call_hash = StableHash::new();
                        call_hash.bytes(b"call");
                        call_hash.bytes(opcode_name.as_bytes());
                        call_hash.u64(operation.inputs.len() as u64);
                        for input in &operation.inputs {
                            call_hash.u64(u64::from(input.size));
                        }
                        push_feature(&mut features, SignatureFeature {
                            kind: SignatureKind::CallShape,
                            hash: call_hash.finish32(),
                            weight: 2,
                        });
                    }
                }

                for (input_index, input) in operation.inputs.iter().enumerate() {
                    if input.space == "const" {
                        let mut constant_hash = StableHash::new();
                        constant_hash.bytes(b"constant");
                        constant_hash.bytes(opcode_name.as_bytes());
                        constant_hash.u64(input_index as u64);
                        constant_hash.u64(u64::from(input.size));
                        if settings.normalize_constants {
                            constant_hash.u64(bit_width_class(input.offset));
                        } else {
                            constant_hash.u64(input.offset);
                        }
                        push_feature(&mut features, SignatureFeature {
                            kind: SignatureKind::ConstantClass,
                            hash: constant_hash.finish32(),
                            weight: 1,
                        });
                    } else if settings.include_dataflow {
                        let identity = (input.space.clone(), input.offset, input.size);
                        if let Some(definition_hash) = last_definition.get(&identity) {
                            let mut dataflow_hash = StableHash::new();
                            dataflow_hash.bytes(b"def-use");
                            dataflow_hash.u64(u64::from(*definition_hash));
                            dataflow_hash.bytes(opcode_name.as_bytes());
                            dataflow_hash.u64(input_index as u64);
                            push_feature(&mut features, SignatureFeature {
                                kind: SignatureKind::DataFlow,
                                hash: dataflow_hash.finish32(),
                                weight: 2,
                            });
                        }
                    }
                }

                if let Some(output) = &operation.output {
                    let mut definition_hash = StableHash::new();
                    definition_hash.bytes(opcode_name.as_bytes());
                    definition_hash.u64(u64::from(output.size));
                    last_definition.insert(
                        (output.space.clone(), output.offset, output.size),
                        definition_hash.finish32(),
                    );
                }

                if is_terminator(operation.opcode) {
                    add_block_feature(
                        &mut features,
                        block_ops,
                        block_branches,
                        block_calls,
                    );
                    block_ops = 0;
                    block_branches = 0;
                    block_calls = 0;
                }
            }
        }

        if block_ops != 0 {
            add_block_feature(&mut features, block_ops, block_branches, block_calls);
        }

        features.sort_unstable();
        if settings.max_features == 0 {
            features.clear();
        } else if features.len() > settings.max_features {
            features.truncate(settings.max_features);
        }
        let overall_hash = overall_hash(&features, settings);
        Self {
            format_version: FORMAT_VERSION,
            settings,
            features,
            overall_hash,
        }
    }

    /// Generate a signature directly from a function in a loaded Program.
    pub fn generate_from_program(
        program: &mut Program,
        function_address: u64,
        settings: SignatureSettings,
    ) -> Result<Self> {
        let pcode = program.function_pcode_shared(function_address)?;
        Ok(Self::generate(&pcode, settings))
    }

    /// Weighted multiset Jaccard similarity in the inclusive range [0, 1].
    pub fn similarity(&self, other: &Self) -> f32 {
        let mut left = BTreeMap::<(SignatureKind, u32), u64>::new();
        let mut right = BTreeMap::<(SignatureKind, u32), u64>::new();
        for feature in &self.features {
            *left.entry((feature.kind, feature.hash)).or_default() += u64::from(feature.weight);
        }
        for feature in &other.features {
            *right.entry((feature.kind, feature.hash)).or_default() += u64::from(feature.weight);
        }
        let mut intersection = 0u64;
        let mut union = 0u64;
        for key in left.keys().chain(right.keys()) {
            let a = left.get(key).copied().unwrap_or(0);
            let b = right.get(key).copied().unwrap_or(0);
            intersection += a.min(b);
            union += a.max(b);
        }
        if union == 0 { 1.0 } else { intersection as f32 / union as f32 }
    }

    /// Encode a compact, versioned binary signature. No platform-dependent fields
    /// or Rust type layouts are written to the stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(28 + self.features.len() * FEATURE_RECORD_SIZE);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&self.format_version.to_le_bytes());
        let flags = u8::from(self.settings.normalize_constants)
            | (u8::from(self.settings.include_calls) << 1)
            | (u8::from(self.settings.include_dataflow) << 2);
        output.push(flags);
        output.push(0);
        output.extend_from_slice(&(self.features.len() as u32).to_le_bytes());
        output.extend_from_slice(&(self.settings.max_features as u64).to_le_bytes());
        output.extend_from_slice(&self.overall_hash.to_le_bytes());
        for feature in &self.features {
            output.push(feature.kind as u8);
            output.push(0);
            output.extend_from_slice(&feature.weight.to_le_bytes());
            output.extend_from_slice(&feature.hash.to_le_bytes());
        }
        output
    }

    /// Decode a signature while validating version, flags, feature count and
    /// exact payload length before allocating the feature vector.
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, String> {
        if bytes.len() < 28 || &bytes[..4] != MAGIC {
            return Err("invalid or truncated GHSG signature header".into());
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FORMAT_VERSION {
            return Err(format!("unsupported GHSG signature version {version}"));
        }
        let flags = bytes[6];
        if flags & !0b111 != 0 || bytes[7] != 0 {
            return Err("signature contains unsupported flags or reserved bits".into());
        }
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if count > MAX_DECODED_FEATURES {
            return Err(format!("signature feature count {count} exceeds safety limit"));
        }
        let expected = 28usize
            .checked_add(count.checked_mul(FEATURE_RECORD_SIZE).ok_or("signature size overflow")?)
            .ok_or("signature size overflow")?;
        if bytes.len() != expected {
            return Err(format!("signature payload length mismatch: expected {expected}, got {}", bytes.len()));
        }
        let max_features_u64 = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
        let max_features = usize::try_from(max_features_u64).map_err(|_| "signature feature limit does not fit this platform")?;
        let stored_hash = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
        let mut features = Vec::with_capacity(count);
        let mut cursor = 28;
        for _ in 0..count {
            let kind = SignatureKind::try_from(bytes[cursor])?;
            if bytes[cursor + 1] != 0 {
                return Err("signature feature reserved byte must be zero".into());
            }
            let weight = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
            let hash = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
            features.push(SignatureFeature { kind, hash, weight });
            cursor += FEATURE_RECORD_SIZE;
        }
        features.sort_unstable();
        let settings = SignatureSettings {
            normalize_constants: flags & 1 != 0,
            include_calls: flags & 2 != 0,
            include_dataflow: flags & 4 != 0,
            max_features,
        };
        let computed_hash = overall_hash(&features, settings);
        if computed_hash != stored_hash {
            return Err("signature overall hash does not match its feature payload".into());
        }
        Ok(Self {
            format_version: version,
            settings,
            features,
            overall_hash: stored_hash,
        })
    }
}

fn push_feature(features: &mut Vec<SignatureFeature>, feature: SignatureFeature) {
    features.push(feature);
}

fn add_block_feature(features: &mut Vec<SignatureFeature>, operations: usize, branches: usize, calls: usize) {
    let mut hash = StableHash::new();
    hash.bytes(b"block-shape");
    hash.u64(operations as u64);
    hash.u64(branches as u64);
    hash.u64(calls as u64);
    features.push(SignatureFeature {
        kind: SignatureKind::BlockShape,
        hash: hash.finish32(),
        weight: 2,
    });
}

fn is_call(opcode: crate::opcodes::OpCode) -> bool {
    matches!(opcode, crate::opcodes::OpCode::Call | crate::opcodes::OpCode::Callind | crate::opcodes::OpCode::Callother)
}

fn is_branch(opcode: crate::opcodes::OpCode) -> bool {
    matches!(opcode, crate::opcodes::OpCode::Branch | crate::opcodes::OpCode::Cbranch | crate::opcodes::OpCode::Branchind)
}

fn is_terminator(opcode: crate::opcodes::OpCode) -> bool {
    is_branch(opcode) || matches!(opcode, crate::opcodes::OpCode::Return)
}

fn bit_width_class(value: u64) -> u64 {
    if value == 0 { 0 } else { u64::from(64 - value.leading_zeros()) }
}

fn overall_hash(features: &[SignatureFeature], settings: SignatureSettings) -> u64 {
    let mut hash = StableHash::new();
    hash.bytes(b"ghidra-rust-signature-v1");
    hash.u64(settings.normalize_constants as u64);
    hash.u64(settings.include_calls as u64);
    hash.u64(settings.include_dataflow as u64);
    for feature in features {
        hash.u64(u64::from(feature.kind as u8));
        hash.u64(u64::from(feature.hash));
        hash.u64(u64::from(feature.weight));
    }
    hash.finish64()
}

struct StableHash(u64);

impl StableHash {
    fn new() -> Self { Self(0xcbf29ce484222325) }

    fn bytes(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn u64(&mut self, value: u64) {
        for byte in value.to_le_bytes() {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn finish32(&self) -> u32 {
        (self.0 ^ (self.0 >> 32)) as u32
    }

    fn finish64(&self) -> u64 { self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::OpCode;
    use crate::program::{PcodeOperation, PcodeVarnode};

    fn vn(space: &str, offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode { space: space.into(), offset, size }
    }

    fn op(opcode: OpCode, output: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOperation {
        PcodeOperation { opcode, output, inputs, space: None }
    }

    fn sample(value: u64) -> Vec<InstructionPcode> {
        vec![
            InstructionPcode {
                address: 0x1000,
                length: 4,
                operations: vec![op(OpCode::Copy, Some(vn("unique", 8, 8)), vec![vn("const", value, 8)])],
            },
            InstructionPcode {
                address: 0x1004,
                length: 4,
                operations: vec![op(OpCode::IntAdd, Some(vn("unique", 16, 8)), vec![vn("unique", 8, 8), vn("const", 1, 8)])],
            },
            InstructionPcode {
                address: 0x1008,
                length: 4,
                operations: vec![op(OpCode::Return, None, vec![vn("unique", 16, 8)])],
            },
        ]
    }

    #[test]
    fn generation_is_deterministic() {
        let a = FunctionSignature::generate(&sample(7), SignatureSettings::default());
        let b = FunctionSignature::generate(&sample(7), SignatureSettings::default());
        assert_eq!(a, b);
        assert!(!a.features.is_empty());
    }

    #[test]
    fn normalized_constants_preserve_shape_across_values() {
        let a = FunctionSignature::generate(&sample(7), SignatureSettings::default());
        let b = FunctionSignature::generate(&sample(6), SignatureSettings::default());
        assert_eq!(a.overall_hash, b.overall_hash);
        assert_eq!(a.similarity(&b), 1.0);
    }

    #[test]
    fn raw_constant_mode_distinguishes_values() {
        let settings = SignatureSettings { normalize_constants: false, ..Default::default() };
        let a = FunctionSignature::generate(&sample(7), settings);
        let b = FunctionSignature::generate(&sample(9), settings);
        assert_ne!(a.overall_hash, b.overall_hash);
        assert!(a.similarity(&b) < 1.0);
    }

    #[test]
    fn binary_roundtrip_and_corruption_checks() {
        let signature = FunctionSignature::generate(&sample(7), SignatureSettings::default());
        let encoded = signature.encode();
        assert_eq!(FunctionSignature::decode(&encoded).unwrap(), signature);
        let mut corrupt = encoded;
        corrupt[0] = b'X';
        assert!(FunctionSignature::decode(&corrupt).is_err());
    }

    #[test]
    fn feature_limit_is_enforced() {
        let settings = SignatureSettings { max_features: 2, ..Default::default() };
        let signature = FunctionSignature::generate(&sample(7), settings);
        assert_eq!(signature.features.len(), 2);
    }

    #[test]
    fn empty_signatures_compare_as_identical() {
        let a = FunctionSignature::generate(&[], SignatureSettings::default());
        let b = FunctionSignature::generate(&[], SignatureSettings::default());
        assert_eq!(a.similarity(&b), 1.0);
    }
}
