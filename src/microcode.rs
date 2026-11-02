//! Microcode data-flow analysis primitives for the independent decompiler.
//!
//! This is a conservative first layer: it builds linear def-use chains over
//! the backend's P-code stream. It does not claim SSA or CFG-wide reaching
//! definitions; those require block-sensitive data-flow and phi construction.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::Result;
use crate::opcodes::OpCode;
use crate::program::{InstructionPcode, PcodeOperation, PcodeVarnode, Program};

/// Stable location of an operation in a function's flattened P-code stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MicrocodeLocation {
    pub instruction_address: u64,
    pub instruction_index: usize,
    pub operation_index: usize,
    pub ordinal: usize,
}

/// A varnode storage identity. Constants are represented separately.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarnodeIdentity {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

impl From<&PcodeVarnode> for VarnodeIdentity {
    fn from(value: &PcodeVarnode) -> Self {
        Self {
            space: value.space.clone(),
            offset: value.offset,
            size: value.size,
        }
    }
}

/// One definition-to-use relationship in the linear instruction stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefUseEdge {
    pub definition: MicrocodeLocation,
    pub use_location: MicrocodeLocation,
    pub input_index: usize,
    pub varnode: VarnodeIdentity,
}

/// Operation-level facts suitable for decompiler optimization passes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MicrocodeReport {
    pub operation_count: usize,
    pub definition_count: usize,
    pub use_count: usize,
    pub constant_inputs: Vec<(MicrocodeLocation, usize, u64, u32)>,
    pub def_use: Vec<DefUseEdge>,
    pub unused_pure_definitions: Vec<MicrocodeLocation>,
    pub definitions_by_varnode: BTreeMap<VarnodeIdentity, Vec<MicrocodeLocation>>,
}

/// Configurable microcode analyzer over the backend's P-code representation.
#[derive(Clone, Copy, Debug, Default)]
pub struct MicrocodeAnalyzer;

impl MicrocodeAnalyzer {
    /// Analyze the P-code stream for a function entry.
    pub fn analyze(&self, program: &mut Program, address: u64) -> Result<MicrocodeReport> {
        let instructions = program.function_pcode_shared(address)?;
        Ok(self.analyze_instructions(&instructions))
    }

    /// Analyze an existing P-code stream without requiring a Program handle.
    pub fn analyze_instructions(&self, instructions: &[InstructionPcode]) -> MicrocodeReport {
        let mut report = MicrocodeReport::default();
        let mut last_definition = HashMap::<VarnodeIdentity, MicrocodeLocation>::new();
        let mut used_definitions = HashSet::<MicrocodeLocation>::new();
        let mut definitions = Vec::<(VarnodeIdentity, MicrocodeLocation, bool)>::new();

        for (instruction_index, instruction) in instructions.iter().enumerate() {
            for (operation_index, operation) in instruction.operations.iter().enumerate() {
                let location = MicrocodeLocation {
                    instruction_address: instruction.address,
                    instruction_index,
                    operation_index,
                    ordinal: report.operation_count,
                };
                report.operation_count += 1;

                for (input_index, input) in operation.inputs.iter().enumerate() {
                    report.use_count += 1;
                    if input.space == "const" {
                        report.constant_inputs.push((
                            location,
                            input_index,
                            input.offset,
                            input.size,
                        ));
                        continue;
                    }

                    let identity = VarnodeIdentity::from(input);
                    if let Some(definition) = last_definition.get(&identity).copied() {
                        used_definitions.insert(definition);
                        report.def_use.push(DefUseEdge {
                            definition,
                            use_location: location,
                            input_index,
                            varnode: identity,
                        });
                    }
                }

                if let Some(output) = &operation.output {
                    report.definition_count += 1;
                    let identity = VarnodeIdentity::from(output);
                    report
                        .definitions_by_varnode
                        .entry(identity.clone())
                        .or_default()
                        .push(location);
                    last_definition.insert(identity.clone(), location);
                    definitions.push((identity, location, is_effectful(operation)));
                }
            }
        }

        for (_, location, effectful) in definitions {
            if !effectful && !used_definitions.contains(&location) {
                report.unused_pure_definitions.push(location);
            }
        }

        report
    }
}

/// Operations with observable behavior must never be classified as dead
/// merely because their output is unused. Loads are retained conservatively.
fn is_effectful(operation: &PcodeOperation) -> bool {
    matches!(
        operation.opcode,
        OpCode::Load
            | OpCode::Store
            | OpCode::Call
            | OpCode::Callind
            | OpCode::Callother
            | OpCode::Branch
            | OpCode::Cbranch
            | OpCode::Branchind
            | OpCode::Return
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::OpCode;

    fn varnode(space: &str, offset: u64) -> PcodeVarnode {
        PcodeVarnode {
            space: space.into(),
            offset,
            size: 8,
        }
    }

    fn op(opcode: OpCode, output: Option<PcodeVarnode>, inputs: Vec<PcodeVarnode>) -> PcodeOperation {
        PcodeOperation {
            opcode,
            output,
            inputs,
            space: None,
        }
    }

    #[test]
    fn links_a_definition_to_its_later_use() {
        let instructions = vec![
            InstructionPcode {
                address: 0x1000,
                length: 4,
                operations: vec![op(OpCode::Copy, Some(varnode("unique", 8)), vec![varnode("const", 7)])],
            },
            InstructionPcode {
                address: 0x1004,
                length: 4,
                operations: vec![op(OpCode::IntAdd, Some(varnode("unique", 16)), vec![varnode("unique", 8), varnode("const", 1)])],
            },
        ];

        let report = MicrocodeAnalyzer.analyze_instructions(&instructions);
        assert_eq!(report.operation_count, 2);
        assert_eq!(report.definition_count, 2);
        assert_eq!(report.def_use.len(), 1);
        assert_eq!(report.def_use[0].definition.instruction_address, 0x1000);
        assert_eq!(report.unused_pure_definitions.len(), 1);
        assert_eq!(report.unused_pure_definitions[0].instruction_address, 0x1004);
        assert_eq!(report.constant_inputs.len(), 2);
    }

    #[test]
    fn preserves_unused_memory_effects() {
        let instructions = vec![InstructionPcode {
            address: 0x2000,
            length: 4,
            operations: vec![op(OpCode::Store, None, vec![varnode("const", 0), varnode("const", 1)])],
        }];

        let report = MicrocodeAnalyzer.analyze_instructions(&instructions);
        assert!(report.unused_pure_definitions.is_empty());
    }

    #[test]
    fn reports_an_unused_pure_result() {
        let instructions = vec![InstructionPcode {
            address: 0x3000,
            length: 4,
            operations: vec![op(OpCode::IntAdd, Some(varnode("unique", 32)), vec![varnode("const", 2), varnode("const", 3)])],
        }];

        let report = MicrocodeAnalyzer.analyze_instructions(&instructions);
        assert_eq!(report.unused_pure_definitions.len(), 1);
    }
}
