use crate::opcodes::OpCode;
use crate::program::{InstructionPcode, PcodeVarnode};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoveredTypeKind {
    Boolean,
    SignedInteger,
    UnsignedInteger,
    FloatingPoint,
    Pointer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeConstraintEvidence {
    pub variable: crate::microcode::VarnodeIdentity,
    pub kind: RecoveredTypeKind,
    pub observations: usize,
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredVariableType {
    pub variable: crate::microcode::VarnodeIdentity,
    pub inferred: Option<RecoveredTypeKind>,
    pub confidence_percent: u8,
    pub conflicting: bool,
    pub evidence: Vec<TypeConstraintEvidence>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeRecoveryReport {
    pub variables: Vec<RecoveredVariableType>,
    pub constrained_variables: usize,
    pub ambiguous_variables: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TypeRecoveryAnalyzer;

#[derive(Default)]
struct Votes {
    counts: BTreeMap<RecoveredTypeKind, usize>,
    operations: BTreeMap<RecoveredTypeKind, Vec<String>>,
}

impl TypeRecoveryAnalyzer {
    pub fn analyze(&self, instructions: &[InstructionPcode]) -> TypeRecoveryReport {
        let mut votes = BTreeMap::<crate::microcode::VarnodeIdentity, Votes>::new();
        for instruction in instructions {
            for operation in &instruction.operations {
                let name = crate::opcodes::get_opname(operation.opcode).to_string();
                let mut mark = |node: &PcodeVarnode, kind: RecoveredTypeKind| {
                    if node.space == "const" {
                        return;
                    }
                    let entry = votes.entry(node.into()).or_default();
                    *entry.counts.entry(kind).or_default() += 1;
                    let ops = entry.operations.entry(kind).or_default();
                    if !ops.contains(&name) {
                        ops.push(name.clone());
                    }
                };
                use RecoveredTypeKind::*;
                match operation.opcode {
                    OpCode::FloatAdd
                    | OpCode::FloatSub
                    | OpCode::FloatMult
                    | OpCode::FloatDiv
                    | OpCode::FloatNeg
                    | OpCode::FloatAbs
                    | OpCode::FloatSqrt
                    | OpCode::FloatNan
                    | OpCode::FloatEqual
                    | OpCode::FloatNotequal
                    | OpCode::FloatLess
                    | OpCode::FloatLessequal => {
                        if let Some(out) = &operation.output {
                            mark(out, FloatingPoint);
                        }
                        for input in &operation.inputs {
                            mark(input, FloatingPoint);
                        }
                        if matches!(
                            operation.opcode,
                            OpCode::FloatEqual
                                | OpCode::FloatNotequal
                                | OpCode::FloatLess
                                | OpCode::FloatLessequal
                                | OpCode::FloatNan
                        ) {
                            if let Some(out) = &operation.output {
                                mark(out, Boolean);
                            }
                        }
                    }
                    OpCode::FloatInt2float => {
                        if let Some(out) = &operation.output {
                            mark(out, FloatingPoint);
                        }
                        if let Some(input) = operation.inputs.first() {
                            mark(input, SignedInteger);
                        }
                    }
                    OpCode::FloatFloat2float => {
                        if let Some(out) = &operation.output {
                            mark(out, FloatingPoint);
                        }
                        for input in &operation.inputs {
                            mark(input, FloatingPoint);
                        }
                    }
                    OpCode::FloatTrunc | OpCode::FloatCeil | OpCode::FloatFloor | OpCode::FloatRound => {
                        if let Some(out) = &operation.output {
                            mark(out, SignedInteger);
                        }
                        for input in &operation.inputs {
                            mark(input, FloatingPoint);
                        }
                    }
                    OpCode::IntSless
                    | OpCode::IntSlessequal
                    | OpCode::IntSdiv
                    | OpCode::IntSrem
                    | OpCode::IntSright
                    | OpCode::IntScarry
                    | OpCode::IntSborrow
                    | OpCode::IntSext => {
                        if let Some(out) = &operation.output {
                            mark(
                                out,
                                if matches!(
                                    operation.opcode,
                                    OpCode::IntSless | OpCode::IntSlessequal | OpCode::IntScarry | OpCode::IntSborrow
                                ) {
                                    Boolean
                                } else {
                                    SignedInteger
                                },
                            );
                        }
                        for input in &operation.inputs {
                            mark(input, SignedInteger);
                        }
                    }
                    OpCode::IntLess
                    | OpCode::IntLessequal
                    | OpCode::IntDiv
                    | OpCode::IntRem
                    | OpCode::IntRight
                    | OpCode::IntCarry
                    | OpCode::IntZext => {
                        if let Some(out) = &operation.output {
                            mark(
                                out,
                                if matches!(
                                    operation.opcode,
                                    OpCode::IntLess | OpCode::IntLessequal | OpCode::IntCarry
                                ) {
                                    Boolean
                                } else {
                                    UnsignedInteger
                                },
                            );
                        }
                        for input in &operation.inputs {
                            mark(input, UnsignedInteger);
                        }
                    }
                    OpCode::IntEqual
                    | OpCode::IntNotequal
                    | OpCode::BoolNegate
                    | OpCode::BoolXor
                    | OpCode::BoolAnd
                    | OpCode::BoolOr => {
                        if let Some(out) = &operation.output {
                            mark(out, Boolean);
                        }
                    }
                    OpCode::Ptradd | OpCode::Ptrsub | OpCode::New => {
                        if let Some(out) = &operation.output {
                            mark(out, Pointer);
                        }
                        if let Some(base) = operation.inputs.first() {
                            mark(base, Pointer);
                        }
                        if let Some(index) = operation.inputs.get(1) {
                            mark(index, UnsignedInteger);
                        }
                    }
                    OpCode::Load | OpCode::Store => {
                        if let Some(address) = operation.inputs.get(1) {
                            mark(address, Pointer);
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut report = TypeRecoveryReport::default();
        for (variable, votes) in votes {
            let mut evidence: Vec<_> = votes
                .counts
                .iter()
                .map(|(kind, count)| TypeConstraintEvidence {
                    variable: variable.clone(),
                    kind: *kind,
                    observations: *count,
                    operations: votes.operations.get(kind).cloned().unwrap_or_default(),
                })
                .collect();
            evidence.sort_by(|a, b| b.observations.cmp(&a.observations).then(a.kind.cmp(&b.kind)));
            let total: usize = evidence.iter().map(|e| e.observations).sum();
            let winner = evidence.first();
            let runner = evidence.get(1);
            let conflicting = runner.is_some_and(|v| v.observations > 0);
            let inferred = winner
                .filter(|v| runner.is_none_or(|r| v.observations > r.observations))
                .map(|v| v.kind);
            let confidence_percent = winner.map_or(0, |v| ((v.observations * 100) / total.max(1)).min(100) as u8);
            report.constrained_variables += 1;
            if inferred.is_none() {
                report.ambiguous_variables += 1;
            }
            report.variables.push(RecoveredVariableType {
                variable,
                inferred,
                confidence_percent,
                conflicting,
                evidence,
            });
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::PcodeOperation;
    fn node(space: &str, offset: u64) -> PcodeVarnode {
        PcodeVarnode {
            space: space.into(),
            offset,
            size: 8,
        }
    }

    #[test]
    fn infers_float_and_pointer_from_semantic_constraints() {
        let p = vec![InstructionPcode {
            address: 0x1000,
            length: 4,
            operations: vec![
                PcodeOperation {
                    opcode: OpCode::FloatAdd,
                    output: Some(node("unique", 1)),
                    inputs: vec![node("unique", 2), node("unique", 3)],
                    space: None,
                },
                PcodeOperation {
                    opcode: OpCode::Load,
                    output: Some(node("unique", 4)),
                    inputs: vec![node("const", 0), node("unique", 5)],
                    space: None,
                },
            ],
        }];
        let r = TypeRecoveryAnalyzer.analyze(&p);
        assert_eq!(
            r.variables.iter().find(|v| v.variable.offset == 1).unwrap().inferred,
            Some(RecoveredTypeKind::FloatingPoint)
        );
        assert_eq!(
            r.variables.iter().find(|v| v.variable.offset == 5).unwrap().inferred,
            Some(RecoveredTypeKind::Pointer)
        );
    }

    #[test]
    fn preserves_conflicting_constraints_instead_of_guessing() {
        let p = vec![InstructionPcode {
            address: 0x2000,
            length: 4,
            operations: vec![
                PcodeOperation {
                    opcode: OpCode::FloatAdd,
                    output: Some(node("unique", 1)),
                    inputs: vec![],
                    space: None,
                },
                PcodeOperation {
                    opcode: OpCode::IntSdiv,
                    output: Some(node("unique", 1)),
                    inputs: vec![],
                    space: None,
                },
            ],
        }];
        let v = &TypeRecoveryAnalyzer.analyze(&p).variables[0];
        assert!(v.conflicting);
        assert_eq!(v.inferred, None);
    }
}
