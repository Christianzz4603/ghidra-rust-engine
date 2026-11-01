//! High-level reconstruction evidence for the independent Rust decompiler.
//!
//! Findings are explicitly evidence-based. Optimized machine code can erase
//! source-level variable boundaries and type information, so uncertain results
//! remain heuristic instead of being presented as recovered source truth.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::error::Result;
use crate::intelligence::{BinaryIntelligence, Confidence, ControlFlowGraph, FlowKind, FunctionAnalysisFailure};
use crate::microcode::{MicrocodeAnalyzer, MicrocodeLocation, VarnodeIdentity};
use crate::opcodes::{get_opname, OpCode};
use crate::program::{FunctionEntry, Instruction, InstructionPcode, PcodeOperation, Program};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredRegionKind { If, IfElse, Loop, SwitchCandidate, Unstructured }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredRegion {
    pub kind: StructuredRegionKind,
    pub header: u64,
    pub join: Option<u64>,
    pub members: Vec<u64>,
    pub confidence: Confidence,
    pub evidence: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlFlowReconstruction {
    pub block_count: usize,
    pub edge_count: usize,
    pub dominators: BTreeMap<u64, Vec<u64>>,
    pub loop_headers: Vec<u64>,
    pub regions: Vec<StructuredRegion>,
    pub irreducible_scc_candidates: Vec<Vec<u64>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableLifetime {
    pub variable: VarnodeIdentity,
    pub first_definition: Option<MicrocodeLocation>,
    pub last_definition: Option<MicrocodeLocation>,
    pub first_use: Option<MicrocodeLocation>,
    pub last_use: Option<MicrocodeLocation>,
    pub definition_count: usize,
    pub use_count: usize,
    pub live_range: Option<(usize, usize)>,
    pub crosses_basic_block_boundary: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterEvidence {
    pub ordinal: usize,
    pub storage: VarnodeIdentity,
    pub size_bytes: u32,
    pub first_read: MicrocodeLocation,
    pub confidence: Confidence,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnEvidence {
    pub observed_sizes: Vec<u32>,
    pub return_operations: usize,
    pub confidence: Confidence,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconstructedSignature {
    pub function_address: u64,
    pub function_name: String,
    pub parameters: Vec<ParameterEvidence>,
    pub return_value: ReturnEvidence,
    pub calling_convention: Option<String>,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpressionNode {
    pub id: usize,
    pub address: u64,
    pub opcode: String,
    pub output: Option<VarnodeIdentity>,
    pub operands: Vec<ExpressionOperand>,
    pub complexity: usize,
    pub side_effecting: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpressionOperand {
    Constant { value: u64, size_bytes: u32 },
    Expression { node: usize },
    Variable(VarnodeIdentity),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpressionReconstruction {
    pub nodes: Vec<ExpressionNode>,
    pub roots: Vec<usize>,
    pub maximum_complexity: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompilerPatternKind {
    StackFrameSetup, StackFrameTeardown, StackCanary,
    PositionIndependentAddressing, TailCall, FunctionThunk,
    LoopVectorizationCandidate, MultiplyAccumulate, CompareAndSelect, BitMasking, JumpTableDispatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerPattern {
    pub kind: CompilerPatternKind,
    pub address: u64,
    pub confidence: Confidence,
    pub evidence: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HighLevelReconstruction {
    pub type_recovery: crate::type_recovery::TypeRecoveryReport,
    pub control_flow: ControlFlowReconstruction,
    pub variables: Vec<VariableLifetime>,
    pub signature: Option<ReconstructedSignature>,
    pub expressions: ExpressionReconstruction,
    pub compiler_patterns: Vec<CompilerPattern>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionReconstruction {
    pub function: FunctionEntry,
    /// Native decompiler output, including its recovered C-like declaration.
    pub pseudocode: String,
    /// Best-effort first-line declaration extracted from the native output.
    pub decompiler_declaration: Option<String>,
    pub result: HighLevelReconstruction,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DecompilerReconstructor;

impl DecompilerReconstructor {
    pub fn reconstruct_function(&self, program: &mut Program, address: u64) -> Result<FunctionReconstruction> {
        let function = program.functions()?.into_iter().find(|f| f.address == address)
            .ok_or_else(|| crate::Error::Lowlevel(format!("no function found at {address:#x}")))?;

        let cfg = {
            let mut intelligence = BinaryIntelligence::new(program);
            intelligence.analyze_one(address)?.control_flow_graphs.into_iter().next()
        };
        let size = program.function_size(address)?;
        let instructions = if size == 0 { Vec::new() } else { program.disassemble_range(address, size)? };
        let pseudocode = program.decompile(address)?;
        let decompiler_declaration = extract_declaration(&pseudocode);
        let pcode = program.function_pcode(address)?;
        let microcode = MicrocodeAnalyzer.analyze_instructions(&pcode);
        let type_recovery = crate::type_recovery::TypeRecoveryAnalyzer.analyze(&pcode);
        let mut control_flow = cfg.as_ref().map(reconstruct_control_flow).unwrap_or_default();
        add_jump_table_candidates(&mut control_flow, &pcode);
        let variables = reconstruct_lifetimes(&pcode, cfg.as_ref());
        let signature = Some(reconstruct_signature(&function, &pcode));
        let expressions = reconstruct_expressions(&pcode);
        let compiler_patterns = detect_compiler_patterns(&instructions, &pcode);
        let mut notes = vec![
            "Control-flow regions, lifetimes, prototypes, and compiler patterns are evidence-based reconstructions.".into(),
            "Optimized binaries can erase source-level variable boundaries and types; ambiguous findings remain heuristic.".into(),
        ];
        if control_flow.regions.iter().any(|r| r.kind == StructuredRegionKind::Unstructured) {
            notes.push("At least one conditional edge could not be confidently represented as a structured region.".into());
        }
        if signature.as_ref().is_some_and(|s| s.parameters.is_empty()) {
            notes.push("No reliable incoming register or stack parameter storage was identified; this does not prove the function has no parameters.".into());
        }
        if microcode.operation_count == 0 {
            notes.push("No P-code operations were available for this function.".into());
        }
        Ok(FunctionReconstruction {
            function,
            pseudocode,
            decompiler_declaration,
            result: HighLevelReconstruction { type_recovery, control_flow, variables, signature, expressions, compiler_patterns, notes },
        })
    }

    pub fn reconstruct_all(&self, program: &mut Program) -> Result<Vec<std::result::Result<FunctionReconstruction, FunctionAnalysisFailure>>> {
        let mut entries = program.functions()?;
        entries.sort_by_key(|entry| entry.address);
        let mut output = Vec::with_capacity(entries.len());
        for entry in entries {
            match self.reconstruct_function(program, entry.address) {
                Ok(value) => output.push(Ok(value)),
                Err(error) => output.push(Err(FunctionAnalysisFailure {
                    address: entry.address, name: entry.name,
                    stage: "high-level reconstruction".into(), message: error.to_string(),
                })),
            }
        }
        Ok(output)
    }
}

fn extract_declaration(pseudocode: &str) -> Option<String> {
    let first = pseudocode.lines().find(|line| !line.trim().is_empty())?.trim();
    let declaration = first.split('{').next().unwrap_or(first).trim();
    (!declaration.is_empty()).then(|| declaration.to_string())
}

fn reconstruct_control_flow(cfg: &ControlFlowGraph) -> ControlFlowReconstruction {
    let nodes: Vec<u64> = cfg.blocks.iter().map(|b| b.start).collect();
    let Some(&entry) = nodes.first() else { return ControlFlowReconstruction::default() };
    let node_set: BTreeSet<u64> = nodes.iter().copied().collect();
    let mut predecessors = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut successors = BTreeMap::<u64, BTreeSet<u64>>::new();
    for edge in &cfg.edges {
        if let Some(to) = edge.to.filter(|to| node_set.contains(to)) {
            successors.entry(edge.from).or_default().insert(to);
            predecessors.entry(to).or_default().insert(edge.from);
        }
    }
    let mut dominators = BTreeMap::<u64, BTreeSet<u64>>::new();
    for node in &nodes {
        dominators.insert(*node, if *node == entry { BTreeSet::from([entry]) } else { node_set.clone() });
    }
    let mut changed = true;
    while changed {
        changed = false;
        for node in nodes.iter().copied().filter(|node| *node != entry) {
            let preds = predecessors.get(&node).cloned().unwrap_or_default();
            let mut next = if let Some(first) = preds.iter().next() {
                dominators.get(first).cloned().unwrap_or_default()
            } else { BTreeSet::new() };
            for pred in preds.iter().skip(1) {
                let other = dominators.get(pred).cloned().unwrap_or_default();
                next = next.intersection(&other).copied().collect();
            }
            next.insert(node);
            if dominators.get(&node) != Some(&next) {
                dominators.insert(node, next);
                changed = true;
            }
        }
    }
    let mut result = ControlFlowReconstruction {
        block_count: cfg.blocks.len(), edge_count: cfg.edges.len(),
        dominators: dominators.iter().map(|(k,v)| (*k, v.iter().copied().collect())).collect(),
        ..Default::default()
    };
    for edge in &cfg.edges {
        let Some(target) = edge.to else { continue };
        if dominators.get(&edge.from).is_some_and(|set| set.contains(&target)) {
            result.loop_headers.push(target);
            result.regions.push(StructuredRegion {
                kind: StructuredRegionKind::Loop, header: target, join: Some(target),
                members: natural_loop_members(target, edge.from, &predecessors),
                confidence: edge.confidence,
                evidence: format!("Back edge from {:#x} to dominating block {target:#x}", edge.from),
            });
        }
    }
    result.loop_headers.sort_unstable();
    result.loop_headers.dedup();
    for edge in cfg.edges.iter().filter(|e| e.kind == FlowKind::ConditionalBranch) {
        let Some(branch_target) = edge.to else { continue };
        let Some(fallthrough) = cfg.edges.iter().find(|e| e.from == edge.from && e.kind == FlowKind::Fallthrough).and_then(|e| e.to) else {
            result.regions.push(StructuredRegion {
                kind: StructuredRegionKind::Unstructured, header: edge.from, join: None,
                members: vec![edge.from, branch_target], confidence: Confidence::Heuristic,
                evidence: "Conditional branch has no recovered fallthrough edge".into(),
            });
            continue;
        };
        let branch_reach = reachable(branch_target, &successors);
        let fall_reach = reachable(fallthrough, &successors);
        let join = branch_reach.intersection(&fall_reach).copied().min_by_key(|candidate| {
            dominators.get(candidate).map_or(usize::MAX, |set| usize::MAX - set.len())
        });
        let kind = if join.is_some() { StructuredRegionKind::IfElse } else { StructuredRegionKind::If };
        let mut members = branch_reach.union(&fall_reach).copied().collect::<Vec<_>>();
        members.sort_unstable();
        result.regions.push(StructuredRegion {
            kind, header: edge.from, join, members, confidence: Confidence::Heuristic,
            evidence: "Conditional branch with two reachable paths; join is an approximation".into(),
        });
    }
    result.irreducible_scc_candidates = irreducible_components(&nodes, &successors, &predecessors);
    for (source, targets) in &successors {
        if targets.len() >= 3 {
            result.regions.push(StructuredRegion {
                kind: StructuredRegionKind::SwitchCandidate, header: *source, join: None,
                members: targets.iter().copied().collect(), confidence: Confidence::Heuristic,
                evidence: format!("Dispatch block has {} outgoing targets", targets.len()),
            });
        }
    }
    result
}

fn irreducible_components(
    nodes: &[u64],
    successors: &BTreeMap<u64, BTreeSet<u64>>,
    predecessors: &BTreeMap<u64, BTreeSet<u64>>,
) -> Vec<Vec<u64>> {
    fn finish(node: u64, successors: &BTreeMap<u64, BTreeSet<u64>>, seen: &mut BTreeSet<u64>, order: &mut Vec<u64>) {
        if !seen.insert(node) { return; }
        for next in successors.get(&node).into_iter().flatten() {
            finish(*next, successors, seen, order);
        }
        order.push(node);
    }
    fn collect(node: u64, predecessors: &BTreeMap<u64, BTreeSet<u64>>, seen: &mut BTreeSet<u64>, component: &mut Vec<u64>) {
        if !seen.insert(node) { return; }
        component.push(node);
        for next in predecessors.get(&node).into_iter().flatten() {
            collect(*next, predecessors, seen, component);
        }
    }
    let mut seen = BTreeSet::new();
    let mut order = Vec::new();
    for node in nodes { finish(*node, successors, &mut seen, &mut order); }
    seen.clear();
    let mut irreducible = Vec::new();
    for node in order.into_iter().rev() {
        if seen.contains(&node) { continue; }
        let mut component = Vec::new();
        collect(node, predecessors, &mut seen, &mut component);
        let cyclic = component.len() > 1 || successors.get(&node).is_some_and(|set| set.contains(&node));
        if !cyclic { continue; }
        let members: BTreeSet<u64> = component.iter().copied().collect();
        let entry_count = component.iter().filter(|target| {
            predecessors.get(target).into_iter().flatten().any(|pred| !members.contains(pred))
        }).count();
        if entry_count > 1 {
            component.sort_unstable();
            irreducible.push(component);
        }
    }
    irreducible
}

fn add_jump_table_candidates(result: &mut ControlFlowReconstruction, pcode: &[InstructionPcode]) {
    let flat: Vec<_> = pcode.iter().flat_map(|instruction| {
        instruction.operations.iter().map(move |operation| (instruction.address, operation.opcode))
    }).collect();
    for (index, (address, opcode)) in flat.iter().enumerate() {
        if *opcode != OpCode::Branchind { continue; }
        let start = index.saturating_sub(12);
        let window = &flat[start..index];
        let has_table_load = window.iter().any(|(_, op)| *op == OpCode::Load);
        let has_index_math = window.iter().any(|(_, op)| matches!(op, OpCode::IntMult | OpCode::Ptradd | OpCode::IntLeft | OpCode::IntAdd));
        if has_table_load && has_index_math {
            result.regions.push(StructuredRegion {
                kind: StructuredRegionKind::SwitchCandidate,
                header: *address,
                join: None,
                members: Vec::new(),
                confidence: Confidence::Heuristic,
                evidence: "Indirect branch preceded by indexed address arithmetic and a memory load, consistent with a compiler jump table".into(),
            });
        }
    }
}

fn natural_loop_members(header: u64, tail: u64, predecessors: &BTreeMap<u64, BTreeSet<u64>>) -> Vec<u64> {
    let mut members = BTreeSet::from([header, tail]);
    let mut work = vec![tail];
    while let Some(node) = work.pop() {
        for pred in predecessors.get(&node).into_iter().flatten() {
            if members.insert(*pred) && *pred != header { work.push(*pred); }
        }
    }
    members.into_iter().collect()
}

fn reachable(start: u64, successors: &BTreeMap<u64, BTreeSet<u64>>) -> BTreeSet<u64> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(node) = queue.pop_front() {
        if !seen.insert(node) { continue; }
        for next in successors.get(&node).into_iter().flatten() { queue.push_back(*next); }
    }
    seen
}

fn reconstruct_lifetimes(pcode: &[InstructionPcode], cfg: Option<&ControlFlowGraph>) -> Vec<VariableLifetime> {
    #[derive(Default)]
    struct Facts {
        first_def: Option<MicrocodeLocation>, last_def: Option<MicrocodeLocation>,
        first_use: Option<MicrocodeLocation>, last_use: Option<MicrocodeLocation>,
        defs: usize, uses: usize, first: usize, last: usize,
    }
    let mut facts = BTreeMap::<VarnodeIdentity, Facts>::new();
    let mut ordinal = 0usize;
    for (instruction_index, instruction) in pcode.iter().enumerate() {
        for (operation_index, operation) in instruction.operations.iter().enumerate() {
            let location = MicrocodeLocation {
                instruction_address: instruction.address, instruction_index, operation_index, ordinal,
            };
            ordinal += 1;
            if let Some(output) = &operation.output {
                let fact = facts.entry(VarnodeIdentity::from(output)).or_default();
                if fact.defs + fact.uses == 0 { fact.first = location.ordinal; }
                fact.first_def.get_or_insert(location);
                fact.last_def = Some(location);
                fact.defs += 1;
                fact.last = location.ordinal;
            }
            for input in &operation.inputs {
                if input.space == "const" { continue; }
                let fact = facts.entry(VarnodeIdentity::from(input)).or_default();
                if fact.defs + fact.uses == 0 { fact.first = location.ordinal; }
                fact.first_use.get_or_insert(location);
                fact.last_use = Some(location);
                fact.uses += 1;
                fact.last = location.ordinal;
            }
        }
    }
    let boundaries: BTreeSet<u64> = cfg.into_iter().flat_map(|g| g.blocks.iter().map(|b| b.start)).collect();
    let mut values: Vec<_> = facts.into_iter().map(|(variable, f)| {
        let first = f.first_def.or(f.first_use);
        let last = f.last_use.or(f.last_def);
        let first_addr = first.map(|x| x.instruction_address).unwrap_or(0);
        let last_addr = last.map(|x| x.instruction_address).unwrap_or(0);
        let crosses = first_addr < last_addr && boundaries.range((first_addr + 1)..=last_addr).next().is_some();
        VariableLifetime {
            variable, first_definition: f.first_def, last_definition: f.last_def,
            first_use: f.first_use, last_use: f.last_use, definition_count: f.defs, use_count: f.uses,
            live_range: Some((f.first, f.last)), crosses_basic_block_boundary: crosses,
        }
    }).collect();
    values.sort_by_key(|v| v.live_range.map(|r| r.0).unwrap_or(usize::MAX));
    values
}

fn reconstruct_signature(function: &FunctionEntry, pcode: &[InstructionPcode]) -> ReconstructedSignature {
    let mut defined = BTreeSet::<VarnodeIdentity>::new();
    let mut incoming = BTreeMap::<VarnodeIdentity, MicrocodeLocation>::new();
    let mut return_ops = 0usize;
    let mut ordinal = 0usize;
    for (instruction_index, instruction) in pcode.iter().enumerate() {
        for (operation_index, operation) in instruction.operations.iter().enumerate() {
            let location = MicrocodeLocation {
                instruction_address: instruction.address, instruction_index, operation_index, ordinal,
            };
            ordinal += 1;
            for input in &operation.inputs {
                if input.space == "const" || !matches!(input.space.as_str(), "register" | "stack") { continue; }
                let id = VarnodeIdentity::from(input);
                if !defined.contains(&id) { incoming.entry(id).or_insert(location); }
            }
            if operation.opcode == OpCode::Return { return_ops += 1; }
            if let Some(output) = &operation.output { defined.insert(VarnodeIdentity::from(output)); }
        }
    }
    let mut ordered: Vec<_> = incoming.into_iter().collect();
    ordered.sort_by_key(|(_, location)| location.ordinal);
    let parameters = ordered.into_iter().enumerate().map(|(ordinal, (storage, first_read))| ParameterEvidence {
        ordinal, size_bytes: storage.size, storage, first_read, confidence: Confidence::Heuristic,
        evidence: "Register or stack storage is read before a definition; ABI argument assignment is not yet proven".into(),
    }).collect();
    ReconstructedSignature {
        function_address: function.address, function_name: function.name.clone(), parameters,
        return_value: ReturnEvidence {
            observed_sizes: Vec::new(), return_operations: return_ops, confidence: Confidence::Heuristic,
            evidence: "Return instructions were counted. ABI return registers, values, and return types require architecture-specific calling-convention analysis".into(),
        },
        calling_convention: None, confidence: Confidence::Heuristic,
    }
}

fn reconstruct_expressions(pcode: &[InstructionPcode]) -> ExpressionReconstruction {
    let mut nodes = Vec::<ExpressionNode>::new();
    let mut latest = BTreeMap::<VarnodeIdentity, usize>::new();
    let mut used = BTreeSet::<usize>::new();
    let mut maximum_complexity = 0usize;
    for instruction in pcode {
        for operation in &instruction.operations {
            let mut operands = Vec::with_capacity(operation.inputs.len());
            let mut complexity = 1usize;
            for input in &operation.inputs {
                if input.space == "const" {
                    operands.push(ExpressionOperand::Constant { value: input.offset, size_bytes: input.size });
                } else {
                    let identity = VarnodeIdentity::from(input);
                    if let Some(node) = latest.get(&identity).copied() {
                        used.insert(node);
                        complexity = complexity.saturating_add(nodes[node].complexity);
                        operands.push(ExpressionOperand::Expression { node });
                    } else { operands.push(ExpressionOperand::Variable(identity)); }
                }
            }
            let id = nodes.len();
            let side_effecting = is_side_effecting(operation);
            nodes.push(ExpressionNode {
                id, address: instruction.address, opcode: get_opname(operation.opcode).to_string(),
                output: operation.output.as_ref().map(VarnodeIdentity::from), operands, complexity, side_effecting,
            });
            maximum_complexity = maximum_complexity.max(complexity);
            if let Some(output) = &operation.output { latest.insert(VarnodeIdentity::from(output), id); }
        }
    }
    let roots = nodes.iter().filter(|n| !used.contains(&n.id) || n.side_effecting).map(|n| n.id).collect();
    ExpressionReconstruction { nodes, roots, maximum_complexity }
}

fn is_side_effecting(operation: &PcodeOperation) -> bool {
    matches!(operation.opcode, OpCode::Load | OpCode::Store | OpCode::Call | OpCode::Callind |
        OpCode::Callother | OpCode::Branch | OpCode::Cbranch | OpCode::Branchind | OpCode::Return)
}

fn detect_compiler_patterns(instructions: &[Instruction], pcode: &[InstructionPcode]) -> Vec<CompilerPattern> {
    let mut found = Vec::new();
    let first_addr = instructions.first().map(|i| i.address).unwrap_or(0);
    let last_addr = instructions.last().map(|i| i.address).unwrap_or(first_addr);
    let text: Vec<String> = instructions.iter().map(|i| format!("{} {}", i.mnemonic, i.operands).to_ascii_lowercase()).collect();
    let joined = text.join("\n");
    if text.iter().take(8).any(|s| s.contains("push") && s.contains("rbp"))
        && text.iter().take(8).any(|s| s.contains("mov") && s.contains("rbp") && s.contains("rsp")) {
        found.push(pattern(CompilerPatternKind::StackFrameSetup, first_addr, "x86 frame-pointer save and establishment sequence"));
    }
    if text.iter().take(8).any(|s| s.contains("stp") && s.contains("x29") && s.contains("x30"))
        && text.iter().take(8).any(|s| (s.contains("mov") || s.contains("add")) && s.contains("x29") && s.contains("sp")) {
        found.push(pattern(CompilerPatternKind::StackFrameSetup, first_addr, "AArch64 frame/link-register save and frame-pointer setup"));
    }
    if text.iter().rev().take(8).any(|s| s.contains("leave") || (s.contains("mov") && s.contains("rsp") && s.contains("rbp")))
        || text.iter().rev().take(8).any(|s| s.contains("ldp") && s.contains("x29") && s.contains("x30")) {
        found.push(pattern(CompilerPatternKind::StackFrameTeardown, last_addr, "Frame restoration sequence near function exit"));
    }
    if joined.contains("__stack_chk_fail") || joined.contains("__security_check_cookie") {
        found.push(pattern(CompilerPatternKind::StackCanary, first_addr, "Known stack-protector helper reference"));
    }
    if text.iter().any(|s| s.contains("@got") || s.contains("adrp") || s.contains("rip")) {
        found.push(pattern(CompilerPatternKind::PositionIndependentAddressing, first_addr, "PC-relative or global-offset-table addressing syntax"));
    }
    if instructions.last().is_some_and(|i| {
        let m = i.mnemonic.to_ascii_lowercase();
        m.starts_with("jmp") || m == "b" || m == "br" || m == "jr"
    }) {
        found.push(pattern(CompilerPatternKind::TailCall, last_addr, "Terminal unconditional transfer; target must be validated as a tail call"));
    }
    if instructions.len() <= 5 && text.iter().any(|s| s.starts_with("jmp") || s.starts_with("b ")) {
        found.push(pattern(CompilerPatternKind::FunctionThunk, first_addr, "Small forwarding-function candidate"));
    }
    let ops: Vec<OpCode> = pcode.iter().flat_map(|i| i.operations.iter().map(|o| o.opcode)).collect();
    if ops.windows(3).any(|w| w[0] == OpCode::IntMult && w[1] == OpCode::IntAdd) {
        found.push(pattern(CompilerPatternKind::MultiplyAccumulate, first_addr, "Multiply followed by addition in P-code"));
    }
    if ops.windows(2).any(|w| matches!(w[0], OpCode::IntLess | OpCode::IntLessequal | OpCode::IntSless | OpCode::IntSlessequal) && w[1] == OpCode::IntZext) {
        found.push(pattern(CompilerPatternKind::CompareAndSelect, first_addr, "Comparison result widened into an integer value"));
    }
    if ops.contains(&OpCode::Branchind) {
        let has_load = ops.contains(&OpCode::Load);
        let has_index = ops.iter().any(|op| matches!(op, OpCode::IntMult | OpCode::Ptradd | OpCode::IntLeft | OpCode::IntAdd));
        if has_load && has_index {
            found.push(pattern(CompilerPatternKind::JumpTableDispatch, first_addr, "Indirect branch with table load and index arithmetic"));
        }
    }
    if ops.iter().any(|op| matches!(op, OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor)) {
        found.push(pattern(CompilerPatternKind::BitMasking, first_addr, "Bitwise operations may encode masks, flags, or packed fields"));
    }
    if ops.iter().filter(|op| matches!(op, OpCode::FloatAdd | OpCode::FloatMult | OpCode::FloatDiv)).count() >= 4 {
        found.push(pattern(CompilerPatternKind::LoopVectorizationCandidate, first_addr, "Dense floating-point sequence; vectorization is only a candidate"));
    }
    found
}

fn pattern(kind: CompilerPatternKind, address: u64, evidence: &str) -> CompilerPattern {
    CompilerPattern { kind, address, confidence: Confidence::Heuristic, evidence: evidence.into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{BasicBlock, FlowEdge};
    use crate::program::Instruction;

    fn instruction(address: u64) -> Instruction {
        Instruction { address, length: 4, bytes: vec![0; 4], mnemonic: "nop".into(), operands: String::new() }
    }

    #[test]
    fn recognizes_a_back_edge_as_a_loop() {
        let cfg = ControlFlowGraph {
            function: 0x1000,
            blocks: vec![
                BasicBlock { start: 0x1000, end: 0x1004, instructions: vec![instruction(0x1000)] },
                BasicBlock { start: 0x1004, end: 0x1008, instructions: vec![instruction(0x1004)] },
            ],
            edges: vec![
                FlowEdge { from: 0x1000, to: Some(0x1004), kind: FlowKind::ConditionalBranch, confidence: Confidence::Heuristic },
                FlowEdge { from: 0x1000, to: Some(0x1004), kind: FlowKind::Fallthrough, confidence: Confidence::Confirmed },
                FlowEdge { from: 0x1004, to: Some(0x1000), kind: FlowKind::Branch, confidence: Confidence::Heuristic },
            ],
        };
        assert!(reconstruct_control_flow(&cfg).loop_headers.contains(&0x1000));
    }

    #[test]
    fn heuristic_patterns_are_explicitly_marked() {
        assert_eq!(pattern(CompilerPatternKind::TailCall, 0x4000, "branch").confidence, Confidence::Heuristic);
    }
}
