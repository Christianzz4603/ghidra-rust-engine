#![allow(
    clippy::mutable_key_type,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::if_same_then_else,
    clippy::while_let_loop,
    clippy::unnecessary_unwrap,
    clippy::field_reassign_with_default,
    clippy::needless_late_init,
    clippy::should_implement_trait
)]

pub mod action;
pub mod abi;
pub mod address;
pub mod analysis;
pub mod architecture;
pub mod arena;
pub mod bitfield;
pub mod block;
pub mod blockaction;
pub mod callgraph;
pub mod capability;
pub mod cast;
pub mod comment;
pub mod compression;
pub mod condexe;
pub mod constseq;
pub mod context;
pub mod coreaction;
pub mod cover;
pub mod cpool;
pub mod crc32;
pub mod database;
pub mod dex;
pub mod double;
pub mod dynamic;
pub mod embedded_languages;
pub mod emulate;
pub mod emulateutil;
pub mod error;
pub mod expression;
pub mod float;
pub mod flow;
pub mod fspec;
pub mod funcdata;
pub mod globalcontext;
pub mod grammar;
pub mod graph;
pub mod ghidra_host;
pub mod ghidra_worker;
pub mod heritage;
pub mod ifacedecomp;
pub mod inject_sleigh;
pub mod intelligence;
pub mod interface;
pub mod istream;
pub mod jumptable;
pub mod kotlin;
pub mod loadimage;
pub mod loadimage_xml;
pub mod marshal;
pub mod marshal_registry;
pub mod memstate;
pub mod merge;
pub mod modelrules;
pub mod multiprecision;
pub mod object_arch;
pub mod op;
pub mod opbehavior;
pub mod opcodes;
pub mod oplist;
pub mod options;
pub mod orderedindex;
pub mod overrides;
pub mod paramid;
pub mod partmap;
pub mod pcodecompile;
pub mod pcodeinject;
pub mod pcodeparse;
pub mod pcoderaw;
pub mod prefersplit;
pub mod prettyprint;
pub mod printc;
pub mod printjava;
pub mod printlanguage;
pub mod program;
pub mod pseudocode;
pub mod microcode;
pub mod reconstruction;
pub mod flirt;
pub mod filemanage;
#[cfg(feature = "lumina")]
pub mod lumina;
pub mod rangemap;
pub mod rangeutil;
pub mod raw_arch;
pub mod ruleaction;
pub mod semantics;
pub mod slaformat;
pub mod signature;
pub mod sleigh;
pub mod sleigh_arch;
pub mod sleighbase;
pub mod slghpatexpress;
pub mod slghpattern;
pub mod slghsymbol;
pub mod space;
pub mod ssa;
pub mod stdsort;
pub mod stringmanage;
pub mod subflow;
pub mod testfunction;
pub mod transform;
pub mod translate;
pub mod type_recovery;
pub mod typeop;
pub mod types;
pub mod unionresolve;
pub mod userop;
pub mod variable;
pub mod varmap;
pub mod varnode;
pub mod xml;
pub mod xml_arch;

pub use analysis::{
    AnalysisEngine, AnalysisEvent, AnalysisOptions, AnalysisReport, AnalysisSelection, FullAnalysisReport, FunctionAnalysis,
};
pub use error::{Error, Result};
pub use abi::{Abi, AbiArgumentAllocator, AbiLocation, AbiProfile, AbiValueClass};
pub use ssa::{SsaAnalyzer, SsaBlock, SsaDefinition, SsaOperation, SsaPhi, SsaReport, SsaUse, SsaVersion};
pub use intelligence::{
    BasicBlock, BinaryIntelligence, Confidence, ControlFlowGraph, CrossReference, DataFlowSummary, FlowEdge, FlowKind,
    FunctionFingerprint, FunctionPrototype, FunctionAnalysisFailure, IntelligenceReport, ReferenceKind, SimilarFunction, TypeEvidence,
};
pub use reconstruction::{CompilerPattern, CompilerPatternKind, ControlFlowReconstruction, DecompilerReconstructor, ExpressionNode, ExpressionOperand, ExpressionReconstruction, FunctionReconstruction, HighLevelReconstruction, ParameterEvidence, ReconstructedSignature, ReturnEvidence, StructuredRegion, StructuredRegionKind, VariableLifetime};
pub use microcode::{DefUseEdge, MicrocodeAnalyzer, MicrocodeLocation, MicrocodeReport, VarnodeIdentity};
pub use type_recovery::{RecoveredTypeKind, RecoveredVariableType, TypeConstraintEvidence, TypeRecoveryAnalyzer, TypeRecoveryReport};
pub use pseudocode::{DecompileBatch, DecompileFailure, FunctionPseudocode, PseudocodeDecompiler, PseudocodeLine, PseudocodeOptions};
pub use flirt::{FlirtAnalyzer, FlirtMatch, FlirtOptions, FlirtReport};
#[cfg(feature = "lumina")]
pub use lumina::LuminaClient;
pub use signature::{FunctionSignature, SignatureFeature, SignatureKind, SignatureSettings};
pub use ghidra_host::{CommentDescriptor, ContextValueDescriptor, DataTypeDescriptor, Endianness, FunctionDescriptor, ParameterDescriptor, HostCommand, HostRequest, HostResponse, MemoryBlock, ProgramSnapshot, ReferenceDescriptor, RelocationDescriptor, SymbolDescriptor};
pub use program::{
    CallEdge, CodeScanSummary, CodeSectionSummary, DataEntry, DisassemblyGap, DisassemblyReport, FunctionEntry,
    FunctionSource, ImportedDataType, ImportedFunctionSignature, ImportedParameter, Instruction, InstructionPcode, PcodeOperation, PcodeVarnode, Program, ProgramReference, ProgramRelocation, StringEntry, SymbolLoading,
};

pub use dex::{Apk, DexClass, DexFile, DexMethod};
pub use kotlin::{KotlinBuiltins, KotlinDeclaration, KotlinDeclarationKind};
