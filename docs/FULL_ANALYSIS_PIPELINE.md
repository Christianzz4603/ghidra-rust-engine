# Full reverse-engineering pipeline

`AnalysisEngine::analyze_full` coordinates the current multi-pass engine:

1. Discover functions (unless disabled).
2. Identify known library functions using optional FLIRT signatures.
3. Run the existing base analysis pass.
4. Build cross-reference, control-flow, data-flow, and function-fingerprint evidence.
5. Reconstruct high-level function structures and native pseudocode.

```rust
use ghidra_decompiler::{
    AnalysisEngine, AnalysisOptions, FlirtAnalyzer, FlirtOptions,
};

let mut engine = AnalysisEngine::open(std::path::Path::new("sample"), None)?;
let signatures = FlirtAnalyzer::load_dir("signatures")?;
let report = engine.analyze_full(
    &AnalysisOptions::default(),
    Some((&signatures, &FlirtOptions::default())),
)?;
println!("Functions: {}", report.base.functions.len());
println!("FLIRT matches: {}", report.flirt.as_ref().map_or(0, |r| r.matches.len()));
println!("Xrefs: {}", report.intelligence.cross_references.len());
println!("Reconstructed functions: {}", report.reconstructions.len());
# Ok::<(), ghidra_decompiler::Error>(())
```

FLIRT can be omitted by passing `None`. The Dazhbog Lumina client remains a
separate metadata query interface; remote metadata is not automatically trusted
or merged into local types without a stable key and provenance check.

## Processor coverage

The default feature set now enables `all-processors`, including the processor
families represented by the repository's feature catalogue: 6502, 68000,
8048, 8051, 8085, AArch64, ARM, Atmel, BPF/eBPF, CP1600, CR16, Dalvik, Hexagon,
JVM, LoongArch, M16C, M8C, MC6800, MCS96, MIPS, NDS32, PA-RISC, PIC, PowerPC,
RISC-V, SPARC, SuperH, MSP430, TriCore, V850, x86, Xtensa, and Z80.

The processor feature catalogue controls the selected build profile. Actual
decoding/decompilation still depends on the language definition and SLEIGH
specification available in the repository. Enabling every feature does not
magically add missing language specifications or guarantee identical maturity
across processors. The `mobile` profile remains available for smaller builds.
