# Upstream Ghidra decompiler port audit

Audit baseline: NationalSecurityAgency/ghidra, master, tree commit
4718f50d9941b9d7b7ebd1febc2982f055560a73. The authoritative source inventory
is the upstream Ghidra/Features/Decompiler/src/decompile/cpp/Makefile.
This document separates the reusable decompiler core from Ghidra's Java-facing
host integration and command-line development utilities.

## Scope

The Rust crate is a standalone decompiler/library, not a complete replacement
for the entire Ghidra desktop application. The upstream Makefile separates
common core, decompiler core, SLEIGH decoder, Ghidra-specific host integration,
SLEIGH compiler, and special command-line/test programs.

## Port coverage map

| Upstream area | Rust implementation | Status |
| --- | --- | --- |
| Core address/space, XML and marshaling | address, space, xml, marshal, translate, pcoderaw, opcodes, float, globalcontext | Core equivalents present |
| Decompiler graph, blocks, variables and operations | graph, block, cover, varnode, op, variable, varmap, funcdata/*, heritage, flow, merge, subflow | Core equivalents present |
| Type system and prototype models | types/*, typeop, fspec, paramid, type_recovery | Core equivalents present; validate behavior and edge cases |
| Simplification/action engine | action, ruleaction/*, blockaction, coreaction/*, condexe, constseq, transform | Core equivalents present |
| C/Java output and pretty printing | printc/*, printjava, printlanguage, prettyprint | Core equivalents present |
| SLEIGH decoder and compiled SLA loading | sleigh, sleighbase, slghsymbol, slghpattern, slghpatexpress, semantics, pcodeparse/*, pcodecompile, slaformat, compression, context | Core equivalents present |
| Filesystem search-path manager | filemanage | Rust implementation; integrated into SLEIGH language discovery |
| FLIRT-style external signatures | flirt | Separate signature-format integration; not the same as Ghidra graph signatures |
| Ghidra graph-based function signatures | No direct equivalent identified | Missing |
| Dynamic rule compiler and unification language | No direct equivalent identified | Missing |
| SLEIGH source compiler (slgh_compile, slghparse, slghscan) | No complete compiler pipeline identified | Missing; current runtime consumes compiled SLA data |
| Ghidra Java/native host bridge | integration/ghidra-scripts/DecompileWithRustEngine.java | Initial Script Manager bridge only; not host parity |
| Ghidra-native adapters (ghidra_arch, inject_ghidra, ghidra_translate, loadimage_ghidra, typegrp_ghidra, database_ghidra, ghidra_context, cpool_ghidra, ghidra_process, comment_ghidra, string_ghidra, signature_ghidra) | No complete equivalents | Missing; design is documented in integration/README.md |
| Java process/result protocol (DecompInterface, DecompileResults) | Isolated CLI process invocation from GhidraScript | Partial; structured request/response and persistent process are missing |
| Console shell, sample program and C++ test driver | Rust CLI/examples/tests | Replaced with Rust-native interfaces |

The mapping is architectural, not proof that every Rust module is behaviorally
identical to its upstream C++ counterpart. Exact parity requires differential tests
over the same binaries, processor specifications, compiler specs, options and
expected pseudocode.

## Newly added FileManage implementation

src/filemanage.rs provides ordered resource search paths, file resolution,
prefix/suffix directory matching, child-directory enumeration, bounded recursive
discovery, path splitting and conservative Ghidra-root discovery. SLEIGH language
discovery reuses this shared implementation rather than duplicating directory scans.

## Ghidra host integration

The first host adapter is a Ghidra Script Manager bridge under integration/.
It launches the standalone CLI out-of-process, uses a temporary output file to avoid
pipe deadlocks, enforces a timeout and supports Ghidra cancellation. It currently
requires the original executable to remain available and assumes its address mapping
matches the Ghidra program. It does not yet transfer Ghidra's database memory, overlays,
patched bytes, symbols, relocations, compiler-spec state or datatype manager.

A complete host integration requires a versioned, bounded IPC protocol and adapters
for program architecture, image loading, database-backed symbols/types, context,
injections, comments/strings and signature metadata. Keep this bridge isolated from
Ghidra's UI JVM and treat all program-derived data as untrusted input.

## Highest-value remaining upstream gaps

1. Ghidra graph signatures (signature.cc/.hh): distinct from FLIRT. Port feature
   graph construction, deterministic hashing, serialization and validation tests.
2. Dynamic rule compiler and unification (unify.cc/.hh, rulecompile.cc/.hh):
   implement a lexer/parser, constraint graph and bounded rule execution model.
3. SLEIGH source compiler (slgh_compile, slghparse, slghscan): runtime decoding
   of compiled SLA files is not equivalent to compiling processor specification source.
4. Full Ghidra host protocol and adapters: transfer memory, symbols, types, calling
   conventions, relocations, context, overlays and cancellation through bounded IPC.
5. Differential correctness harness: run identical corpus inputs through upstream
   Ghidra and this Rust implementation, compare normalized P-code, control-flow,
   recovered types and pseudocode, and retain minimized failures.
6. Performance and robustness evidence: benchmark representative binaries, record
   memory/time per phase, fuzz parsers and decoders, and track regressions.

## Licensing and provenance

Ghidra is Apache-2.0 licensed. Preserve applicable upstream notices and attribution
when translating or adapting source. Keep newly designed implementations distinguishable
from mechanically translated code, and do not describe an unimplemented subsystem as complete.
