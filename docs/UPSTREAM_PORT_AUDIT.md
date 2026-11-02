# Upstream Ghidra decompiler port audit

Audit baseline: NationalSecurityAgency/ghidra, master, tree commit
4718f50d9941b9d7b7ebd1febc2982f055560a73. The authoritative source inventory
is the upstream Ghidra/Features/Decompiler/src/decompile/cpp/Makefile.
This document separates the reusable decompiler core from Ghidra's Java-facing
host integration and command-line development utilities.

## Scope

The Rust crate is a standalone decompiler/library, not a complete replacement
for the entire Ghidra desktop application. The upstream Makefile itself
separates common core, decompiler core, SLEIGH decoder, Ghidra-specific host
integration, SLEIGH compiler, and special command-line/test programs. Those
categories must not be conflated when counting missing files.

## Port coverage map

| Upstream area | Rust implementation | Status |
| --- | --- | --- |
| Core address/space, XML and marshaling | address, space, xml, marshal, translate, pcoderaw, opcodes, float, globalcontext | Core equivalents present |
| Decompiler graph, blocks, variables and operations | graph, block, cover, varnode, op, variable, varmap, funcdata/*, heritage, flow, merge, subflow | Core equivalents present |
| Type system and prototype models | types/*, typeop, fspec, paramid, type_recovery | Core equivalents present; validate behavior and edge cases |
| Simplification/action engine | action, ruleaction/*, blockaction, coreaction/*, condexe, constseq, transform | Core equivalents present |
| C/Java output and pretty printing | printc/*, printjava, printlanguage, prettyprint | Core equivalents present |
| SLEIGH decoder and compiled SLA loading | sleigh, sleighbase, slghsymbol, slghpattern, slghpatexpress, semantics, pcodeparse/*, pcodecompile, slaformat, compression, context | Core equivalents present |
| Filesystem search-path manager | filemanage | Newly ported; integrated into LanguageRegistry directory enumeration |
| FLIRT-style external signatures | flirt | Separate signature-format integration; not the same as Ghidra graph signatures |
| Ghidra graph-based function signatures | No direct equivalent identified | Missing |
| Dynamic rule compiler and unification language | No direct equivalent identified | Missing |
| SLEIGH source compiler (slgh_compile, slghparse, slghscan) | No complete compiler pipeline identified | Missing; current runtime consumes compiled SLA data |
| Ghidra Java/native host bridge (ghidra_arch, ghidra_process, database_ghidra, loadimage_ghidra, typegrp_ghidra, and related adapters) | Standalone Rust loaders and APIs instead | Deliberately not a direct port; requires a separate host integration design |
| Console command shell, sample program and C++ test driver | Rust CLI/examples/tests | Replaced with Rust-native interfaces |

The mapping above is an architectural inventory, not a claim that every Rust
module is behaviorally identical to its upstream C++ counterpart. Exact parity
requires differential tests over the same binaries, processor specifications,
compiler specs, options and expected pseudocode.

## Newly added FileManage port

src/filemanage.rs implements the reusable filesystem support layer:
- ordered resource search paths and file resolution;
- prefix/suffix directory matching with hidden-file control;
- child-directory enumeration;
- bounded recursive directory discovery;
- path splitting and conservative Ghidra-root discovery.

LanguageRegistry now uses this shared implementation rather than maintaining
its own duplicate directory enumeration and recursive search helpers.
Unit tests cover search precedence, absolute paths, hidden entries, recursive
depth limits and path splitting.

## Highest-value remaining upstream gaps

1. Ghidra graph signatures (signature.cc/.hh): distinct from FLIRT. Port the
   feature graph, deterministic hashing, serialization and tests; then expose
   it through a Rust-native API.
2. Rule compiler (unify.cc/.hh, rulecompile.cc/.hh): dynamic user-defined
   simplification rules require a lexer/parser, constraint graph and safe rule
   execution model. This is a separate language subsystem, not a small missing
   file.
3. SLEIGH source compiler (slgh_compile, slghparse, slghscan): runtime decoding
   of compiled SLA files is not equivalent to compiling processor
   specification source.
4. Differential correctness harness: run identical corpus inputs through
   upstream Ghidra and this Rust implementation, compare normalized P-code,
   control-flow, recovered types and pseudocode, and retain minimized failures.
5. Performance and robustness evidence: benchmark representative binaries,
   record memory/time per phase, fuzz parsers and decoders, and track regressions.

## Licensing and provenance

Ghidra is Apache-2.0 licensed. Preserve applicable upstream notices and
attribution when translating or adapting source. Keep newly designed Rust
implementations distinguishable from mechanically translated code, and do not
describe an unimplemented upstream subsystem as complete.
