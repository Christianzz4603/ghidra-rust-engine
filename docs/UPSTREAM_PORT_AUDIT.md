# Upstream Ghidra decompiler port audit

Audit baseline: NationalSecurityAgency/ghidra, master, tree commit
4718f50d9941b9d7b7ebd1febc2982f055560a73. The upstream native build inventory
is maintained in Ghidra/Features/Decompiler/buildNatives.gradle and the
decompile/cpp Makefile. This audit separates reusable decompiler code from
Ghidra's Java-facing host integration and development utilities.

## Port coverage map

| Upstream area | Rust implementation | Status |
| --- | --- | --- |
| Core address/space, XML and marshaling | address, space, xml, marshal, translate, pcoderaw, opcodes, float, globalcontext | Core equivalents present |
| Decompiler graph, blocks, variables and operations | graph, block, cover, varnode, op, variable, varmap, funcdata/*, heritage, flow, merge, subflow | Core equivalents present |
| Type system and prototype models | types/*, typeop, fspec, paramid, type_recovery | Core equivalents present; behavior still needs differential validation |
| Simplification/action engine | action, ruleaction/*, blockaction, coreaction/*, condexe, constseq, transform | Core equivalents present |
| C/Java output and pretty printing | printc/*, printjava, printlanguage, prettyprint | Core equivalents present |
| SLEIGH decoder and compiled SLA loading | sleigh, sleighbase, slghsymbol, slghpattern, slghpatexpress, semantics, pcodeparse/*, pcodecompile, slaformat, compression, context | Runtime equivalents present |
| Filesystem resource manager | filemanage | Rust implementation integrated into SLEIGH language discovery |
| FLIRT-style signatures | flirt | External FLIRT signature matching; not Ghidra graph signatures |
| Ghidra graph-based function signatures | signature | Initial independent implementation: operation, block-shape, call-shape, normalized-constant and linear def-use features; bounded binary format and weighted similarity. Not yet exact Ghidra feature parity |
| Dynamic rule compiler and unification | dynamic, modelrules, ruleaction | Existing runtime/rule infrastructure; complete Ghidra rule compiler and unification DSL remain unverified/missing |
| SLEIGH source compiler | pcodecompile and parser components | Runtime/compiled-SLA support exists; full slgh_compile/slghparse/slghscan source compiler pipeline remains missing |
| Ghidra Java/native host bridge | integration/ghidra-scripts/DecompileWithRustEngine.java; ghidra_host | Initial Script Manager bridge plus bounded JSON-lines protocol, persistent worker executable and lazy executable-block decompilation; Java client transport and complete Ghidra database hydration remain missing |
| Ghidra-native adapters | No complete direct equivalents | Missing: ghidra_arch, inject_ghidra, ghidra_translate, loadimage_ghidra, typegrp_ghidra, database_ghidra, ghidra_context, cpool_ghidra, ghidra_process, comment_ghidra, string_ghidra, signature_ghidra |
| Java process/result protocol | ghidra_host request/response framing and GhidraScript CLI bridge | Partial; Java client, persistent worker loop, snapshot hydration and structured pseudocode transport remain missing |
| Console shell, sample program and C++ test driver | Rust CLI/examples/tests | Replaced with Rust-native interfaces |

This mapping is architectural, not proof of behavioral equivalence. Exact parity
requires differential tests against upstream Ghidra over identical binaries,
processor/compiler specifications, options and expected P-code/pseudocode.

## Ghidra host integration

The first host adapter launches the standalone CLI out-of-process. It uses a
temporary output file, enforces a timeout and supports task cancellation. It currently
requires the original executable and assumes its address mapping matches the Ghidra
program. It does not transfer database memory, overlays, patched bytes, symbols,
relocations, compiler-spec state or datatypes.

The Rust side now has a versioned, bounded JSON-lines protocol model (`src/ghidra_host.rs`) with `ping`, `open_program`, `decompile`, `cancel` and `shutdown` commands. Snapshot validation bounds frames to 16 MiB, each memory block to 8 MiB and total memory to 64 MiB, rejects overlapping blocks and validates function/symbol/relocation metadata. The persistent `ghidra-rust-worker` executable now serves the protocol over stdin/stdout, retains a program snapshot, lazily constructs/reuses raw-binary `Program` instances for executable memory blocks, registers snapshot function entries and invokes the existing pseudocode decompiler. The Java Script Manager adapter still uses the older one-shot CLI path and does not yet speak this protocol. Snapshot symbols, relocations, overlays, types, register context, injections, comments/strings and compiler-spec metadata are transported/validated but not yet hydrated into the Rust database. The worker currently processes requests serially; cancellation is therefore acknowledged as unavailable. Keep the worker isolated from Ghidra's UI JVM.

## Highest-value remaining gaps

1. Exact Ghidra graph signatures: compare feature traversal, settings, hashes and XML
   serialization against upstream signature.cc/.hh and signature_ghidra.cc/.hh.
2. Dynamic rule compiler and unification: complete parser/compiler semantics and
   bounded rule execution corresponding to rulecompile.cc/.hh and unify.cc/.hh.
3. SLEIGH source compiler: implement source parsing and compilation, not only SLA loading.
4. Full Ghidra host protocol: memory snapshots, symbols, types, calling conventions,
   relocations, context, overlays, cancellation and structured pseudocode tokens.
5. Differential correctness harness: compare normalized P-code, CFG, recovered types,
   signatures and pseudocode against upstream Ghidra.
6. Performance/robustness evidence: benchmark representative binaries, profile phases,
   fuzz parsers/decoders and retain minimized regression cases.

## Signature subsystem limitations

The Rust signature module is a deterministic, bounded first implementation inspired by
Ghidra's feature-signature model. It hashes normalized P-code operation shapes, block
summaries, call shapes, constant classes and linear def-use relationships. It is not
yet the same algorithm, feature traversal, settings model or XML protocol as Ghidra.
The linear data-flow feature is not CFG-sensitive SSA; collisions remain possible in
32-bit feature hashes. Do not use these signatures as proof of function identity.

## Licensing and provenance

Ghidra is Apache-2.0 licensed. Preserve applicable upstream notices and attribution
when translating or adapting source. Keep independent implementations distinguishable
from mechanically translated code and do not describe an unimplemented subsystem as complete.


### Database hydration status (worker)

The worker's `open_program` now eagerly creates a native `Program` for every non-empty snapshot memory block and imports function symbols, supported data symbols and comments into the Rust symbol/comment databases. Hydration counters and per-record warnings are returned to the host. Decompilation reuses these pre-hydrated executable-block instances. The transport now accepts datatype descriptors, references and processor-context records in addition to relocations. Those four metadata classes are explicitly deferred and remain available in the retained snapshot; they are not yet installed into native engine structures. The per-block raw loader is not a unified Ghidra address-space image, so cross-block references, relocations and functions spanning blocks remain unresolved.


### Follow-up: native metadata hydration tables

The worker now imports references into a per-Program reference index, stores relocation descriptors and imported datatype descriptors in native Program metadata tables, and applies named SLEIGH context variables through the architecture context database. These are distinct from full Ghidra parity: relocation arithmetic/byte patching, recursive datatype graph construction and symbol-to-type binding remain outstanding. The raw memory model remains one independent Program per memory block; it is not yet a unified address-space-backed ProgramDB. A Java exporter that serializes the live Ghidra database into the expanded protocol is also outstanding.
