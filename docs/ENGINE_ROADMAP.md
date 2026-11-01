# Integrated Reverse-Engineering Engine Roadmap

This project uses the Rust Ghidra decompiler port as its decoding, SLEIGH, P-code,
and native decompilation foundation. The goal is to build an independent analysis
product around that foundation, not to rewrite a mature processor semantics and
decompiler stack from zero.

## Analysis pipeline

The engine should run repeatable passes with explicit inputs, outputs, confidence,
and provenance:

1. Container and loader analysis: executable format, segments, sections, imports,
   exports, relocations, entry points, TLS, resources, and debug metadata.
2. Processor analysis: language/compiler specification selection, instruction
   decoding, delay slots, context, calling conventions, and ABI metadata.
3. Discovery: function boundaries, tail calls, thunks, jump tables, exception
   landing pads, and code/data classification.
4. Identification: symbols, demangling, FLIRT signatures, compiler/runtime
   fingerprints, and optional external function metadata.
5. Graph analysis: cross references, call graph, basic blocks, CFG, dominators,
   post-dominators, loops, SCCs, and interprocedural summaries.
6. Microcode analysis: def-use, reaching definitions, SSA/phi construction,
   value sets, constant propagation, liveness, alias and memory analysis.
7. Semantic recovery: ABI-aware prototypes, parameter and return recovery,
   signedness, scalar/floating/pointer types, stack variables, structures,
   enums, arrays, strings, and object layouts.
8. Decompilation: expression normalization, control-flow structuring, switch and
   loop recovery, type propagation, variable naming, and readable C-like output.
9. Recognition: compiler idioms, standard libraries, cryptographic primitives,
   allocators, runtimes, framework patterns, and user-defined signatures.
10. Collaboration: versioned annotations, comments, types, names, and reviewed
    metadata synchronization with provenance and conflict handling.

## Engineering rules

- Every inferred fact carries evidence, confidence, and a source pass.
- A heuristic must never be presented as a confirmed fact.
- Preserve raw disassembly, P-code, and native pseudocode beside enhanced output.
- Make passes independently runnable and cacheable; avoid recomputing whole-program
  analysis for a single-function query.
- Support cancellation, progress events, address/function selection, and bounded
  memory profiles for mobile devices.
- Prefer deterministic analysis and regression fixtures over opaque guesses.
- Validate every pass against multiple architectures and compiler optimization
  levels. An enabled Cargo feature is not proof that a processor language
  definition is bundled or supported.

## Near-term implementation order

1. Keep CI green and make the full pipeline selection-aware.
2. Add ABI profiles and register/stack parameter recovery for System V AMD64,
   Windows x64, and AAPCS64.
3. Add CFG-aware reaching definitions and SSA phi nodes.
4. Add confidence-scored type constraints and propagation over P-code.
5. Recover stack locals, aggregate layouts, and pointer relationships.
6. Improve control-flow structuring and expression simplification.
7. Add interprocedural summaries, devirtualization evidence, and call-site
   prototype propagation.
8. Expand FLIRT formats and compiler/runtime signature databases.
9. Add reviewed Lumina-style metadata import/export with stable identity keys.
10. Build an architecture/compiler regression corpus and differential tests.

## Compatibility boundary

The backend supplies Ghidra-derived language semantics and native decompilation.
This project layers analysis and UX on top. Proprietary Hex-Rays/IDA internals are
not reproduced, and optimized machine code does not retain enough information to
recover every original source-level name, type, or construct.
