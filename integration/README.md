# Ghidra host integration

This directory contains the first Ghidra-facing adapter for the standalone Rust engine.
It deliberately keeps Ghidra's Java APIs on the host side and the analysis engine in a
separate process. That preserves process isolation and avoids loading Rust/native code
into Ghidra's UI JVM.

## Current adapter: Script Manager bridge

The Java script at ghidra-scripts/DecompileWithRustEngine.java adds a
"Decompile with Rust Engine" action through Ghidra's Script Manager. It:

1. Reads the active Ghidra program's original executable path and cursor address.
2. Starts the configured ghidra-rust_cli executable with ProcessBuilder, without a shell.
3. Redirects output to a temporary file, avoiding pipe-buffer deadlocks on large reports.
4. Enforces a five-minute timeout and supports Ghidra task cancellation.
5. Prints pseudocode and reconstruction evidence in the Ghidra script console.

### Install

1. Build the Rust CLI using the repository's all-processors build instructions.
2. In Ghidra, open Window -> Script Manager -> Manage Script Directories.
3. Add this repository's integration/ghidra-scripts directory.
4. Set GHIDRA_RUST_ENGINE to the absolute CLI executable path, or set the JVM property
   -Dghidra.rust.engine=/absolute/path/to/ghidra-rust_cli.
5. Open a supported binary, place the cursor in a function, and run DecompileWithRustEngine.

The script passes the numeric offset from Ghidra's current address. The CLI independently
opens the original executable, so this bridge is intended for programs whose Ghidra image
base and address mapping still match the original file. It does not yet represent
database-only programs, memory patches, overlays, imported symbols, Ghidra datatypes,
relocations applied after loading, or per-program compiler-spec overrides.

## Host protocol roadmap

The next integration layer should replace the one-shot reconstruct invocation with a
versioned, length-bounded JSON-lines or framed-binary protocol. The Java side should
provide Ghidra-owned facts through a stable adapter interface:

- program identity, language/compiler-spec IDs, endianness and address spaces;
- memory blocks and initialized bytes, with explicit permissions and holes;
- functions, entry points, symbols, external references and relocations;
- function signatures, parameter storage, calling convention and datatypes;
- cancellation, progress, timeout, diagnostics and structured pseudocode tokens.

The native/Rust worker should remain out-of-process. Requests need size limits, explicit
protocol versions, request IDs, bounded queues and cancellation. A persistent worker can
reuse decoded language state and caches across functions while isolating crashes from Ghidra.

## Upstream architecture mapping

The official Ghidra decompiler Makefile separates reusable decompiler/SLEIGH code from
its Ghidra-specific host build. The host-only native group includes ghidra_arch,
inject_ghidra, ghidra_translate, loadimage_ghidra, typegrp_ghidra, database_ghidra,
ghidra_context, cpool_ghidra, ghidra_process, comment_ghidra, string_ghidra and
signature_ghidra. The Java DecompInterface and DecompileResults classes coordinate the
process and decode structured results.

This repository does not copy those adapters wholesale. The script bridge is an initial
integration point, not full Ghidra host parity. The versioned host protocol and adapter
subsystems remain implementation work.
