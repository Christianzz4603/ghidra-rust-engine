DISCLAIMER: This was automatically ported by an agent from Ghidra's C++ source code into Rust.

# ghidra-decompiler

A pure Rust port of the Ghidra decompiler (Ghidra 12.2, `Ghidra/Features/Decompiler/src/decompile/cpp`).
It has no C, C++ or Java dependencies. The output is textually identical to the C++ decompiler on the
test corpora in `tests/data`.

## Full-library decompilation

After loading a binary in the interactive console, run:

```text
open /path/to/library.so
decompile all /path/to/output
```

This runs whole-image analysis rather than requiring a function name. It discovers functions from the entry point, symbols, and reachable code, then attempts to export C pseudocode and assembly for every recovered function. It also exports data symbols, strings, and call edges.

The output directory contains:
- `<library>.c`: combined C-like pseudocode for successfully decompiled functions.
- `<library>.asm`: recovered function assembly, with undecodable gaps explicitly marked.
- `<library>.csv`: discovered functions, data symbols, strings, call edges, and per-function status.
- `<library>.coverage.csv`: a bounded-memory linear sweep of every executable section, including decoded-byte totals and undecodable address ranges. Linear decoding coverage does not prove that every decoded byte is reachable code.
- `<library>.xrefs.csv`: call references and heuristic memory read/write references.
- `<library>.cfg.csv`: recovered basic blocks and control-flow edges.
- `<library>.dataflow.csv`: P-code operation counts, memory activity, constants, and observed storage widths.
- `<library>.fingerprints.csv`: function byte hashes and opcode histograms.
- `<library>.prototypes.csv`: prototype evidence and explicit notes about what has not yet been recovered.
- `<library>.intelligence-failures.csv`: per-function failures from the intelligence passes.
- `<library>.report.txt`: aggregate coverage, success/failure counts, and analysis limitations.

Cross-references and CFG branch targets may be heuristic. Prototype records are evidence summaries, not reconstructed function signatures. Decompiled C remains inferred pseudocode, not original source.

The output directory argument is optional. Without it, output is written to `/sdcard/home/analysis` on Termux. This is best-effort binary analysis, not recovery of the original source: stripped binaries, embedded data, jump tables, and code that cannot be reached from known seeds may require additional analysis.

The existing `analyze [output-directory]` command remains an alias for the same whole-library pipeline.

## Beginner-friendly console workflow

The interactive console supports short commands for the most common tasks:

```text
open /path/to/program.so
decompile add
```

- `open <file>` loads an ELF, PE, or Mach-O binary. It is a shorter alias for `load file <file>`.
- `select <function>` selects a function. It is a shorter alias for `load function <function>`.
- `decompile <function>` selects and decompiles that function in one step.
- A successful decompilation automatically saves readable C pseudocode to the executable's `output/` folder. The folder is created automatically.
- Set `GHIDRA_DECOMPILER_OUTPUT_DIR` before launching the program to choose another output folder.
- The original Ghidra-style analysis commands remain available, including disassembly, P-code, control-flow, data-flow and graph analysis.
- Typing a required-argument command by itself prints its syntax, for example `open`, `select`, `decompile`, `save` or `restore`.
- The console can be launched from any working directory. Processor definitions are embedded in the build, so it does not need to be started from the repository root.
- Absolute file paths work regardless of the current directory. Relative paths are resolved from the directory where the program was launched.
- Commands that save files accept either absolute paths or paths relative to the launch directory. Decompiled C output defaults to the executable's `output/` folder, with a home-directory fallback when needed.

## Standalone executable

The release archive contains the self-contained `ghidra-rust_cli` executable. Processor specifications are embedded in the binary, so it does **not** need the repository, Rust, Cargo, a SLEIGH directory, an installer, or a separate launcher at runtime.

1. Download the archive matching your device ABI from the GitHub Releases page. For most modern Android phones, choose `Android-arm64-v8a`.
2. Extract `ghidra-rust_cli` anywhere you want.
3. Run it directly from that folder:

```sh
chmod +x ./ghidra-rust_cli
./ghidra-rust_cli
```

The interactive console starts immediately. Load a library with `open /path/to/library.so`, then use `decompile <function>` to decompile a function. You can also launch it by its absolute path from any working directory.

Decompiled files are saved automatically in an `output/` directory beside the executable. If that location is not writable, the CLI falls back to `~/.local/share/ghidra-engine/output`. Set `GHIDRA_DECOMPILER_OUTPUT_DIR` to override the location. No setup command is required. The optional `setup` command only creates a user workspace; it is not part of normal startup.

The CLI does not check for updates during startup, so running the standalone binary does not require `curl` or an internet connection. Use `ghidra-rust_cli update` when you want to check for a newer release.


## Reusable analysis engine API

The public API combines high-level analysis orchestration with lower-level program controls. `Program` supports function lookup and creation, symbol renaming, memory and code reads, register metadata, P-code, disassembly, decompilation, call graphs, and print-language selection. `AnalysisEngine` adds configurable whole-program passes, address/function filtering, result limits, progress events, and single-function analysis.

Applications can embed the high-level analysis engine directly. It is UI- and file-output-agnostic: a Rust desktop app, Android JNI layer, CLI, or server can receive progress events and decide how to display or store each function result.

```rust
use std::path::Path;
use ghidra_decompiler::analysis::{AnalysisEngine, AnalysisEvent, AnalysisOptions};

let mut engine = AnalysisEngine::open(Path::new("libexample.so"), None)?;
let report = engine.analyze(&AnalysisOptions::default(), |event| {
    match event {
        AnalysisEvent::Started { total_functions } => println!("Found {total_functions} functions"),
        AnalysisEvent::FunctionCompleted { result, .. } => {
            if let Some(code) = result.pseudocode {
                println!("{}: {} bytes of pseudocode", result.function.name, code.len());
            }
        }
        AnalysisEvent::Finished { analyzed, with_errors, total } => {
            println!("Finished: {analyzed}/{total}, {with_errors} with errors");
        }
        _ => {}
    }
});
let _ = report;
```

`AnalysisOptions` can independently enable function discovery, disassembly, decompilation, string extraction, data symbols, and call-graph construction. Use `AnalysisSelection::with_function_addresses`, `with_address_range`, and `with_max_functions` with `AnalysisEngine::analyze_selected` to restrict a run to chosen functions or an address window. `AnalysisEngine::analyze_function(address, options)` analyzes one function. `analyze_function_by_name(name, options)` provides the same operation by symbol name. `Program::pcode_range(address, byte_length)` returns P-code operations across complete instructions until the requested byte range is covered, and `function_pcode(address)` extracts P-code for a known function. `AnalysisSelection::validate()` rejects empty or reversed address windows before analysis starts. `open_with` and `from_image_with` expose loader-only versus full symbol loading, while `from_raw_bytes` supports headerless code. `Program::read_memory` and `read_code` expose bytes; `register_info`, `entry_point`, `find_function_by_name`, `find_function_at`, and `ensure_function_at` provide direct program inspection and control. Use `AnalysisOptions::low_memory()` on constrained phones: it keeps function discovery and decompilation enabled, but skips the separate disassembly pass (which decodes the same bodies again) and skips optional strings, data-symbol, and call-graph collections. The default profile keeps every pass enabled. `AnalysisEngine::from_image` accepts in-memory executable bytes, and `AnalysisEngine::from_program` wraps an already configured `Program`. Function results are emitted one at a time, so applications do not need to retain every function's pseudocode in memory.

### Build profiles

The default Cargo feature set is `desktop`, preserving the existing x86, ARM, AArch64, MIPS, PowerPC, and RISC-V support. For Android/ARM devices, build only the ARM language specifications:

```sh
cargo build --release --no-default-features --features mobile --example decomp
```

This avoids embedding unrelated processor specifications in the executable. It does not change the decompiler algorithms or output for ARM binaries. For an even smaller executable at the cost of some runtime throughput, use the size-oriented profile:

```sh
cargo build --profile release-small --no-default-features --features mobile --example decomp
```

Use the ordinary `--release` profile when maximum decompilation speed is the priority. Desktop users can keep the default `--release` build; no processor support is removed from the desktop defaults.


## Standalone browser workspace (Android / Termux)

The browser workspace is compiled directly into the single `ghidra-rust_cli` executable. No `install-termux.sh`, `termux-open`, Node.js, XFCE, X11, or separate web UI binary is required.

Start it with `./ghidra-rust_cli web`, then manually open `http://127.0.0.1:8080` in Firefox or another browser. Use `./ghidra-rust_cli web --port=9090` to choose another port. The server binds only to `127.0.0.1` and is not exposed to your Wi-Fi network by default.

The normal interactive console remains available by running `./ghidra-rust_cli`.

## Native library builds and signing

The GitHub Actions native-library workflow builds platform-specific library artifacts, including Windows `.dll`, macOS `.dylib`, Linux/Android `.so`, and Rust `.rlib` outputs where supported by the target. Build artifacts are published to GitHub Actions, and release builds can be attached to a GitHub Release.

Android builds target all four standard Android ABIs: `armeabi-v7a` (32-bit ARM), `arm64-v8a` (64-bit ARM), `x86` (32-bit Intel/AMD), and `x86_64` (64-bit Intel/AMD). The Android native libraries are built with Android NDK 27.2 and a minimum API level of 24.

**The project does not sign the published native libraries.** Developers who download, integrate, or redistribute these artifacts are responsible for signing the binaries themselves when their platform, distribution channel, or deployment requirements call for it. Use the signing process appropriate to the target platform, such as Authenticode for Windows or Apple code signing for macOS. Linux and Android distribution requirements vary; do not treat a checksum as an operating-system code signature.

## Library usage

```rust
let mut program = Program::open(Path::new("a.out"), None)?;
let main = program.functions()?.into_iter().find(|function| function.name == "main").expect("no main");
let instructions = program.disassemble(main.address, 4)?;
let pcode = program.pcode(main.address, 1)?;
let c_code = program.decompile(main.address)?;
let edges = program.call_graph()?;
```

## Acknowledgments

Thanks to [koute](https://github.com/koute) for publishing the original Rust port of the Ghidra decompiler, which provided an important foundation for this project.

## Examples

- `examples/inspect.rs` lists the functions of a binary, prints the disassembly, p-code and C code of
  `main`, and prints the call graph (`cargo run --release --example inspect -- <binary>`).
- `examples/raw_decompile.rs` decompiles a headerless code blob
  (`cargo run --release --example raw_decompile -- x86:LE:64:default:gcc <file>`).
- `examples/decomp.rs` is a port of the C++ `decomp_dbg` console (`consolemain.cc`), mainly useful to
  compare output with the C++ console (`cargo run --release --example decomp`).

- `Program::open(path, language)` and `Program::from_image(name, bytes, language)` load ELF, PE and Mach-O
  images. With `language = None` the language id is derived from the file header; otherwise pass a Ghidra
  language id such as `"x86:LE:64:default:gcc"`.
- `Program::from_raw_bytes(bytes, language, base_address)` loads a headerless code blob.
- `decompile(address)` creates a function at the address if the symbol table has none.
- `call_graph()` follows control flow of every known function and reports direct calls.
- `disassemble(address, count)` returns each instruction with its bytes.
- `discover_functions()` finds the functions of a binary without function symbols (see "Symbols").
- `data_symbols()` lists the data symbols. `set_function_name(address, name)` renames the function at the
  address and creates it when none starts there (as `decompile` does); `set_data_name(address, name)`
  renames a data symbol and creates a 1-byte label `DAT_<address>` when none starts there;
  `is_code_address(address)` says whether the address is in an executable section; `set_symbol_name(address, name)` renames whichever of the two starts at the
  address. An empty name restores the loaded name.
- `Program` is `Send`. Internal panics are returned as `Error::Lowlevel`.
- `Program::architecture()` exposes the underlying `Architecture` for everything the C++ decompiler offers
  (options, types, prototypes, actions, the console command set in `ifacedecomp`).

## Symbols

`Program::open` and `Program::from_image` load more symbols than the C++ loader, so the C output has
names where the C++ decompiler prints addresses:

- ELF function symbols from `.symtab` and from `.dynsym` (a stripped binary or a shared library keeps its
  exported names only there). Undefined `.symtab` entries are not functions.
- Import stubs: each PLT entry is named after the symbol of the GOT slot its p-code reads, so a call reads
  `printf(...)`. The stub finder follows constants through the stub's p-code instead of decoding each
  PLT layout; it is tested on x86-64 (`.plt`, `.plt.sec`), i686 PIE, AArch64, ARM and RISC-V 64. A stub
  whose name is also a defined function is `<name>@plt`.
- Data symbols (`STT_OBJECT` with a size, PE and Mach-O data symbols) and one pointer-sized symbol per
  GOT slot with a dynamic relocation (`<name>@got`).
- Demangled names (feature `demangle`, on by default): Rust legacy and v0 names without the hash, C++
  Itanium names without the parameter list. `FunctionEntry.symbol` has the mangled name. Every function
  is in the global scope under its full name, so a call reads `geometry::Circle::area(...)`.
- String literals: before `decompile`, each constant of the function that points into a read-only data
  section at NUL-terminated printable text of at least 4 characters gets a `char[n]` symbol, and the C
  output prints the literal.
- `discover_functions()`, for a binary without function symbols, follows the control flow from the entry
  point (or the base address of raw code) through direct calls and through constants that point into
  executable sections, such as the address of `main` that `_start` passes to `__libc_start_main`. It
  costs one flow analysis per function: about 8 s for a 1.5 MB static glibc binary.

`FunctionEntry.source` says where each function came from. `Program::open_with(path, language,
SymbolLoading::Loader)` loads only the symbols of the C++ loader; the C output of the corpus tests is
equal to the C++ decompiler's in that mode.

Limits: PowerPC32 call stubs in `.text` (lld names them `<n>.plt_pic32.<name>`) and PowerPC64 stubs,
which read the GOT through the TOC register, keep their names; MIPS has no PLT, and its calls go through
the GOT; PE import tables and Mach-O stubs are not named. Rust `&str` constants are not NUL-terminated
and stay addresses. A function reached only through a pointer table in data is not discovered.

## Processor support

The compiled SLEIGH specifications (`.sla`) and the `.ldefs`/`.pspec`/`.cspec` files are embedded with
`include_bytes!`, one Cargo feature per Ghidra processor directory. Default features: `x86`, `arm`, `aarch64`,
`mips`, `powerpc`, `riscv`. The feature `all-processors` enables all 39 processors. Processors outside the
default set decode through the same code but are tested best-effort only.
`sleigh_arch::LanguageRegistry::from_directory` loads language files from disk instead.

The embedded `.sla` files in `languages/` keep the Ghidra `.sla` header, but their payload is xz instead of zlib,
which keeps the crate under the crates.io size limit. Ghidra cannot read these files. The crate reads both
payload formats, so `from_directory` also accepts the `.sla` files of a Ghidra installation.

## Differences from Ghidra

The port fixes upstream decompiler bugs found by differential fuzzing instead of reproducing them:

- Operands that SLEIGH never builds no longer keep handle data from a previous instruction; a p-code
  template that refers to such an operand produces a bad-instruction-data error.
- Instructions with more than 16 bytes read zeros past the instruction buffer instead of adjacent memory.
- Raw p-code that writes to the constant space (for example a RISC-V write to `x0`) is dropped when the
  function is built, instead of leaving an op whose input is later deleted as dead code.
- Repeating action groups stop after 100 repeats and add the warning
  `Exceeded maximum repeat count for action <name>`, instead of looping forever when two rules undo
  each other.
- Common-subexpression elimination no longer matches an op with itself (an op that reads the same varnode in
  two inputs appears twice in the candidate list), which made the rule report a change forever.
- Symbol lookups in address spaces that a scope has no map for return no symbol instead of reading past
  the end of the scope's map table.
- Heritage deletes a free join-space varnode without readers (for example an old call output that a rule
  replaced) instead of dereferencing its missing reader. A free join varnode with several readers produces
  an error.

`tools/fuzz/reference_fixes.patch` applies the same behavior to the C++ reference so that the test data and
the differential fuzzers compare equal behavior.

## Whole-file analysis

After opening a binary, run `analyze` to recursively discover reachable functions and export their pseudocode and assembly:

```text
open /path/to/library.so
analyze
```

The command seeds discovery from the executable entry point and all function symbols, follows direct call targets and code-address references, then exports a navigable analysis set to `/sdcard/home/analysis` by default. Pass another output directory with `analyze <directory>`, or set `GHIDRA_DECOMPILER_OUTPUT_DIR`.

Generated files:

- `all.c`: combined decompiled C pseudocode.
- `all.asm`: disassembly for discovered functions.
- `functions.csv`: discovered function names, addresses, origins, and original symbols.
- `calls.csv`: caller/callee relationships and call-site addresses.
- `data.csv`: known global data and import/GOT symbols.
- `strings.csv`: printable NUL-terminated UTF-8 strings from recognized string sections.

This is a growing static-analysis pipeline, not yet equivalent to IDA Pro. Unreferenced functions, functions reachable only through unresolved indirect calls, non-UTF-8/UTF-16 strings, complex jump tables, and code hidden behind unusual control-flow patterns may still be missed. The output is best-effort and does not claim every executable byte has been classified.

## Tests

```
cargo test --release --features all-processors
```

- `datatests`: the 89 C++ decompiler data tests (733 checks).
- `decomp_corpus`: 1222 functions from 20 ELF binaries (x86-64, i686, ARM, Thumb, AArch64, MIPS BE/LE,
  PowerPC, RISC-V 32/64, each `-O0` and `-O2`); the transcript must equal the C++ `decomp_dbg` output.
- `sleigh_corpus`: disassembly and raw p-code for every language id, compared with the C++ SLEIGH decoder.
- Ports of the C++ unit tests and differential tests of individual modules.

`ci/jobs/` contains one script per CI job (tests, clippy, rustfmt, docs, MSRV check, package size check,
differential fuzzing); `.github/workflows/rust.yml` runs them. `ci/run-all-tests.sh` runs all jobs locally.

`tools/` contains the scripts that build the C++ reference and regenerate the test data; see
`tools/README.md`. `tools/trace/` compares action and rule traces between the C++ and Rust decompilers.

## License

Apache-2.0, as Ghidra. See `LICENSE` and `NOTICE`.


## Android APK and DEX Smali API

The `dex` module provides a separate DEX/APK inspection API. It parses DEX string, type, prototype, method, and class tables, exposes class and method metadata, and renders method code as Smali-style text. APK input is read through ZIP and supports multidex entries (`classes.dex`, `classes2.dex`, and later files).

```rust
use ghidra_decompiler::{Apk, DexFile};

let apk = Apk::open("app.apk")?;
for (index, dex) in apk.dex_files.iter().enumerate() {
    println!("DEX {index}: {} classes", dex.classes().len());
}
apk.write_smali("decoded-smali")?;

let dex = DexFile::open("classes.dex")?;
println!("{}", dex.smali()?);
# Ok::<(), ghidra_decompiler::Error>(())
```

This is an initial DEX metadata and Smali export layer, not yet a full ApkTool replacement: resource table decoding, binary AndroidManifest.xml decoding, annotations, debug directives, and complete Dalvik opcode operand formatting are not implemented yet. Unknown or currently unsupported instruction formats are emitted as opcode placeholders rather than guessed.


## Kotlin built-ins metadata API

The `kotlin` module reads Kotlin `.kotlin_builtins` package-fragment metadata. It exposes the metadata version, class/function/property declaration names, and the underlying protobuf payload. It can emit a preliminary Kotlin-like declaration listing.

```rust
use ghidra_decompiler::KotlinBuiltins;

let builtins = KotlinBuiltins::open("kotlin/collections/collections.kotlin_builtins")?;
println!("Metadata version: {:?}", builtins.version());
for class in builtins.classes() {
    println!("{}", class.qualified_name);
}
println!("{}", builtins.decompile());
```

This is an initial metadata reader, not a complete Kotlin source decompiler. It does not recover executable function bodies, and full signatures, type aliases, annotations, extension receivers, and complete string-table transformations require additional metadata schema support. For JVM bytecode, use the JVM processor support when built with the `jvm` feature; `.kotlin_builtins` contains declarations and type metadata rather than method bytecode.


## Advanced binary intelligence foundation

The `intelligence` module adds first-pass cross-reference, CFG, data-flow, prototype-evidence, function-fingerprint, and similarity APIs. Direct calls from the native call graph are marked confirmed. Constant-address memory references and assembly-parsed CFG targets are heuristic. CFG and prototype recovery remain preliminary: processor-semantic branch resolution, calling-convention parameter recovery, stack variables, value propagation, jump tables, and signature databases are future work. Similarity is a triage score, not proof of code equivalence.


## Standalone CLI releases and updates

Every push to `master` triggers a cross-platform release build. The workflow publishes the CLI executable and native libraries together as a GitHub Release, using the next patch version after the latest semantic Git tag (starting at `v0.0.1` when no version tags exist). A failed platform build prevents publication, so a release is not marked complete with missing targets.

Standalone, uncompressed CLI executables are provided directly as GitHub Release assets for Android `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`; Linux x86_64 and ARM64; Windows x64; and macOS Intel and Apple Silicon. Choose the asset matching your operating system and CPU architecture. Android assets are named `ghidra-rust_cli-Android-<ABI>`; other platforms use `ghidra-rust_cli-<platform>`. No ZIP, TAR, installer, or Termux setup script is needed.

On Android/Termux, download the ARM64 executable, then run `chmod +x ghidra-rust_cli-Android-arm64-v8a` and `./ghidra-rust_cli-Android-arm64-v8a`. Launch the browser interface with `./ghidra-rust_cli-Android-arm64-v8a web`. The update notice is informational and points to GitHub Releases; it never replaces the running executable automatically.


### Release performance

Release builds use `opt-level=3`, fat LTO, and one codegen unit for cross-crate optimization. This increases build time and avoids `target-cpu=native` so distributed binaries remain portable. Analysis hot paths use allocation-free assembly sinks during code coverage sweeps, pre-index call edges, hash-based internal aggregation with sorted output, and pre-sized instruction buffers.


## Interactive pseudocode API

The `pseudocode` module provides a cross-platform, presentation-oriented API for applications that need Hex-Rays-style function pseudocode. It is an independent Rust implementation layer over this repository's native decompiler, not a copy of Hex-Rays source or a claim of binary compatibility.

```rust
use ghidra_decompiler::{Program, PseudocodeDecompiler, PseudocodeOptions};
use std::path::Path;

let mut program = Program::open(Path::new("libexample.so"), None)?;
let decompiler = PseudocodeDecompiler::new(PseudocodeOptions::default());
let batch = decompiler.decompile_all(&mut program)?;

for function in batch.functions {
    println!("{} @ {:#x}", function.name, function.address);
    println!("{}", function.source);
}
println!("{} succeeded, {} failed", batch.succeeded(), batch.failed());
# Ok::<(), ghidra_decompiler::Error>(())
```

The API returns per-function pseudocode, numbered display lines, symbol metadata, truncation status, and per-function failures so a UI can keep rendering when an individual function cannot be decompiled. Options can bound the number of functions and output bytes for memory-constrained devices. The initial layer uses the existing Ghidra-derived analysis/decompilation backend; higher-level type recovery, structured variable naming, interactive microcode editing, and richer source mapping remain incremental work.


## Independent Hex-Rays-style decompiler work

The `hex-rays-style-decompiler` branch is an independent implementation effort.
It does not copy Hex-Rays source code, private formats, or proprietary algorithms.
The goal is capability parity through independently implemented analysis passes,
with compatibility and correctness measured against public binaries and test
corpora rather than claims of identical internals.

Current foundations on this branch:

- A cross-platform pseudocode API with bounded batch processing and per-function
  failures (`PseudocodeDecompiler`).
- A microcode data-flow layer that records P-code definitions, uses, linear
  def-use edges, constant inputs, and conservatively identified unused pure
  results (`MicrocodeAnalyzer`).
- The microcode report explicitly models a linear pass. It is not SSA and does
  not yet solve CFG-wide reaching definitions, loops, or phi nodes.

The next engineering layers are CFG-aware SSA construction, type propagation,
stack/register variable recovery, calling-convention and prototype inference,
expression simplification, structured control-flow recovery, and regression
corpora across x86/x64, ARM/ARM64, and other supported architectures.
