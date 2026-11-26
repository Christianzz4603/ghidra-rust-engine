# Reverse++

**An open-source reverse-engineering tool for every device.** Reverse++ is a pure-Rust engine built on a
port of the [Ghidra](https://github.com/NationalSecurityAgency/ghidra) decompiler and SLEIGH processor
specifications, with extra analysis, binary patching and readers for several compiled formats. Today it
ships as a headless command-line tool (like Ghidra headless); a native cross-platform app on the same
engine is the next project.

> **Status: early and under active development.** Read [What works today](#what-works-today) and
> [Known limitations](#known-limitations) before relying on it. Nothing here claims IDA Pro parity.

Reverse++ is independent of, and not affiliated with or endorsed by, the NSA or the Ghidra project. See
`NOTICE` and `LICENSE` (Apache-2.0). The decompiler core was ported automatically from Ghidra's C++
source; the crate and binary names (`ghidra-decompiler`, `ghidra-rust_cli`) are unchanged for now so
existing builds, release assets and the `update` command keep working.

## Goals

- One engine, every platform: Linux, Windows, macOS and Android today (CLI); a native desktop/mobile app next.
- Pure Rust: no C, C++ or Java at build or run time. Processor specs are embedded in the binary.
- Recover as much as possible from a binary: functions, symbols, strings, cross-references, control flow, pseudocode.
- Fast and memory-bounded on very large libraries (this is the current focus, see below).
- Open and scriptable: a reusable library API, not just a UI.

## What works today

- **Decompiler core**: ported Ghidra decompiler and SLEIGH; output matches the C++ decompiler on the
  test corpora in `tests/data`.
- **Containers**: ELF, PE, Mach-O; Android DEX/APK; Java `.class`/`.jar`; Python `.pyc`. The Java,
  DEX and `.pyc` readers are disassemblers/metadata readers, not source decompilers.
- **Whole-library analysis** (`open <file>` then `analyze <dir>` / `decompile all <dir>`): function
  discovery (entry point, symbols, `.eh_frame`, PE `.pdata`, Mach-O `LC_FUNCTION_STARTS`, prologue
  patterns, reachable calls), then per function: assembly, pseudocode, CFG, cross-references, data-flow
  summaries, fingerprints, and a coverage sweep of executable sections.
- **IDA-style output**: `<lib>.lst` (annotated listing with xrefs and labels) and `<lib>.ida.c`
  (restyled pseudocode). The style is modelled on IDA's; it has not been compared against IDA output.
- **Binary patching**: byte/assembly-level patch support in `src/patch.rs` (library API; CLI hooks are planned).
- **Binary scanning and graph signatures**: `src/binscan.rs`, `src/graph_signature.rs`.

## Quick start

Download a release archive for your platform from the GitHub Releases page (Android users: `Android-arm64-v8a`),
or build from source:

```sh
cargo build --release --example decomp     # produces the CLI example binary
./ghidra-rust_cli                           # interactive console (release binary)
```

```text
open /path/to/library.so
decompile main                  # one function
analyze /path/to/output         # whole library
```

Whole-library output files: `.c`, `.ida.c`, `.asm`, `.lst`, `.csv`, `.coverage.csv`, `.xrefs.csv`,
`.cfg.csv`, `.dataflow.csv`, `.fingerprints.csv`, `.prototypes.csv`, `.intelligence-failures.csv`,
`.report.txt`. Set `REVERSEPP_STAGE_LOG=1` for stage timing and memory logging.

Full command list, output descriptions, library API and build notes: [`docs/ENGINE_REFERENCE.md`](docs/ENGINE_REFERENCE.md).
The longer-term plan is in [`docs/ENGINE_ROADMAP.md`](docs/ENGINE_ROADMAP.md).

## Scale: measured, not promised

A CI job (`.github/workflows/scale.yml`) builds a large stripped shared library with known ground truth
and runs whole-library analysis on it. Latest measurements (6 GB memory cap, time-capped):

| Library | Real functions | Result |
| --- | --- | --- |
| ~12.5 MB | 32,000 | Pipeline runs end to end. Discovery took ~9 min; decompiling ran at ~18 functions/s. In the time cap it covered 11,206 functions (29.7% of the real ones). 1,700 reported functions are not real. |
| ~100+ MB | 300,800 | **Fails**: ran out of memory during discovery at 166k functions (~35 KB per discovered function). |

So a 100 MB library cannot yet be fully processed. Current work: per-function memory in discovery,
reducing repeated P-code lifting, then parallelism. See the open pull requests for progress.

## Known limitations

- Whole-library recovery is incomplete on large or stripped binaries; function discovery is heuristic
  and has both misses and false positives.
- Decompiled C is inferred pseudocode, not original source; some functions fail and are reported as
  such (see `.report.txt` and `.intelligence-failures.csv`).
- Speed and memory on very large libraries are not yet where they need to be (see above).
- No native GUI yet; no project database; patching has no CLI commands yet.
- The `master` CI is not fully green: the Linux test job and clippy have pre-existing failures.

## Roadmap

1. Make 100 MB+ libraries finish: memory per function, lazy structures, parallel analysis, checkpoints.
2. Complete coverage accounting (every byte classified) and fall back to disassembly with a reason when pseudocode fails.
3. IDA-style graph export (CFG and call graph as DOT/SVG/JSON).
4. Project database, CLI commands for patching and scanning, struct/enum editors, more signatures.
5. Native cross-platform app (desktop first, then mobile) on top of the engine API.
6. Rename the crate and binaries to Reverse++ (separate, breaking change).

## Contributing

Issues and pull requests are welcome. Build with the toolchain pinned in `rust-toolchain.toml`;
formatting is `cargo fmt` (edition 2024) and lints are `cargo clippy -D warnings`. Please include
measurements, not claims, with performance or recovery changes.

## License and acknowledgments

Apache-2.0. Based on the Ghidra decompiler and SLEIGH (Apache-2.0); see `NOTICE`.
