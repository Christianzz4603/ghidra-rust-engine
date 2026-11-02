# FLIRT and Lumina integration

The engine now has two complementary metadata integrations.

## FLIRT function identification

The `flirt` module uses the pure-Rust `fast-flirt` parser and matcher. It loads
FLAIR `.pat` and binary `.sig` corpora, then matches each known function using
its bytes and the FLIRT head/CRC/discriminator checks.

Library API:

```rust
use ghidra_decompiler::{FlirtAnalyzer, FlirtOptions, Program};

let mut program = Program::open(std::path::Path::new("sample"), None)?;
program.discover_functions()?;

let flirt = FlirtAnalyzer::load_dir("signatures")?;
let report = flirt.analyze(&mut program, &FlirtOptions::default())?;

println!("Loaded {} signatures", report.signatures_loaded);
for item in report.matches {
    println!("{:#x}: {} -> {} (renamed: {})",
        item.address, item.previous_name, item.library_name, item.renamed);
}
# Ok::<(), ghidra_decompiler::Error>(())
```

Automatic renaming is conservative: symbol-table functions are not renamed
unless their source name looks like an automatically generated placeholder.
Set `rename_automatic_functions: false` to perform identification only.
Function reads are capped at 1 MiB by default and can be configured.

FLIRT identifies known library routines. It does not recover arbitrary source
code, infer complete types, or replace control-flow and data-flow analysis.

## Lumina metadata through Dazhbog

[Dazhbog](https://github.com/19h/dazhbog) is a standalone, Lumina-compatible
metadata server. It provides persistent function metadata, version history,
binary context, search, and a web workbench. The engine's `lumina` module
provides a read-only HTTP client for Dazhbog's function search and detail APIs:

```rust
use ghidra_decompiler::LuminaClient;

let lumina = LuminaClient::new("http://127.0.0.1:8080")?;
let matches = lumina.search_functions("memcpy", 20)?;
println!("{matches:#}");
# Ok::<(), ghidra_decompiler::Error>(())
```

Run Dazhbog as a separate service using its own configuration and storage.
Keep it bound to localhost or a trusted network unless you have configured
appropriate access controls. Its Lumina RPC listener is intended for IDA
clients; the engine currently consumes the Dazhbog HTTP search/detail API.
Native Lumina RPC push/pull synchronization and automatic application of
retrieved prototypes/comments are future integration work.

## Combined analysis pipeline

1. Load the executable and discover functions.
2. Run FLIRT to label known statically linked library routines.
3. Query Dazhbog for corroborating function metadata where a stable Lumina key
   is available.
4. Feed recovered names and reviewed metadata into decompilation and type
   reconstruction.
5. Preserve evidence provenance and confidence. A FLIRT or Lumina name is
   metadata evidence, not proof that a candidate is the exact source function.

The Lumina client needs the `lumina` cargo feature. It is part of `default` and `desktop`, and it is not part of `mobile`, so that mobile builds do not need the C toolchain of the TLS library.
