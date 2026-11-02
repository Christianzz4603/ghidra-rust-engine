# Resource-bounded decompilation

The engine accepts large native libraries, but a host application must not assume
that every function or whole-program pass is safe to run in one UI operation.

## Built-in guardrails

- Object-file capability detection reads only the file header instead of loading
  the entire library just to identify its format.
- Object image bytes are shared between the architecture builder and load image,
  avoiding a second full-size copy of large ELF/PE/Mach-O inputs.
- Single-function decompilation rejects function bodies larger than 1 MiB with
  a normal engine error rather than attempting an unbounded analysis.
- P-code and disassembly ranges are capped at 4 MiB and 250,000 instructions.
- The P-code cache is capped at 16 MiB.
- ARM64 prologue discovery and reachable-function discovery have hard candidate
  and function-count ceilings.
- The Ghidra worker uses `PseudocodeOptions::resource_bounded()`, limiting a
  batch to 1,000 functions by default and returned function text to 128 KiB.

## Host application recommendations

- Run decompilation on a background worker, never on the UI thread.
- Decompile one function at a time and release result buffers after display/export.
- Treat limit errors as per-function failures; do not retry the same oversized
  function in a tight loop.
- Offer paging or range-based analysis instead of forcing a whole-library pass.
- Keep the process alive across functions to reuse the loaded image and caches.

These are defensive limits, not a promise that every binary can be decompiled
without failure. Native process memory pressure, unsupported instructions,
malformed binaries, platform constraints, and host-side bugs can still cause
failures. Validate against the target library on each supported device class.
