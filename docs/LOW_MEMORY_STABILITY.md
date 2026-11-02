# Keeping large-library analysis stable

The engine uses defensive limits and bounded work to reduce the chance that a large or malformed executable overwhelms its host. These controls are safeguards, not a guarantee that every binary can be analyzed or that native code can never crash.

## Current safeguards

- File-backed image loading reads at most 512 MiB plus one byte before rejecting an oversized input.
- Raw program memory is shared through `Arc` between the worker, architecture builder, and load-image implementation. The worker moves received blocks into that shared backing store instead of retaining an extra copy in its snapshot.
- ELF and generic object parsing cap section and symbol enumeration, bound symbol-name length, and validate file-backed section ranges with checked arithmetic.
- P-code cache eviction is least-recently-used and accounts for vector and string capacities rather than only logical element sizes.
- P-code and disassembly requests have range and instruction-count limits, and their initial allocations are kept modest.
- ARM64 prologue scanning is chunked and stops after a 128 MiB scan budget or 50,000 candidates.
- Worker requests are isolated. An unexpected unwind becomes an error response, and the worker resets its session before accepting another request.

## Low-memory operating guidance

- Prefer the worker process over running long analysis on a UI thread.
- Analyze one function or bounded address range at a time.
- Release returned instruction and pseudocode buffers when they are no longer needed.
- Treat an oversized function or request as a per-operation failure, not a reason to retry the same work without limits.
- Keep the host snapshot and worker memory transfer bounded. Avoid converting large binary buffers to hexadecimal JSON when the chunked binary transport is available.

## Known limits

The 512 MiB image limit is a hard safety ceiling, not a promise that a 512 MiB image fits on every device. Parsing metadata, analysis state, and output can require additional memory. The current worker protocol still serializes metadata and has no true concurrent cancellation. ARM64 prologue scanning can intentionally leave later portions of a very large executable unexplored after its scan budget is exhausted.

For the same reason, “crash-proof” is not a technically supportable claim. The goal is graceful rejection, bounded memory use, recoverable worker errors, and testable behavior under stress.
