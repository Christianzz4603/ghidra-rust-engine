// Ghidra Rust Engine integration script.
// Run from Ghidra's Script Manager with the cursor inside the target function.

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

public class DecompileWithRustEngine extends GhidraScript {
    private static final long TIMEOUT_SECONDS = 300;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open.");
            return;
        }
        if (currentAddress == null) {
            printerr("Place the cursor at a function entry or inside a function first.");
            return;
        }

        String binaryPath = currentProgram.getExecutablePath();
        if (binaryPath == null || binaryPath.isBlank() ||
                !Files.isRegularFile(Path.of(binaryPath))) {
            printerr("The original executable is not available at the path recorded by Ghidra: "
                    + binaryPath);
            printerr("This first integration pass analyzes the original on-disk executable. "
                    + "Database-only and memory-patched programs need the future memory-snapshot bridge.");
            return;
        }

        String configuredEngine = System.getProperty("ghidra.rust.engine");
        if (configuredEngine == null || configuredEngine.isBlank()) {
            configuredEngine = System.getenv("GHIDRA_RUST_ENGINE");
        }

        File engineFile;
        if (configuredEngine == null || configuredEngine.isBlank()) {
            engineFile = askFile("Select Ghidra Rust Engine executable", "Select");
        }
        else {
            engineFile = new File(configuredEngine);
        }

        if (engineFile == null || !engineFile.isFile() || !engineFile.canExecute()) {
            printerr("The configured Ghidra Rust Engine executable is missing or not executable: "
                    + engineFile);
            return;
        }

        // Ghidra's textual address may include a space name. The current CLI accepts
        // numeric virtual addresses, so pass the unsigned offset explicitly.
        String address = "0x" + Long.toUnsignedString(currentAddress.getOffset(), 16);
        Path outputFile = Files.createTempFile("ghidra-rust-engine-", ".log");
        Process process = null;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);

        try {
            ProcessBuilder builder = new ProcessBuilder(
                    engineFile.getAbsolutePath(), "reconstruct", binaryPath, address);
            // A file redirect prevents large reports from filling an unread pipe buffer.
            builder.redirectErrorStream(true);
            builder.redirectOutput(outputFile.toFile());
            process = builder.start();

            while (!process.waitFor(150, TimeUnit.MILLISECONDS)) {
                if (monitor.isCancelled()) {
                    process.destroy();
                    if (!process.waitFor(2, TimeUnit.SECONDS)) {
                        process.destroyForcibly();
                    }
                    throw new CancelledException();
                }
                if (System.nanoTime() >= deadline) {
                    process.destroy();
                    if (!process.waitFor(2, TimeUnit.SECONDS)) {
                        process.destroyForcibly();
                    }
                    printerr("Rust decompilation exceeded the " + TIMEOUT_SECONDS + " second limit.");
                    return;
                }
                monitor.setMessage("Ghidra Rust Engine: analyzing " + address);
            }

            String output = Files.readString(outputFile, StandardCharsets.UTF_8);
            if (process.exitValue() != 0) {
                printerr("Ghidra Rust Engine exited with status " + process.exitValue() + ".");
                printerr(output);
                return;
            }
            println(output);
        }
        finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
            Files.deleteIfExists(outputFile);
        }
    }
}
