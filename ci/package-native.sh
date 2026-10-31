#!/usr/bin/env bash
# Collect the files produced by
#   cargo build --release --lib --target <target>
# into dist/ under stable, release-friendly names, and fail loudly if any
# expected file is missing. The expected names come from the crate's
# `crate-type = ["rlib", "cdylib", "staticlib"]` and the crate name
# `ghidra-decompiler` (library name `ghidra_decompiler`).
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <rust-target> <asset-name> <linux|android|macos|windows>" >&2
    exit 2
fi

target="$1"
name="$2"
kind="$3"

lib="ghidra_decompiler"
src="target/${target}/release"
dist="${DIST_DIR:-dist}"
prefix="ghidra-rust-engine-${name}"

mkdir -p "$dist"

copy() {
    local from="$1" to="$2"
    if [ ! -s "${src}/${from}" ]; then
        echo "error: expected build output '${src}/${from}' is missing or empty" >&2
        echo "contents of ${src}:" >&2
        ls -la "$src" >&2 || true
        exit 1
    fi
    cp "${src}/${from}" "${dist}/${to}"
    echo "packaged ${src}/${from} -> ${dist}/${to}"
}

case "$kind" in
    linux | android)
        copy "lib${lib}.so" "${prefix}.so"
        copy "lib${lib}.a" "${prefix}.a"
        copy "lib${lib}.rlib" "${prefix}.rlib"
        ;;
    macos)
        copy "lib${lib}.dylib" "${prefix}.dylib"
        copy "lib${lib}.a" "${prefix}.a"
        copy "lib${lib}.rlib" "${prefix}.rlib"
        ;;
    windows)
        # rustc names the DLL import library `<name>.dll.lib` and the static
        # library `<name>.lib`; the rlib keeps the `lib` prefix on MSVC too.
        copy "${lib}.dll" "${prefix}.dll"
        copy "${lib}.dll.lib" "${prefix}-import.lib"
        copy "${lib}.lib" "${prefix}.lib"
        copy "lib${lib}.rlib" "${prefix}.rlib"
        ;;
    *)
        echo "error: unknown platform kind '${kind}'" >&2
        exit 2
        ;;
esac

# Ship the C header next to the libraries when it exists.
if [ -f include/ghidra_engine.h ]; then
    cp include/ghidra_engine.h "${dist}/ghidra_engine.h"
fi
