#!/system/bin/sh
set -eu

if [ -z "${PREFIX:-}" ] || [ ! -d "$PREFIX" ]; then
    printf 'This installer must be run inside Termux.\n' >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEST="$PREFIX/bin"
BINARY=""
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        *)
            if [ -n "$BINARY" ]; then
                printf 'Usage: sh install-termux.sh [binary-path] [--force]\n' >&2
                exit 2
            fi
            BINARY=$arg
            ;;
    esac
done

if [ -z "$BINARY" ]; then
    if [ -x "$SCRIPT_DIR/ghidra-engine" ]; then
        BINARY="$SCRIPT_DIR/ghidra-engine"
    else
        ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
        BINARY="$ROOT/target/release/examples/decomp"
    fi
fi

case "$BINARY" in
    /*) ;;
    *) BINARY="$PWD/$BINARY" ;;
esac

WRAPPER="$SCRIPT_DIR/termux-open"
if [ ! -f "$BINARY" ]; then
    printf 'Standalone binary not found: %s\n' "$BINARY" >&2
    printf 'Pass a binary path or extract the Android release archive first.\n' >&2
    exit 1
fi
if [ ! -f "$WRAPPER" ]; then
    printf 'The termux-open launcher is missing beside this installer.\n' >&2
    exit 1
fi

if [ -e "$DEST/open" ] && [ "$FORCE" -ne 1 ]; then
    printf 'A command already exists at %s/open.\n' "$DEST" >&2
    printf 'To replace it, rerun: sh install-termux.sh --force\n' >&2
    exit 1
fi

mkdir -p "$DEST"
install -m 755 "$BINARY" "$DEST/ghidra-engine"
ln -sf ghidra-engine "$DEST/ghidra-decompiler"
install -m 755 "$WRAPPER" "$DEST/open"

printf 'Ghidra Rust Engine installed successfully.\n'
printf 'Run: ghidra-engine --version\n'
printf 'Or load a binary with: open /sdcard/libtest.so\n'
printf 'No Rust toolchain or source checkout is needed on this device.\n'
