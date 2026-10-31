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
        *) if [ -n "$BINARY" ]; then
               printf 'Usage: sh install-termux.sh [binary-path] [--force]\n' >&2
               exit 2
           fi
           BINARY=$arg ;;
    esac
done

# Works from the repository, an extracted release archive, or ~/ where
# install-termux.sh sits beside the ghidra-rust-engine clone.
REPO_ROOT=""
if [ -f "$SCRIPT_DIR/Cargo.toml" ] && [ -d "$SCRIPT_DIR/scripts" ]; then
    REPO_ROOT="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/ghidra-rust-engine/Cargo.toml" ]; then
    REPO_ROOT="$SCRIPT_DIR/ghidra-rust-engine"
elif [ -f "$SCRIPT_DIR/../Cargo.toml" ] && [ -d "$SCRIPT_DIR/../scripts" ]; then
    REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
fi
WRAPPER=""
for candidate in "$SCRIPT_DIR/termux-open" "$SCRIPT_DIR/scripts/termux-open" "$REPO_ROOT/scripts/termux-open"; do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then WRAPPER="$candidate"; break; fi
done
if [ -z "$BINARY" ]; then
    for candidate in \
        "$SCRIPT_DIR/ghidra-rust_cli" \
        "$SCRIPT_DIR/ghidra-rust_cli".bin \
        "$REPO_ROOT/target/release/examples/decomp" \
        "$SCRIPT_DIR/ghidra-rust-engine/target/release/examples/decomp"; do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then BINARY="$candidate"; break; fi
    done
fi
if [ -n "$BINARY" ]; then
    case "$BINARY" in /*) ;; *) BINARY="$PWD/$BINARY" ;; esac
fi
if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    printf 'Standalone binary not found. Checked the release archive and repository build output.\n' >&2
    printf 'Build with: cd ~/ghidra-rust-engine && cargo build --release --example decomp\n' >&2
    printf 'Or pass the executable path: sh install-termux.sh /path/to/binary\n' >&2
    exit 1
fi
if [ -z "$WRAPPER" ]; then
    printf 'termux-open launcher not found beside installer or in repository scripts/.\n' >&2
    exit 1
fi
if [ -e "$DEST/open" ] && [ "$FORCE" -ne 1 ]; then
    printf 'A command already exists at %s/open. Rerun with --force to replace it.\n' "$DEST" >&2
    exit 1
fi
mkdir -p "$DEST"
install -m 755 "$BINARY" "$DEST/ghidra-rust_cli"
ln -sf ghidra-rust_cli "$DEST/ghidra-rust"
install -m 755 "$WRAPPER" "$DEST/open"
printf 'Ghidra Rust CLI installed. Run: ghidra-rust_cli --version\n'
printf 'Load a binary with: open /sdcard/libtest.so\n'
