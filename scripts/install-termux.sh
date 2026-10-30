#!/system/bin/sh
set -eu

if [ -z "${PREFIX:-}" ] || [ ! -d "$PREFIX" ]; then
    printf 'This installer must be run inside Termux.\n' >&2
    exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BINARY="$ROOT/target/release/examples/decomp"
DEST="$PREFIX/bin"

if [ ! -x "$BINARY" ]; then
    printf 'Built decompiler not found. Build it first with:\n  cd %s\n  cargo build --release --example decomp\n' "$ROOT" >&2
    exit 1
fi

if [ -e "$DEST/open" ] && [ "${1:-}" != "--force" ]; then
    printf 'A command already exists at %s/open.\n' "$DEST" >&2
    printf 'If you want to replace it, rerun: sh scripts/install-termux.sh --force\n' >&2
    exit 1
fi

mkdir -p "$DEST"
install -m 755 "$BINARY" "$DEST/ghidra-decompiler"
install -m 755 "$ROOT/scripts/termux-open" "$DEST/open"
printf 'Installed successfully.\n'
printf 'Try: open /sdcard/libtest.so\n'
printf 'The interactive decompiler will stay open after loading the file.\n'
