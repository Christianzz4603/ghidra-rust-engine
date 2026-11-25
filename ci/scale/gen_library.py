#!/usr/bin/env python3
"""Generate a large shared library with known function boundaries.

usage: gen_library.py <target_mb> <out_dir>

Writes <out_dir>/libscale.so (with symbols, used as ground truth) and
<out_dir>/libscale.stripped.so (symbols removed; what the analysis is run on).
Most functions are hidden-visibility, so a stripped library keeps dynamic symbols
for only ~5% of them. The rest must be recovered from unwind tables, calls and code shape.
"""
import os
import random
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

FUNCS_PER_UNIT = 400


def unit_source(unit, rng):
    lines = ["#include <stddef.h>", "#include <string.h>", "#include <stdio.h>", ""]
    lines.append("#define HID __attribute__((visibility(\"hidden\"))) __attribute__((noinline))")
    lines.append("#define EXP __attribute__((visibility(\"default\"))) __attribute__((noinline))")
    lines.append(f"static const char *const table_{unit}[] = {{")
    for i in range(16):
        lines.append(f'    "unit {unit} message {i} {rng.getrandbits(32):08x}",')
    lines.append("};")
    names = []
    for f in range(FUNCS_PER_UNIT):
        name = f"u{unit}_f{f}"
        exported = f % 20 == 0
        attr = "EXP" if exported else "HID"
        callee = ""
        if names:
            c = rng.choice(names)
            callee = f"    acc += {c}(a + {rng.randrange(100)}, b ^ {rng.randrange(1 << 16)});"
        body = []
        for _ in range(rng.randrange(2, 6)):
            body.append("    {")
            body.extend(body_piece(unit, rng))
            body.append("    }")
        lines.append(f"{attr} long {name}(int a, int b) {{")
        lines.append("    long acc = 0;")
        lines.extend(body)
        if callee:
            lines.append(callee)
        lines.append("    return acc;")
        lines.append("}")
        names.append(name)
    return "\n".join(lines) + "\n"


def body_piece(unit, rng):
    body = []
    if True:
        kind = rng.randrange(6)
        if kind == 0:
            body = ["    for (int i = 0; i < (b & 15); i++) acc = acc * 31 + (a ^ i);"]
        elif kind == 1:
            cases = "\n".join(f"        case {k}: acc += a * {rng.randrange(1, 90)}; break;" for k in range(rng.randrange(4, 12)))
            body = ["    switch (a & 15) {", cases, "        default: acc -= b; }"]
        elif kind == 2:
            body = [f"    acc += (long)strlen(table_{unit}[a & 15]);"]
        elif kind == 3:
            body = ["    if (a > b) { acc += a / (b | 1); } else { acc += (long)b % (a | 1); }"]
        elif kind == 4:
            body = ["    long t[8];", "    for (int i = 0; i < 8; i++) t[i] = a + i * b;",
                    "    for (int i = 0; i < 8; i++) acc ^= t[i] << (i & 7);"]
        else:
            body = [f'    char buf[64]; snprintf(buf, sizeof buf, "%s:%d", table_{unit}[b & 15], a);',
                    "    acc += buf[0] + (long)strlen(buf);"]
    return body


def compile_unit(args):
    src_dir, unit = args
    c = os.path.join(src_dir, f"u{unit}.c")
    o = os.path.join(src_dir, f"u{unit}.o")
    with open(c, "w") as fh:
        fh.write(unit_source(unit, random.Random(unit)))
    subprocess.run(["gcc", "-O1", "-g0", "-fPIC", "-fvisibility=hidden", "-c", c, "-o", o], check=True)
    os.remove(c)
    return o


def main():
    # the stripped .so is about two thirds of the summed object size; overshoot so it is at least target_mb
    target = int(float(sys.argv[1]) * 1024 * 1024 * 1.9)
    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    src = os.path.join(out, "obj")
    os.makedirs(src, exist_ok=True)
    objs, total, unit = [], 0, 0
    workers = os.cpu_count() or 2
    with ThreadPoolExecutor(workers) as pool:
        while total < target:
            batch = [(src, unit + i) for i in range(workers * 4)]
            unit += len(batch)
            for o in pool.map(compile_unit, batch):
                objs.append(o)
                total += os.path.getsize(o)
            print(f"objects: {len(objs)}, bytes so far: {total}", flush=True)
    lib = os.path.join(out, "libscale.so")
    subprocess.run(["gcc", "-shared", "-o", lib] + objs, check=True)
    stripped = os.path.join(out, "libscale.stripped.so")
    subprocess.run(["strip", "--strip-all", "-o", stripped, lib], check=True)
    print("libscale.so", os.path.getsize(lib), "bytes")
    print("libscale.stripped.so", os.path.getsize(stripped), "bytes")


if __name__ == "__main__":
    main()
