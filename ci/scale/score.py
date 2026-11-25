#!/usr/bin/env python3
"""Score function recovery against the unstripped library's symbol table.

usage: score.py <libscale.so> <analysis_dir> <binary_name>
Prints a markdown block. Ground truth = defined text symbols (nm) of the unstripped library.
Recovered = function addresses in <binary_name>.csv written by the analysis.
"""
import csv
import re
import subprocess
import sys

lib, outdir, name = sys.argv[1:4]
truth = set()
for line in subprocess.run(["nm", "--defined-only", lib], capture_output=True, text=True, check=True).stdout.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[1] in ("T", "t") and not parts[2].startswith(("_init", "_fini", "deregister", "register_tm", "frame_dummy", "__do_global")):
        truth.add(int(parts[0], 16))
found = set()
decompiled = 0
try:
    with open(f"{outdir}/{name}.csv", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) >= 3 and row[0] == "analysis_status":
                m = re.fullmatch(r"0x[0-9a-fA-F]+", row[2])
                if m:
                    found.add(int(row[2], 16))
                    if "decompile=ok" in ",".join(row[3:]):
                        decompiled += 1
except FileNotFoundError:
    pass
hit = truth & found
print(f"- ground-truth functions (nm): {len(truth)}")
print(f"- functions the engine reached (csv rows): {len(found)}")
print(f"- recovered ground-truth functions: {len(hit)} ({100.0 * len(hit) / max(1, len(truth)):.2f}% recall)")
print(f"- extra addresses (not in nm): {len(found - truth)}")
print(f"- functions decompiled ok: {decompiled}")
