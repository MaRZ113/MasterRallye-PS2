#!/usr/bin/env python3
"""
Master Rallye PS2 · Stage 21
43fc7f split-aware recovery and selective promotion

This script documents the exact byte-based recovery decisions used in Stage 21.
It assumes the Stage 20 source bundles already exist.
"""

from pathlib import Path

RANK04_TRIM_LOCAL = 172271
RANK07_SEG_A_END_LOCAL = 1557331
RANK07_SEG_B_START_LOCAL = 1647443

def byte_slice(src: Path, start: int | None = None, end: int | None = None) -> bytes:
    data = src.read_bytes()
    return data[slice(start, end)]

def main() -> None:
    print("Stage 21 recovery parameters")
    print(" rank04 trim local start =", hex(RANK04_TRIM_LOCAL))
    print(" rank07 segA end local   =", hex(RANK07_SEG_A_END_LOCAL))
    print(" rank07 segB start local =", hex(RANK07_SEG_B_START_LOCAL))
    print()
    print("Policy:")
    print(" - rank04 => trim and promote")
    print(" - rank07 => split into evidence-only subsegments until routing is solved")

if __name__ == "__main__":
    main()
