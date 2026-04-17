#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, struct
from pathlib import Path

def find_startcodes(buf: bytes):
    i=0
    while True:
        j=buf.find(b'\x00\x00\x01', i)
        if j < 0 or j+4 > len(buf):
            return
        yield j, buf[j+3]
        i = j+1

def prev_pack(pack_headers, pos):
    import bisect
    i = bisect.bisect_right(pack_headers, pos) - 1
    return pack_headers[i] if i >= 0 else None

def main():
    ap = argparse.ArgumentParser(description="43fc65 rank07 packet-level salvage splitter")
    ap.add_argument("rank07_pss")
    ap.add_argument("outdir")
    args = ap.parse_args()

    buf = Path(args.rank07_pss).read_bytes()
    codes = list(find_startcodes(buf))
    pack_headers = [p for p,c in codes if c == 0xBA]
    seq_headers = [p for p,c in codes if c == 0xB3]

    import bisect
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    segments = []
    for idx, sh in enumerate(seq_headers):
        start = prev_pack(pack_headers, sh)
        if start is None:
            continue
        if idx + 1 < len(seq_headers):
            end = prev_pack(pack_headers, seq_headers[idx+1])
        else:
            b9 = next((p for p,c in codes if c == 0xB9), None)
            end = b9
        if end is None or end <= start:
            continue
        seg = buf[start:end]
        name = f"seg_{idx:02d}_{start:08X}_{end:08X}.pss"
        (outdir / name).write_bytes(seg)
        segments.append((idx, start, end, len(seg)))

    manifest = outdir / "manifest.csv"
    with manifest.open("w", encoding="utf-8") as f:
        f.write("segment_idx,start_off,end_off,size,filename\n")
        for idx, start, end, size in segments:
            f.write(f"{idx},{start},{end},{size},seg_{idx:02d}_{start:08X}_{end:08X}.pss\n")

if __name__ == "__main__":
    main()