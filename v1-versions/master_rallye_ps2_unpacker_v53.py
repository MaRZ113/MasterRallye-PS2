#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from pathlib import Path

RID_MARKERS = {
    0x07: b"\x00\x00\x01\x07",
    0x08: b"\x00\x00\x01\x08",
    0x09: b"\x00\x00\x01\x09",
    0x0A: b"\x00\x00\x01\x0A",
    0x0B: b"\x00\x00\x01\x0B",
}

def find_all(mm: mmap.mmap, needle: bytes):
    out = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def main():
    ap = argparse.ArgumentParser(description='BX v53 global rid0A locator')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('locate-rid0a')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--window-before', type=int, default=96)
    p.add_argument('--window-after', type=int, default=512)
    p.add_argument('--record-size', type=int, default=253)

    ns = ap.parse_args()
    if ns.cmd != 'locate-rid0a':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        hits_0a = find_all(mm, RID_MARKERS[0x0A])

        rows = []
        summary = []
        summary.append('BX v53 global rid0A locator')
        summary.append('==========================')
        summary.append(f'tng_path: {tng_path}')
        summary.append(f'rid0A_hits: {len(hits_0a)}')
        summary.append('')

        for idx, off in enumerate(hits_0a, 1):
            around_start = max(0, off - ns.window_before)
            around_len = ns.window_before + ns.window_after
            blob = carve(tng_path, around_start, around_len)

            # neighborhood markers relative to around window
            rel = {}
            for rid, marker in RID_MARKERS.items():
                pos = blob.find(marker)
                rel[f'rid_{rid:02X}_rel'] = pos

            # fixed-size candidate record from exact marker
            rec = carve(tng_path, off, ns.record_size)

            hit_dir = out_dir / 'hits' / f'hit_{idx:03d}_0x{off:X}'
            hit_dir.mkdir(parents=True, exist_ok=True)
            (hit_dir / 'around.bin').write_bytes(blob)
            (hit_dir / 'around.hex.txt').write_text(blob.hex(), encoding='utf-8')
            (hit_dir / 'rid0A_record_253.bin').write_bytes(rec)
            (hit_dir / 'rid0A_record_253.hex.txt').write_text(rec.hex(), encoding='utf-8')

            meta = {
                'index': idx,
                'off': off,
                'off_hex': f'0x{off:X}',
                **rel,
            }
            (hit_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            rows.append({
                'index': idx,
                'off': off,
                'off_hex': f'0x{off:X}',
                **rel,
            })

        mm.close()

    with (out_dir / 'rid0a_hits.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['index','off','off_hex','rid_07_rel','rid_08_rel','rid_09_rel','rid_0A_rel','rid_0B_rel']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    summary.append('Top hits:')
    for r in rows[:20]:
        summary.append(
            f'{r["index"]:03d}) {r["off_hex"]} '
            f'07={r["rid_07_rel"]} 08={r["rid_08_rel"]} 09={r["rid_09_rel"]} 0A={r["rid_0A_rel"]} 0B={r["rid_0B_rel"]}'
        )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
