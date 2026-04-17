#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Tuple

RECORD_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
}

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[i] == blobs[0][i] for b in blobs[1:]):
        i += 1
    return i

def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[-1-i] == blobs[0][-1-i] for b in blobs[1:]):
        i += 1
    return i

def find_all(data: bytes, needle: bytes) -> List[int]:
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def nearest_markers(before: bytes, after: bytes, packet_len: int):
    rows = []
    # before: relative to packet start are negative
    for name, marker in RECORD_MARKERS.items():
        for off in find_all(before, marker):
            rows.append({'rid': name, 'delta': off - len(before)})
        for off in find_all(after, marker):
            rows.append({'rid': name, 'delta': packet_len + off})
    rows.sort(key=lambda r: r['delta'])
    prev_rows = [r for r in rows if r['delta'] < 0]
    next_rows = [r for r in rows if r['delta'] > 0]
    prev_nearest = prev_rows[-1] if prev_rows else None
    next_nearest = next_rows[0] if next_rows else None
    return rows, prev_nearest, next_nearest

def main():
    ap = argparse.ArgumentParser(description='BX v66 exact packet context inspector')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('inspect-exact-context')
    p.add_argument('tng_path', type=Path)
    p.add_argument('offsets_csv', type=Path)
    p.add_argument('packet_bin', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1024)

    ns = ap.parse_args()
    if ns.cmd != 'inspect-exact-context':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    offsets_csv: Path = ns.offsets_csv
    packet_bin: Path = ns.packet_bin
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    packet = read_bytes(packet_bin)
    packet_len = len(packet)

    with offsets_csv.open('r', encoding='utf-8', newline='') as f:
        offsets = list(csv.DictReader(f))

    before_blobs = []
    after_blobs = []
    summary = []
    summary.append('BX v66 exact packet context inspector')
    summary.append('====================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'packet_len: {packet_len}')
    summary.append(f'offset_count: {len(offsets)}')
    summary.append('')

    context_rows = []

    with tng_path.open('rb') as f:
        for row in offsets:
            off = int(row['off'])
            off_hex = row['off_hex']

            start = max(0, off - ns.before)
            f.seek(start)
            before = f.read(off - start)

            f.seek(off + packet_len)
            after = f.read(ns.after)

            before_blobs.append(before)
            after_blobs.append(after)

            hdir = out_dir / f'hit_{int(row["index"]):03d}_{off_hex}'
            hdir.mkdir(parents=True, exist_ok=True)
            write_bytes(hdir / 'before.bin', before)
            write_bytes(hdir / 'packet.bin', packet)
            write_bytes(hdir / 'after.bin', after)
            (hdir / 'before.hex.txt').write_text(before.hex(), encoding='utf-8')
            (hdir / 'after.hex.txt').write_text(after.hex(), encoding='utf-8')

            all_marks, prev_nearest, next_nearest = nearest_markers(before, after, packet_len)
            (hdir / 'markers.json').write_text(json.dumps(all_marks, indent=2), encoding='utf-8')

            context_rows.append({
                'index': int(row['index']),
                'off_hex': off_hex,
                'prev_rid': prev_nearest['rid'] if prev_nearest else '',
                'prev_delta': prev_nearest['delta'] if prev_nearest else '',
                'next_rid': next_nearest['rid'] if next_nearest else '',
                'next_delta': next_nearest['delta'] if next_nearest else '',
            })

            summary.append(
                f'{off_hex}: prev={prev_nearest["rid"]+"@"+str(prev_nearest["delta"]) if prev_nearest else "none"} '
                f'next={next_nearest["rid"]+"@"+str(next_nearest["delta"]) if next_nearest else "none"}'
            )

    cp_after = common_prefix_len(after_blobs)
    cs_before = common_suffix_len(before_blobs)

    summary.append('')
    summary.append(f'common_before_suffix: {cs_before}')
    summary.append(f'common_after_prefix: {cp_after}')

    if before_blobs:
        shared_before_suffix = before_blobs[0][len(before_blobs[0]) - cs_before:] if cs_before > 0 else b''
        shared_after_prefix = after_blobs[0][:cp_after]
        write_bytes(out_dir / 'shared_before_suffix.bin', shared_before_suffix)
        write_bytes(out_dir / 'shared_after_prefix.bin', shared_after_prefix)
        (out_dir / 'shared_before_suffix.hex.txt').write_text(shared_before_suffix.hex(), encoding='utf-8')
        (out_dir / 'shared_after_prefix.hex.txt').write_text(shared_after_prefix.hex(), encoding='utf-8')

    with (out_dir / 'context_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off_hex','prev_rid','prev_delta','next_rid','next_delta'])
        w.writeheader()
        w.writerows(context_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
