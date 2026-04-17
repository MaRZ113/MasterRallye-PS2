#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

RID0D_LEN = 54
RID0C_LEN = 507
TARGET_SIG8_0D = '0000010d423f4fc8'
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
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

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def find_markers(blob: bytes):
    rows = []
    for rid, marker in RID_MARKERS.items():
        offs = []
        start = 0
        while True:
            i = blob.find(marker, start)
            if i == -1:
                break
            offs.append(i)
            start = i + 1
        for off in offs:
            rows.append({'rid': rid, 'rel_off': off})
    rows.sort(key=lambda r: r['rel_off'])
    return rows

def main():
    ap = argparse.ArgumentParser(description='BX v85 companion rid0D family locator')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('locate-companion-0d')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig8', type=str, default=TARGET_SIG8_0D)
    p.add_argument('--before', type=int, default=1024)
    p.add_argument('--after', type=int, default=256)
    p.add_argument('--probe-prev-0c-len', type=int, default=507)

    ns = ap.parse_args()
    if ns.cmd != 'locate-companion-0d':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    sig8 = bytes.fromhex(ns.sig8.lower())
    summary = []
    summary.append('BX v85 companion rid0D family locator')
    summary.append('====================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig8: {ns.sig8.lower()}')
    summary.append('')

    rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        hits = find_all(mm, sig8)

        summary.append(f'raw_sig8_hits: {len(hits)}')
        summary.append('')

        for idx, off in enumerate(hits, 1):
            if off + RID0D_LEN > mm.size():
                continue

            record = bytes(mm[off:off + RID0D_LEN])

            before_start = max(0, off - ns.before)
            before = bytes(mm[before_start:off])
            after = bytes(mm[off + RID0D_LEN: off + RID0D_LEN + ns.after])

            # possible preceding 0C candidate exactly 821 bytes before record start,
            # because in v84 companion tail appeared at 0D@821 relative to rid0C start
            prev_0c_off = off - 821
            prev_0c_ok = False
            prev_0c_sig8 = ''
            prev_0c_blob = b''
            if prev_0c_off >= 0 and prev_0c_off + ns.probe_prev_0c_len <= mm.size():
                prev_0c_blob = bytes(mm[prev_0c_off: prev_0c_off + ns.probe_prev_0c_len])
                if prev_0c_blob[:4] == RID_MARKERS['0C']:
                    prev_0c_ok = True
                    prev_0c_sig8 = prev_0c_blob[:8].hex()

            hdir = out_dir / f'hit_{idx:03d}_0x{off:X}'
            hdir.mkdir(parents=True, exist_ok=True)
            write_bytes(hdir / 'rid0D_54.bin', record)
            write_bytes(hdir / 'before.bin', before)
            write_bytes(hdir / 'after.bin', after)
            (hdir / 'rid0D_54.hex.txt').write_text(record.hex(), encoding='utf-8')
            (hdir / 'before.hex.txt').write_text(before.hex(), encoding='utf-8')
            (hdir / 'after.hex.txt').write_text(after.hex(), encoding='utf-8')

            if prev_0c_blob:
                write_bytes(hdir / 'prev_0C_507.bin', prev_0c_blob)
                (hdir / 'prev_0C_507.hex.txt').write_text(prev_0c_blob.hex(), encoding='utf-8')

            markers = find_markers(before + record + after)
            (hdir / 'markers.json').write_text(json.dumps(markers, indent=2), encoding='utf-8')

            rows.append({
                'index': idx,
                'off_hex': f'0x{off:X}',
                'prev_0c_at_minus_821': 1 if prev_0c_ok else 0,
                'prev_0c_sig8': prev_0c_sig8,
                'rid0d_sig8': record[:8].hex(),
            })

            summary.append(
                f'{idx:03d}) off=0x{off:X} prev_0c_at_-821={prev_0c_ok} prev_0c_sig8={prev_0c_sig8}'
            )

        mm.close()

    with (out_dir / 'companion_0d_hits.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off_hex','prev_0c_at_minus_821','prev_0c_sig8','rid0d_sig8'])
        w.writeheader()
        w.writerows(rows)

    summary.append('')
    summary.append('Grouped prev_0C sig8:')
    cnt = Counter(r['prev_0c_sig8'] for r in rows if r['prev_0c_sig8'])
    for sig8, count in cnt.most_common():
        summary.append(f'  {sig8} :: {count}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'raw_sig8_hits': len(rows),
        'grouped_prev_0c_sig8': cnt,
    }, indent=2, default=list), encoding='utf-8')

if __name__ == '__main__':
    main()
