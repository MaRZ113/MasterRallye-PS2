#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from pathlib import Path

TARGET_SIG8 = '0000010a423f729a'
RID0B = b'\x00\x00\x01\x0B'

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def read_csv(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v64 subtype-729a bridge extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-729a-bridge')
    p.add_argument('tng_path', type=Path)
    p.add_argument('classified_hits_csv', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-size', type=int, default=253)
    p.add_argument('--sig8', type=str, default=TARGET_SIG8)

    ns = ap.parse_args()
    if ns.cmd != 'extract-729a-bridge':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    classified_hits_csv: Path = ns.classified_hits_csv
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = read_csv(classified_hits_csv)
    binary_rows = [r for r in rows if r.get('kind') == 'binary_like']

    hits = []
    for r in binary_rows:
        off = int(r['off'])
        rec = carve(tng_path, off, ns.record_size)
        if rec[:8].hex() == ns.sig8.lower():
            hits.append({
                'index': int(r['index']),
                'off': off,
                'off_hex': r['off_hex'],
                'record': rec,
            })

    summary = []
    summary.append('BX v64 subtype bridge extractor')
    summary.append('==============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig8: {ns.sig8.lower()}')
    summary.append(f'hits: {len(hits)}')
    summary.append('')

    manifest_rows = []

    for item in hits:
        # From rid0A start to the expected 0B marker at +414, plus 32 bytes after it
        start = item['off']
        size = 414 + 9 + 32
        blob = carve(tng_path, start, size)

        # Segments:
        rid0a = blob[:253]
        gap = blob[253:414]
        rid0b = blob[414:423]
        post0b = blob[423:]

        hdir = out_dir / f'hit_{item["index"]:05d}_{item["off_hex"]}'
        hdir.mkdir(parents=True, exist_ok=True)

        write_bytes(hdir / 'rid0A_253.bin', rid0a)
        write_bytes(hdir / 'gap_161.bin', gap)
        write_bytes(hdir / 'rid0B_9.bin', rid0b)
        write_bytes(hdir / 'post0B_32.bin', post0b)

        (hdir / 'rid0A_253.hex.txt').write_text(rid0a.hex(), encoding='utf-8')
        (hdir / 'gap_161.hex.txt').write_text(gap.hex(), encoding='utf-8')
        (hdir / 'rid0B_9.hex.txt').write_text(rid0b.hex(), encoding='utf-8')
        (hdir / 'post0B_32.hex.txt').write_text(post0b.hex(), encoding='utf-8')

        meta = {
            'index': item['index'],
            'off': item['off'],
            'off_hex': item['off_hex'],
            'sig8': item['record'][:8].hex(),
            'rid0B_expected_at_rel': 414,
            'rid0B_head_hex': rid0b[:4].hex(),
            'rid0B_exact_marker': rid0b.startswith(RID0B),
        }
        (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

        manifest_rows.append({
            'index': item['index'],
            'off_hex': item['off_hex'],
            'sig8': item['record'][:8].hex(),
            'gap_len': len(gap),
            'rid0B_exact_marker': meta['rid0B_exact_marker'],
        })

        summary.append(
            f'{item["off_hex"]}: gap_len={len(gap)} rid0B_exact={meta["rid0B_exact_marker"]} '
            f'rid0B_head={rid0b[:4].hex()} post0B_len={len(post0b)}'
        )

    with (out_dir / 'bridge_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off_hex','sig8','gap_len','rid0B_exact_marker'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
