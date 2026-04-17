#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

def read_csv(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def parse_int(v):
    if v in ('', None):
        return None
    if isinstance(v, float):
        return int(v)
    s = str(v).strip()
    if not s or s.lower() == 'nan':
        return None
    return int(float(s))

def main():
    ap = argparse.ArgumentParser(description='BX v36 physical branch packet extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-branches')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v35_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--window-before', type=int, default=32)
    p.add_argument('--window-size', type=int, default=4096)
    p.add_argument('--max-per-signature', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'extract-branches':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v35_root: Path = ns.v35_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = read_csv(v35_root / 'classified_clusters.csv')

    # strongest physical hits only
    filt = []
    for r in rows:
        gap12 = parse_int(r.get('gap12'))
        gap23 = parse_int(r.get('gap23'))
        bx_count = parse_int(r.get('bx_count_in_window'))
        sig = r.get('signature_4', '')
        if gap12 == 9 and gap23 == 9 and bx_count is not None and bx_count >= 5 and sig.startswith('BX*H|BX91|BXA0|'):
            filt.append(r)

    sig_counts = Counter(r['signature_4'] for r in filt)
    top_sigs = [sig for sig, _ in sig_counts.most_common(4)]

    summary = []
    summary.append('BX v36 physical branch extractor')
    summary.append('===============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'candidate_hits: {len(filt)}')
    summary.append('top_signatures:')
    for sig in top_sigs:
        summary.append(f'  {sig}: {sig_counts[sig]}')
    summary.append('')

    manifest = []
    for sig in top_sigs:
        sig_dir = out_dir / ('sig_' + sig.replace('|','__').replace('*','_').replace(' ','_').replace('\\','_').replace('/','_'))
        sig_dir.mkdir(parents=True, exist_ok=True)
        sig_hits = [r for r in filt if r['signature_4'] == sig][:ns.max_per_signature]

        for r in sig_hits:
            idx = int(r['index'])
            rid01_off = parse_int(r['rid01_off'])
            rid02_off = parse_int(r.get('rid02_off'))
            rid03_off = parse_int(r.get('rid03_common_off'))
            start = max(0, rid01_off - ns.window_before)

            blob = carve(tng_path, start, ns.window_size)
            hdir = sig_dir / f'hit_{idx:03d}_{r["rid01_off_hex"]}'
            hdir.mkdir(parents=True, exist_ok=True)
            (hdir / 'packet_candidate.bin').write_bytes(blob)
            (hdir / 'packet_candidate.hex.txt').write_text(blob.hex(), encoding='utf-8')

            # Also provide tighter slices
            if rid01_off is not None:
                (hdir / 'from_rid01.bin').write_bytes(carve(tng_path, rid01_off, 1024))
            if rid02_off is not None:
                (hdir / 'from_rid02.bin').write_bytes(carve(tng_path, rid02_off, 1024))
            if rid03_off is not None:
                (hdir / 'from_rid03_common.bin').write_bytes(carve(tng_path, rid03_off, 1024))

            meta = {
                'index': idx,
                'signature_4': sig,
                'rid01_off': rid01_off,
                'rid02_off': rid02_off,
                'rid03_common_off': rid03_off,
                'gap12': parse_int(r.get('gap12')),
                'gap23': parse_int(r.get('gap23')),
                'bx_count_in_window': parse_int(r.get('bx_count_in_window')),
            }
            (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            manifest.append({
                'signature_4': sig,
                'index': idx,
                'rid01_off_hex': r['rid01_off_hex'],
                'rid02_off_hex': r.get('rid02_off_hex',''),
                'rid03_common_off_hex': r.get('rid03_common_off_hex',''),
                'bx_count_in_window': r.get('bx_count_in_window',''),
            })

        summary.append(f'{sig}: exported {len(sig_hits)} hit(s)')

    with (out_dir / 'branch_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['signature_4','index','rid01_off_hex','rid02_off_hex','rid03_common_off_hex','bx_count_in_window'])
        w.writeheader()
        w.writerows(manifest)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
