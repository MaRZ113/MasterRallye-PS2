#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
import hashlib
from collections import Counter
from pathlib import Path

RECORD_LEN = 507
DEFAULT_FAMILY_DIR = '09_0000010c423a0868'

RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def find_all_mm(mm: mmap.mmap, needle: bytes):
    out = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def find_all(data: bytes, needle: bytes):
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def nearest_markers(before: bytes, after: bytes, rec_len: int):
    rows = []
    for rid, marker in RID_MARKERS.items():
        for off in find_all(before, marker):
            rows.append({'rid': rid, 'delta': off - len(before)})
        for off in find_all(after, marker):
            rows.append({'rid': rid, 'delta': rec_len + off})
    rows.sort(key=lambda r: r['delta'])
    prev_rows = [r for r in rows if r['delta'] < 0]
    next_rows = [r for r in rows if r['delta'] > 0]
    return prev_rows[-1] if prev_rows else None, next_rows[0] if next_rows else None, rows

def main():
    ap = argparse.ArgumentParser(description='BX v92 rid0C sibling family transfer probe')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('probe-rid0c-sibling')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v74_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--family-dir', type=str, default=DEFAULT_FAMILY_DIR)
    p.add_argument('--record-len', type=int, default=RECORD_LEN)
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1024)

    ns = ap.parse_args()
    if ns.cmd != 'probe-rid0c-sibling':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v74_root: Path = ns.v74_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    fam_dir = v74_root / 'sig8_families' / ns.family_dir
    if not fam_dir.exists():
        raise SystemExit(f'Family dir not found: {fam_dir}')

    shared_head = read_bytes(fam_dir / 'shared_head.bin')
    head_len = len(shared_head)
    family_meta = json.loads((fam_dir / 'family_meta.json').read_text(encoding='utf-8'))

    summary = []
    summary.append('BX v92 rid0C sibling family transfer probe')
    summary.append('==========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'family_dir: {ns.family_dir}')
    summary.append(f'shared_head_len: {head_len}')
    summary.append(f'sig8: {family_meta.get("sig8","")}')
    summary.append('')

    rows = []
    body_md5_counts = Counter()
    next_counts = Counter()
    prev_counts = Counter()

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        raw_hits = find_all_mm(mm, shared_head)

        valid = []
        for off in raw_hits:
            if off + ns.record_len > mm.size():
                continue
            rec = bytes(mm[off:off + ns.record_len])
            if not rec.startswith(shared_head):
                continue
            valid.append((off, rec))

            body = rec[head_len:]
            body_md5 = hashlib.md5(body).hexdigest()
            body_md5_counts[body_md5] += 1

            before_start = max(0, off - ns.before)
            before = bytes(mm[before_start:off])
            after = bytes(mm[off + ns.record_len: off + ns.record_len + ns.after])

            prev_nearest, next_nearest, marks = nearest_markers(before, after, ns.record_len)
            if prev_nearest:
                prev_counts[(prev_nearest['rid'], prev_nearest['delta'])] += 1
            else:
                prev_counts[('none','')] += 1
            if next_nearest:
                next_counts[(next_nearest['rid'], next_nearest['delta'])] += 1
            else:
                next_counts[('none','')] += 1

            hdir = out_dir / f'hit_{len(valid):02d}_0x{off:X}'
            hdir.mkdir(parents=True, exist_ok=True)
            write_bytes(hdir / 'record.bin', rec)
            write_bytes(hdir / 'before.bin', before)
            write_bytes(hdir / 'after.bin', after)
            (hdir / 'record.hex.txt').write_text(rec.hex(), encoding='utf-8')
            (hdir / 'markers.json').write_text(json.dumps(marks, indent=2), encoding='utf-8')

            rows.append({
                'index': len(valid),
                'off_hex': f'0x{off:X}',
                'body_md5': body_md5,
                'prev_rid': prev_nearest['rid'] if prev_nearest else '',
                'prev_delta': prev_nearest['delta'] if prev_nearest else '',
                'next_rid': next_nearest['rid'] if next_nearest else '',
                'next_delta': next_nearest['delta'] if next_nearest else '',
            })

        mm.close()

    with (out_dir / 'sibling_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off_hex','body_md5','prev_rid','prev_delta','next_rid','next_delta'])
        w.writeheader()
        w.writerows(rows)

    with (out_dir / 'body_md5_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['body_md5','count'])
        w.writeheader()
        for md5, count in body_md5_counts.most_common():
            w.writerow({'body_md5': md5, 'count': count})

    summary.append(f'raw_head_hits: {len(raw_hits)}')
    summary.append(f'valid_hits: {len(rows)}')
    summary.append(f'unique_body_md5: {len(body_md5_counts)}')
    summary.append('')
    summary.append('Body variants:')
    for md5, count in body_md5_counts.most_common():
        summary.append(f'  {md5} :: {count}')
    summary.append('')
    summary.append('Top prev:')
    for (rid, delta), count in prev_counts.most_common(8):
        summary.append(f'  {rid}@{delta} :: {count}')
    summary.append('')
    summary.append('Top next:')
    for (rid, delta), count in next_counts.most_common(8):
        summary.append(f'  {rid}@{delta} :: {count}')
    summary.append('')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'family_dir': ns.family_dir,
        'shared_head_len': head_len,
        'raw_head_hits': len(raw_hits),
        'valid_hits': len(rows),
        'unique_body_md5': len(body_md5_counts),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
