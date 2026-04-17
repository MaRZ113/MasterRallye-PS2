#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

RECORD_LEN = 507
RID0C_MARKER = b'\x00\x00\x01\x0C'
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

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
    return prev_rows[-1] if prev_rows else None, next_rows[0] if next_rows else None

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def main():
    ap = argparse.ArgumentParser(description='BX v107 rid0C sig7 macro-family miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-sig7-family')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--top-export', type=int, default=6)

    ns = ap.parse_args()
    if ns.cmd != 'mine-sig7-family':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v107 rid0C sig7 macro-family miner')
    summary.append('=====================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append('')

    sig8_hits = defaultdict(list)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        rid0c_hits = find_all_mm(mm, RID0C_MARKER)

        for off in rid0c_hits:
            if off + RECORD_LEN > mm.size():
                continue
            rec = bytes(mm[off:off+RECORD_LEN])
            sig8 = rec[:8].hex()
            if not sig8.startswith(ns.sig7):
                continue
            sig8_hits[sig8].append((off, rec))

        rows = []
        member_root = out_dir / 'members'
        member_root.mkdir(exist_ok=True)

        for rank, (sig8, items) in enumerate(sorted(sig8_hits.items(), key=lambda kv: (-len(kv[1]), kv[0])), 1):
            body_counts = Counter()
            next_counts = Counter()
            prev_counts = Counter()

            for off, rec in items:
                body = rec[8:]
                body_md5 = md5(body)
                body_counts[body_md5] += 1

                before_start = max(0, off - ns.before)
                before = bytes(mm[before_start:off])
                after = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + ns.after])

                prev_nearest, next_nearest = nearest_markers(before, after, RECORD_LEN)
                if prev_nearest:
                    prev_counts[(prev_nearest['rid'], prev_nearest['delta'])] += 1
                else:
                    prev_counts[('none','')] += 1
                if next_nearest:
                    next_counts[(next_nearest['rid'], next_nearest['delta'])] += 1
                else:
                    next_counts[('none','')] += 1

            row = {
                'rank': rank,
                'sig8': sig8,
                'hits': len(items),
                'unique_body_md5': len(body_counts),
                'top_body_md5': body_counts.most_common(1)[0][0] if body_counts else '',
                'top_body_count': body_counts.most_common(1)[0][1] if body_counts else 0,
                'top_next': json.dumps([{'rid': rid, 'delta': delta, 'count': count} for (rid, delta), count in next_counts.most_common(4)]),
                'top_prev': json.dumps([{'rid': rid, 'delta': delta, 'count': count} for (rid, delta), count in prev_counts.most_common(4)]),
            }
            rows.append(row)

            summary.append(f'{sig8}: hits={len(items)} variants={len(body_counts)}')
            for md5_, count in body_counts.most_common(8):
                summary.append(f'  body {md5_} :: {count}')
            summary.append(f'  top_next={next_counts.most_common(6)}')
            summary.append(f'  top_prev={prev_counts.most_common(6)}')
            summary.append('')

            if rank <= ns.top_export:
                sdir = member_root / f'{rank:02d}_{sig8}'
                sdir.mkdir(parents=True, exist_ok=True)
                with (sdir / 'body_md5_counts.csv').open('w', encoding='utf-8', newline='') as f_csv:
                    w = csv.DictWriter(f_csv, fieldnames=['body_md5','count'])
                    w.writeheader()
                    for md5_, count in body_counts.most_common():
                        w.writerow({'body_md5': md5_, 'count': count})

                for idx, (off, rec) in enumerate(items[:3], 1):
                    write_bytes(sdir / f'sample_{idx:02d}_0x{off:X}.bin', rec)
                    (sdir / f'sample_{idx:02d}_0x{off:X}.hex.txt').write_text(rec.hex(), encoding='utf-8')

        mm.close()

    with (out_dir / 'sig8_member_overview.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','sig8','hits','unique_body_md5','top_body_md5','top_body_count','top_next','top_prev'])
        w.writeheader()
        w.writerows(rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'sig7': ns.sig7,
        'member_sig8_count': len(rows),
        'total_hits': sum(r['hits'] for r in rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
