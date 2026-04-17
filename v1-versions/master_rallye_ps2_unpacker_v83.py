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
    prev_nearest = prev_rows[-1] if prev_rows else None
    next_nearest = next_rows[0] if next_rows else None
    return rows, prev_nearest, next_nearest

def main():
    ap = argparse.ArgumentParser(description='BX v83 rid0C family context miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0c-family-context')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v75_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-len', type=int, default=RECORD_LEN)
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1024)
    p.add_argument('--max-export-per-variant', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0c-family-context':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v75_root: Path = ns.v75_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    head = read_bytes(v75_root / 'shared_head.bin')
    head_len = len(head)

    summary = []
    summary.append('BX v83 rid0C family context miner')
    summary.append('=================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'head_len: {head_len}')
    summary.append(f'record_len: {ns.record_len}')
    summary.append('')

    variant_hits = defaultdict(list)
    variant_prev = defaultdict(Counter)
    variant_next = defaultdict(Counter)
    variant_pattern = defaultdict(Counter)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        raw_hits = []
        start = 0
        while True:
            i = mm.find(head, start)
            if i == -1:
                break
            raw_hits.append(i)
            start = i + 1

        valid_hits = []
        for off in raw_hits:
            if off + ns.record_len > mm.size():
                continue
            rec = bytes(mm[off:off+ns.record_len])
            if not rec.startswith(head):
                continue
            valid_hits.append((off, rec))

            body = rec[head_len:]
            body_md5 = hashlib.md5(body).hexdigest()
            variant_hits[body_md5].append((off, rec))

            start = max(0, off - ns.before)
            before = bytes(mm[start:off])
            after = bytes(mm[off + ns.record_len : off + ns.record_len + ns.after])
            marks, prev_nearest, next_nearest = nearest_markers(before, after, ns.record_len)

            if prev_nearest:
                variant_prev[body_md5][(prev_nearest['rid'], prev_nearest['delta'])] += 1
            else:
                variant_prev[body_md5][('none', '')] += 1

            if next_nearest:
                variant_next[body_md5][(next_nearest['rid'], next_nearest['delta'])] += 1
            else:
                variant_next[body_md5][('none', '')] += 1

            next_marks = [(m['rid'], m['delta']) for m in marks if m['delta'] > 0][:4]
            pat = ' | '.join(f'{rid}@{delta}' for rid, delta in next_marks) if next_marks else 'none'
            variant_pattern[body_md5][pat] += 1

        mm.close()

    summary.append(f'raw_head_hits: {len(raw_hits)}')
    summary.append(f'valid_hits: {len(valid_hits)}')
    summary.append(f'unique_body_variants: {len(variant_hits)}')
    summary.append('')

    rows = []
    rep_root = out_dir / 'variants'
    rep_root.mkdir(exist_ok=True)

    for rank, (body_md5, hits) in enumerate(sorted(variant_hits.items(), key=lambda kv: (-len(kv[1]), kv[0])), 1):
        vdir = rep_root / f'{rank:02d}_{body_md5}'
        vdir.mkdir(parents=True, exist_ok=True)

        prev_top = variant_prev[body_md5].most_common(5)
        next_top = variant_next[body_md5].most_common(5)
        pat_top = variant_pattern[body_md5].most_common(5)

        summary.append(f'variant {rank:02d}: body_md5={body_md5} count={len(hits)}')
        summary.append('  top prev:')
        for (rid, delta), count in prev_top:
            summary.append(f'    {rid}@{delta} :: {count}')
        summary.append('  top next:')
        for (rid, delta), count in next_top:
            summary.append(f'    {rid}@{delta} :: {count}')
        summary.append('  top patterns:')
        for pat, count in pat_top:
            summary.append(f'    {pat} :: {count}')
        summary.append('')

        with (vdir / 'context_summary.json').open('w', encoding='utf-8') as f:
            json.dump({
                'body_md5': body_md5,
                'count': len(hits),
                'top_prev': [{'rid': rid, 'delta': delta, 'count': count} for (rid, delta), count in prev_top],
                'top_next': [{'rid': rid, 'delta': delta, 'count': count} for (rid, delta), count in next_top],
                'top_patterns': [{'pattern': pat, 'count': count} for pat, count in pat_top],
            }, f, indent=2)

        for idx, (off, rec) in enumerate(hits[:ns.max_export_per_variant], 1):
            start = max(0, off - ns.before)
            with tng_path.open('rb') as f:
                f.seek(start)
                before = f.read(off - start)
                f.seek(off + ns.record_len)
                after = f.read(ns.after)

            hdir = vdir / f'sample_{idx:02d}_0x{off:X}'
            hdir.mkdir(parents=True, exist_ok=True)
            write_bytes(hdir / 'record.bin', rec)
            write_bytes(hdir / 'before.bin', before)
            write_bytes(hdir / 'after.bin', after)
            (hdir / 'record.hex.txt').write_text(rec.hex(), encoding='utf-8')

            rows.append({
                'variant_rank': rank,
                'body_md5': body_md5,
                'count': len(hits),
                'off_hex': f'0x{off:X}',
                'record_head16': rec[:16].hex(),
            })

    with (out_dir / 'variant_context_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['variant_rank','body_md5','count','off_hex','record_head16'])
        w.writeheader()
        w.writerows(rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'head_len': head_len,
        'record_len': ns.record_len,
        'raw_head_hits': len(raw_hits),
        'valid_hits': len(valid_hits),
        'unique_body_variants': len(variant_hits),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
