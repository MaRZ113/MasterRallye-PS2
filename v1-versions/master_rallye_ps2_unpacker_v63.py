#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

RECORD_SIZE = 253
RID_MARKERS = {
    0x07: b"\x00\x00\x01\x07",
    0x08: b"\x00\x00\x01\x08",
    0x09: b"\x00\x00\x01\x09",
    0x0A: b"\x00\x00\x01\x0A",
    0x0B: b"\x00\x00\x01\x0B",
}

def carve(src: Path, off: int, size: int = RECORD_SIZE) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def read_classified_hits(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

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

def main():
    ap = argparse.ArgumentParser(description='BX v63 rid0A context grammar miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0a-context')
    p.add_argument('tng_path', type=Path)
    p.add_argument('classified_hits_csv', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--subprefix', type=str, default='0000010a423f')
    p.add_argument('--record-size', type=int, default=253)
    p.add_argument('--window-before', type=int, default=128)
    p.add_argument('--window-after', type=int, default=768)
    p.add_argument('--top-sig8', type=int, default=8)
    p.add_argument('--max-export', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0a-context':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    hits_csv: Path = ns.classified_hits_csv
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = read_classified_hits(hits_csv)
    binary_rows = [r for r in rows if r.get('kind') == 'binary_like']

    # collect hits by exact sig8 within chosen subprefix
    hits_by_sig8 = defaultdict(list)
    for r in binary_rows:
        off = int(r['off'])
        rec = carve(tng_path, off, ns.record_size)
        sig8 = rec[:8].hex()
        if not sig8.startswith(ns.subprefix.lower()):
            continue
        hits_by_sig8[sig8].append({
            'index': int(r['index']),
            'off': off,
            'off_hex': r['off_hex'],
            'record': rec,
        })

    top_sigs = sorted(hits_by_sig8.keys(), key=lambda s: len(hits_by_sig8[s]), reverse=True)[:ns.top_sig8]

    summary = []
    summary.append('BX v63 rid0A context grammar')
    summary.append('============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'subprefix: {ns.subprefix.lower()}')
    summary.append(f'top_sig8_count: {len(top_sigs)}')
    summary.append('')

    family_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for rank, sig8 in enumerate(top_sigs, 1):
            hits = hits_by_sig8[sig8]
            sig_dir = out_dir / f'{rank:02d}_{sig8}'
            sig_dir.mkdir(parents=True, exist_ok=True)

            next_counter = Counter()
            prev_counter = Counter()
            pattern_counter = Counter()

            # export a few representative windows
            for item in hits[:ns.max_export]:
                start = max(0, item['off'] - ns.window_before)
                size = ns.window_before + ns.window_after
                blob = mm[start:start+size]

                hdir = sig_dir / f'hit_{item["index"]:05d}_{item["off_hex"]}'
                hdir.mkdir(parents=True, exist_ok=True)
                (hdir / 'around.bin').write_bytes(blob)
                (hdir / 'around.hex.txt').write_text(blob.hex(), encoding='utf-8')
                (hdir / 'record.bin').write_bytes(item['record'])
                (hdir / 'record.hex.txt').write_text(item['record'].hex(), encoding='utf-8')

            # scan all hits for nearby record markers
            for item in hits:
                start = max(0, item['off'] - ns.window_before)
                size = ns.window_before + ns.window_after
                blob = mm[start:start+size]
                zero = item['off'] - start  # rid0A starts here

                rel_marks = []
                for rid, marker in RID_MARKERS.items():
                    for rel in find_all(blob, marker):
                        delta = rel - zero
                        if delta == 0 and rid == 0x0A:
                            continue
                        rel_marks.append((delta, rid))
                rel_marks.sort()

                prev_marks = [(d, rid) for d, rid in rel_marks if d < 0]
                next_marks = [(d, rid) for d, rid in rel_marks if d > 0]

                if prev_marks:
                    d, rid = prev_marks[-1]
                    prev_counter[(rid, d)] += 1
                else:
                    prev_counter[('none', '')] += 1

                if next_marks:
                    d, rid = next_marks[0]
                    next_counter[(rid, d)] += 1
                else:
                    next_counter[('none', '')] += 1

                # short pattern of first up to 4 next markers
                pat = ' | '.join(f'{rid:02X}@{d}' for d, rid in next_marks[:4]) if next_marks else 'none'
                pattern_counter[pat] += 1

            # write counts
            with (sig_dir / 'next_marker_counts.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(f_csv, fieldnames=['rid','delta','count'])
                w.writeheader()
                for (rid, delta), count in next_counter.most_common():
                    w.writerow({'rid': rid, 'delta': delta, 'count': count})

            with (sig_dir / 'prev_marker_counts.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(f_csv, fieldnames=['rid','delta','count'])
                w.writeheader()
                for (rid, delta), count in prev_counter.most_common():
                    w.writerow({'rid': rid, 'delta': delta, 'count': count})

            with (sig_dir / 'pattern_counts.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(f_csv, fieldnames=['pattern','count'])
                w.writeheader()
                for pattern, count in pattern_counter.most_common():
                    w.writerow({'pattern': pattern, 'count': count})

            summary.append(f'{sig8}: hits={len(hits)}')
            summary.append('  top next markers:')
            for (rid, delta), count in next_counter.most_common(6):
                summary.append(f'    rid={rid} delta={delta} count={count}')
            summary.append('  top prev markers:')
            for (rid, delta), count in prev_counter.most_common(6):
                summary.append(f'    rid={rid} delta={delta} count={count}')
            summary.append('  top next-patterns:')
            for pattern, count in pattern_counter.most_common(5):
                summary.append(f'    {pattern} :: {count}')
            summary.append('')

            family_rows.append({
                'rank': rank,
                'sig8': sig8,
                'hits': len(hits),
                'top_next': json.dumps([{'rid': rid, 'delta': delta, 'count': count} for (rid, delta), count in next_counter.most_common(3)]),
                'top_prev': json.dumps([{'rid': rid, 'delta': delta, 'count': count} for (rid, delta), count in prev_counter.most_common(3)]),
                'top_pattern': pattern_counter.most_common(1)[0][0] if pattern_counter else 'none',
            })

        mm.close()

    with (out_dir / 'family_context_summary.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','sig8','hits','top_next','top_prev','top_pattern'])
        w.writeheader()
        w.writerows(family_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
