#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import List


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def common_prefix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    m = min(len(b) for b in blobs)
    i = 0
    while i < m:
        x = blobs[0][i]
        if any(b[i] != x for b in blobs[1:]):
            break
        i += 1
    return i


def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    rev = [b[::-1] for b in blobs]
    return common_prefix_len(rev)


def median(values: List[int]):
    if not values:
        return None
    vals = sorted(values)
    n = len(vals)
    if n % 2:
        return vals[n // 2]
    return (vals[n // 2 - 1] + vals[n // 2]) / 2


def classify_rid(rid: int) -> str:
    if 1 <= rid <= 4:
        return 'header'
    if 5 <= rid <= 7:
        return 'descriptor'
    if 8 <= rid <= 15:
        return 'data'
    if rid == 16:
        return 'terminal'
    return 'unknown'


def parse_rid_dir_name(name: str):
    # rid_01_header / rid_08_data
    parts = name.split('_')
    if len(parts) < 3 or parts[0] != 'rid':
        return None, None
    try:
        return int(parts[1]), '_'.join(parts[2:])
    except ValueError:
        return None, None


def load_family(unpack_dir: Path):
    rid_banks = unpack_dir / 'rid_banks'
    data = {}
    if not rid_banks.exists():
        raise FileNotFoundError(f'rid_banks not found in {unpack_dir}')
    for p in sorted(rid_banks.iterdir()):
        if not p.is_dir():
            continue
        rid, role = parse_rid_dir_name(p.name)
        if rid is None:
            continue
        blobs = []
        for f in sorted(p.glob('*.bin')):
            b = f.read_bytes()
            blobs.append({
                'name': f.name,
                'path': str(f),
                'size': len(b),
                'md5': hashlib.md5(b).hexdigest(),
                'sha1': hashlib.sha1(b).hexdigest(),
                'entropy': round(shannon_entropy(b), 4),
                'blob': b,
            })
        data[rid] = {'role': role, 'files': blobs}
    return data


def write_hex_preview(blob: bytes, out_path: Path, width: int = 16, limit: int = 256):
    blob = blob[:limit]
    lines = []
    for i in range(0, len(blob), width):
        chunk = blob[i:i+width]
        hexs = ' '.join(f'{x:02X}' for x in chunk)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
        lines.append(f'{i:04X}  {hexs:<47}  {asc}')
    out_path.write_text('\n'.join(lines), encoding='utf-8')


def compare_families(full_dir: Path, variant_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    full = load_family(full_dir)
    variant = load_family(variant_dir)

    rows = []
    per_rid_dir = out_dir / 'per_rid'
    per_rid_dir.mkdir(exist_ok=True)

    focus_rids = [1,2,3,4,5,6,7,8,9,10,12,13,14,15]

    for rid in range(1, 17):
        f = full.get(rid, {'role': classify_rid(rid), 'files': []})
        v = variant.get(rid, {'role': classify_rid(rid), 'files': []})
        f_blobs = [x['blob'] for x in f['files']]
        v_blobs = [x['blob'] for x in v['files']]
        f_sizes = [x['size'] for x in f['files']]
        v_sizes = [x['size'] for x in v['files']]
        f_ent = [x['entropy'] for x in f['files']]
        v_ent = [x['entropy'] for x in v['files']]
        row = {
            'rid': rid,
            'role': classify_rid(rid),
            'full_count': len(f_blobs),
            'variant_count': len(v_blobs),
            'full_med_size': median(f_sizes),
            'variant_med_size': median(v_sizes),
            'size_delta_variant_minus_full': (median(v_sizes) - median(f_sizes)) if f_sizes and v_sizes else None,
            'full_common_prefix': common_prefix_len(f_blobs),
            'variant_common_prefix': common_prefix_len(v_blobs),
            'full_common_suffix': common_suffix_len(f_blobs),
            'variant_common_suffix': common_suffix_len(v_blobs),
            'full_avg_entropy': round(sum(f_ent)/len(f_ent), 4) if f_ent else None,
            'variant_avg_entropy': round(sum(v_ent)/len(v_ent), 4) if v_ent else None,
            'full_unique_md5': len({x['md5'] for x in f['files']}),
            'variant_unique_md5': len({x['md5'] for x in v['files']}),
        }
        rows.append(row)

        if rid in focus_rids:
            rid_dir = per_rid_dir / f'rid_{rid:02d}_{classify_rid(rid)}'
            rid_dir.mkdir(exist_ok=True)
            summary = []
            summary.append(f'rid {rid:02d} [{classify_rid(rid)}]')
            summary.append('=' * 40)
            summary.append(f"full_count={row['full_count']} variant_count={row['variant_count']}")
            summary.append(f"full_med_size={row['full_med_size']} variant_med_size={row['variant_med_size']}")
            summary.append(f"size_delta_variant_minus_full={row['size_delta_variant_minus_full']}")
            summary.append(f"full_common_prefix={row['full_common_prefix']} variant_common_prefix={row['variant_common_prefix']}")
            summary.append(f"full_common_suffix={row['full_common_suffix']} variant_common_suffix={row['variant_common_suffix']}")
            summary.append(f"full_avg_entropy={row['full_avg_entropy']} variant_avg_entropy={row['variant_avg_entropy']}")
            summary.append(f"full_unique_md5={row['full_unique_md5']} variant_unique_md5={row['variant_unique_md5']}")
            summary.append('')
            summary.append('full files:')
            for x in f['files']:
                summary.append(f"  {x['name']} size={x['size']} md5={x['md5']} entropy={x['entropy']}")
            summary.append('')
            summary.append('variant files:')
            for x in v['files']:
                summary.append(f"  {x['name']} size={x['size']} md5={x['md5']} entropy={x['entropy']}")
            (rid_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

            if f['files']:
                write_hex_preview(f['files'][0]['blob'], rid_dir / 'full_sample_0.hex.txt')
            if v['files']:
                write_hex_preview(v['files'][0]['blob'], rid_dir / 'variant_sample_0.hex.txt')

    csv_path = out_dir / 'rid_compare_v15.csv'
    with csv_path.open('w', newline='', encoding='utf-8') as fcsv:
        writer = csv.DictWriter(fcsv, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    txt = []
    txt.append('BX v15 compare')
    txt.append('==============')
    txt.append(f'full_family={full_dir}')
    txt.append(f'variant_family={variant_dir}')
    txt.append('')
    txt.append('Recommended reverse focus order:')
    txt.append('1) rid 01 as strongest header candidate')
    txt.append('2) rid 05-07 as family descriptors')
    txt.append('3) rid 09,10,13,15 as strongest divergent payloads')
    txt.append('')
    for row in rows:
        txt.append(
            f"rid {row['rid']:02d} [{row['role']}]: "
            f"full_med={row['full_med_size']} variant_med={row['variant_med_size']} "
            f"dV-F={row['size_delta_variant_minus_full']} "
            f"f_pref={row['full_common_prefix']} v_pref={row['variant_common_prefix']} "
            f"f_md5={row['full_unique_md5']} v_md5={row['variant_unique_md5']}"
        )
    (out_dir / 'summary.txt').write_text('\n'.join(txt), encoding='utf-8')

    meta = {
        'full_dir': str(full_dir),
        'variant_dir': str(variant_dir),
        'focus_rids': focus_rids,
        'rows': rows,
    }
    (out_dir / 'rid_compare_v15.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description='Master Rallye PS2 BX v15 rid-oriented compare')
    sub = ap.add_subparsers(dest='cmd', required=True)

    c = sub.add_parser('compare-rids', help='Compare two canonical family unpack dirs at rid level')
    c.add_argument('full_unpack_dir', type=Path)
    c.add_argument('variant_unpack_dir', type=Path)
    c.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd == 'compare-rids':
        compare_families(ns.full_unpack_dir, ns.variant_unpack_dir, ns.out_dir)


if __name__ == '__main__':
    main()
