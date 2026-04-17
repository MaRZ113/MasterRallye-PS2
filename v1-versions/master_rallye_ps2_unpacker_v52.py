#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import struct
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def is_plausible_float32_le(x: int) -> bool:
    try:
        f = struct.unpack('<f', struct.pack('<I', x))[0]
    except Exception:
        return False
    return math.isfinite(f) and abs(f) > 1e-12 and abs(f) < 1e6

def is_plausible_float32_be(x: int) -> bool:
    try:
        f = struct.unpack('>f', struct.pack('>I', x))[0]
    except Exception:
        return False
    return math.isfinite(f) and abs(f) > 1e-12 and abs(f) < 1e6

def main():
    ap = argparse.ArgumentParser(description='BX v52 rid0A structure miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0a-structure')
    p.add_argument('v48_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0a-structure':
        raise SystemExit(1)

    root: Path = ns.v48_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    record = read_bytes(root / 'record.bin')
    body = read_bytes(root / 'body.bin')

    summary = []
    summary.append('BX v52 rid0A structure miner')
    summary.append('===========================')
    summary.append(f'v48_root: {root}')
    summary.append(f'record_len: {len(record)}')
    summary.append(f'body_len: {len(body)}')
    summary.append(f'head8: {record[:8].hex()}')
    summary.append('')

    rows = []
    candidates = []

    for off in range(0, len(record) - 3):
        chunk = record[off:off+4]
        u32le = struct.unpack('<I', chunk)[0]
        u32be = struct.unpack('>I', chunk)[0]

        row = {
            'off': off,
            'hex4': chunk.hex(),
            'u32_le': f'0x{u32le:08X}',
            'u32_be': f'0x{u32be:08X}',
            'le_in_record_range': 1 if 0 < u32le <= len(record) else 0,
            'be_in_record_range': 1 if 0 < u32be <= len(record) else 0,
            'le_in_body_range': 1 if 0 < u32le <= len(body) else 0,
            'be_in_body_range': 1 if 0 < u32be <= len(body) else 0,
            'le_floatish': 1 if is_plausible_float32_le(u32le) else 0,
            'be_floatish': 1 if is_plausible_float32_be(u32be) else 0,
        }
        rows.append(row)

        # shortlist interesting positions
        if row['le_in_record_range'] or row['be_in_record_range'] or row['le_floatish'] or row['be_floatish']:
            candidates.append({
                'off': off,
                **row
            })

    with (out_dir / 'rolling_word_scan.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(rows[0].keys())
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    # aligned views
    aligned_rows = []
    for off in range(0, len(record) - 3, 4):
        chunk = record[off:off+4]
        u32le = struct.unpack('<I', chunk)[0]
        u32be = struct.unpack('>I', chunk)[0]
        aligned_rows.append({
            'off': off,
            'hex4': chunk.hex(),
            'u32_le': f'0x{u32le:08X}',
            'u32_be': f'0x{u32be:08X}',
            'le_in_record_range': 1 if 0 < u32le <= len(record) else 0,
            'be_in_record_range': 1 if 0 < u32be <= len(record) else 0,
            'le_in_body_range': 1 if 0 < u32le <= len(body) else 0,
            'be_in_body_range': 1 if 0 < u32be <= len(body) else 0,
            'le_floatish': 1 if is_plausible_float32_le(u32le) else 0,
            'be_floatish': 1 if is_plausible_float32_be(u32be) else 0,
        })

    with (out_dir / 'aligned_word_scan.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(aligned_rows[0].keys())
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(aligned_rows)

    # small candidate shortlist
    cand_rows = []
    for c in candidates:
        if c['off'] > 96:
            continue
        cand_rows.append({
            'off': c['off'],
            'hex4': c['hex4'],
            'u32_le': c['u32_le'],
            'u32_be': c['u32_be'],
            'le_in_record_range': c['le_in_record_range'],
            'be_in_record_range': c['be_in_record_range'],
            'le_in_body_range': c['le_in_body_range'],
            'be_in_body_range': c['be_in_body_range'],
            'le_floatish': c['le_floatish'],
            'be_floatish': c['be_floatish'],
        })

    with (out_dir / 'candidate_field_shortlist.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(cand_rows[0].keys()) if cand_rows else ['off']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(cand_rows)

    summary.append('Top candidate fields (first 96 bytes):')
    for row in cand_rows[:40]:
        flags = []
        if row['le_in_record_range']: flags.append('le_rec')
        if row['be_in_record_range']: flags.append('be_rec')
        if row['le_in_body_range']: flags.append('le_body')
        if row['be_in_body_range']: flags.append('be_body')
        if row['le_floatish']: flags.append('le_float')
        if row['be_floatish']: flags.append('be_float')
        summary.append(
            f'  off={row["off"]:02d} hex={row["hex4"]} le={row["u32_le"]} be={row["u32_be"]} flags={",".join(flags)}'
        )

    meta = {
        'record_len': len(record),
        'body_len': len(body),
        'candidate_count_first96': len(cand_rows),
        'head8': record[:8].hex(),
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
