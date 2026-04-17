#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from collections import Counter

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def load_records(v59_root: Path):
    items = []
    for p in sorted(v59_root.glob('*.bin')):
        if p.name in ('shared_head.bin', 'shared_tail.bin'):
            continue
        if p.name.endswith('_body.bin'):
            continue
        sig8 = p.stem.split('_', 1)[1] if '_' in p.stem else p.stem
        data = read_bytes(p)
        items.append({'sig8': sig8, 'data': data})
    return items

def main():
    ap = argparse.ArgumentParser(description='BX v62 rid0A 423f archetype zone miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-423f-zones')
    p.add_argument('v59_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--probe-len', type=int, default=96)

    ns = ap.parse_args()
    if ns.cmd != 'mine-423f-zones':
        raise SystemExit(1)

    v59_root: Path = ns.v59_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    items = load_records(v59_root)
    if not items:
        raise SystemExit('No archetype records found')

    probe_len = min(ns.probe_len, min(len(x['data']) for x in items))
    summary = []
    summary.append('BX v62 rid0A 423f zone miner')
    summary.append('============================')
    summary.append(f'v59_root: {v59_root}')
    summary.append(f'archetypes: {len(items)}')
    summary.append(f'probe_len: {probe_len}')
    summary.append('')

    byte_rows = []
    candidate_rows = []

    # Per-offset value distribution
    for off in range(probe_len):
        vals = [x['data'][off] for x in items]
        uniq = len(set(vals))
        row = {'off': off, 'uniq_values': uniq}
        for it, v in zip(items, vals):
            row[it['sig8']] = f'{v:02X}'
        byte_rows.append(row)

        # interesting offsets after common head (>=6) but not too late
        if off >= 6 and uniq <= max(3, len(items)//2):
            cnt = Counter(vals)
            candidate_rows.append({
                'off': off,
                'uniq_values': uniq,
                'top_values': ' '.join(f'{k:02X}:{v}' for k, v in cnt.most_common(4)),
            })

    with (out_dir / 'byte_zone_atlas.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(byte_rows[0].keys())
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(byte_rows)

    with (out_dir / 'candidate_low_variability_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['off', 'uniq_values', 'top_values']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(candidate_rows)

    # Build contiguous zones by uniq_values profile
    zones = []
    start = 0
    current = byte_rows[0]['uniq_values']
    for i in range(1, len(byte_rows)):
        if byte_rows[i]['uniq_values'] != current:
            zones.append({'start': start, 'end': i-1, 'uniq_values': current, 'len': i-start})
            start = i
            current = byte_rows[i]['uniq_values']
    zones.append({'start': start, 'end': len(byte_rows)-1, 'uniq_values': current, 'len': len(byte_rows)-start})

    with (out_dir / 'zones.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['start','end','len','uniq_values']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(zones)

    summary.append('Top low-variability offsets after head:')
    for row in candidate_rows[:24]:
        summary.append(f'  off={row["off"]} uniq={row["uniq_values"]} values={row["top_values"]}')
    summary.append('')
    summary.append('Top zones:')
    # prioritize longer zones with low uniq
    top_zones = sorted(zones, key=lambda z: (z['uniq_values'], -z['len'], z['start']))[:20]
    for z in top_zones:
        summary.append(f'  {z["start"]:02d}-{z["end"]:02d} len={z["len"]} uniq={z["uniq_values"]}')

    meta = {
        'archetype_count': len(items),
        'probe_len': probe_len,
        'candidate_offset_count': len(candidate_rows),
        'zone_count': len(zones),
        'sig8': [x['sig8'] for x in items],
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
