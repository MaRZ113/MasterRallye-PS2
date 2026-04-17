#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path

MAGICS = [
    b'BX', b'ELF', b'DDS ', b'RIFF', b'TIM2', b'<?xml', b'<Egg',
    b'AI_List', b'PNG', b'OggS', b'PK\x03\x04', b'\x1f\x8b',
    b'\x78\x01', b'\x78\x9c', b'\x78\xda', b'BZh'
]

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def common_prefix_len(a: bytes, b: bytes) -> int:
    i = 0
    for x, y in zip(a, b):
        if x != y:
            break
        i += 1
    return i

def scan_magics(data: bytes):
    out = {}
    for m in MAGICS:
        key = m.hex() if any(b < 32 or b > 126 for b in m) else m.decode('latin1')
        out[key] = data.find(m)
    return out

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def load_bin(root: Path, name: str) -> bytes:
    return (root / name).read_bytes()

def main():
    ap = argparse.ArgumentParser(description='BX v32 packet split / core-tail extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('split-packets')
    p.add_argument('v31_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'split-packets':
        raise SystemExit(1)

    root: Path = ns.v31_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    header = load_bin(root, 'header_core.bin')
    t_full = load_bin(root, 'transition_full.bin')
    t_var = load_bin(root, 'transition_variant.bin')
    d_full = load_bin(root, 'descriptor_full.bin')
    d_var = load_bin(root, 'descriptor_variant.bin')
    p_full = load_bin(root, 'payload_full.bin')
    p_var = load_bin(root, 'payload_variant.bin')
    packet_full = load_bin(root, 'packet_full.bin')
    packet_var = load_bin(root, 'packet_variant.bin')

    prefix = common_prefix_len(packet_full, packet_var)
    header_len = len(header)
    shared_transition_prefix = max(0, prefix - header_len)
    full_transition_tail_len = max(0, len(t_full) - shared_transition_prefix)
    variant_transition_tail_len = max(0, len(t_var) - shared_transition_prefix)

    shared_packet_prefix = packet_full[:prefix]
    full_tail = packet_full[prefix:]
    variant_tail = packet_var[prefix:]

    full_transition_tail = t_full[shared_transition_prefix:]
    variant_transition_tail = t_var[shared_transition_prefix:]

    outputs = {
        'shared_packet_prefix.bin': shared_packet_prefix,
        'full_tail.bin': full_tail,
        'variant_tail.bin': variant_tail,
        'full_transition_tail.bin': full_transition_tail,
        'variant_transition_tail.bin': variant_transition_tail,
        'descriptor_full.bin': d_full,
        'descriptor_variant.bin': d_var,
        'payload_full.bin': p_full,
        'payload_variant.bin': p_var,
        'full_tail_desc_payload.bin': d_full + p_full,
        'variant_tail_desc_payload.bin': d_var + p_var,
    }

    rows = []
    summary = []
    summary.append('BX v32 packet split')
    summary.append('===================')
    summary.append(f'v31_root: {root}')
    summary.append(f'header_len: {header_len}')
    summary.append(f'common_packet_prefix: {prefix}')
    summary.append(f'shared_transition_prefix: {shared_transition_prefix}')
    summary.append(f'full_transition_tail_len: {full_transition_tail_len}')
    summary.append(f'variant_transition_tail_len: {variant_transition_tail_len}')
    summary.append('')

    for name, data in outputs.items():
        write_bytes(out_dir / name, data)
        (out_dir / (name + '.hex.txt')).write_text(data.hex(), encoding='utf-8')
        row = {'name': name, 'len': len(data), 'entropy': round(entropy(data), 6)}
        row.update(scan_magics(data))
        rows.append(row)
        summary.append(f'{name}: len={len(data)} entropy={entropy(data):.4f}')
        for k, v in row.items():
            if k not in ('name', 'len', 'entropy') and v != -1:
                summary.append(f'  magic {k} @ {v}')

    with (out_dir / 'packet_split_scan.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    meta = {
        'header_len': header_len,
        'common_packet_prefix': prefix,
        'shared_transition_prefix': shared_transition_prefix,
        'full_transition_tail_len': full_transition_tail_len,
        'variant_transition_tail_len': variant_transition_tail_len,
    }
    (out_dir / 'split_meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
