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

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def scan_magics(data: bytes):
    out = {}
    for m in MAGICS:
        out[m.hex() if any(b < 32 or b > 126 for b in m) else m.decode('latin1')] = data.find(m)
    return out

def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))

def main():
    ap = argparse.ArgumentParser(description='BX v31 family packet candidate builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-packets')
    p.add_argument('v25_seed_schema', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--descriptor-rid', type=int, default=7)
    p.add_argument('--payload-rid', type=int, default=13)

    ns = ap.parse_args()
    if ns.cmd != 'build-packets':
        raise SystemExit(1)

    root: Path = ns.v25_seed_schema
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    drid = ns.descriptor_rid
    prid = ns.payload_rid

    # header core
    rid01 = (root / 'header_core' / 'rid_01.bin').read_bytes()
    rid02 = (root / 'header_core' / 'rid_02.bin').read_bytes()

    # transition
    r3f = (root / 'rid_03_transition' / 'rid_03_full.bin').read_bytes()
    r3v = (root / 'rid_03_transition' / 'rid_03_variant.bin').read_bytes()

    # descriptor
    rdf = (root / f'rid_{drid:02d}_descriptor' / f'rid_{drid:02d}_full.bin').read_bytes()
    rdv = (root / f'rid_{drid:02d}_descriptor' / f'rid_{drid:02d}_variant.bin').read_bytes()

    # payload
    rpf = (root / f'rid_{prid:02d}_payload' / f'rid_{prid:02d}_full.bin').read_bytes()
    rpv = (root / f'rid_{prid:02d}_payload' / f'rid_{prid:02d}_variant.bin').read_bytes()

    packets = {
        'header_core.bin': rid01 + rid02,
        'transition_full.bin': r3f,
        'transition_variant.bin': r3v,
        'descriptor_full.bin': rdf,
        'descriptor_variant.bin': rdv,
        'payload_full.bin': rpf,
        'payload_variant.bin': rpv,
        'packet_full.bin': rid01 + rid02 + r3f + rdf + rpf,
        'packet_variant.bin': rid01 + rid02 + r3v + rdv + rpv,
        'packet_headerless_full.bin': r3f + rdf + rpf,
        'packet_headerless_variant.bin': r3v + rdv + rpv,
        'packet_desc_payload_full.bin': rdf + rpf,
        'packet_desc_payload_variant.bin': rdv + rpv,
    }

    rows = []
    summary = []
    summary.append('BX v31 family packet candidates')
    summary.append('==============================')
    summary.append(f'root: {root}')
    summary.append(f'descriptor_rid: {drid}')
    summary.append(f'payload_rid: {prid}')
    summary.append('')

    for name, data in packets.items():
        write_bytes(out_dir / name, data)
        (out_dir / (name + '.hex.txt')).write_text(data.hex(), encoding='utf-8')
        found = scan_magics(data)
        row = {
            'name': name,
            'len': len(data),
            'entropy': round(entropy(data), 6),
        }
        row.update(found)
        rows.append(row)
        summary.append(f'{name}: len={len(data)} entropy={entropy(data):.4f}')
        for k, v in found.items():
            if v != -1:
                summary.append(f'  magic {k} @ {v}')

    with (out_dir / 'packet_scan.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(rows[0].keys()) if rows else ['name','len','entropy']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
