#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path
from typing import List, Dict

def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def summarize_segments(schema: dict) -> List[dict]:
    out = []
    for seg in schema.get('segments', []):
        entry = {'index': seg['index'], 'kind': seg['kind']}
        if seg['kind'] == 'shared':
            entry['len'] = seg.get('len', 0)
            entry['hex_preview'] = seg.get('hex_preview', '')
        else:
            entry['full_off'] = seg.get('full_off', 0)
            entry['full_len'] = seg.get('full_len', 0)
            entry['variant_off'] = seg.get('variant_off', 0)
            entry['variant_len'] = seg.get('variant_len', 0)
            entry['full_hex_preview'] = seg.get('full_hex_preview', '')
            entry['variant_hex_preview'] = seg.get('variant_hex_preview', '')
        out.append(entry)
    return out

def carve_from_schema(src_dir: Path, rid: int, family: str) -> bytes:
    return (src_dir / f'rid_{rid:02d}_{family}.bin').read_bytes()

def build_focus(v27_root: Path, pack_name: str, out_dir: Path):
    pack = v27_root / pack_name
    desc_dir = pack / 'descriptor'
    pay_dir = pack / 'payload'
    hypothesis = load_json(pack / 'hypothesis.json')

    drid = int(hypothesis['descriptor_rid'])
    prid = int(hypothesis['payload_rid'])

    d_schema = load_json(desc_dir / 'schema.json')
    p_schema = load_json(pay_dir / 'schema.json')

    d_full = carve_from_schema(desc_dir, drid, 'full')
    d_var  = carve_from_schema(desc_dir, drid, 'variant')
    p_full = carve_from_schema(pay_dir, prid, 'full')
    p_var  = carve_from_schema(pay_dir, prid, 'variant')

    out_dir.mkdir(parents=True, exist_ok=True)

    # raw originals
    write_bytes(out_dir / 'descriptor' / f'rid_{drid:02d}_full.bin', d_full)
    write_bytes(out_dir / 'descriptor' / f'rid_{drid:02d}_variant.bin', d_var)
    write_bytes(out_dir / 'payload' / f'rid_{prid:02d}_full.bin', p_full)
    write_bytes(out_dir / 'payload' / f'rid_{prid:02d}_variant.bin', p_var)

    # segment-wise extraction
    seg_rows = []

    for layer_name, schema, full_b, var_b in [
        ('descriptor', d_schema, d_full, d_var),
        ('payload', p_schema, p_full, p_var),
    ]:
        for seg in schema.get('segments', []):
            idx = int(seg['index'])
            kind = seg['kind']
            seg_base = out_dir / layer_name / 'segments' / f'seg_{idx:02d}_{kind}'
            seg_base.mkdir(parents=True, exist_ok=True)

            if kind == 'shared':
                off = int(seg['full_off'])
                ln = int(seg['len'])
                blob = full_b[off:off+ln]
                write_bytes(seg_base / 'shared.bin', blob)
                (seg_base / 'shared.hex.txt').write_text(blob.hex(), encoding='utf-8')
                seg_rows.append({
                    'layer': layer_name, 'seg_index': idx, 'kind': kind,
                    'full_off': off, 'variant_off': int(seg['variant_off']),
                    'full_len': ln, 'variant_len': ln,
                })
            else:
                fo = int(seg['full_off']); fl = int(seg['full_len'])
                vo = int(seg['variant_off']); vl = int(seg['variant_len'])
                fblob = full_b[fo:fo+fl]
                vblob = var_b[vo:vo+vl]
                write_bytes(seg_base / 'full.bin', fblob)
                write_bytes(seg_base / 'variant.bin', vblob)
                (seg_base / 'full.hex.txt').write_text(fblob.hex(), encoding='utf-8')
                (seg_base / 'variant.hex.txt').write_text(vblob.hex(), encoding='utf-8')
                seg_rows.append({
                    'layer': layer_name, 'seg_index': idx, 'kind': kind,
                    'full_off': fo, 'variant_off': vo,
                    'full_len': fl, 'variant_len': vl,
                })

    with (out_dir / 'segment_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['layer','seg_index','kind','full_off','variant_off','full_len','variant_len'])
        w.writeheader()
        w.writerows(seg_rows)

    summary = []
    summary.append('BX v28 decode focus')
    summary.append('===================')
    summary.append(f'pack_name: {pack_name}')
    summary.append(f'descriptor_rid: {drid}')
    summary.append(f'payload_rid: {prid}')
    summary.append('')
    summary.append('Descriptor schema:')
    for seg in summarize_segments(d_schema):
        summary.append(json.dumps(seg, ensure_ascii=False))
    summary.append('')
    summary.append('Payload schema:')
    for seg in summarize_segments(p_schema):
        summary.append(json.dumps(seg, ensure_ascii=False))

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'hypothesis.json').write_text(json.dumps(hypothesis, indent=2), encoding='utf-8')

def main():
    ap = argparse.ArgumentParser(description='BX v28 focused decode pack builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-focus')
    p.add_argument('v27_root', type=Path)
    p.add_argument('pack_name', type=str, choices=['primary_d07_p13', 'secondary_d06_p10', 'alternate_A_d05_p09', 'alternate_B_d07_p15'])
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd == 'build-focus':
        build_focus(ns.v27_root, ns.pack_name, ns.out_dir)

if __name__ == '__main__':
    main()
