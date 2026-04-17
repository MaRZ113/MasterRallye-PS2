#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Dict

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def read_bytes(path: Path) -> bytes:
    return path.read_bytes()

def load_hypothesis(root: Path) -> dict:
    p = root / 'hypothesis.json'
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding='utf-8'))

def load_manifest(root: Path) -> List[dict]:
    p = root / 'segment_manifest.csv'
    if not p.exists():
        raise FileNotFoundError(p)
    with p.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        rr = dict(r)
        for k in ('seg_index', 'full_off', 'variant_off', 'full_len', 'variant_len'):
            if k in rr and rr[k] not in ('', None):
                rr[k] = int(rr[k])
        out.append(rr)
    return out

def collect_family_stream(root: Path, layer: str, family: str) -> List[dict]:
    """
    Read segment files from v28 output:
      descriptor/segments/seg_XX_kind/{full.bin|variant.bin|shared.bin}
      payload/segments/...
    Return ordered list of non-empty segments relevant to the chosen family.
    """
    rows = [r for r in load_manifest(root) if r['layer'] == layer]
    rows.sort(key=lambda r: int(r['seg_index']))

    segs: List[dict] = []
    seg_root = root / layer / 'segments'

    for r in rows:
        seg_name = f"seg_{int(r['seg_index']):02d}_{r['kind']}"
        sdir = seg_root / seg_name
        if not sdir.exists():
            continue

        kind = r['kind']
        if kind == 'shared':
            sp = sdir / 'shared.bin'
            if sp.exists():
                segs.append({
                    'seg_index': int(r['seg_index']),
                    'kind': kind,
                    'family': 'shared',
                    'data': read_bytes(sp),
                    'len': len(read_bytes(sp)),
                    'source_rel': str(sp.relative_to(root)),
                })
            continue

        fp = sdir / 'full.bin'
        vp = sdir / 'variant.bin'

        if family == 'full' and fp.exists():
            data = read_bytes(fp)
            segs.append({
                'seg_index': int(r['seg_index']),
                'kind': kind,
                'family': family,
                'data': data,
                'len': len(data),
                'source_rel': str(fp.relative_to(root)),
            })
        elif family == 'variant' and vp.exists():
            data = read_bytes(vp)
            segs.append({
                'seg_index': int(r['seg_index']),
                'kind': kind,
                'family': family,
                'data': data,
                'len': len(data),
                'source_rel': str(vp.relative_to(root)),
            })

    return segs

def build_streams(v28_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)

    hyp = load_hypothesis(v28_root)
    drid = hyp.get('descriptor_rid')
    prid = hyp.get('payload_rid')

    summary_lines = []
    summary_lines.append('BX v30.1 artifact streams')
    summary_lines.append('=========================')
    summary_lines.append(f'focus_root: {v28_root}')
    summary_lines.append(f'descriptor_rid: {drid}')
    summary_lines.append(f'payload_rid: {prid}')
    summary_lines.append('')

    manifest_rows = []

    for family in ('full', 'variant'):
        dsegs = collect_family_stream(v28_root, 'descriptor', family)
        psegs = collect_family_stream(v28_root, 'payload', family)

        desc_stream = b''.join(seg['data'] for seg in dsegs)
        pay_stream = b''.join(seg['data'] for seg in psegs)
        combo_stream = desc_stream + pay_stream

        # Write main streams
        write_bytes(out_dir / f'descriptor_{family}_exclusive.bin', desc_stream)
        write_bytes(out_dir / f'payload_{family}_exclusive.bin', pay_stream)
        write_bytes(out_dir / f'combo_{family}_exclusive.bin', combo_stream)

        (out_dir / f'descriptor_{family}_exclusive.bin.hex.txt').write_text(desc_stream.hex(), encoding='utf-8')
        (out_dir / f'payload_{family}_exclusive.bin.hex.txt').write_text(pay_stream.hex(), encoding='utf-8')
        (out_dir / f'combo_{family}_exclusive.bin.hex.txt').write_text(combo_stream.hex(), encoding='utf-8')

        # Copy per-segment banks
        family_dir = out_dir / family
        for seg in dsegs:
            name = f'descriptor_seg_{seg["seg_index"]:02d}_{seg["kind"]}.bin'
            write_bytes(family_dir / 'descriptor_segments' / name, seg['data'])
            manifest_rows.append({
                'family': family,
                'layer': 'descriptor',
                'seg_index': seg['seg_index'],
                'kind': seg['kind'],
                'len': seg['len'],
                'source_rel': seg['source_rel'],
                'out_file': str((family_dir / 'descriptor_segments' / name).relative_to(out_dir)),
            })

        for seg in psegs:
            name = f'payload_seg_{seg["seg_index"]:02d}_{seg["kind"]}.bin'
            write_bytes(family_dir / 'payload_segments' / name, seg['data'])
            manifest_rows.append({
                'family': family,
                'layer': 'payload',
                'seg_index': seg['seg_index'],
                'kind': seg['kind'],
                'len': seg['len'],
                'source_rel': seg['source_rel'],
                'out_file': str((family_dir / 'payload_segments' / name).relative_to(out_dir)),
            })

        summary_lines.append(
            f'{family}: descriptor_exclusive={len(desc_stream)} payload_exclusive={len(pay_stream)} combo={len(combo_stream)}'
        )

        if dsegs:
            summary_lines.append(
                '  descriptor top segs: ' +
                ', '.join(f'{s["seg_index"]:02d}:{s["kind"]}:{s["len"]}' for s in sorted(dsegs, key=lambda x: x['len'], reverse=True)[:6])
            )
        if psegs:
            summary_lines.append(
                '  payload top segs: ' +
                ', '.join(f'{s["seg_index"]:02d}:{s["kind"]}:{s["len"]}' for s in sorted(psegs, key=lambda x: x['len'], reverse=True)[:8])
            )

    # Manifest and summary
    with (out_dir / 'artifact_stream_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family','layer','seg_index','kind','len','source_rel','out_file'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')
    (out_dir / 'hypothesis.json').write_text(json.dumps(hyp, indent=2), encoding='utf-8')

def main():
    ap = argparse.ArgumentParser(description='BX v30.1 artifact stream builder (fixed for v28 layout)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-streams')
    p.add_argument('v28_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd == 'build-streams':
        build_streams(ns.v28_root, ns.out_dir)

if __name__ == '__main__':
    main()
