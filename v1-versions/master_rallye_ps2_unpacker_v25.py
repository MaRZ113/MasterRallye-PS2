#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import csv
from pathlib import Path
from typing import List, Dict

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def dump_hex(b: bytes) -> str:
    return b.hex()

def build_segments(full_b: bytes, var_b: bytes, changes: List[dict]) -> List[dict]:
    """
    Build a coarse schema from difflib-style change hunks already computed in v24.
    Each change defines a divergence window. Everything between windows is shared.
    """
    segs: List[dict] = []
    fcur = 0
    vcur = 0
    idx = 0
    for ch in changes:
        fo = int(ch['full_off']); fl = int(ch['full_len'])
        vo = int(ch['variant_off']); vl = int(ch['variant_len'])

        # shared bytes before divergence
        if fo > fcur and vo > vcur:
            shared_f = full_b[fcur:fo]
            shared_v = var_b[vcur:vo]
            # keep only exact-overlap shared prefix if lengths differ unexpectedly
            shared_len = min(len(shared_f), len(shared_v))
            if shared_len > 0 and shared_f[:shared_len] == shared_v[:shared_len]:
                segs.append({
                    'kind': 'shared',
                    'index': idx,
                    'full_off': fcur,
                    'variant_off': vcur,
                    'len': shared_len,
                    'hex_preview': shared_f[:32].hex(),
                })
                idx += 1

        # divergent slice
        segs.append({
            'kind': ch['tag'],
            'index': idx,
            'full_off': fo,
            'full_len': fl,
            'variant_off': vo,
            'variant_len': vl,
            'full_hex_preview': full_b[fo:fo+min(fl,32)].hex(),
            'variant_hex_preview': var_b[vo:vo+min(vl,32)].hex(),
        })
        idx += 1
        fcur = fo + fl
        vcur = vo + vl

    # trailing shared
    tf = full_b[fcur:]
    tv = var_b[vcur:]
    tlen = min(len(tf), len(tv))
    if tlen > 0 and tf[:tlen] == tv[:tlen]:
        segs.append({
            'kind': 'shared',
            'index': idx,
            'full_off': fcur,
            'variant_off': vcur,
            'len': tlen,
            'hex_preview': tf[:32].hex(),
        })
    return segs

def classify_rid(rid: int) -> str:
    if rid in (1,2):
        return 'shared_header_core'
    if rid == 3:
        return 'transition'
    if 4 <= rid <= 7:
        return 'descriptor'
    if 8 <= rid <= 15:
        return 'payload'
    if rid == 16:
        return 'terminal'
    return 'other'

def run(seed_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_lines = []
    manifest = []

    # Shared header
    sh = seed_root / 'shared_header_core'
    if sh.exists():
        hdr_dir = out_dir / 'header_core'
        hdr_dir.mkdir(parents=True, exist_ok=True)
        for rid in (1,2):
            src = sh / f'rid_{rid:02d}.bin'
            if src.exists():
                data = src.read_bytes()
                (hdr_dir / f'rid_{rid:02d}.bin').write_bytes(data)
                (hdr_dir / f'rid_{rid:02d}.hex.txt').write_text(data.hex(), encoding='utf-8')
                manifest.append({'rid': rid, 'bucket': 'header_core', 'len': len(data)})
        summary_lines.append('header_core: extracted rid_01 and rid_02')

    # Rid folders
    for rid_dir in sorted([p for p in seed_root.iterdir() if p.is_dir() and p.name.startswith('rid_')]):
        rid = int(rid_dir.name.split('_')[1])
        if rid in (1,2):
            continue

        diff_path = rid_dir / 'diff.json'
        full_path = rid_dir / f'rid_{rid:02d}_full.bin'
        var_path = rid_dir / f'rid_{rid:02d}_variant.bin'
        if not (diff_path.exists() and full_path.exists() and var_path.exists()):
            continue

        diff = json.loads(diff_path.read_text(encoding='utf-8'))
        full_b = read_bytes(full_path)
        var_b = read_bytes(var_path)
        segs = build_segments(full_b, var_b, diff.get('changes', []))

        bucket = classify_rid(rid)
        rd = out_dir / f'rid_{rid:02d}_{bucket}'
        rd.mkdir(parents=True, exist_ok=True)

        # Write original binaries
        (rd / f'rid_{rid:02d}_full.bin').write_bytes(full_b)
        (rd / f'rid_{rid:02d}_variant.bin').write_bytes(var_b)
        (rd / f'rid_{rid:02d}_full.hex.txt').write_text(full_b.hex(), encoding='utf-8')
        (rd / f'rid_{rid:02d}_variant.hex.txt').write_text(var_b.hex(), encoding='utf-8')

        schema = {
            'rid': rid,
            'bucket': bucket,
            'full_len': len(full_b),
            'variant_len': len(var_b),
            'equal_ratio': diff.get('equal_ratio'),
            'change_count': diff.get('change_count'),
            'segments': segs,
        }
        (rd / 'schema.json').write_text(json.dumps(schema, indent=2), encoding='utf-8')

        manifest.append({
            'rid': rid,
            'bucket': bucket,
            'full_len': len(full_b),
            'variant_len': len(var_b),
            'equal_ratio': diff.get('equal_ratio'),
            'change_count': diff.get('change_count'),
            'segment_count': len(segs),
        })

        summary_lines.append(
            f"rid {rid:02d} [{bucket}] full={len(full_b)} variant={len(var_b)} "
            f"equal_ratio={diff.get('equal_ratio'):.4f} changes={diff.get('change_count')} segments={len(segs)}"
        )

    # Write manifest
    with (out_dir / 'seed_schema_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fn = ['rid','bucket','full_len','variant_len','equal_ratio','change_count','segment_count','len']
        w = csv.DictWriter(f, fieldnames=fn)
        w.writeheader()
        for row in manifest:
            out = {k: row.get(k) for k in fn}
            w.writerow(out)

    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')

def main():
    ap = argparse.ArgumentParser(description='BX v25 seed schema builder from v24 seed decode pack')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('build-seed-schema')
    p.add_argument('seed_root', type=Path)
    p.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'build-seed-schema':
        run(ns.seed_root, ns.out_dir)

if __name__ == '__main__':
    main()
