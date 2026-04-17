#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
from difflib import SequenceMatcher
from pathlib import Path

TARGET_RIDS = [3,4,5,6,7,9,10,13,15]


def read_bytes(p: Path) -> bytes:
    return p.read_bytes()


def find_group_dir(root: Path, group: str) -> Path:
    p = root / group
    if p.exists():
        return p
    raise FileNotFoundError(f'group not found: {group}')


def locate_pair(group_dir: Path, rid: int) -> tuple[Path, Path, str]:
    if rid == 3:
        layer = 'transition_layer'
    elif 4 <= rid <= 7:
        layer = 'divergence_layer'
    else:
        layer = 'payload_layer'
    full = group_dir / layer / f'rid_{rid:02d}_full.bin'
    variant = group_dir / layer / f'rid_{rid:02d}_variant.bin'
    return full, variant, layer


def render_hex(b: bytes, width: int = 16, limit: int = 128) -> str:
    b = b[:limit]
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hx = ' '.join(f'{x:02X}' for x in chunk)
        lines.append(f'{i:04X}: {hx}')
    return '\n'.join(lines)


def summarize_diff(a: bytes, b: bytes):
    sm = SequenceMatcher(a=a, b=b)
    opcodes = sm.get_opcodes()
    eq = sum(i2-i1 for tag,i1,i2,j1,j2 in opcodes if tag == 'equal')
    ratio = eq / max(len(a), len(b)) if max(len(a), len(b)) else 0.0
    changes = []
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == 'equal':
            continue
        changes.append({
            'tag': tag,
            'full_off': i1,
            'full_len': i2-i1,
            'variant_off': j1,
            'variant_len': j2-j1,
            'full_hex_preview': a[i1:i1+32].hex(),
            'variant_hex_preview': b[j1:j1+32].hex(),
        })
    return ratio, changes


def run_seed(v23_root: Path, group: str, out_dir: Path):
    group_dir = find_group_dir(v23_root, group)
    out_dir.mkdir(parents=True, exist_ok=True)

    # copy shared header core
    sh = out_dir / 'shared_header_core'
    sh.mkdir(exist_ok=True)
    for rid in (1,2):
        src = group_dir / 'shared_header_core' / f'rid_{rid:02d}.bin'
        if src.exists():
            shutil.copy2(src, sh / src.name)
            (sh / f'rid_{rid:02d}.hex.txt').write_text(render_hex(read_bytes(src), limit=64), encoding='utf-8')

    rows = []
    summary = [f'BX v24 seed decode pass', f'group: {group}', '']
    summary.append('Interpretation target:')
    summary.append('- rid 01-02 = shared header core')
    summary.append('- rid 03 = cleanest transition candidate')
    summary.append('- rid 04-07 = descriptor divergence')
    summary.append('- rid 09/10/13/15 = strongest payload candidates')
    summary.append('')

    for rid in TARGET_RIDS:
        full, variant, layer = locate_pair(group_dir, rid)
        if not full.exists() or not variant.exists():
            continue
        a = read_bytes(full)
        b = read_bytes(variant)
        ratio, changes = summarize_diff(a, b)

        rid_dir = out_dir / f'rid_{rid:02d}'
        rid_dir.mkdir(exist_ok=True)
        shutil.copy2(full, rid_dir / full.name)
        shutil.copy2(variant, rid_dir / variant.name)
        (rid_dir / 'full.hex.txt').write_text(render_hex(a), encoding='utf-8')
        (rid_dir / 'variant.hex.txt').write_text(render_hex(b), encoding='utf-8')
        (rid_dir / 'diff.json').write_text(json.dumps({
            'rid': rid,
            'layer': layer,
            'full_len': len(a),
            'variant_len': len(b),
            'equal_ratio': ratio,
            'change_count': len(changes),
            'changes': changes,
        }, indent=2), encoding='utf-8')

        rows.append({
            'rid': rid,
            'layer': layer,
            'full_len': len(a),
            'variant_len': len(b),
            'equal_ratio': f'{ratio:.6f}',
            'change_count': len(changes),
        })
        summary.append(
            f'rid {rid:02d} [{layer}] full={len(a)} variant={len(b)} equal_ratio={ratio:.4f} changes={len(changes)}'
        )

    with (out_dir / 'seed_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rid','layer','full_len','variant_len','equal_ratio','change_count'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description='BX v24 seed decode pass for one paired group')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('seed-decode-group')
    p.add_argument('v23_root', type=Path)
    p.add_argument('group', type=str)
    p.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'seed-decode-group':
        run_seed(ns.v23_root, ns.group, ns.out_dir)

if __name__ == '__main__':
    main()
