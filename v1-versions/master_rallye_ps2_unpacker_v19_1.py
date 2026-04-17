#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from difflib import SequenceMatcher
from pathlib import Path
from statistics import median
from typing import List

TARGET_RIDS = [1, 5, 6, 7, 9, 10, 13, 15]
DESCRIPTOR_RIDS = [5, 6, 7]


def iter_payload_files(root: Path, rid: int):
    bank = root / 'rid_banks' / f'rid_{rid:02d}'
    if not bank.exists():
        return []
    return sorted([p for p in bank.glob('*.bin') if p.is_file()])


def read_all_payloads(root: Path, rid: int) -> List[bytes]:
    return [p.read_bytes() for p in iter_payload_files(root, rid)]


def common_prefix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    shortest = min(len(b) for b in blobs)
    i = 0
    while i < shortest:
        x = blobs[0][i]
        if all(b[i] == x for b in blobs[1:]):
            i += 1
        else:
            break
    return i


def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    shortest = min(len(b) for b in blobs)
    i = 0
    while i < shortest:
        x = blobs[0][-1 - i]
        if all(b[-1 - i] == x for b in blobs[1:]):
            i += 1
        else:
            break
    return i


def align_family(blobs: List[bytes]) -> dict:
    if not blobs:
        return {}
    ref = max(blobs, key=len)
    matcher_stats = []
    for b in blobs:
        sm = SequenceMatcher(None, ref, b, autojunk=False)
        blocks = sm.get_matching_blocks()
        kept = [blk for blk in blocks if blk.size >= 4]
        matcher_stats.append({
            'len': len(b),
            'match_blocks': [{'a': blk.a, 'b': blk.b, 'size': blk.size} for blk in kept[:64]],
            'ratio': sm.ratio(),
        })
    return {
        'ref_len': len(ref),
        'count': len(blobs),
        'common_prefix': common_prefix_len(blobs),
        'common_suffix': common_suffix_len(blobs),
        'matcher_stats': matcher_stats,
    }


def pairwise_diff_summary(a_blobs: List[bytes], b_blobs: List[bytes]) -> dict:
    if not a_blobs or not b_blobs:
        return {}
    results = []
    for a in a_blobs:
        best = None
        best_sm = None
        for b in b_blobs:
            sm = SequenceMatcher(None, a, b, autojunk=False)
            r = sm.ratio()
            if best is None or r > best:
                best = r
                best_sm = sm
        blocks = [blk for blk in best_sm.get_matching_blocks() if blk.size >= 4]
        results.append({
            'a_len': len(a),
            'best_ratio': best,
            'common_prefix': next((blk.size for blk in blocks if blk.a == 0 and blk.b == 0), 0),
            'max_block': max((blk.size for blk in blocks), default=0),
            'block_count': len(blocks),
        })
    return {
        'count': len(results),
        'median_best_ratio': median(r['best_ratio'] for r in results),
        'median_common_prefix': median(r['common_prefix'] for r in results),
        'median_max_block': median(r['max_block'] for r in results),
        'median_block_count': median(r['block_count'] for r in results),
        'samples': results[:32],
    }


def summarize_rid(full_root: Path, variant_root: Path, rid: int) -> dict:
    full = read_all_payloads(full_root, rid)
    variant = read_all_payloads(variant_root, rid)
    fam_full = align_family(full)
    fam_var = align_family(variant)
    cross = pairwise_diff_summary(full, variant)
    return {
        'rid': rid,
        'full_count': len(full),
        'variant_count': len(variant),
        'full_median_len': median([len(x) for x in full]) if full else None,
        'variant_median_len': median([len(x) for x in variant]) if variant else None,
        'full_common_prefix': fam_full.get('common_prefix', 0),
        'variant_common_prefix': fam_var.get('common_prefix', 0),
        'full_common_suffix': fam_full.get('common_suffix', 0),
        'variant_common_suffix': fam_var.get('common_suffix', 0),
        'cross_median_best_ratio': cross.get('median_best_ratio'),
        'cross_median_common_prefix': cross.get('median_common_prefix'),
        'cross_median_max_block': cross.get('median_max_block'),
        'cross_median_block_count': cross.get('median_block_count'),
        'descriptor_candidate': rid in DESCRIPTOR_RIDS,
    }


def dump_hex_preview(blobs: List[bytes], out_path: Path, limit: int = 64):
    lines = []
    for i, b in enumerate(blobs):
        lines.append(f'[{i}] len={len(b)}')
        lines.append(b[:limit].hex(' '))
        lines.append('')
    out_path.write_text('\n'.join(lines), encoding='utf-8')


def fmt_ratio(v):
    return 'n/a' if v is None else f'{v:.4f}'


def pick_rank_item(arr, idx):
    return arr[idx] if len(arr) > idx else None


def run_descriptor_diff(full_root: Path, variant_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for rid in TARGET_RIDS:
        row = summarize_rid(full_root, variant_root, rid)
        rows.append(row)
        rid_dir = out_dir / f'rid_{rid:02d}'
        rid_dir.mkdir(exist_ok=True)
        full = read_all_payloads(full_root, rid)
        variant = read_all_payloads(variant_root, rid)
        dump_hex_preview(full, rid_dir / 'full_preview.txt')
        dump_hex_preview(variant, rid_dir / 'variant_preview.txt')
        (rid_dir / 'summary.json').write_text(json.dumps(row, indent=2), encoding='utf-8')

    csv_path = out_dir / 'rid_diff.csv'
    with csv_path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    desc = [r for r in rows if r['descriptor_candidate']]
    data = [r for r in rows if r['rid'] not in DESCRIPTOR_RIDS and r['rid'] not in [1, 2, 3, 4, 16]]
    desc_rank = sorted(desc, key=lambda r: ((r['cross_median_best_ratio'] or 0), -(r['full_median_len'] or 0)))
    data_rank = sorted(data, key=lambda r: ((r['cross_median_best_ratio'] or 0), -(abs((r['full_median_len'] or 0) - (r['variant_median_len'] or 0)))))

    summary_lines = []
    summary_lines.append('BX v19 descriptor-aware diff')
    summary_lines.append('==========================')
    summary_lines.append(f'full_root: {full_root}')
    summary_lines.append(f'variant_root: {variant_root}')
    summary_lines.append('')
    summary_lines.append('Descriptor rids ranked by lowest cross-family similarity:')
    for r in desc_rank:
        summary_lines.append(
            f"rid {r['rid']:02d}: ratio={fmt_ratio(r['cross_median_best_ratio'])} full_med={r['full_median_len']} var_med={r['variant_median_len']} full_pref={r['full_common_prefix']} var_pref={r['variant_common_prefix']}"
        )
    summary_lines.append('')
    summary_lines.append('Payload rids ranked by lowest cross-family similarity:')
    for r in data_rank:
        summary_lines.append(
            f"rid {r['rid']:02d}: ratio={fmt_ratio(r['cross_median_best_ratio'])} full_med={r['full_median_len']} var_med={r['variant_median_len']} max_block={r['cross_median_max_block']}"
        )
    summary_lines.append('')
    summary_lines.append('Suggested next decode focus:')
    summary_lines.append('1) rid 01 as common header')
    first_desc = pick_rank_item(desc_rank, 0)
    second_desc = pick_rank_item(desc_rank, 1)
    if first_desc and second_desc:
        summary_lines.append(f"2) rid {first_desc['rid']:02d} then rid {second_desc['rid']:02d} as top descriptor candidates")
    elif first_desc:
        summary_lines.append(f"2) rid {first_desc['rid']:02d} as top descriptor candidate")
    first_data = pick_rank_item(data_rank, 0)
    second_data = pick_rank_item(data_rank, 1)
    if first_data and second_data:
        summary_lines.append(f"3) rid {first_data['rid']:02d} then rid {second_data['rid']:02d} as top payload candidates")
    elif first_data:
        summary_lines.append(f"3) rid {first_data['rid']:02d} as top payload candidate")

    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('descriptor-diff')
    p.add_argument('full_root', type=Path)
    p.add_argument('variant_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd == 'descriptor-diff':
        run_descriptor_diff(ns.full_root, ns.variant_root, ns.out_dir)


if __name__ == '__main__':
    main()
