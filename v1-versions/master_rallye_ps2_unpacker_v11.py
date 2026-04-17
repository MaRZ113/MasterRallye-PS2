#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median

def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def lcp(blobs: list[bytes]) -> int:
    if not blobs:
        return 0
    m = min(len(b) for b in blobs)
    i = 0
    while i < m:
        x = blobs[0][i]
        if all(b[i] == x for b in blobs[1:]):
            i += 1
        else:
            break
    return i

def lcs(blobs: list[bytes]) -> int:
    return lcp([b[::-1] for b in blobs]) if blobs else 0

def analyze_profile(profile_dir: Path, out_dir: Path):
    rows = list(csv.DictReader((profile_dir/'manifest.csv').open('r', encoding='utf-8')))
    by = defaultdict(list)
    for r in rows:
        by[int(r['rid'])].append(r)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for rid in sorted(by):
        blobs=[]; lens=[]; ents=[]
        for r in by[rid]:
            if not r.get('payload_len') or r['payload_len'] in ('nan','NaN',''):
                continue
            p = profile_dir/'payloads'/f"chain_{int(r['chain_index']):03d}"/f"rid_{int(r['rid']):02d}_{r['tag_safe']}.bin"
            if not p.exists():
                continue
            b = p.read_bytes()
            blobs.append(b); lens.append(len(b)); ents.append(entropy(b))
        summary.append({
            'rid': rid,
            'samples': len(blobs),
            'len_min': min(lens) if lens else None,
            'len_med': median(lens) if lens else None,
            'len_max': max(lens) if lens else None,
            'entropy_min': round(min(ents),4) if ents else None,
            'entropy_med': round(median(ents),4) if ents else None,
            'entropy_max': round(max(ents),4) if ents else None,
            'common_prefix_len': lcp(blobs),
            'common_suffix_len': lcs(blobs),
        })
    (out_dir/'rid_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    with (out_dir/'rid_summary.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys())); w.writeheader(); w.writerows(summary)
    with (out_dir/'summary.txt').open('w', encoding='utf-8') as f:
        for r in summary:
            f.write(f"rid {r['rid']:02d}: samples={r['samples']} len={r['len_min']}/{r['len_med']}/{r['len_max']} ent={r['entropy_min']}/{r['entropy_med']}/{r['entropy_max']} prefix={r['common_prefix_len']} suffix={r['common_suffix_len']}\n")

def compare_profiles(full_out: Path, variant_out: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    full = {int(r['rid']):r for r in json.loads((full_out/'rid_summary.json').read_text(encoding='utf-8'))}
    var = {int(r['rid']):r for r in json.loads((variant_out/'rid_summary.json').read_text(encoding='utf-8'))}
    rows=[]
    for rid in sorted(set(full)|set(var)):
        a=full.get(rid,{}); b=var.get(rid,{})
        rows.append({
            'rid': rid,
            'full_len_med': a.get('len_med'), 'full_entropy_med': a.get('entropy_med'), 'full_prefix': a.get('common_prefix_len'), 'full_suffix': a.get('common_suffix_len'),
            'variant_len_med': b.get('len_med'), 'variant_entropy_med': b.get('entropy_med'), 'variant_prefix': b.get('common_prefix_len'), 'variant_suffix': b.get('common_suffix_len'),
        })
    with (out_dir/'compare.csv').open('w', encoding='utf-8', newline='') as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    with (out_dir/'compare.txt').open('w', encoding='utf-8') as f:
        f.write('Canonical family compare\n')
        for r in rows:
            f.write(f"rid {r['rid']:02d}: full len_med={r['full_len_med']} ent={r['full_entropy_med']} prefix={r['full_prefix']} suffix={r['full_suffix']} | variant len_med={r['variant_len_med']} ent={r['variant_entropy_med']} prefix={r['variant_prefix']} suffix={r['variant_suffix']}\n")

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('analyze-profile')
    a.add_argument('profile_dir', type=Path)
    a.add_argument('out_dir', type=Path)
    c = sub.add_parser('compare-profiles')
    c.add_argument('full_profile_out', type=Path)
    c.add_argument('variant_profile_out', type=Path)
    c.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'analyze-profile':
        analyze_profile(ns.profile_dir, ns.out_dir)
    else:
        compare_profiles(ns.full_profile_out, ns.variant_profile_out, ns.out_dir)

if __name__ == '__main__':
    main()
