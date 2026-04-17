#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional


def safe_name(s: str) -> str:
    s = s.strip().replace('/', '_').replace('\\', '_')
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', s)
    s = re.sub(r'_+', '_', s).strip('._')
    return s or 'untagged'


def classify_rid(rid: int) -> str:
    if 1 <= rid <= 4:
        return 'header'
    if 5 <= rid <= 7:
        return 'descriptor'
    if 8 <= rid <= 15:
        return 'data'
    if rid == 16:
        return 'terminal'
    return 'unknown'


def load_manifest(profile_dir: Path) -> List[dict]:
    path = profile_dir / 'manifest.csv'
    rows: List[dict] = []
    with path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            row['chain_index'] = int(row['chain_index'])
            row['rid'] = int(row['rid'])
            row['start'] = int(row['start'])
            row['payload_start'] = int(row['payload_start']) if row['payload_start'] else None
            row['payload_len'] = int(float(row['payload_len'])) if row['payload_len'] else None
            row['tag_safe'] = row.get('tag_safe') or safe_name(row.get('tag_ascii', ''))
            rows.append(row)
    return rows


def find_payload_file(profile_dir: Path, chain_index: int, rid: int) -> Optional[Path]:
    cdir = profile_dir / 'payloads' / f'chain_{chain_index:03d}'
    if not cdir.exists():
        return None
    matches = sorted(cdir.glob(f'rid_{rid:02d}_*.bin'))
    return matches[0] if matches else None


def file_hash(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open('rb') as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def chain_signature(chain_rows: List[dict]) -> str:
    # Signature based on ordered md5 list by rid, compact but stable.
    items = [f"{r['rid']:02d}:{r.get('md5','')}" for r in sorted(chain_rows, key=lambda x: x['rid']) if r.get('md5')]
    digest = hashlib.md5('|'.join(items).encode('utf-8')).hexdigest()
    return digest


def unpack_family(profile_dir: Path, out_dir: Path) -> None:
    rows = load_manifest(profile_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    chains_dir = out_dir / 'chains'
    rid_banks_dir = out_dir / 'rid_banks'
    chains_dir.mkdir(exist_ok=True)
    rid_banks_dir.mkdir(exist_ok=True)

    by_chain: Dict[int, List[dict]] = defaultdict(list)
    for row in rows:
        by_chain[row['chain_index']].append(row)

    family_summary = {
        'profile_dir': str(profile_dir),
        'chains_total': len(by_chain),
        'rid_role_map': {f'{rid:02d}': classify_rid(rid) for rid in sorted({r['rid'] for r in rows})},
        'role_counts': Counter(classify_rid(r['rid']) for r in rows),
        'chain_groups': {},
    }

    chain_groups: Dict[str, List[int]] = defaultdict(list)
    all_manifest_rows: List[dict] = []

    for chain_index in sorted(by_chain):
        crows = sorted(by_chain[chain_index], key=lambda r: r['rid'])
        sig = chain_signature(crows)
        chain_groups[sig].append(chain_index)

        cdir = chains_dir / f'chain_{chain_index:03d}'
        (cdir / 'header').mkdir(parents=True, exist_ok=True)
        (cdir / 'descriptor').mkdir(exist_ok=True)
        (cdir / 'data').mkdir(exist_ok=True)
        (cdir / 'terminal').mkdir(exist_ok=True)

        chain_json = {
            'chain_index': chain_index,
            'signature_md5': sig,
            'records': [],
        }

        for row in crows:
            rid = row['rid']
            role = classify_rid(rid)
            src = find_payload_file(profile_dir, chain_index, rid)
            dst = cdir / role / f"rid_{rid:02d}_{safe_name(row['tag_safe'])}.bin"
            payload_size = 0
            sha256 = ''
            if src and src.exists():
                shutil.copy2(src, dst)
                payload_size = dst.stat().st_size
                sha256 = file_hash(dst, 'sha256') if payload_size else ''
                # Also build rid banks for cross-chain comparison.
                bank_dir = rid_banks_dir / f'rid_{rid:02d}_{role}'
                bank_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dst, bank_dir / f'chain_{chain_index:03d}_{safe_name(row["tag_safe"])}.bin')

            rec = {
                'rid': rid,
                'role': role,
                'tag_ascii': row.get('tag_ascii', ''),
                'tag_safe': row.get('tag_safe', ''),
                'start': row['start'],
                'payload_start': row['payload_start'],
                'payload_len': row['payload_len'],
                'md5': row.get('md5', ''),
                'sha1': row.get('sha1', ''),
                'sha256': sha256,
                'copied_payload_size': payload_size,
                'output_path': str(dst.relative_to(out_dir)) if src and src.exists() else '',
            }
            chain_json['records'].append(rec)
            all_manifest_rows.append({'chain_index': chain_index, **rec, 'signature_md5': sig})

        (cdir / 'chain.json').write_text(json.dumps(chain_json, ensure_ascii=False, indent=2), encoding='utf-8')

    family_summary['chain_groups'] = {sig: chains for sig, chains in chain_groups.items()}
    (out_dir / 'family_summary.json').write_text(json.dumps(family_summary, ensure_ascii=False, indent=2), encoding='utf-8')

    # Write a convenient manifest CSV.
    manifest_csv = out_dir / 'unpacked_manifest.csv'
    fieldnames = [
        'chain_index', 'signature_md5', 'rid', 'role', 'tag_ascii', 'tag_safe', 'start',
        'payload_start', 'payload_len', 'md5', 'sha1', 'sha256', 'copied_payload_size', 'output_path'
    ]
    with manifest_csv.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in all_manifest_rows:
            w.writerow(row)

    # Human-readable summary.
    rid_stats: Dict[int, List[int]] = defaultdict(list)
    for row in all_manifest_rows:
        if row['copied_payload_size']:
            rid_stats[row['rid']].append(row['copied_payload_size'])

    lines = []
    lines.append('BX v13 first real unpacker prototype summary')
    lines.append('===========================================')
    lines.append(f'profile_dir: {profile_dir}')
    lines.append(f'chains_total: {len(by_chain)}')
    lines.append(f'unique_chain_signatures: {len(chain_groups)}')
    lines.append('')
    lines.append('RID groups:')
    for rid in sorted(rid_stats):
        vals = sorted(rid_stats[rid])
        med = vals[len(vals)//2]
        lines.append(f'rid {rid:02d} [{classify_rid(rid)}]: count={len(vals)} min={vals[0]} med={med} max={vals[-1]}')
    lines.append('')
    lines.append('Chain signature groups:')
    for sig, chains in sorted(chain_groups.items(), key=lambda kv: (len(kv[1]), kv[0]), reverse=True):
        lines.append(f'{sig}: chains={chains}')
    (out_dir / 'summary.txt').write_text('\n'.join(lines), encoding='utf-8')



def main() -> int:
    ap = argparse.ArgumentParser(description='Master Rallye PS2 BX v13 first real unpacker prototype')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_unpack = sub.add_parser('unpack-family', help='Unpack one canonical BX family profile into structured chains/rid banks')
    p_unpack.add_argument('profile_dir', type=Path)
    p_unpack.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd == 'unpack-family':
        unpack_family(ns.profile_dir, ns.out_dir)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
