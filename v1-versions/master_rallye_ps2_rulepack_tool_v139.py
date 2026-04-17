#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def validate_rulepack(rulepack: list[dict[str, Any]]) -> tuple[bool, str]:
    required_keys = {'name', 'sig7', 'prev', 'next', 'members'}
    seen = set()
    for i, rule in enumerate(rulepack):
        missing = required_keys - set(rule.keys())
        if missing:
            return False, f'rule #{i} missing keys: {sorted(missing)}'
        if not isinstance(rule['members'], dict) or not rule['members']:
            return False, f'rule #{i} has empty members'
        if rule['name'] in seen:
            return False, f'duplicate rule name: {rule["name"]}'
        seen.add(rule['name'])
    return True, 'ok'


def normalize_rulepack(rulepack: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for rule in rulepack:
        r = dict(rule)
        if 'source' not in r or not r['source']:
            r['source'] = 'manual_base'
        out.append(r)
    return out


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def load_rulepack(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding='utf-8'))
    ok, msg = validate_rulepack(data)
    if not ok:
        raise SystemExit(f'Invalid rulepack: {msg}')
    return normalize_rulepack(data)


def cmd_lint(args: argparse.Namespace) -> None:
    rp = load_rulepack(Path(args.rulepack_json))
    print(f'OK: {len(rp)} rules')


def cmd_stats(args: argparse.Namespace) -> None:
    rp = load_rulepack(Path(args.rulepack_json))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    by_source = Counter(r.get('source', 'unknown') for r in rp)
    by_sig7 = Counter(r['sig7'] for r in rp)
    by_prev_next = Counter(f'{r["prev"]} || {r["next"]}' for r in rp)
    by_member_count = Counter(len(r['members']) for r in rp)

    write_csv(
        out_dir / 'by_source.csv',
        [{'source': k, 'rules': v} for k, v in by_source.most_common()],
        ['source', 'rules'],
    )
    write_csv(
        out_dir / 'by_sig7.csv',
        [{'sig7': k, 'rules': v} for k, v in by_sig7.most_common()],
        ['sig7', 'rules'],
    )
    write_csv(
        out_dir / 'by_prev_next.csv',
        [{'prev_next': k, 'rules': v} for k, v in by_prev_next.most_common()],
        ['prev_next', 'rules'],
    )
    write_csv(
        out_dir / 'by_member_count.csv',
        [{'member_count': k, 'rules': v} for k, v in sorted(by_member_count.items())],
        ['member_count', 'rules'],
    )
    write_csv(
        out_dir / 'rule_names.csv',
        [
            {
                'rule_name': r['name'],
                'source': r.get('source', 'unknown'),
                'sig7': r['sig7'],
                'prev': r['prev'],
                'next': r['next'],
                'member_count': len(r['members']),
            }
            for r in rp
        ],
        ['rule_name', 'source', 'sig7', 'prev', 'next', 'member_count'],
    )

    summary = []
    summary.append('MRPS2 v139 rulepack stats')
    summary.append('========================')
    summary.append(f'rulepack_json: {args.rulepack_json}')
    summary.append(f'total_rules: {len(rp)}')
    summary.append('')
    summary.append('By source:')
    for k, v in by_source.most_common():
        summary.append(f'  {k} :: {v}')
    summary.append('')
    summary.append('Top prev/next groups:')
    for k, v in by_prev_next.most_common(20):
        summary.append(f'  {k} :: {v}')
    summary.append('')
    summary.append('By member_count:')
    for k, v in sorted(by_member_count.items()):
        summary.append(f'  {k} :: {v}')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')


def merge_rulepacks(base: list[dict[str, Any]], additions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = {r['name']: dict(r) for r in base}
    replaced = 0
    added = 0
    for r in additions:
        if r['name'] in merged:
            replaced += 1
        else:
            added += 1
        merged[r['name']] = dict(r)
    out = list(merged.values())
    out.sort(key=lambda r: (r.get('source', 'unknown'), r['name']))
    return out, added, replaced


def cmd_merge(args: argparse.Namespace) -> None:
    base = load_rulepack(Path(args.base_rulepack_json))
    additions = load_rulepack(Path(args.additions_json))
    merged, added, replaced = merge_rulepacks(base, additions)
    out_path = Path(args.output_rulepack_json)
    out_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'OK: merged={len(merged)} added={added} replaced={replaced}')


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description='Master Rallye PS2 rulepack tool')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_lint = sub.add_parser('lint', help='Validate rulepack JSON')
    p_lint.add_argument('rulepack_json', type=Path)
    p_lint.set_defaults(func=cmd_lint)

    p_stats = sub.add_parser('stats', help='Generate rulepack statistics')
    p_stats.add_argument('rulepack_json', type=Path)
    p_stats.add_argument('out_dir', type=Path)
    p_stats.set_defaults(func=cmd_stats)

    p_merge = sub.add_parser('merge', help='Merge additions into base rulepack')
    p_merge.add_argument('base_rulepack_json', type=Path)
    p_merge.add_argument('additions_json', type=Path)
    p_merge.add_argument('output_rulepack_json', type=Path)
    p_merge.set_defaults(func=cmd_merge)

    return ap


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
