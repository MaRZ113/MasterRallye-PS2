#!/usr/bin/env python3
import argparse, csv, shutil
from pathlib import Path

DEFAULT_ASSIGN = Path('/mnt/data/semantic_pass_43fc65_stage5/43fc65_best_record_assignments_stage5.csv')
DEFAULT_EXPORT_ROOT = Path('/mnt/data/semantic_pass_43fc65_stage4/refined_exports')

MODES = {
    'safe': {'safe_playable'},
    'experimental': {'safe_playable','ffprobe_only','aggressive_blob'},
    'all': {'safe_playable','ffprobe_only','aggressive_blob','rejected','unreviewed'},
}

def main():
    ap = argparse.ArgumentParser(description='43fc65 extractor prototype v3 (safe vs experimental)')
    ap.add_argument('--assignments', type=Path, default=DEFAULT_ASSIGN)
    ap.add_argument('--export-root', type=Path, default=DEFAULT_EXPORT_ROOT)
    ap.add_argument('--outdir', type=Path, required=True)
    ap.add_argument('--mode', choices=MODES.keys(), default='safe')
    ap.add_argument('--dedupe', action='store_true', help='export each cluster only once')
    args = ap.parse_args()

    args.outdir.mkdir(parents=True, exist_ok=True)
    allowed = MODES[args.mode]
    seen = set()
    manifest_rows = []
    with args.assignments.open('r', newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row.get('validation_class') not in allowed:
                continue
            fn = row['cluster_file']
            src = args.export_root / fn
            if not src.exists():
                continue
            key = fn if args.dedupe else (row['rec_off'], fn)
            if key in seen:
                continue
            seen.add(key)
            if args.dedupe:
                dst = args.outdir / fn
            else:
                dst = args.outdir / f"rec_{row['rec_off']}_{fn}"
            shutil.copy2(src, dst)
            manifest_rows.append({
                'rec_off': row['rec_off'],
                'cluster_file': fn,
                'validation_class': row.get('validation_class',''),
                'assign_score': row.get('assign_score',''),
                'out_file': dst.name,
            })

    with (args.outdir / 'manifest.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['rec_off','cluster_file','validation_class','assign_score','out_file'])
        w.writeheader(); w.writerows(manifest_rows)

if __name__ == '__main__':
    main()
