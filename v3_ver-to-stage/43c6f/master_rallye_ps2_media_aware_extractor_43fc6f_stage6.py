#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pandas as pd


DEFAULT_TNG = '/mnt/data/TNG_rebuilt/TNG.000'
BASE3 = '/mnt/data/semantic_pass_43fc6f_stage3'
BASE5 = '/mnt/data/semantic_pass_43fc6f_stage5'
DEFAULT_OUT = '/mnt/data/semantic_pass_43fc6f_stage6/run'


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ffprobe_summary(path: Path) -> dict:
    cmd = [
        'ffprobe', '-v', 'error',
        '-show_format', '-show_streams',
        '-print_format', 'json',
        str(path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(proc.stdout)
    except Exception as exc:
        return {
            'ffprobe_ok': False,
            'ffprobe_error': str(exc),
            'format_name': '',
            'duration': '',
            'stream_count': 0,
            'stream_types': '',
        }

    streams = data.get('streams', [])
    fmt = data.get('format', {})
    stream_types = '|'.join([s.get('codec_type', '') for s in streams if s.get('codec_type')])
    return {
        'ffprobe_ok': True,
        'ffprobe_error': '',
        'format_name': fmt.get('format_name', ''),
        'duration': fmt.get('duration', ''),
        'stream_count': len(streams),
        'stream_types': stream_types,
    }


def main():
    ap = argparse.ArgumentParser(description='Stage6 media-aware extractor prototype for Master Rallye PS2 43fc6f.')
    ap.add_argument('--tng', default=DEFAULT_TNG, help='Path to canonical TNG.000')
    ap.add_argument('--out', default=DEFAULT_OUT, help='Output directory')
    args = ap.parse_args()

    tng_path = Path(args.tng)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    unique_dir = out / 'unique_media'
    unique_dir.mkdir(exist_ok=True)
    manifests_dir = out / 'manifests'
    manifests_dir.mkdir(exist_ok=True)

    if not tng_path.exists():
        raise SystemExit(f'TNG.000 not found: {tng_path}')

    stage3 = pd.read_csv(f'{BASE3}/43fc6f_stage3_record_bank_assignments.csv')
    rules = pd.read_csv(f'{BASE5}/43fc6f_stage5_curated_extractor_rules.csv')
    media = pd.read_csv(f'{BASE5}/43fc6f_stage5_curated_media_catalog.csv')
    branch_resolution = pd.read_csv(f'{BASE5}/43fc6f_stage5_branch_resolution.csv')

    assign = stage3.merge(
        rules[['branch_family', 'field_pos_dec', 'bank_id', 'media_class', 'selected_rule_note', 'manual_note_stage5']],
        on=['branch_family', 'field_pos_dec', 'bank_id'],
        how='inner',
    )

    media_cols = [
        'bank_id', 'media_class', 'hex_start', 'hex_end', 'start', 'end',
        'size_bytes', 'duration_best_cut', 'format_name_best_cut',
        'manual_status_stage5', 'manual_note_stage5', 'stage5_bank_class'
    ]
    assign = assign.merge(media[media_cols], on=['bank_id', 'media_class'], how='left', suffixes=('', '_media'))

    # One canonical file per curated bank/media pair.
    unique_media_rows = []
    for _, row in media.sort_values(['media_class', 'bank_id']).iterrows():
        start = int(row['start'])
        end = int(row['end'])
        bank_id = row['bank_id']
        media_class = row['media_class']
        ext = '.pss'
        out_name = f'43fc6f_stage6_{bank_id}_{media_class}_{int(start):08X}_{int(end):08X}{ext}'
        out_path = unique_dir / out_name

        with tng_path.open('rb') as src, out_path.open('wb') as dst:
            src.seek(start)
            remaining = end - start
            chunk_size = 1024 * 1024
            while remaining > 0:
                chunk = src.read(min(chunk_size, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)

        probe = ffprobe_summary(out_path)
        size = out_path.stat().st_size
        unique_media_rows.append({
            'bank_id': bank_id,
            'media_class': media_class,
            'hex_start': row['hex_start'],
            'hex_end': row['hex_end'],
            'start': start,
            'end': end,
            'expected_size_bytes': end - start,
            'written_size_bytes': size,
            'output_file': out_name,
            'output_path': str(out_path),
            'sha256': sha256_file(out_path),
            **probe,
            'manual_status_stage5': row['manual_status_stage5'],
            'manual_note_stage5': row['manual_note_stage5'],
            'stage5_bank_class': row['stage5_bank_class'],
        })

    unique_media_df = pd.DataFrame(unique_media_rows)
    unique_media_df.to_csv(manifests_dir / '43fc6f_stage6_unique_media_manifest.csv', index=False)

    # Record-level manifest.
    file_map = unique_media_df.set_index(['bank_id', 'media_class'])['output_file'].to_dict()
    assign['output_file'] = [file_map[(b, m)] for b, m in zip(assign['bank_id'], assign['media_class'])]
    assign['record_media_id'] = (
        assign['branch_family'].astype(str) + '__' +
        assign['bank_id'].astype(str) + '__' +
        assign['record_index'].astype(str)
    )
    assign = assign.sort_values(['media_class', 'bank_id', 'record_index'])
    record_cols = [
        'record_media_id', 'record_index', 'record_offset', 'record_offset_hex',
        'sig8', 'body_prefix', 'tail_sig8', 'branch_family',
        'field_pos_dec', 'field_pos_hex', 'bank_id', 'media_class',
        'cand_off', 'cand_off_hex', 'cluster_start', 'cluster_start_hex',
        'cluster_end', 'cluster_end_hex', 'output_file',
        'selected_rule_note', 'manual_note_stage5',
    ]
    assign[record_cols].to_csv(manifests_dir / '43fc6f_stage6_record_media_assignments.csv', index=False)

    # Branch summary.
    branch_summary = (
        assign.groupby(['branch_family', 'bank_id', 'media_class', 'output_file'], as_index=False)
        .agg(
            record_count=('record_index', 'count'),
            min_record_index=('record_index', 'min'),
            max_record_index=('record_index', 'max'),
            min_record_offset=('record_offset', 'min'),
            max_record_offset=('record_offset', 'max'),
        )
        .sort_values(['media_class', 'branch_family'])
    )
    branch_summary = branch_summary.merge(
        branch_resolution[['branch_family', 'coverage_pct', 'stage5_branch_outcome']],
        on='branch_family', how='left'
    )
    branch_summary.to_csv(manifests_dir / '43fc6f_stage6_branch_media_summary.csv', index=False)

    # Rulepack-style CSV with explicit start/end.
    proto = rules.merge(
        media[['bank_id', 'media_class', 'hex_start', 'hex_end', 'start', 'end', 'stage5_bank_class']],
        on=['bank_id', 'media_class'], how='left'
    ).sort_values(['media_class', 'branch_family'])
    proto.to_csv(manifests_dir / '43fc6f_stage6_media_aware_prototype_rules.csv', index=False)

    # High-level stats.
    stats = {
        'tng_path': str(tng_path),
        'curated_rule_count': int(len(rules)),
        'unique_media_count': int(len(unique_media_df)),
        'record_assignment_count': int(len(assign)),
        'unique_record_count': int(assign['record_index'].nunique()),
        'media_class_counts': assign['media_class'].value_counts().to_dict(),
        'bank_counts': assign['bank_id'].value_counts().to_dict(),
        'branch_count': int(assign['branch_family'].nunique()),
    }
    with (manifests_dir / '43fc6f_stage6_stats.json').open('w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    print(json.dumps(stats, indent=2))


if __name__ == '__main__':
    main()
