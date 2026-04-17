#!/usr/bin/env python3
from __future__ import annotations
import csv, argparse
from pathlib import Path

DEFAULT_ASSIGN = Path('/mnt/data/semantic_pass_43fc65_stage6_final/43fc65_safe_record_assignments_stage6.csv')
RESEARCH_ASSIGN = Path('/mnt/data/semantic_pass_43fc65_stage6_final/43fc65_research_record_assignments_stage6.csv')

def load_rows(path: Path):
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def export_rows(rows, tng: Path, outdir: Path, dedupe: bool=True):
    outdir.mkdir(parents=True, exist_ok=True)
    seen=set()
    with tng.open('rb') as fh:
        for r in rows:
            start=int(r['stream_start']); end=int(r['stream_end'])
            key=(start,end)
            if dedupe and key in seen:
                continue
            seen.add(key)
            name=f"43fc65_{r['stage6_class']}_{start:08X}_{end:08X}.pss"
            fh.seek(start)
            data=fh.read(end-start)
            (outdir/name).write_bytes(data)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('tng')
    ap.add_argument('outdir')
    ap.add_argument('--mode', choices=['safe','research','all'], default='safe')
    ap.add_argument('--no-dedupe', action='store_true')
    args=ap.parse_args()
    rows=[]
    if args.mode in ('safe','all'):
        rows += load_rows(DEFAULT_ASSIGN)
    if args.mode in ('research','all'):
        rows += load_rows(RESEARCH_ASSIGN)
    export_rows(rows, Path(args.tng), Path(args.outdir), dedupe=not args.no_dedupe)

if __name__ == '__main__':
    main()
