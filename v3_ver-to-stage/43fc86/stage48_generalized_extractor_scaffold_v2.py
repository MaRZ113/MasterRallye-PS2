#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd

THIS = Path(__file__).resolve().parent
SEEDS = pd.read_csv(THIS / "manifests" / "stage48_seed_router_table_v2.csv")
FIELD_RULES = pd.read_csv(THIS / "manifests" / "stage48_field_aware_router_43fc86.csv")

def classify_row(row: dict) -> dict:
    sig8 = str(row.get('sig8',''))
    body_prefix = str(row.get('body_prefix',''))
    matched_field = str(row.get('matched_field','')).strip()

    if matched_field and matched_field.lower() != 'nan':
        fm = FIELD_RULES[
            (FIELD_RULES['sig8'].astype(str) == sig8) &
            (FIELD_RULES['body_prefix'].astype(str) == body_prefix) &
            (FIELD_RULES['matched_field'].astype(str) == matched_field)
        ]
        if len(fm):
            top = fm.sort_values(['seed_count'], ascending=False).iloc[0]
            return {
                'status': top['promoted_status'],
                'family_id': top['family_id'],
                'content_class': top['content_class'],
                'routing_result': 'field_aware_resolution',
                'semantic_label': top['semantic_label'],
                'rationale': 'resolved by sig8 + body_prefix + matched_field'
            }

    sm = SEEDS[(SEEDS['sig8'].astype(str)==sig8) & (SEEDS['body_prefix'].astype(str)==body_prefix)]
    if len(sm):
        top = sm.sort_values(['seed_count'], ascending=False).iloc[0]
        return {
            'status': 'confirmed_clean' if str(top['routing_layer']) == 'primary_clean' else str(top['routing_layer']),
            'family_id': top['family_id'],
            'content_class': top['content_class'],
            'routing_result': 'seed_pair_match',
            'semantic_label': '',
            'rationale': 'resolved by sig8 + body_prefix'
        }

    if sig8 == '0000010c43fc86e9' and body_prefix in ('4cc3','521f'):
        return {
            'status':'needs_field_resolution',
            'family_id':'',
            'content_class':'',
            'routing_result':'ambiguous_43fc86_pair',
            'semantic_label':'',
            'rationale':'43fc86 pair is ambiguous without matched_field'
        }

    return {
        'status':'unresolved',
        'family_id':'',
        'content_class':'',
        'routing_result':'unknown_pair',
        'semantic_label':'',
        'rationale':'no router rule matched'
    }

def main():
    ap = argparse.ArgumentParser(description='Stage 48 field-aware generalized media router')
    ap.add_argument('input_csv')
    ap.add_argument('output_csv')
    args = ap.parse_args()
    df = pd.read_csv(args.input_csv)
    out = []
    for _, row in df.iterrows():
        info = classify_row(row.to_dict())
        d = dict(row)
        d.update(info)
        out.append(d)
    pd.DataFrame(out).to_csv(args.output_csv, index=False)
    print(f'wrote {len(out)} rows to {args.output_csv}')

if __name__ == '__main__':
    main()
