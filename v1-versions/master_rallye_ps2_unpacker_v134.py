#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

RECORD_LEN = 507
TAIL_LEN = 54
RID0C_MARKER = b'\x00\x00\x01\x0C'
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

BASE_BUCKET_REGISTRY = [
    {'name':'cross_sig8_tailed_508','sig7':'0000010c425425','prev':'none','next':'0D@508','members':{
        '0000010c42542562': {'body_prefix':'bc82','tail_sig8':'0000010d424864cb'},
        '0000010c42542563': {'body_prefix':'7e79','tail_sig8':'0000010d424864c3'},
    }},
    {'name':'cross_sig8_prevlink_0b313','sig7':'0000010c425425','prev':'0B@-313','next':'none','members':{
        '0000010c42542561': {'body_prefix':'a618'},
        '0000010c42542562': {'body_prefix':'b65d'},
    }},
    {'name':'cross_sig8_tailed_832_asymmetric','sig7':'0000010c425425','prev':'none','next':'0D@832','members':{
        '0000010c42542562': {'body_prefix':'bf6a','tail_sig8':'0000010d424864cb'},
        '0000010c42542563': {'body_prefix':'b141','tail_sig8':'0000010d424864c3'},
    }},
    {'name':'cross_sig8_tailed_552_branch_61','sig7':'0000010c425425','prev':'none','next':'0D@552','members':{
        '0000010c42542561': {'body_prefix':'cc58','tail_sig8':'0000010d424864ce'},
    }},
    {'name':'cross_sig8_tailed_552_branch_63','sig7':'0000010c425425','prev':'none','next':'0D@552','members':{
        '0000010c42542563': {'body_prefix':'7e61','tail_sig8':'0000010d22f03100'},
    }},
    {'name':'cross_sig8_prevlink_0b295_branch_61_930c','sig7':'0000010c425425','prev':'0B@-295','next':'none','members':{
        '0000010c42542561': {'body_prefix':'930c'},
    }},
    {'name':'cross_sig8_prevlink_0b295_branch_61_f628','sig7':'0000010c425425','prev':'0B@-295','next':'none','members':{
        '0000010c42542561': {'body_prefix':'f628'},
    }},
    {'name':'cross_sig8_tailed_1188_branch_63_7ea0','sig7':'0000010c425425','prev':'none','next':'0D@1188','members':{
        '0000010c42542563': {'body_prefix':'7ea0','tail_sig8':'0000010d42486562'},
    }},
    {'name':'cross_sig8_tailed_1188_branch_63_7b2e','sig7':'0000010c425425','prev':'none','next':'0D@1188','members':{
        '0000010c42542563': {'body_prefix':'7b2e','tail_sig8':'0000010d424864cb'},
    }},
]

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def find_all_mm(mm: mmap.mmap, needle: bytes):
    out=[]; start=0
    while True:
        i=mm.find(needle,start)
        if i==-1: break
        out.append(i); start=i+1
    return out

def find_all(data: bytes, needle: bytes):
    out=[]; start=0
    while True:
        i=data.find(needle,start)
        if i==-1: break
        out.append(i); start=i+1
    return out

def nearest_markers(before: bytes, after: bytes, rec_len: int):
    rows=[]
    for rid, marker in RID_MARKERS.items():
        for off in find_all(before, marker):
            rows.append({'rid': rid, 'delta': off - len(before)})
        for off in find_all(after, marker):
            rows.append({'rid': rid, 'delta': rec_len + off})
    rows.sort(key=lambda r:r['delta'])
    prev_rows=[r for r in rows if r['delta'] < 0]
    next_rows=[r for r in rows if r['delta'] > 0]
    return prev_rows[-1] if prev_rows else None, next_rows[0] if next_rows else None

def score_bucket_match(hit, bucket):
    if not hit['sig8'].startswith(bucket['sig7']): return 0
    if hit['prev_key'] != bucket['prev'] or hit['next_key'] != bucket['next']: return 0
    expected=bucket['members'].get(hit['sig8'])
    if not expected: return 1
    score=2
    if expected.get('body_prefix'):
        if hit['body_prefix']==expected['body_prefix']: score=3
        else: return score
    if expected.get('tail_sig8'):
        if hit['tail_sig8']==expected['tail_sig8']: score=4
        else: return score
    return score

def required_score(bucket):
    member=next(iter(bucket['members'].values()))
    return 4 if member.get('tail_sig8') else 3

def assign_hits(all_hits, registry):
    framework=[]; quarantine=[]
    for hit in all_hits:
        best_bucket=None; best_score=0; best_required=99
        for bucket in registry:
            score=score_bucket_match(hit,bucket)
            req=required_score(bucket)
            if score > best_score or (score == best_score and req < best_required):
                best_bucket=bucket; best_score=score; best_required=req
        if best_bucket is not None and best_score >= best_required:
            framework.append(hit | {
                'bucket_name': best_bucket['name'],
                'source': best_bucket.get('source','manual'),
                'match_score': best_score,
                'required_score': best_required,
            })
        else:
            quarantine.append(hit | {
                'best_bucket_name': best_bucket['name'] if best_bucket else '',
                'best_score': best_score,
                'required_score': best_required if best_bucket else '',
            })
    return framework, quarantine

def branch_key(hit):
    if hit['next_key'].startswith('0D@'):
        return f"{hit['sig8']} | {hit['body_prefix']} | {hit['tail_sig8']}"
    return f"{hit['sig8']} | {hit['body_prefix']}"

def propose_name(prev_key: str, next_key: str, sig8: str, body_prefix: str) -> str:
    p=prev_key.replace('@','_').replace('-','m').replace('none','n')
    n=next_key.replace('@','_').replace('-','m').replace('none','n')
    return f'auto_{p}_{n}_{sig8[-2:]}_{body_prefix}'

def build_auto_rule(sig7: str, prev_key: str, next_key: str, hit: dict, count: int, source: str):
    member={hit['sig8']:{'body_prefix':hit['body_prefix'], **({'tail_sig8': hit['tail_sig8']} if hit['tail_sig8'] else {})}}
    return {'name': propose_name(prev_key,next_key,hit['sig8'],hit['body_prefix']),
            'sig7': sig7, 'prev': prev_key, 'next': next_key, 'members': member, 'count': count, 'source': source}

def bucket_key(bucket):
    return (bucket['prev'], bucket['next'])

def build_pure_quarantine_rules(quarantine_rows, sig7: str, min_count: int, skip_bucket_keys: set[tuple[str,str]], source='auto_pure_bucket'):
    bucket_hits=defaultdict(list)
    for hit in quarantine_rows:
        bucket_hits[(hit['prev_key'],hit['next_key'])].append(hit)
    rules=[]
    for (prev_key,next_key), hits in bucket_hits.items():
        if (prev_key,next_key) in skip_bucket_keys: continue
        branches=Counter(branch_key(h) for h in hits)
        if len(branches)==1 and len(hits) >= min_count:
            rules.append(build_auto_rule(sig7,prev_key,next_key,hits[0],len(hits),source))
    rules.sort(key=lambda r:(-r['count'],r['name']))
    return rules

def build_backbone_rules(quarantine_rows, sig7: str, min_count: int, source='auto_backbone'):
    backbone=[r for r in quarantine_rows if r['prev_key']=='none' and r['next_key']=='none']
    branch_counts=Counter((r['sig8'],r['body_prefix']) for r in backbone)
    rules=[]
    for (sig8,body_prefix), count in branch_counts.items():
        if count >= min_count:
            rules.append({'name': f'backbone_none_none_{sig8[-2:]}_{body_prefix}',
                          'sig7': sig7, 'prev': 'none', 'next': 'none',
                          'members': {sig8:{'body_prefix':body_prefix}},
                          'count': count, 'source': source})
    rules.sort(key=lambda r:(-r['count'],r['name']))
    return rules

def build_dominant_split_rules(quarantine_rows, sig7: str, min_count: int, min_dominance: float, exact_bucket_size: int | None, source: str):
    bucket_hits=defaultdict(list)
    for hit in quarantine_rows:
        bucket_hits[(hit['prev_key'], hit['next_key'])].append(hit)
    rules=[]; bucket_rows=[]
    for (prev_key,next_key), hits in bucket_hits.items():
        branches=Counter(branch_key(h) for h in hits)
        top_branch, top_count = branches.most_common(1)[0]
        dominance = top_count / len(hits)
        bucket_rows.append({
            'bucket': f'{prev_key} || {next_key}',
            'hits': len(hits),
            'unique_branches': len(branches),
            'top_branch': top_branch,
            'top_count': top_count,
            'dominance': round(dominance, 4),
        })
        cond_size = True if exact_bucket_size is None else (len(hits) == exact_bucket_size)
        if len(branches) >= 2 and top_count >= min_count and dominance >= min_dominance and cond_size:
            hit0 = next(h for h in hits if branch_key(h) == top_branch)
            rules.append(build_auto_rule(sig7, prev_key, next_key, hit0, top_count, source))
    rules.sort(key=lambda r:(-r['count'],r['name']))
    bucket_rows.sort(key=lambda r:(-r['hits'], r['unique_branches'], -r['dominance'], r['bucket']))
    return rules, bucket_rows

def write_csv(path: Path, rows: list[dict], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        w=csv.DictWriter(f, fieldnames=fieldnames); w.writeheader(); w.writerows(rows)

def main():
    ap=argparse.ArgumentParser(description='BX v134 rulepack-driven 425425 extractor')
    sub=ap.add_subparsers(dest='cmd', required=True)

    p=sub.add_parser('extract-425425-rulepack')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)
    p.add_argument('--min-pure-count', type=int, default=3)
    p.add_argument('--min-backbone-count', type=int, default=3)
    p.add_argument('--min-micro-pure-count', type=int, default=2)
    p.add_argument('--min-dominant-count', type=int, default=3)
    p.add_argument('--min-dominance', type=float, default=0.6)
    p.add_argument('--triad-min-dominant-count', type=int, default=2)
    p.add_argument('--triad-min-dominance', type=float, default=0.6666)
    p.add_argument('--triad-exact-bucket-size', type=int, default=3)
    p.add_argument('--micro-backbone-min-count', type=int, default=2)

    ns=ap.parse_args()
    if ns.cmd != 'extract-425425-rulepack':
        raise SystemExit(1)

    out_dir=Path(ns.out_dir); out_dir.mkdir(parents=True, exist_ok=True)

    # collect all hits under sig7
    all_hits=[]
    with Path(ns.tng_path).open('rb') as f:
        mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
        hits=find_all_mm(mm,RID0C_MARKER)
        for off in hits:
            if off + RECORD_LEN > mm.size(): continue
            rec=bytes(mm[off:off+RECORD_LEN])
            sig8=rec[:8].hex()
            if not sig8.startswith(ns.sig7): continue
            body=rec[8:]
            body_prefix=body[:ns.body_prefix_bytes].hex()
            before_start=max(0, off-ns.before)
            before=bytes(mm[before_start:off]); after=bytes(mm[off+RECORD_LEN: off+RECORD_LEN+ns.after])
            prev_nearest,next_nearest=nearest_markers(before,after,RECORD_LEN)
            prev_key=f'{prev_nearest["rid"]}@{prev_nearest["delta"]}' if prev_nearest else 'none'
            next_key=f'{next_nearest["rid"]}@{next_nearest["delta"]}' if next_nearest else 'none'
            tail_sig8=''
            if next_nearest and next_nearest['rid']=='0D':
                rel0=next_nearest['delta']-RECORD_LEN
                tail=after[rel0:rel0+TAIL_LEN]
                tail_sig8=tail[:8].hex() if len(tail)>=8 else ''
            all_hits.append({
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': md5(body),
                'body_prefix': body_prefix,
                'prev_key': prev_key,
                'next_key': next_key,
                'tail_sig8': tail_sig8,
            })
        mm.close()

    wave_rows=[]
    registry=BASE_BUCKET_REGISTRY[:]
    framework, quarantine = assign_hits(all_hits, registry)
    wave_rows.append({'wave':'manual_base','rules_added':len(BASE_BUCKET_REGISTRY),'assigned_hits':len(framework),'quarantine_hits':len(quarantine)})

    covered_bucket_keys=set(bucket_key(b) for b in registry)
    auto_pure_rules=build_pure_quarantine_rules(quarantine, ns.sig7, ns.min_pure_count, covered_bucket_keys, 'auto_pure_bucket')
    registry += auto_pure_rules
    framework, quarantine = assign_hits(all_hits, registry)
    wave_rows.append({'wave':'auto_pure','rules_added':len(auto_pure_rules),'assigned_hits':len(framework),'quarantine_hits':len(quarantine)})

    auto_backbone_rules=build_backbone_rules(quarantine, ns.sig7, ns.min_backbone_count, 'auto_backbone')
    registry += auto_backbone_rules
    framework, quarantine = assign_hits(all_hits, registry)
    wave_rows.append({'wave':'auto_backbone','rules_added':len(auto_backbone_rules),'assigned_hits':len(framework),'quarantine_hits':len(quarantine)})

    covered_after_backbone=set(bucket_key(b) for b in registry)
    micro_pure_rules=build_pure_quarantine_rules(quarantine, ns.sig7, ns.min_micro_pure_count, covered_after_backbone, 'secondary_micro_pure')
    registry += micro_pure_rules
    framework, quarantine = assign_hits(all_hits, registry)
    wave_rows.append({'wave':'micro_pure','rules_added':len(micro_pure_rules),'assigned_hits':len(framework),'quarantine_hits':len(quarantine)})

    dominant_rules,_=build_dominant_split_rules(quarantine, ns.sig7, ns.min_dominant_count, ns.min_dominance, None, 'auto_dominant_split')
    registry += dominant_rules
    framework, quarantine = assign_hits(all_hits, registry)
    wave_rows.append({'wave':'primary_dominant','rules_added':len(dominant_rules),'assigned_hits':len(framework),'quarantine_hits':len(quarantine)})

    triad_rules,_=build_dominant_split_rules(quarantine, ns.sig7, ns.triad_min_dominant_count, ns.triad_min_dominance, ns.triad_exact_bucket_size, 'triad_dominant_wave')
    registry += triad_rules
    framework, quarantine = assign_hits(all_hits, registry)
    wave_rows.append({'wave':'triad_dominant','rules_added':len(triad_rules),'assigned_hits':len(framework),'quarantine_hits':len(quarantine)})

    micro_backbone_rules=build_backbone_rules(quarantine, ns.sig7, ns.micro_backbone_min_count, 'micro_backbone')
    registry += micro_backbone_rules
    framework, quarantine = assign_hits(all_hits, registry)
    wave_rows.append({'wave':'micro_backbone','rules_added':len(micro_backbone_rules),'assigned_hits':len(framework),'quarantine_hits':len(quarantine)})

    # Final outputs
    write_csv(out_dir/'wave_progress.csv', wave_rows, ['wave','rules_added','assigned_hits','quarantine_hits'])
    write_csv(out_dir/'clean_bucket_framework_manifest.csv', framework,
              ['bucket_name','off_hex','sig8','body_md5','body_prefix','prev_key','next_key','tail_sig8','source','match_score','required_score'])
    write_csv(out_dir/'quarantine'/'quarantine_manifest.csv', quarantine,
              ['off_hex','sig8','body_md5','body_prefix','prev_key','next_key','tail_sig8','best_bucket_name','best_score','required_score'])

    # Registry and source split
    with (out_dir/'bucket_registry.json').open('w', encoding='utf-8') as f:
        json.dump(registry, f, indent=2)

    registry_by_source=defaultdict(list)
    for r in registry:
        registry_by_source[r.get('source','manual')].append(r)
    with (out_dir/'registry_by_source.json').open('w', encoding='utf-8') as f:
        json.dump(registry_by_source, f, indent=2)

    # Covered counts by source and by bucket
    covered_by_source=Counter(r['source'] for r in framework)
    covered_by_bucket=Counter(r['bucket_name'] for r in framework)
    write_csv(out_dir/'covered_by_source.csv',
              [{'source':k,'hits':v} for k,v in covered_by_source.most_common()],
              ['source','hits'])
    write_csv(out_dir/'covered_by_bucket.csv',
              [{'bucket_name':k,'hits':v} for k,v in covered_by_bucket.most_common()],
              ['bucket_name','hits'])

    # Residual frontier summary
    q_bucket_counts=Counter(f'{r["prev_key"]} || {r["next_key"]}' for r in quarantine)
    write_csv(out_dir/'residual_frontier.csv',
              [{'bucket':k,'hits':v} for k,v in q_bucket_counts.most_common()],
              ['bucket','hits'])

    summary=[]
    summary.append('BX v134 rulepack-driven 425425 extractor')
    summary.append('======================================')
    summary.append(f'total_hits_under_sig7: {len(all_hits)}')
    summary.append(f'final_assigned_hits: {len(framework)}')
    summary.append(f'final_quarantine_hits: {len(quarantine)}')
    summary.append(f'coverage_ratio: {len(framework)}/{len(all_hits)} = {len(framework)/len(all_hits):.4f}')
    summary.append(f'total_rules_in_rulepack: {len(registry)}')
    summary.append('')
    summary.append('Wave progress:')
    for row in wave_rows:
        summary.append(
            f'  {row["wave"]}: rules+={row["rules_added"]} assigned={row["assigned_hits"]} quarantine={row["quarantine_hits"]}'
        )
    summary.append('')
    summary.append('Covered by source:')
    for k,v in covered_by_source.most_common():
        summary.append(f'  {k} :: {v}')
    summary.append('')
    summary.append('Top residual frontier buckets:')
    for k,v in q_bucket_counts.most_common(30):
        summary.append(f'  {k} :: {v}')
    (out_dir/'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir/'meta.json').write_text(json.dumps({
        'total_hits_under_sig7': len(all_hits),
        'final_assigned_hits': len(framework),
        'final_quarantine_hits': len(quarantine),
        'coverage_ratio': len(framework)/len(all_hits),
        'total_rules_in_rulepack': len(registry),
    }, indent=2), encoding='utf-8')

if __name__=='__main__':
    main()
