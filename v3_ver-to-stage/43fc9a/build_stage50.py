#!/usr/bin/env python3
from pathlib import Path
import pandas as pd, zipfile, io, mmap, struct, hashlib, os, shutil, subprocess, csv, json

TNG = Path('/mnt/data/TNG.000')
ZIP = Path('/mnt/data/protocol-reversing.zip')
OUT = Path('/mnt/data/stage50_bundle')
MANI = OUT/'manifests'
EX = OUT/'exemplars'
CS = OUT/'contact_sheets'
for d in [OUT, MANI, EX, CS]: d.mkdir(parents=True, exist_ok=True)
PRE = 0x20000
WIN = 0x2C0000

# Load prior context
zf = zipfile.ZipFile(ZIP)
stage24_hits = pd.read_csv(io.BytesIO(zf.read('43fc9a/manifests/43fc9a_stage24_domain_hits.csv')))
stage24_exports = pd.read_csv(io.BytesIO(zf.read('43fc9a/manifests/43fc9a_stage24_candidate_exports.csv')))
stage24_hints = pd.read_csv(io.BytesIO(zf.read('43fc9a/manifests/43fc9a_stage24_family_hint_matches.csv')))
stage49q = pd.read_csv('/mnt/data/stage49_bundle/manifests/stage49_next_ambiguity_queue.csv')

# Manual derivation rules after visual review + stage24 evidence
rules = [
    dict(sig8='0000010c43fc9ae9', body_prefix='71d0', matched_field='pos020', field_offset=0x20, match_mode='exact_value', match_value=162754444,
         content_class='track_menu_preview', family_id='track_menu_preview_family_01', confidence='medium_high', status='soft_clean',
         semantic_label='audio-backed track/menu preview candidate', source_candidate='43fc9a_stage24_rank02_pos020_09B16F8C_09DD6F8C.pss', rationale='audio_present|mpeg1video|sane_duration|visual_sheet_unreliable'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos024', field_offset=0x24, match_mode='exact_value', match_value=925218112,
         content_class='track_menu_preview', family_id='track_menu_preview_family_01', confidence='high', status='clean',
         semantic_label='Fujitsu Siemens track/menu preview', source_candidate='fujitsu-NORM-43fc9a_stage24_rank03_pos024_3723B540_374FB540.pss', rationale='visual_confirmed|single_car_sponsor_backdrop'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos024', field_offset=0x24, match_mode='exact_value', match_value=886042620,
         content_class='challenge_preview', family_id='challenge_preview_family_misc', confidence='high', status='clean',
         semantic_label='challenge preview two-car backdrop', source_candidate='challenge-NORM-43fc9a_stage24_rank06_pos024_34CDEFFC_34F9EFFC.pss', rationale='visual_confirmed|two_cars_background|challenge_taxonomy'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='value_set', match_value='4461302;115344352;33030392',
         content_class='track_menu_preview', family_id='track_menu_preview_family_01', confidence='medium', status='evidence',
         semantic_label='degraded track/menu preview window', source_candidate='43fc9a_stage24_rank04/05/07_pos094_series', rationale='mpeg2video|sane_duration|mostly_black_or_degraded_contact_sheets'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos0a4', field_offset=0xA4, match_mode='exact_value', match_value=85835445,
         content_class='track_menu_preview', family_id='track_menu_preview_family_01', confidence='medium', status='evidence',
         semantic_label='audio-backed degraded preview candidate', source_candidate='43fc9a_stage24_rank01_pos0a4_051BBEB5_0547BEB5.pss', rationale='audio_present|mpeg2video|mostly_black_sheet')
]
rule_df = pd.DataFrame(rules)
rule_df.to_csv(MANI/'stage50_field_derivation_rules_43fc9a.csv', index=False)

# Live scan for sig8 43fc9ae9 only
marker = b'\x00\x00\x01\x0c\x43\xfc\x9a\xe9'
rows=[]
with open(TNG,'rb') as f:
    mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    pos=0
    while True:
        idx=mm.find(marker,pos)
        if idx==-1: break
        bp = mm[idx+8:idx+10].hex()
        rec = {'record_offset': idx, 'sig8':'0000010c43fc9ae9', 'body_prefix': bp,
               'pos020': struct.unpack_from('<I',mm,idx+0x20)[0],
               'pos024': struct.unpack_from('<I',mm,idx+0x24)[0],
               'pos094': struct.unpack_from('<I',mm,idx+0x94)[0],
               'pos0a4': struct.unpack_from('<I',mm,idx+0xA4)[0]}
        rows.append(rec)
        pos=idx+1
    mm.close()
live = pd.DataFrame(rows).sort_values(['body_prefix','record_offset'])
live.to_csv(MANI/'stage50_live_43fc9a_hits.csv', index=False)

# Apply rules, possibly multiple per record
status_rank = {'clean':4,'soft_clean':3,'evidence':2,'rejected':1,'unresolved':0}
routed=[]
for _, rec in live.iterrows():
    matched_any=False
    for _, rule in rule_df.iterrows():
        if rec['body_prefix'] != rule['body_prefix']: continue
        val = int(rec[rule['matched_field']])
        ok=False
        if rule['match_mode']=='exact_value':
            ok = val == int(rule['match_value'])
        elif rule['match_mode']=='value_set':
            ok = str(val) in set(str(rule['match_value']).split(';'))
        if not ok: continue
        start = max(0, val - PRE)
        end = min(TNG.stat().st_size, start + WIN)
        window_state = 'routable' if end - start == WIN else 'truncated_or_oob'
        routed.append({
            'record_offset': int(rec['record_offset']), 'sig8': rec['sig8'], 'body_prefix': rec['body_prefix'],
            'matched_field': rule['matched_field'], 'field_value': val, 'window_start': start, 'window_end': end,
            'window_state': window_state, 'status': rule['status'], 'content_class': rule['content_class'],
            'family_id': rule['family_id'], 'confidence': rule['confidence'], 'semantic_label': rule['semantic_label'],
            'source_candidate': rule['source_candidate'], 'rationale': rule['rationale']
        })
        matched_any=True
    if not matched_any:
        routed.append({
            'record_offset': int(rec['record_offset']), 'sig8': rec['sig8'], 'body_prefix': rec['body_prefix'],
            'matched_field': '', 'field_value': '', 'window_start': '', 'window_end': '', 'window_state': 'unresolved',
            'status': 'unresolved', 'content_class': 'unresolved', 'family_id': 'unresolved', 'confidence': 'none',
            'semantic_label': 'unresolved_43fc9a', 'source_candidate': '', 'rationale': 'no_stage50_rule_match'
        })

routed_df = pd.DataFrame(routed)
routed_df.to_csv(MANI/'stage50_routed_candidates.csv', index=False)

# Primary route per record
primary=[]
for off, grp in routed_df.groupby('record_offset', sort=True):
    g=grp.copy()
    g['rank']=g['status'].map(status_rank).fillna(0)
    g=g.sort_values(['rank','confidence','window_state'], ascending=[False,False,True])
    primary.append(g.iloc[0].drop(labels=['rank'], errors='ignore'))
primary_df = pd.DataFrame(primary)
primary_df.to_csv(MANI/'stage50_record_level_primary_routes.csv', index=False)

# Summaries
summary = primary_df.groupby(['body_prefix','status','content_class','family_id'], dropna=False).size().reset_index(name='record_count')
summary.to_csv(MANI/'stage50_route_status_summary.csv', index=False)

# Unresolved cluster summaries
unresolved = live.merge(primary_df[['record_offset','status']], on='record_offset', how='left')
unresolved = unresolved[unresolved['status']=='unresolved'].copy()
clusters=[]
for bp, g in unresolved.groupby('body_prefix'):
    for fld in ['pos020','pos024','pos094','pos0a4']:
        vc=g[fld].value_counts().head(20)
        for val,cnt in vc.items():
            clusters.append({'body_prefix':bp,'field':fld,'value_u32':int(val),'count':int(cnt)})
clusters_df = pd.DataFrame(clusters).sort_values(['body_prefix','count','field'], ascending=[True,False,True])
clusters_df.to_csv(MANI/'stage50_unresolved_value_clusters.csv', index=False)

# Exemplar carve/export for rules (unique windows)
with open(TNG,'rb') as f:
    for _, row in routed_df[(routed_df['window_state']=='routable') & (routed_df['status']!='unresolved')].drop_duplicates(['window_start','window_end','semantic_label']).iterrows():
        ws,we = int(row['window_start']), int(row['window_end'])
        label = row['semantic_label'].lower().replace(' ','_').replace('/','_').replace('-','_')
        base = f"43fc9a_{row['body_prefix']}_{row['matched_field']}_{label}_{ws:08X}_{we:08X}"
        outpss = EX/f'{base}.pss'
        f.seek(ws)
        data=f.read(we-ws)
        outpss.write_bytes(data)
        # contact sheet best-effort
        outpng = CS/f'{base}.png'
        cmd = ['ffmpeg','-y','-fflags','+genpts','-i',str(outpss),'-an','-vf',"select='not(mod(n,40))',scale=320:-1,tile=4x3",'-frames:v','1',str(outpng)]
        rr = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rr.returncode != 0 or (not outpng.exists()) or outpng.stat().st_size==0:
            if outpng.exists(): outpng.unlink()

# exemplar catalog
exrows=[]
for pss in sorted(EX.glob('*.pss')):
    name=pss.name
    png = CS/(pss.stem + '.png')
    ff = subprocess.run(['ffprobe','-v','error','-show_streams','-show_format','-of','json',str(pss)], capture_output=True, text=True)
    duration=''; codecs=''; streams=0
    if ff.returncode==0 and ff.stdout.strip().startswith('{'):
        data=json.loads(ff.stdout)
        duration=data.get('format',{}).get('duration','')
        codecs=','.join([s.get('codec_name','') for s in data.get('streams',[])])
        streams=len(data.get('streams',[]))
    exrows.append({'file':name,'contact_sheet':png.name if png.exists() else '', 'size_bytes':pss.stat().st_size,'duration':duration,'codecs':codecs,'streams':streams})
pd.DataFrame(exrows).to_csv(MANI/'stage50_exemplar_catalog.csv', index=False)

# integrity
sha=hashlib.sha256(TNG.read_bytes()).hexdigest().upper()
pd.DataFrame([{'file':'TNG.000','size_bytes':TNG.stat().st_size,'sha256':sha}]).to_csv(MANI/'stage50_tng_integrity_check.csv', index=False)

# report
clean_count=int((primary_df['status']=='clean').sum())
soft_count=int((primary_df['status']=='soft_clean').sum())
ev_count=int((primary_df['status']=='evidence').sum())
un_count=int((primary_df['status']=='unresolved').sum())

report=f'''Stage 50: field-aware derivation pass for 43fc9a

Objective
- resolve Stage49 ambiguity on pair 0000010c43fc9ae9 + 7321
- validate 43fc9a against live canonical TNG.000
- promote field/value-derived routes where evidence is strong enough

Canonical TNG
- size: {TNG.stat().st_size}
- sha256: {sha}

Live 43fc9a hits
- total hits: {len(live)}
- body_prefix 7321: {int((live.body_prefix=='7321').sum())}
- body_prefix 71d0: {int((live.body_prefix=='71d0').sum())}

Derived routing outcome (record-level primary)
- clean: {clean_count}
- soft_clean: {soft_count}
- evidence: {ev_count}
- unresolved: {un_count}

Key derivations
1. body_prefix 71d0 is no longer pair-only ambiguous in practice: pos020 @ 0x09B16F8C yields a stable audio-backed track/menu preview candidate. Promoted as soft_clean.
2. body_prefix 7321 cannot be solved by pair-only routing. pos024 splits into at least two visually distinct semantic branches:
   - 0x3723B540 -> Fujitsu Siemens track/menu preview
   - 0x34CDEFFC -> challenge preview with two-car backdrop
3. body_prefix 7321 pos094 series remains video-valid but visually degraded/mostly black in current sheets. Kept as evidence, not promoted.
4. body_prefix 7321 pos0a4 remains audio-backed/video-valid but visually degraded. Kept as evidence.

Practical conclusion
- Stage50 partially resolves 43fc9a, but also proves that field-aware routing alone is insufficient for the whole 7321 branch.
- The decisive next step is value-cluster routing for 43fc9a pos024 / pos094 / pos0a4, not another domain scout.

Recommended next stage
- Stage 51: 43fc9a value-cluster routing pass
'''
(OUT/'stage50_report.md').write_text(report, encoding='utf-8')

# build script copy
shutil.copy2('/mnt/data/build_stage50_temp.py', OUT/'build_stage50.py')
print('Stage50 built at', OUT)
