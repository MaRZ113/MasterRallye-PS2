#!/usr/bin/env python3
from pathlib import Path
import pandas as pd, zipfile, io, mmap, struct, hashlib, shutil, subprocess, json

TNG = Path('/mnt/data/TNG.000')
ZIP = Path('/mnt/data/protocol-reversing.zip')
OUT = Path('/mnt/data/stage51_bundle')
MANI = OUT/'manifests'
EX = OUT/'exemplars'
CS = OUT/'contact_sheets'
SRC = Path('/mnt/data/stage51_probe')
for d in [OUT, MANI, EX, CS]: d.mkdir(parents=True, exist_ok=True)
PRE = 0x20000
WIN = 0x2C0000
TNG_SIZE = TNG.stat().st_size

# Load stage50 context
rule50 = pd.read_csv('/mnt/data/stage50_bundle/manifests/stage50_field_derivation_rules_43fc9a.csv')
live = pd.read_csv('/mnt/data/stage50_bundle/manifests/stage50_live_43fc9a_hits.csv')
primary50 = pd.read_csv('/mnt/data/stage50_bundle/manifests/stage50_record_level_primary_routes.csv')
unresolved_clusters = pd.read_csv('/mnt/data/stage50_bundle/manifests/stage50_unresolved_value_clusters.csv')
probe = pd.read_csv(SRC/'probe_summary.csv')
probe['key'] = probe['field'].astype(str) + '|' + probe['value_u32'].astype(str)
probe_map = {k:r for k,r in probe.set_index('key').to_dict(orient='index').items()}

# Stage51 new rules
new_rules = []
# 1) exact value cluster promotions / dispositions from plausible unresolved probes
new_rules += [
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos024', field_offset=0x24, match_mode='exact_value', match_value=876598009,
         content_class='challenge_preview', family_id='challenge_preview_family_misc', confidence='medium_high', status='soft_clean',
         semantic_label='Elf multi-vehicle challenge preview', source_candidate='43fc9a_pos024_343FD2F9_343DD2F9_3469D2F9_c4.pss',
         rationale='visual_confirmed|elf_branding|multi_vehicle_backdrop|duration_missing_but_sheet_clear'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos024', field_offset=0x24, match_mode='exact_value', match_value=939042206,
         content_class='track_flythrough_preview', family_id='track_flythrough_family_01', confidence='medium', status='soft_clean',
         semantic_label='GO-overlay track flythrough preview', source_candidate='43fc9a_pos024_37F8A59E_37F6A59E_3822A59E_c3.pss',
         rationale='visual_confirmed|go_overlay|course_flythrough|new_family_candidate'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos024', field_offset=0x24, match_mode='exact_value', match_value=70811129,
         content_class='nonstandard', family_id='reject_nonstandard_family', confidence='medium', status='rejected',
         semantic_label='corrupt or false-positive preview window', source_candidate='43fc9a_pos024_04387DF9_04367DF9_04627DF9_c3.pss',
         rationale='weird_duration|mostly_black_sheet|false_positive_like'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos020', field_offset=0x20, match_mode='exact_value', match_value=632995377,
         content_class='nonvideo', family_id='reject_nonvideo_family', confidence='medium', status='rejected',
         semantic_label='non-video candidate window', source_candidate='43fc9a_pos020_25BABE31_25B8BE31_25E4BE31_c4.pss',
         rationale='ffprobe_failed|no_video_signature'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=63968575,
         content_class='nonstandard', family_id='reject_nonstandard_family', confidence='medium', status='rejected',
         semantic_label='weird mixed-stream candidate', source_candidate='43fc9a_pos094_03CFEDBF_03CDEDBF_03F9EDBF_c3.pss',
         rationale='mpeg1video+mp2_or_mp3_like|weird_duration|sheet_failed'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=4472320,
         content_class='degraded_video', family_id='reject_black_video_family', confidence='medium', status='rejected',
         semantic_label='black/degraded video window', source_candidate='43fc9a_pos094_00443E00_00423E00_006E3E00_c3.pss',
         rationale='video_valid_but_black_sheet'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=546484295,
         content_class='degraded_video', family_id='reject_black_video_family', confidence='medium', status='rejected',
         semantic_label='black/degraded video window', source_candidate='43fc9a_pos094_2092B047_2090B047_20BCB047_c3.pss',
         rationale='mpeg2video+audio|black_or_garbled_sheet'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=520101760,
         content_class='degraded_video', family_id='reject_black_video_family', confidence='medium', status='rejected',
         semantic_label='black/degraded video window', source_candidate='43fc9a_pos094_1F001F80_1EFE1F80_1F2A1F80_c3.pss',
         rationale='mpeg2video_valid|black_sheet'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=2231164,
         content_class='degraded_video', family_id='reject_black_video_family', confidence='medium', status='rejected',
         semantic_label='truncated or black video window', source_candidate='43fc9a_pos094_00220B7C_00200B7C_004C0B7C_c3.pss',
         rationale='mpeg2video_valid|no_duration|black_sheet'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=571046676,
         content_class='nonstandard', family_id='reject_nonstandard_family', confidence='medium', status='rejected',
         semantic_label='weird-duration flythrough false positive', source_candidate='43fc9a_pos094_22097B14_22077B14_22337B14_c3.pss',
         rationale='huge_duration|sheet_unreliable'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=9536529,
         content_class='audio_only', family_id='reject_audio_only_family', confidence='medium', status='rejected',
         semantic_label='audio-only candidate', source_candidate='43fc9a_pos094_009183F1_008F83F1_00BB83F1_c3.pss',
         rationale='mp3_only|no_video'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos094', field_offset=0x94, match_mode='exact_value', match_value=12247559,
         content_class='audio_only', family_id='reject_audio_only_family', confidence='medium', status='rejected',
         semantic_label='audio-only candidate', source_candidate='43fc9a_pos094_00BAD047_00B8D047_00E4D047_c3.pss',
         rationale='mp3_only|no_video'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos0a4', field_offset=0xA4, match_mode='exact_value', match_value=1156816569,
         content_class='nonvideo', family_id='reject_nonvideo_family', confidence='medium', status='rejected',
         semantic_label='non-video candidate window', source_candidate='43fc9a_pos0a4_44F4A559_44F2A559_451EA559_c3.pss',
         rationale='ffprobe_failed|no_video_signature'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos0a4', field_offset=0xA4, match_mode='exact_value', match_value=773127104,
         content_class='nonvideo', family_id='reject_nonvideo_family', confidence='medium', status='rejected',
         semantic_label='non-video candidate window', source_candidate='43fc9a_pos0a4_2E1486C0_2E1286C0_2E3E86C0_c3.pss',
         rationale='ffprobe_failed|no_video_signature'),
    dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field='pos0a4', field_offset=0xA4, match_mode='exact_value', match_value=361560150,
         content_class='nonvideo', family_id='reject_nonvideo_family', confidence='medium', status='rejected',
         semantic_label='non-video candidate window', source_candidate='43fc9a_pos0a4_158DB156_158BB156_15B7B156_c3.pss',
         rationale='ffprobe_failed|no_video_signature'),
]

# 2) deferred_oob exact rules for repeated unresolved values count>=3 where value cannot form an in-bounds window
uc = unresolved_clusters[(unresolved_clusters['body_prefix']==7321) & (unresolved_clusters['count']>=3)].copy()
uc['window_ok'] = uc['value_u32'].apply(lambda v: (max(0,int(v)-PRE)+WIN) <= TNG_SIZE)
for _, r in uc[~uc['window_ok']].iterrows():
    field=r['field']
    field_offset={'pos020':0x20,'pos024':0x24,'pos094':0x94,'pos0a4':0xA4}[field]
    new_rules.append(dict(sig8='0000010c43fc9ae9', body_prefix='7321', matched_field=field, field_offset=field_offset, match_mode='exact_value', match_value=int(r['value_u32']),
        content_class='deferred_oob', family_id='deferred_oob_43fc9a', confidence='medium', status='deferred_oob',
        semantic_label=f'deferred out-of-bounds value cluster {field}', source_candidate=f'value_cluster_{field}_{int(r.value_u32):08X}',
        rationale='value_cluster_above_tng_size_or_truncated_window|needs_future_relative_or_transformed_interpretation'))

rule51_new = pd.DataFrame(new_rules)
rule_catalog = pd.concat([rule50, rule51_new], ignore_index=True)
rule_catalog.to_csv(MANI/'stage51_value_cluster_rule_catalog.csv', index=False)

# route function
status_rank = {'clean':5,'soft_clean':4,'evidence':3,'deferred_oob':2,'rejected':1,'unresolved':0}
routed=[]
for _, rec in live.iterrows():
    rec_rules=[]
    for _, rule in rule_catalog.iterrows():
        if rec['body_prefix'] != rule['body_prefix']:
            continue
        field=rule['matched_field']
        val = int(rec[field])
        ok=False
        if rule['match_mode']=='exact_value':
            ok = val == int(rule['match_value'])
        elif rule['match_mode']=='value_set':
            ok = str(val) in set(str(rule['match_value']).split(';'))
        if not ok:
            continue
        start = max(0, val - PRE)
        end = min(TNG_SIZE, start + WIN)
        window_state = 'routable' if end - start == WIN else 'truncated_or_oob'
        routed.append({
            'record_offset': int(rec['record_offset']), 'sig8': rec['sig8'], 'body_prefix': rec['body_prefix'],
            'matched_field': field, 'field_value': val, 'window_start': start, 'window_end': end,
            'window_state': window_state, 'status': rule['status'], 'content_class': rule['content_class'],
            'family_id': rule['family_id'], 'confidence': rule['confidence'], 'semantic_label': rule['semantic_label'],
            'source_candidate': rule['source_candidate'], 'rationale': rule['rationale']
        })
        rec_rules.append(True)
    if not rec_rules:
        routed.append({
            'record_offset': int(rec['record_offset']), 'sig8': rec['sig8'], 'body_prefix': rec['body_prefix'],
            'matched_field': '', 'field_value': '', 'window_start': '', 'window_end': '', 'window_state': 'unresolved',
            'status': 'unresolved', 'content_class': 'unresolved', 'family_id': 'unresolved', 'confidence': 'none',
            'semantic_label': 'unresolved_43fc9a', 'source_candidate': '', 'rationale': 'no_stage51_rule_match'
        })

routed_df = pd.DataFrame(routed)
routed_df.to_csv(MANI/'stage51_routed_candidates.csv', index=False)

primary=[]
for off, grp in routed_df.groupby('record_offset', sort=True):
    g=grp.copy()
    g['rank']=g['status'].map(status_rank).fillna(0)
    # prefer routable over oob/truncated within same rank
    g['window_pref']=g['window_state'].map({'routable':1,'truncated_or_oob':0,'unresolved':0}).fillna(0)
    g=g.sort_values(['rank','window_pref'], ascending=[False,False])
    primary.append(g.iloc[0].drop(labels=['rank','window_pref'], errors='ignore'))
primary_df = pd.DataFrame(primary)
primary_df.to_csv(MANI/'stage51_record_level_primary_routes.csv', index=False)

# summaries
status_summary = primary_df.groupby(['body_prefix','status','content_class','family_id'], dropna=False).size().reset_index(name='record_count')
status_summary.to_csv(MANI/'stage51_route_status_summary.csv', index=False)

# remaining unresolved clusters
remaining = live.merge(primary_df[['record_offset','status']], on='record_offset', how='left')
remaining = remaining[remaining['status']=='unresolved'].copy()
rem_clusters=[]
for bp, g in remaining.groupby('body_prefix'):
    for fld in ['pos020','pos024','pos094','pos0a4']:
        vc=g[fld].value_counts().head(20)
        for val,cnt in vc.items():
            rem_clusters.append({'body_prefix':bp,'field':fld,'value_u32':int(val),'count':int(cnt)})
rem_df = pd.DataFrame(rem_clusters)
if len(rem_df):
    rem_df.to_csv(MANI/'stage51_remaining_unresolved_clusters.csv', index=False)
else:
    pd.DataFrame(columns=['body_prefix','field','value_u32','count']).to_csv(MANI/'stage51_remaining_unresolved_clusters.csv', index=False)

# OOB deferred catalog
oob_catalog = rule51_new[rule51_new['status']=='deferred_oob'][['matched_field','match_value','semantic_label','rationale']].copy()
oob_catalog.to_csv(MANI/'stage51_deferred_oob_catalog.csv', index=False)

# probe derivation catalog
probe_rows=[]
for _, r in probe.iterrows():
    disp='unclassified'
    if int(r['value_u32'])==876598009 and r['field']=='pos024': disp='soft_clean_challenge_preview'
    elif int(r['value_u32'])==939042206 and r['field']=='pos024': disp='soft_clean_track_flythrough_preview'
    elif int(r['value_u32'])==70811129 and r['field']=='pos024': disp='rejected_false_positive'
    elif int(r['value_u32']) in [63968575,4472320,546484295,520101760,2231164,571046676,9536529,12247559] and r['field']=='pos094': disp='rejected_nonstable_pos094_cluster'
    elif int(r['value_u32']) in [632995377] and r['field']=='pos020': disp='rejected_no_video'
    elif int(r['value_u32']) in [1156816569,773127104,361560150] and r['field']=='pos0a4': disp='rejected_no_video'
    probe_rows.append({**r, 'derived_disposition':disp})
probe_catalog = pd.DataFrame(probe_rows)
probe_catalog.to_csv(MANI/'stage51_probe_derivation_catalog.csv', index=False)

# exemplar export for new routable non-rejected rules
copied=[]
for _, row in rule51_new[rule51_new['status'].isin(['soft_clean','clean','evidence'])].iterrows():
    val=int(row['match_value']) if str(row['match_mode'])=='exact_value' else None
    if val is None:
        continue
    key=f"{row['matched_field']}|{val}"
    pr = probe_map.get(key)
    if not pr:
        continue
    stem = f"43fc9a_{row['matched_field']}_{val:08X}_{int(pr['start']):08X}_{int(pr['end']):08X}_c{int(pr['count'])}"
    pss = SRC/f'{stem}.pss'
    png = SRC/f'{stem}.png'
    if pss.exists(): shutil.copy2(pss, EX/pss.name)
    if png.exists(): shutil.copy2(png, CS/png.name)
    copied.append({'file':pss.name if pss.exists() else '', 'contact_sheet':png.name if png.exists() else '', 'status':row['status'], 'semantic_label':row['semantic_label'], 'family_id':row['family_id'], 'matched_field':row['matched_field'], 'value_u32':val})
pd.DataFrame(copied).to_csv(MANI/'stage51_exemplar_catalog.csv', index=False)

# integrity
sha=hashlib.sha256(TNG.read_bytes()).hexdigest().upper()
pd.DataFrame([{'file':'TNG.000','size_bytes':TNG_SIZE,'sha256':sha}]).to_csv(MANI/'stage51_tng_integrity_check.csv', index=False)

# Report
sum50 = primary50['status'].value_counts().to_dict()
sum51 = primary_df['status'].value_counts().to_dict()
report=f'''Stage 51: 43fc9a value-cluster routing pass

Objective
- continue Stage 50 by resolving 43fc9ae9|7321 not only by field, but by exact repeated value clusters
- separate stable new preview families from false positives, black/degraded windows, and out-of-bounds clusters

Canonical TNG
- size: {TNG_SIZE}
- sha256: {sha}

Live domain scope
- total 43fc9a hits: {len(live)}
- body_prefix 71d0: {int((live.body_prefix=='71d0').sum())}
- body_prefix 7321: {int((live.body_prefix=='7321').sum())}

Key Stage 51 findings
1. pos024 contains at least two additional stable value-cluster outcomes beyond Stage 50:
   - 0x343FD2F9 (876598009) -> Elf multi-vehicle challenge preview (soft_clean)
   - 0x37F8A59E (939042206) -> GO-overlay track flythrough preview (soft_clean, new family)
2. pos024 also contains a corrupt/false-positive cluster:
   - 0x04387DF9 (70811129) -> rejected
3. Several plausible pos094 clusters are not useful expansions: they are either black/degraded windows, audio-only, or weird-duration false positives. These are now routed as rejected instead of remaining unresolved.
4. A large share of the remaining unresolved mass is actually repeated out-of-bounds value clusters. These are now explicitly marked as deferred_oob instead of being conflated with truly unknown in-bounds candidates.

Record-level primary-route comparison
- Stage 50: {sum50}
- Stage 51: {sum51}

Practical conclusion
- Stage 51 materially reduces ambiguity for 43fc9a by splitting unresolved mass into three honest bins:
  (a) newly routable soft-clean value clusters,
  (b) rejected nonstable/no-video/black clusters,
  (c) deferred out-of-bounds clusters that may need future relative or transformed interpretation.
- The next best step is no longer another blind value pass across all fields; it is a focused follow-up on the new track_flythrough family and on deferred_oob normalization logic.

Recommended next stage
- Stage 52: deferred-oob normalization + track_flythrough family validation pass
'''
(OUT/'stage51_report.md').write_text(report, encoding='utf-8')

# build script copy
shutil.copy2('/mnt/data/build_stage51_temp.py', OUT/'build_stage51.py')
print('Stage51 built at', OUT)
print(status_summary.to_string())
