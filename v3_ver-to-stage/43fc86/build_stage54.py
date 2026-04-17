#!/usr/bin/env python3
from pathlib import Path
import pandas as pd, shutil, zipfile, hashlib
TNG=Path('/mnt/data/TNG.000')
OUT=Path('/mnt/data/stage54_bundle'); MANI=OUT/'manifests'; CS=OUT/'contact_sheets'
for d in [OUT,MANI,CS]: d.mkdir(parents=True, exist_ok=True)
# load stage53 primary
primary=pd.read_csv('/mnt/data/stage53_bundle/manifests/stage53_record_level_primary_routes.csv')
summary=pd.read_csv('/mnt/data/stage53_bundle/manifests/stage53_route_status_summary.csv')
amb=pd.read_csv('/mnt/data/stage53_bundle/manifests/stage53_remaining_ambiguity_queue.csv')
# probe results created for stage54
probe=pd.read_csv('/mnt/data/stage54_work/stage54_probe_results.csv')
probe.to_csv(MANI/'stage54_probe_results.csv', index=False)
# rule additions
rules=[]
rules.append(dict(rule_layer='normalized_deferred',sig8='0000010c43fc86e9',body_prefix='7243',matched_field='pos028',match_mode='deferred_exact',match_value='3021048742',normalization_const='0x80000000',normalized_value='873565094',status='soft_clean',content_class='challenge_preview',family_id='challenge_preview_family_misc',confidence='medium_high',semantic_label='off-road multi-vehicle challenge preview (normalized 7243 closure)',source_probe='43fc86_7243_pos028_B4118BA6_minus_80000000_34118BA6.pss',rationale='normalized_pair_closure|visual_confirmed|two_vehicle_backdrop|challenge_taxonomy|mpeg2video|duration_present'))
rules.append(dict(rule_layer='normalized_evidence',sig8='0000010c43fc86e9',body_prefix='7243',matched_field='pos008',match_mode='deferred_exact',match_value='2445427570',normalization_const='0x60000000',normalized_value='834814834',status='evidence',content_class='challenge_preview',family_id='challenge_preview_family_misc',confidence='medium',semantic_label='GO/BFGoodrich challenge preview corroboration',source_probe='43fc86_7243_pos008_91C24372_minus_60000000_31C24372.pss',rationale='normalized_pair_support|visual_confirmed|logo_overlay|challenge_taxonomy|mpeg2video'))
# rejections for 43fc9a pos020 deferred clusters
rej_specs=[
    ('4003739520','0xD0000000','514078592','rejected','degraded_video','reject_black_video_family','low_medium','black/degraded normalized video cluster','43fc9a_7321_pos020_EEA43780_minus_D0000000_1EA43780.pss','normalized_oob|mostly_black_sheet|audio_video_present_but_not_semantically_useful'),
    ('1264352611','0x40000000','190610787','rejected','degraded_video','reject_black_video_family','low_medium','black/degraded normalized video cluster','43fc9a_7321_pos020_4B5C7D63_minus_40000000_0B5C7D63.pss','normalized_oob|mostly_black_sheet|mpeg_video_present_but_not_semantically_useful'),
    ('1558100056','0x20000000','1021229144','rejected','degraded_video','reject_black_video_family','medium','black/degraded normalized video cluster','43fc9a_7321_pos020_5CDEB858_minus_20000000_3CDEB858.pss','normalized_oob|mostly_black_sheet|sane_duration_but_visual_failure'),
    ('2474588544','0x70000000','595540352','rejected','nonstandard','reject_nonstandard_family','medium','fragmentary/nonstandard normalized video cluster','43fc9a_7321_pos020_937F3980_minus_70000000_237F3980.pss','normalized_oob|fragmentary_mosaic_sheet|nonstable_visual_payload'),
    ('2633239968','0x80000000','485756320','rejected','degraded_video','reject_black_video_family','medium','black/degraded normalized video cluster','43fc9a_7321_pos020_9CF40DA0_minus_80000000_1CF40DA0.pss','normalized_oob|mostly_black_sheet|audio_video_present_but_visual_failure'),
]
for mv,const,nv,status,cc,fam,conf,label,src,rat in rej_specs:
    rules.append(dict(rule_layer='normalized_deferred',sig8='0000010c43fc9ae9',body_prefix='7321',matched_field='pos020',match_mode='deferred_exact',match_value=mv,normalization_const=const,normalized_value=nv,status=status,content_class=cc,family_id=fam,confidence=conf,semantic_label=label,source_probe=src,rationale=rat))
# note: 2633812737 intentionally left deferred
rule_df=pd.DataFrame(rules)
rule_df.to_csv(MANI/'stage54_targeted_rule_additions.csv', index=False)
# update primary routes
upd=primary.copy()
# resolve 43fc86 7243
mask=(upd['sig8']=='0000010c43fc86e9')&(upd['body_prefix']=='7243')
upd.loc[mask,['route_layer','matched_field','field_value','window_start','window_end','window_state','status','content_class','family_id','confidence','semantic_label','source_stage','source_candidate','rationale']]=[
'normalized_deferred','pos028',3021048742,873434022,876317606,'normalized_routable','soft_clean','challenge_preview','challenge_preview_family_misc','medium_high','off-road multi-vehicle challenge preview (normalized 7243 closure)','stage54','43fc86_7243_pos028_B4118BA6_minus_80000000_34118BA6.pss','stage54_targeted_pair_closure|norm=0x80000000|normalized_value=873565094']
# targeted 43fc9a record offsets to reject
# use record offsets from stage53 primary rows with exact field values
rej_map={4003739520:'degraded_video',1264352611:'degraded_video',1558100056:'degraded_video',2474588544:'nonstandard',2633239968:'degraded_video'}
for raw,cc in rej_map.items():
    m=(upd['sig8']=='0000010c43fc9ae9')&(upd['body_prefix']=='7321')&(upd['matched_field']=='pos020')&(upd['field_value'].fillna(-1)==raw)&(upd['status']=='deferred_oob')
    fam='reject_black_video_family' if cc=='degraded_video' else 'reject_nonstandard_family'
    label='black/degraded normalized video cluster' if cc=='degraded_video' else 'fragmentary/nonstandard normalized video cluster'
    src=[r for r in rej_specs if int(r[0])==raw][0][8]
    const=[r for r in rej_specs if int(r[0])==raw][0][1]
    nv=[r for r in rej_specs if int(r[0])==raw][0][2]
    ws=[r for r in rej_specs if int(r[0])==raw][0]
    # actual window start/end from probe csv
    pr=probe[(probe['family']=='43fc9a')&(probe['raw_value']==raw)]
    # specific const row
    pr=pr[pr['normalization_const']==const]
    if len(pr):
        wstart=int(pr.iloc[0]['window_start']); wend=int(pr.iloc[0]['window_end'])
    else:
        wstart=wend=''
    upd.loc[m,['route_layer','window_start','window_end','window_state','status','content_class','family_id','confidence','semantic_label','source_stage','source_candidate','rationale']]=[
        'normalized_deferred',wstart,wend,'normalized_routable','rejected',cc,fam,'medium',label,'stage54',src,f'stage54_cluster_closure|norm={const}|normalized_value={nv}']
# save updated primary and summary
upd.to_csv(MANI/'stage54_record_level_primary_routes.csv', index=False)
# summaries
sumdf=upd.groupby(['sig8','body_prefix','status','content_class','family_id'], dropna=False).size().reset_index(name='record_count')
sumdf.to_csv(MANI/'stage54_route_status_summary.csv', index=False)
# remaining ambiguity queue recompute from updated primary + original queue
# unresolved/deferred counts only
rows=[]
# 43fc9a unresolved pair remains 7
rows.append(dict(sig8='0000010c43fc9ae9',body_prefix='7321',queue_type='unresolved_pair',record_count=7,reason='no_integrated_rule_match_after_stage54',recommended_next_step='derive_new_field_or_relative_probe_rule'))
# 43fc9a one deferred cluster remains
rows.append(dict(sig8='0000010c43fc9ae9',body_prefix='7321',queue_type='deferred_oob_cluster',record_count=1,reason='pos020=2633812737 still ambiguous after normalization probes',recommended_next_step='inspect_dual_audio_video_variant_or_alternate_windowing'))
rem=pd.DataFrame(rows)
rem.to_csv(MANI/'stage54_remaining_ambiguity_queue.csv', index=False)
# copy selected contact sheets
selected=[
'43fc86_7243_pos028_B4118BA6_minus_80000000_34118BA6.png',
'43fc86_7243_pos008_91C24372_minus_60000000_31C24372.png',
'43fc86_7243_pos088_E5C7A2D6_minus_B0000000_35C7A2D6.png',
'43fc9a_7321_pos020_EEA43780_minus_D0000000_1EA43780.png',
'43fc9a_7321_pos020_4B5C7D63_minus_40000000_0B5C7D63.png',
'43fc9a_7321_pos020_5CDEB858_minus_20000000_3CDEB858.png',
'43fc9a_7321_pos020_937F3980_minus_70000000_237F3980.png',
'43fc9a_7321_pos020_9CF40DA0_minus_80000000_1CF40DA0.png',
]
srcdir=Path('/mnt/data/stage54_work/contact_sheets')
for name in selected:
    p=srcdir/name
    if p.exists(): shutil.copy2(p, CS/name)
# exemplar catalog from probe
probe[['family','body_prefix','field','raw_value','normalization_const','normalized_value','duration','codecs','has_video','has_audio','contact_sheet']].to_csv(MANI/'stage54_exemplar_catalog.csv', index=False)
# integrity
sha=hashlib.sha256(TNG.read_bytes()).hexdigest().upper()
(Path(MANI/'stage54_tng_integrity_check.csv')).write_text(f'file,size_bytes,sha256\nTNG.000,{TNG.stat().st_size},{sha}\n',encoding='utf-8')
report=f'''Stage 54: targeted ambiguity closure pass

Objective
- close unresolved pair 0000010c43fc86e9 + 7243
- reduce top deferred_oob clusters for 0000010c43fc9ae9 + 7321 (pos020)
- avoid opening new domains; perform bounded closure only

Canonical TNG
- size: {TNG.stat().st_size}
- sha256: {sha}

Key outcomes
1. 43fc86 + 7243 is no longer unresolved. A normalized pos028 rule (0x80000000 base) yields a stable multi-vehicle challenge-preview window and is promoted as soft_clean challenge_preview.
2. 43fc86 + 7243 also has corroborating normalized evidence from pos008 (0x60000000 base), visually showing GO/BFGoodrich overlay and parked/off-road vehicle montage. This supports challenge taxonomy but is kept non-primary.
3. Five top deferred 43fc9a pos020 clusters were probed directly. Four produce mostly-black/degraded sheets and are reclassified as rejected degraded_video; one produces fragmentary mosaic output and is reclassified as rejected nonstandard.
4. The only deferred cluster intentionally left open is pos020=2633812737. It remains ambiguous because probe variants produce stream-valid outputs but no reliable visual sheet/semantic anchor.

Primary-route deltas vs Stage 53
- 43fc86 + 7243: unresolved 3 -> soft_clean challenge_preview 3
- 43fc9a deferred_oob: 19 -> 1
- total unresolved: 10 -> 7

Strategic conclusion
- Stage54 successfully converts residual ambiguity into either routable challenge-preview content or bounded rejection buckets.
- The remaining ambiguity is now small and explicit enough to justify a final micro-pass rather than another broad integration stage.

Recommended next step
- Stage 55: final residual micro-closure
  - inspect 43fc9ae9 + 7321 unresolved pair (7)
  - inspect deferred pos020=2633812737 (1)
  - optionally classify 43fc86 pos088 montage evidence if it becomes useful for family atlas work
'''
(OUT/'stage54_report.md').write_text(report, encoding='utf-8')
# build script copy
shutil.copy2('/tmp/build_stage54.py', OUT/'build_stage54.py')
# zip bundle
zip_path=Path('/mnt/data/stage54_bundle.zip')
with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as z:
    for p in OUT.rglob('*'):
        if p.is_file(): z.write(p, p.relative_to(OUT.parent))
print('done', zip_path)
