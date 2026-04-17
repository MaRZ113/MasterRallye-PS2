import os, mmap, struct, collections, subprocess, json, math, hashlib, csv, shutil, zipfile
from pathlib import Path
import pandas as pd

TNG=Path('/mnt/data/TNG_rebuilt/TNG.000')
OUT=Path('/mnt/data/semantic_pass_cross_domain_stage20')
if OUT.exists():
    shutil.rmtree(OUT)
(OUT/'manifests').mkdir(parents=True)
(OUT/'candidate_media').mkdir()
(OUT/'contact_sheets').mkdir()

size=TNG.stat().st_size
# atlas references
ref_files=[]
for pat in [
    '/mnt/data/semantic_pass_cross_domain_stage19/clean_media/*.pss',
    '/mnt/data/semantic_pass_cross_domain_stage15/clean_media/*.pss',
    '/mnt/data/semantic_pass_cross_domain_stage12/clean_media/*.pss',
    '/mnt/data/semantic_pass_43fc6f_stage7/unique_media/*.pss',
]:
    ref_files += list(Path('/').glob(pat.lstrip('/')))
# dedupe by basename preserving latest first
seen=set(); refs=[]
for p in ref_files:
    if p.name in seen: continue
    seen.add(p.name); refs.append(p)

def ffprobe_info(path):
    r=subprocess.run(['ffprobe','-v','error','-print_format','json','-show_streams','-show_format',str(path)],capture_output=True,text=True,timeout=60)
    js=json.loads(r.stdout or '{}')
    streams=js.get('streams',[]); fmt=js.get('format',{})
    codecs=','.join(sorted(set(s.get('codec_name','') for s in streams if s.get('codec_name'))))
    dur=float(fmt['duration']) if fmt.get('duration') not in (None,'N/A','') else None
    widths=sorted(set((s.get('width'),s.get('height')) for s in streams if s.get('width')))
    wh=';'.join(f'{w}x{h}' for w,h in widths)
    return {'codec':codecs,'duration':dur,'resolution':wh,'streams':len(streams)}

atlas=[]
for p in refs:
    info=ffprobe_info(p)
    cls='unknown'
    fam='unknown'
    n=p.name.lower()
    if 'menu_background' in n:
        cls='menu_background_fmv'; fam='menu_background_family_01'
    elif 'track_menu_preview' in n:
        cls='track_menu_preview_fmv'; fam='track_menu_preview_family_01'
    elif 'challenge_preview' in n:
        cls='challenge_preview_fmv'; fam='challenge_preview_family_misc'
    atlas.append({'file':str(p),'name':p.name,**info,'content_class':cls,'family_id':fam})
atlas_df=pd.DataFrame(atlas)
atlas_df.to_csv(OUT/'manifests'/'stage20_reference_atlas_catalog.csv',index=False)

# scan domain hits
DOMAIN='43fc7f'
positions=[0x08,0x14,0x1c,0x20,0x24,0x28,0x88,0x94,0xa4]
pat=b'\x00\x00\x01\x0c\x43\xfc\x7f'
hits=[]
with open(TNG,'rb') as f:
    mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    pos=0
    while True:
        i=mm.find(pat,pos)
        if i==-1: break
        rec=mm[i:i+0xA8]
        sig8=rec[:8].hex(); body=rec[8:10].hex()
        vals={f'pos_{p:03x}':struct.unpack_from('<I',rec,p)[0] for p in positions if p+4<=len(rec)}
        hits.append({'offset':i,'sig8':sig8,'body_prefix':body,**vals})
        pos=i+1
    mm.close()
hits_df=pd.DataFrame(hits)
hits_df.to_csv(OUT/'manifests'/'43fc7f_stage20_domain_hits.csv',index=False)

# scorer
rows=[]
for p in positions:
    col=f'pos_{p:03x}'
    ctr=hits_df[col].value_counts()
    for val,support in ctr.items():
        if support<2: continue
        plausible=0 < int(val) < size
        rows.append({'field_pos':p,'value_u32':int(val),'support':int(support),'plausible_offset':plausible})
scorer_df=pd.DataFrame(rows).sort_values(['support','field_pos'],ascending=[False,True])
scorer_df.to_csv(OUT/'manifests'/'43fc7f_stage20_transfer_field_scorer.csv',index=False)

# candidate selection
cand=scorer_df[scorer_df['plausible_offset']].copy()
# keep strongest and ffprobe-able ones by trying top values
selected=[]
probes=[]
with open(TNG,'rb') as src:
    for _,r in cand.head(18).iterrows():
        field_pos=int(r.field_pos); val=int(r.value_u32); support=int(r.support)
        start=max(0, val-0x20000)
        end=min(size, val+0x280000)
        if end<=start: continue
        name=f'43fc7f_stage20_probe_p{field_pos:03x}_{val:08X}_{support}.pss'
        p=OUT/'candidate_media'/name
        src.seek(start); data=src.read(end-start)
        p.write_bytes(data)
        info=ffprobe_info(p)
        probes.append({'file':name,'field_pos':field_pos,'value_u32':val,'support':support,'start_offset':start,'end_offset':end,**info})
probe_df=pd.DataFrame(probes)
# heuristic ranking: prefer valid video + support + duration known
probe_df['video_like']=probe_df['codec'].str.contains('mpeg',na=False)
probe_df['audio_like']=probe_df['codec'].str.contains('mp2|mp3',na=False)
probe_df['dur_score']=probe_df['duration'].fillna(0).clip(0,60)
probe_df['score']=probe_df['video_like'].astype(int)*100 + probe_df['support']*2 + probe_df['audio_like'].astype(int)*5 + probe_df['dur_score']
probe_df=probe_df.sort_values(['score','support'],ascending=[False,False]).reset_index(drop=True)
# top 7
cand_df=probe_df.head(7).copy()
# rename files rankXX
ranked=[]
for idx,row in cand_df.iterrows():
    rank=idx+1
    old=OUT/'candidate_media'/row['file']
    new_name=f"43fc7f_stage20_rank{rank:02d}_pos{int(row['field_pos']):03x}_{int(row['start_offset']):08X}_{int(row['end_offset']):08X}.pss"
    new=OUT/'candidate_media'/new_name
    old.rename(new)
    info=row.to_dict(); info['rank']=rank; info['file']=new_name
    # top branch summary for this value/field
    col=f'pos_{int(row['field_pos']):03x}'
    subset=hits_df[hits_df[col]==int(row['value_u32'])]
    top=subset.groupby(['sig8','body_prefix']).size().sort_values(ascending=False).head(3)
    info['top_branches']=' | '.join([f'{a}|{b}:{c}' for (a,b),c in top.items()])
    ranked.append(info)
    # contact sheet
    sheet=OUT/'contact_sheets'/(new.stem+'.png')
    subprocess.run(['ffmpeg','-y','-v','error','-i',str(new),'-vf','fps=1,scale=320:-1,tile=3x3',str(sheet)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
rank_df=pd.DataFrame(ranked)
rank_df.to_csv(OUT/'manifests'/'43fc7f_stage20_candidate_exports.csv',index=False)

# family hints heuristic by nearest known family duration
family_refs=[]
for fam,grp in atlas_df.groupby('family_id'):
    ds=[d for d in grp['duration'].tolist() if isinstance(d,(int,float)) and not math.isnan(d)]
    family_refs.append({'family_id':fam,'content_class':grp['content_class'].iloc[0],'median_duration':sum(ds)/len(ds) if ds else None,'codec':grp['codec'].mode().iloc[0] if len(grp) else ''})
fam_df=pd.DataFrame(family_refs)
fh=[]
for _,r in rank_df.iterrows():
    for _,f in fam_df.iterrows():
        dur=r['duration']
        dur_delta=None if pd.isna(dur) or pd.isna(f['median_duration']) else abs(float(dur)-float(f['median_duration']))
        codec_match = 1 if isinstance(r['codec'],str) and isinstance(f['codec'],str) and r['codec']==f['codec'] else 0
        score=(100 if codec_match else 0) - (dur_delta if dur_delta is not None else 999)
        fh.append({'candidate_file':r['file'],'rank':r['rank'],'hint_family_id':f['family_id'],'hint_content_class':f['content_class'],'candidate_duration':r['duration'],'family_median_duration':f['median_duration'],'duration_delta':dur_delta,'codec_match':codec_match,'hint_score':score})
fh_df=pd.DataFrame(fh).sort_values(['candidate_file','hint_score'],ascending=[True,False])
fh_top=fh_df.groupby('candidate_file').head(3)
fh_top.to_csv(OUT/'manifests'/'43fc7f_stage20_family_hint_matches.csv',index=False)

# branch cluster summary
branch_rows=[]
for _,r in rank_df.iterrows():
    for part in str(r['top_branches']).split(' | '):
        if not part: continue
        sigbody,count=part.rsplit(':',1)
        sig,body=sigbody.split('|')
        branch_rows.append({'candidate_file':r['file'],'rank':r['rank'],'sig8':sig,'body_prefix':body,'count':int(count)})
pd.DataFrame(branch_rows).to_csv(OUT/'manifests'/'43fc7f_stage20_branch_cluster_summary.csv',index=False)

# secondary candidate bundle catalog
sec=[]
for _,r in rank_df.iterrows():
    top=fh_top[fh_top['candidate_file']==r['file']].iloc[0]
    sec.append({'file':r['file'],'rank':r['rank'],'content_layer':'secondary_candidate_bundle','domain':DOMAIN,'field_pos':int(r['field_pos']),'support':int(r['support']),'codec':r['codec'],'duration':r['duration'],'resolution':r['resolution'],'hint_family_id':top['hint_family_id'],'hint_content_class':top['hint_content_class'],'top_branches':r['top_branches']})
sec_df=pd.DataFrame(sec)
sec_df.to_csv(OUT/'manifests'/'stage20_secondary_candidate_bundle_catalog.csv',index=False)

# next step recommendations
reco=[]
for _,r in sec_df.iterrows():
    action='manual_review'
    if isinstance(r['codec'],str) and 'mpeg' in r['codec'] and (pd.isna(r['duration']) or float(r['duration'])>=10):
        action='priority_manual_review'
    if isinstance(r['codec'],str) and 'mp2' in r['codec']:
        action+=';check_audio_presence'
    reco.append({'file':r['file'],'rank':r['rank'],'recommended_action':action,'reason':f"{r['codec']} {r['duration']}s hint->{r['hint_family_id']}"})
reco_df=pd.DataFrame(reco)
reco_df.to_csv(OUT/'manifests'/'stage20_next_step_recommendations.csv',index=False)

# report
report=f'''Stage 20 — family-aware transfer scout for 43fc7f\n\nDomain hits: {len(hits_df)}\nSelected candidates: {len(rank_df)}\nStrongest fields by repeated values: {', '.join(f'0x{int(p):03X}' for p in scorer_df.groupby('field_pos')['support'].max().sort_values(ascending=False).head(5).index)}\n\nTop candidates:\n'''
for _,r in rank_df.head(5).iterrows():
    report += f"- rank{int(r['rank']):02d}: field 0x{int(r['field_pos']):03X}, support {int(r['support'])}, codec={r['codec']}, duration={r['duration']}, branches={r['top_branches']}\n"
report += '\nThis stage keeps 43fc7f in the secondary family-aware layer only. No clean promotion is performed before manual validation.\n'
(OUT/'stage20_report.txt').write_text(report)

# minimal script placeholder/record
(OUT/'master_rallye_ps2_stage20_family_aware_transfer_scout_43fc7f.py').write_text('# Stage20 builder executed in-container; see manifests and report for outputs.\n')

# bundle manifest
bundle_files=[]
for p in OUT.rglob('*'):
    if p.is_file() and p.name != 'stage20_bundle.zip':
        bundle_files.append({'path':str(p.relative_to(OUT)),'size':p.stat().st_size})
pd.DataFrame(bundle_files).sort_values('path').to_csv(OUT/'manifests'/'stage20_bundle_manifest.csv',index=False)

# zip bundle
zip_path=OUT/'stage20_bundle.zip'
with zipfile.ZipFile(zip_path,'w',compression=zipfile.ZIP_DEFLATED) as z:
    for p in OUT.rglob('*'):
        if p.is_file() and p != zip_path:
            z.write(p, p.relative_to(OUT))
print('done', OUT, zip_path.stat().st_size)
print(rank_df[['rank','file','codec','duration','top_branches']].to_string(index=False))
