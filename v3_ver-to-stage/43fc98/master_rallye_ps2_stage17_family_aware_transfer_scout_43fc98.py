import os, mmap, struct, json, subprocess, glob, hashlib, csv, zipfile, math, shutil
from collections import Counter, defaultdict
from PIL import Image

BASE='/mnt/data/semantic_pass_cross_domain_stage17'
MAN=os.path.join(BASE,'manifests')
CAND=os.path.join(BASE,'candidate_media')
SHEETS=os.path.join(BASE,'contact_sheets')
REFS=os.path.join(BASE,'reference_sheets')
for d in [BASE,MAN,CAND,SHEETS,REFS]: os.makedirs(d, exist_ok=True)

TNG='/mnt/data/TNG_rebuilt/TNG.000'
DOMAIN='43fc98'
PAT=bytes.fromhex('0000010c'+DOMAIN)
FIELDS=[0x08,0x0c,0x14,0x1c,0x20,0x24,0x28,0x88,0x94,0xa4]
MAX_CANDIDATES=8
EXTRACT_LEN=0x300000

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def ffprobe_json(path):
    r=run(['ffprobe','-v','error','-print_format','json','-show_streams','-show_format',path])
    try:
        return json.loads(r.stdout)
    except Exception:
        return {}

def make_sheet(video_path, out_png):
    cmd=['ffmpeg','-y','-v','error','-i',video_path,'-vf','fps=1,scale=240:-1,tile=3x3','-frames:v','1',out_png]
    r=subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode==0 and os.path.exists(out_png)

def ahash(image_path, size=16):
    im=Image.open(image_path).convert('L').resize((size,size))
    px=list(im.getdata())
    avg=sum(px)/len(px)
    bits=''.join('1' if p>=avg else '0' for p in px)
    return bits

def hamming(a,b):
    if not a or not b or len(a)!=len(b): return 10**9
    return sum(x!=y for x,y in zip(a,b))

def sha256_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for chunk in iter(lambda:f.read(1<<20), b''):
            h.update(chunk)
    return h.hexdigest()

# reference media and family registry
ref_files=[]
for pat in [
    '/mnt/data/semantic_pass_cross_domain_stage12/clean_media/*.pss',
    '/mnt/data/semantic_pass_cross_domain_stage14/clean_media/*.pss',
    '/mnt/data/semantic_pass_cross_domain_stage15/clean_media/*.pss',
    '/mnt/data/semantic_pass_43fc6f_stage7/unique_media/*.pss',
]:
    ref_files.extend(glob.glob(pat))
ref_files=sorted(set(ref_files))
family_registry=[]
reg_csv='/mnt/data/semantic_pass_cross_domain_stage16/manifests/stage16_family_registry.csv'
if os.path.exists(reg_csv):
    import pandas as pd
    family_registry=pd.read_csv(reg_csv).to_dict('records')
else:
    family_registry=[]
# map media id to family
media_to_family={}
for row in family_registry:
    fam=row.get('family_id')
    members=str(row.get('member_media_ids','')).split('|') if row.get('member_media_ids') is not None else []
    for m in members:
        if m: media_to_family[m]=fam

# build reference hashes
ref_rows=[]
for p in ref_files:
    base=os.path.basename(p)
    media_id=os.path.splitext(base)[0]
    out=os.path.join(REFS, media_id+'.png')
    if not os.path.exists(out):
        make_sheet(p,out)
    h=ahash(out) if os.path.exists(out) else None
    fam=media_to_family.get(media_id, media_id)
    content_class='unknown'
    low=media_id.lower()
    if 'menu_background' in low: content_class='menu_background_fmv'
    elif 'challenge_preview' in low: content_class='challenge_preview_fmv'
    ref_rows.append({'media_id':media_id,'path':p,'sheet_path':out,'family_id':fam,'content_class':content_class,'ahash':h})

import pandas as pd
pd.DataFrame(ref_rows).to_csv(os.path.join(MAN,'stage17_reference_atlas_catalog.csv'), index=False)

size=os.path.getsize(TNG)
with open(TNG,'rb') as f:
    mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    hits=[]; pos=0
    while True:
        i=mm.find(PAT,pos)
        if i==-1: break
        if i+507<=size:
            sig8=mm[i:i+8].hex(); bp=mm[i+8:i+10].hex()
            hits.append({'rec_pos':i,'sig8':sig8,'body_prefix':bp,'branch_id':f'{sig8}|{bp}'})
        pos=i+1
    pd.DataFrame(hits).to_csv(os.path.join(MAN,f'{DOMAIN}_stage17_domain_hits.csv'), index=False)

    # field scorer
    scorer=[]
    cluster_rows=[]
    pack_pat=b'\x00\x00\x01\xba'
    for fo in FIELDS:
        vals=[]
        backrefs=defaultdict(list)
        for h in hits:
            v=struct.unpack_from('<I',mm,h['rec_pos']+fo)[0]
            if 0 < v < size-0x1000:
                vals.append(v)
                backrefs[v].append(h)
        cnt=Counter(vals)
        reps=[(v,n) for v,n in cnt.items() if n>=2]
        support=sum(n for _,n in reps)
        scorer.append({'field_off':f'0x{fo:03X}','support':support,'cluster_count':len(reps),'top_values':'|'.join(f'0x{v:08X}:{n}' for v,n in sorted(reps,key=lambda x:(-x[1],x[0]))[:8])})
        for v,n in reps:
            # locate nearby pack starts
            lo=max(0,v-0x200000); hi=min(size,v+0x8000)
            starts=[]; s=lo
            while True:
                j=mm.find(pack_pat,s,hi)
                if j==-1: break
                starts.append(j); s=j+1
            chosen=None
            probe_info={}
            for j in starts[-10:]:
                end=min(size,j+EXTRACT_LEN)
                tmp='/tmp/stage17_probe.pss'
                with open(tmp,'wb') as out: out.write(mm[j:end])
                info=ffprobe_json(tmp)
                vids=[st for st in info.get('streams',[]) if st.get('codec_type')=='video']
                if vids:
                    chosen=j; probe_info=info; break
            branch_counts=Counter(r['branch_id'] for r in backrefs[v])
            cluster_rows.append({
                'field_off':f'0x{fo:03X}','target_value':v,'target_hex':f'0x{v:08X}','support':n,
                'branch_count':len(branch_counts),'top_branch':branch_counts.most_common(1)[0][0],
                'pack_start':chosen,'pack_start_hex':(f'0x{chosen:08X}' if chosen is not None else ''),
                'delta_to_target':(chosen-v if chosen is not None else ''),
                'probe_video': bool([st for st in probe_info.get('streams',[]) if st.get('codec_type')=='video']),
                'probe_audio': bool([st for st in probe_info.get('streams',[]) if st.get('codec_type')=='audio']),
                'codec_names':'|'.join(sorted(set(st.get('codec_name','') for st in probe_info.get('streams',[])))),
                'duration': (probe_info.get('format',{}) or {}).get('duration','')
            })
    pd.DataFrame(sorted(scorer, key=lambda r:(-r['support'], r['field_off']))).to_csv(os.path.join(MAN,f'{DOMAIN}_stage17_transfer_field_scorer.csv'), index=False)
    clus_df=pd.DataFrame(cluster_rows)
    clus_df=clus_df.sort_values(['probe_video','support'], ascending=[False,False])
    clus_df.to_csv(os.path.join(MAN,f'{DOMAIN}_stage17_cluster_catalog.csv'), index=False)

    # pick candidates: probe_video first then support, dedupe by pack_start
    chosen=[]; seen_pack=set()
    for _,r in clus_df.iterrows():
        ps=r['pack_start']
        if pd.isna(ps) or ps in seen_pack: continue
        seen_pack.add(ps)
        chosen.append(r.to_dict())
        if len(chosen)>=MAX_CANDIDATES: break

    cand_rows=[]
    for rank,r in enumerate(chosen, start=1):
        ps=int(r['pack_start'])
        end=min(size, ps+EXTRACT_LEN)
        fn=f'{DOMAIN}_stage17_rank{rank:02d}_pos{int(str(r["field_off"]),16):03d}_{int(r["target_value"]):08X}_{ps:08X}.pss'
        outp=os.path.join(CAND,fn)
        with open(outp,'wb') as out: out.write(mm[ps:end])
        info=ffprobe_json(outp)
        vids=[st for st in info.get('streams',[]) if st.get('codec_type')=='video']
        auds=[st for st in info.get('streams',[]) if st.get('codec_type')=='audio']
        sheet=os.path.join(SHEETS, os.path.splitext(fn)[0]+'.png')
        make_sheet(outp,sheet)
        sh=ahash(sheet) if os.path.exists(sheet) else None
        best=None
        for ref in ref_rows:
            dist=hamming(sh, ref['ahash']) if sh and ref['ahash'] else 10**9
            row={'ref_media_id':ref['media_id'],'ref_family_id':ref['family_id'],'ref_content_class':ref['content_class'],'distance':dist}
            if best is None or dist<best['distance']: best=row
        cand_rows.append({
            'rank':rank,'candidate_file':fn,'candidate_path':outp,'sheet_path':sheet,
            'field_off':r['field_off'],'target_hex':r['target_hex'],'pack_start_hex':f'0x{ps:08X}','support':r['support'],
            'top_branch':r['top_branch'],'codec_names':'|'.join(sorted(set(st.get('codec_name','') for st in info.get('streams',[])))),
            'video_streams':len(vids),'audio_streams':len(auds),'duration':(info.get('format',{}) or {}).get('duration',''),
            'width': vids[0].get('width') if vids else '', 'height': vids[0].get('height') if vids else '',
            'best_ref_media_id': best['ref_media_id'] if best else '', 'best_ref_family_id': best['ref_family_id'] if best else '',
            'best_ref_content_class': best['ref_content_class'] if best else '', 'best_ref_distance': best['distance'] if best else '',
            'family_hint': ('menu_background_family_01' if best and best['ref_family_id']=='menu_background_family_01' and best['distance']<110 else ('challenge_preview_like' if best and 'challenge_preview' in best['ref_content_class'] and best['distance']<120 else 'unknown')),
            'sha256': sha256_file(outp)
        })

pd.DataFrame(cand_rows).to_csv(os.path.join(MAN,f'{DOMAIN}_stage17_candidate_exports.csv'), index=False)
pd.DataFrame(cand_rows)[['rank','candidate_file','best_ref_media_id','best_ref_family_id','best_ref_content_class','best_ref_distance','family_hint']].to_csv(os.path.join(MAN,f'{DOMAIN}_stage17_family_hint_matches.csv'), index=False)

# branch summary from hits referencing top targets
cand_targets={int(r['target_hex'],16):r for r in chosen}
branch_summary=defaultdict(lambda:{'count':0,'candidate_ranks':set(),'field_offs':set()})
with open(TNG,'rb') as f:
    mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    for h in hits:
        for fo in FIELDS:
            v=struct.unpack_from('<I',mm,h['rec_pos']+fo)[0]
            if v in cand_targets:
                b=branch_summary[h['branch_id']]
                b['count']+=1; b['candidate_ranks'].add(next(i+1 for i,r in enumerate(chosen) if int(r['target_value'])==v)); b['field_offs'].add(f'0x{fo:03X}')
    rows=[]
    for bid,meta in branch_summary.items():
        rows.append({'branch_id':bid,'assignment_count':meta['count'],'candidate_ranks':'|'.join(map(str,sorted(meta['candidate_ranks']))),'field_offs':'|'.join(sorted(meta['field_offs']))})
    pd.DataFrame(sorted(rows,key=lambda r:-r['assignment_count'])).to_csv(os.path.join(MAN,f'{DOMAIN}_stage17_branch_cluster_summary.csv'), index=False)

# secondary catalog
sec=[]
for row in cand_rows:
    sec.append({'domain':DOMAIN,'candidate_rank':row['rank'],'candidate_file':row['candidate_file'],'top_branch':row['top_branch'],'content_class_hint':row['best_ref_content_class'],'family_hint':row['family_hint'],'promote_policy':'manual_validation_required','layer':'secondary_candidate_bundle'})
pd.DataFrame(sec).to_csv(os.path.join(MAN,'stage17_secondary_candidate_bundle_catalog.csv'), index=False)

# report
report=f'''Stage 17 · family-aware transfer-scout on domain {DOMAIN}\n\nInput TNG: {TNG}\nTNG size: {os.path.getsize(TNG)} bytes\nDomain hits: {len(hits)}\nCandidate exports: {len(cand_rows)}\n\nTop fields by repeated support:\n'''
sc=pd.read_csv(os.path.join(MAN,f'{DOMAIN}_stage17_transfer_field_scorer.csv'))
for _,r in sc.head(6).iterrows():
    report += f"- {r['field_off']}: support={r['support']}, clusters={r['cluster_count']}, top={r['top_values']}\n"
report += '\nCandidate summary:\n'
for row in cand_rows:
    report += f"- rank{row['rank']:02d}: {row['candidate_file']} :: {row['codec_names']} :: {row['width']}x{row['height']} :: family_hint={row['family_hint']} :: best_ref={row['best_ref_media_id']} (dist={row['best_ref_distance']})\n"
report += '\nInterpretation:\n- This is a secondary-layer scout only. No clean promotion is performed at Stage 17.\n- Family hints are advisory and derived from contact-sheet hash proximity to the current atlas.\n- Manual validation is required before any candidate is promoted into the primary clean extractor.\n'
open(os.path.join(BASE,'stage17_report.txt'),'w').write(report)

# script copy
src='/mnt/data/run_stage17.py'
dst=os.path.join(BASE,'master_rallye_ps2_stage17_family_aware_transfer_scout_43fc98.py')
shutil.copyfile(src,dst)

# bundle manifest
bundle_entries=[]
for root,_,files in os.walk(BASE):
    for fn in files:
        p=os.path.join(root,fn)
        if p.endswith('stage17_bundle.zip'): continue
        bundle_entries.append({'path':os.path.relpath(p,BASE),'size':os.path.getsize(p)})
pd.DataFrame(bundle_entries).to_csv(os.path.join(MAN,'stage17_bundle_manifest.csv'), index=False)

# zip bundle
zip_path=os.path.join(BASE,'stage17_bundle.zip')
with zipfile.ZipFile(zip_path,'w',compression=zipfile.ZIP_DEFLATED) as z:
    for root,_,files in os.walk(BASE):
        for fn in files:
            p=os.path.join(root,fn)
            if p==zip_path: continue
            z.write(p, os.path.relpath(p,BASE))
print('DONE', zip_path)
