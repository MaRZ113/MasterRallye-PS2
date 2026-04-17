#!/usr/bin/env python3
# Auto-generated Stage 34 scout builder for 43fc85
import os, mmap, struct, subprocess, json, hashlib, zlib, shutil, pandas as pd
from collections import Counter
DOMAIN='43fc85'
FIELDS=[0x08,0x14,0x1c,0x20,0x24,0x28,0x88,0x94,0xa4,0x148,0x164]
FIELD_NAMES={0x08:'pos008',0x14:'pos014',0x1c:'pos01c',0x20:'pos020',0x24:'pos024',0x28:'pos028',0x88:'pos088',0x94:'pos094',0xa4:'pos0a4',0x148:'pos148',0x164:'pos164'}
WINDOW=0x2C000

def ffprobe(path):
    cp=subprocess.run(['ffprobe','-v','error','-print_format','json','-show_streams',path],capture_output=True,text=True,timeout=25)
    try:
        return json.loads(cp.stdout or '{}')
    except Exception:
        return {}

def main(tng,outdir):
    os.makedirs(os.path.join(outdir,'candidate_media'),exist_ok=True)
    os.makedirs(os.path.join(outdir,'manifests'),exist_ok=True)
    size=os.path.getsize(tng)
    hits=[]
    marker=b'\x00\x00\x01\x0c'
    with open(tng,'rb') as f:
        mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
        pos=0
        while True:
            i=mm.find(marker,pos)
            if i==-1: break
            if mm[i+4:i+7].hex()==DOMAIN:
                rec={'offset':i}
                for fld in FIELDS:
                    if i+fld+4 <= len(mm):
                        rec[FIELD_NAMES[fld]]=struct.unpack_from('<I',mm,i+fld)[0]
                hits.append(rec)
            pos=i+1
        rows=[]
        for fld in FIELDS:
            key=FIELD_NAMES[fld]
            vals=[r[key] for r in hits if 0<r[key]<size-0x1000]
            c=Counter(vals)
            for value,support in c.most_common(8):
                start=value; end=min(value+WINDOW,size)
                out=os.path.join(outdir,'candidate_media',f'{DOMAIN}_{key}_{start:08X}_{end:08X}.pss')
                with open(out,'wb') as fo:
                    mm.seek(start); fo.write(mm.read(end-start))
                info=ffprobe(out)
                streams=info.get('streams',[])
                video=[s for s in streams if s.get('codec_type')=='video']
                rows.append({'field':key,'start':start,'end':end,'support':support,'video_streams':len(video),'candidate_file':out})
        mm.close()
    pd.DataFrame(rows).to_csv(os.path.join(outdir,'manifests',f'{DOMAIN}_stage34_candidate_exports.csv'),index=False)

if __name__=='__main__':
    main('/mnt/data/TNG_rebuilt/TNG.000','/mnt/data/semantic_pass_cross_domain_stage34')
