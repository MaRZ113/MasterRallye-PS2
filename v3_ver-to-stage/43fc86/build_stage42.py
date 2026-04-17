#!/usr/bin/env python3
from pathlib import Path
import csv, json, hashlib, zlib, shutil, subprocess

base = Path('/mnt/data/semantic_pass_cross_domain_stage42')
tng = Path('/mnt/data/TNG_rebuilt/TNG.000')
src_csv = Path('/mnt/data/semantic_pass_cross_domain_stage41/manifests/43fc86_stage41_candidate_exports.csv')
status_map = {1:'launches',2:'launches',3:'launches',4:'broken',5:'launches',6:'launches',7:'broken'}

if base.exists():
    shutil.rmtree(base)
(base/'candidate_media').mkdir(parents=True)
(base/'manifests').mkdir()
(base/'contact_sheets').mkdir()

sha = hashlib.sha256()
crc=0
with open(tng,'rb') as f:
    while True:
        b=f.read(1024*1024)
        if not b: break
        sha.update(b); crc = zlib.crc32(b, crc)
size = tng.stat().st_size
shahex = sha.hexdigest()
crchex = f"0x{crc & 0xffffffff:08X}"

rows=list(csv.DictReader(src_csv.open()))
manual_rows=[]
expanded_rows=[]
for row in rows:
    r=int(float(row['rank']))
    manual_rows.append({
        'rank':r,'candidate_file':row['candidate_file'],'start_hex':row['start_hex'],
        'end_hex':row['end_hex'],'status':status_map[r],
        'note':'user confirmed launches' if status_map[r]=='launches' else 'user confirmed broken'
    })
    if status_map[r] != 'launches':
        continue
    start = int(row['start_hex'],16)
    exp_start = start & ~0xFFF
    exp_end = min(size, exp_start + 0x200000)
    out = base/'candidate_media'/f"43fc86_stage42_rank{r:02d}_expanded_{exp_start:08X}_{exp_end:08X}.pss"
    with open(tng,'rb') as src, open(out,'wb') as dst:
        src.seek(exp_start)
        remaining = exp_end-exp_start
        while remaining>0:
            chunk=src.read(min(1024*1024, remaining))
            if not chunk: break
            dst.write(chunk)
            remaining -= len(chunk)
    probe={'duration_s':'','video_codec':'','width':'','height':'','video_streams':'0','audio_streams':'0','probe_ok':'0'}
    try:
        outj = subprocess.check_output(['ffprobe','-v','error','-print_format','json','-show_format','-show_streams',str(out)], text=True)
        j=json.loads(outj)
        probe['duration_s']=j.get('format',{}).get('duration','')
        streams=j.get('streams',[])
        probe['video_streams']=str(sum(1 for s in streams if s.get('codec_type')=='video'))
        probe['audio_streams']=str(sum(1 for s in streams if s.get('codec_type')=='audio'))
        vids=[s for s in streams if s.get('codec_type')=='video']
        if vids:
            probe['video_codec']=vids[0].get('codec_name','')
            probe['width']=str(vids[0].get('width',''))
            probe['height']=str(vids[0].get('height',''))
        probe['probe_ok']='1'
    except Exception:
        pass
    expanded_rows.append({
        'rank':r,'source_start_hex':row['start_hex'],'source_end_hex':row['end_hex'],
        'expanded_start_hex':f"{exp_start:08X}",'expanded_end_hex':f"{exp_end:08X}",
        'expanded_size_bytes':exp_end-exp_start,'candidate_file':str(out),**probe
    })

def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        w=csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)

write_csv(base/'manifests'/'stage42_43fc86_manual_validation.csv', manual_rows)
write_csv(base/'manifests'/'stage42_expanded_candidates.csv', expanded_rows)
write_csv(base/'manifests'/'stage42_probe_window_explanation.csv', [{
    'reason':'stage41 scout windows were fixed-size micro-probes (~0x2C000 bytes)',
    'implication':'playable <1s windows can still indicate valid media families',
    'stage42_action':'expand only user-confirmed live windows to 0x200000-byte candidates for manual review'
}])
write_csv(base/'manifests'/'stage42_tng_integrity_check.csv', [{
    'path':str(tng),'size_bytes':size,'crc32':crchex,'sha256':shahex
}])

for row in expanded_rows:
    inp=row['candidate_file']
    outpng=str(base/'contact_sheets'/(Path(inp).stem + '.png'))
    subprocess.run(['bash','-lc',f"ffmpeg -y -v error -i '{inp}' -vf \"fps=1,scale=256:-1,tile=4x3\" -frames:v 1 '{outpng}' || ffmpeg -y -v error -i '{inp}' -vf \"scale=256:-1\" -frames:v 1 '{outpng}'"], check=False)

(base/'stage42_report.txt').write_text('Stage 42 rebuilt successfully\n')
