
from pathlib import Path
import pandas as pd, subprocess, json, hashlib

TNG = Path('/mnt/data/TNG_rebuilt/TNG.000')
STAGE38 = Path('/mnt/data/semantic_pass_cross_domain_stage38')
OUTDIR = Path('/mnt/data/semantic_pass_cross_domain_stage39')
MANIF = OUTDIR / 'manifests'
CANDDIR = OUTDIR / 'candidate_media'
SHEETS = OUTDIR / 'contact_sheets'
for d in [OUTDIR, MANIF, CANDDIR, SHEETS]:
    d.mkdir(parents=True, exist_ok=True)

EXPAND_LEN = 0x200000
PREPAD = 0x2000
ALIGN = 0x1000

def align_down(x, a=ALIGN):
    return x - (x % a)

def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def ffprobe_info(path):
    r = run(['ffprobe','-v','error','-print_format','json','-show_streams','-show_format',str(path)])
    data = json.loads(r.stdout) if r.returncode == 0 else {}
    streams = data.get('streams', [])
    v = next((s for s in streams if s.get('codec_type')=='video'), None)
    a = next((s for s in streams if s.get('codec_type')=='audio'), None)
    return {
        'video': v is not None,
        'audio': a is not None,
        'vcodec': v.get('codec_name') if v else '',
        'width': v.get('width') if v else None,
        'height': v.get('height') if v else None,
        'duration': float(data.get('format',{}).get('duration')) if data.get('format',{}).get('duration') not in (None,'N/A') else None,
    }

def make_sheet(infile, outfile):
    subprocess.run([
        'ffmpeg','-y','-hide_banner','-loglevel','error','-i',str(infile),
        '-vf','fps=1/2,scale=256:-1,tile=3x2','-frames:v','1',str(outfile)
    ], check=False)

df = pd.read_csv(STAGE38 / 'manifests' / '43fc84_stage38_candidate_exports.csv')
size = TNG.stat().st_size
rows = []
with open(TNG, 'rb') as f:
    for _, row in df.iterrows():
        start = int(row['start'])
        st = align_down(max(0, start - PREPAD))
        en = min(size, st + EXPAND_LEN)
        f.seek(st)
        data = f.read(en-st)
        out = CANDDIR / f"43fc84_stage39_rank{int(row['rank']):02d}_expanded_{st:08X}_{en:08X}.pss"
        out.write_bytes(data)
        probe = ffprobe_info(out)
        make_sheet(out, SHEETS / (out.stem + '.png'))
        rows.append({
            'rank': int(row['rank']),
            'source_file': row['file'],
            'expanded_start_hex': f"{st:08X}",
            'expanded_end_hex': f"{en:08X}",
            'expanded_size_bytes': en-st,
            **probe
        })
pd.DataFrame(rows).to_csv(MANIF / 'stage39_expanded_candidates.csv', index=False)
print('Stage 39 rebuilt.')
