#!/usr/bin/env python3
import argparse, mmap, os, pandas as pd
from pathlib import Path
TOP_POSITIONS=[0x6C,0x88,0x100,0x154]

def main():
    ap=argparse.ArgumentParser(description="Master Rallye PS2 extractor prototype v2 for 43fc65 refined focused anchors")
    ap.add_argument('tng')
    ap.add_argument('--feature-table', required=True)
    ap.add_argument('--cluster-catalog', required=True)
    ap.add_argument('--outdir', required=True)
    args=ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    export_dir=Path(args.outdir)/'exports'
    export_dir.mkdir(parents=True, exist_ok=True)
    ft=pd.read_csv(args.feature_table)
    rec_col='off' if 'off' in ft.columns else ('rec_off' if 'rec_off' in ft.columns else ft.columns[0])
    cat=pd.read_csv(args.cluster_catalog)
    clusters=[(int(r.start),int(r.end),int(r.cluster_rank),r.export_file,float(r.score)) for r in cat.itertuples(index=False)]
    with open(args.tng,'rb') as f:
        mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
        for start,end,cid,fn,score in clusters:
            outp=export_dir/fn
            if not outp.exists():
                outp.write_bytes(mm[start:end+4])
        rows=[]
        for rec_off in ft[rec_col].astype(int).tolist():
            best=None
            for pos in TOP_POSITIONS:
                if rec_off+pos+4>len(mm): continue
                val=int.from_bytes(mm[rec_off+pos:rec_off+pos+4],'little')
                if not (0 < val < len(mm)): continue
                for start,end,cid,fn,cscore in clusters:
                    if start <= val <= end:
                        sc=cscore - ((val-start)/8192.0)
                        cand=(sc,rec_off,pos,val,start,end,cid,fn,val-start)
                        if best is None or sc>best[0]: best=cand
            if best:
                sc,rec_off,pos,val,start,end,cid,fn,delta=best
                rows.append({'rec_off':rec_off,'field_pos':pos,'target_off':val,'cluster_rank':cid,'cluster_file':fn,'stream_start':start,'stream_end':end,'delta_from_start':delta,'assign_score':round(sc,3)})
        pd.DataFrame(rows).to_csv(Path(args.outdir)/'record_assignments.csv', index=False)

if __name__=='__main__':
    main()
