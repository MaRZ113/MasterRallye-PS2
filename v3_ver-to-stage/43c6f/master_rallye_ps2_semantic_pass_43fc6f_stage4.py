from pathlib import Path
import pandas as pd, subprocess, json, math

base = Path('/mnt/data')
stage3_dir = base/'semantic_pass_43fc6f_stage3'
stage4_dir = base/'semantic_pass_43fc6f_stage4'
review_dir = stage4_dir/'review_bundle'
thumb_dir = stage4_dir/'review_thumbnails'
for d in (stage4_dir, review_dir, thumb_dir):
    d.mkdir(exist_ok=True)

tng = base/'TNG_rebuilt'/'TNG.000'
if not tng.exists():
    raise FileNotFoundError(f"Missing rebuilt TNG.000 at {tng}")

sb = pd.read_csv(stage3_dir/'43fc6f_stage3_stable_banks.csv')
bc = pd.read_csv(stage3_dir/'43fc6f_stage3_bank_contributors.csv')
pr = pd.read_csv(stage3_dir/'43fc6f_stage3_prototype_rules.csv')

manual = pd.DataFrame([
    {"bank_id":"BANK_16","manual_status":"validated_preview","manual_note":"User-confirmed clean challenge preview (cand1)."},
    {"bank_id":"BANK_14","manual_status":"validated_preview","manual_note":"User-confirmed clean challenge preview (cand3)."},
    {"bank_id":"BANK_11","manual_status":"artifact_prone","manual_note":"User reported garbled/unclear playback with artifacts (cand2)."},
    {"bank_id":"BANK_03","manual_status":"artifact_prone","manual_note":"User reported garbled/unclear playback with artifacts on the original union cut (cand4)."},
    {"bank_id":"BANK_12","manual_status":"artifact_prone","manual_note":"User reported garbled/unclear playback with artifacts (cand5)."},
])
manual.to_csv(stage4_dir/'43fc6f_stage4_manual_validation_notes.csv', index=False)

def preview_score(row):
    score = 0.0
    score += float(row['support']) * 10
    dur = float(row['duration'])
    streams = int(row['streams'])
    size_mb = float(row['size_bytes']) / (1024*1024)
    if streams == 1:
        score += 20
    elif streams == 2:
        score += 4
    else:
        score -= 20 + 8*(streams-2)
    if 18 <= dur <= 25:
        score += 26
    elif 15 <= dur < 18 or 25 < dur <= 30:
        score += 18
    elif 10 <= dur < 15 or 30 < dur <= 40:
        score += 8
    elif 3 <= dur < 10 or 40 < dur <= 60:
        score -= 4
    else:
        score -= 18
    if 3 <= size_mb <= 7:
        score += 10
    elif 1 <= size_mb < 3 or 7 < size_mb <= 10:
        score += 3
    else:
        score -= 8
    if int(row['pos']) in (20,108,140,148,164):
        score += 2
    return score

bc['preview_like_score'] = bc.apply(preview_score, axis=1)
best = bc.sort_values(['bank_id','preview_like_score','support','duration','size_bytes'], ascending=[True,False,False,False,False]).groupby('bank_id', as_index=False).first()
best = best.merge(sb[['bank_id','rep_support','support_sum','num_contributors','positions','human_validated','validation_note']], on='bank_id', how='left')
best = best.merge(manual, on='bank_id', how='left')

def classify(row):
    bank = row['bank_id']
    manual_status = row.get('manual_status')
    dur = float(row['duration']); streams = int(row['streams']); support = int(row['support']); score = float(row['preview_like_score'])
    if manual_status == 'validated_preview':
        return 'validated_preview'
    if bank == 'BANK_03':
        return 'needs_recut_review'
    if bank == 'BANK_12':
        return 'needs_recut_review'
    if manual_status == 'artifact_prone' and streams > 2:
        return 'artifact_prone_nonpreview'
    if streams == 1 and support >= 6 and 15 <= dur <= 25 and score >= 90:
        return 'likely_preview'
    if streams == 2 and support >= 6 and 15 <= dur <= 25:
        return 'multistream_preview_candidate'
    if streams == 1 and support >= 6 and 40 < dur <= 60:
        return 'extended_preview_candidate'
    if streams == 1 and support >= 6 and 10 <= dur < 15:
        return 'fragment_or_alt_preview_candidate'
    if streams == 1 and support >= 6 and 3 <= dur < 10:
        return 'short_fragment_candidate'
    return 'low_confidence_or_nonpreview'

best['stage4_status'] = best.apply(classify, axis=1)
best['hex_start'] = best['start'].map(lambda x:f"0x{x:08X}")
best['hex_end'] = best['end'].map(lambda x:f"0x{x:08X}")

selected_statuses = {
    'likely_preview', 'multistream_preview_candidate',
    'extended_preview_candidate', 'needs_recut_review',
    'fragment_or_alt_preview_candidate'
}
review_manifest_rows = []
with open(tng, 'rb') as f:
    for _, row in best.sort_values(['stage4_status','preview_like_score','bank_id'], ascending=[True,False,True]).iterrows():
        if row['stage4_status'] not in selected_statuses:
            continue
        start = int(row['start']); end = int(row['end']); size = end - start + 1
        f.seek(start); data = f.read(size)
        fname = f"43fc6f_stage4_{row['bank_id']}_{row['stage4_status']}_{start:08X}_{end:08X}.pss"
        out = review_dir/fname
        with open(out, 'wb') as g:
            g.write(data)
        res = subprocess.run(
            ['ffprobe','-v','error','-show_entries','format=duration,format_name','-show_entries','stream=index,codec_type,codec_name,width,height','-of','json',str(out)],
            capture_output=True, text=True, check=False
        )
        try:
            probe_json = json.loads(res.stdout or '{}')
        except Exception:
            probe_json = {}
        ffprobe_rc = res.returncode
        fmt = probe_json.get('format') or {}
        duration_probe = None
        if 'duration' in fmt:
            try:
                duration_probe = float(fmt['duration'])
            except Exception:
                pass
        sts = probe_json.get('streams') or []
        stream_types = [s.get('codec_type') for s in sts if s.get('codec_type')]
        thumb = thumb_dir/(out.stem + '.png')
        ss = 0.5
        if duration_probe and math.isfinite(duration_probe):
            ss = max(0.2, min(duration_probe * 0.25, max(0.2, duration_probe - 0.2)))
        subprocess.run(['ffmpeg','-y','-loglevel','error','-ss',str(ss),'-i',str(out),'-vframes','1',str(thumb)], capture_output=True, check=False)
        review_manifest_rows.append({
            'bank_id': row['bank_id'],
            'stage4_status': row['stage4_status'],
            'start': start, 'end': end,
            'hex_start': row['hex_start'], 'hex_end': row['hex_end'],
            'size_bytes': size,
            'field_pos_dec': int(row['pos']),
            'field_pos_hex': f"0x{int(row['pos']):03X}",
            'support': int(row['support']),
            'preview_like_score': round(float(row['preview_like_score']),3),
            'manual_status': row.get('manual_status'),
            'manual_note': row.get('manual_note'),
            'candidate_file': fname,
            'thumbnail_file': thumb.name if thumb.exists() and thumb.stat().st_size > 0 else '',
            'ffprobe_rc': ffprobe_rc,
            'streams_probe': len(sts),
            'stream_types': '|'.join(stream_types),
            'format_name_probe': fmt.get('format_name'),
            'duration_probe': duration_probe,
        })

review_manifest = pd.DataFrame(review_manifest_rows).sort_values(['stage4_status','preview_like_score'], ascending=[True,False])
review_manifest.to_csv(stage4_dir/'43fc6f_stage4_review_bundle_manifest.csv', index=False)

catalog = best.merge(review_manifest[['bank_id','candidate_file','thumbnail_file','duration_probe','streams_probe','stream_types','format_name_probe']], on='bank_id', how='left')
catalog.rename(columns={'duration':'duration_best_cut','streams':'streams_best_cut','format_name':'format_name_best_cut'}, inplace=True)
catalog.to_csv(stage4_dir/'43fc6f_stage4_bank_catalog.csv', index=False)

status_rank = {
    'validated_preview': 0,
    'likely_preview': 1,
    'multistream_preview_candidate': 2,
    'extended_preview_candidate': 3,
    'needs_recut_review': 4,
    'fragment_or_alt_preview_candidate': 5,
    'short_fragment_candidate': 6,
    'artifact_prone_nonpreview': 7,
    'low_confidence_or_nonpreview': 8,
}
pr2 = pr.merge(catalog[['bank_id','stage4_status','candidate_file','thumbnail_file','manual_status','manual_note']], on='bank_id', how='left')
pr2['status_rank'] = pr2['stage4_status'].map(status_rank).fillna(99)
pruned_keep = pr2[pr2['stage4_status'].isin([
    'validated_preview','likely_preview','multistream_preview_candidate',
    'extended_preview_candidate','needs_recut_review','fragment_or_alt_preview_candidate'
])].copy()
pruned_keep = pruned_keep.sort_values(['branch_family','status_rank','hits','coverage_pct'], ascending=[True,True,False,False])
branch_catalog = pruned_keep.groupby('branch_family', as_index=False).first()
branch_catalog.to_csv(stage4_dir/'43fc6f_stage4_branch_catalog.csv', index=False)
pruned_keep.to_csv(stage4_dir/'43fc6f_stage4_pruned_prototype_rules.csv', index=False)

all_branches = pd.DataFrame({'branch_family': sorted(pr['branch_family'].unique())})
resolved = set(branch_catalog['branch_family'])
unresolved = all_branches[~all_branches['branch_family'].isin(resolved)].copy()
if not unresolved.empty:
    strongest = pr.sort_values(['branch_family','hits','coverage_pct'], ascending=[True,False,False]).groupby('branch_family', as_index=False).first()
    unresolved = unresolved.merge(strongest, on='branch_family', how='left')
unresolved.to_csv(stage4_dir/'43fc6f_stage4_unresolved_branches.csv', index=False)

lines = []
lines.append("43fc6f semantic pass stage 4")
lines.append("Status: completed on reconstructed canonical TNG.000")
lines.append("")
lines.append("Main outcome")
lines.append("- Manual user playback validation has been merged into the bank model.")
lines.append("- Artifact-prone stage2/stage3 cuts are now separated from likely clean contributor-level recuts.")
lines.append("- A pruned challenge-preview prototype and review bundle have been generated.")
(stage4_dir/'43fc6f_semantic_pass_stage4.txt').write_text("\n".join(lines), encoding='utf-8')
