#!/usr/bin/env python3
import os
import shutil
import pandas as pd
import numpy as np

BASE4 = '/mnt/data/semantic_pass_43fc6f_stage4'
BASE2 = '/mnt/data/semantic_pass_43fc6f_stage2'
OUT = '/mnt/data/semantic_pass_43fc6f_stage5'

MANUAL_UPDATES = [
    ('BANK_14','validated_preview_clean','User-confirmed clean challenge preview (cand3).'),
    ('BANK_16','validated_preview_clean','User-confirmed clean challenge preview (cand1).'),
    ('BANK_11','artifact_prone_unusable','User reported garbled/unclear playback with artifacts (cand2).'),
    ('BANK_03','broken_unusable','User reported stage4 re-cut still broken / not playable.'),
    ('BANK_12','artifact_prone_unusable','User reported stage4 re-cut still artifacted / not playable.'),
    ('BANK_17','validated_preview_clean','User-confirmed clean challenge preview (stage4 BANK_17).'),
    ('BANK_20','validated_menu_background_clean','User-confirmed clean main-menu background FMV / ambient loop (stage4 BANK_20).'),
    ('BANK_01','broken_unusable','User reported file did not open at all.'),
    ('BANK_07','broken_unusable','User reported file is broken / does not play cleanly.'),
    ('BANK_02','artifact_prone_unusable','User reported visible but artifacted / not playable.'),
    ('BANK_08','artifact_prone_unusable','User reported visible but artifacted / not playable.'),
    ('BANK_09','artifact_prone_unusable','User reported visible but artifacted / not playable.'),
    ('BANK_18','artifact_prone_unusable','User reported visible but artifacted / not playable.'),
]

def classify_bank(row):
    ms = row.get('manual_status_stage5')
    if pd.notna(ms):
        return {
            'validated_preview_clean':'clean_challenge_preview',
            'validated_menu_background_clean':'clean_menu_background',
            'broken_unusable':'rejected_broken',
            'artifact_prone_unusable':'rejected_artifact'
        }.get(ms, 'unclassified')
    st = row.get('stage4_status')
    if st == 'validated_preview':
        return 'clean_challenge_preview'
    if st == 'short_fragment_candidate':
        return 'short_fragment'
    if st in ('low_confidence_or_nonpreview','artifact_prone_nonpreview'):
        return 'likely_nonpreview_or_noise'
    if st in ('likely_preview','multistream_preview_candidate','extended_preview_candidate','needs_recut_review'):
        return 'unreviewed_or_ambiguous_candidate'
    return 'unclassified'

def resolve_branch_outcome(bank_class):
    if bank_class == 'clean_challenge_preview':
        return 'resolved_clean_challenge_preview'
    if bank_class == 'clean_menu_background':
        return 'resolved_clean_menu_background'
    if bank_class in ('rejected_artifact','rejected_broken'):
        return 'resolved_rejected_nonusable'
    if bank_class == 'likely_nonpreview_or_noise':
        return 'resolved_nonpreview_or_noise'
    if bank_class == 'short_fragment':
        return 'still_fragmentary'
    return 'still_unresolved'

def run():
    os.makedirs(OUT, exist_ok=True)
    bundle = os.path.join(OUT, 'curated_bundle')
    os.makedirs(bundle, exist_ok=True)

    bank = pd.read_csv(os.path.join(BASE4,'43fc6f_stage4_bank_catalog.csv'))
    pruned = pd.read_csv(os.path.join(BASE4,'43fc6f_stage4_pruned_prototype_rules.csv'))
    unres = pd.read_csv(os.path.join(BASE4,'43fc6f_stage4_unresolved_branches.csv'))

    manual_df = pd.DataFrame(MANUAL_UPDATES, columns=['bank_id','manual_status_stage5','manual_note_stage5'])
    manual_df.to_csv(os.path.join(OUT,'43fc6f_stage5_manual_validation_notes.csv'), index=False)

    bank5 = bank.merge(manual_df, on='bank_id', how='left')
    bank5['stage5_bank_class'] = bank5.apply(classify_bank, axis=1)
    bank5['usable_media'] = bank5['stage5_bank_class'].isin(['clean_challenge_preview','clean_menu_background'])

    all_branches = sorted(set(pruned['branch_family']) | set(unres['branch_family']))
    priority = {
        'clean_challenge_preview':0,
        'clean_menu_background':1,
        'unreviewed_or_ambiguous_candidate':2,
        'short_fragment':3,
        'likely_nonpreview_or_noise':4,
        'rejected_artifact':5,
        'rejected_broken':6,
        'unclassified':7,
    }

    selected_rows = []
    for branch_family in all_branches:
        cand = pruned[pruned['branch_family'] == branch_family].copy()
        if cand.empty:
            c = unres[unres['branch_family'] == branch_family].copy().merge(
                bank5[['bank_id','stage5_bank_class','manual_status_stage5','manual_note_stage5','stage4_status']],
                on='bank_id', how='left'
            )
            c['status_rank'] = 99
            c['candidate_file'] = np.nan
            c['thumbnail_file'] = np.nan
            c['selected_from'] = 'stage4_unresolved'
        else:
            c = cand.merge(
                bank5[['bank_id','stage5_bank_class','manual_status_stage5','manual_note_stage5']],
                on='bank_id', how='left'
            )
            c['selected_from'] = 'stage4_pruned'
        c['rank'] = c['stage5_bank_class'].map(priority).fillna(99)
        c = c.sort_values(['rank','status_rank','coverage_pct','hits'], ascending=[True, True, False, False])
        chosen = c.iloc[0].to_dict()
        selected_rows.append(chosen)

    branch5 = pd.DataFrame(selected_rows)
    branch5['stage5_branch_outcome'] = branch5['stage5_bank_class'].map(resolve_branch_outcome)

    curated_rules = branch5[branch5['stage5_branch_outcome'].isin([
        'resolved_clean_challenge_preview',
        'resolved_clean_menu_background'
    ])].copy()
    curated_rules['media_class'] = np.where(
        curated_rules['stage5_branch_outcome'].eq('resolved_clean_menu_background'),
        'menu_background_fmv',
        'challenge_preview_fmv'
    )
    curated_rules['selected_rule_note'] = np.where(
        curated_rules['media_class'].eq('menu_background_fmv'),
        'Manual stage5 validation: clean menu/background FMV.',
        'Manual stage5 validation: clean challenge preview FMV.'
    )
    curated_rules = curated_rules[[
        'branch_family','sig8','body_prefix','field_pos_dec','field_pos_hex',
        'bank_id','media_class','hits','branch_records','coverage_pct',
        'selected_rule_note','manual_note_stage5'
    ]]

    curated_banks = bank5[bank5['stage5_bank_class'].isin(['clean_challenge_preview','clean_menu_background'])].copy()
    curated_banks['media_class'] = curated_banks['stage5_bank_class'].map({
        'clean_challenge_preview':'challenge_preview_fmv',
        'clean_menu_background':'menu_background_fmv'
    })

    for fn in os.listdir(bundle):
        os.remove(os.path.join(bundle, fn))

    source_map = {
        'BANK_16': os.path.join(BASE2,'43fc6f_stage2_revised_pos20_modeabs_cand1_34670A3F_34B18A3F.pss'),
        'BANK_14': os.path.join(BASE2,'43fc6f_stage2_revised_pos164_modeabs_cand3_328C4A2B_32E14A2B.pss'),
        'BANK_17': os.path.join(BASE4,'review_bundle','43fc6f_stage4_BANK_17_likely_preview_34B5CA43_350B4A43.pss'),
        'BANK_20': os.path.join(BASE4,'review_bundle','43fc6f_stage4_BANK_20_extended_preview_candidate_39B31E38_3A389E38.pss'),
    }

    copied_rows = []
    for _, row in curated_banks.iterrows():
        bank_id = row['bank_id']
        src = source_map.get(bank_id)
        if src and os.path.exists(src):
            dst_name = f"43fc6f_stage5_{bank_id}_{row['media_class']}_{row['hex_start'][2:]}_{row['hex_end'][2:]}.pss"
            dst = os.path.join(bundle, dst_name)
            shutil.copy2(src, dst)
            copied_rows.append({
                'bank_id': bank_id,
                'media_class': row['media_class'],
                'source_file': src,
                'copied_file': dst_name,
                'hex_start': row['hex_start'],
                'hex_end': row['hex_end'],
                'duration_probe': row.get('duration_probe', np.nan)
            })
    copied_df = pd.DataFrame(copied_rows)

    bank5.to_csv(os.path.join(OUT,'43fc6f_stage5_bank_status_catalog.csv'), index=False)
    branch5.to_csv(os.path.join(OUT,'43fc6f_stage5_branch_resolution.csv'), index=False)
    curated_rules.to_csv(os.path.join(OUT,'43fc6f_stage5_curated_extractor_rules.csv'), index=False)
    curated_banks.to_csv(os.path.join(OUT,'43fc6f_stage5_curated_media_catalog.csv'), index=False)
    copied_df.to_csv(os.path.join(OUT,'43fc6f_stage5_curated_bundle_manifest.csv'), index=False)
    curated_banks[curated_banks['media_class'] == 'challenge_preview_fmv'].to_csv(
        os.path.join(OUT,'43fc6f_stage5_challenge_preview_catalog.csv'), index=False
    )

if __name__ == '__main__':
    run()
