from pathlib import Path
import csv, json, subprocess, hashlib, zlib

# Rebuild Stage 35 adaptive expansions from Stage 34 scout windows.
TNG = Path('/mnt/data/TNG_rebuilt/TNG.000')
STAGE34 = Path('/mnt/data/semantic_pass_cross_domain_stage34/manifests/43fc85_stage34_candidate_exports.csv')
OUT = Path('/mnt/data/semantic_pass_cross_domain_stage35')
