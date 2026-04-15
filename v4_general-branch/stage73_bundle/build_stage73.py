from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent
MAN = BASE / "manifests"
registry = pd.read_csv(MAN / "stage73_fmv_registry_consolidated.csv")
print(registry[['pak_path','registry_status','decoder_class','tng_pack_start_hex']].to_string(index=False))
