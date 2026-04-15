#!/usr/bin/env python3
import pandas as pd
from pathlib import Path

BASE = Path("/mnt/data")
OUT = BASE / "stage85_bundle" / "manifests"

def main():
    results = pd.read_csv(OUT / "stage85_selector_transfer_results.csv")
    print(results.groupby("status").size())

if __name__ == "__main__":
    main()
