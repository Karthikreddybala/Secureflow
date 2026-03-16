import pandas as pd
import numpy as np
import glob
import json
import os

# ── Paths ──────────────────────────────────────────────────────────────────────
raw_data_path       = r'C:\Users\saket\3-2Mini\datasets\raw'
processed_data_path = r'C:\Users\saket\3-2Mini\datasets\processed\processed_new.csv'
feature_list_path   = r'C:\Users\saket\3-2Mini\secureflow\ml_model\ml_core\feature_list1.json'

# NOTE: StandardScaler is intentionally NOT applied here.
#       Scaling must be fit on training data only (inside each training script)
#       to prevent data leakage between train and test splits.

# ── Attack label normalisation ─────────────────────────────────────────────────
ATTACK_MAPPING = {
    "BENIGN":                   "Normal",
    "DoS Hulk":                 "DoS",
    "DoS GoldenEye":            "DoS",
    "DoS slowloris":            "DoS",
    "DoS Slowhttptest":         "DoS",
    "DDoS":                     "DDoS",
    "FTP-Patator":              "BruteForce",
    "SSH-Patator":              "BruteForce",
    "Web Attack \x96 XSS":      "WebAttack",
    "Web Attack - XSS":         "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "PortScan":                 "PortScan",
    "Bot":                      "Botnet",
    "Infiltration":             "Infiltration",
    "Heartbleed":               "Heartbleed",
}

# ── Columns to drop ────────────────────────────────────────────────────────────
# Removed " Destination Port" from DROP_COLS — it is a high-signal feature
# for PortScan, SSH-Patator, FTP-Patator and should be kept.
DROP_COLS = [
    # Broken / corrupted fields
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",

    # Redundant packet-length stats (keep Mean only)
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Std",
    "Bwd Packet Length Max",
    " Bwd Packet Length Min",
    " Bwd Packet Length Std",
    " Min Packet Length",
    " Max Packet Length",

    # Bulk features (always zero in CICIDS-2017)
    "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",

    # Subflow duplicates (same info as Tot_Fwd/Bwd_Pkts)
    "Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",

    # Low-signal / always-zero flags
    " Down/Up Ratio",
    " CWE Flag Count",
    " ECE Flag Count",
    " URG Flag Count",

    # Redundant IAT extremes (keep Mean + Std)
    " Flow IAT Max",
    " Flow IAT Min",
    " Fwd IAT Max",
    " Fwd IAT Min",
    " Bwd IAT Max",
    " Bwd IAT Min",

    # Duplicate header-length column
    " Fwd Header Length.1",
]


def load_data() -> pd.DataFrame:
    """Read and concatenate all raw CSV files, drop unwanted columns, clean NaNs."""
    all_files = glob.glob(os.path.join(raw_data_path, '*.csv'))
    if not all_files:
        raise FileNotFoundError(f"No CSV files found in: {raw_data_path}")

    dfs = []
    for f in all_files:
        df = pd.read_csv(f, low_memory=False)
        print(f"  Loaded {f}  shape={df.shape}")

        # Drop unwanted columns (only those that exist)
        cols_to_drop = [c for c in DROP_COLS if c in df.columns]
        df.drop(columns=cols_to_drop, inplace=True)

        # Replace inf values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # Normalise label column
        label_col = None
        if ' Label' in df.columns:
            label_col = ' Label'
        elif 'Label' in df.columns:
            label_col = 'Label'

        if label_col is None:
            print(f"  WARNING: No 'Label' column in {f} — skipping file.")
            continue

        df[label_col] = df[label_col].map(ATTACK_MAPPING)
        unmapped = df[label_col].isna().sum()
        if unmapped:
            print(f"  WARNING: {unmapped} rows had unmapped labels in {f} — dropping them.")
            df.dropna(subset=[label_col], inplace=True)

        # Rename to canonical "Label"
        if label_col != 'Label':
            df.rename(columns={label_col: 'Label'}, inplace=True)

        dfs.append(df)
        print(f"  After clean  shape={df.shape}")

    if not dfs:
        raise ValueError("No valid DataFrames loaded. Check file paths and column names.")

    dataset = pd.concat(dfs, ignore_index=True)
    print(f"\nFinal dataset shape: {dataset.shape}")
    print("Label distribution:\n", dataset['Label'].value_counts())
    return dataset


def preprocessing():
    """Save raw (unscaled) processed CSV + feature list."""
    dataset = load_data()

    # Put Label last
    cols = [c for c in dataset.columns if c != 'Label'] + ['Label']
    dataset = dataset[cols]

    # Ensure output directory exists
    os.makedirs(os.path.dirname(processed_data_path), exist_ok=True)
    dataset.to_csv(processed_data_path, index=False)
    print(f"\nProcessed data saved to: {processed_data_path}")

    # Save feature list (all columns except Label)
    feature_cols = [c for c in dataset.columns if c != 'Label']
    os.makedirs(os.path.dirname(feature_list_path), exist_ok=True)
    with open(feature_list_path, 'w') as f:
        json.dump(feature_cols, f)
    print(f"Feature list saved to:   {feature_list_path}  ({len(feature_cols)} features)")


if __name__ == "__main__":
    preprocessing()