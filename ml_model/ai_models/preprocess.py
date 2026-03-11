import pandas as pd
import numpy as np
import glob
import json
from sklearn.preprocessing import StandardScaler
import os

# Use relative path for better portability
raw_data_path = r'C:\Users\saket\3-2Mini\secureflow\datasets\raw'
processed_data_path = r'C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed.csv'
feature_list_path = r'C:\Users\saket\3-2Mini\secureflow\ml_model\ml_core\feature_list.json'

ATTACK_MAPPING = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS",
    "DDoS": "DDoS",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Infiltration": "Infiltration"
}

DROP_COLS = [
    # Broken / corrupted fields
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",

    # Duplicate / redundant packet-length stats
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Std",
    "Bwd Packet Length Max",
    " Bwd Packet Length Min",
    " Bwd Packet Length Std",

    # Redundant packet summary stats
    " Min Packet Length",
    " Max Packet Length",
    " Fwd Packet Length Std",  # Using Fwd version to avoid conflict
    " Bwd Packet Length Std",   # Using Bwd version to avoid conflict

    # Bulk features (always zero in CICIDS-2017)
    "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",

    # Subflow duplicates (same info as Tot_Fwd_Pkts, Tot_Bwd_Pkts)
    "Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",

    # Useless ratio
    " Down/Up Ratio",

    # Flags that are nearly always zero (no signal)
    " CWE Flag Count",
    " ECE Flag Count",
    " URG Flag Count",

    # Excessive IAT features (keep only Mean + Std)
    " Flow IAT Max",
    " Flow IAT Min",
    " Fwd IAT Max",
    " Fwd IAT Min",
    " Bwd IAT Max",
    " Bwd IAT Min",
    " Destination Port",
]

def load_data():
    # Fix: Add proper path separator between directory and pattern
    all_files = glob.glob(os.path.join(raw_data_path, '*.csv'))
    # print(f"Found {len(all_files)} CSV files:")
    # for f in all_files:
    #     print(f"  - {f}")
    
    dfs = []
    for f in all_files:
        df = pd.read_csv(f)
        print(f"  Shape: {df.shape}")
        for c in df.columns:
            if c in DROP_COLS:
                df.drop(c, axis=1, inplace=True)
        print(f"  Shape: {df.shape}")
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Fix: Handle case where 'Label' column might not exist
        if ' Label' in df.columns:
            df[" Label"] = df[" Label"].map(ATTACK_MAPPING)
        else:
            print(f"Warning: Neither 'Lable' nor 'Label' column found in {f}")
            continue
            
        dfs.append(df)
    
    if not dfs:
        raise ValueError("No valid dataframes loaded. Check file paths and column names.")
    
    dataset = pd.concat(dfs, ignore_index=True)
    print(f"Final dataset shape: {dataset.shape}")
    return dataset

def preprocessing():
    # Fix: load_data() already returns a DataFrame, don't call pd.read_csv on it
    dataset = load_data()
    X = dataset.iloc[:, :-1]
    Y = dataset.iloc[:, -1]
    
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)
    process_data = pd.DataFrame(X_s, columns=X.columns)
    process_data["Label"] = Y
    
    # Ensure processed directory exists
    os.makedirs(os.path.dirname(processed_data_path), exist_ok=True)
    process_data.to_csv(processed_data_path, index=False)
    # print(f"Processed data saved to: {processed_data_path}")

    # Fix: Remove extra quote in JSON file path
    os.makedirs(os.path.dirname(feature_list_path), exist_ok=True)
    with open(feature_list_path, "w") as f:
        json.dump(list(X.columns), f)
    # print(f"Feature list saved to: {feature_list_path}")
    
if __name__ == "__main__":
    preprocessing()