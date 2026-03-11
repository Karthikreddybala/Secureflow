import pandas as pd

# Check column names in one of the CSV files
df = pd.read_csv('datasets/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', nrows=0)
print("Available columns:")
for i, col in enumerate(df.columns):
    print(f"{i+1:2d}. {col}")

print(f"\nTotal columns: {len(df.columns)}")

# Check which DROP_COLS actually exist
DROP_COLS = [
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min", 
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Std",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Std",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Down/Up Ratio",
    "CWE Flag Count",
    "ECE Flag Count",
    "URG Flag Count",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Destination Port",
]

print("\nChecking DROP_COLS:")
existing_cols = []
missing_cols = []
for col in DROP_COLS:
    if col in df.columns:
        existing_cols.append(col)
    else:
        missing_cols.append(col)

print(f"\nExisting in DROP_COLS: {len(existing_cols)}")
for col in existing_cols:
    print(f"  ✓ {col}")

print(f"\nMissing from DROP_COLS: {len(missing_cols)}")
for col in missing_cols:
    print(f"  ✗ {col}")