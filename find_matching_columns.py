import pandas as pd

# Read the header to see all available columns
df = pd.read_csv('datasets/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', nrows=0)
columns = list(df.columns)

# Define the concepts you want to drop and search for similar column names
search_terms = [
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
    "Destination Port"
]

print("Looking for matching columns:")
print("=" * 50)

for search_term in search_terms:
    # Convert to lowercase and remove spaces for better matching
    search_lower = search_term.lower().replace(" ", "")
    
    matches = []
    for col in columns:
        col_lower = col.lower().replace(" ", "")
        if search_lower in col_lower or col_lower in search_lower:
            matches.append(col)
    
    if matches:
        print(f"✓ '{search_term}' -> Found: {matches}")
    else:
        print(f"✗ '{search_term}' -> Not found")

print("\nAll available columns:")
for i, col in enumerate(columns):
    print(f"{i+1:2d}.{col}")