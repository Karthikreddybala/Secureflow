"""
Random Forest Classifier v2 — SecureFlow IDS (direct from raw CSVs)
Same best-practice fixes as trainrandomforest.py but reads raw data directly.
"""

import os
import glob
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ── Paths ──────────────────────────────────────────────────────────────────────
RAW_DATA_PATH = r'C:\Users\saket\3-2Mini\secureflow\datasets\raw'
MODEL_DIR     = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH    = os.path.join(MODEL_DIR, "rf2.pkl")
SCALER_PATH   = os.path.join(MODEL_DIR, "scaler_rf2.pkl")

ATTACK_MAPPING = {
    "BENIGN":                   "Normal",
    "DoS Hulk":                 "DoS",
    "DoS GoldenEye":            "DoS",
    "DoS slowloris":            "DoS",
    "DoS Slowhttptest":         "DoS",
    "DDoS":                     "DDoS",
    "FTP-Patator":              "BruteForce",
    "SSH-Patator":              "BruteForce",
    "Web Attack - XSS":         "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "PortScan":                 "PortScan",
    "Bot":                      "Botnet",
    "Infiltration":             "Infiltration",
    "Heartbleed":               "Heartbleed",
}


def predata() -> pd.DataFrame:
    all_files = glob.glob(os.path.join(RAW_DATA_PATH, '*.csv'))
    if not all_files:
        raise FileNotFoundError(f"No CSV files in: {RAW_DATA_PATH}")

    dfs = []
    for file in all_files:
        df = pd.read_csv(file, low_memory=False)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        label_col = ' Label' if ' Label' in df.columns else ('Label' if 'Label' in df.columns else None)
        if label_col is None:
            print(f"  WARNING: No Label column in {file}, skipping.")
            continue

        df[label_col] = df[label_col].str.strip().map(ATTACK_MAPPING)
        df.dropna(subset=[label_col], inplace=True)
        if label_col != 'Label':
            df.rename(columns={label_col: 'Label'}, inplace=True)
        dfs.append(df)

    if not dfs:
        raise ValueError("No valid DataFrames loaded.")

    result = pd.concat(dfs, ignore_index=True)
    print(f"Combined shape: {result.shape}")
    print("Label distribution:\n", result['Label'].value_counts().to_string())
    return result


def train_model():
    print("=" * 60)
    print("  Random Forest v2 Training — SecureFlow IDS")
    print("=" * 60)

    # ── 1. Load ───────────────────────────────────────────────────
    print("\n[1/5] Loading raw data...")
    df = predata()
    df.dropna(inplace=True)

    X = df.drop(columns=['Label'])
    y = df['Label']

    # ── 2. Split ──────────────────────────────────────────────────
    print("\n[2/5] Train/test split...")
    x_train, x_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {x_train.shape[0]}  |  Test: {x_test.shape[0]}")

    # ── 3. Scale (fit on train only) ──────────────────────────────
    print("\n[3/5] Scaling features...")
    scaler = StandardScaler()
    x_train_s = scaler.fit_transform(x_train)
    x_test_s  = scaler.transform(x_test)

    # ── 4. Train ──────────────────────────────────────────────────
    print("\n[4/5] Training Random Forest v2...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(x_train_s, y_train)

    # ── 5. Evaluate ───────────────────────────────────────────────
    print("\n[5/5] Evaluating...")
    y_pred = model.predict(x_test_s)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n  Overall Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print("\n  Per-class Report:")
    print(classification_report(y_test, y_pred, digits=4))

    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    cm_df = pd.DataFrame(cm, index=model.classes_, columns=model.classes_)
    print("  Confusion Matrix:\n", cm_df.to_string())

    # ── Save ──────────────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\n  Model  saved → {MODEL_PATH}")
    print(f"  Scaler saved → {SCALER_PATH}")
    print("\nDone ✓")


if __name__ == "__main__":
    train_model()
