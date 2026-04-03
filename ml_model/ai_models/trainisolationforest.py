"""
Isolation Forest — SecureFlow IDS
Trains on BENIGN/Normal traffic only to detect anomalies.
Fixes:
  - Contamination calculated from real data ratio (not hardcoded)
  - Uses unscaled processed.csv + fits its own scaler on normal data only
  - Saves both model and scaler for inference
"""

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

# ── Paths ──────────────────────────────────────────────────────────────────────
PROCESSED_PATH = r"C:\Users\saket\3-2Mini\datasets\processed\processed_new.csv"
MODEL_DIR      = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH     = os.path.join(MODEL_DIR, "iso_forest_new.pkl")
SCALER_PATH    = os.path.join(MODEL_DIR, "scaler_iso_new.pkl")


def train_isolation_forest():
    print("=" * 60)
    print("  Isolation Forest Training — SecureFlow IDS")
    print("=" * 60)

    # ── 1. Load data ──────────────────────────────────────────────
    print("\n[1/4] Loading processed data...")
    df = pd.read_csv(PROCESSED_PATH)
    df.dropna(subset=['Label'], inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    print(f"  Shape: {df.shape}")
    print("  Label distribution:\n", df['Label'].value_counts().to_string())

    # ── 2. Compute real contamination ratio ───────────────────────
    n_total  = len(df)
    n_attack = (df['Label'] != 'Normal').sum()
    contamination = round(min(n_attack / n_total, 0.5), 4)
    print(f"\n[2/4] Real contamination ratio: {contamination:.4f} "
          f"({n_attack:,} attack / {n_total:,} total)")

    # ── 3. Fit scaler and model on Normal traffic only ────────────
    df_normal = df[df['Label'] == 'Normal'].drop(columns=['Label'])
    print(f"\n[3/4] Training on {len(df_normal):,} Normal samples...")

    scaler   = StandardScaler()
    X_normal = scaler.fit_transform(df_normal)

    model = IsolationForest(
        n_estimators=400,
        contamination=contamination,
        max_samples="auto",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_normal)

    # ── 4. Quick validation on full dataset ───────────────────────
    print("\n[4/4] Validating on full dataset...")
    X_all = df.drop(columns=['Label'])
    X_all_s = scaler.transform(X_all)

    preds = model.predict(X_all_s)       # +1 = normal, -1 = anomaly
    y_true = (df['Label'] != 'Normal').astype(int)   # 1 = attack
    y_pred = (preds == -1).astype(int)               # -1 → anomaly → attack

    print(classification_report(
        y_true, y_pred,
        target_names=['Normal', 'Attack'],
        digits=4
    ))

    # ── Save ──────────────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"  Isolation Forest saved → {MODEL_PATH}")
    print(f"  Scaler saved           → {SCALER_PATH}")
    print("\nDone ✓")


if __name__ == "__main__":
    train_isolation_forest()