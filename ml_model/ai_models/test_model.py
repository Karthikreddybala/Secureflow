"""
Model Test Script — SecureFlow IDS
Quickly tests any trained model against the processed dataset.

Usage:
    python test_model.py                  # tests XGBoost (default)
    python test_model.py rf               # tests Random Forest
    python test_model.py iso              # tests Isolation Forest

What it does:
  - Loads 5000 random samples from processed.csv
  - Scales them with the model-specific scaler
  - Runs prediction and prints results
  - For RF/XGBoost: shows per-class accuracy
  - For IsoForest: shows anomaly detection summary
"""

import sys
import os
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import classification_report, accuracy_score

# ── Paths ──────────────────────────────────────────────────────────────────────
PROCESSED_PATH = r"C:\Users\saket\3-2Mini\datasets\processed\processed_new.csv"
MODEL_DIR      = os.path.join(os.path.dirname(__file__), "models")


def test_xgboost(df: pd.DataFrame):
    model_path   = os.path.join(MODEL_DIR, "xgb.pkl")
    scaler_path  = os.path.join(MODEL_DIR, "scaler_xgb.pkl")
    encoder_path = os.path.join(MODEL_DIR, "label_encoder_xgb.pkl")

    for p in [model_path, scaler_path, encoder_path]:
        if not os.path.exists(p):
            print(f"  ❌  File not found: {p}")
            print("     Run  python trainxgboost.py  first.")
            return

    print("  Loading XGBoost model...")
    model  = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    le     = joblib.load(encoder_path)

    X = df.drop(columns=['Label'])
    y_true = df['Label'].values

    X_s    = scaler.transform(X)
    y_pred = model.predict(X_s)
    y_pred_lbl = le.inverse_transform(y_pred)

    acc = accuracy_score(y_true, y_pred_lbl)
    print(f"\n  ✅ XGBoost Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print("\n  Per-class report:")
    print(classification_report(y_true, y_pred_lbl, digits=4))

    print("\n  Sample predictions (first 20 rows):")
    sample_df = pd.DataFrame({
        'True Label' : y_true[:20],
        'Predicted'  : y_pred_lbl[:20],
        'Correct?'   : ['✓' if a == b else '✗' for a, b in zip(y_true[:20], y_pred_lbl[:20])]
    })
    print(sample_df.to_string(index=False))


def test_random_forest(df: pd.DataFrame):
    model_path  = os.path.join(MODEL_DIR, "rf.pkl")
    scaler_path = os.path.join(MODEL_DIR, "scaler_rf.pkl")

    # fallback to old pickle extension
    if not os.path.exists(model_path):
        model_path = os.path.join(MODEL_DIR, "rf.plk")
    if not os.path.exists(scaler_path):
        print(f"  ❌  Scaler not found: {scaler_path}")
        print("     Run  python trainrandomforest.py  first.")
        return

    print("  Loading Random Forest model...")
    model  = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    X = df.drop(columns=['Label'])
    y_true = df['Label'].values

    X_s    = scaler.transform(X)
    y_pred = model.predict(X_s)

    acc = accuracy_score(y_true, y_pred)
    print(f"\n  ✅ Random Forest Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print("\n  Per-class report:")
    print(classification_report(y_true, y_pred, digits=4))

    print("\n  Sample predictions (first 20 rows):")
    sample_df = pd.DataFrame({
        'True Label' : y_true[:20],
        'Predicted'  : y_pred[:20],
        'Correct?'   : ['✓' if a == b else '✗' for a, b in zip(y_true[:20], y_pred[:20])]
    })
    print(sample_df.to_string(index=False))


def test_isolation_forest(df: pd.DataFrame):
    model_path  = os.path.join(MODEL_DIR, "iso_forest.pkl")
    scaler_path = os.path.join(MODEL_DIR, "scaler_iso.pkl")

    if not os.path.exists(model_path):
        # fallback
        model_path = os.path.join(MODEL_DIR, "iso_scale.pkl")
    if not os.path.exists(scaler_path):
        print(f"  ❌  Scaler not found: {scaler_path}")
        print("     Run  python trainisolationforest.py  first.")
        return

    print("  Loading Isolation Forest model...")
    model  = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    X      = df.drop(columns=['Label'])
    y_true = (df['Label'] != 'Normal').astype(int)    # 1 = attack

    X_s    = scaler.transform(X)
    preds  = model.predict(X_s)                       # +1 normal, -1 anomaly
    y_pred = (preds == -1).astype(int)                # anomaly → attack

    n_detected = y_pred.sum()
    n_actual   = y_true.sum()
    print(f"\n  ✅ Isolation Forest Results ({len(df)} samples):")
    print(f"     Actual attacks in sample : {n_actual}")
    print(f"     Anomalies flagged         : {n_detected}")

    from sklearn.metrics import classification_report as cr
    print("\n  Binary report (Normal vs Attack):")
    print(cr(y_true, y_pred, target_names=['Normal', 'Attack'], digits=4))


def main():
    model_type = sys.argv[1].lower() if len(sys.argv) > 1 else "xgb"

    print("=" * 60)
    print(f"  SecureFlow — Model Test  [{model_type.upper()}]")
    print("=" * 60)

    # ── Load a sample from processed.csv ─────────────────────────
    if not os.path.exists(PROCESSED_PATH):
        print(f"❌  Processed CSV not found: {PROCESSED_PATH}")
        print("   Run python preprocess.py first.")
        sys.exit(1)

    print(f"\n  Loading 5,000 random samples from processed.csv...")
    df = pd.read_csv(PROCESSED_PATH)
    df.dropna(subset=['Label'], inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Stratified sample so all classes are represented
    sample_dfs = []
    for label, group in df.groupby('Label'):
        n = min(len(group), max(1, int(5000 * len(group) / len(df))))
        sample_dfs.append(group.sample(n=n, random_state=42))
    sample = pd.concat(sample_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"  Sample shape: {sample.shape}")
    print("  Label distribution:\n", sample['Label'].value_counts().to_string())

    # ── Run the right test ────────────────────────────────────────
    print()
    if model_type in ("xgb", "xgboost"):
        test_xgboost(sample)
    elif model_type in ("rf", "randomforest", "random_forest"):
        test_random_forest(sample)
    elif model_type in ("iso", "isolation", "isoforest"):
        test_isolation_forest(sample)
    else:
        print(f"  Unknown model type: {model_type}")
        print("  Use: xgb | rf | iso")


if __name__ == "__main__":
    main()
