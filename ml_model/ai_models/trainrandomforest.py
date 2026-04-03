"""
Random Forest Classifier — SecureFlow IDS
Best-practice pipeline:
  - Scaler fit on train split only (no data leakage)
  - class_weight="balanced" for imbalanced CICIDS-2017
  - Reduced n_estimators + capped max_depth (smaller model, better generalisation)
  - Saves scaler + model for use in inference engine
  - Full per-class classification report
"""

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# ── Paths ──────────────────────────────────────────────────────────────────────
PROCESSED_PATH = r"C:\Users\saket\3-2Mini\datasets\processed\processed_new.csv"
MODEL_DIR      = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH     = os.path.join(MODEL_DIR, "rf_new.pkl")
SCALER_PATH    = os.path.join(MODEL_DIR, "scaler_rf_new.pkl")


def train_model():
    print("=" * 60)
    print("  Random Forest Training — SecureFlow IDS")
    print("=" * 60)

    # ── 1. Load data ──────────────────────────────────────────────
    print("\n[1/5] Loading processed data...")
    df = pd.read_csv(PROCESSED_PATH)
    df.dropna(inplace=True)
    print(f"  Shape: {df.shape}")
    print("  Label distribution:\n", df['Label'].value_counts().to_string())

    X = df.drop(columns=['Label'])
    y = df['Label']

    # ── 2. Train / test split (stratified) ────────────────────────
    print("\n[2/5] Splitting data (80/20 stratified)...")
    x_train, x_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train size: {x_train.shape[0]}  |  Test size: {x_test.shape[0]}")

    # ── 3. Scale features (fit on train ONLY) ─────────────────────
    print("\n[3/5] Scaling features...")
    scaler = StandardScaler()
    x_train_s = scaler.fit_transform(x_train)
    x_test_s  = scaler.transform(x_test)      # no fit on test data

    # ── 4. Train Random Forest ────────────────────────────────────
    print("\n[4/5] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=300,          # 300 trees — good balance of speed vs accuracy
        max_depth=20,              # cap depth to reduce overfitting & model size
        min_samples_leaf=5,        # require at least 5 samples per leaf
        class_weight="balanced",   # compensate for Normal >> Attack imbalance
        n_jobs=-1,
        random_state=42,
    )
    model.fit(x_train_s, y_train)

    # ── 5. Evaluate ───────────────────────────────────────────────
    print("\n[5/5] Evaluating...")
    y_pred = model.predict(x_test_s)

    acc = accuracy_score(y_test, y_pred)
    print(f"\n  Overall Accuracy : {acc:.4f} ({acc*100:.2f}%)")
    print("\n  Per-class Report:")
    print(classification_report(y_test, y_pred, digits=4))

    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    cm_df = pd.DataFrame(cm, index=model.classes_, columns=model.classes_)
    print("  Confusion Matrix:\n", cm_df.to_string())

    # ── Save model + scaler ───────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\n  Model  saved → {MODEL_PATH}")
    print(f"  Scaler saved → {SCALER_PATH}")
    print("\nDone ✓")


if __name__ == "__main__":
    train_model()