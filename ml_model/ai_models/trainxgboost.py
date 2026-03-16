"""
XGBoost Classifier — SecureFlow IDS
Advantages over Random Forest:
  - 5-10x faster training
  - Much smaller model file (~5–10 MB vs 380 MB)
  - Usually equal or better accuracy on tabular network data
  - Built-in class weighting via scale_pos_weight / sample_weight

Best practices applied:
  - Train/test split BEFORE any scaling (no data leakage)
  - StandardScaler fit on train only
  - LabelEncoder for XGBoost's integer label requirement
  - Multi-class classification with softmax
  - Full per-class classification report
  - Saves model, scaler, label encoder for inference
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight

try:
    import xgboost as xgb
except ImportError:
    raise ImportError(
        "XGBoost is not installed. Run:  pip install xgboost"
    )

# ── Paths ──────────────────────────────────────────────────────────────────────
PROCESSED_PATH = r"C:\Users\saket\3-2Mini\datasets\processed\processed_new.csv"
MODEL_DIR      = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH     = os.path.join(MODEL_DIR, "xgb.pkl")
SCALER_PATH    = os.path.join(MODEL_DIR, "scaler_xgb.pkl")
ENCODER_PATH   = os.path.join(MODEL_DIR, "label_encoder_xgb.pkl")


def train_model():
    print("=" * 60)
    print("  XGBoost Training — SecureFlow IDS")
    print("=" * 60)

    # ── 1. Load data ──────────────────────────────────────────────
    print("\n[1/6] Loading processed data...")
    df = pd.read_csv(PROCESSED_PATH)
    df.dropna(subset=['Label'], inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    print(f"  Shape: {df.shape}")
    print("  Label distribution:\n", df['Label'].value_counts().to_string())

    X = df.drop(columns=['Label'])
    y = df['Label']

    # ── 2. Encode labels ──────────────────────────────────────────
    print("\n[2/6] Encoding labels...")
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    print(f"  Classes: {list(le.classes_)}")
    n_classes = len(le.classes_)

    # ── 3. Train / test split ─────────────────────────────────────
    print("\n[3/6] Splitting data (80/20 stratified)...")
    x_train, x_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )
    print(f"  Train: {x_train.shape[0]}  |  Test: {x_test.shape[0]}")

    # ── 4. Scale features (fit on train ONLY) ─────────────────────
    print("\n[4/6] Scaling features...")
    scaler    = StandardScaler()
    x_train_s = scaler.fit_transform(x_train)
    x_test_s  = scaler.transform(x_test)

    # ── 5. Train XGBoost ──────────────────────────────────────────
    print("\n[5/6] Training XGBoost...")

    # Sample weights replicate class_weight="balanced" for XGBoost
    sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

    model = xgb.XGBClassifier(
        n_estimators=500,          # number of boosting rounds
        max_depth=8,               # depth of each tree
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='mlogloss',
        objective='multi:softprob',
        num_class=n_classes,
        early_stopping_rounds=20,  # XGBoost 3.x: back in constructor, NOT in fit()
        n_jobs=-1,
        random_state=42,
        tree_method='hist',
        verbosity=1,
    )

    model.fit(
        x_train_s, y_train,
        sample_weight=sample_weights,
        eval_set=[(x_test_s, y_test)],
        verbose=50,
    )

    # ── 6. Evaluate ───────────────────────────────────────────────
    print("\n[6/6] Evaluating...")
    # multi:softprob returns class indices directly from predict()
    y_pred     = model.predict(x_test_s).astype(int)
    y_pred_lbl = le.inverse_transform(y_pred)
    y_test_lbl = le.inverse_transform(y_test)

    acc = accuracy_score(y_test_lbl, y_pred_lbl)
    print(f"\n  Overall Accuracy : {acc:.4f} ({acc*100:.2f}%)")
    best_it = getattr(model, 'best_iteration', 'N/A')
    print(f"  Best iteration   : {best_it}")
    print("\n  Per-class Report:")
    print(classification_report(y_test_lbl, y_pred_lbl, digits=4))

    cm = confusion_matrix(y_test_lbl, y_pred_lbl, labels=le.classes_)
    cm_df = pd.DataFrame(cm, index=le.classes_, columns=le.classes_)
    print("  Confusion Matrix:\n", cm_df.to_string())

    # ── Save ──────────────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODER_PATH)
    print(f"\n  Model         saved → {MODEL_PATH}")
    print(f"  Scaler        saved → {SCALER_PATH}")
    print(f"  Label Encoder saved → {ENCODER_PATH}")
    print("\nDone ✓")


if __name__ == "__main__":
    train_model()
