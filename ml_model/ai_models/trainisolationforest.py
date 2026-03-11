import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import joblib
import os

PROCESSED_PATH = r"C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed.csv"
MODEL_PATH = "models/iso_scale.pkl"

def train_isolation_forest():
    df=pd.read_csv(PROCESSED_PATH)
    df_normal = df[df["Label"] == "Normal"].drop(columns=["Label"])
    model=IsolationForest(
        n_estimators=400,
        contamination=0.03,
        max_samples="auto",
        n_jobs=-1,
        random_state=42
    )
    model.fit(df_normal)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)

if __name__ == "__main__":
    train_isolation_forest()