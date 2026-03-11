import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix, accuracy_score

# load the saved random forest model (saved with joblib in train_randomforest)
try:
    model = joblib.load('C:\\Users\\saket\\3-2Mini\\secureflow\\ml_model\\ai_models\\models\\isolation_forest.pkl')
except Exception as e:
    raise RuntimeError(f"could not load model from C:\\Users\\saket\\3-2Mini\\secureflow\\ml_model\\ai_models\\models\\isolation_forest.pkl: {e}")
procesed_path=r"C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed.csv"
def test():
    df = pd.read_csv(procesed_path)
    df.dropna(inplace=True)
    df_test_iso = df[df["Label"] != "Normal"]
    X_test_iso = df_test_iso.drop(columns=["Label"])
    
    iso_preds = model.predict(X_test_iso)

    # Convert Isolation Forest output
    # -1 = anomaly → attack
    #  1 = normal
    iso_preds = [-1 if v == -1 else 1 for v in iso_preds]

    # Build true labels as: normal=1, attack=-1
    true = [-1] * len(iso_preds)

    print(classification_report(true, iso_preds))


if __name__ == "__main__":
    test()