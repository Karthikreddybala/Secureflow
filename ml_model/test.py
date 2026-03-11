import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score

# load the saved random forest model (saved with joblib in train_randomforest)
try:
    model = joblib.load('models/rf.plk')
except Exception as e:
    raise RuntimeError(f"could not load model from models/rf.plk: {e}")
procesed_path=r"C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed.csv"
def test():
    df = pd.read_csv(procesed_path)
    df.dropna(inplace=True)
    X = df.iloc[:, :-1]
    y = df.iloc[:, -1]

    x_train, x_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    y_pred = model.predict(x_test)
    cm = confusion_matrix(y_test, y_pred)
    print("Confusion matrix:\n", cm)
    print("Accuracy:", accuracy_score(y_test, y_pred))


if __name__ == "__main__":
    test()