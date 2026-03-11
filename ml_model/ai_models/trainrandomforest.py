import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

from sklearn.metrics import confusion_matrix, accuracy_score


procesed_path=r"C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed.csv"
model_path="models/rf.plk"

def train_model():
    df=pd.read_csv(procesed_path)
    print(df.shape)
    df.dropna(inplace=True)
    print(df.shape)
    X=df.iloc[:,:-1]
    y=df.iloc[:,-1]
    # y.dropna(inplace=True)
    # print(y.isna().sum())
    
    x_train,x_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=0,stratify=y)
    model=RandomForestClassifier( n_estimators=700,
        max_depth=None,
        random_state=0,
        n_jobs=-1)
    model.fit(x_train,y_train)
    # with open(model_path,'')
    joblib.dump(model,model_path)

    
    y_pred = model.predict(x_test)
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(accuracy_score(y_test, y_pred))


if __name__ == "__main__":
    train_model()