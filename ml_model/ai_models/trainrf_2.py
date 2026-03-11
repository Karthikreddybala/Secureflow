import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os
import glob
import numpy as np
from sklearn.preprocessing import StandardScaler

from sklearn.metrics import confusion_matrix, accuracy_score


raw_data_path = r'C:\Users\saket\3-2Mini\secureflow\datasets\raw'

ATTACK_MAPPING = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS",
    "DDoS": "DDoS",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Infiltration": "Infiltration"
}



model_path="models/rf2.plk"
def predata():
    all_files = glob.glob(os.path.join(raw_data_path, '*.csv'))
    dfs=[]
    for file in all_files:
        df=pd.read_csv(file)
        dfs.append(df)
    df=pd.concat(dfs,ignore_index=True)
    if ' Label' in df.columns:
            df[" Label"] = df[" Label"].map(ATTACK_MAPPING)
    else:
        print(f"Warning: Neither 'Lable' nor 'Label' column found in dataset")
    return df

def train_model():
    # predata() already returns a DataFrame, so call it directly
    df = predata()
    df.dropna(inplace=True)
    X=df.iloc[:,:-1]
    y=df.iloc[:,-1]
    # y.dropna(inplace=True)
    # print(y.isna().sum())
    
    x_train,x_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)
    sc = StandardScaler()
    x_train.replace([np.inf, -np.inf], np.nan, inplace=True)
    x_test.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Fill NaNs with 0 (or median/mean if you prefer)
    x_train.fillna(0, inplace=True)
    x_test.fillna(0, inplace=True)
    x_train = sc.fit_transform(x_train)
    x_test = sc.transform(x_test)
    model=RandomForestClassifier( n_estimators=500,
        # class_weight="balanced",
        n_jobs=-1,
        max_depth=None,
        random_state=42)
    model.fit(x_train,y_train)
    # with open(model_path,'')
    joblib.dump(model,model_path)

    
    y_pred = model.predict(x_test)
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(accuracy_score(y_test, y_pred))


if __name__ == "__main__":
    train_model()
