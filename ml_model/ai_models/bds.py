import numpy as np
import joblib
import pandas as pd

ppd=r'C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed.csv'
ppd1=r'C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed1.csv'

store=r'C:\Users\saket\3-2Mini\secureflow\datasets\processed\dsbalance1.csv'

def dsbalance():
    df = pd.read_csv(ppd)
    df = df.dropna(subset=["Label"])
    df_attack = df[df["Label"] != "Normal"]
    print(df_attack["Label"].value_counts())
    df_balanced = df[df['Label'] == 'Normal'].sample(len(df_attack), random_state=42)
    df_balanced = pd.concat([df_balanced, df_attack])
    print(df_balanced["Label"].value_counts())
    # df_balanced["Label"] = df_balanced["Label"].astype("category").cat.codes
    df_balanced.to_csv(store, index=False)


if __name__ == "__main__":
    dsbalance()
