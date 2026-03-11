# data_prep

import pandas as pd
import numpy as np
import glob
import json
from sklearn.preprocessing import StandardScaler
import os

# Use relative path for better portability
raw_data_path = r'C:\Users\saket\3-2Mini\secureflow\datasets\raw\Monday-WorkingHours.pcap_ISCX.csv'
processed_data_path = r'C:\Users\saket\3-2Mini\secureflow\datasets\processed\Mon_processed.csv'
# feature_list_path = r'C:\Users\saket\3-2Mini\secureflow\ml_model\ml_core\feature_list.json'

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

DROP_COLS = [
    # Broken / corrupted fields
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",

    # Duplicate / redundant packet-length stats
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Std",
    "Bwd Packet Length Max",
    " Bwd Packet Length Min",
    " Bwd Packet Length Std",

    # Redundant packet summary stats
    " Min Packet Length",
    " Max Packet Length",
    " Fwd Packet Length Std",  # Using Fwd version to avoid conflict
    " Bwd Packet Length Std",   # Using Bwd version to avoid conflict

    # Bulk features (always zero in CICIDS-2017)
    "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",

    # Subflow duplicates (same info as Tot_Fwd_Pkts, Tot_Bwd_Pkts)
    "Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",

    # Useless ratio
    " Down/Up Ratio",

    # Flags that are nearly always zero (no signal)
    " CWE Flag Count",
    " ECE Flag Count",
    " URG Flag Count",

    # Excessive IAT features (keep only Mean + Std)
    " Flow IAT Max",
    " Flow IAT Min",
    " Fwd IAT Max",
    " Fwd IAT Min",
    " Bwd IAT Max",
    " Bwd IAT Min",
    " Destination Port",
]

def load_data():
    all_files = glob.glob(os.path.join(raw_data_path))
    dfs = []
    for f in all_files:
        df = pd.read_csv(f)
        print(f"  Shape: {df.shape}")
        for c in df.columns:
            if c in DROP_COLS:
                df.drop(c, axis=1, inplace=True)
        print(f"  Shape: {df.shape}")
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Fix: Handle case where 'Label' column might not exist
        if ' Label' in df.columns:
            df[" Label"] = df[" Label"].map(ATTACK_MAPPING)
        else:
            print(f"Warning: Neither 'Lable' nor 'Label' column found in {f}")
            continue
            
        dfs.append(df)
    
    if not dfs:
        raise ValueError("No valid dataframes loaded. Check file paths and column names.")
    
    dataset = pd.concat(dfs, ignore_index=True)
    print(f"Final dataset shape: {dataset.shape}")
    return dataset

def preprocessing():
    # Fix: load_data() already returns a DataFrame, don't call pd.read_csv on it
    dataset = load_data()
    X = dataset.iloc[:, :-1]
    Y = dataset.iloc[:, -1]
    
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)
    process_data = pd.DataFrame(X_s, columns=X.columns)
    process_data["Label"] = Y
    
    # Ensure processed directory exists
    os.makedirs(os.path.dirname(processed_data_path), exist_ok=True)
    process_data.to_csv(processed_data_path, index=False)
    # print(f"Processed data saved to: {processed_data_path}")

    # Fix: Remove extra quote in JSON file path
    # os.makedirs(os.path.dirname(feature_list_path), exist_ok=True)
    # with open(feature_list_path, "w") as f:
    #     json.dump(list(X.columns), f)
    # print(f"Feature list saved to: {feature_list_path}")
    
if __name__ == "__main__":
    preprocessing()


# -------------------------------------------------
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


# -----------------------------------------------------------------------------------------views.py
from django.shortcuts import render

# Create your views here.
import json
import joblib
import pandas as pd
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

# Load ML models
rf = joblib.load("C:\\Users\\saket\\3-2Mini\\secureflow\\ml_model\\ai_models\\models\\rf.plk")
iso = joblib.load("C:\\Users\\saket\\3-2Mini\\secureflow\\ml_model\\ai_models\\models\\isolation_forest.pkl")
FEATURES = [" Flow Duration", " Total Fwd Packets", " Total Backward Packets", "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Mean", " Bwd Packet Length Mean", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", "Fwd IAT Total", " Fwd IAT Mean", " Fwd IAT Std", "Bwd IAT Total", " Bwd IAT Mean", " Bwd IAT Std", "Fwd PSH Flags", " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length", "Fwd Packets/s", " Bwd Packets/s", " Packet Length Mean", " Packet Length Std", " Packet Length Variance", "FIN Flag Count", " SYN Flag Count", " RST Flag Count", " PSH Flag Count", " ACK Flag Count", " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size", " Fwd Header Length.1", " act_data_pkt_fwd", " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min"]  # 46 ordered feature list

def fusion_engine(rf_label, rf_conf, iso_score):
    """
    Combines RandomForest + IsolationForest signals to produce:
    - final_score
    - severity
    - attack_type
    """

    # If RF predicts attack → trust RF
    if rf_label != "Normal":
        severity = "High" if rf_conf > 0.80 else "Medium"
        return {
            "final_score": round(float(rf_conf * 100), 2),
            "attack_type": rf_label,
            "severity": severity
        }

    # Otherwise, trust Isolation Forest
    if iso_score > 0.3:
        return {
            "final_score": iso_score,
            "attack_type": "Anomaly",
            "severity": "Medium"
        }

    return {
        "final_score": iso_score,
        "attack_type": "Normal",
        "severity": "Low"
    }
@csrf_exempt
def priftf(request):
    print("Hello from priftf!")
    return JsonResponse({"message": "priftf endpoint is working"})




@csrf_exempt
def network_traffic(request):
    print("Received network traffic data:", request.body)
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        data = json.loads(request.body)
        # print("Parsed data:", data)
    except:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    return JsonResponse({"message": "Network traffic data received"})




@csrf_exempt
def predict_flow(request):
    print("Received request:", request.body)
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        data = json.loads(request.body)
    except:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    # Convert input → DataFrame with correct order
    df = pd.DataFrame([data], columns=FEATURES)

    # RF PREDICTION
    rf_pred_raw = rf.predict(df)[0]             
    rf_label = str(rf_pred_raw)
    rf_prob = float(rf.predict_proba(df)[0].max())

    # ISO FOREST SCORE
    iso_score = abs(float(iso.decision_function(df)[0]))

    fused = fusion_engine(rf_label, rf_prob, iso_score)

    # Full response
    result = {
        "rf_label": rf_label,
        "rf_confidence": rf_prob,
        "iso_score": iso_score,
        "final": fused,
        "features_used": FEATURES
    }

    # SEND TO NODE SERVER FOR REAL-TIME UPDATES
    try:
        # requests.post(NODE_WS_ENDPOINT, json=result)
        print("Node push:", result)
    except Exception as e:
        print("Node push failed:", e)

    return JsonResponse(result)

# ------------------------------------urls
from django.http import JsonResponse
from django.urls import path
from .views import predict_flow, priftf ,network_traffic

urlpatterns = [
    path("", priftf, name="priftf"),
    path("predict", predict_flow, name="predict_flow"),
    path("network_traffic", network_traffic, name="network_traffic"),
]





# -----------------------
"""
URL configuration for ml_model project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("model_app/", include("model_app.urls")),
]


# ------------------------------------ruls
def rule_engine(flow):
    score = 0
    attack_type = "Unknown"

    # DDoS detection
    if flow["Flow_Pkts_s"] > 3000:
        score += 20
        attack_type = "DDoS"

    # Port Scan detection
    if flow["Tot_Fwd_Pkts"] > 100 and flow["Pkt_Size_Variance"] < 5:
        score += 15
        attack_type = "PortScan"

    # Brute Force detection
    if flow["Fwd_IAT_Mean"] < 200:
        score += 10
        attack_type = "BruteForce"

    # Web attack detection
    if flow["Flow_Byts_s"] > 150000 and flow["SYN_Flag"] == 1:
        score += 25
        attack_type = "WebAttack"

    return score, attack_type



# ----------------------------------------------------------pp.py
from scapy.all import sniff
import time, numpy as np, requests
from collections import defaultdict

DJANGO_API = "http://127.0.0.1:8000/model_app/predict"
DJANGO_API_net = "http://127.0.0.1:8000/model_app/network_traffic"
FLOW_TIMEOUT = 3   # seconds of inactivity

flows = {}

def flow_id(pkt):
    try:
        try:
            data_n = requests.post(DJANGO_API_net, json={'src': pkt["IP"].src, 'dst': pkt["IP"].dst, 'timestamp': time.time() , 'size': len(pkt),'proto': pkt["IP"].proto,'info': pkt.summary()})
            print("Network Traffic:", data_n.json())
        except Exception as e:
            print("Send error:", e)

        return (
            pkt["IP"].src,
            pkt["IP"].dst,
            pkt.sport if hasattr(pkt, "sport") else 0,
            pkt.dport if hasattr(pkt, "dport") else 0,
            pkt["IP"].proto
        )
    except:
        return None


def process_packet(pkt):
    fid = flow_id(pkt)
    if not fid:
        return
    
    now = time.time()
    size = len(pkt)

    if fid not in flows:
        flows[fid] = {
            "timestamps": [],
            "sizes": [],
            "fwd_sizes": [],
            "bwd_sizes": [],
            "flags": [],
            "fwd_hdr_len": [],
            "bwd_hdr_len": [],
            "src": fid[0],
            "last": now
        }

    f = flows[fid]
    direction = "fwd" if pkt["IP"].src == f["src"] else "bwd"

    # GENERAL
    f["timestamps"].append(now)
    f["sizes"].append(size)

    # LENGTHS
    if direction == "fwd":
        f["fwd_sizes"].append(size)
    else:
        f["bwd_sizes"].append(size)

    # FLAGS
    if pkt.haslayer("TCP"):
        flags = pkt.sprintf("%TCP.flags%")
        for fl in flags:
            f["flags"].append(fl)

    # HEADER LENGTHS
    if pkt.haslayer("IP"):
        hlen = pkt["IP"].ihl * 4
        if direction == "fwd":
            f["fwd_hdr_len"].append(hlen)
        else:
            f["bwd_hdr_len"].append(hlen)

    f["last"] = now


def compute_features(f):
    t = f["timestamps"]
    dur = (t[-1] - t[0]) if len(t) > 1 else 0.001
    sizes = f["sizes"]
    iats = np.diff(t) if len(t) > 1 else [0]

    fwd = f["fwd_sizes"]
    bwd = f["bwd_sizes"]

    return {
        # Duration + basic counts
        "Flow Duration": dur,
        "Total Fwd Packets": len(fwd),
        "Total Backward Packets": len(bwd),
        "Total Length of Fwd Packets": sum(fwd),
        "Total Length of Bwd Packets": sum(bwd),
        "Fwd Packet Length Mean": np.mean(fwd) if fwd else 0,
        "Bwd Packet Length Mean": np.mean(bwd) if bwd else 0,

        # Rates
        "Flow Bytes/s": sum(sizes) / dur,
        "Flow Packets/s": len(sizes) / dur,

        # IAT
        "Flow IAT Mean": np.mean(iats),
        "Flow IAT Std": np.std(iats),
        "Fwd IAT Total": sum(iats[:len(fwd)]) if len(fwd) else 0,
        "Fwd IAT Mean": np.mean(iats[:len(fwd)]) if len(fwd) else 0,
        "Fwd IAT Std": np.std(iats[:len(fwd)]) if len(fwd) else 0,
        "Bwd IAT Total": sum(iats[len(fwd):]) if len(bwd) else 0,
        "Bwd IAT Mean": np.mean(iats[len(fwd):]) if len(bwd) else 0,
        "Bwd IAT Std": np.std(iats[len(fwd):]) if len(bwd) else 0,

        # Flags
        "Fwd PSH Flags": f["flags"].count("P"),
        "Bwd PSH Flags": f["flags"].count("p"),
        "Fwd URG Flags": f["flags"].count("U"),
        "Bwd URG Flags": f["flags"].count("u"),

        # Header lengths
        "Fwd Header Length": np.mean(f["fwd_hdr_len"]) if f["fwd_hdr_len"] else 0,
        "Bwd Header Length": np.mean(f["bwd_hdr_len"]) if f["bwd_hdr_len"] else 0,

        # Packet rates per direction
        "Fwd Packets/s": len(fwd) / dur,
        "Bwd Packets/s": len(bwd) / dur,

        # Packet statistics
        "Packet Length Mean": np.mean(sizes),
        "Packet Length Std": np.std(sizes),
        "Packet Length Variance": np.var(sizes),

        # TCP flag counts
        "FIN Flag Count": f["flags"].count("F"),
        "SYN Flag Count": f["flags"].count("S"),
        "RST Flag Count": f["flags"].count("R"),
        "PSH Flag Count": f["flags"].count("P"),
        "ACK Flag Count": f["flags"].count("A"),

        # Additional flow-level features
        "Average Packet Size": sum(sizes) / len(sizes),
        "Avg Fwd Segment Size": np.mean(fwd) if fwd else 0,
        "Avg Bwd Segment Size": np.mean(bwd) if bwd else 0,

        "Fwd Header Length.1": np.mean(f["fwd_hdr_len"]) if f["fwd_hdr_len"] else 0,
        "act_data_pkt_fwd": len([x for x in fwd if x > 0]),
        "min_seg_size_forward": min(fwd) if fwd else 0,

        # Active/Idle
        "Active Mean": dur / len(sizes),
        "Active Std": np.std(iats),
        "Active Max": max(iats) if len(iats) else 0,
        "Active Min": min(iats) if len(iats) else 0,

        "Idle Mean": np.mean(iats),
        "Idle Std": np.std(iats),
        "Idle Max": max(iats),
        "Idle Min": min(iats)
    }


def flush_flows():
    now = time.time()
    expired = []

    for fid, f in flows.items():
        if now - f["last"] > FLOW_TIMEOUT:
            features = compute_features(f)
            print()
            print(features)
            try:
                r = requests.post(DJANGO_API, json=features)
                print("Prediction:", r.json())
            except Exception as e:
                print("Send error:", e)
            expired.append(fid)

    for fid in expired:
        del flows[fid]


def start_capture(interface="Wi-Fi"):
    sniff(iface=interface, store=False, prn=process_packet)
    flush_flows()


if __name__ == "__main__":
    print("STARTING HOST IDS...")
    while True:
        start_capture("Wi-Fi")

# --------------------------train rf2
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


# ----------------------train rand----
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

from sklearn.metrics import confusion_matrix, accuracy_score


procesed_path=r"C:\Users\saket\3-2Mini\secureflow\datasets\processed\dsbalance1.csv"
model_path="models/rf3_bs1.plk"

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
    model=RandomForestClassifier( n_estimators=800,
        max_depth=None,
        random_state=0)
    model.fit(x_train,y_train)
    # with open(model_path,'')
    joblib.dump(model,model_path)

    
    y_pred = model.predict(x_test)
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(accuracy_score(y_test, y_pred))


if __name__ == "__main__":
    train_model()

# ----------------------------------------trainsisolation forest
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import joblib
import os

PROCESSED_PATH = r"C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed1.csv"
MODEL_PATH = "models/isf1.pkl"

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


# --------------------------------------------test
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
    # ---------------------------------------------------preprocesing data

    
import pandas as pd
import numpy as np
import glob
import json
from sklearn.preprocessing import StandardScaler
import os

# Use relative path for better portability
raw_data_path = r'C:\Users\saket\3-2Mini\secureflow\datasets\raw'
processed_data_path = r'C:\Users\saket\3-2Mini\secureflow\datasets\processed\processed.csv'
feature_list_path = r'C:\Users\saket\3-2Mini\secureflow\ml_model\ml_core\feature_list.json'

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

DROP_COLS = [
    # Broken / corrupted fields
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",

    # Duplicate / redundant packet-length stats
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Std",
    "Bwd Packet Length Max",
    " Bwd Packet Length Min",
    " Bwd Packet Length Std",

    # Redundant packet summary stats
    " Min Packet Length",
    " Max Packet Length",
    " Fwd Packet Length Std",  # Using Fwd version to avoid conflict
    " Bwd Packet Length Std",   # Using Bwd version to avoid conflict

    # Bulk features (always zero in CICIDS-2017)
    "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",

    # Subflow duplicates (same info as Tot_Fwd_Pkts, Tot_Bwd_Pkts)
    "Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",

    # Useless ratio
    " Down/Up Ratio",

    # Flags that are nearly always zero (no signal)
    " CWE Flag Count",
    " ECE Flag Count",
    " URG Flag Count",

    # Excessive IAT features (keep only Mean + Std)
    " Flow IAT Max",
    " Flow IAT Min",
    " Fwd IAT Max",
    " Fwd IAT Min",
    " Bwd IAT Max",
    " Bwd IAT Min",
    " Destination Port",
]

def load_data():
    # Fix: Add proper path separator between directory and pattern
    all_files = glob.glob(os.path.join(raw_data_path, '*.csv'))
    # print(f"Found {len(all_files)} CSV files:")
    # for f in all_files:
    #     print(f"  - {f}")
    
    dfs = []
    for f in all_files:
        df = pd.read_csv(f)
        print(f"  Shape: {df.shape}")
        for c in df.columns:
            if c in DROP_COLS:
                df.drop(c, axis=1, inplace=True)
        print(f"  Shape: {df.shape}")
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Fix: Handle case where 'Label' column might not exist
        if ' Label' in df.columns:
            df[" Label"] = df[" Label"].map(ATTACK_MAPPING)
        else:
            print(f"Warning: Neither 'Lable' nor 'Label' column found in {f}")
            continue
            
        dfs.append(df)
    
    if not dfs:
        raise ValueError("No valid dataframes loaded. Check file paths and column names.")
    
    dataset = pd.concat(dfs, ignore_index=True)
    print(f"Final dataset shape: {dataset.shape}")
    return dataset

def preprocessing():
    # Fix: load_data() already returns a DataFrame, don't call pd.read_csv on it
    dataset = load_data()
    X = dataset.iloc[:, :-1]
    Y = dataset.iloc[:, -1]
    
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)
    process_data = pd.DataFrame(X_s, columns=X.columns)
    process_data["Label"] = Y
    
    # Ensure processed directory exists
    os.makedirs(os.path.dirname(processed_data_path), exist_ok=True)
    process_data.to_csv(processed_data_path, index=False)
    # print(f"Processed data saved to: {processed_data_path}")

    # Fix: Remove extra quote in JSON file path
    os.makedirs(os.path.dirname(feature_list_path), exist_ok=True)
    with open(feature_list_path, "w") as f:
        json.dump(list(X.columns), f)
    # print(f"Feature list saved to: {feature_list_path}")
    
if __name__ == "__main__":
    preprocessing()








# --------------test2
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