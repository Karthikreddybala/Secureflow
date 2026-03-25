"""
SecureFlow — model_app/views.py
Real-time flow processing and ML inference backend.

Fixes applied (2026-03-16):
  - Load persisted scalers (scaler_rf.pkl / scaler_iso.pkl) at startup —
    NEVER re-fit a scaler on inference data.
  - Correct model paths pointing to newly trained rf.pkl / iso_forest.pkl.
  - FEATURES list aligned with feature_list.json: added Destination Port,
    removed Fwd Header Length.1.
  - _compute_features now extracts Destination Port from flow['dport'].
  - _predict_alerts uses scaler_rf.transform() for RF and scaler_iso for ISO.
  - Removed all debug print() statements from hot paths.
  - Graceful startup: warns if models/scalers are missing (not yet trained).
"""

import csv
import io
import json
import logging
import subprocess
import threading
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt

# Local enrichment modules
try:
    from model_app import abuse_ipdb, incidents as incident_engine, simulate as sim
    from model_app.models import AlertRecord
except ImportError:
    from . import abuse_ipdb, incidents as incident_engine, simulate as sim
    from .models import AlertRecord

logger = logging.getLogger(__name__)

# ── Model & scaler paths ───────────────────────────────────────────────────────
MODEL_ROOT       = Path(__file__).resolve().parents[1] / 'ai_models' / 'models'

# ── RF (new trained model) ────────────────────────────────────────────────────
RF_MODEL_PATH    = MODEL_ROOT / 'rf_new.pkl'
RF_SCALER_PATH   = MODEL_ROOT / 'scaler_rf_new.pkl'

# ── XGBoost (new trained model — use as primary if available) ─────────────────
XGB_MODEL_PATH   = MODEL_ROOT / 'xgb.pkl'
XGB_SCALER_PATH  = MODEL_ROOT / 'scaler_xgb.pkl'
XGB_ENCODER_PATH = MODEL_ROOT / 'label_encoder_xgb.pkl'

# ── Isolation Forest (new trained model) ──────────────────────────────────────
ISO_MODEL_PATH   = MODEL_ROOT / 'iso_forest_new.pkl'
ISO_SCALER_PATH  = MODEL_ROOT / 'scaler_iso_new.pkl'

# ── Feature list — must match feature_list.json exactly ───────────────────────
# Destination Port is a high-signal feature (PortScan, BruteForce).
# Fwd Header Length.1 dropped — it was a duplicate column removed in preprocessing.
FEATURES = [
    ' Destination Port',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' Total Backward Packets',
    'Total Length of Fwd Packets',
    ' Total Length of Bwd Packets',
    ' Fwd Packet Length Mean',
    ' Bwd Packet Length Mean',
    'Flow Bytes/s',
    ' Flow Packets/s',
    ' Flow IAT Mean',
    ' Flow IAT Std',
    'Fwd IAT Total',
    ' Fwd IAT Mean',
    ' Fwd IAT Std',
    'Bwd IAT Total',
    ' Bwd IAT Mean',
    ' Bwd IAT Std',
    'Fwd PSH Flags',
    ' Bwd PSH Flags',
    ' Fwd URG Flags',
    ' Bwd URG Flags',
    ' Fwd Header Length',
    ' Bwd Header Length',
    'Fwd Packets/s',
    ' Bwd Packets/s',
    ' Packet Length Mean',
    ' Packet Length Std',
    ' Packet Length Variance',
    'FIN Flag Count',
    ' SYN Flag Count',
    ' RST Flag Count',
    ' PSH Flag Count',
    ' ACK Flag Count',
    ' Average Packet Size',
    ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size',
    ' act_data_pkt_fwd',
    ' min_seg_size_forward',
    'Active Mean',
    ' Active Std',
    ' Active Max',
    ' Active Min',
    'Idle Mean',
    ' Idle Std',
    ' Idle Max',
    ' Idle Min',
]

# ── Flow processing settings ───────────────────────────────────────────────────
FLOW_TIMEOUT               = 8.0    # seconds — flush idle flow
MIN_PACKETS_FOR_PROCESSING = 5      # minimum packets before a flow is eligible
MAX_FLOW_PACKETS           = 120    # force-flush at this packet count
ACTIVE_FLOW_FLUSH_INTERVAL = 2.0    # flush active flows every N seconds
MAX_Y_ALERT_SCORE          = 100.0

# ── Load models & scalers at startup (fail gracefully if not yet trained) ──────
def _load_artifact(path, label):
    if not path.exists():
        logger.warning(
            "⚠  %s not found at %s — run the training script first.", label, path
        )
        return None
    try:
        obj = joblib.load(path)
        logger.info("✓  Loaded %s from %s", label, path)
        return obj
    except Exception as exc:
        logger.error("✗  Failed to load %s: %s", label, exc)
        return None


rf         = _load_artifact(RF_MODEL_PATH,    "Random Forest model")
iso        = _load_artifact(ISO_MODEL_PATH,   "Isolation Forest model")
scaler_rf  = _load_artifact(RF_SCALER_PATH,   "RF scaler")
scaler_iso = _load_artifact(ISO_SCALER_PATH,  "ISO scaler")

# XGBoost — loaded separately and used as a drop-in replacement for RF when available
_xgb_model   = _load_artifact(XGB_MODEL_PATH,   "XGBoost model")
_xgb_scaler  = _load_artifact(XGB_SCALER_PATH,  "XGBoost scaler")
_xgb_encoder = _load_artifact(XGB_ENCODER_PATH, "XGBoost label encoder")

# Use XGBoost as primary classifier if it was successfully loaded
if _xgb_model is not None and _xgb_scaler is not None and _xgb_encoder is not None:
    rf        = _xgb_model
    scaler_rf = _xgb_scaler
    _use_xgb  = True
    logger.info("✓  Using XGBoost as primary classifier")
else:
    _use_xgb  = False
    logger.info("→  XGBoost not available, falling back to Random Forest")

# ── MITRE ATT&CK mapping ───────────────────────────────────────────────────────
ATTACK_TO_MITRE: dict[str, dict] = {
    'DoS':         {'id': 'T1498',     'name': 'Network Denial of Service',   'tactic': 'Impact'},
    'DDoS':        {'id': 'T1498.001', 'name': 'Direct Network Flood',        'tactic': 'Impact'},
    'PortScan':    {'id': 'T1046',     'name': 'Network Service Discovery',   'tactic': 'Discovery'},
    'BruteForce':  {'id': 'T1110',     'name': 'Brute Force',                 'tactic': 'Credential Access'},
    'Botnet':      {'id': 'T1071',     'name': 'Application Layer Protocol',  'tactic': 'Command & Control'},
    'Infiltration':{'id': 'T1190',     'name': 'Exploit Public-Facing App',   'tactic': 'Initial Access'},
    'Heartbleed':  {'id': 'T1203',     'name': 'Exploitation for Client Exec','tactic': 'Execution'},
    'Anomaly':     {'id': 'T1499',     'name': 'Endpoint Denial of Service',  'tactic': 'Impact'},
}

# ── SHAP explainer (initialised after model load) ──────────────────────────────
_shap_explainer = None

def _init_shap():
    global _shap_explainer
    if rf is None:
        return
    try:
        import shap
        _shap_explainer = shap.TreeExplainer(rf)
        logger.info('✓  SHAP TreeExplainer initialised')
    except Exception as exc:
        msg = str(exc)
        if _use_xgb and "could not convert string to float" in msg:
            logger.info('SHAP disabled for XGBoost model due SHAP/XGBoost compatibility: %s', msg)
            return
        logger.warning('SHAP init failed: %s', exc)

# Initialise SHAP in background so startup stays fast
threading.Thread(target=_init_shap, daemon=True).start()

# ── Host Threat Scores ─────────────────────────────────────────────────────────
# Rolling score per source IP.  Decays 2% every 60 s.
_host_scores: dict[str, dict] = {}   # ip → {score, attacks, last_seen}
_host_lock   = threading.Lock()
_DECAY_FACTOR = 0.98
_AUTO_BLOCK_THRESHOLD = 85.0

def _update_host_score(src_ip: str, severity: str, attack_type: str):
    delta = {'High': 30, 'Medium': 15, 'Low': 2}.get(severity, 2)
    with _host_lock:
        rec = _host_scores.setdefault(src_ip, {'score': 0.0, 'attacks': [], 'last_seen': 0})
        rec['score']     = min(100.0, rec['score'] + delta)
        rec['last_seen'] = time.time()
        if attack_type not in rec['attacks']:
            rec['attacks'].append(attack_type)
        # Auto-block if score exceeds threshold
        if rec['score'] >= _AUTO_BLOCK_THRESHOLD:
            _block_ip_system(src_ip)

def _decay_scores():
    """Background task: decay all host scores every 60 s."""
    while True:
        time.sleep(60)
        with _host_lock:
            for ip in list(_host_scores):
                _host_scores[ip]['score'] *= _DECAY_FACTOR
                if _host_scores[ip]['score'] < 0.5:
                    del _host_scores[ip]

threading.Thread(target=_decay_scores, daemon=True).start()

# ── IP Blocking ────────────────────────────────────────────────────────────────
_blocked_ips: set[str] = set()
_block_lock  = threading.Lock()

def _block_ip_system(ip: str):
    """Add a Windows Firewall inbound block rule for the given IP."""
    if ip in ('unknown', '') or ip.startswith(('127.', '192.168.', '10.')):
        return  # never block private/loopback
    with _block_lock:
        if ip in _blocked_ips:
            return
        try:
            rule = f'SecureFlow_Block_{ip}'
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule}', 'dir=in', 'action=block', f'remoteip={ip}'],
                capture_output=True, timeout=5
            )
            _blocked_ips.add(ip)
            logger.info('Blocked IP via firewall: %s', ip)
        except Exception as exc:
            logger.warning('Firewall block failed for %s: %s', ip, exc)

# ── In-memory flow table ───────────────────────────────────────────────────────
flows      = {}
flows_lock = threading.Lock()

processing_stats = {
    'flows_processed':        0,
    'packets_processed':      0,
    'alerts_emitted':         0,
    'avg_processing_time_ms': 0.0,
    'start_time':             time.time(),
}

# ── Recent alerts store (for export) ──────────────────────────────────────────
_recent_alerts: list[dict] = []
_MAX_RECENT    = 5000


# ── Helpers ────────────────────────────────────────────────────────────────────
def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _protocol_label(value):
    proto = str(value).upper()
    return {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}.get(proto, proto)


def _flow_id(packet):
    """
    Bidirectional canonical flow key: A→B and B→A map to the same flow.
    The side with the lexicographically lower (src, sport) is always 'fwd'.
    """
    required = ('src', 'dst', 'sport', 'dport', 'proto')
    if any(k not in packet for k in required):
        return None

    src, dst = str(packet['src']), str(packet['dst'])
    sp,  dp  = str(packet['sport']), str(packet['dport'])
    proto    = str(packet['proto'])

    # Canonical order: always put the lower endpoint first
    if (src, sp) <= (dst, dp):
        return (src, dst, sp, dp, proto)
    else:
        return (dst, src, dp, sp, proto)


# ── Fusion engine ──────────────────────────────────────────────────────────────
def fusion_engine(rf_label, rf_confidence, iso_score):
    if str(rf_label).lower() != 'normal':
        severity = 'High' if rf_confidence >= 0.80 else 'Medium'
        return {
            'final_score': round(min(MAX_Y_ALERT_SCORE, rf_confidence * 100.0), 2),
            'attack_type': str(rf_label),
            'severity':    severity,
        }

    if iso_score > 0.25:
        return {
            'final_score': round(min(MAX_Y_ALERT_SCORE, iso_score * 100.0), 2),
            'attack_type': 'Anomaly',
            'severity':    'Medium',
        }

    return {
        'final_score': round(min(MAX_Y_ALERT_SCORE, iso_score * 100.0), 2),
        'attack_type': 'Normal',
        'severity':    'Low',
    }


# ── Packet ingestion ───────────────────────────────────────────────────────────
def process_packet(packet):
    with flows_lock:
        _ingest_packet_locked(packet)


# TCP flag bitmasks
_FIN = 0x01; _SYN = 0x02; _RST = 0x04; _PSH = 0x08; _ACK = 0x10; _URG = 0x20


def _ingest_packet_locked(packet):
    fid = _flow_id(packet)
    if not fid:
        return False

    now         = time.time()
    packet_size = max(1, int(packet.get('size') or packet.get('bytes') or 0))
    flags       = int(packet.get('flags', 0))
    # Header lengths: IP header + TCP/UDP header
    hdr_len     = int(packet.get('ip_hdr_len', 0)) + int(packet.get('tcp_hdr_len', 0))

    flow = flows.get(fid)
    if flow is None:
        # canonical_fwd_src = fid[0] (lower endpoint)
        flow = {
            'canonical_fwd_src':   fid[0],
            'canonical_fwd_sport': fid[2],
            # all-packet tracking
            'timestamps':    [],
            'sizes':         [],
            # per-direction tracking
            'fwd_timestamps': [],
            'bwd_timestamps': [],
            'fwd_sizes':     [],
            'bwd_sizes':     [],
            'fwd_hdr_lens':  [],   # sum for Fwd Header Length
            'bwd_hdr_lens':  [],
            # per-direction TCP flag accumulators
            'fwd_fin': 0, 'fwd_syn': 0, 'fwd_rst': 0,
            'fwd_psh': 0, 'fwd_ack': 0, 'fwd_urg': 0,
            'bwd_fin': 0, 'bwd_syn': 0, 'bwd_rst': 0,
            'bwd_psh': 0, 'bwd_ack': 0, 'bwd_urg': 0,
            # metadata
            'dport': fid[3],
            'first': now,
            'last':  now,
        }
        flows[fid] = flow

    flow['timestamps'].append(now)
    flow['sizes'].append(packet_size)

    # Determine direction using canonical key
    is_fwd = (
        str(packet.get('src'))   == flow['canonical_fwd_src'] and
        str(packet.get('sport')) == flow['canonical_fwd_sport']
    )

    if is_fwd:
        flow['fwd_timestamps'].append(now)
        flow['fwd_sizes'].append(packet_size)
        flow['fwd_hdr_lens'].append(hdr_len)
        if flags & _FIN: flow['fwd_fin'] += 1
        if flags & _SYN: flow['fwd_syn'] += 1
        if flags & _RST: flow['fwd_rst'] += 1
        if flags & _PSH: flow['fwd_psh'] += 1
        if flags & _ACK: flow['fwd_ack'] += 1
        if flags & _URG: flow['fwd_urg'] += 1
    else:
        flow['bwd_timestamps'].append(now)
        flow['bwd_sizes'].append(packet_size)
        flow['bwd_hdr_lens'].append(hdr_len)
        if flags & _FIN: flow['bwd_fin'] += 1
        if flags & _SYN: flow['bwd_syn'] += 1
        if flags & _RST: flow['bwd_rst'] += 1
        if flags & _PSH: flow['bwd_psh'] += 1
        if flags & _ACK: flow['bwd_ack'] += 1
        if flags & _URG: flow['bwd_urg'] += 1

    flow['last'] = now
    return True


# ── Active / Idle helper (CICFlowMeter definition) ────────────────────────────
_ACTIVITY_TIMEOUT = 5.0  # seconds — gap >= this separates active periods


def _compute_active_idle(all_timestamps):
    """
    Split a list of timestamps into active-period durations and idle gaps.
    Active period = consecutive burst of packets separated by < ACTIVITY_TIMEOUT.
    Idle period   = gap between two consecutive active periods.
    """
    if len(all_timestamps) < 2:
        return np.array([0.0]), np.array([0.0])

    ts = np.array(all_timestamps, dtype=float)
    iats = np.diff(ts)

    active_durations = []
    idle_gaps        = []
    period_start     = ts[0]

    for i, gap in enumerate(iats):
        if gap >= _ACTIVITY_TIMEOUT:
            # End of an active period
            active_durations.append(ts[i] - period_start)
            idle_gaps.append(gap)
            period_start = ts[i + 1]

    # Last active period
    active_durations.append(ts[-1] - period_start)

    return (
        np.array(active_durations) if active_durations else np.array([0.0]),
        np.array(idle_gaps)        if idle_gaps        else np.array([0.0]),
    )


# ── Feature extraction ─────────────────────────────────────────────────────────
def _compute_features(flow):
    timestamps     = flow['timestamps']
    sizes          = flow['sizes']
    fwd_sizes      = flow['fwd_sizes']
    bwd_sizes      = flow['bwd_sizes']
    fwd_timestamps = flow['fwd_timestamps']
    bwd_timestamps = flow['bwd_timestamps']

    duration      = (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.001
    duration_safe = max(duration, 0.001)
    packet_count  = max(len(sizes), 1)

    # ── All-flow IAT (any direction) ──────────────────────────────────────
    all_iats = np.diff(np.array(timestamps, dtype=float)) if len(timestamps) > 1 else np.array([0.0])

    # ── Per-direction IAT (true fwd/bwd inter-arrival times) ─────────────
    fwd_iats = np.diff(np.array(fwd_timestamps, dtype=float)) if len(fwd_timestamps) > 1 else np.array([0.0])
    bwd_iats = np.diff(np.array(bwd_timestamps, dtype=float)) if len(bwd_timestamps) > 1 else np.array([0.0])

    # ── Active / Idle periods (CICFlowMeter-style 5s timeout) ────────────
    active_arr, idle_arr = _compute_active_idle(timestamps)

    # ── Header lengths (sum across direction) ─────────────────────────────
    fwd_hdr_total = float(sum(flow.get('fwd_hdr_lens', [0])))
    bwd_hdr_total = float(sum(flow.get('bwd_hdr_lens', [0])))

    return {
        # ── High-signal: Destination Port ────────────────────────
        ' Destination Port':            _safe_float(flow.get('dport', 0)),

        # ── Flow-level ────────────────────────────────────────────
        ' Flow Duration':               duration,
        ' Total Fwd Packets':           float(len(fwd_sizes)),
        ' Total Backward Packets':      float(len(bwd_sizes)),
        'Total Length of Fwd Packets':  float(sum(fwd_sizes)),
        ' Total Length of Bwd Packets': float(sum(bwd_sizes)),
        'Flow Bytes/s':                 _safe_float(sum(sizes) / duration_safe),
        ' Flow Packets/s':              _safe_float(len(sizes) / duration_safe),

        # ── Packet lengths ────────────────────────────────────────
        ' Fwd Packet Length Mean':      _safe_float(np.mean(fwd_sizes)) if fwd_sizes else 0.0,
        ' Bwd Packet Length Mean':      _safe_float(np.mean(bwd_sizes)) if bwd_sizes else 0.0,
        ' Packet Length Mean':          _safe_float(np.mean(sizes)),
        ' Packet Length Std':           _safe_float(np.std(sizes)),
        ' Packet Length Variance':      _safe_float(np.var(sizes)),
        ' Average Packet Size':         _safe_float(sum(sizes) / packet_count),
        ' Avg Fwd Segment Size':        _safe_float(np.mean(fwd_sizes)) if fwd_sizes else 0.0,
        ' Avg Bwd Segment Size':        _safe_float(np.mean(bwd_sizes)) if bwd_sizes else 0.0,

        # ── Flow IAT ──────────────────────────────────────────────
        ' Flow IAT Mean':               _safe_float(np.mean(all_iats)),
        ' Flow IAT Std':                _safe_float(np.std(all_iats)),

        # ── Fwd IAT (true per-direction inter-arrival times) ──────
        'Fwd IAT Total':                _safe_float(np.sum(fwd_iats)),
        ' Fwd IAT Mean':                _safe_float(np.mean(fwd_iats)),
        ' Fwd IAT Std':                 _safe_float(np.std(fwd_iats)),

        # ── Bwd IAT (true per-direction inter-arrival times) ──────
        'Bwd IAT Total':                _safe_float(np.sum(bwd_iats)),
        ' Bwd IAT Mean':                _safe_float(np.mean(bwd_iats)),
        ' Bwd IAT Std':                 _safe_float(np.std(bwd_iats)),

        # ── TCP flags — real counts from packet-level extraction ──
        'Fwd PSH Flags':                float(flow.get('fwd_psh', 0)),
        ' Bwd PSH Flags':               float(flow.get('bwd_psh', 0)),
        ' Fwd URG Flags':               float(flow.get('fwd_urg', 0)),
        ' Bwd URG Flags':               float(flow.get('bwd_urg', 0)),
        # Flow-level flag totals (fwd + bwd)
        'FIN Flag Count':               float(flow.get('fwd_fin', 0) + flow.get('bwd_fin', 0)),
        ' SYN Flag Count':              float(flow.get('fwd_syn', 0) + flow.get('bwd_syn', 0)),
        ' RST Flag Count':              float(flow.get('fwd_rst', 0) + flow.get('bwd_rst', 0)),
        ' PSH Flag Count':              float(flow.get('fwd_psh', 0) + flow.get('bwd_psh', 0)),
        ' ACK Flag Count':              float(flow.get('fwd_ack', 0) + flow.get('bwd_ack', 0)),

        # ── Header lengths (IP + TCP/UDP, summed per direction) ───
        ' Fwd Header Length':           fwd_hdr_total,
        ' Bwd Header Length':           bwd_hdr_total,

        # ── Sub-flow packet rates ─────────────────────────────────
        'Fwd Packets/s':                _safe_float(len(fwd_sizes) / duration_safe),
        ' Bwd Packets/s':               _safe_float(len(bwd_sizes) / duration_safe),

        # ── Forward data payload ──────────────────────────────────
        ' act_data_pkt_fwd':            float(sum(1 for v in fwd_sizes if v > 0)),
        ' min_seg_size_forward':        float(min(fwd_sizes)) if fwd_sizes else 0.0,

        # ── Active / Idle (CICFlowMeter 5s-timeout definition) ────
        'Active Mean':                  _safe_float(np.mean(active_arr)),
        ' Active Std':                  _safe_float(np.std(active_arr)),
        ' Active Max':                  _safe_float(np.max(active_arr)),
        ' Active Min':                  _safe_float(np.min(active_arr)),
        'Idle Mean':                    _safe_float(np.mean(idle_arr)),
        ' Idle Std':                    _safe_float(np.std(idle_arr)),
        ' Idle Max':                    _safe_float(np.max(idle_arr)),
        ' Idle Min':                    _safe_float(np.min(idle_arr)),
    }


def _prepare_model_row(feature_map):
    """Build a dict with exactly FEATURES keys, defaulting missing ones to 0."""
    row = {}
    for feature in FEATURES:
        trimmed = feature.strip()
        row[feature] = _safe_float(feature_map.get(feature, feature_map.get(trimmed, 0.0)))
    return row


# ── Inference ──────────────────────────────────────────────────────────────────
def _predict_alerts(flow_items):
    if not flow_items:
        return []

    if rf is None or scaler_rf is None:
        logger.error(
            "RF model or its scaler is not loaded — cannot predict. "
            "Run trainrandomforest.py or trainxgboost.py first."
        )
        return []

    start = time.time()

    feature_rows = [_prepare_model_row(_compute_features(flow)) for _, flow in flow_items]
    frame = pd.DataFrame(feature_rows, columns=FEATURES).fillna(0.0)

    # ── Classifier inference — use the SAVED scaler (transform only, never fit) ─
    X_rf       = scaler_rf.transform(frame)
    rf_pred_raw = rf.predict(X_rf)
    rf_pred    = rf_pred_raw.copy()
    rf_prob    = rf.predict_proba(X_rf).max(axis=1) if hasattr(rf, 'predict_proba') else np.ones(len(flow_items))

    # XGBoost predicts integer class indices — decode back to string labels
    if _use_xgb and _xgb_encoder is not None:
        rf_pred = _xgb_encoder.inverse_transform(rf_pred.astype(int))

    # ── Isolation Forest — uses its own scaler ─────────────────────────────────
    if iso is not None and scaler_iso is not None:
        X_iso      = scaler_iso.transform(frame)
        iso_scores = np.abs(iso.decision_function(X_iso))
    else:
        logger.warning("ISO model/scaler not loaded — anomaly scoring skipped.")
        iso_scores = np.zeros(len(flow_items))

    alerts = []
    for idx, (fid, _) in enumerate(flow_items):
        fused       = fusion_engine(str(rf_pred[idx]), float(rf_prob[idx]), float(iso_scores[idx]))
        attack_type = fused['attack_type']
        src_ip      = fid[0]

        # ── MITRE ATT&CK ─────────────────────────────────────────────────────
        mitre = ATTACK_TO_MITRE.get(attack_type, {})

        # ── SHAP top-3 feature drivers (only for non-Normal alerts) ─────────
        shap_top = []
        if _shap_explainer is not None and attack_type.lower() != 'normal':
            try:
                sv = _shap_explainer.shap_values(X_rf[idx:idx+1])
                # sv may be 2D (binary) or 3D (multi-class)
                if isinstance(sv, list):
                    pred_cls = int(rf_pred_raw[idx]) if _use_xgb else 0
                    vals = sv[min(pred_cls, len(sv)-1)][0]
                else:
                    vals = sv[0]
                top3_idx = np.argsort(np.abs(vals))[-3:][::-1]
                shap_top = [
                    {'feature': FEATURES[i].strip(), 'impact': round(float(vals[i]), 4)}
                    for i in top3_idx if i < len(FEATURES)
                ]
            except Exception:
                pass

        # ── AbuseIPDB reputation ──────────────────────────────────────────────
        abuse_score = abuse_ipdb.get_abuse_score(src_ip)

        # ── Host threat score update ──────────────────────────────────────────
        if attack_type.lower() != 'normal':
            _update_host_score(src_ip, fused['severity'], attack_type)

        alert = {
            'final':       fused,
            'protocol':    _protocol_label(fid[4]),
            'src_ip':      src_ip,
            'dst_ip':      fid[1],
            'sport':       fid[2],
            'dport':       fid[3],
            'timestamp':   time.time(),
            'mitre':       mitre,
            'shap':        shap_top,
            'abuse_score': abuse_score,
            'abuse_badge': abuse_ipdb.badge(abuse_score),
            'message':     f"Flow: {attack_type} ({fused['severity']})",
        }

        # ── Alert correlation → incident ──────────────────────────────────────
        incident = incident_engine.correlate_alert(alert)
        if incident:
            alert['incident_id'] = incident['id']

        alerts.append(alert)

        # Store for export (in-memory ring buffer)
        global _recent_alerts
        _recent_alerts = (_recent_alerts + alerts)[-_MAX_RECENT:]

        # ── Persist to database ───────────────────────────────────────────────
        db_records = []
        for a in alerts:
            f = a.get('final', {})
            m = a.get('mitre', {})
            db_records.append(AlertRecord(
                timestamp    = a.get('timestamp', time.time()),
                src_ip       = (a.get('src_ip') or None),
                dst_ip       = (a.get('dst_ip') or None),
                sport        = (a.get('sport') or None),
                dport        = (a.get('dport') or None),
                protocol     = a.get('protocol', ''),
                attack_type  = f.get('attack_type', ''),
                severity     = f.get('severity', ''),
                confidence   = float(f.get('final_score', 0.0)),
                mitre_id     = m.get('id', ''),
                mitre_tactic = m.get('tactic', ''),
                abuse_score  = int(a.get('abuse_score', 0)),
                incident_id  = str(a.get('incident_id', '')),
                is_simulated = a.get('is_simulated', False),
            ))
        try:
            AlertRecord.objects.bulk_create(db_records, ignore_conflicts=True)
        except Exception as db_err:
            logger.warning('DB write failed: %s', db_err)


    elapsed_ms = (time.time() - start) * 1000.0
    n = len(flow_items)
    if n:
        prev_total = processing_stats['flows_processed']
        new_total  = prev_total + n
        processing_stats['avg_processing_time_ms'] = (
            (processing_stats['avg_processing_time_ms'] * prev_total) + elapsed_ms
        ) / max(new_total, 1)

    return alerts


# ── Flow selection ─────────────────────────────────────────────────────────────
def _select_ready_flows(force=False):
    now   = time.time()
    ready = []

    with flows_lock:
        for fid, flow in list(flows.items()):
            packet_count = len(flow['sizes'])
            flow_age     = now - flow['first']
            idle_age     = now - flow['last']

            should_process = (
                force
                or packet_count >= MAX_FLOW_PACKETS
                or idle_age     >= FLOW_TIMEOUT
                or (packet_count >= MIN_PACKETS_FOR_PROCESSING and flow_age >= ACTIVE_FLOW_FLUSH_INTERVAL)
            )

            if should_process:
                ready.append((fid, flow))
                del flows[fid]

    return ready


# ── Public API ─────────────────────────────────────────────────────────────────
def flush_flows_async(force=False):
    ready_flows = _select_ready_flows(force=force)
    alerts      = _predict_alerts(ready_flows)

    if alerts:
        async_to_sync(send_alert_batch_async)(alerts)

    processing_stats['flows_processed'] += len(ready_flows)
    processing_stats['alerts_emitted']  += len(alerts)
    return len(alerts)


def process_packet_batch(packets, force_flush=False):
    valid_packets = [p for p in packets if isinstance(p, dict)]

    ingested = 0
    with flows_lock:
        for packet in valid_packets:
            if _ingest_packet_locked(packet):
                ingested += 1

    processing_stats['packets_processed'] += ingested

    ready_flows = _select_ready_flows(force=force_flush)
    alerts      = _predict_alerts(ready_flows)

    if alerts:
        async_to_sync(send_alert_batch_async)(alerts)

    processing_stats['flows_processed'] += len(ready_flows)
    processing_stats['alerts_emitted']  += len(alerts)
    return alerts


def get_processing_stats():
    uptime          = time.time() - processing_stats['start_time']
    flows_processed = max(processing_stats['flows_processed'], 1)

    with flows_lock:
        in_memory = len(flows)

    return {
        'flows_processed':              processing_stats['flows_processed'],
        'packets_processed':            processing_stats['packets_processed'],
        'alerts_emitted':               processing_stats['alerts_emitted'],
        'avg_packets_per_flow':         processing_stats['packets_processed'] / flows_processed,
        'avg_processing_time_ms':       processing_stats['avg_processing_time_ms'],
        'queue_depth':                  0,
        'uptime_seconds':               uptime,
        'flows_in_memory':              in_memory,
        'processing_rate_flows_per_sec':   processing_stats['flows_processed'] / max(uptime, 1.0),
        'processing_rate_packets_per_sec': processing_stats['packets_processed'] / max(uptime, 1.0),
    }


# ── Channel layer helpers ──────────────────────────────────────────────────────
async def send_packet_batch_async(packets):
    channel_layer = get_channel_layer()
    await channel_layer.group_send(
        'network_traffic',
        {'type': 'send_traffic', 'data': packets}
    )


async def send_alert_async(alert):
    channel_layer = get_channel_layer()
    await channel_layer.group_send(
        'alerts',
        {'type': 'send_alert', 'data': alert}
    )


async def send_alert_batch_async(alerts):
    for alert in alerts:
        await send_alert_async(alert)


def send_alert(alert):
    async_to_sync(send_alert_async)(alert)


def start_parallel_processors(num_workers=3):
    logger.info(
        'Inline batch processor active. Separate workers not needed (requested: %s).',
        num_workers
    )


# ── Django view ────────────────────────────────────────────────────────────────
@csrf_exempt
def predict_flow(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST is supported'}, status=405)

    try:
        body    = json.loads(request.body)
        packets = body.get('packets', [])

        if not isinstance(packets, list):
            return JsonResponse({'status': 'error', 'message': 'packets must be a list'}, status=400)

        async_to_sync(send_packet_batch_async)(packets)
        alerts = process_packet_batch(packets, force_flush=False)

        return JsonResponse({
            'status':         'ok',
            'message':        'Packets processed',
            'packet_count':   len(packets),
            'alerts_emitted': len(alerts),
        })

    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON body'}, status=400)
    except Exception as error:
        logger.exception('Error in predict_flow')
        return JsonResponse({'status': 'error', 'message': str(error)}, status=500)


# ── Feature 4: Host Threat Scores ──────────────────────────────────────────────
def get_host_scores(request):
    with _host_lock:
        hosts = [
            {'ip': ip, 'score': round(rec['score'], 1),
             'attacks': rec['attacks'], 'last_seen': rec['last_seen']}
            for ip, rec in _host_scores.items()
        ]
    hosts.sort(key=lambda h: h['score'], reverse=True)
    return JsonResponse({'hosts': hosts[:50]})


# ── Feature 5: Incidents ────────────────────────────────────────────────────────
def get_incidents(request):
    return JsonResponse({'incidents': incident_engine.get_all_incidents()})


# ── Feature 6: IP Blocking ─────────────────────────────────────────────────────
@csrf_exempt
def manage_blocked_ips(request):
    if request.method == 'GET':
        with _block_lock:
            return JsonResponse({'blocked_ips': sorted(_blocked_ips)})

    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            ip   = body.get('ip', '').strip()
            if not ip:
                return JsonResponse({'error': 'ip required'}, status=400)
            _block_ip_system(ip)
            return JsonResponse({'status': 'blocked', 'ip': ip})
        except Exception as exc:
            return JsonResponse({'error': str(exc)}, status=500)

    if request.method == 'DELETE':
        try:
            body = json.loads(request.body)
            ip   = body.get('ip', '').strip()
            if not ip:
                return JsonResponse({'error': 'ip required'}, status=400)
            rule = f'SecureFlow_Block_{ip}'
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule}'],
                capture_output=True, timeout=5
            )
            with _block_lock:
                _blocked_ips.discard(ip)
            return JsonResponse({'status': 'unblocked', 'ip': ip})
        except Exception as exc:
            return JsonResponse({'error': str(exc)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


# ── Feature 7: Attack Simulation ───────────────────────────────────────────────
@csrf_exempt
def simulate_attack(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    try:
        body        = json.loads(request.body or '{}')
        attack_type = body.get('attack_type', 'DoS')
        if attack_type not in sim.SUPPORTED:
            return JsonResponse({'error': f'Unknown type. Supported: {sim.SUPPORTED}'}, status=400)

        packets = sim.generate_packets(attack_type)
        # Tag simulated packets so they get marked is_simulated=True in DB
        for p in packets:
            p['is_simulated'] = True
        alerts  = process_packet_batch(packets, force_flush=True)
        resp = JsonResponse({
            'status':         'ok',
            'attack_type':    attack_type,
            'packets_sent':   len(packets),
            'alerts_emitted': len(alerts),
            'model_labels':   list({a.get('final', {}).get('attack_type') for a in alerts}),
        })
        resp['Access-Control-Allow-Origin'] = '*'
        return resp
    except Exception as exc:
        logger.exception('Simulation error')
        return JsonResponse({'error': str(exc)}, status=500)


# ── Feature 8: Export ──────────────────────────────────────────────────────────
def export_alerts(request):
    fmt    = request.GET.get('format', 'csv').lower()
    limit  = min(int(request.GET.get('limit', 1000)), _MAX_RECENT)
    alerts = _recent_alerts[-limit:]

    if fmt == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'sport', 'dport',
                         'protocol', 'attack_type', 'severity', 'confidence',
                         'mitre_id', 'mitre_tactic', 'abuse_score'])
        for a in alerts:
            f = a.get('final', {})
            m = a.get('mitre', {})
            writer.writerow([
                a.get('timestamp', ''), a.get('src_ip', ''), a.get('dst_ip', ''),
                a.get('sport', ''),     a.get('dport', ''),  a.get('protocol', ''),
                f.get('attack_type', ''), f.get('severity', ''), f.get('final_score', ''),
                m.get('id', ''),        m.get('tactic', ''),    a.get('abuse_score', 0),
            ])
        resp = HttpResponse(output.getvalue(), content_type='text/csv')
        resp['Content-Disposition'] = 'attachment; filename="secureflow_alerts.csv"'
        return resp

    if fmt == 'pdf':
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet

            buf    = io.BytesIO()
            doc    = SimpleDocTemplate(buf, pagesize=A4, leftMargin=30, rightMargin=30)
            styles = getSampleStyleSheet()
            story  = []

            story.append(Paragraph('SecureFlow IDS — Alert Report', styles['Title']))
            story.append(Paragraph(f'Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}'    
                                   f'  |  Total alerts: {len(alerts)}', styles['Normal']))
            story.append(Spacer(1, 12))

            headers = ['Time', 'Src IP', 'Attack', 'Severity', 'MITRE ID', 'Abuse']
            rows    = [headers]
            for a in alerts[-200:]:   # PDF: last 200 rows
                f = a.get('final', {})
                m = a.get('mitre', {})
                rows.append([
                    time.strftime('%H:%M:%S', time.localtime(a.get('timestamp', 0))),
                    a.get('src_ip', ''),
                    f.get('attack_type', ''),
                    f.get('severity', ''),
                    m.get('id', ''),
                    str(a.get('abuse_score', 0)),
                ])

            t = Table(rows, repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
                ('FONTSIZE',   (0,0), (-1,-1), 7),
                ('GRID',       (0,0), (-1,-1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0f0f0')]),
            ]))
            story.append(t)
            doc.build(story)
            buf.seek(0)
            resp = HttpResponse(buf.read(), content_type='application/pdf')
            resp['Content-Disposition'] = 'attachment; filename="secureflow_report.pdf"'
            return resp
        except Exception as exc:
            return JsonResponse({'error': f'PDF generation failed: {exc}'}, status=500)


    return JsonResponse({'error': 'format must be csv or pdf'}, status=400)


def _cors(response):
    """Add CORS headers so browser can download blobs cross-origin."""
    response['Access-Control-Allow-Origin']  = '*'
    response['Access-Control-Allow-Headers'] = 'Content-Type'
    response['Access-Control-Expose-Headers'] = 'Content-Disposition'
    return response


def export_alerts(request):
    """Export recent alerts as CSV or PDF — with CORS headers for browser download."""
    fmt    = request.GET.get('format', 'csv').lower()
    limit  = min(int(request.GET.get('limit', 1000)), _MAX_RECENT)
    alerts = _recent_alerts[-limit:]

    if fmt == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'sport', 'dport',
                         'protocol', 'attack_type', 'severity', 'confidence',
                         'mitre_id', 'mitre_tactic', 'abuse_score', 'simulated'])
        for a in alerts:
            f = a.get('final', {})
            m = a.get('mitre', {})
            writer.writerow([
                a.get('timestamp', ''),       a.get('src_ip', ''),     a.get('dst_ip', ''),
                a.get('sport', ''),           a.get('dport', ''),      a.get('protocol', ''),
                f.get('attack_type', ''),     f.get('severity', ''),   f.get('final_score', ''),
                m.get('id', ''),              m.get('tactic', ''),     a.get('abuse_score', 0),
                a.get('is_simulated', False),
            ])
        resp = HttpResponse(output.getvalue(), content_type='text/csv')
        resp['Content-Disposition'] = 'attachment; filename="secureflow_alerts.csv"'
        return _cors(resp)

    if fmt == 'pdf':
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet

            buf    = io.BytesIO()
            doc    = SimpleDocTemplate(buf, pagesize=A4, leftMargin=30, rightMargin=30)
            styles = getSampleStyleSheet()
            story  = []

            story.append(Paragraph('SecureFlow IDS — Alert Report', styles['Title']))
            story.append(Paragraph(
                f'Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}  |  Total alerts: {len(alerts)}',
                styles['Normal']))
            story.append(Spacer(1, 12))

            headers = ['Time', 'Src IP', 'Attack', 'Severity', 'MITRE ID', 'Abuse', 'Sim']
            rows    = [headers]
            for a in alerts[-200:]:
                f = a.get('final', {})
                m = a.get('mitre', {})
                rows.append([
                    time.strftime('%H:%M:%S', time.localtime(a.get('timestamp', 0))),
                    str(a.get('src_ip', '')),
                    str(f.get('attack_type', '')),
                    str(f.get('severity', '')),
                    str(m.get('id', '')),
                    str(a.get('abuse_score', 0)),
                    'Y' if a.get('is_simulated') else 'N',
                ])

            t = Table(rows, repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
                ('FONTSIZE',   (0,0), (-1,-1), 7),
                ('GRID',       (0,0), (-1,-1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0f0f0')]),
            ]))
            story.append(t)
            doc.build(story)
            buf.seek(0)
            resp = HttpResponse(buf.read(), content_type='application/pdf')
            resp['Content-Disposition'] = 'attachment; filename="secureflow_report.pdf"'
            return _cors(resp)
        except Exception as exc:
            return JsonResponse({'error': f'PDF generation failed: {exc}'}, status=500)

    return JsonResponse({'error': 'format must be csv or pdf'}, status=400)


# ── DB Alert Management ────────────────────────────────────────────────────────
def list_db_alerts(request):
    """Return paginated DB-persisted alerts."""
    page   = max(1, int(request.GET.get('page', 1)))
    limit  = min(int(request.GET.get('limit', 50)), 200)
    offset = (page - 1) * limit
    qs     = AlertRecord.objects.all()[offset:offset + limit]
    total  = AlertRecord.objects.count()
    resp   = JsonResponse({'alerts': [a.to_dict() for a in qs], 'total': total, 'page': page, 'limit': limit})
    return _cors(resp)


@csrf_exempt
def delete_db_alert(request, alert_id=None):
    """DELETE /model_app/db_alerts/<id> — remove one alert. DELETE /model_app/db_alerts — clear all."""
    if request.method not in ('DELETE', 'POST'):
        return JsonResponse({'error': 'DELETE/POST only'}, status=405)
    try:
        if alert_id:
            AlertRecord.objects.filter(pk=alert_id).delete()
            return _cors(JsonResponse({'status': 'deleted', 'id': alert_id}))
        else:
            # Body may contain {"filter": "simulated"} or empty = delete all
            body   = json.loads(request.body or '{}')
            filt   = body.get('filter', 'all')
            if filt == 'simulated':
                n, _ = AlertRecord.objects.filter(is_simulated=True).delete()
            elif filt == 'attack_type' and body.get('value'):
                n, _ = AlertRecord.objects.filter(attack_type=body['value']).delete()
            else:
                n, _ = AlertRecord.objects.all().delete()
            return _cors(JsonResponse({'status': 'cleared', 'deleted': n}))
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=500)


# ── Log Viewer ─────────────────────────────────────────────────────────────────
def get_log_lines(request):
    """Return last N lines of the Django/Daphne log file."""
    from django.conf import settings
    import pathlib

    n        = min(int(request.GET.get('lines', 200)), 2000)
    kind     = request.GET.get('kind', 'ids')   # ids | django

    # Try common log locations
    candidates = [
        pathlib.Path(settings.BASE_DIR).parent / 'logs' / f'{kind}.log',
        pathlib.Path(settings.BASE_DIR).parent / f'{kind}.log',
        pathlib.Path(settings.BASE_DIR) / 'logs' / f'{kind}.log',
    ]
    log_path = next((p for p in candidates if p.exists()), None)

    if log_path is None:
        # Fall back to Python logging memory handler or return placeholder
        return _cors(JsonResponse({
            'lines': ['[LOG FILE NOT FOUND] Configure LOGGING in settings.py to write to a file.',
                      'Expected location: <project_root>/logs/ids.log'],
            'path': str(candidates[0]),
        }))

    try:
        with open(log_path, 'r', errors='replace') as f:
            all_lines = f.readlines()
        lines = [l.rstrip() for l in all_lines[-n:]]
        return _cors(JsonResponse({'lines': lines, 'path': str(log_path), 'total': len(all_lines)}))
    except Exception as exc:
        return _cors(JsonResponse({'lines': [f'Error reading log: {exc}'], 'path': str(log_path)}))
