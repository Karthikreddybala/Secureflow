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

import json
import logging
import threading
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

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
    X_rf    = scaler_rf.transform(frame)
    rf_pred = rf.predict(X_rf)
    rf_prob = rf.predict_proba(X_rf).max(axis=1) if hasattr(rf, 'predict_proba') else np.ones(len(flow_items))

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
        fused = fusion_engine(str(rf_pred[idx]), float(rf_prob[idx]), float(iso_scores[idx]))
        alerts.append({
            'final':     fused,
            'protocol':  _protocol_label(fid[4]),
            'src_ip':    fid[0],
            'dst_ip':    fid[1],
            'sport':     fid[2],
            'dport':     fid[3],
            'timestamp': time.time(),
            'message':   f"Flow: {fused['attack_type']} ({fused['severity']})",
        })

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
