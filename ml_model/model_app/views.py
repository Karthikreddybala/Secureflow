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
from sklearn.discriminant_analysis import StandardScaler

logger = logging.getLogger(__name__)

MODEL_ROOT = Path(__file__).resolve().parents[1] / 'ai_models' / 'models'
RF_MODEL_PATH = MODEL_ROOT / 'rf.plk'
ISO_MODEL_PATH = MODEL_ROOT / 'isolation_forest.pkl'

# Model feature list retained exactly as expected by the trained models.
FEATURES = [
    ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets', 'Total Length of Fwd Packets',
    ' Total Length of Bwd Packets', ' Fwd Packet Length Mean', ' Bwd Packet Length Mean', 'Flow Bytes/s',
    ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std',
    'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', 'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags',
    ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count',
    ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' Average Packet Size', ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size', ' Fwd Header Length.1', ' act_data_pkt_fwd', ' min_seg_size_forward',
    'Active Mean', ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
]

# Flow processing settings tuned for smoother real-time response.
FLOW_TIMEOUT = 8.0
MIN_PACKETS_FOR_PROCESSING = 5
MAX_FLOW_PACKETS = 120
ACTIVE_FLOW_FLUSH_INTERVAL = 2.0
MAX_Y_ALERT_SCORE = 100.0

rf = joblib.load(RF_MODEL_PATH)
iso = joblib.load(ISO_MODEL_PATH)

flows = {}
flows_lock = threading.Lock()

processing_stats = {
    'flows_processed': 0,
    'packets_processed': 0,
    'alerts_emitted': 0,
    'avg_processing_time_ms': 0.0,
    'start_time': time.time()
}


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _protocol_label(value):
    protocol = str(value).upper()
    if protocol == '6':
        return 'TCP'
    if protocol == '17':
        return 'UDP'
    if protocol == '1':
        return 'ICMP'
    return protocol


def _flow_id(packet):
    keys = ('src', 'dst', 'sport', 'dport', 'proto')
    if any(key not in packet for key in keys):
        return None

    return (
        str(packet.get('src', 'Unknown')),
        str(packet.get('dst', 'Unknown')),
        str(packet.get('sport', '')),
        str(packet.get('dport', '')),
        str(packet.get('proto', 'Unknown'))
    )


def fusion_engine(rf_label, rf_confidence, iso_score):
    if str(rf_label).lower() != 'normal':
        severity = 'High' if rf_confidence >= 0.80 else 'Medium'
        return {
            'final_score': round(min(MAX_Y_ALERT_SCORE, rf_confidence * 100.0), 2),
            'attack_type': str(rf_label),
            'severity': severity
        }

    if iso_score > 0.25:
        return {
            'final_score': round(min(MAX_Y_ALERT_SCORE, iso_score * 100.0), 2),
            'attack_type': 'Anomaly',
            'severity': 'Medium'
        }

    # Explicitly emit normal traffic alerts so dashboard always shows them.
    return {
        'final_score': round(min(MAX_Y_ALERT_SCORE, iso_score * 100.0), 2),
        'attack_type': 'Normal',
        'severity': 'Low'
    }


def process_packet(packet):
    with flows_lock:
        _ingest_packet_locked(packet)


def _ingest_packet_locked(packet):
    fid = _flow_id(packet)
    if not fid:
        return False

    now = time.time()
    packet_size = max(1, int(packet.get('size') or packet.get('bytes') or 0))

    flow = flows.get(fid)
    if flow is None:
        flow = {
            'timestamps': [],
            'sizes': [],
            'fwd_sizes': [],
            'bwd_sizes': [],
            'flags': [],
            'fwd_hdr_len': [],
            'bwd_hdr_len': [],
            'src': fid[0],
            'first': now,
            'last': now
        }
        flows[fid] = flow

    flow['timestamps'].append(now)
    flow['sizes'].append(packet_size)

    if fid[0] == flow['src']:
        flow['fwd_sizes'].append(packet_size)
    else:
        flow['bwd_sizes'].append(packet_size)

    flow['last'] = now
    return True


def _compute_features(flow):
    print(flow['sizes'])
    timestamps = flow['timestamps']
    sizes = flow['sizes']
    fwd_sizes = flow['fwd_sizes']
    bwd_sizes = flow['bwd_sizes']

    duration = (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.001
    duration_safe = max(duration, 0.001)

    iats = np.diff(np.array(timestamps, dtype=float)) if len(timestamps) > 1 else np.array([0.0], dtype=float)
    packet_count = max(len(sizes), 1)

    fwd_iats = iats[:len(fwd_sizes)] if len(fwd_sizes) else np.array([0.0])
    bwd_iats = iats[len(fwd_sizes):] if len(bwd_sizes) else np.array([0.0])

    return {
        'Flow Duration': duration,
        'Total Fwd Packets': len(fwd_sizes),
        'Total Backward Packets': len(bwd_sizes),
        'Total Length of Fwd Packets': float(sum(fwd_sizes)),
        'Total Length of Bwd Packets': float(sum(bwd_sizes)),
        'Fwd Packet Length Mean': _safe_float(np.mean(fwd_sizes)) if fwd_sizes else 0.0,
        'Bwd Packet Length Mean': _safe_float(np.mean(bwd_sizes)) if bwd_sizes else 0.0,
        'Flow Bytes/s': _safe_float(sum(sizes) / duration_safe),
        'Flow Packets/s': _safe_float(len(sizes) / duration_safe),
        'Flow IAT Mean': _safe_float(np.mean(iats)),
        'Flow IAT Std': _safe_float(np.std(iats)),
        'Fwd IAT Total': _safe_float(np.sum(fwd_iats)),
        'Fwd IAT Mean': _safe_float(np.mean(fwd_iats)),
        'Fwd IAT Std': _safe_float(np.std(fwd_iats)),
        'Bwd IAT Total': _safe_float(np.sum(bwd_iats)),
        'Bwd IAT Mean': _safe_float(np.mean(bwd_iats)),
        'Bwd IAT Std': _safe_float(np.std(bwd_iats)),
        'Fwd PSH Flags': 0.0,
        'Bwd PSH Flags': 0.0,
        'Fwd URG Flags': 0.0,
        'Bwd URG Flags': 0.0,
        'Fwd Header Length': 0.0,
        'Bwd Header Length': 0.0,
        'Fwd Packets/s': _safe_float(len(fwd_sizes) / duration_safe),
        'Bwd Packets/s': _safe_float(len(bwd_sizes) / duration_safe),
        'Packet Length Mean': _safe_float(np.mean(sizes)),
        'Packet Length Std': _safe_float(np.std(sizes)),
        'Packet Length Variance': _safe_float(np.var(sizes)),
        'FIN Flag Count': 0.0,
        'SYN Flag Count': 0.0,
        'RST Flag Count': 0.0,
        'PSH Flag Count': 0.0,
        'ACK Flag Count': 0.0,
        'Average Packet Size': _safe_float(sum(sizes) / packet_count),
        'Avg Fwd Segment Size': _safe_float(np.mean(fwd_sizes)) if fwd_sizes else 0.0,
        'Avg Bwd Segment Size': _safe_float(np.mean(bwd_sizes)) if bwd_sizes else 0.0,
        'Fwd Header Length.1': 0.0,
        'act_data_pkt_fwd': float(len([value for value in fwd_sizes if value > 0])),
        'min_seg_size_forward': float(min(fwd_sizes) if fwd_sizes else 0.0),
        'Active Mean': _safe_float(duration_safe / packet_count),
        'Active Std': _safe_float(np.std(iats)),
        'Active Max': _safe_float(np.max(iats)),
        'Active Min': _safe_float(np.min(iats)),
        'Idle Mean': _safe_float(np.mean(iats)),
        'Idle Std': _safe_float(np.std(iats)),
        'Idle Max': _safe_float(np.max(iats)),
        'Idle Min': _safe_float(np.min(iats))
    }


def _prepare_model_row(feature_map):
    row = {}
    for feature in FEATURES:
        trimmed = feature.strip()
        row[feature] = _safe_float(feature_map.get(feature, feature_map.get(trimmed, 0.0)))
    return row


def _predict_alerts(flow_items):
    if not flow_items:
        return []

    start = time.time()

    feature_rows = []
    for _, flow in flow_items:
        feature_rows.append(_prepare_model_row(_compute_features(flow)))
    

    frame = pd.DataFrame(feature_rows, columns=FEATURES).fillna(0.0)
    scaler = StandardScaler()
    X_s = scaler.fit_transform(frame)
    rf_pred = rf.predict(X_s)
    if hasattr(rf, 'predict_proba'):
        rf_prob = rf.predict_proba(X_s).max(axis=1)
    else:
        rf_prob = np.ones(len(flow_items), dtype=float)
    

    iso_scores = np.abs(iso.decision_function(frame))
    print(rf_pred, rf_prob, iso_scores)

    alerts = []
    for index, (fid, _) in enumerate(flow_items):
        fused = fusion_engine(str(rf_pred[index]), float(rf_prob[index]), float(iso_scores[index]))

        alert = {
            'final': fused,
            'protocol': _protocol_label(fid[4]),
            'src_ip': fid[0],
            'dst_ip': fid[1],
            'sport': fid[2],
            'dport': fid[3],
            'timestamp': time.time(),
            'message': f"Flow processed: {fused['attack_type']} ({fused['severity']})"
        }
        alerts.append(alert)

    elapsed_ms = (time.time() - start) * 1000.0
    flows_count = len(flow_items)

    if flows_count:
        previous_total = processing_stats['flows_processed']
        new_total = previous_total + flows_count
        processing_stats['avg_processing_time_ms'] = (
            (processing_stats['avg_processing_time_ms'] * previous_total) + elapsed_ms
        ) / max(new_total, 1)

    return alerts


def _select_ready_flows(force=False):
    now = time.time()
    ready = []

    with flows_lock:
        for fid, flow in list(flows.items()):
            packet_count = len(flow['sizes'])
            flow_age = now - flow['first']
            idle_age = now - flow['last']

            should_process = (
                force
                or packet_count >= MAX_FLOW_PACKETS
                or idle_age >= FLOW_TIMEOUT
                or (packet_count >= MIN_PACKETS_FOR_PROCESSING and flow_age >= ACTIVE_FLOW_FLUSH_INTERVAL)
            )

            if should_process:
                ready.append((fid, flow))
                del flows[fid]

    return ready


def flush_flows_async(force=False):
    ready_flows = _select_ready_flows(force=force)
    alerts = _predict_alerts(ready_flows)

    if alerts:
        async_to_sync(send_alert_batch_async)(alerts)

    processing_stats['flows_processed'] += len(ready_flows)
    processing_stats['alerts_emitted'] += len(alerts)
    return len(alerts)


def process_packet_batch(packets, force_flush=False):
    valid_packets = [packet for packet in packets if isinstance(packet, dict)]

    ingested_count = 0
    with flows_lock:
        for packet in valid_packets:
            if _ingest_packet_locked(packet):
                ingested_count += 1

    processing_stats['packets_processed'] += ingested_count
    ready_flows = _select_ready_flows(force=force_flush)
    alerts = _predict_alerts(ready_flows)

    if alerts:
        async_to_sync(send_alert_batch_async)(alerts)

    processing_stats['flows_processed'] += len(ready_flows)
    processing_stats['alerts_emitted'] += len(alerts)
    return alerts


def get_processing_stats():
    uptime = time.time() - processing_stats['start_time']
    with flows_lock:
        in_memory_flows = len(flows)

    flows_processed = max(processing_stats['flows_processed'], 1)
    return {
        'flows_processed': processing_stats['flows_processed'],
        'packets_processed': processing_stats['packets_processed'],
        'alerts_emitted': processing_stats['alerts_emitted'],
        'avg_packets_per_flow': processing_stats['packets_processed'] / flows_processed,
        'avg_processing_time_ms': processing_stats['avg_processing_time_ms'],
        'queue_depth': 0,
        'uptime_seconds': uptime,
        'flows_in_memory': in_memory_flows,
        'processing_rate_flows_per_sec': processing_stats['flows_processed'] / max(uptime, 1.0),
        'processing_rate_packets_per_sec': processing_stats['packets_processed'] / max(uptime, 1.0)
    }


async def send_packet_batch_async(packets):
    channel_layer = get_channel_layer()
    await channel_layer.group_send(
        'network_traffic',
        {
            'type': 'send_traffic',
            'data': packets
        }
    )


async def send_alert_async(alert):
    channel_layer = get_channel_layer()
    await channel_layer.group_send(
        'alerts',
        {
            'type': 'send_alert',
            'data': alert
        }
    )


async def send_alert_batch_async(alerts):
    for alert in alerts:
        await send_alert_async(alert)


def send_alert(alert):
    async_to_sync(send_alert_async)(alert)


def start_parallel_processors(num_workers=3):
    # Retained for backward compatibility with existing management command.
    logger.info('Inline batch processor active. Separate workers are not required (requested: %s).', num_workers)


@csrf_exempt
def predict_flow(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST is supported'}, status=405)

    try:
        body = json.loads(request.body)
        packets = body.get('packets', [])

        if not isinstance(packets, list):
            return JsonResponse({'status': 'error', 'message': 'packets must be a list'}, status=400)

        async_to_sync(send_packet_batch_async)(packets)
        alerts = process_packet_batch(packets, force_flush=False)

        return JsonResponse(
            {
                'status': 'ok',
                'message': 'Packets processed',
                'packet_count': len(packets),
                'alerts_emitted': len(alerts)
            }
        )
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON body'}, status=400)
    except Exception as error:
        logger.exception('Error in predict_flow')
        return JsonResponse({'status': 'error', 'message': str(error)}, status=500)
