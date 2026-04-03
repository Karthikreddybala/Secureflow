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
    'DoS':              {'id': 'T1498',     'name': 'Network Denial of Service',   'tactic': 'Impact'},
    'DDoS':             {'id': 'T1498.001', 'name': 'Direct Network Flood',        'tactic': 'Impact'},
    'PortScan':         {'id': 'T1046',     'name': 'Network Service Discovery',   'tactic': 'Discovery'},
    'BruteForce':       {'id': 'T1110',     'name': 'Brute Force',                 'tactic': 'Credential Access'},
    'SSHBruteForce':    {'id': 'T1110.004', 'name': 'SSH Credential Stuffing',     'tactic': 'Credential Access'},
    'RDPBruteForce':    {'id': 'T1110.001', 'name': 'Password Guessing via RDP',   'tactic': 'Credential Access'},
    'SYNFlood':         {'id': 'T1498.001', 'name': 'SYN Flood',                   'tactic': 'Impact'},
    'XmasScan':         {'id': 'T1046',     'name': 'Xmas Tree Port Scan',         'tactic': 'Discovery'},
    'NullScan':         {'id': 'T1046',     'name': 'Null Scan (OS Fingerprint)',   'tactic': 'Discovery'},
    'FINScan':          {'id': 'T1046',     'name': 'FIN Scan (Stealth Probe)',     'tactic': 'Discovery'},
    'ICMPFlood':        {'id': 'T1498',     'name': 'ICMP Flood',                  'tactic': 'Impact'},
    'HTTPFlood':        {'id': 'T1499.002', 'name': 'HTTP/HTTPS Flood',            'tactic': 'Impact'},
    'DNSExfiltration':  {'id': 'T1048.003', 'name': 'DNS Tunneling Exfiltration',  'tactic': 'Exfiltration'},
    'C2Beacon':         {'id': 'T1071',     'name': 'C2 Application Protocol',     'tactic': 'Command & Control'},
    'CredStuffing':     {'id': 'T1110.004', 'name': 'Credential Stuffing',         'tactic': 'Credential Access'},
    'Botnet':           {'id': 'T1071',     'name': 'Application Layer Protocol',  'tactic': 'Command & Control'},
    'Infiltration':     {'id': 'T1190',     'name': 'Exploit Public-Facing App',   'tactic': 'Initial Access'},
    'Heartbleed':       {'id': 'T1203',     'name': 'Exploitation for Client Exec','tactic': 'Execution'},
    'Anomaly':          {'id': 'T1499',     'name': 'Endpoint Denial of Service',  'tactic': 'Impact'},
}

# ── Trusted IP Whitelist (never alert on these — DNS resolvers, CDN, NTP) ──────
WHITELIST_IPS: set[str] = {
    '8.8.8.8', '8.8.4.4',               # Google DNS
    '1.1.1.1', '1.0.0.1',               # Cloudflare DNS
    '9.9.9.9', '149.112.112.112',        # Quad9 DNS
    '208.67.222.222', '208.67.220.220',  # OpenDNS
    '216.58.0.0',                        # Google (block)
    '192.168.137.1',                     # Hotspot gateway — never self-alert
}

# ── Known C2 / malware ports ───────────────────────────────────────────────────
_C2_PORTS: frozenset[int] = frozenset({
    4444,   # Metasploit default
    4445,   # Metasploit alt
    1337,   # leet / hackers
    31337,  # Back Orifice / leet
    6667, 6668, 6669,  # IRC botnet C2
    8080,   # proxy / C2 alt (only flagged if unusual pattern)
    9999,   # common reverse shell
    12345,  # NetBus RAT
    27374,  # SubSeven RAT
    65535,  # common test C2
})

# ── Alert Dedup Cache ─────────────────────────────────────────────────────────
# Suppress duplicate (src_ip, attack_type) alerts within DEDUP_WINDOW seconds.
_dedup_cache: dict[tuple, float] = {}   # (src_ip, attack_type) → last_alerted_ts
_dedup_lock  = threading.Lock()
DEDUP_WINDOW = 60.0  # seconds

def _should_suppress(src_ip: str, attack_type: str) -> bool:
    """Return True if this exact (src, attack) was already alerted within DEDUP_WINDOW."""
    if src_ip in WHITELIST_IPS:
        return True
    key = (src_ip, attack_type)
    now = time.time()
    with _dedup_lock:
        last = _dedup_cache.get(key, 0.0)
        if now - last < DEDUP_WINDOW:
            return True
        _dedup_cache[key] = now
    return False

# Periodic cleanup of stale dedup entries
def _dedup_cleanup():
    while True:
        time.sleep(120)
        now = time.time()
        with _dedup_lock:
            stale = [k for k, v in _dedup_cache.items() if now - v > DEDUP_WINDOW * 3]
            for k in stale:
                del _dedup_cache[k]

threading.Thread(target=_dedup_cleanup, daemon=True).start()

# ── Suricata-Style Deterministic Rule Engine ───────────────────────────────────
# Tracks per-source-IP sliding-window state for stateful rule detection.
# This runs on EVERY PACKET — before flow completion — enabling sub-second detection.

RULE_WINDOW       = 30.0  # seconds — sliding window for most rate rules
RULE_WINDOW_SHORT =  5.0  # seconds — for high-speed floods

# Per-ip state dict structure:
# {
#   'syn_targets':     set of (ts, dport) — for port scan
#   'syn_ts':         list of timestamps  — for SYN flood
#   'ssh_ts':         list of timestamps  — SSH brute-force
#   'rdp_ts':         list of timestamps  — RDP brute-force
#   'http_ts':        list of timestamps  — HTTP flood
#   'icmp_ts':        list of timestamps  — ICMP flood
#   'dns_ts':         list of timestamps  — DNS exfiltration
#   'rst_after_syn':  int                 — credential stuffing RST count
#   'rst_ts':         list of timestamps
#   'c2_hits':        int                 — C2 port matches
# }
_rule_state: dict[str, dict] = {}
_rule_lock  = threading.Lock()

def _rule_state_for(ip: str) -> dict:
    """Get-or-create the rule state dict for an IP (must be called under _rule_lock)."""
    if ip not in _rule_state:
        _rule_state[ip] = {
            'syn_targets': set(),
            'syn_ts':      [],
            'ssh_ts':      [],
            'rdp_ts':      [],
            'http_ts':     [],
            'icmp_ts':     [],
            'dns_ts':      [],
            'rst_ts':      [],
            'c2_hits':     0,
            'c2_last':     0.0,
        }
    return _rule_state[ip]

def _prune_ts(ts_list: list, now: float, window: float) -> list:
    """In-place prune timestamps older than window; returns same list."""
    cutoff = now - window
    ts_list[:] = [t for t in ts_list if t >= cutoff]
    return ts_list

def _prune_syn_targets(targets: set, now: float, window: float) -> set:
    """Remove (ts, port) pairs older than window."""
    cutoff = now - window
    targets -= {(t, p) for t, p in targets if t < cutoff}
    return targets


def _fire_rule_alert(src_ip: str, dst_ip: str, sport, dport,
                     protocol: str, attack_type: str, severity: str,
                     detail: str = '', rule_score: float = 95.0,
                     is_simulated: bool = False):
    """
    Emit a deterministic rule-based alert immediately, bypassing the ML flow pipeline.
    Rule alerts fire in real-time (per-packet) — no need to wait for flow completion.
    """
    if _should_suppress(src_ip, attack_type):
        return

    mitre = ATTACK_TO_MITRE.get(attack_type, {})
    abuse = abuse_ipdb.get_abuse_score(src_ip)

    alert = {
        'final': {
            'final_score':  rule_score,
            'attack_type':  attack_type,
            'severity':     severity,
        },
        'protocol':     protocol,
        'src_ip':       src_ip,
        'dst_ip':       dst_ip,
        'sport':        str(sport),
        'dport':        str(dport),
        'timestamp':    time.time(),
        'mitre':        mitre,
        'shap':         [],
        'abuse_score':  abuse,
        'abuse_badge':  abuse_ipdb.badge(abuse),
        'message':      f'[RULE] {attack_type}: {detail}',
        'rule_triggered': True,
        'is_simulated': is_simulated,
    }

    # Host threat score
    _update_host_score(src_ip, severity, attack_type)

    # Incident correlation
    incident = incident_engine.correlate_alert(alert)
    if incident:
        alert['incident_id'] = incident['id']

    # In-memory store for export
    global _recent_alerts
    _recent_alerts = (_recent_alerts + [alert])[-_MAX_RECENT:]

    # Persist to DB
    try:
        f = alert['final']
        m = alert.get('mitre', {})
        AlertRecord.objects.create(
            timestamp    = alert['timestamp'],
            src_ip       = src_ip or None,
            dst_ip       = dst_ip or None,
            sport        = str(sport) or None,
            dport        = str(dport) or None,
            protocol     = protocol,
            attack_type  = f['attack_type'],
            severity     = f['severity'],
            confidence   = float(f['final_score']),
            mitre_id     = m.get('id', ''),
            mitre_tactic = m.get('tactic', ''),
            abuse_score  = int(abuse),
            incident_id  = str(alert.get('incident_id', '')),
            is_simulated = is_simulated,
        )
    except Exception as _db_err:
        logger.debug('Rule alert DB write failed: %s', _db_err)

    # Email + push for Medium/High hotspot alerts
    if severity in ('Medium', 'High') and _is_hotspot_ip(src_ip):
        _dev_mac = ''
        try:
            with _hotspot_tracker._lock:
                _dev_rec = _hotspot_tracker._devices.get(src_ip)
                if _dev_rec:
                    _dev_mac = _dev_rec.mac
        except Exception:
            pass
        _send_device_alert_email(src_ip, _dev_mac, alert)
    _send_push_notifications(alert)

    # Broadcast via WebSocket immediately
    try:
        async_to_sync(send_alert_async)(alert)
    except Exception as _ws_err:
        logger.debug('Rule alert WS push failed: %s', _ws_err)

    processing_stats['alerts_emitted'] += 1
    logger.info('[RULE] %s | src=%s dst=%s:%s sev=%s score=%.0f detail=%s',
                attack_type, src_ip, dst_ip, dport, severity, rule_score, detail)


def _rule_engine(src_ip: str, dst_ip: str, sport: int, dport: int,
                 proto: int, flags: int, pkt_size: int,
                 is_simulated: bool = False):
    """
    Suricata-style per-packet rule engine.
    Called on EVERY ingested packet — fires deterministic signatures in real-time.
    Operates entirely outside the ML flow pipeline.

    Rules implemented:
      1. PortScan         — SYN to ≥30 unique ports in 30s
      2. SYNFlood         — >50 SYN/s from one IP (5s window)
      3. XmasScan         — FIN+PSH+URG set simultaneously
      4. NullScan         — all flags = 0 on TCP packet
      5. FINScan          — FIN-only TCP
      6. SSHBruteForce    — >10 connections to :22 in 30s
      7. RDPBruteForce    — >10 connections to :3389 in 30s
      8. HTTPFlood        — >100 SYN connections to :80/:443 in 10s
      9. ICMPFlood        — >100 ICMP packets in 5s
     10. DNSExfiltration  — >20 DNS queries in 5s OR single DNS pkt >200 bytes
     11. C2Beacon         — traffic to known C2 ports
     12. CredStuffing     — >20 RST after SYN in 30s (failed connection storm)
    """
    if src_ip in WHITELIST_IPS or dst_ip in WHITELIST_IPS:
        return
    if not src_ip or src_ip == 'unknown':
        return

    now       = time.time()
    proto_str = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))

    with _rule_lock:
        st = _rule_state_for(src_ip)

        # ── Rule 3: Xmas Scan ─────────────────────────────────────────────────
        if proto == 6 and (flags & (_FIN | _PSH | _URG)) == (_FIN | _PSH | _URG):
            _fire_rule_alert(
                src_ip, dst_ip, sport, dport, proto_str,
                'XmasScan', 'High', f'Xmas flags to port {dport}',
                rule_score=96.0, is_simulated=is_simulated
            )
            return

        # ── Rule 4: Null Scan ─────────────────────────────────────────────────
        if proto == 6 and flags == 0:
            _fire_rule_alert(
                src_ip, dst_ip, sport, dport, proto_str,
                'NullScan', 'High', f'Null flags on TCP to port {dport}',
                rule_score=95.0, is_simulated=is_simulated
            )
            return

        # ── Rule 5: FIN Scan ──────────────────────────────────────────────────
        if proto == 6 and flags == _FIN:
            _fire_rule_alert(
                src_ip, dst_ip, sport, dport, proto_str,
                'FINScan', 'Medium', f'FIN-only scan to port {dport}',
                rule_score=88.0, is_simulated=is_simulated
            )
            return

        # ── Rule 9: ICMP Flood ────────────────────────────────────────────────
        if proto == 1:  # ICMP
            _prune_ts(st['icmp_ts'], now, RULE_WINDOW_SHORT)
            st['icmp_ts'].append(now)
            if len(st['icmp_ts']) > 100:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, 'ICMP',
                    'ICMPFlood', 'High',
                    f'{len(st["icmp_ts"])} ICMP pkts in {RULE_WINDOW_SHORT:.0f}s',
                    rule_score=92.0, is_simulated=is_simulated
                )
                st['icmp_ts'].clear()
            return

        # ── Rule 10: DNS Exfiltration ─────────────────────────────────────────
        if dport == 53 or sport == 53:
            _prune_ts(st['dns_ts'], now, RULE_WINDOW_SHORT)
            st['dns_ts'].append(now)
            if len(st['dns_ts']) > 20:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, 'UDP',
                    'DNSExfiltration', 'High',
                    f'{len(st["dns_ts"])} DNS queries in {RULE_WINDOW_SHORT:.0f}s',
                    rule_score=90.0, is_simulated=is_simulated
                )
                st['dns_ts'].clear()
            elif pkt_size > 200 and dport == 53:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, 'UDP',
                    'DNSExfiltration', 'Medium',
                    f'Oversized DNS query: {pkt_size}B',
                    rule_score=82.0, is_simulated=is_simulated
                )
            return

        # ── Rule 11: C2 Port Beacon ───────────────────────────────────────────
        if dport in _C2_PORTS:
            # Only alert once per 120s per (src, port) to avoid spam
            c2_key = (src_ip, dport)
            # We use a simple time gate stored per-IP
            if now - st.get('c2_last', 0.0) > 120:
                st['c2_last'] = now
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, proto_str,
                    'C2Beacon', 'High',
                    f'Traffic to known C2 port {dport}',
                    rule_score=97.0, is_simulated=is_simulated
                )
            return

        # From here: TCP-only rules that use flags
        if proto != 6:
            return

        is_syn_only = (flags & _SYN) and not (flags & _ACK)
        is_syn_ack  = (flags & _SYN) and (flags & _ACK)
        is_rst      = bool(flags & _RST)

        # ── Rule 1: Port Scan ─────────────────────────────────────────────────
        if is_syn_only:
            _prune_syn_targets(st['syn_targets'], now, RULE_WINDOW)
            st['syn_targets'].add((now, dport))
            unique_ports = len({p for _, p in st['syn_targets']})
            if unique_ports >= 30:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, 'TCP',
                    'PortScan', 'High',
                    f'{unique_ports} unique ports SYN-scanned in {RULE_WINDOW:.0f}s',
                    rule_score=95.0, is_simulated=is_simulated
                )
                st['syn_targets'].clear()

        # ── Rule 2: SYN Flood ─────────────────────────────────────────────────
        if is_syn_only:
            _prune_ts(st['syn_ts'], now, RULE_WINDOW_SHORT)
            st['syn_ts'].append(now)
            if len(st['syn_ts']) > 50:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, 'TCP',
                    'SYNFlood', 'High',
                    f'{len(st["syn_ts"])} SYN pkts in {RULE_WINDOW_SHORT:.0f}s',
                    rule_score=98.0, is_simulated=is_simulated
                )
                st['syn_ts'].clear()

        # ── Rule 6: SSH Brute-Force ───────────────────────────────────────────
        if dport == 22 and is_syn_only:
            _prune_ts(st['ssh_ts'], now, RULE_WINDOW)
            st['ssh_ts'].append(now)
            if len(st['ssh_ts']) > 10:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, 22, 'TCP',
                    'SSHBruteForce', 'High',
                    f'{len(st["ssh_ts"])} SSH connections in {RULE_WINDOW:.0f}s',
                    rule_score=93.0, is_simulated=is_simulated
                )
                st['ssh_ts'].clear()

        # ── Rule 7: RDP Brute-Force ───────────────────────────────────────────
        if dport == 3389 and is_syn_only:
            _prune_ts(st['rdp_ts'], now, RULE_WINDOW)
            st['rdp_ts'].append(now)
            if len(st['rdp_ts']) > 10:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, 3389, 'TCP',
                    'RDPBruteForce', 'High',
                    f'{len(st["rdp_ts"])} RDP connections in {RULE_WINDOW:.0f}s',
                    rule_score=93.0, is_simulated=is_simulated
                )
                st['rdp_ts'].clear()

        # ── Rule 8: HTTP Flood ────────────────────────────────────────────────
        if dport in (80, 443, 8080, 8443) and is_syn_only:
            _prune_ts(st['http_ts'], now, 10.0)
            st['http_ts'].append(now)
            if len(st['http_ts']) > 100:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, 'TCP',
                    'HTTPFlood', 'High',
                    f'{len(st["http_ts"])} HTTP/S connections in 10s',
                    rule_score=92.0, is_simulated=is_simulated
                )
                st['http_ts'].clear()

        # ── Rule 12: Credential Stuffing (RST storm) ──────────────────────────
        if is_rst:
            _prune_ts(st['rst_ts'], now, RULE_WINDOW)
            st['rst_ts'].append(now)
            if len(st['rst_ts']) > 20:
                _fire_rule_alert(
                    src_ip, dst_ip, sport, dport, 'TCP',
                    'CredStuffing', 'Medium',
                    f'{len(st["rst_ts"])} RST pkts in {RULE_WINDOW:.0f}s (failed connection storm)',
                    rule_score=80.0, is_simulated=is_simulated
                )
                st['rst_ts'].clear()

# Periodic cleanup of stale rule state (hosts that haven't sent a packet in 5 min)
def _rule_state_cleanup():
    while True:
        time.sleep(300)
        now = time.time()
        with _rule_lock:
            stale = [ip for ip, st in _rule_state.items()
                     if not st['syn_ts'] and not st['syn_targets']
                     and not st['ssh_ts'] and not st['icmp_ts']]
            for ip in stale:
                del _rule_state[ip]

threading.Thread(target=_rule_state_cleanup, daemon=True).start()

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


# ── SMTP / Email Configuration ─────────────────────────────────────────────────
import smtplib
import os as _os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

_SMTP_HOST = _os.getenv('SMTP_HOST', 'smtp.gmail.com')
_SMTP_PORT = int(_os.getenv('SMTP_PORT', 587))
_SMTP_USER = _os.getenv('SMTP_USER', '')
_SMTP_PASS = _os.getenv('SMTP_PASSWORD', '')
_SMTP_FROM = _os.getenv('SMTP_FROM', _os.getenv('SMTP_USER', ''))

# Per-device email cooldown: (device_ip, email) → last_sent_timestamp
_dev_email_cooldown: dict[tuple, float] = {}
_DEV_EMAIL_COOLDOWN_SECS = 300   # max 1 email per device+recipient per 5 min
_dev_email_lock = threading.Lock()

_SEV_ORDER = {'Low': 0, 'Medium': 1, 'High': 2}


def _send_device_alert_email(device_ip: str, device_mac: str, alert: dict):
    """Send email to all DeviceAlertEmail rules matching this device IP/MAC.
    Runs lookups in a background thread — never blocks the hot path.
    """
    if not _SMTP_USER or not _SMTP_PASS:
        return
    severity = alert.get('final', {}).get('severity', 'Low')

    def _worker():
        try:
            from model_app.models import DeviceAlertEmail
            import django.db
            from django.db import models as _dj_models
            rules = DeviceAlertEmail.objects.filter(enabled=True).filter(
                _dj_models.Q(ip=device_ip) | _dj_models.Q(mac__iexact=device_mac)
            )
            now = time.time()
            for rule in rules:
                if _SEV_ORDER.get(severity, 0) < _SEV_ORDER.get(rule.min_severity, 1):
                    continue
                key = (device_ip, rule.email)
                with _dev_email_lock:
                    if now - _dev_email_cooldown.get(key, 0) < _DEV_EMAIL_COOLDOWN_SECS:
                        continue
                    _dev_email_cooldown[key] = now
                _do_send_email(rule.email, device_ip, rule.label or device_ip, alert)
        except Exception as _e:
            logger.warning('Device email worker error: %s', _e)

    threading.Thread(target=_worker, daemon=True).start()


def _do_send_email(to: str, device_ip: str, device_label: str, alert: dict):
    """Blocking SMTP send — always called from a daemon thread."""
    try:
        f = alert.get('final', {})
        m = alert.get('mitre', {})
        attack   = f.get('attack_type', 'Unknown')
        sev      = f.get('severity', 'Unknown')
        score    = f.get('final_score', 0)
        src_ip   = alert.get('src_ip', '—')
        dst_ip   = alert.get('dst_ip', '—')
        sport    = alert.get('sport', '?')
        dport    = alert.get('dport', '?')
        protocol = alert.get('protocol', '—')
        mitre_id = m.get('id', '—')
        mitre_nm = m.get('name', '—')
        tactic   = m.get('tactic', '—')
        ts       = time.strftime('%Y-%m-%d %H:%M:%S',
                                 time.localtime(alert.get('timestamp', time.time())))
        sev_color = {'High': '#f85149', 'Medium': '#d29922'}.get(sev, '#3fb950')
        shap_rows = ''.join(
            f'<tr><td style="padding:6px 8px;color:#8b949e;">{s["feature"]}</td>'
            f'<td style="padding:6px 8px;color:{"#f85149" if s["impact"]>0 else "#58a6ff"};'
            f'font-family:monospace;">{("+" if s["impact"]>0 else "")}{s["impact"]}</td></tr>'
            for s in alert.get('shap', [])
        )

        subject = f'[SecureFlow] {sev} Alert \u2014 {attack} | Device {device_label}'
        html = f"""
<html><body style="margin:0;padding:0;background:#0d1117;font-family:Arial,sans-serif;">
<div style="max-width:620px;margin:24px auto;background:#161b22;border-radius:14px;
            padding:28px;border:1px solid #30363d;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
    <div style="width:42px;height:42px;background:{sev_color}22;border-radius:10px;
                display:flex;align-items:center;justify-content:center;
                font-size:20px;">\U0001f6a8</div>
    <div>
      <div style="font-size:18px;font-weight:700;color:#e6edf3;">SecureFlow IDS Alert</div>
      <div style="font-size:12px;color:#8b949e;">{ts}</div>
    </div>
  </div>

  <div style="background:{sev_color}18;border:1px solid {sev_color}44;
              border-radius:8px;padding:14px 16px;margin-bottom:18px;">
    <div style="font-size:20px;font-weight:800;color:{sev_color};">{attack}</div>
    <div style="font-size:13px;color:{sev_color}cc;margin-top:2px;">
      Severity: <strong>{sev}</strong> &nbsp;|&nbsp; Score: {score:.1f}/100
    </div>
  </div>

  <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
    <tr style="background:#0d111788;">
      <td style="padding:8px 10px;color:#8b949e;font-size:13px;width:38%;">Device</td>
      <td style="padding:8px 10px;color:#e6edf3;font-size:13px;">{device_label}</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;color:#8b949e;font-size:13px;">Device IP</td>
      <td style="padding:8px 10px;font-family:monospace;color:#58a6ff;font-size:13px;">{device_ip}</td>
    </tr>
    <tr style="background:#0d111788;">
      <td style="padding:8px 10px;color:#8b949e;font-size:13px;">Flow</td>
      <td style="padding:8px 10px;font-family:monospace;color:#e6edf3;font-size:12px;">{protocol} {src_ip}:{sport} \u2192 {dst_ip}:{dport}</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;color:#8b949e;font-size:13px;">MITRE ATT&amp;CK</td>
      <td style="padding:8px 10px;color:#e6edf3;font-size:13px;">{mitre_id} \u2014 {mitre_nm}</td>
    </tr>
    <tr style="background:#0d111788;">
      <td style="padding:8px 10px;color:#8b949e;font-size:13px;">Tactic</td>
      <td style="padding:8px 10px;color:#e6edf3;font-size:13px;">{tactic}</td>
    </tr>
  </table>

  {(f'<div style="margin-bottom:16px;"><div style="font-size:12px;color:#8b949e;margin-bottom:6px;">SHAP Feature Drivers</div><table style="width:100%;border-collapse:collapse;font-size:12px;">{shap_rows}</table></div>') if shap_rows else ''}

  <div style="border-top:1px solid #30363d;padding-top:14px;font-size:11px;color:#484f58;">Sent by SecureFlow IDS Gateway &nbsp;|&nbsp; Do not reply</div>
</div></body></html>"""

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = _SMTP_FROM
        msg['To']      = to
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=12) as s:
            s.ehlo()
            s.starttls()
            s.login(_SMTP_USER, _SMTP_PASS)
            s.sendmail(_SMTP_FROM, [to], msg.as_string())
        logger.info('\U0001f4e7 Device alert email sent \u2192 %s  device=%s', to, device_ip)
    except Exception as exc:
        logger.warning('\u2717 Email to %s failed: %s', to, exc)


# ── VAPID Web Push ─────────────────────────────────────────────────────────────
_VAPID_PRIVATE_KEY = _os.getenv('VAPID_PRIVATE_KEY', '')
_VAPID_PUBLIC_KEY  = _os.getenv('VAPID_PUBLIC_KEY', '')
_VAPID_CLAIMS      = {'sub': f'mailto:{_os.getenv("SMTP_USER", "secureflow@localhost")}'}


def _send_push_notifications(alert: dict):
    """Send Web Push to all registered browser subscriptions."""
    if not _VAPID_PRIVATE_KEY or not _VAPID_PUBLIC_KEY:
        return

    def _worker():
        try:
            from pywebpush import webpush, WebPushException
            from model_app.models import PushSubscription
            import json as _json

            f     = alert.get('final', {})
            attack = f.get('attack_type', 'Unknown')
            sev    = f.get('severity', 'Low')
            src    = alert.get('src_ip', '?')
            subs   = list(PushSubscription.objects.all())

            payload = _json.dumps({
                'title': f'\U0001f6a8 SecureFlow — {sev} Alert',
                'body':  f'{attack} detected from {src}',
                'icon':  '/vite.svg',
                'badge': '/vite.svg',
                'data':  {'url': '/alerts', 'severity': sev},
            })

            dead_ids = []
            for sub in subs:
                try:
                    webpush(
                        subscription_info={
                            'endpoint': sub.endpoint,
                            'keys': {'p256dh': sub.p256dh, 'auth': sub.auth},
                        },
                        data=payload,
                        vapid_private_key=_VAPID_PRIVATE_KEY,
                        vapid_claims=_VAPID_CLAIMS,
                    )
                    PushSubscription.objects.filter(pk=sub.pk).update(last_used_at=time.time())
                except WebPushException as e:
                    if e.response and e.response.status_code in (404, 410):
                        dead_ids.append(sub.pk)  # subscription expired
                    else:
                        logger.debug('Push to %s failed: %s', sub.endpoint[:40], e)
                except Exception as e:
                    logger.debug('Push error: %s', e)

            if dead_ids:
                PushSubscription.objects.filter(pk__in=dead_ids).delete()
                logger.info('Pruned %d expired push subscriptions', len(dead_ids))
        except ImportError:
            logger.debug('pywebpush not installed — skipping push notification')
        except Exception as exc:
            logger.warning('Push notification worker error: %s', exc)

    threading.Thread(target=_worker, daemon=True).start()

# ── IP Blocking ────────────────────────────────────────────────────────────────
_blocked_ips: set[str] = set()
_block_lock  = threading.Lock()

def _block_ip_system(ip: str, force: bool = False):
    """Add a Windows Firewall inbound block rule for the given IP.
    force=True bypasses the private-IP guard (used for hotspot client blocks).
    """
    if not force and (ip in ('unknown', '') or ip.startswith(('127.', '10.'))):
        return  # never block loopback
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
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule}_out', 'dir=out', 'action=block', f'remoteip={ip}'],
                capture_output=True, timeout=5
            )
            _blocked_ips.add(ip)
            logger.info('Blocked IP via firewall: %s', ip)
        except Exception as exc:
            logger.warning('Firewall block failed for %s: %s', ip, exc)


def _unblock_ip_system(ip: str):
    """Remove Windows Firewall block rules for an IP."""
    rule = f'SecureFlow_Block_{ip}'
    try:
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule}'],
                       capture_output=True, timeout=5)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule}_out'],
                       capture_output=True, timeout=5)
        with _block_lock:
            _blocked_ips.discard(ip)
        logger.info('Unblocked IP via firewall: %s', ip)
    except Exception as exc:
        logger.warning('Firewall unblock failed for %s: %s', ip, exc)


# ── Hotspot Device Tracker ──────────────────────────────────────────────────────
import ipaddress
import socket
import collections

_HOTSPOT_SUBNET = ipaddress.ip_network('192.168.137.0/24')
_BANDWIDTH_HISTORY_SECS = 60   # keep 60 one-second buckets per device

# ── MAC OUI → Vendor lookup ────────────────────────────────────────────────────
# First 3 bytes (6 hex chars, no separators, upper-cased) → brand name
_OUI_TABLE: dict[str, str] = {
    # Apple
    '000A27': 'Apple', '000D93': 'Apple', '0017F2': 'Apple', '001CB3': 'Apple',
    '002312': 'Apple', '0026BB': 'Apple', '40A6D9': 'Apple', '44D884': 'Apple',
    '3C0754': 'Apple', '8C8590': 'Apple', 'A4B197': 'Apple', 'D83062': 'Apple',
    'F0DBF8': 'Apple', '60F81D': 'Apple', 'BC9FEF': 'Apple', '90B21F': 'Apple',
    # Samsung
    '002339': 'Samsung', '002566': 'Samsung', '0026E8': 'Samsung', '18AF61': 'Samsung',
    '2C4401': 'Samsung', '3C8BFE': 'Samsung', '40B395': 'Samsung', '5495D2': 'Samsung',
    '6C2F2C': 'Samsung', '8C77122': 'Samsung', 'A82174': 'Samsung', 'B4EF39': 'Samsung',
    'CC07AB': 'Samsung', 'E4928D': 'Samsung', 'F025B7': 'Samsung', '02CF24': 'Samsung',
    # Google / Android
    'DA5F47': 'Google', 'F4F5E8': 'Google', '3C5AB4': 'Google', '40E230': 'Google',
    # OnePlus
    '946EE0': 'OnePlus', 'AC37A0': 'OnePlus', 'C8F230': 'OnePlus',
    # Xiaomi
    '0C1DAF': 'Xiaomi', '284FDB': 'Xiaomi', '34CE009': 'Xiaomi', '64B473': 'Xiaomi',
    '8CBEBE': 'Xiaomi', 'AC2B6E': 'Xiaomi', 'F048EF': 'Xiaomi',
    # Huawei
    '001E10': 'Huawei', '009ACD': 'Huawei', '18CFCE': 'Huawei', '286ED4': 'Huawei',
    '4CA8D9': 'Huawei', '68A0F6': 'Huawei', 'B48430': 'Huawei', 'E89C25': 'Huawei',
    # Realme / OPPO
    '00BBF8': 'OPPO', 'A45E60': 'OPPO', '2C4D54': 'Realme',
    # Motorola
    '000A28': 'Motorola', '001B98': 'Motorola', '5C51EC': 'Motorola', 'AC37A0': 'Motorola',
    # Sony
    '001EE1': 'Sony', '0013A9': 'Sony', '7C1E52': 'Sony', 'F07D68': 'Sony',
    # LG
    '001C62': 'LG', '58A2B5': 'LG', 'A88388': 'LG', 'C4346B': 'LG',
    # Nokia / HMD
    '18E2C2': 'Nokia', 'A0C9A0': 'Nokia', 'BC8508': 'Nokia',
    # Dell
    '001560': 'Dell', '14FEB5': 'Dell', '18A99B': 'Dell', 'B8AC6F': 'Dell',
    # HP
    '001083': 'HP', '3C4A92': 'HP', '6C3BE5': 'HP', 'F4CE46': 'HP',
    # Lenovo
    '0024E8': 'Lenovo', '4CF95D': 'Lenovo', '70728D': 'Lenovo', 'E86F38': 'Lenovo',
    # Asus
    '000D18': 'Asus', '1C872C': 'Asus', '2C4D54': 'Asus', '60A44C': 'Asus',
    # Raspberry Pi
    'B827EB': 'RaspberryPi', 'DC:A6:32': 'RaspberryPi', 'E4:5F:01': 'RaspberryPi',
    # Amazon (Kindle/Echo)
    '0C4785': 'Amazon', '44650D': 'Amazon', '74C246': 'Amazon', 'A002DC': 'Amazon',
    # Intel (laptop Wi-Fi chips)
    '001BEB': 'Intel', '001DEA': 'Intel', '086D41': 'Intel', '4C8093': 'Intel',
    # Qualcomm
    '00A0C6': 'Qualcomm',
}


def _oui_vendor(mac: str) -> str:
    """Return the vendor name for a MAC address, or '' if unknown.
    Accepts dashes or colons as separators (Windows or Linux format).
    """
    if not mac or mac in ('-', '---'):
        return ''
    # Normalise to 6 uppercase hex chars with no separator
    clean = mac.upper().replace('-', '').replace(':', '')
    if len(clean) < 6:
        return ''
    prefix = clean[:6]
    return _OUI_TABLE.get(prefix, '')


def _infer_device_type(vendor: str, hostname: str) -> str:
    """Guess device category from vendor name and hostname."""
    v = (vendor or '').lower()
    h = (hostname or '').lower()
    phones  = ('samsung', 'apple', 'iphone', 'xiaomi', 'huawei', 'oppo',
               'realme', 'oneplus', 'nokia', 'motorola', 'sony', 'lg',
               'google', 'pixel', 'android')
    laptops = ('dell', 'hp', 'lenovo', 'asus', 'intel', 'macbook', 'thinkpad',
               'laptop', 'notebook')
    iot     = ('raspberry', 'amazon', 'echo', 'kindle', 'esp', 'arduino')
    if any(p in v or p in h for p in phones):
        return 'phone'
    if any(p in v or p in h for p in laptops):
        return 'laptop'
    if any(p in v or p in h for p in iot):
        return 'iot'
    return 'unknown'


def _is_hotspot_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in _HOTSPOT_SUBNET
    except ValueError:
        return False


class _DeviceRecord:
    """Per-device state tracked in memory."""
    __slots__ = (
        'ip', 'mac', 'hostname', 'first_seen', 'last_seen',
        'bytes_up', 'bytes_down', 'packets_up', 'packets_down',
        'status', 'top_ports', '_bw_history', '_bw_bucket_ts', '_bw_bucket',
        'vendor', 'device_type',
    )

    def __init__(self, ip: str):
        self.ip           = ip
        self.mac          = ''
        self.hostname     = ip
        self.first_seen   = time.time()
        self.last_seen    = time.time()
        self.bytes_up     = 0       # device → internet
        self.bytes_down   = 0       # internet → device
        self.packets_up   = 0
        self.packets_down = 0
        self.status       = 'online'
        self.top_ports: dict[int, int] = {}  # port → packet count
        self.vendor       = ''
        self.device_type  = 'unknown'
        # Bandwidth history: deque of (ts, bytes_up, bytes_down) per second
        self._bw_history: collections.deque = collections.deque(
            maxlen=_BANDWIDTH_HISTORY_SECS
        )
        self._bw_bucket_ts = int(time.time())
        self._bw_bucket    = [0, 0]   # [up_bytes, down_bytes] for current second

    def record_packet(self, pkt_size: int, is_upload: bool, dport: int):
        self.last_seen = time.time()
        self.status    = 'online'
        if is_upload:
            self.bytes_up   += pkt_size
            self.packets_up += 1
        else:
            self.bytes_down   += pkt_size
            self.packets_down += 1

        # Bandwidth bucket
        now_bucket = int(time.time())
        if now_bucket != self._bw_bucket_ts:
            self._bw_history.append((self._bw_bucket_ts, self._bw_bucket[0], self._bw_bucket[1]))
            self._bw_bucket    = [0, 0]
            self._bw_bucket_ts = now_bucket
        if is_upload:
            self._bw_bucket[0] += pkt_size
        else:
            self._bw_bucket[1] += pkt_size

        # Top-ports (cap at 20)
        if dport and dport > 0:
            self.top_ports[dport] = self.top_ports.get(dport, 0) + 1
            if len(self.top_ports) > 20:
                min_port = min(self.top_ports, key=self.top_ports.get)
                del self.top_ports[min_port]

    def to_dict(self) -> dict:
        # _host_scores is defined in this same module — no import needed
        threat = _host_scores.get(self.ip, {}).get('score', 0.0)
        bw_hist = list(self._bw_history)
        # Add current incomplete bucket
        bw_hist.append((self._bw_bucket_ts, self._bw_bucket[0], self._bw_bucket[1]))
        top3 = sorted(self.top_ports.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            'ip':          self.ip,
            'mac':         self.mac,
            'hostname':    self.hostname,
            'vendor':      self.vendor,
            'device_type': self.device_type,
            'first_seen':  self.first_seen,
            'last_seen':   self.last_seen,
            'bytes_up':    self.bytes_up,
            'bytes_down':  self.bytes_down,
            'packets_up':  self.packets_up,
            'packets_down':self.packets_down,
            'status':      self.status if self.ip not in _blocked_ips else 'blocked',
            'threat_score':round(threat, 1),
            'top_ports':   [{'port': p, 'count': c} for p, c in top3],
            'bw_history':  [{'ts': ts, 'up': u, 'down': d} for ts, u, d in bw_hist[-60:]],
        }


class HotspotDeviceTracker:
    """Thread-safe in-memory store of all hotspot-connected devices."""

    def __init__(self):
        self._devices: dict[str, _DeviceRecord] = {}
        self._lock    = threading.Lock()
        self._resolver_cache: dict[str, str] = {}
        # Immediate: query the hotspot neighbor table right now
        threading.Thread(target=self._query_hotspot_clients, daemon=True).start()
        # Background: poll neighbor table every 8 s (router-style)
        threading.Thread(target=self._neighbor_poller, daemon=True).start()
        # Background: mark devices offline when they leave the neighbor table
        threading.Thread(target=self._staleness_checker, daemon=True).start()
        # Background: direct in-process Scapy capture for per-device bandwidth.
        # This is the PRIMARY bandwidth accounting path — it works even when
        # pp.py's hotspot sniffer silently fails (wrong iface name / Npcap issue).
        threading.Thread(target=self._bw_capture_loop, daemon=True).start()

    # ── Direct in-process bandwidth capture ──────────────────────────────────

    def _find_hotspot_iface_name(self) -> str | None:
        """Find the Windows Mobile Hotspot adapter name.

        Strategy 0 (PowerShell — most reliable on all Windows locales):
          Get-NetIPAddress returns exact InterfaceAlias with no parsing ambiguity.

        Strategy 1 — netsh:
          Parse 'netsh interface ip show addresses'. Reliable but locale-dependent.

        Strategy 2 — Scapy interface list:
          Scan for whichever adapter has 192.168.137.x in its IP list.
        """
        import re as _re

        # ── Strategy 0: PowerShell Get-NetIPAddress (fastest + locale-safe) ──────
        try:
            out = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-NetIPAddress -AddressFamily IPv4 '
                 '| Where-Object { $_.IPAddress -like "192.168.137.*" } '
                 '| Select-Object -ExpandProperty InterfaceAlias '
                 '| Select-Object -First 1'],
                capture_output=True, text=True, timeout=8
            ).stdout.strip()
            if out:
                logger.info('BW-capture: hotspot adapter found via PowerShell → "%s"', out)
                return out
        except Exception as exc:
            logger.debug('BW-capture PowerShell probe failed: %s', exc)

        # ── Strategy 1: netsh ────────────────────────────────────────────────────
        try:
            out = subprocess.run(
                ['netsh', 'interface', 'ip', 'show', 'addresses'],
                capture_output=True, text=True, timeout=6
            ).stdout
            current: str | None = None
            for line in out.splitlines():
                m = _re.search(r'Configuration for interface\s+"(.+?)"', line)
                if m:
                    current = m.group(1)
                    continue
                if current and '192.168.137.' in line and 'IP Address' in line:
                    logger.info('BW-capture: hotspot adapter found via netsh → "%s"', current)
                    return current
        except Exception as exc:
            logger.debug('BW-capture netsh probe failed: %s', exc)

        # ── Strategy 2: Scapy interface list ──────────────────────────────────────────
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                ips = iface.get('ips', [])
                if any(ip.startswith('192.168.137.') for ip in ips):
                    name = iface.get('name', '')
                    logger.info('BW-capture: hotspot adapter found via Scapy → "%s"', name)
                    return name
        except Exception as exc:
            logger.debug('BW-capture Scapy probe failed: %s', exc)

        logger.warning(
            'BW-capture: hotspot adapter not found — ensure Mobile Hotspot is '
            'enabled in Windows Settings. Per-device bandwidth will stay 0 until '
            'hotspot is active.'
        )
        return None

    def _bw_packet_cb(self, pkt):
        """Scapy per-packet callback for the in-process BW capture thread.

        Does two things:
          1. Updates per-device bytes_up / bytes_down in HotspotDeviceTracker.
          2. Feeds the packet into the ML/rule-engine pipeline (same as pp.py)
             so attacks FROM hotspot devices are detected even without pp.py.
        """
        try:
            from scapy.all import IP as _IP, TCP as _TCP, UDP as _UDP
            if _IP not in pkt:
                return
            src   = pkt[_IP].src
            dst   = pkt[_IP].dst
            size  = len(pkt)
            proto = pkt[_IP].proto
            dport = 0
            sport = 0
            flags = 0
            ip_hdr = pkt[_IP].ihl * 4
            tcp_hdr = 0

            if _TCP in pkt:
                sport   = int(pkt[_TCP].sport)
                dport   = int(pkt[_TCP].dport)
                flags   = int(pkt[_TCP].flags)
                tcp_hdr = pkt[_TCP].dataofs * 4
            elif _UDP in pkt:
                sport = int(pkt[_UDP].sport)
                dport = int(pkt[_UDP].dport)

            # 1. Per-device bandwidth accounting
            if _is_hotspot_ip(src) or _is_hotspot_ip(dst):
                self.observe(src, dst, size, dport)

            # 2. Feed into ML + rule engine pipeline
            #    This ensures hotspot device traffic triggers IDS rules and alerts
            #    even when pp.py is not running or its WS connection drops.
            packet_info = {
                'timestamp':    time.time(),
                'src':          src,
                'dst':          dst,
                'sport':        sport,
                'dport':        dport,
                'proto':        proto,
                'size':         size,
                'ip_hdr_len':   ip_hdr,
                'tcp_hdr_len':  tcp_hdr,
                'flags':        flags,
                'source_iface': 'hotspot',   # always hotspot adapter
            }
            # Use non-blocking put so a slow queue never blocks capture
            try:
                _bw_packet_queue.put_nowait(packet_info)
            except Exception:
                pass  # queue full — drop silently

        except Exception:
            pass

    def _bw_capture_loop(self):
        """Dedicated bandwidth-capture loop — runs forever inside Django.

        Finds the hotspot adapter by name (PowerShell/netsh/Scapy), starts a
        Scapy sniff, and retries on error.  If the hotspot adapter disappears
        (user toggled hotspot off), it re-probes every 30s until it comes back.

        Guarantees that bytes_up / bytes_down update for every connected device
        INDEPENDENT of whether pp.py / WebSocket is running.
        """
        # Brief startup delay so Django finishes loading before we try Scapy
        time.sleep(5)

        from scapy.all import sniff as _sniff

        while True:
            iface = self._find_hotspot_iface_name()
            if not iface:
                # Hotspot not active yet — wait and retry
                logger.info('BW-capture: hotspot not found, retrying in 30s …')
                time.sleep(30)
                continue

            logger.info('BW-capture: starting on "%s"', iface)
            try:
                _sniff(
                    iface=iface,
                    store=False,
                    prn=self._bw_packet_cb,
                    stop_filter=lambda _: False,
                )
            except Exception as exc:
                logger.warning('BW-capture crashed (%s) — re-detecting interface in 10s', exc)
                time.sleep(10)
                # Loop back → re-detect interface (hotspot adapter name can change)

    def observe(self, src: str, dst: str, pkt_size: int, dport: int):
        """Called for every packet from the hotspot adapter.
        Gateway IP (192.168.137.1) is the laptop acting as router — it is
        NEVER treated as a client device, even though it's in the subnet.
        """
        _GATEWAY = '192.168.137.1'
        # A 'client' is a hotspot IP that is NOT the gateway itself
        src_is_client = _is_hotspot_ip(src) and src != _GATEWAY
        dst_is_client = _is_hotspot_ip(dst) and dst != _GATEWAY

        with self._lock:
            if src_is_client:
                # src is a hotspot client sending data (upload)
                rec = self._devices.setdefault(src, _DeviceRecord(src))
                rec.record_packet(pkt_size, is_upload=True, dport=dport)
            if dst_is_client and not src_is_client:
                # dst is a hotspot client receiving data (download)
                # src could be the gateway (NAT) or the internet — doesn't matter
                rec = self._devices.setdefault(dst, _DeviceRecord(dst))
                rec.record_packet(pkt_size, is_upload=False, dport=dport)

    def observe_wifi(self, src: str, dst: str, pkt_size: int, dport: int):
        """Called for packets tagged 'wifi' (primary Wi-Fi NIC / gateway).
        Only updates EXISTING hotspot client records — does NOT create new ones.
        Captures NAT-reflected download traffic seen on the Wi-Fi card:
          internet IP → 192.168.137.x  (before Windows NAT forwards it)
        This completes the bandwidth picture for each connected device.
        """
        _GATEWAY = '192.168.137.1'
        with self._lock:
            if dst in self._devices and dst != _GATEWAY:
                self._devices[dst].record_packet(pkt_size, is_upload=False, dport=dport)
            elif src in self._devices and src != _GATEWAY:
                self._devices[src].record_packet(pkt_size, is_upload=True, dport=dport)

    def get_all(self) -> list[dict]:
        with self._lock:
            return [d.to_dict() for d in self._devices.values()]

    def get_stats(self) -> dict:
        with self._lock:
            devices  = list(self._devices.values())
            total    = len(devices)
            online   = sum(1 for d in devices if d.status == 'online')
            blocked  = sum(1 for d in devices if d.ip in _blocked_ips)
            bw_up    = sum(d.bytes_up   for d in devices)
            bw_down  = sum(d.bytes_down for d in devices)
        return {
            'total_devices':   total,
            'online_devices':  online,
            'blocked_devices': blocked,
            'total_bytes_up':  bw_up,
            'total_bytes_down':bw_down,
            'gateway_ip':      '192.168.137.1',
            'subnet':          '192.168.137.0/24',
        }

    def _staleness_checker(self):
        """Every 20 s: re-query neighbor table and mark devices online/offline
        based on whether they still appear with a valid MAC — not on packet flow.
        """
        while True:
            time.sleep(20)
            live = self._get_neighbor_ips()   # set of IPs currently in neighbor table
            with self._lock:
                for ip, d in self._devices.items():
                    if ip in _blocked_ips:
                        continue
                    if ip in live:
                        d.status   = 'online'
                        d.last_seen = time.time()
                    else:
                        d.status = 'offline'

    # ── Public: force immediate discovery (router-style) ─────────────────────
    def scan_now(self) -> list[dict]:
        """Query the neighbor table immediately and return current device list.
        Also runs a background ping-sweep so new devices populate the table fast.
        """
        # Non-blocking ping sweep in background to force ARP resolution
        threading.Thread(target=self._ping_sweep, daemon=True).start()
        # Then query the neighbor table (blocks ~1 s)
        self._query_hotspot_clients()
        self._resolve_hostnames()
        with self._lock:
            return [d.to_dict() for d in self._devices.values()]

    # ── Internal helpers ──────────────────────────────────────────────────────

    # States from Get-NetNeighbor that mean the device is connected/reachable.
    # Delay  = ARP reply received, verifying (brief transient before Reachable)
    # Stale  = cache entry aging but device may still be connected
    # Permanent = hotspot assigns this to connected Wi-Fi clients
    _LIVE_STATES = {'Reachable', 'Permanent', 'Stale', 'Delay'}
    # MACs to always ignore (null / broadcast)
    _SKIP_MACS   = {'00-00-00-00-00-00', 'ff-ff-ff-ff-ff-ff',
                    'FF-FF-FF-FF-FF-FF', '00:00:00:00:00:00', ''}

    def _get_neighbor_ips(self) -> set:
        """Return set of IPs currently in the hotspot subnet ARP cache.
        Uses 'arp -a' (~20 ms) — only entries with a resolved MAC appear,
        so presence = connected, absence = disconnected/unreachable.
        """
        live = set()
        try:
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip  = parts[0].strip()
                mac = parts[1].strip().upper()
                if not _is_hotspot_ip(ip):
                    continue
                if ip in ('192.168.137.1', '192.168.137.255'):
                    continue
                if mac in self._SKIP_MACS:
                    continue
                live.add(ip)
        except Exception as exc:
            logger.debug('_get_neighbor_ips error: %s', exc)
        return live

    def _query_hotspot_clients(self):
        """Router-style discovery using 'arp -a' (~20 ms).
        Windows only prints ARP entries that have been successfully resolved —
        so every entry here represents a device that IS currently connected.
        Completely independent of Npcap / packet flow.
        """
        try:
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=5
            )
            seen_ips = set()
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip  = parts[0].strip()
                mac = parts[1].strip().upper().replace(':', '-')

                # Subnet + skip gateway/broadcast
                if not _is_hotspot_ip(ip):
                    continue
                if ip in ('192.168.137.1', '192.168.137.255'):
                    continue
                # Skip null / broadcast MACs
                if mac in self._SKIP_MACS:
                    continue

                seen_ips.add(ip)
                vendor = _oui_vendor(mac)

                with self._lock:
                    if ip not in self._devices:
                        rec             = _DeviceRecord(ip)
                        rec.mac         = mac
                        rec.vendor      = vendor
                        rec.device_type = _infer_device_type(vendor, '')
                        rec.status      = 'online'
                        self._devices[ip] = rec
                        logger.info(
                            'Hotspot client connected: %s  MAC=%s  vendor=%s',
                            ip, mac, vendor
                        )
                    else:
                        d = self._devices[ip]
                        if not d.mac:
                            d.mac = mac
                        if not d.vendor:
                            d.vendor = vendor
                        if d.status != 'blocked':
                            d.status    = 'online'
                            d.last_seen = time.time()

            # Mark devices no longer in ARP table as offline
            with self._lock:
                for ip, d in self._devices.items():
                    if ip not in seen_ips and ip not in _blocked_ips:
                        if d.status == 'online':
                            d.status = 'offline'
                            logger.info('Hotspot client disconnected: %s', ip)

        except Exception as exc:
            logger.warning('_query_hotspot_clients error: %s', exc, exc_info=True)

    def _ping_sweep(self):
        """Send a fast ping to 192.168.137.1-254 to force neighbour-table entries.
        Runs all pings concurrently; finishes in ~2 s.
        """
        import concurrent.futures
        hosts = [f'192.168.137.{i}' for i in range(2, 255)]

        def _ping(ip):
            try:
                subprocess.run(
                    ['ping', '-n', '1', '-w', '400', ip],
                    capture_output=True, timeout=2
                )
            except Exception:
                pass

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
                pool.map(_ping, hosts, timeout=10)
        except Exception as exc:
            logger.debug('Ping sweep error: %s', exc)

    def _resolve_hostnames(self):
        """Multi-strategy device name resolver:
        1. DNS reverse lookup (gethostbyaddr)
        2. NetBIOS name via nbtstat -A (Windows)
        3. OUI vendor prefix from MAC
        4. Friendly label fallback: 'Device-<last 4 of IP>'
        """
        with self._lock:
            to_resolve = [
                (ip, d.mac) for ip, d in self._devices.items()
                if d.hostname == ip  # still unresolved
            ]
        for ip, mac in to_resolve:
            if ip in self._resolver_cache:
                host, vendor = self._resolver_cache[ip]
            else:
                host   = None
                vendor = _oui_vendor(mac)

                # ── Strategy 1: DNS reverse lookup ───────────────────────
                try:
                    dns_name = socket.gethostbyaddr(ip)[0]
                    if dns_name and dns_name != ip:
                        host = dns_name
                except Exception:
                    pass

                # ── Strategy 2: NetBIOS (nbtstat -A <ip>) ────────────────
                if not host:
                    try:
                        nb = subprocess.run(
                            ['nbtstat', '-A', ip],
                            capture_output=True, text=True, timeout=4
                        )
                        for nline in nb.stdout.splitlines():
                            # Line format:  NAME        <00>  UNIQUE  Registered
                            parts = nline.split()
                            if len(parts) >= 3 and '<00>' in nline and 'UNIQUE' in nline:
                                candidate = parts[0].strip()
                                if candidate and candidate.upper() not in ('NAME', 'NODE'):
                                    host = candidate
                                    break
                    except Exception:
                        pass

                # ── Strategy 3: Friendly label from vendor + IP tail ─────
                if not host:
                    tail = ip.split('.')[-1]
                    if vendor:
                        host = f'{vendor}-{tail}'
                    else:
                        host = f'Device-{tail}'

                self._resolver_cache[ip] = (host, vendor)

            with self._lock:
                if ip in self._devices:
                    self._devices[ip].hostname = host
                    if vendor and not self._devices[ip].vendor:
                        self._devices[ip].vendor = vendor
                    # Infer device_type from vendor name
                    self._devices[ip].device_type = _infer_device_type(vendor, host)

    def _neighbor_poller(self):
        """Background loop: poll Windows neighbor table every 8 s.
        This is the primary device discovery mechanism — like a router's
        connected-clients table. No packet capture required.
        """
        while True:
            time.sleep(8)
            self._query_hotspot_clients()
            self._resolve_hostnames()


# Global tracker instance
_hotspot_tracker = HotspotDeviceTracker()

# ── In-memory flow table ───────────────────────────────────────────────────────
flows      = {}
flows_lock = threading.Lock()

# ── BW-capture → ML pipeline queue ────────────────────────────────────────────
# The in-process hotspot Scapy sniffer feeds packets here.
# A background thread drains the queue and calls process_packet() so:
#   • All 12 Suricata-style rules fire on real hotspot traffic in real-time
#   • ML flow features accumulate from real packets (not just simulated ones)
#   • Bandwidth + ML detection both run from the SAME packet stream
import queue as _queue
_bw_packet_queue: _queue.Queue = _queue.Queue(maxsize=10_000)

def _bw_queue_consumer():
    """Drain hotspot packets into the ML/rule engine pipeline."""
    while True:
        try:
            pkt_info = _bw_packet_queue.get(timeout=1.0)
            process_packet(pkt_info)   # ingest into flow table + rule engine
        except _queue.Empty:
            continue
        except Exception as exc:
            logger.debug('BW queue consumer error: %s', exc)

threading.Thread(target=_bw_queue_consumer, daemon=True, name='bw-queue-consumer').start()

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


# ── Fusion engine v2 ─────────────────────────────────────────────────────────
# Suricata-style multi-layer weighted scoring:
#   ML classifier  (50%)  — XGBoost / RF label + calibrated confidence
#   Isolation Forest (20%) — unsupervised anomaly score
#   AbuseIPDB reputation (15%) — external threat intel
#   Rule engine bonus (+25%) — deterministic rule fired ON THIS FLOW
#   Host threat history (+10%) — repeat offender bump
#
# XGBoost raw probabilities are NOT calibrated — apply sigmoid correction.
# A raw score of 0.80 from XGBoost ≈ 0.73 after calibration.
def _calibrate(raw_prob: float) -> float:
    """Sigmoid calibration for XGBoost / RF predict_proba scores."""
    import math
    try:
        return 1.0 / (1.0 + math.exp(-4.0 * (raw_prob - 0.5)))
    except OverflowError:
        return 0.0 if raw_prob < 0.5 else 1.0


def fusion_engine(rf_label, rf_confidence, iso_score,
                  abuse_score: int = 0,
                  rule_hit: bool = False,
                  host_score: float = 0.0):
    """
    Multi-layer fusion engine for SecureFlow IDS.
    Returns dict with final_score (0-100), attack_type, severity.
    """
    label      = str(rf_label)
    is_attack  = label.lower() not in ('normal', 'benign')
    cal_conf   = _calibrate(float(rf_confidence))   # sigmoid-calibrated

    # ── Base score components ─────────────────────────────────────────────────
    ml_score    = cal_conf * 0.50 if is_attack else 0.0
    iso_contrib = float(iso_score) * 0.20
    rep_contrib = min(1.0, abuse_score / 100.0) * 0.15

    base = ml_score + iso_contrib + rep_contrib

    # ── Rule hit overrides — deterministic signatures take priority ───────────
    if rule_hit:
        base = min(1.0, base + 0.25)  # strong boost

    # ── Repeat offender bump ──────────────────────────────────────────────────
    if host_score > 50:
        base = min(1.0, base + 0.10)

    final_score = round(min(MAX_Y_ALERT_SCORE, base * 100.0), 2)

    # ── Determine attack type -------------------------------------------------
    if is_attack:
        attack_type = label
    elif iso_score > 0.25 or rule_hit:
        attack_type = 'Anomaly'
    else:
        attack_type = 'Normal'

    # ── Severity mapping ──────────────────────────────────────────────────────
    if attack_type == 'Normal':
        severity = 'Low'
    elif rule_hit:
        # Deterministic rules guarantee at least Medium
        if final_score >= 90 or cal_conf >= 0.85:
            severity = 'High'
        else:
            severity = 'Medium'
    elif final_score >= 75 or (is_attack and cal_conf >= 0.80):
        severity = 'High'
    elif final_score >= 45 or is_attack or iso_score > 0.25:
        severity = 'Medium'
    else:
        severity = 'Low'

    return {
        'final_score': final_score,
        'attack_type': attack_type,
        'severity':    severity,
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
            # protocol-level hints (accumulated per packet)
            'proto_hints': {},   # e.g. {'dns_oversize': True, 'c2_port': True}
        }
        flows[fid] = flow

    flow['timestamps'].append(now)
    flow['sizes'].append(packet_size)

    # Determine direction using canonical key
    src   = str(packet.get('src', ''))
    dst   = str(packet.get('dst', ''))
    sport = str(packet.get('sport', ''))
    dport_int = int(packet.get('dport', 0))
    proto_int = int(packet.get('proto', 0))

    is_fwd = (
        src   == flow['canonical_fwd_src'] and
        sport == flow['canonical_fwd_sport']
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

    # ── Protocol-aware hints (Improvement 6) ──────────────────────────────────
    hints = flow['proto_hints']
    # DNS oversized payload → exfiltration hint
    if dport_int == 53 and packet_size > 200:
        hints['dns_oversize'] = True
    # Known C2 port connection
    if dport_int in _C2_PORTS:
        hints['c2_port'] = True
    # TLS/HTTPS: many short forward packets in short burst → DGA/C2 beacon
    if dport_int in (443, 8443) and packet_size < 150 and is_fwd:
        hints['tls_small_fwd'] = hints.get('tls_small_fwd', 0) + 1
    # HTTP: very small fwd payload with high packet count → scanner / flood
    if dport_int in (80, 8080) and packet_size < 100 and is_fwd:
        hints['http_small_fwd'] = hints.get('http_small_fwd', 0) + 1
    # ICMP
    if proto_int == 1:
        hints['icmp_count'] = hints.get('icmp_count', 0) + 1

    # ── Suricata-style per-packet rule engine ─────────────────────────────────
    # Runs on every packet immediately — does NOT wait for flow completion.
    is_simulated = bool(packet.get('is_simulated', False))
    _rule_engine(
        src_ip     = src,
        dst_ip     = dst,
        sport      = int(packet.get('sport', 0)),
        dport      = dport_int,
        proto      = proto_int,
        flags      = flags,
        pkt_size   = packet_size,
        is_simulated = is_simulated,
    )

    # ── Hotspot device bandwidth tracking ─────────────────────────────────────
    source_iface = packet.get('source_iface', '')
    if source_iface != 'wifi':
        if _is_hotspot_ip(src) or _is_hotspot_ip(dst):
            _hotspot_tracker.observe(src, dst, packet_size, dport_int)
    # wifi packets: used for system-wide ML/alerts only — no per-device tracking.

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
    for idx, (fid, flow_data) in enumerate(flow_items):
        # Protocol hints from packet-level accumulation (Improvement 6)
        proto_hints = flow_data.get('proto_hints', {})
        _hint_boost  = 0.0
        if proto_hints.get('c2_port'):
            _hint_boost += 0.15
        if proto_hints.get('dns_oversize'):
            _hint_boost += 0.10
        if proto_hints.get('tls_small_fwd', 0) > 20:
            _hint_boost += 0.08
        if proto_hints.get('http_small_fwd', 0) > 50:
            _hint_boost += 0.08

        src_ip       = fid[0]
        _host_rec    = _host_scores.get(src_ip, {})
        _host_cur    = _host_rec.get('score', 0.0)
        _abuse_score = abuse_ipdb.get_abuse_score(src_ip)

        fused = fusion_engine(
            str(rf_pred[idx]),
            float(rf_prob[idx]),
            float(iso_scores[idx]),
            abuse_score  = _abuse_score,
            rule_hit     = bool(_hint_boost > 0),
            host_score   = _host_cur,
        )
        # Apply hint boost on top of fusion score
        if _hint_boost > 0:
            fused['final_score'] = round(
                min(MAX_Y_ALERT_SCORE, fused['final_score'] + _hint_boost * 100), 2
            )
        attack_type = fused['attack_type']
        src_ip      = fid[0]

        # ── Skip whitelisted or dedup-suppressed flows ────────────────────────
        if src_ip in WHITELIST_IPS or fid[1] in WHITELIST_IPS:
            continue
        if attack_type.lower() not in ('normal', 'benign'):
            if _should_suppress(src_ip, attack_type):
                continue

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

        # ── AbuseIPDB reputation (already computed above for fusion) ──────────
        abuse_score = _abuse_score

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

        # ── Per-device email + browser push for Medium/High hotspot alerts ─────
        _alert_sev = fused.get('severity', 'Low')
        if _alert_sev in ('Medium', 'High') and attack_type.lower() != 'normal':
            if _is_hotspot_ip(src_ip):
                # Get MAC from tracker for richer email matching
                _dev_mac = ''
                try:
                    with _hotspot_tracker._lock:
                        _dev_rec = _hotspot_tracker._devices.get(src_ip)
                        if _dev_rec:
                            _dev_mac = _dev_rec.mac
                except Exception:
                    pass
                _send_device_alert_email(src_ip, _dev_mac, alert)
            # Push notification to all registered browser subscribers
            _send_push_notifications(alert)

        # ── Persist classified flow to NetworkFlow table ──────────────────────
        try:
            _persist_flow(fid, flow_items[idx][1], alert)
        except Exception as _pf_err:
            logger.debug('_persist_flow skipped: %s', _pf_err)

    # ── After loop: update in-memory store + bulk DB write ────────────────────
    global _recent_alerts
    _recent_alerts = (_recent_alerts + alerts)[-_MAX_RECENT:]

    # ── Persist batch to database (one write for the whole batch) ─────────────
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
    return JsonResponse({
        'incidents': incident_engine.get_all_incidents(),
        'summary':   incident_engine.get_summary(),
    })


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
        if attack_type == '__list__':
            # Return all supported types with descriptions
            return JsonResponse({
                'supported': [
                    {'type': t, 'description': sim.get_description(t)}
                    for t in sim.SUPPORTED
                ]
            })
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
            'description':    sim.get_description(attack_type),
            'packets_sent':   len(packets),
            'alerts_emitted': len(alerts),
            'model_labels':   list({a.get('final', {}).get('attack_type') for a in alerts}),
            'rule_alerts':    sum(1 for a in alerts if a.get('rule_triggered')),
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


# ══════════════════════════════════════════════════════════════════════════════
# ── CAPTURE CONTROL (start/stop pp.py subprocess) ─────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
import sys as _sys
_capture_process: subprocess.Popen | None = None
_capture_lock = threading.Lock()


def _capture_is_running():
    global _capture_process
    return _capture_process is not None and _capture_process.poll() is None


@csrf_exempt
def capture_control(request):
    """
    GET  /model_app/capture          → { running: bool }
    POST /model_app/capture          → { action: "start"|"stop", mode: "live"|"pcap" }
    """
    global _capture_process

    # ── Handle CORS preflight explicitly ─────────────────────────────────────
    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return resp

    if request.method == 'GET':
        return _cors(JsonResponse({'running': _capture_is_running()}))

    if request.method != 'POST':
        return _cors(JsonResponse({'error': 'GET or POST only'}, status=405))


    try:
        body = json.loads(request.body or '{}')
    except Exception:
        body = {}

    action = body.get('action', 'start')

    if action == 'stop':
        with _capture_lock:
            if _capture_is_running():
                _capture_process.terminate()
                try:
                    _capture_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _capture_process.kill()
                _capture_process = None
                logger.info('Packet capture stopped by API.')
                return _cors(JsonResponse({'status': 'stopped'}))
            else:
                return _cors(JsonResponse({'status': 'not_running'}))

    # action == 'start'
    with _capture_lock:
        if _capture_is_running():
            return _cors(JsonResponse({'status': 'already_running'}))

        pp_path = Path(__file__).resolve().parents[1] / 'engine' / 'pp.py'
        mode    = body.get('mode', 'live')
        cmd     = [_sys.executable, str(pp_path)]

        if mode == 'pcap':
            pcap_file = body.get('pcap_file', '')
            if pcap_file:
                cmd.append(pcap_file)
            else:
                return _cors(JsonResponse({'error': 'pcap_file required for pcap mode'}, status=400))

        try:
            _capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info('Packet capture started. PID: %s', _capture_process.pid)
            return _cors(JsonResponse({'status': 'started', 'pid': _capture_process.pid, 'mode': mode}))
        except Exception as exc:
            logger.error('Failed to start capture: %s', exc)
            return _cors(JsonResponse({'error': str(exc)}, status=500))


# ══════════════════════════════════════════════════════════════════════════════
# ── NETWORK FLOWS — DB list + CSV download ────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
try:
    from .models import NetworkFlow, BlockedIP
except ImportError:
    from model_app.models import NetworkFlow, BlockedIP


def _persist_flow(fid, flow, alert):
    """Save a completed + classified flow to the NetworkFlow table."""
    try:
        sizes    = flow.get('sizes', [])
        fwd_sz   = flow.get('fwd_sizes', [])
        bwd_sz   = flow.get('bwd_sizes', [])
        ts       = flow.get('timestamps', [])
        duration = (ts[-1] - ts[0]) if len(ts) > 1 else 0.0
        f = alert.get('final', {})
        NetworkFlow.objects.create(
            start_time   = flow.get('first', time.time()),
            end_time     = flow.get('last', time.time()),
            src_ip       = fid[0] or None,
            dst_ip       = fid[1] or None,
            sport        = int(fid[2]) if str(fid[2]).isdigit() else None,
            dport        = int(fid[3]) if str(fid[3]).isdigit() else None,
            protocol     = _protocol_label(fid[4]),
            bytes_fwd    = sum(fwd_sz),
            bytes_bwd    = sum(bwd_sz),
            packets_fwd  = len(fwd_sz),
            packets_bwd  = len(bwd_sz),
            flow_duration= duration,
            attack_type  = f.get('attack_type', ''),
            severity     = f.get('severity', ''),
            confidence   = float(f.get('final_score', 0.0)),
            is_simulated = alert.get('is_simulated', False),
        )
    except Exception as exc:
        logger.warning('NetworkFlow persist failed: %s', exc)


def list_network_flows(request):
    """GET /model_app/flows — paginated list with optional filters."""
    page         = max(1, int(request.GET.get('page', 1)))
    limit        = min(int(request.GET.get('limit', 50)), 200)
    attack_type  = request.GET.get('attack_type', '')
    severity     = request.GET.get('severity', '')
    date_from    = request.GET.get('date_from', '')
    date_to      = request.GET.get('date_to', '')

    qs = NetworkFlow.objects.all()
    if attack_type:
        qs = qs.filter(attack_type__icontains=attack_type)
    if severity:
        qs = qs.filter(severity__iexact=severity)
    if date_from:
        try:
            qs = qs.filter(start_time__gte=float(date_from))
        except Exception:
            pass
    if date_to:
        try:
            qs = qs.filter(start_time__lte=float(date_to))
        except Exception:
            pass

    total  = qs.count()
    offset = (page - 1) * limit
    flows_data = [f.to_dict() for f in qs[offset:offset + limit]]
    return _cors(JsonResponse({'flows': flows_data, 'total': total, 'page': page, 'limit': limit}))


def download_network_flows(request):
    """GET /model_app/flows/download — stream CSV of all stored flows."""
    attack_type = request.GET.get('attack_type', '')
    severity    = request.GET.get('severity', '')

    qs = NetworkFlow.objects.all()
    if attack_type:
        qs = qs.filter(attack_type__icontains=attack_type)
    if severity:
        qs = qs.filter(severity__iexact=severity)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'id', 'start_time', 'end_time', 'src_ip', 'dst_ip', 'sport', 'dport',
        'protocol', 'bytes_fwd', 'bytes_bwd', 'packets_fwd', 'packets_bwd',
        'flow_duration', 'attack_type', 'severity', 'confidence', 'is_simulated',
    ])
    for flow in qs.iterator(chunk_size=500):
        writer.writerow([
            flow.pk, flow.start_time, flow.end_time, flow.src_ip, flow.dst_ip,
            flow.sport, flow.dport, flow.protocol, flow.bytes_fwd, flow.bytes_bwd,
            flow.packets_fwd, flow.packets_bwd, round(flow.flow_duration, 4),
            flow.attack_type, flow.severity, flow.confidence, flow.is_simulated,
        ])

    resp = HttpResponse(output.getvalue(), content_type='text/csv')
    resp['Content-Disposition'] = 'attachment; filename="secureflow_flows.csv"'
    return _cors(resp)


# ══════════════════════════════════════════════════════════════════════════════
# ── BLOCKED IPs — DB-backed list, system-level block/unblock ──────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _block_ip_db(ip: str, reason: str = '', blocked_by: str = 'system'):
    """Block IP at firewall level and persist to DB."""
    _block_ip_system(ip)  # existing netsh logic
    BlockedIP.objects.update_or_create(
        ip=ip,
        defaults={
            'reason':     reason,
            'blocked_at': time.time(),
            'blocked_by': blocked_by,
            'is_active':  True,
            'unblocked_at': None,
            'unblocked_by': '',
        }
    )


def _unblock_ip_db(ip: str, unblocked_by: str = 'system'):
    """Remove firewall rule and mark DB record inactive."""
    rule = f'SecureFlow_Block_{ip}'
    try:
        subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule}'],
            capture_output=True, timeout=5
        )
    except Exception as exc:
        logger.warning('Firewall unblock failed for %s: %s', ip, exc)
    with _block_lock:
        _blocked_ips.discard(ip)
    BlockedIP.objects.filter(ip=ip).update(
        is_active=False,
        unblocked_at=time.time(),
        unblocked_by=unblocked_by,
    )
    logger.info('Unblocked IP: %s (by %s)', ip, unblocked_by)


@csrf_exempt
def manage_blocked_ips_db(request):
    """
    GET  /model_app/blocked_ips_db            — paginated DB list
    POST /model_app/blocked_ips_db            { ip, reason, blocked_by, action:'block'|'unblock' }
    """
    if request.method == 'GET':
        page   = max(1, int(request.GET.get('page', 1)))
        limit  = min(int(request.GET.get('limit', 50)), 200)
        active_only = request.GET.get('active', 'false').lower() == 'true'
        qs = BlockedIP.objects.all()
        if active_only:
            qs = qs.filter(is_active=True)
        total  = qs.count()
        offset = (page - 1) * limit
        return _cors(JsonResponse({
            'blocked_ips': [b.to_dict() for b in qs[offset:offset+limit]],
            'total': total, 'page': page, 'limit': limit,
        }))

    if request.method == 'POST':
        try:
            body   = json.loads(request.body or '{}')
            ip     = body.get('ip', '').strip()
            action = body.get('action', 'block')

            if not ip:
                return _cors(JsonResponse({'error': 'ip required'}, status=400))

            performer = body.get('blocked_by', body.get('unblocked_by', 'api'))

            if action == 'unblock':
                _unblock_ip_db(ip, unblocked_by=performer)
                return _cors(JsonResponse({'status': 'unblocked', 'ip': ip}))
            else:
                reason = body.get('reason', 'Manual block via dashboard')
                _block_ip_db(ip, reason=reason, blocked_by=performer)
                return _cors(JsonResponse({'status': 'blocked', 'ip': ip}))

        except Exception as exc:
            return _cors(JsonResponse({'error': str(exc)}, status=500))

    return _cors(JsonResponse({'error': 'Method not allowed'}, status=405))


# ══════════════════════════════════════════════════════════════════════════════
# ── HOTSPOT DEVICE MANAGEMENT ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def get_hotspot_devices(request):
    """
    GET /model_app/hotspot/devices
    Returns all seen hotspot devices with live stats.
    """
    devices = _hotspot_tracker.get_all()
    # Sort: online first, then offline, blocked last
    order = {'online': 0, 'offline': 1, 'blocked': 2}
    devices.sort(key=lambda d: (order.get(d['status'], 9), -d['last_seen']))
    return _cors(JsonResponse({'devices': devices, 'count': len(devices)}))


def get_hotspot_stats(request):
    """
    GET /model_app/hotspot/stats
    Returns gateway-level aggregated stats.
    """
    return _cors(JsonResponse(_hotspot_tracker.get_stats()))


@csrf_exempt
def manage_hotspot_device(request, device_ip):
    """
    POST /model_app/hotspot/devices/<ip>/action
    Body: { "action": "block" | "unblock" | "refresh" }
    """
    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    if request.method != 'POST':
        return _cors(JsonResponse({'error': 'POST only'}, status=405))

    try:
        body   = json.loads(request.body or '{}')
        action = body.get('action', 'block')
    except Exception:
        return _cors(JsonResponse({'error': 'Invalid JSON'}, status=400))

    if not _is_hotspot_ip(device_ip):
        return _cors(JsonResponse({'error': 'Not a hotspot IP'}, status=400))

    if action == 'block':
        _block_ip_system(device_ip, force=True)
        # Also persist to DB
        try:
            _block_ip_db(device_ip, reason='Hotspot client blocked via dashboard', blocked_by='dashboard')
        except Exception:
            pass
        # Push update via WebSocket
        _push_device_update()
        return _cors(JsonResponse({'status': 'blocked', 'ip': device_ip}))

    elif action == 'unblock':
        _unblock_ip_system(device_ip)
        try:
            _unblock_ip_db(device_ip, unblocked_by='dashboard')
        except Exception:
            pass
        _push_device_update()
        return _cors(JsonResponse({'status': 'unblocked', 'ip': device_ip}))

    return _cors(JsonResponse({'error': f'Unknown action: {action}'}, status=400))


def _push_device_update():
    """Push fresh device list to all WebSocket subscribers."""
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer
        layer   = get_channel_layer()
        devices = _hotspot_tracker.get_all()
        stats   = _hotspot_tracker.get_stats()
        async_to_sync(layer.group_send)(
            'hotspot_devices',
            {'type': 'send_devices', 'data': {'devices': devices, 'stats': stats}}
        )
    except Exception as exc:
        logger.debug('Device push error: %s', exc)


# ══════════════════════════════════════════════════════════════════════════════
# ── HOTSPOT ACTIVE SCAN ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@csrf_exempt
def scan_hotspot_now(request):
    """
    POST /model_app/hotspot/scan
    Triggers a full ping sweep of the hotspot subnet (192.168.137.0/24),
    reads ARP table, creates device records for any new clients, and
    pushes the result to all WebSocket subscribers.

    Returns the full device list immediately.
    """
    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    if request.method not in ('POST', 'GET'):
        return _cors(JsonResponse({'error': 'GET or POST only'}, status=405))

    try:
        logger.info('Manual hotspot scan triggered via API')
        devices = _hotspot_tracker.scan_now()
        stats   = _hotspot_tracker.get_stats()
        # Broadcast the fresh data to any open WebSocket clients
        _push_device_update()
        return _cors(JsonResponse({
            'status':  'ok',
            'scanned': True,
            'devices': devices,
            'stats':   stats,
            'count':   len(devices),
        }))
    except Exception as exc:
        logger.error('Hotspot scan error: %s', exc)
        return _cors(JsonResponse({'error': str(exc)}, status=500))


def hotspot_arp_check(request):
    """
    GET /model_app/hotspot/arp_check
    Returns the Windows neighbor table filtered to the hotspot subnet.
    Uses Get-NetNeighbor (same source as the tracker) so state is accurate.
    """
    try:
        ps = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-NetNeighbor -AddressFamily IPv4 '
             '| Select-Object -Property IPAddress,LinkLayerAddress,State,InterfaceAlias '
             '| ConvertTo-Csv -NoTypeInformation'],
            capture_output=True, text=True, timeout=10
        )
        rows = []
        live_count = 0
        _live = {'Reachable', 'Permanent', 'Stale'}
        for line in ps.stdout.splitlines()[1:]:
            parts = [p.strip('"') for p in line.split(',')]
            if len(parts) < 4:
                continue
            ip, mac, state, iface = parts[0], parts[1], parts[2], parts[3]
            if not _is_hotspot_ip(ip):
                continue
            is_live = (state in _live
                       and mac not in ('00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF', '00:00:00:00:00:00'))
            if is_live:
                live_count += 1
            rows.append({
                'ip':     ip,
                'mac':    mac,
                'state':  state,
                'iface':  iface,
                'vendor': _oui_vendor(mac),
                'live':   is_live,
            })
        # Sort: live first
        rows.sort(key=lambda r: (0 if r['live'] else 1, r['ip']))
        return _cors(JsonResponse({
            'neighbor_entries': rows,
            'total':      len(rows),
            'live_count': live_count,
            'note':       'live=true means device is connected (Reachable/Permanent/Stale state with valid MAC)',
        }))
    except Exception as exc:
        return _cors(JsonResponse({'error': str(exc)}, status=500))


# ══════════════════════════════════════════════════════════════════════════════
# ── DEVICE ALERT EMAIL RULES ──────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@csrf_exempt
def manage_device_emails(request):
    """
    GET    /model_app/device_emails          → list all rules (+ connected hotspot devices)
    POST   /model_app/device_emails          → create new rule
    """
    try:
        from model_app.models import DeviceAlertEmail
    except ImportError:
        from .models import DeviceAlertEmail

    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    if request.method == 'GET':
        rules   = [r.to_dict() for r in DeviceAlertEmail.objects.all()]
        devices = _hotspot_tracker.get_all()
        return _cors(JsonResponse({'rules': rules, 'connected_devices': devices}))

    if request.method == 'POST':
        try:
            body = json.loads(request.body or '{}')
            ip           = body.get('ip', '').strip()
            email        = body.get('email', '').strip()
            label        = body.get('label', '').strip()
            mac          = body.get('mac', '').strip()
            min_severity = body.get('min_severity', 'Medium')
            enabled      = body.get('enabled', True)
            if not email:
                return _cors(JsonResponse({'error': 'email required'}, status=400))
            if min_severity not in ('Low', 'Medium', 'High'):
                min_severity = 'Medium'
            rule = DeviceAlertEmail.objects.create(
                ip=ip, mac=mac, label=label or ip,
                email=email, min_severity=min_severity, enabled=enabled,
            )
            return _cors(JsonResponse({'status': 'created', 'rule': rule.to_dict()}))
        except Exception as exc:
            return _cors(JsonResponse({'error': str(exc)}, status=400))

    return _cors(JsonResponse({'error': 'Method not allowed'}, status=405))


@csrf_exempt
def manage_device_email_detail(request, rule_id):
    """
    PUT    /model_app/device_emails/<id>     → update rule
    DELETE /model_app/device_emails/<id>     → delete rule
    """
    try:
        from model_app.models import DeviceAlertEmail
    except ImportError:
        from .models import DeviceAlertEmail

    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Methods'] = 'PUT, DELETE, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    try:
        rule = DeviceAlertEmail.objects.get(pk=rule_id)
    except DeviceAlertEmail.DoesNotExist:
        return _cors(JsonResponse({'error': 'Rule not found'}, status=404))

    if request.method in ('PUT', 'POST'):
        try:
            body = json.loads(request.body or '{}')
            if 'ip'           in body: rule.ip           = body['ip'].strip()
            if 'mac'          in body: rule.mac          = body['mac'].strip()
            if 'label'        in body: rule.label        = body['label'].strip()
            if 'email'        in body: rule.email        = body['email'].strip()
            if 'min_severity' in body:
                ms = body['min_severity']
                rule.min_severity = ms if ms in ('Low', 'Medium', 'High') else 'Medium'
            if 'enabled' in body: rule.enabled = bool(body['enabled'])
            rule.save()
            return _cors(JsonResponse({'status': 'updated', 'rule': rule.to_dict()}))
        except Exception as exc:
            return _cors(JsonResponse({'error': str(exc)}, status=400))

    if request.method == 'DELETE':
        rule.delete()
        return _cors(JsonResponse({'status': 'deleted', 'id': rule_id}))

    return _cors(JsonResponse({'error': 'Method not allowed'}, status=405))


@csrf_exempt
def test_device_email(request):
    """
    POST /model_app/device_emails/test
    Body: { "rule_id": <int> }  OR  { "email": "x@y.com", "ip": "192.168.137.x", "label": "..." }
    Sends a synthetic test alert email so the user can verify SMTP settings.
    """
    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin'] = '*'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    if request.method != 'POST':
        return _cors(JsonResponse({'error': 'POST only'}, status=405))

    if not _SMTP_USER or not _SMTP_PASS:
        return _cors(JsonResponse({
            'error': 'SMTP not configured. Set SMTP_USER and SMTP_PASSWORD in .env',
        }, status=400))

    try:
        body = json.loads(request.body or '{}')
    except Exception:
        return _cors(JsonResponse({'error': 'Invalid JSON'}, status=400))

    try:
        from model_app.models import DeviceAlertEmail
    except ImportError:
        from .models import DeviceAlertEmail

    rule_id = body.get('rule_id')
    if rule_id:
        try:
            rule  = DeviceAlertEmail.objects.get(pk=int(rule_id))
            to    = rule.email
            dev_ip    = rule.ip or '192.168.137.x'
            dev_label = rule.label or dev_ip
        except DeviceAlertEmail.DoesNotExist:
            return _cors(JsonResponse({'error': 'Rule not found'}, status=404))
    else:
        to        = body.get('email', '').strip()
        dev_ip    = body.get('ip',    '192.168.137.x').strip()
        dev_label = body.get('label', dev_ip).strip()
        if not to:
            return _cors(JsonResponse({'error': 'email or rule_id required'}, status=400))

    # Build a synthetic test alert
    test_alert = {
        'final': {
            'attack_type': 'TEST Alert',
            'severity':    'Medium',
            'final_score': 75.0,
        },
        'protocol':    'TCP',
        'src_ip':      dev_ip,
        'dst_ip':      '8.8.8.8',
        'sport':       '54321',
        'dport':       '443',
        'timestamp':   time.time(),
        'mitre':       {'id': 'T0000', 'name': 'Test Technique', 'tactic': 'Test'},
        'shap':        [{'feature': 'Flow Duration', 'impact': 0.42}],
        'abuse_score': 0,
    }
    threading.Thread(
        target=_do_send_email,
        args=(to, dev_ip, dev_label, test_alert),
        daemon=True,
    ).start()
    return _cors(JsonResponse({'status': 'queued', 'to': to, 'device': dev_label}))


# ══════════════════════════════════════════════════════════════════════════════
# ── WEB PUSH SUBSCRIPTION ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def get_vapid_public_key(request):
    """GET /model_app/push/vapid_key — returns VAPID public key for browser subscription."""
    if not _VAPID_PUBLIC_KEY:
        return _cors(JsonResponse({'error': 'VAPID keys not configured'}, status=404))
    return _cors(JsonResponse({'public_key': _VAPID_PUBLIC_KEY}))


@csrf_exempt
def push_subscribe(request):
    """
    POST /model_app/push/subscribe
    Body: { endpoint, keys: { p256dh, auth } }
    Saves the browser push subscription.
    """
    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    if request.method != 'POST':
        return _cors(JsonResponse({'error': 'POST only'}, status=405))

    try:
        body     = json.loads(request.body or '{}')
        endpoint = body.get('endpoint', '').strip()
        keys     = body.get('keys', {})
        p256dh   = keys.get('p256dh', '').strip()
        auth     = keys.get('auth',   '').strip()

        if not endpoint or not p256dh or not auth:
            return _cors(JsonResponse({'error': 'endpoint, keys.p256dh and keys.auth required'}, status=400))

        try:
            from model_app.models import PushSubscription
        except ImportError:
            from .models import PushSubscription

        ua = request.META.get('HTTP_USER_AGENT', '')[:255]
        obj, created = PushSubscription.objects.update_or_create(
            endpoint=endpoint,
            defaults={'p256dh': p256dh, 'auth': auth, 'user_agent': ua, 'last_used_at': time.time()},
        )
        logger.info('Push subscription %s: %s', 'registered' if created else 'refreshed', endpoint[:60])
        return _cors(JsonResponse({'status': 'subscribed', 'created': created}))

    except Exception as exc:
        logger.warning('push_subscribe error: %s', exc)
        return _cors(JsonResponse({'error': str(exc)}, status=500))


@csrf_exempt
def push_unsubscribe(request):
    """
    POST /model_app/push/unsubscribe
    Body: { endpoint }
    Removes the push subscription from the DB.
    """
    if request.method == 'OPTIONS':
        resp = JsonResponse({})
        resp['Access-Control-Allow-Origin']  = '*'
        resp['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    if request.method != 'POST':
        return _cors(JsonResponse({'error': 'POST only'}, status=405))

    try:
        body     = json.loads(request.body or '{}')
        endpoint = body.get('endpoint', '').strip()
        if not endpoint:
            return _cors(JsonResponse({'error': 'endpoint required'}, status=400))

        try:
            from model_app.models import PushSubscription
        except ImportError:
            from .models import PushSubscription

        deleted, _ = PushSubscription.objects.filter(endpoint=endpoint).delete()
        return _cors(JsonResponse({'status': 'unsubscribed', 'deleted': deleted}))

    except Exception as exc:
        return _cors(JsonResponse({'error': str(exc)}, status=500))
