"""
Alert Correlation → Incidents — SecureFlow IDS
Groups alerts from the same source IP + attack type within a 5-minute window
into a single Incident object.

Upgrades (Suricata-level):
  - Multi-source DDoS grouping: same dst_ip + attack_type from MANY src IPs
    → single DDoS/Botnet incident (maps distributed attacks correctly).
  - Rule-triggered flag propagated to incident for priority display.
  - Severity escalation: incident severity rises if alert count grows.
  - Peak rate computed from actual alert timestamps (rolling 10s window).
  - Incident confidence (0-100) tracks average ML/rule score.
"""

import time
import threading
import uuid
from collections import defaultdict

_lock = threading.Lock()

# ── In-memory incident store ──────────────────────────────────────────────────
# Key: (src_ip, attack_type) for single-source incidents
# Key: ('__multi__', dst_ip, attack_type) for multi-source DDoS incidents
_active: dict[tuple, dict] = {}
_resolved: list[dict] = []      # completed incidents (last 500)
MAX_RESOLVED = 500
WINDOW_SECS  = 300   # 5-minute correlation window
IDLE_SECS    = 90    # incident marked resolved if no alert in 90s
                     # (was 60s — raised to avoid premature resolution of slow scans)

# Attack types that should be grouped by dst_ip (multi-source distributed attacks)
_MULTI_SOURCE_ATTACKS = frozenset({'DDoS', 'DoS', 'SYNFlood', 'ICMPFlood', 'HTTPFlood', 'Botnet'})

# Severity ordering helper
_SEV_RANK = {'Low': 0, 'Medium': 1, 'High': 2}


def _max_severity(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


def _compute_peak_rate(timestamps: list) -> float:
    """Compute peak alerts per second in the last 10s rolling window."""
    now = time.time()
    recent = [t for t in timestamps if now - t <= 10.0]
    if len(recent) < 2:
        return float(len(recent))
    return round(len(recent) / 10.0, 2)


def correlate_alert(alert: dict) -> dict | None:
    """
    Feed an alert into the correlation engine.
    Returns the updated incident dict (or None if skipped).

    Routing logic:
    - DDoS / SYNFlood / HTTPFlood / ICMPFlood / Botnet → group by (dst_ip, attack_type)
      so distributed attacks from many IPs become ONE incident.
    - All other attacks → group by (src_ip, attack_type) as before.
    """
    final    = alert.get('final', {})
    attack   = final.get('attack_type', 'Unknown')
    src_ip   = alert.get('src_ip', 'unknown')
    dst_ip   = alert.get('dst_ip', 'unknown')
    severity = final.get('severity', 'Low')
    score    = float(final.get('final_score', 0.0))
    is_rule  = bool(alert.get('rule_triggered', False))
    now      = time.time()

    # Don't correlate Normal traffic
    if attack.lower() in ('normal', 'benign'):
        return None

    # ── Choose incident key ───────────────────────────────────────────────────
    if attack in _MULTI_SOURCE_ATTACKS:
        # Multi-source: group by destination + attack type
        key = ('__multi__', dst_ip or 'unknown', attack)
        incident_src = '__distributed__'
    else:
        # Single-source: group by origin + attack type
        key = (src_ip, attack)
        incident_src = src_ip

    with _lock:
        inc = _active.get(key)

        if inc is None or (now - inc['last_alert_time']) > IDLE_SECS:
            # Archive old idle incident
            if inc is not None:
                old = inc.copy()
                old['status']    = 'resolved'
                old['dst_ips']   = list(old['dst_ips'])
                old['dst_ports'] = list(old['dst_ports'])
                old['src_ips']   = list(old['src_ips'])
                _resolved.append(old)
                if len(_resolved) > MAX_RESOLVED:
                    _resolved.pop(0)

            # Start new incident
            inc = {
                'id':              str(uuid.uuid4())[:8],
                'src_ip':          incident_src,
                'attack_type':     attack,
                'mitre':           alert.get('mitre', {}),
                'severity':        severity,
                'start':           now,
                'last_alert_time': now,
                'alert_count':     1,
                'peak_rate':       0.0,
                'dst_ips':         set(),
                'dst_ports':       set(),
                'src_ips':         set(),
                'status':          'ongoing',
                'rule_triggered':  is_rule,
                'avg_score':       score,
                '_scores':         [score],       # raw scores for avg computation
                '_timestamps':     [now],         # for peak rate
                'multi_source':    attack in _MULTI_SOURCE_ATTACKS,
            }
            _active[key] = inc

        else:
            # Update existing incident
            inc['alert_count']     += 1
            inc['last_alert_time']  = now
            inc['severity']         = _max_severity(inc['severity'], severity)
            inc['_timestamps'].append(now)
            inc['_scores'].append(score)
            # Keep lists bounded (last 500 entries)
            if len(inc['_timestamps']) > 500:
                inc['_timestamps'] = inc['_timestamps'][-500:]
            if len(inc['_scores']) > 500:
                inc['_scores'] = inc['_scores'][-500:]

            # If any alert in this incident was from a rule engine, mark it
            if is_rule:
                inc['rule_triggered'] = True

            # Escalate severity based on alert count + recency
            if inc['alert_count'] >= 50 and severity != 'High':
                inc['severity'] = 'High'
            elif inc['alert_count'] >= 10 and inc['severity'] == 'Low':
                inc['severity'] = 'Medium'

        # Track metadata
        if dst_ip:
            inc['dst_ips'].add(dst_ip)
        if alert.get('dport'):
            inc['dst_ports'].add(str(alert['dport']))
        if src_ip and src_ip != '__distributed__':
            inc['src_ips'].add(src_ip)

        # Recompute stats
        inc['peak_rate'] = _compute_peak_rate(inc['_timestamps'])
        inc['avg_score'] = round(
            sum(inc['_scores']) / max(len(inc['_scores']), 1), 1
        )

        # For multi-source incidents: show unique source count
        if inc['multi_source']:
            inc['unique_sources'] = len(inc['src_ips'])

        return _incident_snapshot(inc)


def _incident_snapshot(inc: dict) -> dict:
    """Return a JSON-serialisable copy (no sets, no internal _ fields)."""
    snap = {k: v for k, v in inc.items() if not k.startswith('_')}
    snap['dst_ips']   = list(inc['dst_ips'])
    snap['dst_ports'] = list(inc['dst_ports'])
    snap['src_ips']   = list(inc['src_ips'])
    return snap


def get_all_incidents() -> list[dict]:
    """Return all active + recently resolved incidents, newest first."""
    now    = time.time()
    result = []

    with _lock:
        for key, inc in list(_active.items()):
            snap = _incident_snapshot(inc)
            # Auto-resolve idle incidents in the snapshot (don't mutate _active)
            if (now - inc['last_alert_time']) > IDLE_SECS:
                snap['status'] = 'resolved'
            result.append(snap)

        # Last 50 resolved incidents
        for inc in _resolved[-50:]:
            result.append(dict(inc))

    result.sort(key=lambda x: x.get('last_alert_time', 0), reverse=True)
    return result


def get_active_count() -> int:
    now = time.time()
    with _lock:
        return sum(
            1 for inc in _active.values()
            if (now - inc['last_alert_time']) <= IDLE_SECS
        )


def get_summary() -> dict:
    """Return a summary dict for the dashboard stats panel."""
    now      = time.time()
    active   = []
    resolved = 0
    with _lock:
        for inc in _active.values():
            if (now - inc['last_alert_time']) <= IDLE_SECS:
                active.append(inc)
            else:
                resolved += 1
        resolved += len(_resolved)

    high_count   = sum(1 for i in active if i.get('severity') == 'High')
    medium_count = sum(1 for i in active if i.get('severity') == 'Medium')
    rule_count   = sum(1 for i in active if i.get('rule_triggered'))
    return {
        'active_incidents':    len(active),
        'resolved_incidents':  resolved,
        'high_severity':       high_count,
        'medium_severity':     medium_count,
        'rule_triggered':      rule_count,
        'multi_source_ddos':   sum(1 for i in active if i.get('multi_source')),
    }
