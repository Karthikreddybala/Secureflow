"""
Alert Correlation → Incidents — SecureFlow IDS
Groups alerts from the same source IP + attack type within a 5-minute window
into a single Incident object.
"""

import time
import threading
import uuid
from collections import defaultdict

_lock = threading.Lock()

# ── In-memory incident store ──────────────────────────────────────────────────
# Key: (src_ip, attack_type)
# Value: incident dict
_active: dict[tuple, dict] = {}
_resolved: list[dict] = []      # completed incidents (last 500)
MAX_RESOLVED = 500
WINDOW_SECS  = 300   # 5-minute correlation window
IDLE_SECS    = 60    # incident marked resolved if no alert for 60s


def correlate_alert(alert: dict) -> dict | None:
    """
    Feed an alert into the correlation engine.
    Returns the updated incident dict (or None if skipped).
    """
    final    = alert.get('final', {})
    attack   = final.get('attack_type', 'Unknown')
    src_ip   = alert.get('src_ip', 'unknown')
    severity = final.get('severity', 'Low')
    now      = time.time()

    # Don't correlate Normal traffic
    if attack.lower() == 'normal':
        return None

    key = (src_ip, attack)

    with _lock:
        inc = _active.get(key)

        if inc is None or (now - inc['last_alert_time']) > IDLE_SECS:
            # Start new incident
            inc = {
                'id':             str(uuid.uuid4())[:8],
                'src_ip':         src_ip,
                'attack_type':    attack,
                'mitre':          alert.get('mitre', {}),
                'severity':       severity,
                'start':          now,
                'last_alert_time': now,
                'alert_count':    1,
                'peak_rate':      0.0,
                'dst_ips':        set(),
                'dst_ports':      set(),
                'status':         'ongoing',
            }
            if _active.get(key):
                # Previous was idle — archive it first
                old = _active[key]
                old['status'] = 'resolved'
                old['dst_ips']   = list(old['dst_ips'])
                old['dst_ports'] = list(old['dst_ports'])
                _resolved.append(old)
                if len(_resolved) > MAX_RESOLVED:
                    _resolved.pop(0)
            _active[key] = inc
        else:
            # Update existing incident
            inc['alert_count']     += 1
            inc['last_alert_time']  = now
            inc['severity'] = max(inc['severity'], severity,
                                  key=lambda s: {'Low': 0, 'Medium': 1, 'High': 2}.get(s, 0))

        # Track metadata
        if alert.get('dst_ip'):
            inc['dst_ips'].add(alert['dst_ip'])
        if alert.get('dport'):
            inc['dst_ports'].add(str(alert['dport']))

        # Compute rough packet rate
        elapsed = max(now - inc['start'], 1.0)
        inc['peak_rate'] = round(inc['alert_count'] / elapsed, 2)

        return _incident_snapshot(inc)


def _incident_snapshot(inc: dict) -> dict:
    """Return a JSON-serialisable copy."""
    snap = dict(inc)
    snap['dst_ips']   = list(inc['dst_ips'])
    snap['dst_ports'] = list(inc['dst_ports'])
    return snap


def get_all_incidents() -> list[dict]:
    """Return all active + recently resolved incidents."""
    now = time.time()
    result = []

    with _lock:
        for key, inc in list(_active.items()):
            snap = _incident_snapshot(inc)
            # Auto-resolve idle
            if (now - inc['last_alert_time']) > IDLE_SECS:
                snap['status'] = 'resolved'
            result.append(snap)

        for inc in _resolved[-50:]:    # last 50 resolved
            result.append(inc)

    result.sort(key=lambda x: x.get('last_alert_time', 0), reverse=True)
    return result


def get_active_count() -> int:
    now = time.time()
    with _lock:
        return sum(
            1 for inc in _active.values()
            if (now - inc['last_alert_time']) <= IDLE_SECS
        )
