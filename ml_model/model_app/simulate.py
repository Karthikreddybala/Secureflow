"""
Attack Simulation — SecureFlow IDS
Injects synthetic packet flows directly into the processing pipeline.
No WebSocket or PCAP required — useful for demos and testing.

Upgraded to Suricata-level: each new attack type is crafted to specifically
trigger the deterministic rule engine (per-packet rules), not just ML features.
"""

import random
import time

# ── TCP flag bitmasks ─────────────────────────────────────────────────────────
_FIN = 0x01; _SYN = 0x02; _RST = 0x04; _PSH = 0x08; _ACK = 0x10; _URG = 0x20

# ── Signature templates ───────────────────────────────────────────────────────
# Each template defines the statistical profile of that attack type's packets.
_SIGNATURES = {

    # ── ML-tuned attacks (trigger ML flow classifier) ─────────────────────────
    'DoS': {
        'dst_port':   80,
        'proto':      6,        # TCP
        'pkt_count':  120,
        'size_range': (60, 120),
        'flags':      _SYN,     # SYN flood to port 80
        'fwd_ratio':  0.98,
        'description': 'SYN flood to HTTP (port 80)',
    },
    'DDoS': {
        'dst_port':   443,
        'proto':      17,       # UDP
        'pkt_count':  100,
        'size_range': (100, 1400),
        'flags':      0,
        'fwd_ratio':  0.98,
        'description': 'UDP flood to HTTPS port',
    },
    'BruteForce': {
        'dst_port':   22,       # SSH
        'proto':      6,
        'pkt_count':  80,
        'size_range': (80, 200),
        'flags':      _PSH | _ACK,
        'fwd_ratio':  0.6,
        'description': 'SSH credential brute-force',
    },
    'Botnet': {
        'dst_port':   6667,     # IRC C2 — also triggers C2Beacon rule
        'proto':      6,
        'pkt_count':  30,
        'size_range': (60, 400),
        'flags':      _PSH | _ACK,
        'fwd_ratio':  0.5,
        'description': 'IRC botnet C2 communication',
    },
    'Normal': {
        'dst_port':   443,
        'proto':      6,
        'pkt_count':  20,
        'size_range': (200, 1400),
        'flags':      _PSH | _ACK,
        'fwd_ratio':  0.6,
        'description': 'Normal HTTPS web traffic',
    },

    # ── Rule-engine attacks (trigger per-packet Suricata-style rules) ─────────

    'PortScan': {
        # Each packet goes to a DIFFERENT destination port with SYN-only flag.
        # Uses rotate_ports=True so each packet creates a distinct flow entry.
        'dst_port':   None,     # rotates: 1 → 1024
        'proto':      6,
        'pkt_count':  50,       # 50 unique ports → triggers ≥30 threshold
        'size_range': (40, 60),
        'flags':      _SYN,     # SYN-only (no ACK) → rule engine sees port scan
        'fwd_ratio':  1.0,
        'rotate_ports': True,
        'description': 'TCP SYN port scan (triggers PortScan rule at 30 unique ports)',
    },

    'SYNFlood': {
        # High-rate SYN packets all to same port — triggers SYN flood rule (>50 in 5s).
        'dst_port':   80,
        'proto':      6,
        'pkt_count':  60,
        'size_range': (40, 60),
        'flags':      _SYN,     # SYN-only
        'fwd_ratio':  1.0,
        'time_compress': 1.0,   # all packets within 1 second → very high rate
        'description': 'TCP SYN flood (>50 SYN/s → SYNFlood rule)',
    },

    'XmasScan': {
        # Xmas tree scan: FIN+PSH+URG all set — triggers immediately on first packet.
        'dst_port':   None,     # rotates
        'proto':      6,
        'pkt_count':  10,
        'size_range': (40, 60),
        'flags':      _FIN | _PSH | _URG,  # Xmas flags
        'fwd_ratio':  1.0,
        'rotate_ports': True,
        'description': 'TCP Xmas tree scan (FIN+PSH+URG → XmasScan rule per packet)',
    },

    'NullScan': {
        # Null scan: all TCP flags = 0 — triggers immediately.
        'dst_port':   None,
        'proto':      6,
        'pkt_count':  10,
        'size_range': (40, 60),
        'flags':      0x00,     # null flags
        'fwd_ratio':  1.0,
        'rotate_ports': True,
        'description': 'TCP Null scan (flags=0 → NullScan rule per packet)',
    },

    'FINScan': {
        # FIN-only scan — stealth probe, triggers FINScan rule.
        'dst_port':   None,
        'proto':      6,
        'pkt_count':  10,
        'size_range': (40, 60),
        'flags':      _FIN,     # FIN only
        'fwd_ratio':  1.0,
        'rotate_ports': True,
        'description': 'TCP FIN stealth scan (FIN-only → FINScan rule)',
    },

    'SSHBruteForce': {
        # 12 SYN-only packets to port 22 → SSH brute-force rule fires at 11th.
        'dst_port':   22,
        'proto':      6,
        'pkt_count':  12,
        'size_range': (40, 60),
        'flags':      _SYN,     # SYN-only (new connection attempt each time)
        'fwd_ratio':  1.0,
        'description': 'SSH brute-force (>10 SYN to :22 → SSHBruteForce rule)',
    },

    'RDPBruteForce': {
        # 12 SYN-only packets to port 3389 → RDP brute-force rule.
        'dst_port':   3389,
        'proto':      6,
        'pkt_count':  12,
        'size_range': (40, 60),
        'flags':      _SYN,
        'fwd_ratio':  1.0,
        'description': 'RDP brute-force (>10 SYN to :3389 → RDPBruteForce rule)',
    },

    'ICMPFlood': {
        # 110 ICMP packets — triggers ICMPFlood rule (>100 in 5s).
        'dst_port':   0,
        'proto':      1,        # ICMP
        'pkt_count':  110,
        'size_range': (64, 64),
        'flags':      0,
        'fwd_ratio':  1.0,
        'time_compress': 2.0,   # all within 2 seconds
        'description': 'ICMP flood (>100 pkts in 5s → ICMPFlood rule)',
    },

    'DNSExfiltration': {
        # 25 large DNS packets rapidly — triggers DNSExfil rule (>20 in 5s).
        'dst_port':   53,
        'proto':      17,       # UDP
        'pkt_count':  25,
        'size_range': (220, 400),   # >200 bytes → also triggers per-packet DNS rule
        'flags':      0,
        'fwd_ratio':  1.0,
        'time_compress': 2.0,
        'description': 'DNS tunneling exfiltration (>20 queries/5s OR payload >200B)',
    },

    'C2Beacon': {
        # Traffic to Metasploit default port 4444 → C2Beacon rule fires immediately.
        'dst_port':   4444,
        'proto':      6,
        'pkt_count':  5,
        'size_range': (60, 200),
        'flags':      _PSH | _ACK,
        'fwd_ratio':  0.6,
        'description': 'C2 beacon to port 4444 (Metasploit default → C2Beacon rule)',
    },

    'CredStuffing': {
        # RST storm: >20 RSTs in 30s → CredStuffing rule.
        'dst_port':   443,
        'proto':      6,
        'pkt_count':  25,
        'size_range': (40, 60),
        'flags':      _RST,     # RST-only = failed connections
        'fwd_ratio':  1.0,
        'description': 'Credential stuffing RST storm (>20 RSTs in 30s)',
    },

    'HTTPFlood': {
        # 105 SYN packets to port 80 in 10s → HTTPFlood rule.
        'dst_port':   80,
        'proto':      6,
        'pkt_count':  105,
        'size_range': (40, 80),
        'flags':      _SYN,
        'fwd_ratio':  1.0,
        'time_compress': 5.0,   # all within 5 seconds
        'description': 'HTTP flood (>100 SYN to :80 in 10s → HTTPFlood rule)',
    },
}

SUPPORTED = sorted(_SIGNATURES.keys())


def _random_private_ip():
    return f'192.168.{random.randint(0, 254)}.{random.randint(1, 254)}'


def _random_attacker_ip():
    # Return a routable (non-private, non-loopback) IP
    while True:
        a = random.randint(1, 223)
        if a not in (10, 127, 169, 172, 192):
            return f'{a}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}'


def generate_packets(attack_type: str = 'DoS') -> list[dict]:
    """
    Generate a list of synthetic packet dicts that precisely trigger the
    SecureFlow rule engine and/or ML classifier for the given attack type.

    Key design decisions:
    - PortScan / XmasScan / NullScan / FINScan use UNIQUE sport per packet so
      each packet creates its own flow (or many flows), ensuring the rule engine
      sees them as distinct probe connections \u2014 not one aggregate flow.
    - SYNFlood / ICMPFlood / HTTPFlood use time_compress to pack all packets
      within the rate window (5s or 10s).
    - SSHBruteForce / RDPBruteForce use unique sport per packet to simulate
      distinct connection attempts (each new TCP SYN = new connection).
    """
    sig = _SIGNATURES.get(attack_type, _SIGNATURES['Normal'])
    src_ip  = _random_attacker_ip()
    dst_ip  = _random_private_ip()
    now     = time.time()
    count   = sig['pkt_count']

    # Time window: compress all packets into sig.get('time_compress') seconds
    # Default: spread over 8s (normal flow), compressed for flood attacks.
    total_duration = sig.get('time_compress', 8.0)
    interval       = total_duration / max(count, 1)

    # Port rotation: each packet gets its own unique destination port
    rotate_ports = sig.get('rotate_ports', False)
    _port_pool = list(range(1, 1025))
    random.shuffle(_port_pool)

    packets = []
    base_sport = random.randint(32768, 60999)

    for i in range(count):
        # Destination port
        if rotate_ports:
            dport = _port_pool[i % len(_port_pool)]
        elif sig['dst_port'] is None:
            dport = random.randint(1, 1024)
        else:
            dport = sig['dst_port']

        is_fwd = random.random() < sig['fwd_ratio']

        # For scan/brute-force types: each packet is a NEW connection attempt
        # so we give each its own unique source port to avoid flow aggregation.
        if rotate_ports or attack_type in ('SSHBruteForce', 'RDPBruteForce',
                                           'SYNFlood', 'HTTPFlood', 'CredStuffing'):
            sport = base_sport + i          # unique source port per packet
        else:
            sport = base_sport

        pkt_src = src_ip if is_fwd else dst_ip
        pkt_dst = dst_ip if is_fwd else src_ip
        pkt_sp  = sport  if is_fwd else dport
        pkt_dp  = dport  if is_fwd else sport

        packets.append({
            'timestamp':    now + i * interval,
            'src':          pkt_src,
            'dst':          pkt_dst,
            'sport':        pkt_sp,
            'dport':        pkt_dp,
            'proto':        sig['proto'],
            'size':         random.randint(*sig['size_range']),
            'ip_hdr_len':   20,
            'tcp_hdr_len':  20 if sig['proto'] == 6 else 0,
            'flags':        sig['flags'],
        })

    return packets


def get_description(attack_type: str) -> str:
    """Return a human-readable description of the simulation."""
    sig = _SIGNATURES.get(attack_type, {})
    return sig.get('description', attack_type)
