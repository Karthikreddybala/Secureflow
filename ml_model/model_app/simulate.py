"""
Attack Simulation — SecureFlow IDS
Injects synthetic packet flows directly into the processing pipeline.
No WebSocket or PCAP required — useful for demos and testing.
"""

import random
import time

# ── Signature templates ───────────────────────────────────────────────────────
# Each template defines the statistical profile of that attack type's packets.
_SIGNATURES = {
    'DoS': {
        'dst_port':   80,
        'proto':      6,      # TCP
        'pkt_count':  random.randint(80, 120),
        'size_range': (60, 120),
        'flags':      0x02,   # SYN
        'fwd_ratio':  0.95,   # almost all fwd
    },
    'DDoS': {
        'dst_port':   443,
        'proto':      17,     # UDP
        'pkt_count':  random.randint(50, 100),
        'size_range': (100, 1400),
        'flags':      0,
        'fwd_ratio':  0.98,
    },
    'PortScan': {
        'dst_port':   None,   # rotates through ports
        'proto':      6,
        'pkt_count':  random.randint(30, 60),
        'size_range': (40, 80),
        'flags':      0x02,   # SYN only
        'fwd_ratio':  1.0,
    },
    'BruteForce': {
        'dst_port':   22,     # SSH
        'proto':      6,
        'pkt_count':  random.randint(40, 80),
        'size_range': (80, 200),
        'flags':      0x18,   # PSH+ACK
        'fwd_ratio':  0.6,
    },
    'Botnet': {
        'dst_port':   6667,   # IRC C2
        'proto':      6,
        'pkt_count':  random.randint(20, 40),
        'size_range': (60, 400),
        'flags':      0x18,
        'fwd_ratio':  0.5,
    },
    'Normal': {
        'dst_port':   443,
        'proto':      6,
        'pkt_count':  random.randint(10, 30),
        'size_range': (200, 1400),
        'flags':      0x18,
        'fwd_ratio':  0.6,
    },
}

SUPPORTED = list(_SIGNATURES.keys())


def _random_private_ip():
    return f'192.168.{random.randint(0,254)}.{random.randint(1,254)}'


def _random_attacker_ip():
    return f'{random.randint(1,223)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}'


def generate_packets(attack_type: str = 'DoS') -> list[dict]:
    """
    Generate a list of synthetic packet dicts that mimic the given attack type.
    Returns packets ready to be fed to views.process_packet().
    """
    sig = _SIGNATURES.get(attack_type, _SIGNATURES['Normal'])
    src_ip   = _random_attacker_ip()
    dst_ip   = _random_private_ip()
    sport    = random.randint(1024, 65535)
    now      = time.time()

    packets = []
    count   = sig['pkt_count']
    ports   = list(range(1, 1025)) if attack_type == 'PortScan' else None

    for i in range(count):
        dport   = ports[i % len(ports)] if ports else sig['dst_port']
        is_fwd  = random.random() < sig['fwd_ratio']
        pkt_src = src_ip if is_fwd else dst_ip
        pkt_dst = dst_ip if is_fwd else src_ip
        pkt_sp  = sport  if is_fwd else dport
        pkt_dp  = dport  if is_fwd else sport

        packets.append({
            'timestamp':   now + i * random.uniform(0.001, 0.05),
            'src':         pkt_src,
            'dst':         pkt_dst,
            'sport':       pkt_sp,
            'dport':       pkt_dp,
            'proto':       sig['proto'],
            'size':        random.randint(*sig['size_range']),
            'ip_hdr_len':  20,
            'tcp_hdr_len': 20 if sig['proto'] == 6 else 0,
            'flags':       sig['flags'],
        })

    return packets
