"""
dso6_security/agent.py
======================
DSO6 — Security Anomaly Detection Agent
Détecte : Port Scan, SYN Flood, DDoS, Brute Force, Banner Grab

Entrée  ← dso6_input_queue (valise depuis DSO3)
Sortie  → dso5_queue (valise enrichie + events sécurité)
"""

import os, re, csv, json, time, subprocess, threading, queue
import numpy as np
from collections import defaultdict, deque, Counter
from datetime import datetime

from shared.config import WATCHED_PORTS, THRESHOLDS_DSO6, CSV_ATTACKS, JSON_REPORTS
from shared.queues import dso6_input_queue, dso5_queue, log_agent, safe_put

# ── Imports optionnels
try:
    from sklearn.ensemble import IsolationForest
    _ml_ok = True
except ImportError:
    _ml_ok = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    _scapy_ok = True
except Exception:
    _scapy_ok = False

# ── États TCP Linux
TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT',  '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',   '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE',       '08': 'CLOSE_WAIT','09': 'LAST_ACK',
    '0A': 'LISTEN',      '0B': 'CLOSING',
}

# ── Patterns syslog
SYSLOG_PATTERNS = {
    'BRUTE_FORCE': [
        re.compile(r'Failed password for .+ from ([\d\.]+)', re.I),
        re.compile(r'Invalid user .+ from ([\d\.]+)',         re.I),
        re.compile(r'authentication failure.*rhost=([\d\.]+)', re.I),
    ],
    'PORT_SCAN': [
        re.compile(r'SCAN.+SRC=([\d\.]+)', re.I),
    ],
    'BANNER_GRAB': [
        re.compile(r'Did not receive identification string from ([\d\.]+)', re.I),
    ],
}

# ── État local DSO6
dso6_state = {
    'running':        False,
    'total':          0,
    'attacks_found':  0,
    'log':            [],
}

# ── Buffer paquets Scapy
_packet_buffer = deque(maxlen=500)


# ═══════════════════════════════════════════════════════════════
# COLLECTEURS
# ═══════════════════════════════════════════════════════════════

def _hex_to_ip(hex_str):
    try:
        addr = int(hex_str, 16)
        return f'{addr&0xFF}.{(addr>>8)&0xFF}.{(addr>>16)&0xFF}.{(addr>>24)&0xFF}'
    except Exception:
        return '0.0.0.0'

def _hex_to_port(hex_str):
    try:
        return int(hex_str, 16)
    except Exception:
        return 0


def collect_proc_net_tcp() -> list:
    """Lit /proc/net/tcp — fallback vers netstat (Cellule 3 du notebook)."""
    connections = []
    for path in ['/proc/net/tcp', '/proc/net/tcp6']:
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    la, lp  = parts[1].split(':')
                    ra, rp  = parts[2].split(':')
                    connections.append({
                        'local_ip':    _hex_to_ip(la),
                        'local_port':  _hex_to_port(lp),
                        'remote_ip':   _hex_to_ip(ra),
                        'remote_port': _hex_to_port(rp),
                        'state':       TCP_STATES.get(parts[3].upper(), parts[3]),
                    })
        except Exception:
            pass

    if not connections:
        try:
            out = subprocess.check_output(
                ['netstat', '-tn'], timeout=3, stderr=subprocess.DEVNULL,
            ).decode(errors='ignore')
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 5 or parts[0] not in ('tcp', 'tcp6', 'TCP'):
                    continue
                try:
                    la = parts[3].rsplit(':', 1)
                    ra = parts[4].rsplit(':', 1)
                    connections.append({
                        'local_ip':    la[0].strip('[]'),
                        'local_port':  int(la[1]) if len(la) > 1 else 0,
                        'remote_ip':   ra[0].strip('[]'),
                        'remote_port': int(ra[1]) if len(ra) > 1 else 0,
                        'state':       parts[5] if len(parts) > 5 else '?',
                    })
                except Exception:
                    pass
        except Exception:
            pass
    return connections


def collect_syslog(n_lines=200) -> list:
    """Lit les N dernières lignes de auth.log / syslog (Cellule 4)."""
    findings = []
    for path in ['/var/log/auth.log', '/var/log/syslog',
                 '/var/log/secure', '/var/log/messages']:
        if not os.path.exists(path):
            continue
        try:
            result = subprocess.check_output(
                ['tail', '-n', str(n_lines), path],
                timeout=2, stderr=subprocess.DEVNULL,
            ).decode(errors='ignore')
            for line in result.splitlines():
                for attack_type, patterns in SYSLOG_PATTERNS.items():
                    for pat in patterns:
                        m = pat.search(line)
                        if m:
                            ip = m.group(1) if m.lastindex else '?'
                            findings.append({
                                'attack_hint': attack_type,
                                'ip':          ip,
                                'raw':         line.strip()[:200],
                            })
                            break
        except Exception:
            pass
    return findings


def get_packet_stats(window_sec=20) -> dict:
    """Agrège les paquets Scapy des W dernières secondes (Cellule 5)."""
    now    = time.time()
    recent = [p for p in _packet_buffer if now - p['ts'] <= window_sec]
    total  = len(recent)
    tcp_syn     = sum(1 for p in recent if 'S' in p.get('flags','') and 'A' not in p.get('flags',''))
    tcp_syn_ack = sum(1 for p in recent if 'S' in p.get('flags','') and 'A' in p.get('flags',''))
    total_syn   = tcp_syn + tcp_syn_ack
    return {
        'total_packets':  total,
        'pps':            round(total / max(window_sec, 1), 2),
        'tcp_syn':        tcp_syn,
        'tcp_syn_ack':    tcp_syn_ack,
        'unique_src_ips': len(set(p['src'] for p in recent)),
        'top_src_ips':    Counter(p['src'] for p in recent).most_common(5),
        'syn_ratio':      round(tcp_syn / max(total_syn, 1), 3),
    }


# ═══════════════════════════════════════════════════════════════
# ATTACK DETECTOR (Cellule 6)
# ═══════════════════════════════════════════════════════════════

class AttackDetector:
    def __init__(self):
        self._ip_attempts = defaultdict(list)
        self._ip_ports    = defaultdict(set)

    def _clean_windows(self, window=20):
        cutoff = time.time() - window
        for ip in list(self._ip_attempts):
            self._ip_attempts[ip] = [t for t in self._ip_attempts[ip] if t > cutoff]

    def _severity(self, score):
        if score >= 90: return 'CRITICAL'
        if score >= 70: return 'HIGH'
        if score >= 50: return 'MEDIUM'
        if score >= 30: return 'LOW'
        return 'INFO'

    def detect_portscan(self, connections):
        events = []
        by_src = defaultdict(set)
        for c in connections:
            ip = c.get('remote_ip', '')
            if ip and ip != '0.0.0.0':
                by_src[ip].add(c.get('local_port', 0))
                self._ip_ports[ip].add(c.get('local_port', 0))
        for ip, ports in by_src.items():
            n = len(self._ip_ports[ip])
            if n >= THRESHOLDS_DSO6['portscan_conn_count']:
                score = min(100, 40 + n * 5)
                events.append({
                    'attack_type': 'PORT_SCAN',
                    'severity':    self._severity(score),
                    'score':       score,
                    'source_ip':   ip,
                    'detail':      f'{n} ports scannés',
                    'evidence':    'proc_net_tcp',
                })
        return events

    def detect_syn_flood(self, pkt_stats, connections):
        events = []
        syn_ratio = pkt_stats.get('syn_ratio', 0)
        pps       = pkt_stats.get('pps', 0)
        syn_recv  = sum(1 for c in connections if c.get('state') == 'SYN_RECV')
        if syn_ratio >= THRESHOLDS_DSO6['syn_flood_ratio'] or syn_recv > 50:
            score = min(100, int(syn_ratio * 80 + syn_recv * 0.5))
            top   = pkt_stats.get('top_src_ips', [])
            events.append({
                'attack_type': 'SYN_FLOOD',
                'severity':    self._severity(score),
                'score':       score,
                'source_ip':   top[0][0] if top else '?',
                'detail':      f'SYN ratio={syn_ratio:.2f} pps={pps}',
                'evidence':    'scapy + proc_net',
            })
        return events

    def detect_ddos(self, pkt_stats):
        events = []
        pps   = pkt_stats.get('pps', 0)
        n_src = pkt_stats.get('unique_src_ips', 0)
        if pps >= THRESHOLDS_DSO6['ddos_pps_threshold']:
            score = min(100, int(pps / 10))
            events.append({
                'attack_type': 'DDOS_FLOOD',
                'severity':    self._severity(score),
                'score':       score,
                'source_ip':   f'{n_src} IPs distinctes',
                'detail':      f'{pps} paquets/s',
                'evidence':    'scapy',
            })
        return events

    def detect_bruteforce(self, syslog_findings):
        events = []
        self._clean_windows()
        for f in syslog_findings:
            if f.get('attack_hint') == 'BRUTE_FORCE':
                self._ip_attempts[f.get('ip', '?')].append(time.time())
        for ip, ts_list in self._ip_attempts.items():
            n = len(ts_list)
            if n >= THRESHOLDS_DSO6['bruteforce_attempts']:
                score = min(100, 50 + n * 2)
                events.append({
                    'attack_type': 'BRUTE_FORCE',
                    'severity':    self._severity(score),
                    'score':       score,
                    'source_ip':   ip,
                    'detail':      f'{n} tentatives auth en 20s',
                    'evidence':    'syslog',
                })
        return events

    def detect_banner_grab(self, syslog_findings):
        return [{
            'attack_type': 'BANNER_GRAB',
            'severity':    'LOW',
            'score':       30,
            'source_ip':   f.get('ip', '?'),
            'detail':      f['raw'][:120],
            'evidence':    'syslog',
        } for f in syslog_findings if f.get('attack_hint') == 'BANNER_GRAB']

    def detect_from_dso3(self, valise):
        events = []
        pred = valise.get('dso3_prediction', {})
        risk = pred.get('risk_score', 0)
        if risk >= THRESHOLDS_DSO6['dso3_risk_trigger']:
            events.append({
                'attack_type': 'ANOMALY_INHERITED',
                'severity':    pred.get('risk_class', 'MEDIUM'),
                'score':       risk,
                'source_ip':   '— (comportement réseau global)',
                'detail':      f'DSO3 risk={risk}/100 anomaly={pred.get("is_anomaly",False)}',
                'evidence':    'DSO3',
            })
        return events

    def run_all(self, connections, pkt_stats, syslog_findings, valise):
        all_events = (
            self.detect_portscan(connections) +
            self.detect_syn_flood(pkt_stats, connections) +
            self.detect_ddos(pkt_stats) +
            self.detect_bruteforce(syslog_findings) +
            self.detect_banner_grab(syslog_findings) +
            self.detect_from_dso3(valise)
        )
        seen, unique = set(), []
        for e in all_events:
            key = (e['attack_type'], e.get('source_ip', ''))
            if key not in seen:
                seen.add(key)
                unique.append(e)
        return sorted(unique, key=lambda x: -x['score'])


# ═══════════════════════════════════════════════════════════════
# BOUCLE PRINCIPALE DSO6
# ═══════════════════════════════════════════════════════════════

_detector = AttackDetector()


def dso6_loop():
    os.makedirs(os.path.dirname(CSV_ATTACKS) or '.', exist_ok=True)
    log_agent(dso6_state, 'log', 'DSO6 démarré — détection sécurité active')

    while dso6_state['running']:
        try:
            valise = dso6_input_queue.get(timeout=2)
        except queue.Empty:
            continue

        dso6_state['total'] += 1
        n = dso6_state['total']

        try:
            connections     = collect_proc_net_tcp()
            pkt_stats       = get_packet_stats()
            syslog_findings = collect_syslog()
            events          = _detector.run_all(connections, pkt_stats, syslog_findings, valise)

            overall_severity = 'CLEAN'
            if events:
                top = max(e['score'] for e in events)
                overall_severity = ('CRITICAL' if top >= 90 else 'HIGH' if top >= 70 else
                                    'MEDIUM' if top >= 50 else 'LOW')
                dso6_state['attacks_found'] += len(events)

            # Enrichir la valise avec les résultats DSO6
            valise['meta']['dso_stage'] = 'DSO6'
            valise['dso6_security'] = {
                'overall_severity': overall_severity,
                'n_events':         len(events),
                'events':           events,
                'attack_types':     list({e['attack_type'] for e in events}),
                'timestamp':        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }

            # Propager à DSO5
            safe_put(dso5_queue, valise)

            log_agent(dso6_state, 'log',
                      f'#{n} — {overall_severity} — {len(events)} événements')

        except Exception as e:
            log_agent(dso6_state, 'log', f'#{n} erreur: {e}')


def start():
    global _detector
    _detector = AttackDetector()
    dso6_state.update({
        'running': True, 'total': 0, 'attacks_found': 0, 'log': [],
    })
    t = threading.Thread(target=dso6_loop, name='DSO6-Security', daemon=True)
    t.start()
    return t


def stop():
    dso6_state['running'] = False
