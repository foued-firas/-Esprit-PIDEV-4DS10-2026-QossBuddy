"""
shared/config.py
================
Configuration globale du pipeline QoS — INMS
Toutes les constantes et paramètres centralisés ici.
"""

import os

# ── Réseau
TARGET_HOST   = '8.8.8.8'
TARGET_HOST2  = '1.1.1.1'
PING_COUNT    = 5
MAX_HOPS      = 10
INTERVAL_SEC  = 10

# ── Chemins
OUTPUT_DIR    = os.path.join(os.getcwd(), 'outputs')
CSV_LIVE      = os.path.join(OUTPUT_DIR, 'monitoring_live.csv')
CSV_ALERTS    = os.path.join(OUTPUT_DIR, 'alerts_log.csv')

# ── Autoencoder (DSO1)
AE_INPUT_DIM          = 54
AE_HIDDEN_DIM         = 32
AE_BOTTLENECK         = 10    # réduit (35 features → bottleneck 10 évite surapprentissage)
AE_EPOCHS             = 100
AE_LR                 = 1e-3
AE_BATCH_SIZE         = 64
AE_FINE_TUNE_N        = 10
AE_RECON_CRITICAL_PCT = 95

# ── Modèles ensemble DSO1 (IF + EE + SVM)
IF_CONTAMINATION = 0.08
LOF_N_NEIGHBORS  = 20
SVM_NU           = 0.08

# ── Vote pondéré DSO1
VOTE_W_IF   = 0.45
VOTE_W_EE   = 0.35
VOTE_W_SVM  = 0.20
VOTE_SEUIL  = 0.50   # relevé (0.40→0.50) pour réduire les faux positifs

# ── DSO2 — Seuils Cisco / ITU-T / 3GPP
DSO2_THRESHOLDS = {
    'latency_ms':                (150,   200,   False),
    'mean_latency_ms':           (150,   200,   False),
    'max_latency_ms':            (200,   400,   False),
    'std_latency_ms':            (20,    50,    False),
    'jitter_ms':                 (30,    50,    False),
    'latency_spread':            (20,    50,    False),
    'latency_trend':             (50,    100,   False),
    'packet_loss_rate_pct':      (1.0,   5.0,   False),
    'risk_score':                (0.4,   0.6,   False),
    'instability_score':         (5.0,   15.0,  False),
    'bandwidth_utilization_pct': (50.0,  75.0,  False),
    'network_load':              (0.5,   0.75,  False),
    'queue_length':              (70,    90,    False),
    'buffer_occupancy_pct':      (75,    90,    False),
    'prb_utilization_proxy':     (50.0,  75.0,  False),
    'hops_mean':                 (50,    100,   False),
    'hops_max':                  (150,   300,   False),
    'hops_std':                  (30,    60,    False),
    'hops_range':                (100,   200,   False),
    'mos_proxy':                 (3.6,   3.1,   True),
    'rsrp_estimated':            (-80,   -100,  True),
    'sinr_estimated':            (0,     -3,    True),
    'cqi_estimated':             (7,     4,     True),
    'bandwidth_efficiency':      (0.3,   0.1,   True),
}
DSO2_BINARY_FLAGS = {
    'spike':               'Pic de latence',
    'ho_failure_proxy':    'Echec handover',
    'coverage_hole_proxy': 'Zone couverture faible',
    'performance_degraded':'Degradation performance',
}

# ── DSO3 — Risk Prediction
HORIZONS_SEC     = [20, 60, 300]
RISK_THRESHOLDS  = {
    'LOW':      (0,   30),
    'MEDIUM':   (30,  60),
    'HIGH':     (60,  80),
    'CRITICAL': (80, 100),
}
SEQ_FEATURES = [
    'latency_ms', 'jitter_ms', 'packet_loss_rate_pct',
    'throughput_mbps', 'risk_score', 'instability_score',
    'rsrp_estimated', 'sinr_estimated', 'mos_proxy',
    'buffer_occupancy_pct', 'queue_length',
    'bandwidth_utilization_pct', 'hops_mean',
]
TAB_FEATURES = SEQ_FEATURES + [
    'spike', 'ho_failure_proxy', 'coverage_hole_proxy', 'performance_degraded',
    'peak_offpeak_indicator', 'hour_sin', 'hour_cos',
    'dayofweek_sin', 'dayofweek_cos',
    'severity_encoded', 'n_critical', 'n_warning',
    'delta_latency', 'delta_jitter', 'delta_packet_loss',
    'delta_throughput', 'delta_risk_score',
]
WINDOW_SIZE     = 15
MIN_WINDOW_PRED = 5
W_SEQ           = 0.55
W_TAB           = 0.45
CSV_PREDICTIONS = os.path.join(OUTPUT_DIR, 'dso3_predictions.csv')
CSV_VALISE      = os.path.join(OUTPUT_DIR, 'dso3_valise.csv')

# ── DSO6 — Security
WATCHED_PORTS = {
    4040: 'Spark UI', 22: 'SSH', 23: 'Telnet', 3389: 'RDP',
    445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 6379: 'Redis',
    9200: 'Elasticsearch', 5900: 'VNC', 21: 'FTP', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-alt',
}
THRESHOLDS_DSO6 = {
    'portscan_conn_count': 5,
    'ddos_pps_threshold':  500,
    'bruteforce_attempts': 10,
    'dso3_risk_trigger':   60,
    'syn_flood_ratio':     0.7,
    'ip_conn_limit':       20,
}
CSV_ATTACKS  = os.path.join(OUTPUT_DIR, 'dso6_attacks.csv')
JSON_REPORTS = os.path.join(OUTPUT_DIR, 'dso6_reports.json')

# ── Seed global
SEED = 42

# ── Data preparation
COLS_DROP = ['timestamp', 'congestion_level']
TARGET_COL = 'rsrp_category'
BINARY_COLS = ['spike', 'ho_failure_proxy', 'coverage_hole_proxy', 'peak_offpeak_indicator']
COLS_REDUNDANT = [
    'mean_latency_ms', 'network_load', 'prb_utilization_proxy',
    'latency_spread', 'hour', 'minute', 'dayofweek',
    *[f'hop_{i}' for i in range(1, 11)],
]
