"""
dso2_classification/agent.py
============================
Agent 2 — Network State Classification Agent
Modele : Seuils Cisco/ITU-T/3GPP + Random Forest (supervisé)

Les seuils produisent un premier diagnostic déterministe.
Le Random Forest affine la classification finale en apprenant
les patterns complexes du dataset.

Entrée  <- dso2_queue (raw_row depuis Agent 1)
Sortie  -> dso3_input_queue (raw_row, analysis)
"""

import os, queue, threading, warnings
import numpy as np
warnings.filterwarnings('ignore')

from shared.config import DSO2_THRESHOLDS, DSO2_BINARY_FLAGS, OUTPUT_DIR
from shared.queues import pipeline_state, dso2_queue, dso3_input_queue, log_agent, safe_put

# Imports ML avec fallback
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    import joblib
    _rf_ok = True
except ImportError:
    _rf_ok = False

# Etat local
dso2_state = {
    'running':      False,
    'total':        0,
    'alerts_count': 0,
    'log':          [],
}

# Classes réseau
NETWORK_CLASSES = ['Bon', 'Faible', 'Mauvais', 'Tres mauvais']
SEV_MAP = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2}

# Features utilisées par le Random Forest
RF_FEATURES = [
    'latency_ms', 'jitter_ms', 'packet_loss_rate_pct', 'throughput_mbps',
    'mos_proxy', 'rsrp_estimated', 'sinr_estimated', 'cqi_estimated',
    'instability_score', 'risk_score', 'buffer_occupancy_pct',
    'bandwidth_utilization_pct', 'hops_mean', 'spike',
    'ho_failure_proxy', 'coverage_hole_proxy', 'performance_degraded',
    # features issues des seuils (enrichissement)
    'severity_encoded', 'n_critical_thresh', 'n_warning_thresh',
]

# Modèle global (chargé depuis le train)
_rf_model = None
_rf_le    = None


def load_rf_model():
    """Charge le Random Forest depuis outputs/ si disponible."""
    global _rf_model, _rf_le
    if not _rf_ok:
        return False
    rf_path = os.path.join(OUTPUT_DIR, 'rf_classifier.pkl')
    le_path = os.path.join(OUTPUT_DIR, 'rf_label_encoder.pkl')
    if os.path.exists(rf_path) and os.path.exists(le_path):
        _rf_model = joblib.load(rf_path)
        _rf_le    = joblib.load(le_path)
        return True
    return False


def _cisco_thresholds(row: dict) -> dict:
    """
    Etape 1 : Seuils Cisco / ITU-T / 3GPP.
    Produit severity, alerts, n_critical, n_warning.
    """
    alerts = []
    for metric, (warn, crit, inv) in DSO2_THRESHOLDS.items():
        val = row.get(metric)
        if val is None or val == -1:
            continue
        v = float(val)
        level = ('CRITICAL' if (v <= crit if inv else v >= crit) else
                 'WARNING'  if (v <= warn if inv else v >= warn) else 'OK')
        if level != 'OK':
            alerts.append({
                'metric':    metric,
                'value':     round(v, 4),
                'threshold': crit if level == 'CRITICAL' else warn,
                'level':     level,
                'source':    'Cisco/ITU-T/3GPP',
            })

    for metric, desc in DSO2_BINARY_FLAGS.items():
        if int(float(row.get(metric, 0))) == 1:
            alerts.append({
                'metric':      metric,
                'value':       1,
                'description': desc,
                'level':       'CRITICAL',
                'source':      'Binary flag',
            })

    has_crit  = any(a['level'] == 'CRITICAL' for a in alerts)
    severity  = 'CRITICAL' if has_crit else ('WARNING' if alerts else 'OK')
    n_crit    = sum(1 for a in alerts if a['level'] == 'CRITICAL')
    n_warn    = sum(1 for a in alerts if a['level'] == 'WARNING')
    return severity, alerts, n_crit, n_warn


def _rf_predict(row: dict, severity: str, n_crit: int, n_warn: int) -> dict:
    """
    Etape 2 : Random Forest.
    Prend les métriques brutes + sortie des seuils → classe réseau finale.
    """
    if _rf_model is None or not _rf_ok:
        # Fallback heuristique si modèle absent
        rsrp = float(row.get('rsrp_estimated', -80) or -80)
        if rsrp >= -80:   return {'class': 'Bon',          'confidence': 0.7, 'source': 'heuristic'}
        if rsrp >= -90:   return {'class': 'Faible',       'confidence': 0.7, 'source': 'heuristic'}
        if rsrp >= -100:  return {'class': 'Mauvais',      'confidence': 0.7, 'source': 'heuristic'}
        return                   {'class': 'Tres mauvais', 'confidence': 0.7, 'source': 'heuristic'}

    try:
        vec = []
        for f in RF_FEATURES:
            if f == 'severity_encoded':
                vec.append(SEV_MAP.get(severity, 0))
            elif f == 'n_critical_thresh':
                vec.append(n_crit)
            elif f == 'n_warning_thresh':
                vec.append(n_warn)
            else:
                vec.append(float(row.get(f, 0) or 0))

        X       = np.array([vec])
        pred    = _rf_model.predict(X)[0]
        probas  = _rf_model.predict_proba(X)[0]
        label   = _rf_le.inverse_transform([pred])[0]
        conf    = round(float(max(probas)), 3)
        return {'class': label, 'confidence': conf, 'source': 'RandomForest'}
    except Exception as e:
        return {'class': row.get('rsrp_category', 'Mauvais'), 'confidence': 0.5, 'source': f'fallback({e})'}


def dso2_classify(row: dict) -> dict:
    """
    Classification complète : Seuils Cisco + Random Forest.
    """
    severity, alerts, n_crit, n_warn = _cisco_thresholds(row)
    rf_result = _rf_predict(row, severity, n_crit, n_warn)

    return {
        'severity':         severity,
        'has_critical':     n_crit > 0,
        'rsrp_class':       row.get('rsrp_category', '?'),
        'n_critical':       n_crit,
        'n_warning':        n_warn,
        'alerts':           alerts,
        # Résultat Random Forest
        'rf_class':         rf_result['class'],
        'rf_confidence':    rf_result['confidence'],
        'rf_source':        rf_result['source'],
        # Features enrichies transmises à l'agent suivant
        'severity_encoded': SEV_MAP.get(severity, 0),
    }


def dso2_loop():
    load_rf_model()
    rf_loaded = _rf_model is not None
    log_agent(dso2_state, 'log',
              f'Agent2 demarre — Seuils Cisco + RF({"charge" if rf_loaded else "heuristic"})')

    while dso2_state['running']:
        try:
            raw_row = dso2_queue.get(timeout=2)
        except queue.Empty:
            continue

        dso2_state['total'] += 1
        try:
            analysis = dso2_classify(raw_row)
            safe_put(dso3_input_queue, (raw_row, analysis))
            pipeline_state['last_analysis'] = analysis

            if analysis['severity'] != 'OK':
                dso2_state['alerts_count'] += 1
                pipeline_state['alerts_count'] += 1
                log_agent(dso2_state, 'log',
                          f'{analysis["severity"]} | RF={analysis["rf_class"]} '
                          f'({analysis["rf_confidence"]:.0%}) | '
                          f'{analysis["n_critical"]}C {analysis["n_warning"]}W')
            else:
                log_agent(dso2_state, 'log',
                          f'OK | RF={analysis["rf_class"]} ({analysis["rf_confidence"]:.0%})')
        except Exception as e:
            log_agent(dso2_state, 'log', f'Erreur: {e}')


def start():
    dso2_state.update({'running': True, 'total': 0, 'alerts_count': 0, 'log': []})
    t = threading.Thread(target=dso2_loop, name='Agent2-Classify', daemon=True)
    t.start()
    return t


def stop():
    dso2_state['running'] = False
