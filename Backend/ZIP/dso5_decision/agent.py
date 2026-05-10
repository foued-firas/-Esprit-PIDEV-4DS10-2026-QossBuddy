"""
dso5_decision/agent.py
======================
Agent 5 — Network Optimization Agent
Modele : XGBoost multi-label + règles expertes

XGBoost apprend quelles actions sont optimales selon l'état réseau.
Les règles expertes garantissent la cohérence métier.

Entrée  <- dso5_queue (valise depuis Agent Sécurité)
Sortie  -> dso4_queue (valise + plan d'optimisation)
"""

import os, queue, threading, warnings
import numpy as np
warnings.filterwarnings('ignore')

from shared.queues import dso5_queue, dso4_queue, log_agent, safe_put
from shared.config import OUTPUT_DIR
from datetime import datetime

try:
    import xgboost as xgb
    from sklearn.preprocessing import MultiLabelBinarizer
    import joblib
    _xgb_ok = True
except ImportError:
    _xgb_ok = False

# Etat local
dso5_state = {
    'running':       False,
    'total':         0,
    'actions_taken': 0,
    'log':           [],
}

# Actions possibles indexées
ALL_ACTIONS = [
    'REROUTE_TRAFFIC',
    'BLOCK_SUSPICIOUS_IPS',
    'ALERT_NOC',
    'THROTTLE_BANDWIDTH',
    'ADJUST_QOS_WEIGHTS',
    'MONITOR_CLOSELY',
    'PREPARE_FAILOVER',
    'LOG_AND_WATCH',
    'SOFT_REBALANCE',
    'NO_ACTION_REQUIRED',
    'FIREWALL_BLOCK_SCANNER',
    'ENABLE_SYN_COOKIES',
    'ACTIVATE_SCRUBBING',
    'BLOCK_SOURCE_IP',
    'INVESTIGATE_ANOMALY',
]

ACTION_TARGETS = {
    'REROUTE_TRAFFIC':       'QoS Controller',
    'BLOCK_SUSPICIOUS_IPS':  'Security Enforcement',
    'ALERT_NOC':             'Network Operations',
    'THROTTLE_BANDWIDTH':    'Routing Controller',
    'ADJUST_QOS_WEIGHTS':    'QoS Controller',
    'MONITOR_CLOSELY':       'Network Operations',
    'PREPARE_FAILOVER':      'Routing Controller',
    'LOG_AND_WATCH':         'Monitoring',
    'SOFT_REBALANCE':        'QoS Controller',
    'NO_ACTION_REQUIRED':    'None',
    'FIREWALL_BLOCK_SCANNER':'Security Enforcement',
    'ENABLE_SYN_COOKIES':    'Security Enforcement',
    'ACTIVATE_SCRUBBING':    'Security Enforcement',
    'BLOCK_SOURCE_IP':       'Security Enforcement',
    'INVESTIGATE_ANOMALY':   'Network Operations',
}

ACTION_PRIORITY = {
    'REROUTE_TRAFFIC': 1, 'BLOCK_SUSPICIOUS_IPS': 1, 'ALERT_NOC': 1,
    'ENABLE_SYN_COOKIES': 1, 'ACTIVATE_SCRUBBING': 1, 'BLOCK_SOURCE_IP': 1,
    'THROTTLE_BANDWIDTH': 2, 'ADJUST_QOS_WEIGHTS': 2,
    'MONITOR_CLOSELY': 2, 'FIREWALL_BLOCK_SCANNER': 2, 'INVESTIGATE_ANOMALY': 2,
    'PREPARE_FAILOVER': 3, 'LOG_AND_WATCH': 3, 'SOFT_REBALANCE': 3,
    'NO_ACTION_REQUIRED': 4,
}

# Règles expertes garanties (toujours appliquées)
EXPERT_RULES = {
    'CRITICAL': ['REROUTE_TRAFFIC', 'ALERT_NOC'],
    'HIGH':     ['ADJUST_QOS_WEIGHTS', 'MONITOR_CLOSELY'],
    'MEDIUM':   ['LOG_AND_WATCH'],
    'LOW':      ['NO_ACTION_REQUIRED'],
}

SECURITY_ACTIONS = {
    'PORT_SCAN':         'FIREWALL_BLOCK_SCANNER',
    'SYN_FLOOD':         'ENABLE_SYN_COOKIES',
    'DDOS_FLOOD':        'ACTIVATE_SCRUBBING',
    'BRUTE_FORCE':       'BLOCK_SOURCE_IP',
    'ANOMALY_INHERITED': 'INVESTIGATE_ANOMALY',
}

# Modèle XGBoost (chargé au démarrage)
_xgb_models  = {}   # un modèle par action (one-vs-rest)
_xgb_buffer_X = []
_xgb_buffer_y = []
_xgb_fitted   = False
MIN_FIT = 20        # captures minimum avant premier entraînement


def _extract_features(valise: dict) -> list:
    """Extrait le vecteur de features depuis la valise complète."""
    pred    = valise.get('dso3_prediction', {})
    analysis= valise.get('dso2_analysis', {})
    sec     = valise.get('dso6_security', {})
    capture = valise.get('dso1_capture', {}).get('features', {})

    risk_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    sec_map  = {'CLEAN': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    sev_map  = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2}

    return [
        risk_map.get(pred.get('risk_class', 'LOW'), 0),
        float(pred.get('risk_score', 0)),
        float(pred.get('score_seq', 0)),
        float(pred.get('score_tab', 0)),
        int(pred.get('is_anomaly', False)),
        sev_map.get(analysis.get('severity', 'OK'), 0),
        int(analysis.get('n_critical', 0)),
        int(analysis.get('n_warning', 0)),
        sec_map.get(sec.get('overall_severity', 'CLEAN'), 0),
        int(sec.get('n_events', 0)),
        float(capture.get('latency_ms', 0) or 0),
        float(capture.get('packet_loss_rate_pct', 0) or 0),
        float(capture.get('instability_score', 0) or 0),
        float(capture.get('buffer_occupancy_pct', 0) or 0),
    ]


def _pseudo_label(risk_class: str, sec_events: list) -> list:
    """Génère les labels d'actions appropriées pour l'entraînement en ligne."""
    actions = EXPERT_RULES.get(risk_class, ['NO_ACTION_REQUIRED']).copy()
    for ev in sec_events:
        at = ev.get('attack_type', '')
        if at in SECURITY_ACTIONS:
            a = SECURITY_ACTIONS[at]
            if a not in actions:
                actions.append(a)
    return actions


def _xgb_update(features: list, actions: list):
    """Entraîne (ou ré-entraîne) les modèles XGBoost en ligne."""
    global _xgb_fitted, _xgb_models
    if not _xgb_ok:
        return

    _xgb_buffer_X.append(features)
    # Encode actions en vecteur binaire
    y_vec = [1 if a in actions else 0 for a in ALL_ACTIONS]
    _xgb_buffer_y.append(y_vec)

    if len(_xgb_buffer_X) < MIN_FIT:
        return

    X = np.array(_xgb_buffer_X)
    Y = np.array(_xgb_buffer_y)

    for i, action in enumerate(ALL_ACTIONS):
        y_col = Y[:, i]
        if len(set(y_col)) < 2:
            continue
        try:
            m = xgb.XGBClassifier(
                n_estimators=50, max_depth=3, learning_rate=0.1,
                use_label_encoder=False, eval_metric='logloss',
                verbosity=0, random_state=42,
            )
            m.fit(X, y_col)
            _xgb_models[action] = m
        except Exception:
            pass
    _xgb_fitted = True


def _xgb_predict(features: list, risk_class: str, sec_events: list) -> list:
    """
    Prédit les actions optimales.
    XGBoost si entraîné, sinon règles expertes.
    """
    # Toujours appliquer les règles expertes en base
    expert = EXPERT_RULES.get(risk_class, ['NO_ACTION_REQUIRED']).copy()
    for ev in sec_events:
        at = ev.get('attack_type', '')
        if at in SECURITY_ACTIONS:
            a = SECURITY_ACTIONS[at]
            if a not in expert:
                expert.append(a)

    if not _xgb_fitted or not _xgb_ok:
        return expert

    # XGBoost ajoute des actions supplémentaires si probabilité > 0.55
    X = np.array([features])
    xgb_actions = list(expert)
    for action, model in _xgb_models.items():
        if action in xgb_actions:
            continue
        try:
            proba = model.predict_proba(X)[0][1]
            if proba > 0.55:
                xgb_actions.append(action)
        except Exception:
            pass

    return xgb_actions


def _build_decision(valise: dict) -> dict:
    features    = _extract_features(valise)
    pred        = valise.get('dso3_prediction', {})
    analysis    = valise.get('dso2_analysis', {})
    sec         = valise.get('dso6_security', {})
    risk_class  = pred.get('risk_class', 'LOW')
    risk_score  = pred.get('risk_score', 0)
    sec_events  = sec.get('events', [])
    sec_severity= sec.get('overall_severity', 'CLEAN')

    # Mise à jour du modèle XGBoost en ligne
    pseudo = _pseudo_label(risk_class, sec_events)
    _xgb_update(features, pseudo)

    # Prédiction actions
    action_names = _xgb_predict(features, risk_class, sec_events)

    # Construire liste actions structurées
    seen, actions = set(), []
    for name in action_names:
        if name not in seen:
            seen.add(name)
            actions.append({
                'action':   name,
                'priority': ACTION_PRIORITY.get(name, 4),
                'target':   ACTION_TARGETS.get(name, '?'),
                'source':   'XGBoost+Expert' if _xgb_fitted else 'Expert',
            })
    actions.sort(key=lambda x: x['priority'])

    overall_priority = min(a['priority'] for a in actions) if actions else 4
    decision_level   = {1:'IMMEDIATE', 2:'URGENT', 3:'ROUTINE', 4:'NONE'}.get(
        overall_priority, 'NONE')

    return {
        'decision_level':  decision_level,
        'risk_class':      risk_class,
        'risk_score':      risk_score,
        'security_level':  sec_severity,
        'actions':         actions,
        'n_actions':       len(actions),
        'model_source':    'XGBoost+Expert' if _xgb_fitted else 'Expert rules',
        'timestamp':       datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


def dso5_loop():
    log_agent(dso5_state, 'log', 'Agent5 demarre — XGBoost Optimization active')
    while dso5_state['running']:
        try:
            valise = dso5_queue.get(timeout=2)
        except queue.Empty:
            continue

        dso5_state['total'] += 1
        n = dso5_state['total']
        try:
            decision = _build_decision(valise)
            valise['meta']['dso_stage'] = 'Agent5'
            valise['dso5_decision'] = decision

            if decision['decision_level'] != 'NONE':
                dso5_state['actions_taken'] += decision['n_actions']

            safe_put(dso4_queue, valise)
            log_agent(dso5_state, 'log',
                      f'#{n} {decision["decision_level"]} | '
                      f'{decision["n_actions"]} actions | {decision["model_source"]}')
        except Exception as e:
            log_agent(dso5_state, 'log', f'#{n} erreur: {e}')


def start():
    global _xgb_buffer_X, _xgb_buffer_y, _xgb_fitted, _xgb_models
    _xgb_buffer_X = []
    _xgb_buffer_y = []
    _xgb_fitted   = False
    _xgb_models   = {}
    dso5_state.update({'running': True, 'total': 0, 'actions_taken': 0, 'log': []})
    t = threading.Thread(target=dso5_loop, name='Agent5-Optimize', daemon=True)
    t.start()
    return t


def stop():
    dso5_state['running'] = False
