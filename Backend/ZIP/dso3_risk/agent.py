"""
dso3_risk/agent.py
==================
DSO3 — Risk Prediction Agent
Pipeline : LSTM + XGBoost + horizons multi-temporels

Entrée  ← dso3_input_queue (raw_row, analysis depuis DSO2)
Sortie  → dso6_input_queue (valise DSO1+DSO2+DSO3)
"""

import os, csv, json, math, time, threading, queue
import numpy as np
from collections import deque
from datetime import datetime

from shared.config import (
    OUTPUT_DIR, SEQ_FEATURES, TAB_FEATURES, WINDOW_SIZE,
    MIN_WINDOW_PRED, HORIZONS_SEC, W_SEQ, W_TAB,
    CSV_PREDICTIONS, CSV_VALISE,
)
from shared.queues import dso3_input_queue, dso6_input_queue, log_agent, safe_put

# ── Imports optionnels avec fallback
try:
    from sklearn.preprocessing import MinMaxScaler
    from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
    _sklearn_ok = True
except ImportError:
    _sklearn_ok = False

try:
    import xgboost as xgb
    _xgb_ok = True
except ImportError:
    _xgb_ok = False

try:
    import torch
    import torch.nn as nn
    _torch_ok = True
except ImportError:
    _torch_ok = False

# ── État DSO3
dso3_state = {
    'running':       False,
    'total':         0,
    'anomalies':     0,
    'critical_pred': 0,
    'last_pred':     None,
    'last_valise':   None,
    'log':           [],
}


# ═══════════════════════════════════════════════════════════════
# MODÈLE SÉQUENTIEL (LSTM ou fallback EWMA)
# ═══════════════════════════════════════════════════════════════

if _torch_ok:
    class LSTMRiskModel(nn.Module):
        """LSTM avec attention pour prédiction série temporelle réseau."""
        def __init__(self, input_size, hidden_size=64, num_layers=2, dropout=0.2):
            super().__init__()
            self.lstm = nn.LSTM(
                input_size=input_size, hidden_size=hidden_size,
                num_layers=num_layers, batch_first=True, bidirectional=False,
                dropout=dropout if num_layers > 1 else 0.0,
            )
            self.attention = nn.Sequential(
                nn.Linear(hidden_size, 32), nn.Tanh(),
                nn.Linear(32, 1), nn.Softmax(dim=1),
            )
            self.head = nn.Sequential(
                nn.Linear(hidden_size, 32), nn.ReLU(),
                nn.Dropout(dropout), nn.Linear(32, 1), nn.Sigmoid(),
            )

        def forward(self, x):
            out, _  = self.lstm(x)
            attn_w  = self.attention(out)
            ctx     = (out * attn_w).sum(1)
            return self.head(ctx).squeeze(-1)

    def build_seq_model(input_size):
        return LSTMRiskModel(input_size=input_size)

else:
    class StatSeqModel:
        """Fallback EWMA + tendance linéaire quand PyTorch absent."""
        def __init__(self, alpha=0.3):
            self.alpha = alpha

        def predict_score(self, seq_array):
            if len(seq_array) < 2:
                return 0.3
            lat   = seq_array[:, 0]
            rsk   = seq_array[:, 4] if seq_array.shape[1] > 4 else lat
            ewma  = lat[0]
            for v in lat[1:]:
                ewma = self.alpha * v + (1 - self.alpha) * ewma
            n     = len(lat)
            trend = np.polyfit(np.arange(n), lat, 1)[0]
            score = np.clip(ewma * 0.6 + rsk[-1] * 0.3 + np.clip(trend * 5, 0, 1) * 0.1, 0, 1)
            return float(score)

    def build_seq_model(input_size):
        return StatSeqModel()


# ═══════════════════════════════════════════════════════════════
# CLASSIFIEUR TABULAIRE (XGBoost ou GradientBoosting fallback)
# ═══════════════════════════════════════════════════════════════

class TabRiskClassifier:
    """XGBoost si disponible, sinon GradientBoosting sklearn."""
    SEV_MAP = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2}

    def __init__(self):
        self.scaler   = MinMaxScaler() if _sklearn_ok else None
        self.fitted   = False
        self.buffer_X = []
        self.buffer_y = []
        self.MIN_FIT  = 30

        if _xgb_ok:
            self.model   = xgb.XGBClassifier(
                n_estimators=100, max_depth=4, learning_rate=0.1,
                subsample=0.8, colsample_bytree=0.8,
                use_label_encoder=False, eval_metric='logloss', verbosity=0,
            )
            self.backend = 'xgboost'
        elif _sklearn_ok:
            self.model   = GradientBoostingClassifier(
                n_estimators=80, max_depth=3, learning_rate=0.1,
                subsample=0.8, warm_start=True,
            )
            self.backend = 'sklearn_gb'
        else:
            self.model   = None
            self.backend = 'heuristic'

    def _extract(self, row, analysis):
        vec = {}
        for f in TAB_FEATURES:
            if f == 'severity_encoded':
                vec[f] = self.SEV_MAP.get(analysis.get('severity', 'OK'), 0)
            elif f == 'n_critical':
                vec[f] = analysis.get('n_critical', 0)
            elif f == 'n_warning':
                vec[f] = analysis.get('n_warning', 0)
            elif f.startswith('delta_'):
                vec[f] = row.get(f, 0.0)
            else:
                vec[f] = float(row.get(f, 0) or 0)
        return [vec[f] for f in TAB_FEATURES]

    def _pseudo_label(self, analysis):
        sev = analysis.get('severity', 'OK')
        nc  = analysis.get('n_critical', 0)
        return 1 if sev == 'CRITICAL' or nc >= 2 else 0

    def update(self, row, analysis):
        x = self._extract(row, analysis)
        y = self._pseudo_label(analysis)
        self.buffer_X.append(x)
        self.buffer_y.append(y)
        if len(self.buffer_X) >= self.MIN_FIT and self.model is not None:
            X = np.array(self.buffer_X)
            if self.scaler and not self.fitted:
                X = self.scaler.fit_transform(X)
            elif self.scaler:
                X = self.scaler.transform(X)
            y_arr = np.array(self.buffer_y)
            if len(set(y_arr)) >= 2:
                self.model.fit(X, y_arr)
                self.fitted = True
                # Sauvegarde pour SHAP
                try:
                    import joblib as _jl, os as _os
                    from shared.config import OUTPUT_DIR as _OD
                    _jl.dump(self.model, _os.path.join(_OD, "dso3_tab_model.pkl"))
                except Exception:
                    pass

    def predict_proba(self, row, analysis):
        if not self.fitted or self.model is None:
            sev  = analysis.get('severity', 'OK')
            nc   = analysis.get('n_critical', 0)
            nw   = analysis.get('n_warning', 0)
            base = {'OK': 0.1, 'WARNING': 0.4, 'CRITICAL': 0.75}.get(sev, 0.1)
            return min(1.0, base + nc * 0.08 + nw * 0.03)
        x = np.array([self._extract(row, analysis)])
        if self.scaler:
            x = self.scaler.transform(x)
        proba = self.model.predict_proba(x)[0]
        return float(proba[1]) if len(proba) > 1 else float(proba[0])


# ═══════════════════════════════════════════════════════════════
# FEATURE ENGINEER
# ═══════════════════════════════════════════════════════════════

class FeatureEngineer:
    """Calcule deltas, rolling moyennes et tableau séquentiel pour le LSTM."""
    def __init__(self, window_size=WINDOW_SIZE):
        self.window     = deque(maxlen=window_size)
        self.seq_scaler = MinMaxScaler() if _sklearn_ok else None
        self.seq_fitted = False

    def push(self, row, analysis):
        enriched = dict(row)
        sev_map  = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2}
        enriched['severity_encoded'] = sev_map.get(analysis.get('severity', 'OK'), 0)
        enriched['n_critical']       = analysis.get('n_critical', 0)
        enriched['n_warning']        = analysis.get('n_warning',  0)

        if self.window:
            prev = self.window[-1]
            for feat in ['latency_ms', 'jitter_ms', 'packet_loss_rate_pct',
                         'throughput_mbps', 'risk_score']:
                prev_val = float(prev.get(feat, 0) or 0)
                curr_val = float(enriched.get(feat, 0) or 0)
                enriched[f'delta_{feat}'] = round(curr_val - prev_val, 4)
        else:
            for feat in ['latency_ms', 'jitter_ms', 'packet_loss_rate_pct',
                         'throughput_mbps', 'risk_score']:
                enriched[f'delta_{feat}'] = 0.0

        if len(self.window) >= 3:
            win_list = list(self.window)
            for feat in ['latency_ms', 'jitter_ms', 'packet_loss_rate_pct']:
                vals = [float(w.get(feat, 0) or 0) for w in win_list[-5:]]
                enriched[f'rolling_mean_{feat}'] = round(np.mean(vals), 4)
                enriched[f'rolling_std_{feat}']  = round(np.std(vals), 4)

        self.window.append(enriched)
        return enriched

    def get_seq_array(self):
        if len(self.window) < MIN_WINDOW_PRED:
            return None
        raw = np.array([[float(w.get(f, 0) or 0) for f in SEQ_FEATURES] for w in self.window])
        if self.seq_scaler:
            if not self.seq_fitted and len(raw) >= 5:
                self.seq_scaler.fit(raw)
                self.seq_fitted = True
            if self.seq_fitted:
                raw = self.seq_scaler.transform(raw)
        return raw

    @property
    def n_seq_features(self):
        return len(SEQ_FEATURES)


# ═══════════════════════════════════════════════════════════════
# ANOMALY DETECTOR (Isolation Forest non supervisé)
# ═══════════════════════════════════════════════════════════════

class AnomalyDetector:
    FEATURES = ['latency_ms','jitter_ms','packet_loss_rate_pct',
                'throughput_mbps','hops_mean','rsrp_estimated',
                'instability_score','risk_score']
    MIN_FIT  = 50

    def __init__(self):
        self.buffer = []
        self.fitted = False
        self.model  = IsolationForest(n_estimators=100, contamination=0.05,
                                      random_state=42, n_jobs=-1) if _sklearn_ok else None

    def _vec(self, row):
        return [float(row.get(f, 0) or 0) for f in self.FEATURES]

    def update(self, row):
        self.buffer.append(self._vec(row))
        if len(self.buffer) >= self.MIN_FIT and self.model:
            self.model.fit(np.array(self.buffer))
            self.fitted = True

    def score(self, row):
        if not self.fitted or not self.model:
            return False, 0.0
        x     = np.array([self._vec(row)])
        pred  = self.model.predict(x)[0]
        score = self.model.score_samples(x)[0]
        return bool(pred == -1), round(float(score), 4)


# ═══════════════════════════════════════════════════════════════
# RISK SCORER
# ═══════════════════════════════════════════════════════════════

def _risk_class(score_0_100):
    if score_0_100 >= 80: return 'CRITICAL'
    if score_0_100 >= 60: return 'HIGH'
    if score_0_100 >= 30: return 'MEDIUM'
    return 'LOW'

def _horizon_decay(base_score, horizon_sec, instability):
    decay = math.exp(-horizon_sec / 120)
    noise = instability * 0.1 * (horizon_sec / 20)
    proj  = base_score * decay + (1 - decay) * 50
    proj  = np.clip(proj + np.random.normal(0, noise), 0, 100)
    return round(float(proj), 1)


class RiskScorer:
    def __init__(self, seq_model, tab_clf, anomaly_det):
        self.seq_model   = seq_model
        self.tab_clf     = tab_clf
        self.anomaly_det = anomaly_det

    def compute(self, row, analysis, seq_array):
        instab = float(row.get('instability_score', 0) or 0)

        if seq_array is not None:
            if _torch_ok and isinstance(self.seq_model, LSTMRiskModel):
                self.seq_model.eval()
                with torch.no_grad():
                    t     = torch.tensor(seq_array, dtype=torch.float32).unsqueeze(0)
                    s_seq = float(self.seq_model(t).item())
            else:
                s_seq = self.seq_model.predict_score(seq_array)
        else:
            s_seq = 0.3

        s_tab           = self.tab_clf.predict_proba(row, analysis)
        is_anom, _      = self.anomaly_det.score(row)
        anom_boost      = 0.1 if is_anom else 0.0

        raw        = W_SEQ * s_seq + W_TAB * s_tab + anom_boost
        base_score = round(np.clip(raw * 100, 0, 100), 1)
        risk_class = _risk_class(base_score)

        horizons = {
            f'risk_{h}s': {
                'score': _horizon_decay(base_score, h, instab),
                'class': _risk_class(_horizon_decay(base_score, h, instab)),
            }
            for h in HORIZONS_SEC
        }

        return {
            'risk_score':    base_score,
            'risk_class':    risk_class,
            'score_seq':     round(s_seq * 100, 1),
            'score_tab':     round(s_tab * 100, 1),
            'is_anomaly':    is_anom,
            'horizons':      horizons,
            'instability':   round(instab, 4),
        }


# ═══════════════════════════════════════════════════════════════
# CONSTRUCTEUR DE VALISE
# ═══════════════════════════════════════════════════════════════

def build_valise(row, analysis, prediction, capture_n):
    """Construit le payload complet (valise) transmis aux agents suivants."""
    ts = row.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    return {
        'meta': {
            'timestamp':    ts,
            'capture_n':    capture_n,
            'pipeline_ver': 'v1.0',
            'dso_stage':    'DSO3',
        },
        'dso1_capture': {
            'features':   dict(row),
            'n_features': len(row),
        },
        'dso2_analysis': {
            'severity':     analysis.get('severity', '—'),
            'rsrp_class':   analysis.get('rsrp_class', '—'),
            'n_critical':   analysis.get('n_critical', 0),
            'n_warning':    analysis.get('n_warning', 0),
            'has_critical': analysis.get('has_critical', False),
            'alerts':       analysis.get('alerts', []),
        },
        'dso3_prediction': {
            'risk_score':  prediction['risk_score'],
            'risk_class':  prediction['risk_class'],
            'score_seq':   prediction['score_seq'],
            'score_tab':   prediction['score_tab'],
            'is_anomaly':  prediction['is_anomaly'],
            'horizons':    prediction['horizons'],
            'instability': prediction['instability'],
        },
    }


# ═══════════════════════════════════════════════════════════════
# BOUCLE PRINCIPALE DSO3
# ═══════════════════════════════════════════════════════════════

_feat_eng    = None
_tab_clf     = None
_anomaly_det = None
_seq_model   = None
_risk_scorer = None


def dso3_loop():
    global _seq_model, _risk_scorer
    log_agent(dso3_state, 'log', 'DSO3 démarré — prédiction des risques active')
    while dso3_state['running']:
        try:
            payload = dso3_input_queue.get(timeout=2)
        except queue.Empty:
            continue

        row, analysis = payload if isinstance(payload, tuple) else (payload, {
            'severity': 'OK', 'n_critical': 0, 'n_warning': 0,
            'has_critical': False, 'alerts': [], 'rsrp_class': '?',
        })

        dso3_state['total'] += 1
        n = dso3_state['total']

        try:
            enriched  = _feat_eng.push(row, analysis)
            seq_array = _feat_eng.get_seq_array()

            _tab_clf.update(enriched, analysis)
            _anomaly_det.update(enriched)

            if _risk_scorer is None:
                _seq_model  = build_seq_model(_feat_eng.n_seq_features)
                _risk_scorer = RiskScorer(_seq_model, _tab_clf, _anomaly_det)

            prediction = _risk_scorer.compute(enriched, analysis, seq_array)
            dso3_state['last_pred'] = prediction

            if prediction['risk_class'] in ('HIGH', 'CRITICAL'):
                dso3_state['critical_pred'] += 1
            if prediction['is_anomaly']:
                dso3_state['anomalies'] += 1

            valise = build_valise(enriched, analysis, prediction, n)
            dso3_state['last_valise'] = valise

            # Propager à DSO6
            safe_put(dso6_input_queue, valise)

            log_agent(dso3_state, 'log',
                      f'#{n} — {prediction["risk_class"]} {prediction["risk_score"]}/100')

        except Exception as e:
            log_agent(dso3_state, 'log', f'#{n} erreur: {e}')

    log_agent(dso3_state, 'log',
              f'arrêté — {dso3_state["total"]} prédictions · '
              f'{dso3_state["anomalies"]} anomalies')


def start():
    global _feat_eng, _tab_clf, _anomaly_det, _seq_model, _risk_scorer
    _feat_eng    = FeatureEngineer(window_size=WINDOW_SIZE)
    _tab_clf     = TabRiskClassifier()
    _anomaly_det = AnomalyDetector()
    _seq_model   = None
    _risk_scorer = None
    dso3_state.update({
        'running': True, 'total': 0, 'anomalies': 0,
        'critical_pred': 0, 'last_pred': None, 'last_valise': None, 'log': [],
    })
    t = threading.Thread(target=dso3_loop, name='DSO3-Risk', daemon=True)
    t.start()
    return t


def stop():
    dso3_state['running'] = False
