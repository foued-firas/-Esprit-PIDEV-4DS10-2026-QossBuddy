"""
dso4_reporting/agent.py
=======================
Agent 6 — XAI & Reporting Agent
Explainability : SHAP sur les prédictions + rapport PDF automatique en fin de pipeline

Entrée  <- dso4_queue (valise complète)
Sortie  -> Dashboard terminal + CSV + JSONL + PDF (généré automatiquement)
"""

import os, csv, json, sys, queue, threading, warnings
import numpy as np
warnings.filterwarnings('ignore')

from datetime import datetime
from shared.config import OUTPUT_DIR
from shared.queues import dso4_queue, log_agent

# SHAP avec fallback
try:
    import shap
    _shap_ok = True
except ImportError:
    _shap_ok = False

try:
    import joblib
    _joblib_ok = True
except ImportError:
    _joblib_ok = False

# Fichiers de sortie
CSV_REPORT  = os.path.join(OUTPUT_DIR, 'reports.csv')
JSON_REPORT = os.path.join(OUTPUT_DIR, 'reports.jsonl')
PDF_REPORT  = os.path.join(OUTPUT_DIR, 'rapport_inms_qos.pdf')

# Etat
dso4_state = {
    'running':      False,
    'total':        0,
    'last_report':  None,
    'last_valise':  None,
    'shap_values':  None,
    'log':          [],
}

RISK_LABELS = {
    'CRITICAL': '🔴 CRITIQUE  — Intervention immediate requise',
    'HIGH':     '🟠 ELEVE     — Surveillance renforcee',
    'MEDIUM':   '🟡 MODERE    — Situation a surveiller',
    'LOW':      '🟢 FAIBLE    — Reseau stable',
}
DECISION_LABELS = {
    'IMMEDIATE': '🔴 ACTION IMMEDIATE',
    'URGENT':    '🟠 ACTION URGENTE',
    'ROUTINE':   '🟡 SURVEILLANCE ROUTINE',
    'NONE':      '🟢 AUCUNE ACTION',
}

# Noms lisibles des features SHAP
FEATURE_NAMES = [
    'latence_ms', 'jitter_ms', 'pertes_paquets_%', 'debit_mbps',
    'mos_proxy', 'rsrp_estime', 'sinr_estime', 'cqi_estime',
    'score_instabilite', 'score_risque', 'occupation_buffer_%',
    'utilisation_bande_%', 'hops_moyen', 'pic_latence',
    'echec_handover', 'zone_couverture_faible', 'perf_degradee',
    'severite_cisco', 'alertes_critiques', 'alertes_warning',
]

# Noms lisibles des actions pour le rapport
ACTION_LABELS = {
    'REROUTE_TRAFFIC':       'Rediriger le trafic',
    'BLOCK_SUSPICIOUS_IPS':  'Bloquer les IPs suspectes',
    'ALERT_NOC':             "Alerter l'equipe technique",
    'THROTTLE_BANDWIDTH':    'Limiter la bande passante',
    'ADJUST_QOS_WEIGHTS':    'Ajuster les priorites reseau',
    'MONITOR_CLOSELY':       'Surveiller de pres',
    'PREPARE_FAILOVER':      'Preparer le reseau de secours',
    'LOG_AND_WATCH':         "Enregistrer et surveiller",
    'SOFT_REBALANCE':        'Reequilibrer la charge',
    'NO_ACTION_REQUIRED':    'Aucune action requise',
    'FIREWALL_BLOCK_SCANNER':'Bloquer le scanner de ports',
    'ENABLE_SYN_COOKIES':    'Activer protection SYN Flood',
    'ACTIVATE_SCRUBBING':    'Activer filtre anti-DDoS',
    'BLOCK_SOURCE_IP':       "Bloquer l'IP source",
    'INVESTIGATE_ANOMALY':   'Investiguer anomalie reseau',
}


# ════════════════════════════════════════════════════════════════
# SHAP — Explainability
# ════════════════════════════════════════════════════════════════

def _compute_shap(valise: dict) -> dict:
    """
    Calcule les valeurs SHAP sur le modèle de prédiction (DSO3 XGBoost).
    Retourne les features les plus influentes sur la prédiction de risque.
    """
    if not _shap_ok or not _joblib_ok:
        return {}

    try:
        # Charger le classificateur tabulaire DSO3 (XGBoost)
        xgb_path = os.path.join(OUTPUT_DIR, 'dso3_tab_model.pkl')
        if not os.path.exists(xgb_path):
            return {}

        model   = joblib.load(xgb_path)
        capture = valise.get('dso1_capture', {}).get('features', {})
        analysis= valise.get('dso2_analysis', {})
        sev_map = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2}

        vec = [
            float(capture.get('latency_ms', 0) or 0),
            float(capture.get('jitter_ms', 0) or 0),
            float(capture.get('packet_loss_rate_pct', 0) or 0),
            float(capture.get('throughput_mbps', 0) or 0),
            float(capture.get('mos_proxy', 0) or 0),
            float(capture.get('rsrp_estimated', 0) or 0),
            float(capture.get('sinr_estimated', 0) or 0),
            float(capture.get('cqi_estimated', 0) or 0),
            float(capture.get('instability_score', 0) or 0),
            float(capture.get('risk_score', 0) or 0),
            float(capture.get('buffer_occupancy_pct', 0) or 0),
            float(capture.get('bandwidth_utilization_pct', 0) or 0),
            float(capture.get('hops_mean', 0) or 0),
            float(capture.get('spike', 0) or 0),
            float(capture.get('ho_failure_proxy', 0) or 0),
            float(capture.get('coverage_hole_proxy', 0) or 0),
            float(capture.get('performance_degraded', 0) or 0),
            float(sev_map.get(analysis.get('severity', 'OK'), 0)),
            float(analysis.get('n_critical', 0)),
            float(analysis.get('n_warning', 0)),
        ]

        X        = np.array([vec])
        explainer = shap.TreeExplainer(model)
        sv        = explainer.shap_values(X)

        # Prendre les valeurs SHAP pour la classe "risque élevé" (index 1)
        if isinstance(sv, list):
            vals = sv[1][0] if len(sv) > 1 else sv[0][0]
        else:
            vals = sv[0]

        names = FEATURE_NAMES[:len(vals)]
        pairs = sorted(zip(names, vals.tolist()), key=lambda x: abs(x[1]), reverse=True)

        return {
            'top_features': [
                {'feature': n, 'shap_value': round(v, 4),
                 'direction': 'augmente le risque' if v > 0 else 'reduit le risque'}
                for n, v in pairs[:5]
            ],
            'base_value': round(float(explainer.expected_value
                                      if not isinstance(explainer.expected_value, list)
                                      else explainer.expected_value[1]), 4),
        }
    except Exception as e:
        return {'error': str(e)}


# ════════════════════════════════════════════════════════════════
# RAPPORT
# ════════════════════════════════════════════════════════════════

def build_executive_summary(valise: dict) -> dict:
    meta    = valise.get('meta', {})
    dso2    = valise.get('dso2_analysis', {})
    dso3    = valise.get('dso3_prediction', {})
    dso6    = valise.get('dso6_security', {})
    dso5    = valise.get('dso5_decision', {})
    capture = valise.get('dso1_capture', {}).get('features', {})

    risk_class   = dso3.get('risk_class', 'LOW')
    risk_score   = dso3.get('risk_score', 0)
    decision_lvl = dso5.get('decision_level', 'NONE')

    network_kpis = {
        'latency_ms':        capture.get('latency_ms', '—'),
        'packet_loss_pct':   capture.get('packet_loss_rate_pct', '—'),
        'throughput_mbps':   capture.get('throughput_mbps', '—'),
        'mos_proxy':         capture.get('mos_proxy', '—'),
        'rsrp_category':     capture.get('rsrp_category', '—'),
        'instability_score': capture.get('instability_score', '—'),
    }

    horizons = {h: dso3.get('horizons', {}).get(f'risk_{h}s', {}) for h in [20, 60, 300]}
    shap_exp = _compute_shap(valise)
    actions  = dso5.get('actions', [])

    return {
        'report_id':         f'RPT-{datetime.now().strftime("%Y%m%d%H%M%S")}',
        'timestamp':         meta.get('timestamp', '—'),
        'capture_n':         meta.get('capture_n', 0),
        'risk_level':        RISK_LABELS.get(risk_class, risk_class),
        'risk_level_raw':    risk_class,
        'risk_score':        risk_score,
        'decision':          DECISION_LABELS.get(decision_lvl, decision_lvl),
        'decision_raw':      decision_lvl,
        'n_critical_alerts': dso2.get('n_critical', 0),
        'n_warnings':        dso2.get('n_warning', 0),
        'rf_class':          dso2.get('rf_class', '—'),
        'rf_confidence':     dso2.get('rf_confidence', 0),
        'security_status':   dso6.get('overall_severity', 'CLEAN'),
        'n_security_events': dso6.get('n_events', 0),
        'attack_types':      dso6.get('attack_types', []),
        'network_kpis':      network_kpis,
        'risk_horizons':     horizons,
        'shap_explanation':  shap_exp,
        'recommended_actions': [
            {'action':   a['action'],
             'label':    ACTION_LABELS.get(a['action'], a['action']),
             'target':   a.get('target', '?'),
             'priority': a['priority'],
             'source':   a.get('source', '?')}
            for a in actions[:6]
        ],
    }


def _save_report(report: dict):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    flat = {
        'report_id':       report['report_id'],
        'timestamp':       report['timestamp'],
        'capture_n':       report['capture_n'],
        'risk_score':      report['risk_score'],
        'risk_level':      report['risk_level'],
        'decision':        report['decision'],
        'rf_class':        report.get('rf_class', '—'),
        'rf_confidence':   report.get('rf_confidence', 0),
        'n_critical':      report['n_critical_alerts'],
        'n_warnings':      report['n_warnings'],
        'security_status': report['security_status'],
        'n_sec_events':    report['n_security_events'],
        'latency_ms':      report['network_kpis'].get('latency_ms', ''),
        'packet_loss_pct': report['network_kpis'].get('packet_loss_pct', ''),
        'throughput_mbps': report['network_kpis'].get('throughput_mbps', ''),
        'mos_proxy':       report['network_kpis'].get('mos_proxy', ''),
    }
    exists = os.path.isfile(CSV_REPORT)
    with open(CSV_REPORT, 'a', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=flat.keys(), delimiter=';')
        if not exists:
            w.writeheader()
        w.writerow(flat)

    with open(JSON_REPORT, 'a', encoding='utf-8') as f:
        f.write(json.dumps(report, ensure_ascii=False, default=str) + '\n')


# ════════════════════════════════════════════════════════════════
# PDF — généré automatiquement en fin de pipeline
# ════════════════════════════════════════════════════════════════

def generate_pdf():
    """Génère le rapport PDF depuis reports.csv + reports.jsonl."""
    import csv as csv_mod

    if not os.path.exists(CSV_REPORT):
        return

    rows = []
    with open(CSV_REPORT, encoding='utf-8') as f:
        rows = list(csv_mod.DictReader(f, delimiter=';'))
    if not rows:
        return

    last_full = {}
    if os.path.exists(JSON_REPORT):
        with open(JSON_REPORT, encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            try:
                last_full = json.loads(lines[-1])
            except Exception:
                pass

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        print('reportlab absent — pip install "reportlab==3.6.13"')
        return

    C_DARK   = colors.HexColor('#1e2d40')
    C_TEAL   = colors.HexColor('#0F6E56')
    C_GRAY   = colors.HexColor('#f4f6f8')
    C_BORDER = colors.HexColor('#dde3ea')
    C_RED    = colors.HexColor('#c0392b')
    C_ORANGE = colors.HexColor('#e67e22')
    C_YELLOW = colors.HexColor('#d4ac0d')
    C_GREEN  = colors.HexColor('#1e8449')
    C_PURPLE = colors.HexColor('#7F77DD')
    C_TEXT   = colors.HexColor('#2c3e50')
    C_MUTED  = colors.HexColor('#6c7a89')
    C_WHITE  = colors.white

    def St(name, **kw):
        return ParagraphStyle(name, **kw)

    S_TITLE = St('TI', fontName='Helvetica-Bold', fontSize=20, textColor=C_DARK,
                 spaceAfter=2, leading=24)
    S_SUB   = St('SU', fontName='Helvetica', fontSize=10, textColor=C_MUTED,
                 spaceAfter=10, leading=14)
    S_H2    = St('H2', fontName='Helvetica-Bold', fontSize=12, textColor=C_DARK,
                 spaceBefore=16, spaceAfter=6, leading=16)
    S_BODY  = St('BO', fontName='Helvetica', fontSize=10, textColor=C_TEXT,
                 leading=15, spaceAfter=5)
    S_SMALL = St('SM', fontName='Helvetica', fontSize=8, textColor=C_MUTED, leading=12)
    S_KPI   = St('KP', fontName='Helvetica-Bold', fontSize=18, textColor=C_WHITE,
                 alignment=TA_CENTER, leading=22)
    S_KPI_L = St('KL', fontName='Helvetica', fontSize=8, textColor=C_WHITE,
                 alignment=TA_CENTER, leading=10)

    # Statistiques
    n_total = len(rows)
    risk_scores, latencies, losses = [], [], []
    rc = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
    n_critical = 0

    for r in rows:
        try: risk_scores.append(float(r.get('risk_score', 0)))
        except: pass
        try: latencies.append(float(r.get('latency_ms', 0)))
        except: pass
        try: losses.append(float(r.get('packet_loss_pct', 0)))
        except: pass
        lvl = r.get('risk_level', '')
        if 'CRITIQUE' in lvl or 'CRITICAL' in lvl: n_critical += 1; rc['CRITICAL'] += 1
        elif 'LEVE' in lvl.upper() or 'HIGH' in lvl: rc['HIGH'] += 1
        elif 'DERE' in lvl.upper() or 'MEDIUM' in lvl: rc['MEDIUM'] += 1
        else: rc['LOW'] += 1

    avg_risk = round(sum(risk_scores)/len(risk_scores), 1) if risk_scores else 0
    avg_lat  = round(sum(latencies)/len(latencies), 1) if latencies else 0
    avg_loss = round(sum(losses)/len(losses), 2) if losses else 0

    if avg_risk >= 80:   risk_color = C_RED;    risk_label = 'Critique'
    elif avg_risk >= 60: risk_color = C_ORANGE; risk_label = 'Eleve'
    elif avg_risk >= 30: risk_color = C_YELLOW; risk_label = 'Modere'
    else:                risk_color = C_GREEN;  risk_label = 'Faible'

    ts_first = rows[0].get('timestamp','—')
    ts_last  = rows[-1].get('timestamp','—')
    net_name = (last_full.get('dso1_capture',{})
                .get('features',{}).get('network_name','Non disponible'))
    rf_class = rows[-1].get('rf_class','—') if rows else '—'
    rf_conf  = rows[-1].get('rf_confidence','—') if rows else '—'

    doc = SimpleDocTemplate(
        PDF_REPORT, pagesize=A4,
        leftMargin=2.2*cm, rightMargin=2.2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    story = []
    W = 16.6*cm

    # En-tete
    story.append(Paragraph('Rapport de surveillance reseau — INMS QoS', S_TITLE))
    story.append(Paragraph(
        f'Reseau : {net_name}   |   Du {ts_first}  au  {ts_last}   |   '
        f'Genere le {datetime.now().strftime("%d/%m/%Y a %H:%M")}', S_SUB))
    story.append(HRFlowable(width='100%', thickness=2, color=C_TEAL, spaceAfter=14))

    # Cartes KPI
    kpi_data = [[
        [Paragraph(str(avg_risk), S_KPI), Paragraph('Score de risque moyen', S_KPI_L)],
        [Paragraph(str(n_total),  S_KPI), Paragraph('Mesures effectuees',    S_KPI_L)],
        [Paragraph(str(n_critical),S_KPI),Paragraph('Alertes graves',        S_KPI_L)],
        [Paragraph(f'{avg_lat}ms',S_KPI), Paragraph('Temps de reponse moy.', S_KPI_L)],
    ]]
    kpi_t = Table(kpi_data, colWidths=[W/4]*4, rowHeights=[1.8*cm])
    kpi_t.setStyle(TableStyle([
        ('BACKGROUND',   (0,0),(0,0), risk_color),
        ('BACKGROUND',   (1,0),(1,0), C_TEAL),
        ('BACKGROUND',   (2,0),(2,0), C_RED if n_critical > 0 else C_GREEN),
        ('BACKGROUND',   (3,0),(3,0), C_TEAL),
        ('VALIGN',       (0,0),(-1,-1), 'MIDDLE'),
        ('ALIGN',        (0,0),(-1,-1), 'CENTER'),
        ('TOPPADDING',   (0,0),(-1,-1), 10),
        ('BOTTOMPADDING',(0,0),(-1,-1), 10),
        ('INNERGRID',    (0,0),(-1,-1), 2, C_WHITE),
        ('BOX',          (0,0),(-1,-1), 0, C_WHITE),
    ]))
    story.append(kpi_t)
    story.append(Spacer(1, 14))

    # Modeles utilises
    story.append(Paragraph('Modeles machine learning utilises', S_H2))
    ml_data = [
        ['Agent', 'Modele(s)', 'Type', 'Role'],
        ['Capture',       'Autoencoder PyTorch\n+ IF + EE + SVM', 'Deep Learning\n+ Ensemble ML', 'Detecte les anomalies reseau'],
        ['Classification','Seuils Cisco/ITU-T\n+ Random Forest',  'Standards + ML supervise',    'Classe l etat du reseau'],
        ['Prediction',    'LSTM + XGBoost\n+ Isolation Forest',   'Deep Learning\n+ ML hybride', 'Predit le risque a +20s/1min/5min'],
        ['Securite',      'Isolation Forest\n+ Heuristiques',     'ML non supervise',             'Detecte les attaques reseau'],
        ['Optimisation',  'XGBoost multi-label\n+ Regles expertes','ML supervise',                'Recommande les actions optimales'],
        ['XAI & Rapport', 'SHAP TreeExplainer',                   'Explainable AI',              'Explique les predictions'],
    ]
    ml_t = Table(ml_data, colWidths=[2.8*cm, 4*cm, 3.5*cm, 6.3*cm])
    ml_t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), C_DARK),
        ('TEXTCOLOR',     (0,0),(-1,0), C_WHITE),
        ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
        ('FONTNAME',      (0,1),(-1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,0),(-1,-1), 8),
        ('ALIGN',         (0,0),(-1,-1), 'LEFT'),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_WHITE, C_GRAY]),
        ('TOPPADDING',    (0,0),(-1,-1), 5),
        ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ('LEFTPADDING',   (0,0),(-1,-1), 6),
        ('RIGHTPADDING',  (0,0),(-1,-1), 6),
        ('BOX',           (0,0),(-1,-1), 0.5, C_BORDER),
        ('LINEBELOW',     (0,0),(-1,-2), 0.3, C_BORDER),
    ]))
    story.append(ml_t)
    story.append(Spacer(1, 12))

    # Classification RF
    story.append(Paragraph('Resultat de la classification reseau (Random Forest)', S_H2))
    story.append(Paragraph(
        f'Le Random Forest a classe le reseau comme <b>{rf_class}</b> '
        f'avec une confiance de <b>{float(rf_conf)*100:.0f}%</b> sur la derniere mesure. '
        f'Cette classification combine les seuils Cisco/ITU-T/3GPP et les patterns appris '
        f'sur {n_total} mesures historiques.', S_BODY))
    story.append(Spacer(1, 8))

    # SHAP
    shap_exp = last_full.get('shap_explanation', {})
    top_feat = shap_exp.get('top_features', [])
    if top_feat:
        story.append(Paragraph('Explication XAI — facteurs influençant la prediction (SHAP)', S_H2))
        story.append(Paragraph(
            'Les valeurs SHAP indiquent quelles metriques ont le plus influence '
            'la prediction de risque. Une valeur positive augmente le score de risque, '
            'une valeur negative le reduit.', S_BODY))
        shap_data = [['Feature reseau', 'Impact SHAP', 'Direction']]
        for f in top_feat:
            direction_color = C_RED if f['direction'] == 'augmente le risque' else C_GREEN
            shap_data.append([
                f['feature'],
                f'{f["shap_value"]:+.4f}',
                f['direction'],
            ])
        shap_t = Table(shap_data, colWidths=[6*cm, 3*cm, 7.6*cm])
        shap_t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0), C_PURPLE),
            ('TEXTCOLOR',     (0,0),(-1,0), C_WHITE),
            ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTNAME',      (0,1),(-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0),(-1,-1), 9),
            ('ALIGN',         (1,0),(1,-1), 'CENTER'),
            ('ALIGN',         (0,0),(0,-1), 'LEFT'),
            ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_WHITE, C_GRAY]),
            ('TOPPADDING',    (0,0),(-1,-1), 6),
            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
            ('LEFTPADDING',   (0,0),(-1,-1), 8),
            ('RIGHTPADDING',  (0,0),(-1,-1), 8),
            ('BOX',           (0,0),(-1,-1), 0.5, C_BORDER),
            ('LINEBELOW',     (0,0),(-1,-2), 0.3, C_BORDER),
        ]))
        story.append(shap_t)
        story.append(Spacer(1, 12))

    # Repartition risques
    story.append(Paragraph('Repartition des niveaux de risque', S_H2))
    rl_data = [['Niveau', 'Mesures', 'Part', 'Signification']]
    for lbl, cnt in [('Critique',rc['CRITICAL']),('Eleve',rc['HIGH']),
                      ('Modere',rc['MEDIUM']),('Faible',rc['LOW'])]:
        pct = f'{round(cnt/n_total*100,0):.0f}%' if n_total > 0 else '0%'
        sig = {'Critique':'Reseau en difficulte grave','Eleve':'Ralentissements importants',
               'Modere':'Fonctionnement acceptable','Faible':'Reseau optimal'}.get(lbl,'')
        rl_data.append([lbl, str(cnt), pct, sig])
    rl_t = Table(rl_data, colWidths=[3*cm, 2.5*cm, 2.5*cm, 8.6*cm])
    rl_t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), C_DARK),
        ('TEXTCOLOR',     (0,0),(-1,0), C_WHITE),
        ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
        ('FONTNAME',      (0,1),(-1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,0),(-1,-1), 9),
        ('ALIGN',         (1,0),(2,-1), 'CENTER'),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_WHITE, C_GRAY]),
        ('TOPPADDING',    (0,0),(-1,-1), 6),
        ('BOTTOMPADDING', (0,0),(-1,-1), 6),
        ('LEFTPADDING',   (0,0),(-1,-1), 8),
        ('RIGHTPADDING',  (0,0),(-1,-1), 8),
        ('BOX',           (0,0),(-1,-1), 0.5, C_BORDER),
        ('LINEBELOW',     (0,0),(-1,-2), 0.3, C_BORDER),
        ('TEXTCOLOR',     (0,1),(0,1), C_RED),
        ('TEXTCOLOR',     (0,2),(0,2), C_ORANGE),
        ('TEXTCOLOR',     (0,3),(0,3), C_YELLOW),
        ('TEXTCOLOR',     (0,4),(0,4), C_GREEN),
        ('FONTNAME',      (0,1),(0,-1), 'Helvetica-Bold'),
    ]))
    story.append(rl_t)
    story.append(Spacer(1, 12))

    # Historique mesures
    story.append(Paragraph(f'Historique ({min(8,n_total)} dernieres mesures)', S_H2))
    last_rows = rows[-8:]
    det_data  = [['Heure', 'Latence', 'Pertes', 'Risque', 'Classe RF', 'Niveau']]
    for r in last_rows:
        ts_s  = r.get('timestamp','')[-8:]
        lat_v = r.get('latency_ms','—')
        los_v = r.get('packet_loss_pct','—')
        rsk_v = r.get('risk_score','—')
        rfc   = r.get('rf_class','—')
        lvl_v = r.get('risk_level','—')
        try:    rs = float(rsk_v); rniv = 'Critique' if rs>=80 else 'Eleve' if rs>=60 else 'Modere' if rs>=30 else 'Normal'
        except: rniv = '—'
        try:    lat_s = f'{float(lat_v):.0f} ms'
        except: lat_s = '—'
        try:    los_s = f'{float(los_v):.1f}%'
        except: los_s = '—'
        try:    rsk_s = f'{float(rsk_v):.0f}/100'
        except: rsk_s = '—'
        det_data.append([ts_s, lat_s, los_s, rsk_s, rfc, rniv])
    det_t = Table(det_data, colWidths=[2.2*cm, 2.5*cm, 2*cm, 2.5*cm, 3*cm, 4.4*cm])
    det_t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), C_DARK),
        ('TEXTCOLOR',     (0,0),(-1,0), C_WHITE),
        ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
        ('FONTNAME',      (0,1),(-1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,0),(-1,-1), 9),
        ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_WHITE, C_GRAY]),
        ('TOPPADDING',    (0,0),(-1,-1), 5),
        ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ('LEFTPADDING',   (0,0),(-1,-1), 5),
        ('RIGHTPADDING',  (0,0),(-1,-1), 5),
        ('BOX',           (0,0),(-1,-1), 0.5, C_BORDER),
        ('LINEBELOW',     (0,0),(-1,-2), 0.3, C_BORDER),
    ]))
    story.append(det_t)
    story.append(Spacer(1, 12))

    # Actions recommandees
    actions = last_full.get('recommended_actions', [])
    if actions:
        story.append(Paragraph('Actions recommandees par le systeme', S_H2))
        prio_labels = {1:'Urgent — a faire immediatement',
                       2:'Important — dans les prochaines heures',
                       3:'Recommande — a planifier', 4:'Optionnel'}
        for a in actions:
            p    = a.get('priority', 4)
            lbl  = a.get('label', a.get('action',''))
            src  = a.get('source','')
            prio = prio_labels.get(p,'')
            story.append(Paragraph(f'<b>{prio} :</b>  {lbl}  <font size="8" color="gray">[{src}]</font>', S_BODY))
        story.append(Spacer(1, 8))

    # Conclusion
    story.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=10))
    story.append(Paragraph('Conclusion', S_H2))
    if avg_risk >= 60:
        ccl = (f'Le reseau presente un niveau de risque <b>{risk_label}</b> '
               f'(score moyen {avg_risk}/100). Le Random Forest a classe le reseau comme '
               f'<b>{rf_class}</b>. Une intervention technique est recommandee.')
    elif avg_risk >= 30:
        ccl = (f'Le reseau presente un niveau de risque <b>{risk_label}</b> '
               f'(score moyen {avg_risk}/100). La classification Random Forest indique '
               f'<b>{rf_class}</b>. Une surveillance continue est conseillee.')
    else:
        ccl = (f'Le reseau est dans un etat <b>{risk_label}</b> '
               f'(score moyen {avg_risk}/100). Classification RF : <b>{rf_class}</b>. '
               f'Aucune action immediate requise.')
    story.append(Paragraph(ccl, S_BODY))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f'Rapport genere automatiquement par INMS QoS Pipeline v2.0  |  '
        f'{datetime.now().strftime("%d/%m/%Y %H:%M")}  |  '
        f'SHAP={"actif" if _shap_ok else "inactif"}  |  '
        f'{n_total} mesures analysees', S_SMALL))

    doc.build(story)
    print(f'\n  PDF genere : {PDF_REPORT}')


# ════════════════════════════════════════════════════════════════
# BOUCLE PRINCIPALE
# ════════════════════════════════════════════════════════════════

def dso4_loop():
    log_agent(dso4_state, 'log', f'Agent6 XAI demarre — SHAP={"actif" if _shap_ok else "inactif"}')
    while dso4_state['running']:
        try:
            valise = dso4_queue.get(timeout=2)
        except queue.Empty:
            continue

        dso4_state['total'] += 1
        n = dso4_state['total']
        try:
            report = build_executive_summary(valise)
            dso4_state['last_report']  = report
            dso4_state['last_valise']  = valise
            dso4_state['shap_values']  = report.get('shap_explanation', {})
            _save_report(report)
            log_agent(dso4_state, 'log', f'#{n} rapport {report["report_id"]} genere')
        except Exception as e:
            log_agent(dso4_state, 'log', f'#{n} erreur: {e}')


def start():
    dso4_state.update({'running': True, 'total': 0,
                       'last_report': None, 'last_valise': None,
                       'shap_values': None, 'log': []})
    t = threading.Thread(target=dso4_loop, name='Agent6-XAI', daemon=True)
    t.start()
    return t


def stop():
    dso4_state['running'] = False
