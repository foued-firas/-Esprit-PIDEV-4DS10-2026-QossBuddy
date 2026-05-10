"""
main.py — INMS QoS Pipeline v2.0
==================================
Flux :
  Agent1 (Capture) -> Agent2 (Classification RF+Cisco) -> Agent3 (Prediction LSTM+XGB)
  -> Agent4 (Securite) -> Agent5 (Optimisation XGB) -> Agent6 (XAI+PDF)

Usage :
    python main.py train    # Entraine tous les modeles offline
    python main.py run      # Pipeline 45s temps reel + PDF auto
    python main.py demo     # Demo simulee + PDF auto
    python main.py status   # Etat des artefacts
"""

import sys, os, time, threading, argparse, math, warnings
from datetime import datetime

warnings.filterwarnings('ignore')
os.environ['LOKY_MAX_CPU_COUNT'] = '4'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.config import OUTPUT_DIR, SEED
from shared.queues import pipeline_state, dso3_input_queue, safe_put

os.makedirs(OUTPUT_DIR, exist_ok=True)

PIPELINE_DURATION = 45


# ════════════════════════════════════════════════════════════════
# AFFICHAGE
# ════════════════════════════════════════════════════════════════

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_dashboard(report, n_total, network_name, elapsed, duration):
    clear()
    risk_labels = {
        'CRITICAL': '🔴  CRITIQUE  — Intervention immediate requise',
        'HIGH':     '🟠  ELEVE     — Surveillance renforcee',
        'MEDIUM':   '🟡  MODERE    — Situation a surveiller',
        'LOW':      '🟢  FAIBLE    — Reseau stable',
    }
    decision_labels = {
        'IMMEDIATE': '🔴  ACTION IMMEDIATE',
        'URGENT':    '🟠  ACTION URGENTE',
        'ROUTINE':   '🟡  SURVEILLANCE ROUTINE',
        'NONE':      '🟢  AUCUNE ACTION REQUISE',
    }
    W         = 70
    bar_done  = int((elapsed / max(duration, 1)) * 30)
    prog_bar  = '█' * bar_done + '░' * (30 - bar_done)
    remaining = max(0, int(duration - elapsed))

    print('┌' + '─'*W + '┐')
    print('│' + '  INMS QoS — SURVEILLANCE RESEAU EN TEMPS REEL  '.center(W) + '│')
    print('│' + f'  {datetime.now().strftime("%d/%m/%Y  %H:%M:%S")}  ·  Rapport n°{n_total}'.center(W) + '│')
    print('│' + f'  Reseau : {network_name}'.ljust(W) + '│')
    print('├' + '─'*W + '┤')
    print('│' + f'  {risk_labels.get(report.get("risk_level_raw","LOW"), "—")}'.ljust(W) + '│')
    print('│' + f'  {decision_labels.get(report.get("decision_raw","NONE"), "—")}'.ljust(W) + '│')
    print('│' + f'  [{prog_bar}]  {remaining}s restantes'.ljust(W) + '│')
    print('└' + '─'*W + '┘')

    print()
    print('  KPIs RESEAU')
    print('  ' + '─'*66)
    kpis = report.get('network_kpis', {})

    def _lat(v):
        try:
            v = float(v)
            if v < 0:   return 'N/A'
            if v < 100: return f'{v:.1f} ms  OK'
            if v < 150: return f'{v:.1f} ms  Attention'
            if v < 200: return f'{v:.1f} ms  Eleve'
            return      f'{v:.1f} ms  CRITIQUE'
        except: return str(v)

    def _loss(v):
        try:
            v = float(v)
            if v == 0: return '0 %  OK'
            if v < 1:  return f'{v:.2f} %  Attention'
            if v < 5:  return f'{v:.2f} %  Eleve'
            return     f'{v:.2f} %  CRITIQUE'
        except: return str(v)

    def _mos(v):
        try:
            v = float(v)
            if v >= 4.0: return f'{v:.2f}/5  OK'
            if v >= 3.6: return f'{v:.2f}/5  Attention'
            if v >= 3.1: return f'{v:.2f}/5  Degrade'
            return       f'{v:.2f}/5  Mauvais'
        except: return str(v)

    rf_class = report.get('rf_class','—')
    rf_conf  = report.get('rf_confidence', 0)
    try:    rf_pct = f'{float(rf_conf)*100:.0f}%'
    except: rf_pct = '—'

    for label, val in [
        ('Latence',            _lat(kpis.get('latency_ms','N/A'))),
        ('Pertes paquets',     _loss(kpis.get('packet_loss_pct',0))),
        ('Debit recu',         f'{float(kpis.get("throughput_mbps",0)):.2f} Mbps'),
        ('Qualite voix MOS',   _mos(kpis.get('mos_proxy',0))),
        ('Signal RSRP',        str(kpis.get('rsrp_category','—'))),
        ('Classe RF',          f'{rf_class}  (confiance {rf_pct})'),
    ]:
        print(f'  {label:<30} {val}')

    print()
    print('  PREVISIONS DE RISQUE')
    print('  ' + '─'*66)
    horizons   = report.get('risk_horizons', {})
    lbl_h      = {20:'Dans 20 secondes', 60:'Dans 1 minute  ', 300:'Dans 5 minutes '}
    risk_short = {'CRITICAL':'Critique','HIGH':'Eleve','MEDIUM':'Modere','LOW':'Faible'}
    for h in [20, 60, 300]:
        d    = horizons.get(h, {})
        sc   = d.get('score', 0)
        cl   = d.get('class','—')
        mini = '█' * int(sc/5) + '░' * (20 - int(sc/5))
        print(f'  {lbl_h.get(h,f"+{h}s")}  [{mini}]  {sc:.0f}/100  {risk_short.get(cl,cl)}')

    print()
    print('  SECURITE')
    print('  ' + '─'*66)
    sec  = report.get('security_status','CLEAN')
    n_ev = report.get('n_security_events',0)
    atk  = report.get('attack_types',[])
    sec_l= {'CLEAN':'Propre','LOW':'Faible','MEDIUM':'Moyen',
             'HIGH':'Eleve','CRITICAL':'CRITIQUE'}.get(sec, sec)
    print(f'  Etat           : {sec_l}')
    print(f'  Evenements     : {n_ev}')
    if atk:
        print(f'  Types detectes : {", ".join(atk)}')

    # SHAP si disponible
    shap_exp = report.get('shap_explanation', {})
    top_feat = shap_exp.get('top_features', [])
    if top_feat:
        print()
        print('  EXPLICATION XAI (SHAP) — Top 3 facteurs')
        print('  ' + '─'*66)
        for f in top_feat[:3]:
            direction = '+' if f['shap_value'] > 0 else '-'
            print(f'  {direction}  {f["feature"]:<35} impact={f["shap_value"]:+.4f}')

    print()
    print('  ACTIONS RECOMMANDEES')
    print('  ' + '─'*66)
    actions = report.get('recommended_actions', [])
    if not actions:
        print('  Aucune action requise.')
    else:
        for a in actions[:4]:
            p  = a.get('priority', 4)
            pl = {1:'P1',2:'P2',3:'P3',4:'P4'}.get(p,'')
            lbl= a.get('label', a.get('action',''))
            print(f'  [{pl}]  {lbl}')

    print()
    print(f'  Sorties : {OUTPUT_DIR}/')


def print_summary(n_captures, n_alerts, n_reports):
    clear()
    print('=' * 65)
    print('  PIPELINE TERMINE')
    print('=' * 65)
    print(f'  Captures effectuees : {n_captures}')
    print(f'  Alertes declenchees : {n_alerts}')
    print(f'  Rapports generes    : {n_reports}')
    print(f'  Fichiers dans       : {OUTPUT_DIR}/')
    print()
    print('  Generation du rapport PDF...')


# ════════════════════════════════════════════════════════════════
# TRAIN — entraine Autoencoder + Random Forest + modeles DSO3
# ════════════════════════════════════════════════════════════════

def cmd_train(file_id='1H3__N0mCX9OdI_xWqRp3trgx-9OUPmjn'):
    print('=' * 65)
    print('  PHASE ENTRAINEMENT — INMS QoS Pipeline v2.0')
    print('=' * 65)

    import joblib
    import numpy as np

    from data.preprocessing import (load_dataset_from_drive, prepare_dataset,
                                     prepare_for_autoencoder)
    from dso1_performance.agent import train_autoencoder, train_ensemble_models

    try:
        import torch
        _torch_ok = True
    except ImportError:
        _torch_ok = False

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        from sklearn.model_selection import cross_val_score
        _rf_ok = True
    except ImportError:
        _rf_ok = False

    print('\n[1/5] Chargement du dataset...')
    df = load_dataset_from_drive(file_id)

    print('\n[2/5] Data Preparation...')
    X_scaled, y, le, knn_imputer, scaler_prep, feature_cols = prepare_dataset(df, save=True)

    print('\n[3/5] Preparation DSO1 (split anti-leakage)...')
    ae_data = prepare_for_autoencoder(df, seed=SEED)

    print('\n[4/5] Entrainement Autoencoder + IF + EE + SVM...')
    if _torch_ok:
        from dso1_performance.agent import QoSAutoencoder
        ae_model, recon_thresh, _, _ = train_autoencoder(
            ae_data['X_train_ae'], ae_data['X_test_ae'], ae_data['input_dim'])
        if_model, ee_model, svm_model, _, _ = train_ensemble_models(
            ae_model, ae_data['X_train_ae'], ae_data['X_test_ae'])

        import torch
        torch.save(ae_model.state_dict(),        f'{OUTPUT_DIR}/ae_model.pt')
        torch.save({'input_dim': ae_data['input_dim'],
                    'recon_thresh': recon_thresh}, f'{OUTPUT_DIR}/ae_meta.pt')
        joblib.dump(if_model,                    f'{OUTPUT_DIR}/if_model.pkl')
        joblib.dump(ee_model,                    f'{OUTPUT_DIR}/ee_model.pkl')
        joblib.dump(svm_model,                   f'{OUTPUT_DIR}/svm_model.pkl')
        joblib.dump(ae_data['scaler'],           f'{OUTPUT_DIR}/ae_scaler.pkl')
        joblib.dump(ae_data['feature_cols'],     f'{OUTPUT_DIR}/feature_cols.pkl')
        print(f'   Autoencoder OK — seuil CRITICAL : {recon_thresh:.4f}')
    else:
        print('   PyTorch absent — Autoencoder ignore')

    print('\n[5/5] Entrainement Random Forest (Agent2 Classification)...')
    if _rf_ok:
        # Features pour le RF : metriques + features seuils
        SEV_MAP = {'Bon': 0, 'Faible': 1, 'Mauvais': 2, 'Tres mauvais': 3}
        rf_features = [
            'latency_ms', 'jitter_ms', 'packet_loss_rate_pct', 'throughput_mbps',
            'mos_proxy', 'rsrp_estimated', 'sinr_estimated', 'cqi_estimated',
            'instability_score', 'risk_score', 'buffer_occupancy_pct',
            'bandwidth_utilization_pct', 'hops_mean', 'spike',
            'ho_failure_proxy', 'coverage_hole_proxy', 'performance_degraded',
        ]
        # Colonnes disponibles dans le dataset
        available = [f for f in rf_features if f in df.columns]
        X_rf = df[available].fillna(df[available].median()).values

        # Ajouter features simulees seuils (severity_encoded, n_critical, n_warning)
        # Calcul simplifie pour l'entrainement
        sev_enc = np.where(
            df.get('packet_loss_rate_pct', 0).fillna(0) > 5, 2,
            np.where(df.get('latency_ms', 0).fillna(0) > 150, 1, 0)
        ).reshape(-1, 1)
        n_crit_approx = np.where(df.get('latency_ms', 0).fillna(0) > 200, 2, 0).reshape(-1, 1)
        n_warn_approx = np.where(df.get('latency_ms', 0).fillna(0) > 150, 1, 0).reshape(-1, 1)
        X_rf = np.hstack([X_rf, sev_enc, n_crit_approx, n_warn_approx])

        # Target
        target_col = None
        for c in ['rsrp_category', 'rsrp_category_label']:
            if c in df.columns:
                target_col = c
                break
        if target_col is None:
            print('   Colonne target introuvable — RF ignore')
        else:
            rf_le = LabelEncoder()
            y_rf  = rf_le.fit_transform(df[target_col].fillna('Mauvais'))

            rf = RandomForestClassifier(
                n_estimators=200, max_depth=8, min_samples_leaf=5,
                class_weight='balanced', random_state=SEED, n_jobs=-1,
            )
            rf.fit(X_rf, y_rf)

            # Cross-validation rapide
            cv_scores = cross_val_score(rf, X_rf, y_rf, cv=3, scoring='f1_macro')
            print(f'   Random Forest OK — F1 macro CV : {cv_scores.mean():.3f} (+/-{cv_scores.std():.3f})')
            print(f'   Classes : {list(rf_le.classes_)}')

            joblib.dump(rf,    f'{OUTPUT_DIR}/rf_classifier.pkl')
            joblib.dump(rf_le, f'{OUTPUT_DIR}/rf_label_encoder.pkl')
    else:
        print('   scikit-learn absent — RF ignore')

    print(f'\nEntrainement termine — artefacts dans {OUTPUT_DIR}/')
    print('  -> python main.py run    pour lancer le pipeline (45s)')
    print('  -> python main.py demo   pour tester sans reseau reel')


# ════════════════════════════════════════════════════════════════
# RUN — Pipeline temps-reel 45 secondes + PDF auto
# ════════════════════════════════════════════════════════════════

def cmd_run():
    clear()
    print('=' * 65)
    print('  PIPELINE TEMPS-REEL — INMS QoS v2.0')
    print(f'  Duree : {PIPELINE_DURATION} secondes  |  PDF genere automatiquement')
    print('=' * 65)

    import joblib
    from dso1_performance.agent import DSO1Agent
    import dso2_classification.agent as dso2
    import dso3_risk.agent as dso3
    import dso6_security.agent as dso6
    import dso5_decision.agent as dso5
    import dso4_reporting.agent as dso4

    try:
        import torch
        from dso1_performance.agent import QoSAutoencoder
        ae_meta     = torch.load(f'{OUTPUT_DIR}/ae_meta.pt', weights_only=False)
        ae_model    = QoSAutoencoder(ae_meta['input_dim'], bottleneck_dim=10)
        ae_model.load_state_dict(torch.load(f'{OUTPUT_DIR}/ae_model.pt', weights_only=True))
        ae_model.eval()
        recon_thresh = ae_meta['recon_thresh']
        if_model     = joblib.load(f'{OUTPUT_DIR}/if_model.pkl')
        ee_model     = joblib.load(f'{OUTPUT_DIR}/ee_model.pkl')
        svm_model    = joblib.load(f'{OUTPUT_DIR}/svm_model.pkl')
        scaler       = joblib.load(f'{OUTPUT_DIR}/ae_scaler.pkl')
        feature_cols = joblib.load(f'{OUTPUT_DIR}/feature_cols.pkl')
        dso1_agent   = DSO1Agent(ae_model, recon_thresh, if_model, ee_model,
                                 svm_model, scaler, feature_cols)
        use_dso1 = True
        print('Modeles charges (Autoencoder + RF + XGBoost)')
    except Exception as e:
        print(f'Modeles DSO1 non disponibles ({e}) — Agent1 desactive')
        use_dso1 = False

    pipeline_state['running'] = True
    if use_dso1:
        threading.Thread(target=dso1_agent.run_loop, name='Agent1', daemon=True).start()
    dso2.start(); dso3.start(); dso6.start(); dso5.start(); dso4.start()

    print(f'Pipeline demarre — arret automatique dans {PIPELINE_DURATION}s\n')
    time.sleep(2)

    start_time    = time.time()
    last_report_n = 0

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= PIPELINE_DURATION:
                break
            report = dso4.dso4_state.get('last_report')
            n      = dso4.dso4_state.get('total', 0)
            if report and n != last_report_n:
                last_report_n = n
                valise   = dso4.dso4_state.get('last_valise', {})
                net_name = (valise.get('dso1_capture', {})
                            .get('features', {}).get('network_name', '—'))
                print_dashboard(report, n, net_name, elapsed, PIPELINE_DURATION)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    pipeline_state['running'] = False
    dso2.stop(); dso3.stop(); dso6.stop(); dso5.stop(); dso4.stop()
    time.sleep(1)

    print_summary(pipeline_state['total'],
                  pipeline_state['alerts_count'],
                  dso4.dso4_state.get('total', 0))

    # PDF automatique
    dso4.generate_pdf()
    print('  Pipeline termine.')


# ════════════════════════════════════════════════════════════════
# DEMO — Injection simulee + PDF auto
# ════════════════════════════════════════════════════════════════

def cmd_demo(n_injections=15, interval=2.0):
    clear()
    print('=' * 65)
    print('  MODE DEMO — Donnees simulees')
    print(f'  {n_injections} captures  |  intervalle {interval}s  |  PDF auto')
    print('=' * 65)

    import random
    import dso3_risk.agent as dso3
    import dso6_security.agent as dso6
    import dso5_decision.agent as dso5
    import dso4_reporting.agent as dso4

    pipeline_state['running'] = True
    dso3.start(); dso6.start(); dso5.start(); dso4.start()
    time.sleep(0.5)

    scenarios = [
        (25,  0.0, 'OK',       'Normal'),
        (180, 2.5, 'WARNING',  'Degrade'),
        (350, 8.0, 'CRITICAL', 'Critique'),
        (50,  0.1, 'OK',       'Normal'),
        (220, 5.0, 'CRITICAL', 'Critique Wi-Fi'),
    ]

    start_time = time.time()
    duration   = n_injections * interval
    last_n     = 0

    for i in range(1, n_injections + 1):
        lat, loss, sev, label = scenarios[i % len(scenarios)]
        now = datetime.now()
        test_row = {
            'timestamp':              now.strftime('%Y-%m-%d %H:%M:%S'),
            'network_name':           'Demo simulee',
            'latency_ms':             lat + random.uniform(-10, 10),
            'mean_latency_ms':        lat,
            'min_latency_ms':         lat * 0.8,
            'max_latency_ms':         lat * 1.3,
            'std_latency_ms':         12.0,
            'jitter_ms':              loss * 3 + random.uniform(0, 5),
            'latency_spread':         12.0,
            'latency_trend':          random.uniform(-5, 5),
            'packet_loss_rate_pct':   loss,
            'throughput_mbps':        max(0.1, 50 - lat * 0.1),
            'available_bandwidth_mbps': 100.0,
            'bandwidth_utilization_pct': min(100, lat / 3),
            'bandwidth_efficiency':   0.7,
            'network_load':           min(1.0, lat / 300),
            'instability_score':      round(loss * 0.3 * lat / 100, 4),
            'risk_score':             min(1.0, (lat/300 + loss/100) / 2),
            'buffer_occupancy_pct':   60.0,
            'queue_length':           45.0,
            'congestion_level':       1 if lat > 200 else 0,
            'prb_utilization_proxy':  50.0,
            'rsrp_estimated':         round(-70 - lat * 0.1, 4),
            'sinr_estimated':         round(20 - loss * 2, 4),
            'cqi_estimated':          max(1, min(15, int(15 - loss / 7))),
            'mos_proxy':              round(max(1, 4.5 - loss*0.1 - lat*0.005), 4),
            'spike':                  1 if lat > 200 else 0,
            'ho_failure_proxy':       1 if loss > 5 else 0,
            'coverage_hole_proxy':    1 if lat > 300 else 0,
            'performance_degraded':   1 if lat > 150 or loss > 3 else 0,
            'rsrp_category':          ('Bon' if lat < 80 else
                                       'Mauvais' if lat < 150 else 'Tres mauvais'),
            'hops_mean':  round(lat*0.2,4), 'hops_max': round(lat*0.3,4),
            'hops_min':   round(lat*0.1,4), 'hops_std': round(lat*0.05,4),
            'hops_range': round(lat*0.2,4),
            **{f'hop_{k}': 0.0 for k in range(1,11)},
            'hour': now.hour, 'minute': now.minute, 'dayofweek': now.weekday(),
            'hour_sin':  round(math.sin(2*math.pi*now.hour/24), 4),
            'hour_cos':  round(math.cos(2*math.pi*now.hour/24), 4),
            'minute_sin': 0.0, 'minute_cos': 1.0,
            'dayofweek_sin': 0.0, 'dayofweek_cos': 1.0,
            'peak_offpeak_indicator': 1 if 8 <= now.hour <= 22 else 0,
        }
        test_analysis = {
            'severity': sev, 'rsrp_class': test_row['rsrp_category'],
            'n_critical': 2 if sev == 'CRITICAL' else 0,
            'n_warning':  1 if sev == 'WARNING' else 0,
            'has_critical': sev == 'CRITICAL',
            'rf_class': test_row['rsrp_category'],
            'rf_confidence': 0.82,
            'rf_source': 'heuristic',
            'severity_encoded': 2 if sev == 'CRITICAL' else 1 if sev == 'WARNING' else 0,
            'alerts': [],
        }
        safe_put(dso3_input_queue, (test_row, test_analysis))
        time.sleep(interval)

        elapsed = time.time() - start_time
        report  = dso4.dso4_state.get('last_report')
        n       = dso4.dso4_state.get('total', 0)
        if report and n != last_n:
            last_n   = n
            valise   = dso4.dso4_state.get('last_valise', {})
            net_name = (valise.get('dso1_capture',{})
                        .get('features',{}).get('network_name','Demo simulee'))
            print_dashboard(report, n, net_name, elapsed, duration)

    time.sleep(3)
    pipeline_state['running'] = False
    dso3.stop(); dso6.stop(); dso5.stop(); dso4.stop()
    time.sleep(1)

    print_summary(n_injections, pipeline_state['alerts_count'],
                  dso4.dso4_state.get('total', 0))

    # PDF automatique
    dso4.generate_pdf()
    print('  Demo terminee.')


# ════════════════════════════════════════════════════════════════
# STATUS
# ════════════════════════════════════════════════════════════════

def cmd_status():
    print('=' * 65)
    print('  STATUT — INMS QoS Pipeline v2.0')
    print('=' * 65)
    artifacts = [
        ('ae_model.pt',         'Autoencoder (Agent1 DL)'),
        ('if_model.pkl',        'Isolation Forest (Agent1)'),
        ('ee_model.pkl',        'Elliptic Envelope (Agent1)'),
        ('svm_model.pkl',       'One-Class SVM (Agent1)'),
        ('ae_scaler.pkl',       'Scaler Autoencoder'),
        ('rf_classifier.pkl',   'Random Forest (Agent2)'),
        ('rf_label_encoder.pkl','Label Encoder RF'),
        ('knn_imputer.pkl',     'KNN Imputer'),
        ('robust_scaler.pkl',   'RobustScaler'),
        ('label_encoder.pkl',   'Label Encoder global'),
    ]
    print('\nModeles ML/DL :')
    all_ok = True
    for fname, label in artifacts:
        exists = os.path.exists(f'{OUTPUT_DIR}/{fname}')
        e = 'OK' if exists else 'MANQUANT'
        if not exists: all_ok = False
        print(f'  [{e}]  {label:<35} {fname}')

    print('\nSorties pipeline :')
    if os.path.exists(OUTPUT_DIR):
        for f in sorted(os.listdir(OUTPUT_DIR)):
            sz = os.path.getsize(f'{OUTPUT_DIR}/{f}')
            print(f'  {f:<45} ({sz/1024:.1f} KB)')

    if not all_ok:
        print('\n  -> Lance python main.py train pour generer les modeles manquants')


# ════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='INMS QoS Pipeline v2.0')
    parser.add_argument('command', choices=['train','run','demo','status'])
    parser.add_argument('--file-id', default='1H3__N0mCX9OdI_xWqRp3trgx-9OUPmjn')
    parser.add_argument('--n',        type=int,   default=15)
    parser.add_argument('--interval', type=float, default=2.0)
    args = parser.parse_args()

    if   args.command == 'train':  cmd_train(args.file_id)
    elif args.command == 'run':    cmd_run()
    elif args.command == 'demo':   cmd_demo(args.n, args.interval)
    elif args.command == 'status': cmd_status()
