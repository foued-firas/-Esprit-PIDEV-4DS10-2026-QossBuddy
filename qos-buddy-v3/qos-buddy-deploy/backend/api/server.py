"""
api/server.py — QoS Buddy Dashboard (Version améliorée)
=========================================================
Corrections :
  - Détection de déconnexion Wi-Fi avec message d'alerte
  - Génération PDF corrigée (avec CORS et gestion d'erreurs)
  - Intégration Speedtest (Ookla) via speedtest-cli
  - Données réelles des agents (pas statiques)
  - CORS complet pour React frontend séparé
"""

import sys, os, time, threading, socket, math, random, subprocess, platform
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, send_file, make_response, request
from shared.config import OUTPUT_DIR
from shared.queues import pipeline_state
import dso3_risk.agent as dso3
import dso6_security.agent as dso6
import dso5_decision.agent as dso5
import dso4_reporting.agent as dso4

app = Flask(__name__)

# ── CORS manuel pour tous les /api/*
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    response.headers['Access-Control-Expose-Headers']= 'Content-Disposition'
    return response

@app.route('/api/<path:p>', methods=['OPTIONS'])
def options_handler(p):
    return '', 200


server_state = {
    'pipeline_running':  False,
    'start_time':        None,
    'mode':              'stopped',
    'network_name':      '—',
    'is_online':         True,
    'last_online_check': time.time(),
    'speedtest_result':  None,
    'speedtest_running': False,
}


# ════════════════════════════════════════════════════════════════
# CONNEXION INTERNET
# ════════════════════════════════════════════════════════════════

def check_internet_connection() -> bool:
    for host, port in [('8.8.8.8', 53), ('1.1.1.1', 53)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((host, port))
            s.close()
            if result == 0:
                return True
        except Exception:
            continue
    return False


def _monitor_connectivity():
    while True:
        try:
            was_online = server_state['is_online']
            online = check_internet_connection()
            server_state['is_online'] = online
            server_state['last_online_check'] = time.time()
            if not online and was_online:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️  CONNEXION PERDUE")
            elif online and not was_online:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅  CONNEXION RÉTABLIE")
        except Exception:
            pass
        time.sleep(5)


# ════════════════════════════════════════════════════════════════
# RÉSEAU
# ════════════════════════════════════════════════════════════════

def detect_network_name() -> str:
    system = platform.system()
    try:
        if system == 'Windows':
            out = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'interfaces'],
                timeout=3, stderr=subprocess.DEVNULL
            ).decode('cp1252', errors='ignore')
            for line in out.splitlines():
                if 'SSID' in line and 'BSSID' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2 and parts[1].strip():
                        return parts[1].strip()
        elif system == 'Linux':
            out = subprocess.check_output(
                ['iwgetid', '-r'], timeout=3, stderr=subprocess.DEVNULL
            ).decode().strip()
            if out:
                return out
        elif system == 'Darwin':
            out = subprocess.check_output(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/'
                 'Versions/Current/Resources/airport', '-I'],
                timeout=3, stderr=subprocess.DEVNULL
            ).decode()
            for line in out.splitlines():
                if ' SSID:' in line:
                    return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return 'Réseau local'


def _refresh_network_name():
    while True:
        try:
            server_state['network_name'] = detect_network_name()
        except Exception:
            pass
        time.sleep(30)


# ════════════════════════════════════════════════════════════════
# SPEEDTEST OOKLA
# ════════════════════════════════════════════════════════════════

def _run_speedtest_background():
    server_state['speedtest_running'] = True
    server_state['speedtest_result']  = None
    try:
        import speedtest as st_lib
        s = st_lib.Speedtest()
        s.get_best_server()
        dl = s.download()
        ul = s.upload()
        res = s.results.dict()
        server_state['speedtest_result'] = {
            'download_mbps':  round(res['download'] / 1_000_000, 2),
            'upload_mbps':    round(res['upload']   / 1_000_000, 2),
            'ping_ms':        round(res['ping'], 1),
            'server_name':    res.get('server', {}).get('name', 'Inconnu'),
            'server_country': res.get('server', {}).get('country', ''),
            'isp':            res.get('client', {}).get('isp', 'Inconnu'),
            'timestamp':      datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source':         'speedtest-cli (Ookla)',
        }
    except ImportError:
        # Estimation depuis les KPIs du pipeline
        report = dso4.dso4_state.get('last_report') or {}
        kpis   = report.get('network_kpis', {})
        thr    = float(kpis.get('throughput_mbps', 20))
        lat    = float(kpis.get('latency_ms', 50))
        loss   = float(kpis.get('packet_loss_pct', 0))
        dl_est = round(max(1, thr * (1 - loss/100) * 2.0 + random.uniform(-2,2)), 2)
        ul_est = round(max(0.5, thr * (1 - loss/100) * 0.85 + random.uniform(-1,1)), 2)
        server_state['speedtest_result'] = {
            'download_mbps':  dl_est,
            'upload_mbps':    ul_est,
            'ping_ms':        round(lat + random.uniform(-3,3), 1),
            'server_name':    'Estimation pipeline (speedtest-cli absent)',
            'server_country': 'TN',
            'isp':            server_state['network_name'],
            'timestamp':      datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source':         'estimation-pipeline',
            'note':           'Installez speedtest-cli pour des résultats réels: pip install speedtest-cli',
        }
    except Exception as e:
        server_state['speedtest_result'] = {
            'error':     str(e),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    finally:
        server_state['speedtest_running'] = False


# ════════════════════════════════════════════════════════════════
# PIPELINE — DEMO
# ════════════════════════════════════════════════════════════════

def _start_pipeline_demo():
    from shared.queues import dso3_input_queue, safe_put

    pipeline_state['running']      = True
    pipeline_state['total']        = 0
    pipeline_state['alerts_count'] = 0

    dso3.start(); dso6.start(); dso5.start(); dso4.start()
    server_state['pipeline_running'] = True
    server_state['mode']             = 'demo'
    server_state['start_time']       = time.time()

    scenarios = [
        (30,  0.0, 'OK',       'Normal'),
        (180, 2.5, 'WARNING',  'Dégradé'),
        (320, 7.0, 'CRITICAL', 'Critique'),
        (45,  0.1, 'OK',       'Normal'),
        (210, 4.5, 'CRITICAL', 'Critique'),
        (60,  0.0, 'OK',       'Normal'),
        (150, 1.5, 'WARNING',  'Attention'),
    ]

    def _inject():
        i = 0
        while server_state['pipeline_running']:
            lat, loss, sev, label = scenarios[i % len(scenarios)]
            lat  = lat + random.uniform(-8, 8)
            loss = max(0, loss + random.uniform(-0.3, 0.3))
            now  = datetime.now()
            net  = server_state['network_name']
            row  = {
                'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
                'network_name': net,
                'latency_ms': round(lat, 2),
                'mean_latency_ms': round(lat, 2),
                'min_latency_ms': round(lat * 0.8, 2),
                'max_latency_ms': round(lat * 1.3, 2),
                'std_latency_ms': 12.0,
                'jitter_ms': round(loss * 3 + random.uniform(0, 4), 2),
                'latency_spread': 12.0,
                'latency_trend': round(random.uniform(-5, 5), 2),
                'packet_loss_rate_pct': round(loss, 2),
                'throughput_mbps': round(max(0.1, 50 - lat * 0.1), 2),
                'available_bandwidth_mbps': 100.0,
                'bandwidth_utilization_pct': round(min(100, lat / 3), 2),
                'bandwidth_efficiency': 0.7,
                'network_load': round(min(1.0, lat / 300), 4),
                'instability_score': round(loss * 0.3 * lat / 100, 4),
                'risk_score': round(min(1.0, (lat/300 + loss/100) / 2), 4),
                'buffer_occupancy_pct': 60.0,
                'queue_length': 45.0,
                'congestion_level': 1 if lat > 200 else 0,
                'prb_utilization_proxy': 50.0,
                'rsrp_estimated': round(-70 - lat * 0.1, 2),
                'sinr_estimated': round(20 - loss * 2, 2),
                'cqi_estimated': max(1, min(15, int(15 - loss / 7))),
                'mos_proxy': round(max(1, 4.5 - loss*0.1 - lat*0.005), 2),
                'spike': 1 if lat > 200 else 0,
                'ho_failure_proxy': 1 if loss > 5 else 0,
                'coverage_hole_proxy': 1 if lat > 300 else 0,
                'performance_degraded': 1 if lat > 150 or loss > 3 else 0,
                'rsrp_category': 'Bon' if lat < 80 else 'Moyen' if lat < 150 else 'Faible',
                'hops_mean': round(lat*0.2, 2), 'hops_max': round(lat*0.3, 2),
                'hops_min': round(lat*0.1, 2),  'hops_std': round(lat*0.05, 2),
                'hops_range': round(lat*0.2, 2),
                **{f'hop_{k}': 0.0 for k in range(1, 11)},
                'hour': now.hour, 'minute': now.minute, 'dayofweek': now.weekday(),
                'hour_sin': round(math.sin(2*math.pi*now.hour/24), 4),
                'hour_cos': round(math.cos(2*math.pi*now.hour/24), 4),
                'minute_sin': 0.0, 'minute_cos': 1.0,
                'dayofweek_sin': 0.0, 'dayofweek_cos': 1.0,
                'peak_offpeak_indicator': 1 if 8 <= now.hour <= 22 else 0,
            }
            analysis = {
                'severity': sev, 'rsrp_class': row['rsrp_category'],
                'n_critical': 2 if sev == 'CRITICAL' else 0,
                'n_warning':  1 if sev == 'WARNING' else 0,
                'has_critical': sev == 'CRITICAL',
                'rf_class': row['rsrp_category'],
                'rf_confidence': round(0.75 + random.uniform(0, 0.2), 2),
                'rf_source': 'demo',
                'severity_encoded': 2 if sev == 'CRITICAL' else 1 if sev == 'WARNING' else 0,
                'alerts': [],
            }
            safe_put(dso3_input_queue, (row, analysis))
            pipeline_state['total'] += 1
            i += 1
            time.sleep(8)

    threading.Thread(target=_inject, name='DemoInjector', daemon=True).start()


def _start_pipeline_real():
    import joblib
    try:
        import torch
        from dso1_performance.agent import QoSAutoencoder, DSO1Agent
        import dso2_classification.agent as dso2

        ae_meta   = torch.load(f'{OUTPUT_DIR}/ae_meta.pt', weights_only=False)
        ae_model  = QoSAutoencoder(ae_meta['input_dim'], bottleneck_dim=10)
        ae_model.load_state_dict(torch.load(f'{OUTPUT_DIR}/ae_model.pt', weights_only=True))
        ae_model.eval()
        if_model  = joblib.load(f'{OUTPUT_DIR}/if_model.pkl')
        ee_model  = joblib.load(f'{OUTPUT_DIR}/ee_model.pkl')
        svm_model = joblib.load(f'{OUTPUT_DIR}/svm_model.pkl')
        scaler    = joblib.load(f'{OUTPUT_DIR}/ae_scaler.pkl')
        feature_cols = joblib.load(f'{OUTPUT_DIR}/feature_cols.pkl')
        dso1_agent = DSO1Agent(ae_model, ae_meta['recon_thresh'],
                               if_model, ee_model, svm_model, scaler, feature_cols)
        pipeline_state['running']      = True
        pipeline_state['total']        = 0
        pipeline_state['alerts_count'] = 0
        threading.Thread(target=dso1_agent.run_loop, name='Agent1', daemon=True).start()
        dso2.start()
    except Exception as e:
        print(f'Modèles absents ({e}) — mode démo activé')
        _start_pipeline_demo()
        return

    dso3.start(); dso6.start(); dso5.start(); dso4.start()
    server_state['pipeline_running'] = True
    server_state['mode']             = 'run'
    server_state['start_time']       = time.time()


# ════════════════════════════════════════════════════════════════
# ROUTES API
# ════════════════════════════════════════════════════════════════

@app.route('/api/status')
def api_status():
    return jsonify({
        'pipeline_running': server_state['pipeline_running'],
        'mode':             server_state['mode'],
        'total_captures':   pipeline_state.get('total', 0),
        'total_alerts':     pipeline_state.get('alerts_count', 0),
        'network_name':     server_state['network_name'],
        'uptime_sec':       int(time.time() - server_state['start_time'])
                            if server_state['start_time'] else 0,
        'is_online':        server_state['is_online'],
        'last_check_ago':   int(time.time() - server_state['last_online_check']),
    })


@app.route('/api/data')
def api_data():
    report = dso4.dso4_state.get('last_report')
    valise = dso4.dso4_state.get('last_valise', {})

    if not report:
        return jsonify({
            'ready': False,
            'network_name': server_state['network_name'],
            'is_online': server_state['is_online'],
        })

    net_name = (valise.get('dso1_capture', {})
                .get('features', {}).get('network_name', ''))
    if not net_name or net_name in ('—', 'Non disponible', ''):
        net_name = server_state['network_name']

    horizons_out = {}
    for h in [20, 60, 300]:
        d = report.get('risk_horizons', {}).get(h, {})
        horizons_out[h] = {'score': d.get('score', 0), 'class': d.get('class', '—')}

    top_feat = report.get('shap_explanation', {}).get('top_features', [])

    return jsonify({
        'ready':          True,
        'timestamp':      report.get('timestamp', '—'),
        'network_name':   net_name,
        'is_online':      server_state['is_online'],
        'risk_score':     report.get('risk_score', 0),
        'risk_level_raw': report.get('risk_level_raw', 'LOW'),
        'decision_raw':   report.get('decision_raw', 'NONE'),
        'rf_class':       report.get('rf_class', '—'),
        'rf_confidence':  report.get('rf_confidence', 0),
        'kpis': {
            'latency_ms':      report['network_kpis'].get('latency_ms', 0),
            'packet_loss_pct': report['network_kpis'].get('packet_loss_pct', 0),
            'throughput_mbps': report['network_kpis'].get('throughput_mbps', 0),
            'mos_proxy':       report['network_kpis'].get('mos_proxy', 0),
            'rsrp_category':   report['network_kpis'].get('rsrp_category', '—'),
        },
        'horizons':       horizons_out,
        'security': {
            'status':   report.get('security_status', 'CLEAN'),
            'n_events': report.get('n_security_events', 0),
            'attacks':  report.get('attack_types', []),
        },
        'actions':        report.get('recommended_actions', []),
        'shap_features':  top_feat[:5],
        'n_critical':     report.get('n_critical_alerts', 0),
        'n_warnings':     report.get('n_warnings', 0),
        'total_captures': pipeline_state.get('total', 0),
        'total_alerts':   pipeline_state.get('alerts_count', 0),
    })


@app.route('/api/pdf')
def api_pdf():
    """Téléchargement du rapport PDF — version corrigée."""
    pdf_path = os.path.join(OUTPUT_DIR, 'rapport_inms_qos.pdf')
    try:
        dso4.generate_pdf()
    except Exception as e:
        if not os.path.exists(pdf_path):
            return jsonify({
                'error': f'PDF non générable : {e}',
                'hint': 'Lancez le pipeline au moins 30s avant.'
            }), 503

    if not os.path.exists(pdf_path):
        return jsonify({
            'error': 'PDF non disponible. Lancez le pipeline d\'abord.'
        }), 404

    try:
        return send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='rapport_qos_buddy.pdf',
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/start/<mode>')
def api_start(mode):
    if server_state['pipeline_running']:
        return jsonify({'error': 'Pipeline déjà en cours'})
    fn = _start_pipeline_demo if mode == 'demo' else _start_pipeline_real
    threading.Thread(target=fn, daemon=True).start()
    time.sleep(1)
    return jsonify({'ok': True, 'mode': mode})


@app.route('/api/stop')
def api_stop():
    pipeline_state['running']        = False
    server_state['pipeline_running'] = False
    server_state['mode']             = 'stopped'
    dso3.stop(); dso6.stop(); dso5.stop(); dso4.stop()
    time.sleep(1)
    try:
        dso4.generate_pdf()
    except Exception:
        pass
    return jsonify({'ok': True})


@app.route('/api/speedtest/run', methods=['POST'])
def api_speedtest_run():
    if server_state['speedtest_running']:
        return jsonify({'error': 'Speedtest déjà en cours', 'running': True})
    if not server_state['is_online']:
        return jsonify({'error': 'Pas de connexion internet'}), 503
    threading.Thread(target=_run_speedtest_background, daemon=True).start()
    return jsonify({'ok': True, 'running': True})


@app.route('/api/speedtest/result')
def api_speedtest_result():
    return jsonify({
        'running': server_state['speedtest_running'],
        'result':  server_state['speedtest_result'],
    })


@app.route('/api/connectivity')
def api_connectivity():
    online = check_internet_connection()
    server_state['is_online'] = online
    return jsonify({
        'is_online':    online,
        'checked_at':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'network_name': server_state['network_name'],
    })


# ════════════════════════════════════════════════════════════════
# DÉMARRAGE
# ════════════════════════════════════════════════════════════════

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    server_state['network_name'] = detect_network_name()
    server_state['is_online']    = check_internet_connection()

    threading.Thread(target=_refresh_network_name, daemon=True).start()
    threading.Thread(target=_monitor_connectivity,  daemon=True).start()
    threading.Thread(target=_start_pipeline_demo,   daemon=True).start()

    ip = get_local_ip()
    print('=' * 60)
    print('  QoS Buddy — Flask API  |  by MindForge')
    print('=' * 60)
    print(f'  Réseau    : {server_state["network_name"]}')
    print(f'  Connexion : {"✅ En ligne" if server_state["is_online"] else "❌ Hors ligne"}')
    print(f'  Localhost : http://localhost:8000/api')
    print(f'  Réseau    : http://{ip}:8000/api')
    print('  Frontend React : http://localhost:3000')
    print('=' * 60)

    app.run(host='0.0.0.0', port=8000, debug=False)
