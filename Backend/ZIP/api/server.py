"""
api/server.py — QoS Buddy Dashboard
=====================================
Usage :
    cd qos-agent
    python api/server.py
"""

import sys, os, time, threading, socket, math, random, subprocess, platform
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, send_file, render_template_string, make_response
from shared.config import OUTPUT_DIR
from shared.queues import pipeline_state
import dso3_risk.agent as dso3
import dso6_security.agent as dso6
import dso5_decision.agent as dso5
import dso4_reporting.agent as dso4

app = Flask(__name__)

server_state = {
    'pipeline_running': False,
    'start_time':       None,
    'mode':             'stopped',
    'network_name':     '—',
}


# ════════════════════════════════════════════════════════════════
# DETECTION NOM RESEAU (Wi-Fi ou Ethernet)
# ════════════════════════════════════════════════════════════════

def detect_network_name() -> str:
    """Detecte le nom du reseau Wi-Fi ou Ethernet actif."""
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
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return ssid
            # Fallback Ethernet Windows
            try:
                import psutil
                stats = psutil.net_if_stats()
                addrs = psutil.net_if_addrs()
                for iface, stat in stats.items():
                    if stat.isup and iface in addrs:
                        if 'loopback' not in iface.lower():
                            return f'Ethernet ({iface})'
            except Exception:
                pass

        elif system == 'Linux':
            try:
                out = subprocess.check_output(
                    ['iwgetid', '-r'], timeout=3, stderr=subprocess.DEVNULL
                ).decode().strip()
                if out:
                    return out
            except Exception:
                pass

        elif system == 'Darwin':
            try:
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
    except Exception:
        pass
    return 'Reseau local'


def _refresh_network_name():
    """Met a jour le nom du reseau toutes les 30s en arriere-plan."""
    while True:
        try:
            name = detect_network_name()
            server_state['network_name'] = name
        except Exception:
            pass
        time.sleep(30)


# ════════════════════════════════════════════════════════════════
# PIPELINE DEMO
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
        (180, 2.5, 'WARNING',  'Degrade'),
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
                'hops_min': round(lat*0.1, 2), 'hops_std': round(lat*0.05, 2),
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

        ae_meta      = torch.load(f'{OUTPUT_DIR}/ae_meta.pt', weights_only=False)
        ae_model     = QoSAutoencoder(ae_meta['input_dim'], bottleneck_dim=10)
        ae_model.load_state_dict(torch.load(f'{OUTPUT_DIR}/ae_model.pt', weights_only=True))
        ae_model.eval()
        if_model     = joblib.load(f'{OUTPUT_DIR}/if_model.pkl')
        ee_model     = joblib.load(f'{OUTPUT_DIR}/ee_model.pkl')
        svm_model    = joblib.load(f'{OUTPUT_DIR}/svm_model.pkl')
        scaler       = joblib.load(f'{OUTPUT_DIR}/ae_scaler.pkl')
        feature_cols = joblib.load(f'{OUTPUT_DIR}/feature_cols.pkl')
        dso1_agent   = DSO1Agent(ae_model, ae_meta['recon_thresh'],
                                 if_model, ee_model, svm_model, scaler, feature_cols)
        pipeline_state['running']      = True
        pipeline_state['total']        = 0
        pipeline_state['alerts_count'] = 0
        threading.Thread(target=dso1_agent.run_loop, name='Agent1', daemon=True).start()
        dso2.start()
    except Exception as e:
        print(f'Modeles absents ({e}) — mode demo active')
        _start_pipeline_demo()
        return

    dso3.start(); dso6.start(); dso5.start(); dso4.start()
    server_state['pipeline_running'] = True
    server_state['mode']             = 'run'
    server_state['start_time']       = time.time()


# ════════════════════════════════════════════════════════════════
# API
# ════════════════════════════════════════════════════════════════

def _cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


@app.route('/api/status')
def api_status():
    r = jsonify({
        'pipeline_running': server_state['pipeline_running'],
        'mode':             server_state['mode'],
        'total_captures':   pipeline_state.get('total', 0),
        'total_alerts':     pipeline_state.get('alerts_count', 0),
        'network_name':     server_state['network_name'],
        'uptime_sec':       int(time.time() - server_state['start_time'])
                            if server_state['start_time'] else 0,
    })
    return _cors(r)


@app.route('/api/data')
def api_data():
    report = dso4.dso4_state.get('last_report')
    valise = dso4.dso4_state.get('last_valise', {})

    if not report:
        return _cors(jsonify({'ready': False,
                              'network_name': server_state['network_name']}))

    # Nom reseau : depuis la valise d'abord, sinon depuis la detection systeme
    net_name = (valise.get('dso1_capture', {})
                .get('features', {}).get('network_name', ''))
    if not net_name or net_name in ('—', 'Non disponible', ''):
        net_name = server_state['network_name']

    horizons_out = {}
    for h in [20, 60, 300]:
        d = report.get('risk_horizons', {}).get(h, {})
        horizons_out[h] = {'score': d.get('score', 0), 'class': d.get('class', '—')}

    shap_exp = report.get('shap_explanation', {})
    top_feat = shap_exp.get('top_features', [])

    r = jsonify({
        'ready':          True,
        'timestamp':      report.get('timestamp', '—'),
        'network_name':   net_name,
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
    return _cors(r)


@app.route('/api/pdf')
def api_pdf():
    pdf_path = os.path.join(OUTPUT_DIR, 'rapport_inms_qos.pdf')
    if not os.path.exists(pdf_path):
        try:
            dso4.generate_pdf()
        except Exception as e:
            return _cors(make_response(
                f'Impossible de generer le PDF : {e}', 500))
    if os.path.exists(pdf_path):
        resp = make_response(send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='rapport_qos_buddy.pdf'
        ))
        return _cors(resp)
    return _cors(make_response('PDF non disponible. Lance le pipeline dabord.', 404))


@app.route('/api/start/<mode>')
def api_start(mode):
    if server_state['pipeline_running']:
        return _cors(jsonify({'error': 'Pipeline deja en cours'}))
    fn = _start_pipeline_demo if mode == 'demo' else _start_pipeline_real
    threading.Thread(target=fn, daemon=True).start()
    time.sleep(1)
    return _cors(jsonify({'ok': True, 'mode': mode}))


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
    return _cors(jsonify({'ok': True}))


# ════════════════════════════════════════════════════════════════
# DASHBOARD HTML
# ════════════════════════════════════════════════════════════════

DASHBOARD = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QoS Buddy — MindForge</title>
<style>
:root {
  --bg:#080c14; --surface:#0f1623; --card:#141d2e; --border:#1e2d45;
  --accent:#3b82f6; --accent2:#6366f1; --green:#22c55e;
  --yellow:#f59e0b; --orange:#f97316; --red:#ef4444;
  --text:#e2e8f0; --muted:#64748b; --subtle:#94a3b8;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:var(--bg);color:var(--text);min-height:100vh}

/* NAV */
nav{position:fixed;top:0;left:0;right:0;z-index:100;
    background:rgba(8,12,20,.9);backdrop-filter:blur(16px);
    border-bottom:1px solid var(--border);
    display:flex;align-items:center;justify-content:space-between;
    padding:0 24px;height:58px}
.logo{display:flex;align-items:center;gap:10px}
.logo-icon{width:34px;height:34px;border-radius:9px;
           background:linear-gradient(135deg,var(--accent),var(--accent2));
           display:flex;align-items:center;justify-content:center;
           font-size:17px;font-weight:900;color:#fff}
.logo-name{font-size:16px;font-weight:800}
.logo-by{font-size:10px;color:var(--muted)}
.nav-links{display:flex;gap:28px}
.nav-links a{font-size:13px;color:var(--muted);text-decoration:none;
             transition:color .2s;cursor:pointer}
.nav-links a:hover{color:var(--text)}
.live-pill{display:flex;align-items:center;gap:7px;
           background:var(--card);border:1px solid var(--border);
           border-radius:20px;padding:5px 12px;font-size:12px;color:var(--muted)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:blink 2s infinite}
.dot.off{background:var(--red);animation:none}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

/* HERO */
.hero{min-height:100vh;display:flex;align-items:center;justify-content:center;
      text-align:center;padding:80px 24px 40px;
      background:radial-gradient(ellipse 70% 50% at 50% 0%,rgba(59,130,246,.1) 0%,transparent 70%)}
.hero-badge{display:inline-flex;align-items:center;gap:6px;
            background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.25);
            color:var(--accent);border-radius:20px;padding:5px 16px;
            font-size:12px;font-weight:700;letter-spacing:.06em;margin-bottom:28px}
.hero h1{font-size:clamp(40px,7vw,80px);font-weight:900;line-height:1.05;
         background:linear-gradient(135deg,#fff 30%,#64748b);
         -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:10px}
.hero h1 em{font-style:normal;
            background:linear-gradient(135deg,var(--accent),var(--accent2));
            -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero-desc{font-size:clamp(14px,2vw,18px);color:var(--subtle);
           max-width:560px;margin:0 auto 36px;line-height:1.7}
.hero-btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:56px}
.btn-hero{padding:13px 30px;border-radius:12px;border:none;cursor:pointer;
          font-size:14px;font-weight:700;transition:transform .2s,box-shadow .2s}
.btn-hero:hover{transform:translateY(-2px)}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;
              box-shadow:0 4px 20px rgba(59,130,246,.3)}
.btn-primary:hover{box-shadow:0 8px 30px rgba(59,130,246,.5)}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--subtle)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.stats-row{display:flex;gap:0;justify-content:center;
           border:1px solid var(--border);border-radius:16px;overflow:hidden;flex-wrap:wrap}
.stat-item{padding:20px 32px;text-align:center;border-right:1px solid var(--border);flex:1;min-width:100px}
.stat-item:last-child{border-right:none}
.stat-val{font-size:28px;font-weight:900;color:var(--text)}
.stat-lbl{font-size:11px;color:var(--muted);margin-top:3px}

/* SECTIONS */
.wrap{max-width:1100px;margin:0 auto;padding:0 24px}
.section{padding:80px 0}
.sec-tag{display:inline-block;background:rgba(99,102,241,.08);
         border:1px solid rgba(99,102,241,.25);color:var(--accent2);
         border-radius:20px;padding:4px 14px;font-size:11px;font-weight:700;
         letter-spacing:.07em;margin-bottom:16px}
.sec-hd{text-align:center;margin-bottom:52px}
.sec-hd h2{font-size:clamp(24px,4vw,42px);font-weight:900;margin-bottom:12px}
.sec-hd p{color:var(--subtle);font-size:15px;max-width:520px;margin:0 auto;line-height:1.7}

/* IMPORTANCE */
.imp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.imp-card{background:var(--card);border:1px solid var(--border);border-radius:16px;
          padding:24px;transition:border-color .3s,transform .3s}
.imp-card:hover{border-color:var(--accent);transform:translateY(-4px)}
.imp-icon{font-size:28px;margin-bottom:14px}
.imp-card h3{font-size:14px;font-weight:700;margin-bottom:8px}
.imp-card p{font-size:13px;color:var(--subtle);line-height:1.6}

/* PIPELINE FLOW */
.flow-wrap{overflow-x:auto;padding:8px 0 20px;
           scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.flow{display:flex;align-items:stretch;gap:0;width:max-content;margin:0 auto}
.agent-card{background:var(--card);border:1px solid var(--border);border-radius:16px;
            padding:22px 18px;width:160px;flex-shrink:0;
            transition:border-color .3s,transform .3s}
.agent-card:hover{transform:translateY(-6px)}
.agent-num{width:28px;height:28px;border-radius:50%;
           background:linear-gradient(135deg,var(--accent),var(--accent2));
           display:flex;align-items:center;justify-content:center;
           font-size:12px;font-weight:900;color:#fff;margin-bottom:14px}
.agent-card h4{font-size:12px;font-weight:800;margin-bottom:6px;line-height:1.4}
.agent-card p{font-size:11px;color:var(--muted);line-height:1.5;margin-bottom:10px}
.agent-model{background:rgba(59,130,246,.07);border:1px solid rgba(59,130,246,.2);
             border-radius:6px;padding:4px 8px;font-size:10px;color:var(--accent);font-weight:700}
.flow-sep{display:flex;align-items:center;padding:0 8px;color:var(--border);font-size:20px;align-self:center}
.flow-note{text-align:center;color:var(--muted);font-size:13px;margin-top:20px}

/* TEAM */
.team-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.team-card{background:var(--card);border:1px solid var(--border);border-radius:16px;
           padding:28px 20px;text-align:center;transition:border-color .3s,transform .3s}
.team-card:hover{border-color:var(--accent2);transform:translateY(-4px)}
.avatar{width:64px;height:64px;border-radius:50%;margin:0 auto 14px;
        display:flex;align-items:center;justify-content:center;
        font-size:22px;font-weight:900;color:#fff}
.team-card h3{font-size:15px;font-weight:800;margin-bottom:4px}
.team-role{font-size:12px;color:var(--accent2);font-weight:700;margin-bottom:8px}
.team-card p{font-size:12px;color:var(--muted);line-height:1.6}

/* DASHBOARD LIVE */
.live-top{display:flex;align-items:center;justify-content:space-between;
          flex-wrap:wrap;gap:14px;margin-bottom:20px}
.live-title-row h2{font-size:22px;font-weight:900}
.net-pill{display:flex;align-items:center;gap:8px;
          background:var(--card);border:1px solid var(--border);
          border-radius:12px;padding:10px 16px;font-size:14px;font-weight:700}
.net-icon{font-size:18px}
.ctrl-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:22px}
.cbtn{padding:11px 22px;border-radius:11px;border:none;cursor:pointer;
      font-size:13px;font-weight:700;transition:transform .2s,box-shadow .2s}
.cbtn:hover{transform:translateY(-2px)}
.cbtn-demo{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;
           box-shadow:0 4px 16px rgba(59,130,246,.25)}
.cbtn-real{background:linear-gradient(135deg,var(--green),#16a34a);color:#fff;
           box-shadow:0 4px 16px rgba(34,197,94,.25)}
.cbtn-stop{background:linear-gradient(135deg,var(--red),#b91c1c);color:#fff;
           box-shadow:0 4px 16px rgba(239,68,68,.25)}
.cbtn-pdf{background:var(--card);border:1px solid var(--border);color:var(--subtle)}
.cbtn-pdf:hover{border-color:var(--accent);color:var(--accent)}

/* WAITING */
.waiting{text-align:center;padding:60px 24px;
         background:var(--card);border:1px solid var(--border);border-radius:20px}
.spinner{width:40px;height:40px;border-radius:50%;
         border:3px solid var(--border);border-top-color:var(--accent);
         animation:spin 1s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.waiting p{color:var(--muted);font-size:14px}

/* RISK CARD */
.risk-card{border-radius:20px;padding:26px;margin-bottom:14px;
           border:1.5px solid;display:flex;align-items:center;gap:20px}
.risk-LOW{border-color:var(--green);background:rgba(34,197,94,.04)}
.risk-MEDIUM{border-color:var(--yellow);background:rgba(245,158,11,.04)}
.risk-HIGH{border-color:var(--orange);background:rgba(249,115,22,.04)}
.risk-CRITICAL{border-color:var(--red);background:rgba(239,68,68,.04)}
.gauge-wrap{position:relative;width:80px;height:80px;flex-shrink:0}
.gauge-wrap svg{transform:rotate(-90deg)}
.gauge-label{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
             text-align:center;line-height:1}
.gauge-num{font-size:20px;font-weight:900}
.gauge-sub{font-size:10px;color:var(--muted)}
.risk-info h2{font-size:17px;font-weight:800;margin-bottom:5px}
.risk-info p{font-size:13px;color:var(--subtle);margin-bottom:10px}
.rf-tag{display:inline-flex;align-items:center;gap:5px;
        background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.25);
        color:var(--accent2);border-radius:20px;padding:4px 12px;font-size:12px;font-weight:700}

/* KPI */
.kpi-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:14px}
@media(min-width:480px){.kpi-grid{grid-template-columns:repeat(4,1fr)}}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:14px;
     padding:18px 14px;text-align:center;transition:border-color .3s}
.kpi:hover{border-color:var(--accent)}
.kpi-val{font-size:22px;font-weight:900;margin-bottom:3px}
.kpi-lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.kpi-bar{height:3px;border-radius:2px;margin-top:10px}
.cg{color:var(--green)} .cy{color:var(--yellow)}
.co{color:var(--orange)} .cr{color:var(--red)} .cb{color:var(--accent)}

/* PANELS */
.panels{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}
@media(max-width:680px){.panels{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px}
.panel-hd{font-size:11px;font-weight:800;color:var(--muted);
          text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}
.full{grid-column:1/-1}

/* horizons */
.h-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.h-row:last-child{margin-bottom:0}
.h-lbl{font-size:12px;color:var(--muted);width:82px;flex-shrink:0}
.h-bg{flex:1;height:6px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.h-fill{height:100%;border-radius:3px;transition:width .6s}
.h-score{font-size:12px;font-weight:700;width:52px;text-align:right}

/* sec */
.sec-tag2{display:inline-flex;align-items:center;gap:6px;
          padding:5px 14px;border-radius:20px;font-size:12px;font-weight:700;margin-bottom:10px}
.s-ok{background:rgba(34,197,94,.1);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.s-warn{background:rgba(245,158,11,.1);color:var(--yellow);border:1px solid rgba(245,158,11,.3)}
.s-bad{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.sec-txt{font-size:12px;color:var(--muted)}

/* actions */
.arow{display:flex;align-items:flex-start;gap:10px;
      padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.arow:last-child{border:none}
.abadge{font-size:9px;font-weight:900;padding:3px 8px;border-radius:4px;
        flex-shrink:0;margin-top:2px;letter-spacing:.04em}
.ap1{background:rgba(239,68,68,.15);color:var(--red)}
.ap2{background:rgba(249,115,22,.15);color:var(--orange)}
.ap3{background:rgba(245,158,11,.15);color:var(--yellow)}
.ap4{background:rgba(59,130,246,.12);color:var(--accent)}
.atext{font-size:12px;color:var(--subtle);line-height:1.4}

/* shap */
.srow{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.srow:last-child{margin-bottom:0}
.sname{font-size:11px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sbg{width:70px;height:5px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden;flex-shrink:0}
.sfill{height:100%;border-radius:3px}
.sval{font-size:11px;font-weight:700;width:52px;text-align:right;flex-shrink:0}

/* metrics table */
.mrow{display:flex;justify-content:space-between;align-items:center;
      padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.mrow:last-child{border:none}
.mlbl{font-size:12px;color:var(--muted)}
.mval{font-size:13px;font-weight:700}

.ts{font-size:11px;color:var(--border);text-align:right;margin-top:8px}

/* FOOTER */
footer{border-top:1px solid var(--border);padding:36px 24px;text-align:center;
       color:var(--muted);font-size:13px}
footer strong{color:var(--text)}
</style>
</head>
<body>

<!-- NAV -->
<nav>
  <div class="logo">
    <div class="logo-icon">Q</div>
    <div>
      <div class="logo-name">QoS Buddy</div>
      <div class="logo-by">by MindForge</div>
    </div>
  </div>
  <div class="nav-links">
    <a onclick="goTo('pourquoi')">Pourquoi</a>
    <a onclick="goTo('comment')">Comment ca marche</a>
    <a onclick="goTo('equipe')">Notre equipe</a>
    <a onclick="goTo('live')">Dashboard</a>
  </div>
  <div class="live-pill">
    <span class="dot off" id="ndot"></span>
    <span id="nstatus">En attente</span>
  </div>
</nav>


<!-- HERO -->
<section class="hero" id="top">
  <div>
    <div class="hero-badge">Surveille ton reseau en temps reel</div>
    <h1>QoS <em>Buddy</em></h1>
    <p class="hero-desc">
      Ton assistant intelligent qui surveille la qualite de ta connexion,
      detecte les problemes avant qu'ils surviennent, et te dit exactement quoi faire.
    </p>
    <div class="hero-btns">
      <button class="btn-hero btn-primary" onclick="goTo('live')">Voir le dashboard</button>
      <button class="btn-hero btn-ghost"   onclick="goTo('comment')">Comment ca marche</button>
    </div>
    <div class="stats-row">
      <div class="stat-item"><div class="stat-val">6</div><div class="stat-lbl">Agents IA</div></div>
      <div class="stat-item"><div class="stat-val">8s</div><div class="stat-lbl">Mise a jour</div></div>
      <div class="stat-item"><div class="stat-val">100%</div><div class="stat-lbl">Automatique</div></div>
      <div class="stat-item"><div class="stat-val">PDF</div><div class="stat-lbl">Rapport auto</div></div>
    </div>
  </div>
</section>


<!-- POURQUOI QOS -->
<section id="pourquoi">
<div class="wrap section">
  <div class="sec-hd">
    <div class="sec-tag">POURQUOI</div>
    <h2>Une mauvaise connexion coute cher</h2>
    <p>La qualite de ta connexion affecte tout : tes appels, tes reunions, ta productivite. QoS Buddy surveille tout ca pour toi.</p>
  </div>
  <div class="imp-grid">
    <div class="imp-card">
      <div class="imp-icon">📞</div>
      <h3>Des appels clairs</h3>
      <p>Un reseau degrade rend les appels video et vocaux inutilisables. QoS Buddy detecte ces problemes a l'avance.</p>
    </div>
    <div class="imp-card">
      <div class="imp-icon">⚡</div>
      <h3>Reactions rapides</h3>
      <p>Plutot que d'attendre que ca plante, QoS Buddy te previent plusieurs minutes avant qu'un probleme survienne.</p>
    </div>
    <div class="imp-card">
      <div class="imp-icon">🛡️</div>
      <h3>Securite reseau</h3>
      <p>Des attaques sur ton reseau peuvent le ralentir ou le bloquer. QoS Buddy les detecte automatiquement.</p>
    </div>
    <div class="imp-card">
      <div class="imp-icon">📊</div>
      <h3>Decisions eclairees</h3>
      <p>QoS Buddy explique exactement pourquoi il alerte et ce qu'il faut faire, sans jargon technique.</p>
    </div>
    <div class="imp-card">
      <div class="imp-icon">🤖</div>
      <h3>Intelligence artificielle</h3>
      <p>5 modeles d'IA travaillent ensemble pour analyser ton reseau sous tous les angles simultanement.</p>
    </div>
    <div class="imp-card">
      <div class="imp-icon">📄</div>
      <h3>Rapports automatiques</h3>
      <p>Un rapport PDF complet est genere automatiquement a la fin de chaque session de surveillance.</p>
    </div>
  </div>
</div>
</section>


<!-- COMMENT CA MARCHE -->
<section id="comment" style="background:var(--surface)">
<div class="wrap section">
  <div class="sec-hd">
    <div class="sec-tag">COMMENT CA MARCHE</div>
    <h2>6 agents, 1 objectif</h2>
    <p>Chaque agent est specialise dans une tache. Ensemble, ils forment un systeme complet de surveillance intelligente.</p>
  </div>

  <div class="flow-wrap">
    <div class="flow">

      <div class="agent-card" style="border-color:rgba(59,130,246,.4)">
        <div class="agent-num">1</div>
        <h4>Collecteur de donnees</h4>
        <p>Mesure la vitesse et la qualite de ta connexion toutes les 10 secondes.</p>
        <div class="agent-model">IA de detection d'anomalies</div>
      </div>
      <div class="flow-sep">→</div>

      <div class="agent-card" style="border-color:rgba(99,102,241,.4)">
        <div class="agent-num">2</div>
        <h4>Evaluateur d'etat</h4>
        <p>Compare ton reseau aux standards internationaux et le classe automatiquement.</p>
        <div class="agent-model">IA de classification</div>
      </div>
      <div class="flow-sep">→</div>

      <div class="agent-card" style="border-color:rgba(34,197,94,.4)">
        <div class="agent-num">3</div>
        <h4>Predicteur de risques</h4>
        <p>Analyse les tendances pour predire ce qui va se passer dans les prochaines minutes.</p>
        <div class="agent-model">IA de prediction</div>
      </div>
      <div class="flow-sep">→</div>

      <div class="agent-card" style="border-color:rgba(239,68,68,.4)">
        <div class="agent-num">4</div>
        <h4>Detecteur de menaces</h4>
        <p>Surveille le trafic reseau pour reperer les attaques ou comportements suspects.</p>
        <div class="agent-model">IA de securite</div>
      </div>
      <div class="flow-sep">→</div>

      <div class="agent-card" style="border-color:rgba(245,158,11,.4)">
        <div class="agent-num">5</div>
        <h4>Conseiller d'actions</h4>
        <p>Decide quoi faire en priorite selon l'ensemble des informations collectees.</p>
        <div class="agent-model">IA de recommandation</div>
      </div>
      <div class="flow-sep">→</div>

      <div class="agent-card" style="border-color:rgba(168,85,247,.4)">
        <div class="agent-num">6</div>
        <h4>Generateur de rapport</h4>
        <p>Explique chaque decision en langage clair et cree le rapport PDF automatiquement.</p>
        <div class="agent-model">IA explicable (XAI)</div>
      </div>

    </div>
  </div>
  <p class="flow-note">
    Les resultats de chaque agent sont transmis au suivant — formant une analyse complete et progressive de ton reseau.
  </p>
</div>
</section>


<!-- EQUIPE -->
<section id="equipe">
<div class="wrap section">
  <div class="sec-hd">
    <div class="sec-tag">NOTRE EQUIPE</div>
    <h2>MindForge</h2>
    <p>Une equipe etudiante passionnee d'IA et de reseaux, developpant des outils intelligents pour les defis de demain.</p>
  </div>
  <div class="team-grid">
    <div class="team-card">
      <div class="avatar" style="background:linear-gradient(135deg,#3b82f6,#6366f1)">M</div>
      <h3>Maram</h3>
      <div class="team-role">Responsable Data Science</div>
      <p>Architecture du systeme, modelisation IA et deploiement de la solution.</p>
    </div>
    <div class="team-card">
      <div class="avatar" style="background:linear-gradient(135deg,#8b5cf6,#a855f7)">A</div>
      <h3>Membre 2</h3>
      <div class="team-role">Ingenieur IA</div>
      <p>Developpement des agents de prediction et optimisation des modeles.</p>
    </div>
    <div class="team-card">
      <div class="avatar" style="background:linear-gradient(135deg,#22c55e,#16a34a)">B</div>
      <h3>Membre 3</h3>
      <div class="team-role">Ingenieur donnees</div>
      <p>Collecte et preparation des donnees reseau pour l'entrainement des modeles.</p>
    </div>
    <div class="team-card">
      <div class="avatar" style="background:linear-gradient(135deg,#f59e0b,#d97706)">C</div>
      <h3>Membre 4</h3>
      <div class="team-role">Expert securite</div>
      <p>Detection des menaces reseau et analyse des comportements suspects.</p>
    </div>
  </div>
</div>
</section>


<!-- DASHBOARD LIVE -->
<section id="live" style="background:var(--surface)">
<div class="wrap section">

  <div class="live-top">
    <div class="live-title-row">
      <h2>Surveillance en direct</h2>
      <p style="color:var(--muted);font-size:13px;margin-top:4px">Mise a jour automatique toutes les 5 secondes</p>
    </div>
    <div class="net-pill" id="net-pill">
      <span class="net-icon">📶</span>
      <span id="net-name">Detection en cours...</span>
    </div>
  </div>

  <div class="ctrl-row">
    <button class="cbtn cbtn-demo" onclick="startPipeline('demo')">▶&nbsp; Demarrer (Demo)</button>
    <button class="cbtn cbtn-real" onclick="startPipeline('run')">📡&nbsp; Reseau reel</button>
    <button class="cbtn cbtn-stop" onclick="stopPipeline()">⏹&nbsp; Arreter + PDF</button>
    <button class="cbtn cbtn-pdf"  onclick="dlPdf()">⬇&nbsp; Telecharger le rapport</button>
  </div>

  <div id="live-zone">
    <div class="waiting">
      <div class="spinner"></div>
      <p>Lance la surveillance pour voir les donnees en temps reel</p>
    </div>
  </div>

  <div class="ts" id="ts"></div>

</div>
</section>


<!-- FOOTER -->
<footer>
  <p><strong>QoS Buddy</strong> — developpe par <strong>MindForge</strong></p>
  <p style="margin-top:6px;font-size:11px">Intelligence Artificielle · Surveillance Reseau · Explainability</p>
</footer>


<script>
// ── Navigation
function goTo(id){
  const el = document.getElementById(id);
  if(el) el.scrollIntoView({behavior:'smooth', block:'start'});
}

// ── Couleurs
function rCol(s){ return s>=80?'var(--red)':s>=60?'var(--orange)':s>=30?'var(--yellow)':'var(--green)'; }
function rCls(s){ return s>=80?'CRITICAL':s>=60?'HIGH':s>=30?'MEDIUM':'LOW'; }
function rLbl(s){
  return s>=80?'Connexion en difficulte grave':
         s>=60?'Connexion degradee, attention requise':
         s>=30?'Connexion acceptable, surveiller':
               'Connexion excellente';
}
function dLbl(d){
  return {IMMEDIATE:'Agir immediatement',URGENT:'Agir rapidement',
          ROUTINE:'Surveiller',NONE:'Rien a faire pour l\'instant'}[d]||d;
}
function latCol(v){ return v<100?'cg':v<200?'cy':'cr'; }
function losCol(v){ return v===0?'cg':v<1?'cy':'cr'; }
function mosCol(v){ return v>=4?'cg':v>=3.6?'cy':'cr'; }

// ── Controles
function startPipeline(mode){
  fetch('/api/start/'+mode).then(r=>r.json()).then(d=>{
    if(d.ok){
      document.getElementById('ndot').className='dot';
      document.getElementById('nstatus').textContent='Actif';
      startLoop();
    } else {
      alert(d.error||'Une erreur est survenue');
    }
  }).catch(()=>alert('Impossible de joindre le serveur'));
}

function stopPipeline(){
  fetch('/api/stop').then(r=>r.json()).then(()=>{
    document.getElementById('ndot').className='dot off';
    document.getElementById('nstatus').textContent='Arrete';
    document.getElementById('ts').textContent='Pipeline arrete — rapport PDF genere';
  }).catch(()=>{});
}

function dlPdf(){
  // Ouvrir dans un nouvel onglet pour forcer le telechargement
  const a = document.createElement('a');
  a.href = '/api/pdf';
  a.target = '_blank';
  a.download = 'rapport_qos_buddy.pdf';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ── Boucle de refresh
let _loop = null;
function startLoop(){
  if(_loop) clearInterval(_loop);
  fetch('/api/data').then(r=>r.json()).then(renderData);
  _loop = setInterval(()=>fetch('/api/data').then(r=>r.json()).then(renderData), 5000);
}

// ── Mise a jour nom reseau depuis /api/status
function refreshNetName(){
  fetch('/api/status').then(r=>r.json()).then(d=>{
    const nn = d.network_name||'—';
    document.getElementById('net-name').textContent = nn;
    if(d.pipeline_running){
      document.getElementById('ndot').className='dot';
      document.getElementById('nstatus').textContent = d.total_captures+' mesures';
      startLoop();
    }
  }).catch(()=>{});
}

// ── Rendu principal
function renderData(d){
  if(!d.ready){
    // Mettre a jour le nom quand meme
    if(d.network_name && d.network_name!=='—')
      document.getElementById('net-name').textContent = d.network_name;
    return;
  }

  // Nom reseau
  const nn = d.network_name||'—';
  document.getElementById('net-name').textContent = nn;
  document.getElementById('nstatus').textContent = d.total_captures+' mesures';

  const rs  = parseFloat(d.risk_score)||0;
  const rc  = rCls(rs);
  const kpi = d.kpis||{};
  const lat = parseFloat(kpi.latency_ms)||0;
  const los = parseFloat(kpi.packet_loss_pct)||0;
  const thr = parseFloat(kpi.throughput_mbps)||0;
  const mos = parseFloat(kpi.mos_proxy)||0;
  const rfp = Math.round((parseFloat(d.rf_confidence)||0)*100);
  const col = rCol(rs);

  // Jauge SVG
  const R=30, C=2*Math.PI*R;
  const offset = C*(1-rs/100);

  // Horizons
  const hHTML = [20,60,300].map(h=>{
    const hd = (d.horizons||{})[h]||{};
    const sc = hd.score||0;
    const c  = rCol(sc);
    const lb = h===20?'Dans 20 sec':h===60?'Dans 1 min':'Dans 5 min';
    return `<div class="h-row">
      <span class="h-lbl">${lb}</span>
      <div class="h-bg"><div class="h-fill" style="width:${sc}%;background:${c}"></div></div>
      <span class="h-score" style="color:${c}">${Math.round(sc)}/100</span>
    </div>`;
  }).join('');

  // Securite
  const sec   = d.security||{};
  const secSt = sec.status||'CLEAN';
  const secCls= secSt==='CLEAN'?'s-ok':secSt==='LOW'?'s-warn':'s-bad';
  const secLb = {CLEAN:'Reseau securise',LOW:'Risque faible',MEDIUM:'Menace moderee',
                 HIGH:'Menace elevee',CRITICAL:'ALERTE SECURITE'}[secSt]||secSt;
  const atkTxt= (sec.attacks||[]).length?sec.attacks.join(' · '):'Aucune menace detectee';

  // Actions
  const pLbl = {1:'URGENT',2:'IMPORTANT',3:'A PLANIFIER',4:'INFO'};
  const pCls = {1:'ap1',2:'ap2',3:'ap3',4:'ap4'};
  const aHTML = (d.actions||[]).slice(0,5).map(a=>{
    const p = a.priority||4;
    return `<div class="arow">
      <span class="abadge ${pCls[p]||'ap4'}">${pLbl[p]||'P'+p}</span>
      <span class="atext">${a.label||a.action}</span>
    </div>`;
  }).join('')||'<span style="color:var(--muted);font-size:13px">Rien a faire, le reseau est stable.</span>';

  // SHAP
  let shapHTML='';
  if((d.shap_features||[]).length){
    const rows = d.shap_features.map(f=>{
      const abs = Math.abs(f.shap_value);
      const pct = Math.min(100,(abs/0.5)*100);
      const c   = f.shap_value>0?'var(--red)':'var(--green)';
      const dir = f.shap_value>0?'aggrave la situation':'ameliore la situation';
      return `<div class="srow" title="${dir}">
        <span class="sname">${f.feature}</span>
        <div class="sbg"><div class="sfill" style="width:${pct}%;background:${c}"></div></div>
        <span class="sval" style="color:${c}">${f.shap_value>0?'+':''}${f.shap_value.toFixed(3)}</span>
      </div>`;
    }).join('');
    shapHTML=`<div class="panel full">
      <div class="panel-hd">Pourquoi cette alerte ? — Facteurs principaux</div>
      ${rows}
      <p style="font-size:11px;color:var(--muted);margin-top:10px">Rouge = aggrave le risque · Vert = ameliore le risque</p>
    </div>`;
  }

  document.getElementById('live-zone').innerHTML=`

    <div class="risk-card risk-${rc}">
      <div class="gauge-wrap">
        <svg width="80" height="80" viewBox="0 0 80 80">
          <circle class="gc" cx="40" cy="40" r="${R}" fill="none"
            stroke="rgba(255,255,255,.06)" stroke-width="8"/>
          <circle cx="40" cy="40" r="${R}" fill="none"
            stroke="${col}" stroke-width="8" stroke-linecap="round"
            stroke-dasharray="${C}" stroke-dashoffset="${offset}"
            style="transition:stroke-dashoffset .8s"/>
        </svg>
        <div class="gauge-label">
          <div class="gauge-num" style="color:${col}">${Math.round(rs)}</div>
          <div class="gauge-sub">/100</div>
        </div>
      </div>
      <div class="risk-info">
        <h2 style="color:${col}">${rLbl(rs)}</h2>
        <p>${dLbl(d.decision_raw)}</p>
        <span class="rf-tag">Etat detecte : ${d.rf_class} — ${rfp}% de certitude</span>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-val ${latCol(lat)}">${lat.toFixed(1)}<small style="font-size:12px;font-weight:400"> ms</small></div>
        <div class="kpi-lbl">Temps de reponse</div>
        <div class="kpi-bar" style="background:${rCol(lat/3)}"></div>
      </div>
      <div class="kpi">
        <div class="kpi-val ${losCol(los)}">${los.toFixed(2)}<small style="font-size:12px;font-weight:400"> %</small></div>
        <div class="kpi-lbl">Paquets perdus</div>
        <div class="kpi-bar" style="background:${los===0?'var(--green)':los<1?'var(--yellow)':'var(--red)'}"></div>
      </div>
      <div class="kpi">
        <div class="kpi-val cb">${thr.toFixed(1)}<small style="font-size:12px;font-weight:400"> Mbps</small></div>
        <div class="kpi-lbl">Vitesse telechargement</div>
        <div class="kpi-bar" style="background:var(--accent)"></div>
      </div>
      <div class="kpi">
        <div class="kpi-val ${mosCol(mos)}">${mos.toFixed(2)}<small style="font-size:12px;font-weight:400">/5</small></div>
        <div class="kpi-lbl">Qualite des appels</div>
        <div class="kpi-bar" style="background:${rCol(100-mos*20)}"></div>
      </div>
    </div>

    <div class="panels">

      <div class="panel">
        <div class="panel-hd">Dans combien de temps ?</div>
        ${hHTML}
      </div>

      <div class="panel">
        <div class="panel-hd">Securite</div>
        <div class="sec-tag2 ${secCls}">${secLb}</div>
        <div class="sec-txt" style="margin-bottom:6px">${sec.n_events} evenement(s) detecte(s)</div>
        <div class="sec-txt">${atkTxt}</div>
      </div>

      <div class="panel">
        <div class="panel-hd">Etat detaille</div>
        <div class="mrow"><span class="mlbl">Signal</span><span class="mval">${kpi.rsrp_category}</span></div>
        <div class="mrow"><span class="mlbl">Alertes graves</span>
          <span class="mval" style="color:${d.n_critical>0?'var(--red)':'var(--green)'}">${d.n_critical}</span></div>
        <div class="mrow"><span class="mlbl">Alertes mineures</span>
          <span class="mval" style="color:${d.n_warnings>0?'var(--yellow)':'var(--green)'}">${d.n_warnings}</span></div>
        <div class="mrow"><span class="mlbl">Mesures effectuees</span>
          <span class="mval cb">${d.total_captures}</span></div>
        <div class="mrow"><span class="mlbl">Alertes totales</span>
          <span class="mval cr">${d.total_alerts}</span></div>
      </div>

      <div class="panel">
        <div class="panel-hd">Que faire ?</div>
        ${aHTML}
      </div>

      ${shapHTML}

    </div>
  `;

  document.getElementById('ts').textContent =
    'Derniere mise a jour : '+new Date().toLocaleTimeString();
}

// Init
refreshNetName();
setInterval(refreshNetName, 15000);
</script>
</body>
</html>"""


@app.route('/')
def index():
    return render_template_string(DASHBOARD)


# ════════════════════════════════════════════════════════════════
# LANCEMENT
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

    # Detection du reseau au demarrage
    server_state['network_name'] = detect_network_name()

    # Thread de mise a jour periodique du nom reseau
    threading.Thread(target=_refresh_network_name, daemon=True).start()

    # Demarrage automatique du pipeline demo
    threading.Thread(target=_start_pipeline_demo, daemon=True).start()

    local_ip = get_local_ip()
    print('=' * 60)
    print('  QoS Buddy — Dashboard Web  |  by MindForge')
    print('=' * 60)
    print(f'  Reseau detecte : {server_state["network_name"]}')
    print(f'  PC             : http://localhost:8000')
    print(f'  Telephone      : http://{local_ip}:8000')
    print(f'  (meme reseau Wi-Fi requis)')
    print('=' * 60)
    print()

    app.run(host='0.0.0.0', port=8000, debug=False)
