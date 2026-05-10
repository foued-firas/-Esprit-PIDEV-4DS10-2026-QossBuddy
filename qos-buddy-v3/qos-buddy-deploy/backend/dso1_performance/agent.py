"""
dso1_performance/agent.py
=========================
DSO1 — Performance Monitoring Agent
Architecture : Autoencoder + Vote pondéré (IF + EE + SVM)

Rôle dans le pipeline :
  - Agent1 : capture réseau (ping, psutil, traceroute)
  - Agent2 : détection d'anomalies via embeddings Autoencoder
  - Sortie → dso2_queue (raw_row) + data_queue (payload embeddings)
"""

import os, csv, math, time, statistics, threading, warnings
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.covariance import EllipticEnvelope
from sklearn.svm import OneClassSVM
from datetime import datetime

warnings.filterwarnings('ignore')
os.environ['LOKY_MAX_CPU_COUNT'] = '4'

from shared.config import (
    TARGET_HOST, TARGET_HOST2, PING_COUNT, MAX_HOPS, INTERVAL_SEC,
    OUTPUT_DIR, CSV_LIVE, CSV_ALERTS,
    AE_BOTTLENECK, AE_EPOCHS, AE_LR, AE_BATCH_SIZE, AE_FINE_TUNE_N,
    AE_RECON_CRITICAL_PCT,
    IF_CONTAMINATION, SVM_NU,
    VOTE_W_IF, VOTE_W_EE, VOTE_W_SVM, VOTE_SEUIL,
    SEED,
)
from shared.queues import (
    pipeline_state, data_queue, dso2_queue, log_agent, safe_put,
)

try:
    from ping3 import ping
    from icmplib import traceroute
    _ping_ok = True
except ImportError:
    _ping_ok = False
    print('⚠️  ping3 / icmplib absents')

try:
    import psutil
    _psutil_ok = True
except ImportError:
    _psutil_ok = False


def get_network_name() -> str:
    """
    Retourne le nom du réseau actif (SSID Wi-Fi ou nom de l'interface ethernet).
    Fonctionne sur Windows, Linux et macOS.
    """
    import subprocess, platform

    system = platform.system()

    # ── Windows : netsh pour récupérer le SSID Wi-Fi
    if system == 'Windows':
        try:
            out = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'interfaces'],
                timeout=3, stderr=subprocess.DEVNULL,
            ).decode('cp1252', errors='ignore')
            for line in out.splitlines():
                if 'SSID' in line and 'BSSID' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return f'Wi-Fi : {ssid}'
        except Exception:
            pass
        # Fallback : nom de l'interface active (ethernet)
        try:
            if _psutil_ok:
                stats = psutil.net_if_stats()
                addrs = psutil.net_if_addrs()
                for iface, stat in stats.items():
                    if stat.isup and iface in addrs:
                        return f'Ethernet : {iface}'
        except Exception:
            pass

    # ── Linux
    elif system == 'Linux':
        try:
            out = subprocess.check_output(
                ['iwgetid', '-r'], timeout=3, stderr=subprocess.DEVNULL,
            ).decode().strip()
            if out:
                return f'Wi-Fi : {out}'
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ['nmcli', '-t', '-f', 'active,ssid', 'dev', 'wifi'],
                timeout=3, stderr=subprocess.DEVNULL,
            ).decode().strip()
            for line in out.splitlines():
                if line.startswith('yes:'):
                    return f'Wi-Fi : {line.split(":", 1)[1]}'
        except Exception:
            pass

    # ── macOS
    elif system == 'Darwin':
        try:
            out = subprocess.check_output(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/'
                 'Versions/Current/Resources/airport', '-I'],
                timeout=3, stderr=subprocess.DEVNULL,
            ).decode()
            for line in out.splitlines():
                if ' SSID:' in line:
                    return f'Wi-Fi : {line.split(":", 1)[1].strip()}'
        except Exception:
            pass

    return 'Réseau inconnu'

# ═══════════════════════════════════════════════════════════════
# AUTOENCODER
# ═══════════════════════════════════════════════════════════════

class QoSAutoencoder(nn.Module):
    """
    Autoencoder simplifié : INPUT → 32 → BOTTLENECK → 32 → INPUT
    LayerNorm remplace BatchNorm (stable avec données réseau haute variance).
    """
    def __init__(self, input_dim: int, bottleneck_dim: int = 16):
        super().__init__()
        hidden = 32
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden),
            nn.LayerNorm(hidden),
            nn.ReLU(),
            nn.Linear(hidden, bottleneck_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, hidden),
            nn.LayerNorm(hidden),
            nn.ReLU(),
            nn.Linear(hidden, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def encode(self, x):
        return self.encoder(x)

    def reconstruction_error(self, x):
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((x - recon) ** 2, dim=1).numpy()


def train_autoencoder(X_train_ae, X_test_ae, input_dim: int):
    """Entraîne l'Autoencoder avec early stopping (Blocs 3 du notebook)."""
    torch.manual_seed(SEED)
    np.random.seed(SEED)

    n_val       = int(0.20 * len(X_train_ae))
    X_ae_val    = X_train_ae[:n_val]
    X_ae_train  = X_train_ae[n_val:]

    model     = QoSAutoencoder(input_dim, AE_BOTTLENECK)
    optimizer = torch.optim.Adam(model.parameters(), lr=AE_LR, weight_decay=5e-3)
    criterion = nn.MSELoss()
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', factor=0.5, patience=7)

    loader = DataLoader(
        TensorDataset(X_ae_train), batch_size=AE_BATCH_SIZE,
        shuffle=True, generator=torch.Generator().manual_seed(SEED),
    )

    best_val_loss   = float('inf')
    best_state      = None
    patience_ctr    = 0
    PATIENCE        = 15
    train_losses, val_losses = [], []

    print(f'Entraînement Autoencoder (max {AE_EPOCHS} epochs)...')
    for epoch in range(AE_EPOCHS):
        model.train()
        epoch_loss = sum(
            (lambda b: (optimizer.zero_grad(),
                        (loss := criterion(model(b[0]), b[0])),
                        loss.backward(),
                        torch.nn.utils.clip_grad_norm_(model.parameters(), 0.5),
                        optimizer.step(),
                        loss.item())[-1])(batch)
            for batch in loader
        )
        avg_train = epoch_loss / len(loader)
        train_losses.append(avg_train)

        model.eval()
        with torch.no_grad():
            avg_val = float(criterion(model(X_ae_val), X_ae_val).item())
        val_losses.append(avg_val)
        scheduler.step(avg_val)

        if (epoch + 1) % 10 == 0:
            print(f'  Epoch {epoch+1:3d} — Train: {avg_train:.4f} | Val: {avg_val:.4f}')

        if avg_val < best_val_loss - 1e-5:
            best_val_loss = avg_val
            best_state    = {k: v.clone() for k, v in model.state_dict().items()}
            patience_ctr  = 0
        else:
            patience_ctr += 1
            if patience_ctr >= PATIENCE:
                print(f'  Early stopping epoch {epoch + 1}')
                break

    if best_state:
        model.load_state_dict(best_state)

    model.eval()
    test_errors  = model.reconstruction_error(X_test_ae)
    recon_thresh = float(np.percentile(test_errors, AE_RECON_CRITICAL_PCT))
    print(f'Autoencoder entraîné — seuil CRITICAL (p{AE_RECON_CRITICAL_PCT}) : {recon_thresh:.4f}')
    return model, recon_thresh, train_losses, val_losses


# ═══════════════════════════════════════════════════════════════
# MODÈLES AGENT2 : IF + EE + SVM (Bloc 4)
# ═══════════════════════════════════════════════════════════════

def train_ensemble_models(ae_model, X_train_ae, X_test_ae):
    """Entraîne IF + EllipticEnvelope + OneClassSVM sur les embeddings."""
    ae_model.eval()
    with torch.no_grad():
        X_train_emb = ae_model.encode(X_train_ae).numpy()
        X_test_emb  = ae_model.encode(X_test_ae).numpy()

    if_model = IsolationForest(
        n_estimators=300, contamination=IF_CONTAMINATION,
        max_samples='auto', max_features=0.8, random_state=SEED, n_jobs=-1,
    )
    if_model.fit(X_train_emb)

    ee_model = EllipticEnvelope(
        contamination=IF_CONTAMINATION, support_fraction=0.85, random_state=SEED,
    )
    ee_model.fit(X_train_emb)

    svm_model = OneClassSVM(kernel='rbf', nu=SVM_NU, gamma='scale')
    svm_model.fit(X_train_emb)

    print('Modèles Agent2 entraînés : IF + EE + SVM')
    return if_model, ee_model, svm_model, X_train_emb, X_test_emb


# ═══════════════════════════════════════════════════════════════
# CAPTURE RÉSEAU — Agent1 (Bloc 4B)
# ═══════════════════════════════════════════════════════════════

def _save_csv(row: dict, path: str):
    exists = os.path.isfile(path)
    with open(path, 'a', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=row.keys(), delimiter=';')
        if not exists:
            w.writeheader()
        w.writerow(row)


def agent1_capture() -> dict:
    """Capture une mesure réseau complète (identique au notebook)."""
    ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    now = datetime.now()
    row = {'timestamp': ts, 'network_name': get_network_name()}

    # ── Ping
    pings, host = [], TARGET_HOST
    if _ping_ok:
        for _ in range(PING_COUNT):
            try:
                r = ping(TARGET_HOST, timeout=2, unit='ms')
                if r: pings.append(r)
            except Exception:
                pass
        if not pings:
            host = TARGET_HOST2
            for _ in range(PING_COUNT):
                try:
                    r = ping(TARGET_HOST2, timeout=2, unit='ms')
                    if r: pings.append(r)
                except Exception:
                    pass

    row['latency_ms']           = round(sum(pings)/len(pings), 4) if pings else -1
    row['mean_latency_ms']      = row['latency_ms']
    row['min_latency_ms']       = round(min(pings), 4) if pings else -1
    row['max_latency_ms']       = round(max(pings), 4) if pings else -1
    row['std_latency_ms']       = round(statistics.stdev(pings), 4) if len(pings) > 1 else 0.0
    row['jitter_ms']            = round(row['max_latency_ms'] - row['min_latency_ms'], 4) if pings else -1
    row['latency_spread']       = row['std_latency_ms']
    row['packet_loss_rate_pct'] = round((PING_COUNT - len(pings)) / PING_COUNT * 100, 2)
    row['spike']                = 1 if row['latency_ms'] > 200 else 0
    prev = float(pipeline_state['last_raw']['latency_ms']) if pipeline_state['last_raw'] else row['latency_ms']
    row['latency_trend']        = round(row['latency_ms'] - prev, 4)

    # ── Réseau psutil
    if _psutil_ok:
        import psutil
        net1 = psutil.net_io_counters(); time.sleep(1); net2 = psutil.net_io_counters()
        s = (net2.bytes_sent - net1.bytes_sent) * 8
        r_bytes = (net2.bytes_recv - net1.bytes_recv) * 8
        drops = (net2.dropin + net2.dropout) - (net1.dropin + net1.dropout)
        pkts  = max(net2.packets_recv - net1.packets_recv, 1)
        row['throughput_mbps']           = round(r_bytes / 1e6, 4)
        row['available_bandwidth_mbps']  = round((s + r_bytes) / 1e6, 4)
        row['bandwidth_utilization_pct'] = round(min(r_bytes / 1e8 * 100, 100), 4)
        row['bandwidth_efficiency']      = round(r_bytes / max(s + r_bytes, 1), 4)
        row['network_load']              = round(row['bandwidth_utilization_pct'] / 100, 4)
        row['packet_loss_rate_pct']      = round(drops / pkts * 100, 4)
        row['buffer_occupancy_pct']      = round(psutil.virtual_memory().percent, 4)
        row['queue_length']              = round(psutil.cpu_percent(interval=0.2), 4)
    else:
        for k in ['throughput_mbps','available_bandwidth_mbps','bandwidth_utilization_pct',
                  'bandwidth_efficiency','network_load','buffer_occupancy_pct','queue_length']:
            row[k] = 0.0
        row['packet_loss_rate_pct'] = round((PING_COUNT - len(pings)) / PING_COUNT * 100, 2)

    row['instability_score'] = round(row['jitter_ms'] * row['packet_loss_rate_pct'] / 100, 4) if row['jitter_ms'] > 0 else 0.0
    row['risk_score']        = round((row['latency_ms'] / 300 + row['packet_loss_rate_pct'] / 100) / 2, 4) if row['latency_ms'] > 0 else 0.0
    row['congestion_level']  = 0
    row['prb_utilization_proxy'] = row.get('bandwidth_utilization_pct', 0)

    # ── Traceroute
    hl = []
    if _ping_ok:
        try:
            hops = traceroute(host, max_hops=MAX_HOPS, timeout=1)
            hl   = [h.avg_rtt for h in hops if h.avg_rtt > 0]
        except Exception:
            pass
    for i in range(1, 11):
        row[f'hop_{i}'] = round(hl[i-1], 4) if i <= len(hl) else 0.0
    row['hops_mean']  = round(sum(hl)/len(hl), 4) if hl else 0.0
    row['hops_max']   = round(max(hl), 4) if hl else 0.0
    row['hops_min']   = round(min(hl), 4) if hl else 0.0
    row['hops_std']   = round(statistics.stdev(hl), 4) if len(hl) > 1 else 0.0
    row['hops_range'] = round(row['hops_max'] - row['hops_min'], 4)

    # ── Features radio / proxy
    row['rsrp_estimated'] = round(-70 - row['latency_ms'] * 0.1, 4) if row['latency_ms'] > 0 else -70
    row['sinr_estimated'] = round(20 - row['packet_loss_rate_pct'] * 2, 4)
    row['cqi_estimated']  = max(1, min(15, int(15 - row['packet_loss_rate_pct'] / 7)))
    row['mos_proxy']      = round(max(1, 4.5 - row['packet_loss_rate_pct'] * 0.1 - row['latency_ms'] * 0.005), 4) if row['latency_ms'] > 0 else 4.5

    row['ho_failure_proxy']    = 1 if row['packet_loss_rate_pct'] > 5 else 0
    row['coverage_hole_proxy'] = 1 if row['rsrp_estimated'] < -100 else 0
    row['performance_degraded']= 1 if (row['latency_ms'] > 150 or row['packet_loss_rate_pct'] > 3) else 0

    rsrp = row['rsrp_estimated']
    row['rsrp_category'] = ('Bon' if rsrp >= -80 else
                            'Mauvais' if rsrp >= -90 else
                            'Faible' if rsrp >= -100 else 'Très mauvais')

    # ── Features temporelles
    row['hour']                   = now.hour
    row['minute']                 = now.minute
    row['dayofweek']              = now.weekday()
    row['hour_sin']               = round(math.sin(2 * math.pi * now.hour / 24), 4)
    row['hour_cos']               = round(math.cos(2 * math.pi * now.hour / 24), 4)
    row['minute_sin']             = round(math.sin(2 * math.pi * now.minute / 60), 4)
    row['minute_cos']             = round(math.cos(2 * math.pi * now.minute / 60), 4)
    row['dayofweek_sin']          = round(math.sin(2 * math.pi * now.weekday() / 7), 4)
    row['dayofweek_cos']          = round(math.cos(2 * math.pi * now.weekday() / 7), 4)
    row['peak_offpeak_indicator'] = 1 if 8 <= now.hour <= 22 else 0
    return row


# ═══════════════════════════════════════════════════════════════
# DSO1 AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class DSO1Agent:
    """
    Encapsule Agent1 (capture) + Agent2 (anomaly detection via embeddings).
    Initialiser avec les résultats de train_autoencoder() et train_ensemble_models().
    """

    def __init__(self, ae_model, recon_thresh, if_model, ee_model, svm_model,
                 scaler, feature_cols):
        self.ae_model     = ae_model
        self.recon_thresh = recon_thresh
        self.if_model     = if_model
        self.ee_model     = ee_model
        self.svm_model    = svm_model
        self.scaler       = scaler
        self.feature_cols = feature_cols
        self._live_buffer = []
        self._emb_buffer  = []
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Embedding + reconstruction error
    def _ae_embed(self, vec_np):
        x = torch.FloatTensor(vec_np).unsqueeze(0)
        with torch.no_grad():
            emb   = self.ae_model.encode(x).squeeze(0).numpy()
            recon = self.ae_model(x).squeeze(0)
            err   = float(torch.mean((x.squeeze(0) - recon) ** 2).item())
        return emb, err

    # ── Fine-tune live (incrémental)
    def _ae_fine_tune(self, vec_scaled):
        self._live_buffer.append(vec_scaled)
        if len(self._live_buffer) < AE_FINE_TUNE_N:
            return
        X_new = torch.FloatTensor(np.array(self._live_buffer))
        ft    = torch.optim.Adam(self.ae_model.parameters(), lr=1e-4, weight_decay=1e-3)
        crit  = nn.MSELoss()
        self.ae_model.train()
        for _ in range(3):
            ft.zero_grad()
            loss = crit(self.ae_model(X_new), X_new)
            loss.backward()
            ft.step()
        self.ae_model.eval()
        self._live_buffer = []

    def _a2_fine_tune(self, embedding, X_train_emb):
        self._emb_buffer.append(embedding)
        if len(self._emb_buffer) < 20:
            return
        X_new      = np.array(self._emb_buffer)
        X_combined = np.vstack([X_train_emb[-500:], X_new])
        self.if_model.fit(X_combined)
        self.ee_model.fit(X_combined)
        self.svm_model.fit(X_combined)
        self._emb_buffer = []

    def build_payload(self, raw_row: dict) -> dict:
        """Vectorise, scale, embed et vote (retourne payload pour les agents suivants)."""
        vec        = np.array([float(raw_row.get(c, 0) or 0) for c in self.feature_cols], dtype=np.float32)
        vec_scaled = self.scaler.transform(vec.reshape(1, -1)).squeeze()
        embedding, recon_error = self._ae_embed(vec_scaled)
        self._ae_fine_tune(vec_scaled)

        # ── Vote pondéré
        emb_2d   = embedding.reshape(1, -1)
        pred_if  = int(self.if_model.predict(emb_2d)[0] == -1)
        pred_ee  = int(self.ee_model.predict(emb_2d)[0] == -1)
        pred_svm = int(self.svm_model.predict(emb_2d)[0] == -1)
        vote_score = pred_if * VOTE_W_IF + pred_ee * VOTE_W_EE + pred_svm * VOTE_W_SVM
        is_anomaly = vote_score >= VOTE_SEUIL

        return {
            'raw_row':     raw_row,
            'embedding':   embedding,
            'recon_error': recon_error,
            'vec_scaled':  vec_scaled,
            'vote_score':  round(vote_score, 4),
            'is_anomaly':  is_anomaly,
            'ae_critical': recon_error >= self.recon_thresh,
        }

    def run_loop(self):
        """Boucle principale DSO1 (thread daemon)."""
        log_agent(pipeline_state, 'a1_log', 'DSO1 démarré')
        while pipeline_state['running']:
            pipeline_state['total'] += 1
            n = pipeline_state['total']
            log_agent(pipeline_state, 'a1_log', f'capture #{n}...')
            try:
                raw_row = agent1_capture()
                pipeline_state['last_raw'] = raw_row
                payload = self.build_payload(raw_row)
                pipeline_state['last_payload'] = payload
                _save_csv(raw_row, CSV_LIVE)
                safe_put(data_queue, payload)
                safe_put(dso2_queue, raw_row)
                lat = raw_row.get('latency_ms', -1)
                log_agent(pipeline_state, 'a1_log', f'#{n} — {lat} ms')
            except Exception as e:
                log_agent(pipeline_state, 'a1_log', f'#{n} erreur: {e}')

            for _ in range(INTERVAL_SEC):
                if not pipeline_state['running']:
                    break
                time.sleep(1)
