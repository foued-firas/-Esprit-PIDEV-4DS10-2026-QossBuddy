# INMS QoS — Intelligent Network Management System
## Architecture Séquentielle Multi-Agents (Wi-Fi Quality of Service)

Projet Data Science · Esprit 4DS11 · 2025–2026

---

## Architecture du pipeline

```
DSO1 (Performance Monitoring)
  └─ Agent1 : Capture réseau (ping, psutil, traceroute)
  └─ Agent2 : Détection anomalies (Autoencoder + IF + EE + SVM)
       │
       ▼ dso2_queue
DSO2 (Network State Classification)
  └─ Seuils Cisco / ITU-T / 3GPP
       │
       ▼ dso3_input_queue
DSO3 (Risk Prediction)
  └─ LSTM bidirectionnel + XGBoost + horizons (+20s, +1min, +5min)
       │
       ▼ dso6_input_queue
DSO6 (Security Anomaly Detection)
  └─ Port Scan, SYN Flood, DDoS, Brute Force, Banner Grab
       │
       ▼ dso5_queue
DSO5 (Decision & Optimization)
  └─ Règles expertes → QoS Controller, Routing Controller, Security Enforcement
       │
       ▼ dso4_queue
DSO4 (Explainability & Reporting)
  └─ Dashboard décideurs + CSV + JSONL
```

## Structure du projet

```
qos-agent/
├── main.py                     # Point d'entrée (train / run / demo / status)
├── requirements.txt
├── shared/
│   ├── config.py               # Toutes les constantes du pipeline
│   └── queues.py               # Queues inter-agents et état partagé
├── data/
│   └── preprocessing.py        # KNN Imputer + RobustScaler + split anti-leakage
├── dso1_performance/
│   └── agent.py                # Autoencoder + IF + EE + SVM + capture réseau
├── dso2_classification/
│   └── agent.py                # Classification par seuils
├── dso3_risk/
│   └── agent.py                # LSTM + XGBoost + FeatureEngineer + RiskScorer
├── dso6_security/
│   └── agent.py                # AttackDetector + collecteurs
├── dso5_decision/
│   └── agent.py                # Moteur de décision expert
├── dso4_reporting/
│   └── agent.py                # Dashboard + CSV + JSONL
└── outputs/                    # Artefacts et sorties générés
```

## Utilisation

### 1. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 2. Entraîner les modèles offline

```bash
python main.py train
# Charge le dataset depuis Google Drive, entraîne Autoencoder + IF + EE + SVM
# Sauvegarde les artefacts dans outputs/
```

### 3. Lancer le pipeline temps-réel

```bash
python main.py run
# Lance les 6 agents en parallèle (threads daemon)
# Capture réseau réelle toutes les 10s
```

### 4. Mode démo (sans réseau réel)

```bash
python main.py demo --n 30 --interval 2
# Injecte 30 captures simulées toutes les 2s
# Permet de tester DSO3 → DSO6 → DSO5 → DSO4
```

### 5. Vérifier l'état des artefacts

```bash
python main.py status
```

## Modèles ML par agent

| Agent | Modèle(s) | Type |
|-------|-----------|------|
| DSO1 Agent1 | QoSAutoencoder | Reconstruction non supervisée |
| DSO1 Agent2 | Isolation Forest + Elliptic Envelope + OneClassSVM | Détection anomalies (vote pondéré) |
| DSO2 | Seuils Cisco/ITU-T/3GPP | Règles expertes |
| DSO3 | LSTMRiskModel + XGBoostClassifier | Prédiction risque séquentiel + tabulaire |
| DSO6 | Règles heuristiques + IsolationForest | Détection attaques réseau |
| DSO5 | Règles expertes (extensible PPO+GAE) | Décision & optimisation |
| DSO4 | — | Agrégation et reporting |

## Correspondance avec le notebook Essai.ipynb

| Section notebook | Module projet |
|-----------------|---------------|
| Section 1 — Data Understanding | `data/preprocessing.py` |
| Section 2 — Data Preparation | `data/preprocessing.py` |
| Section 3 — DSO1 (Blocs 1–5) | `dso1_performance/agent.py` |
| Section 4 — DSO2 (Bloc 4B) | `dso2_classification/agent.py` |
| Section 5 — DSO3 | `dso3_risk/agent.py` |
| Section 6 — DSO6 | `dso6_security/agent.py` |
| Section 7 — DSO5 | `dso5_decision/agent.py` |
| Section 8 — DSO4 | `dso4_reporting/agent.py` |
| Queues / État partagé | `shared/queues.py` |
| Constantes globales | `shared/config.py` |
