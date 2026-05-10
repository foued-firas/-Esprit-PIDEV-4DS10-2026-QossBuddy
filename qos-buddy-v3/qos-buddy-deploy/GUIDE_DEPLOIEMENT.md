# 🚀 QoS Buddy — Guide de Déploiement Complet
## Projet Data Science — MindForge

---

## 📁 Structure du Projet

```
qos-buddy-deploy/
├── backend/                    ← Flask API Python
│   ├── api/
│   │   └── server.py          ← Point d'entrée Flask (AMÉLIORÉ)
│   ├── dso1_performance/       ← Agent 1 : Autoencoder + Ensemble ML
│   ├── dso2_classification/    ← Agent 2 : Seuils Cisco/ITU-T + RF
│   ├── dso3_risk/              ← Agent 3 : XGBoost + LSTM (prédiction)
│   ├── dso4_reporting/         ← Agent 4 : SHAP + PDF (XAI)
│   ├── dso5_decision/          ← Agent 5 : Moteur de décision
│   ├── dso6_security/          ← Agent 6 : Détection menaces réseau
│   ├── shared/                 ← Config + Files d'attente
│   ├── outputs/                ← Modèles .pkl + rapports
│   └── requirements.txt
│
└── frontend/                   ← React App
    ├── public/index.html
    ├── src/
    │   ├── App.js              ← Composant principal React
    │   └── index.js
    └── package.json
```

---

## ⚙️ Installation & Lancement

### 1. Backend Flask

```bash
# Étape 1 — Se placer dans le dossier backend
cd qos-buddy-deploy/backend

# Étape 2 — Installer les dépendances Python
pip install -r requirements.txt

# Étape 3 — Lancer le serveur Flask
python api/server.py
```

> Le serveur démarre sur **http://localhost:8000**
> API disponible sur **http://localhost:8000/api**

---

### 2. Frontend React

```bash
# Dans un nouveau terminal
cd qos-buddy-deploy/frontend

# Étape 1 — Installer les dépendances Node.js
npm install

# Étape 2 — Lancer le serveur de développement
npm start
```

> L'interface s'ouvre sur **http://localhost:3000**

---

## 🔌 Endpoints API Flask

| Endpoint                 | Méthode | Description                              |
|--------------------------|---------|------------------------------------------|
| `/api/status`            | GET     | État du pipeline + connexion internet    |
| `/api/data`              | GET     | Données temps réel des agents IA         |
| `/api/start/demo`        | GET     | Démarrer en mode démonstration           |
| `/api/start/run`         | GET     | Démarrer avec modèles réels              |
| `/api/stop`              | GET     | Arrêter + générer PDF                    |
| `/api/pdf`               | GET     | Télécharger le rapport PDF               |
| `/api/speedtest/run`     | POST    | Lancer un speedtest Ookla                |
| `/api/speedtest/result`  | GET     | Résultat du dernier speedtest            |
| `/api/connectivity`      | GET     | Vérifier la connexion internet           |

---

## 🎭 Scénario de Soutenance (à présenter au professeur)

### Durée estimée : 10-15 minutes

---

### 📌 ÉTAPE 1 — Introduction (1 min)

> "Notre projet est un système multi-agents IA pour la surveillance de la qualité de service (QoS) réseau. Il comprend 6 agents spécialisés qui communiquent entre eux via des files d'attente asynchrones. Le backend est en Python/Flask, le frontend en React."

**Montrez la structure du projet dans l'explorateur de fichiers.**

---

### 📌 ÉTAPE 2 — Démarrage du Backend (2 min)

1. Ouvrez un terminal dans `backend/`
2. Lancez : `python api/server.py`
3. Montrez la console :
   - Réseau détecté (nom Wi-Fi)
   - Statut connexion internet (✅ ou ❌)
   - URL du serveur

> "Le serveur Flask détecte automatiquement le réseau actif et vérifie la connectivité internet toutes les 5 secondes."

---

### 📌 ÉTAPE 3 — Démarrage du Frontend (1 min)

1. Dans un second terminal dans `frontend/`
2. Lancez : `npm start` → s'ouvre sur http://localhost:3000
3. Montrez la page d'accueil React avec la section hero et les statistiques

---

### 📌 ÉTAPE 4 — Démonstration Mode Démo (3 min)

1. Cliquez sur **"▶ Démo"**
2. Attendez ~10 secondes → les données apparaissent
3. Expliquez en montrant :
   - **La jauge de risque** (score 0-100, calculé par XGBoost)
   - **Les 4 KPIs** : latence, pertes de paquets, débit, MOS
   - **Les horizons de prédiction** : risque dans 20s, 1min, 5min
   - **Le module sécurité** : détection d'attaques (DSO6)
   - **Les actions recommandées** (DSO5)
   - **L'explication SHAP** : pourquoi le système alerte

> "Ces données ne sont PAS statiques — elles viennent des agents IA. Le pipeline DSO1 → DSO2 → DSO3 → DSO6 → DSO5 → DSO4 tourne en arrière-plan, chaque agent transformant et enrichissant les données."

---

### 📌 ÉTAPE 5 — Démonstration Déconnexion Wi-Fi (2 min)

1. **Désactivez votre Wi-Fi** (ou coupez la connexion)
2. Dans les 5-10 secondes, une **bannière rouge apparaît en haut** :
   > ⚠️ CONNEXION PERDUE — Vous êtes déconnecté du Wi-Fi. Les données affichées ne sont plus mises à jour.
3. La pastille réseau passe en rouge : "Hors ligne"
4. **Réactivez le Wi-Fi** → le message disparaît automatiquement

> "Le système surveille la connectivité en temps réel. Quand vous perdez la connexion, il vous le signale immédiatement — les données affichées sont gelées et clairement marquées comme obsolètes."

---

### 📌 ÉTAPE 6 — Speedtest Ookla (2 min)

1. Cliquez sur **"⚡ Speedtest"** dans la navigation
2. Cliquez sur **"⚡ Lancer le Speedtest"**
3. Attendez 30-60 secondes → résultats affichés :
   - Débit téléchargement (Mbps)
   - Débit upload (Mbps)
   - Ping (ms)
   - Serveur Ookla utilisé, ISP
4. Montrez la **comparaison Pipeline vs Speedtest**

> "Nous avons intégré l'API Speedtest by Ookla (speedtest-cli) pour mesurer les vitesses réelles de connexion. Les résultats sont comparés aux métriques collectées par notre pipeline pour valider la cohérence."

---

### 📌 ÉTAPE 7 — Génération du Rapport PDF (1 min)

1. Retournez sur **Dashboard**
2. Cliquez **"⏹ Arrêter + PDF"** puis **"⬇ Rapport PDF"**
3. Le PDF se télécharge automatiquement
4. Ouvrez-le — montrez :
   - KPIs récapitulatifs de session
   - Modèles ML utilisés (tableau)
   - Historique des alertes
   - Explication SHAP
   - Recommandations

> "Le rapport PDF est généré automatiquement en fin de session par l'agent DSO4 qui utilise SHAP pour expliquer chaque décision — c'est le côté XAI (Explainable AI) du projet."

---

### 📌 ÉTAPE 8 — Historique (1 min)

1. Cliquez sur **"📈 Historique"**
2. Montrez les graphiques : risque, latence, débit
3. Montrez le tableau avec les 30 dernières mesures

---

### 📌 ÉTAPE 9 — Architecture Data Science (1 min)

> "Ce qui rend ce projet Data Science réel :
> - **Agent 1 (DSO1)** : Autoencoder PyTorch + Isolation Forest + EllipticEnvelope + SVM — détection d'anomalies unsupervised
> - **Agent 2 (DSO2)** : Classification par seuils ITU-T/Cisco + Random Forest supervisé
> - **Agent 3 (DSO3)** : XGBoost tabular + LSTM séquentiel — prédiction temporelle multi-horizon
> - **Agent 4 (DSO4)** : SHAP values sur le modèle XGBoost — explainability
> - **Agent 5 (DSO5)** : Moteur de règles métier + prioritisation des actions
> - **Agent 6 (DSO6)** : Détection de patterns d'attaques réseau (port scan, DDoS, brute force)"

---

## 🔧 Corrections Apportées

### 1. ✅ Détection de déconnexion Wi-Fi
- Thread dédié qui vérifie la connexion toutes les 5 secondes
- Bannière rouge apparaît immédiatement à la déconnexion
- Disparaît automatiquement à la reconnexion
- Pastille d'état dans la navbar change de couleur

### 2. ✅ PDF corrigé
- La génération PDF ne plante plus avec une erreur blanche
- Si le PDF ne peut pas être généré, un message d'erreur clair s'affiche
- Téléchargement via `fetch()` + Blob dans React (pas de redirect)
- CORS headers corrects pour le download cross-origin

### 3. ✅ Données réelles (non statiques)
- Toutes les données viennent des agents DSO3-DSO6 en temps réel
- Le frontend React poll `/api/data` toutes les 5 secondes
- L'historique enregistre les 30 dernières mesures pour les graphiques

### 4. ✅ Speedtest Ookla intégré
- Endpoint `/api/speedtest/run` et `/api/speedtest/result`
- Utilise `speedtest-cli` (bibliothèque officielle Ookla)
- Fallback sur estimation pipeline si `speedtest-cli` absent
- Comparaison Pipeline vs Speedtest affichée

### 5. ✅ CORS complet
- Flask répond aux requêtes cross-origin du frontend React (port 3000)
- Headers `Access-Control-*` sur tous les endpoints

---

## 📝 Notes Techniques

- **Backend** : Python 3.8+ recommandé
- **Frontend** : Node.js 18+ recommandé
- **Port Flask** : 8000
- **Port React** : 3000
- Le frontend React utilise le proxy `http://localhost:8000` configuré dans `package.json`
