"""
shared/queues.py
================
Queues inter-agents et état partagé du pipeline.
Définies ici une seule fois et importées par tous les agents.

Flux :
  DSO1 (Agent1)
    → data_queue        → DSO1 (Agent2 : anomaly detection)
    → dso2_queue        → DSO2 (classification)
  DSO2
    → dso3_input_queue  → DSO3 (risk prediction)
  DSO3
    → dso6_input_queue  → DSO6 (security detection)
  DSO6
    → dso5_queue        → DSO5 (decision & optimization)
  DSO5
    → dso4_queue        → DSO4 (reporting)
"""

import queue as _q

# ── Queues pipeline
data_queue          = _q.Queue(maxsize=10)   # DSO1 Agent1 → DSO1 Agent2
dso2_queue          = _q.Queue(maxsize=10)   # DSO1 → DSO2
dso3_input_queue    = _q.Queue(maxsize=20)   # DSO2 → DSO3
dso6_input_queue    = _q.Queue(maxsize=20)   # DSO3 → DSO6
dso5_queue          = _q.Queue(maxsize=10)   # DSO6 → DSO5
dso4_queue          = _q.Queue(maxsize=10)   # DSO5 → DSO4

# ── Historique des alertes (partagé lecture-seule entre agents)
alert_history = []

# ── État global du pipeline
pipeline_state = {
    'running':       False,
    'total':         0,
    'alerts_count':  0,
    'last_raw':      None,
    'last_payload':  None,
    'last_analysis': None,
    'a1_log':        [],
    'a2_log':        [],
    'api_status':    '—',
}


def log_agent(state_dict: dict, key: str, msg: str, maxlen: int = 20):
    """Utilitaire : insère un message horodaté dans un log d'agent."""
    from datetime import datetime
    ts = datetime.now().strftime('%H:%M:%S')
    state_dict[key].insert(0, f'[{ts}] {msg}')
    state_dict[key] = state_dict[key][:maxlen]


def safe_put(q: _q.Queue, item):
    """Put non bloquant — ignore si la queue est pleine."""
    try:
        q.put_nowait(item)
    except _q.Full:
        pass
