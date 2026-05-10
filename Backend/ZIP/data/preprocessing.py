"""
data/preprocessing.py
=====================
Pipeline de preprocessing — Data Preparation (Section 2 du notebook).
KNN Imputer → RobustScaler → Split stratifié → Encodage target.

Usage :
    from data.preprocessing import prepare_dataset, load_dataset_from_drive
"""

import os
import numpy as np
import pandas as pd
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.impute import KNNImputer
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import torch

from shared.config import (
    OUTPUT_DIR, COLS_DROP, TARGET_COL, BINARY_COLS,
    COLS_REDUNDANT, SEED,
)


# ── Colonnes redondantes à exclure du split anti-leakage (DSO1 Autoencoder)
def _get_feature_cols(df: pd.DataFrame, exclude_redundant: bool = False) -> list:
    excl = COLS_DROP + [TARGET_COL]
    if exclude_redundant:
        excl += COLS_REDUNDANT
    return [
        c for c in df.columns
        if c not in excl
        and df[c].dtype in ['float64', 'int64', 'float32', 'int32']
    ]


def load_dataset_from_drive(file_id: str) -> pd.DataFrame:
    """Charge le dataset depuis Google Drive (identique Section 1.2)."""
    import requests
    from io import StringIO
    url = f'https://drive.google.com/uc?export=download&id={file_id}'
    response = requests.get(url)
    df = pd.read_csv(StringIO(response.text), sep=';')
    print(f'Dataset chargé : {df.shape[0]} lignes × {df.shape[1]} colonnes')
    return df


def prepare_dataset(df: pd.DataFrame, save: bool = True):
    """
    Pipeline Data Preparation complet (Sections 2.2 → 2.8 du notebook).
    Retourne : X_scaled, y, le, knn_imputer, scaler_prep, feature_cols
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Détection automatique de la colonne target
    target_col = None
    for candidate in ['rsrp_category', 'rsrp_category_label', 'rsrp_cat', 'category']:
        if candidate in df.columns:
            target_col = candidate
            break
    if target_col is None:
        raise ValueError(f'Colonne target introuvable. Colonnes : {df.columns.tolist()}')

    # ── Features
    feature_cols = _get_feature_cols(df)
    cols_to_scale = [c for c in feature_cols if c not in BINARY_COLS]

    # ── Encodage target
    le = LabelEncoder()
    y  = le.fit_transform(df[target_col])
    print(f'Target : {target_col} — {len(le.classes_)} classes : {list(le.classes_)}')

    # ── KNN Imputer
    X = df[feature_cols].copy()
    knn_imputer = KNNImputer(n_neighbors=5, weights='distance')
    X_imputed   = pd.DataFrame(knn_imputer.fit_transform(X), columns=feature_cols)
    print(f'KNN Imputer : NaN avant={X.isnull().sum().sum()} | après={X_imputed.isnull().sum().sum()}')

    # ── RobustScaler (IQR 10–90)
    scaler_prep = RobustScaler(quantile_range=(10, 90))
    X_scaled = X_imputed.copy()
    X_scaled[cols_to_scale] = scaler_prep.fit_transform(X_imputed[cols_to_scale])
    print(f'RobustScaler appliqué sur {len(cols_to_scale)} colonnes')

    if save:
        X_scaled.to_csv(f'{OUTPUT_DIR}/X_prepared.csv', index=False)
        y_df = pd.DataFrame({'rsrp_category_encoded': y,
                              'rsrp_category_label': df[target_col].values})
        y_df.to_csv(f'{OUTPUT_DIR}/y_target.csv', index=False)
        full = X_scaled.copy()
        full['rsrp_category_encoded'] = y
        full['rsrp_category_label']   = df[target_col].values
        full.to_csv(f'{OUTPUT_DIR}/qos_prepared_full.csv', index=False)
        joblib.dump(knn_imputer, f'{OUTPUT_DIR}/knn_imputer.pkl')
        joblib.dump(scaler_prep, f'{OUTPUT_DIR}/robust_scaler.pkl')
        joblib.dump(le,          f'{OUTPUT_DIR}/label_encoder.pkl')
        print('Artefacts sauvegardés dans outputs/')

    return X_scaled, y, le, knn_imputer, scaler_prep, feature_cols


def prepare_for_autoencoder(df: pd.DataFrame, seed: int = SEED):
    """
    Préparation spécifique DSO1 — Split stratifié AVANT scaling (Section 2.9).
    Anti-leakage : scaler fitté sur train uniquement.
    Retourne tenseurs PyTorch + métadonnées.
    """
    feature_cols = _get_feature_cols(df, exclude_redundant=True)
    target_map   = {'Bon': 0, 'Faible': 1, 'Mauvais': 2, 'Très mauvais': 3}
    X_raw        = df[feature_cols].copy().fillna(df[feature_cols].median())
    y_labels     = df[TARGET_COL].map(target_map).fillna(0).astype(int).values

    X_train_raw, X_test_raw, y_train_raw, y_test = train_test_split(
        X_raw.values, y_labels,
        test_size=0.2, random_state=seed, stratify=y_labels,
    )

    scaler     = RobustScaler()
    X_train_np = scaler.fit_transform(X_train_raw)
    X_test_np  = scaler.transform(X_test_raw)

    X_train_ae = torch.FloatTensor(X_train_np)
    X_test_ae  = torch.FloatTensor(X_test_np)

    print(f'Préparation DSO1 : train={len(X_train_np)} | test={len(X_test_np)} | features={X_train_np.shape[1]}')
    return {
        'X_train_ae':   X_train_ae,
        'X_test_ae':    X_test_ae,
        'X_train_np':   X_train_np,
        'X_test_np':    X_test_np,
        'y_train_raw':  y_train_raw,
        'y_test':       y_test,
        'scaler':       scaler,
        'feature_cols': feature_cols,
        'input_dim':    X_train_np.shape[1],
    }
