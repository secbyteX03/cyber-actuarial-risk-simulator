"""
Module for anomaly detection using machine learning.
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import numpy as np

MODEL_FILENAME = 'isolation_forest_model.joblib'


def train_isolation_forest(data: pd.DataFrame, save_path=MODEL_FILENAME):
    """
    Train an Isolation Forest model on the provided DataFrame.
    Saves the model to disk and returns the trained model.
    """
    # Use only numeric columns
    X = data.select_dtypes(include=[np.number])
    model = IsolationForest(random_state=42, contamination='auto')
    model.fit(X)
    joblib.dump(model, save_path)
    return model


def detect_anomalies(model, new_data: pd.DataFrame):
    """
    Use the trained model to detect anomalies in new_data.
    Returns a risk_score (0-1) for each row (1=most anomalous).
    """
    X = new_data.select_dtypes(include=[np.number])
    # IsolationForest: lower scores = more anomalous
    anomaly_scores = -model.decision_function(X)  # invert so higher = more anomalous
    # Normalize to 0-1
    risk_scores = (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min() + 1e-9)
    return risk_scores


def alert_if_high_risk(risk_scores, threshold=0.8):
    """
    Returns indices of rows where risk_score > threshold.
    """
    return np.where(risk_scores > threshold)[0]


def save_model(model, path=MODEL_FILENAME):
    """
    Save the trained model to disk.
    """
    joblib.dump(model, path)


def load_model(path=MODEL_FILENAME):
    """
    Load a trained model from disk.
    """
    return joblib.load(path) 