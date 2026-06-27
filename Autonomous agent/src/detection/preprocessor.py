import numpy as np
import pandas as pd
from typing import List, Dict, Any
from sklearn.preprocessing import StandardScaler
from src.ingestion.schema import CanonicalEvent
from src.utils.logging import get_logger

logger = get_logger("preprocessor")

class LogFeatureExtractor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.fitted = False
        
        # Fixed list of categories to ensure consistent output dimensions
        self.log_sources = ["windows_event", "ssh", "proxy", "firewall", "unknown"]
        self.action_types = ["login_attempt", "process_spawn", "file_modification", "network_connect", "unknown"]
        
    def _extract_event_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Helper to convert a single event dictionary into a flat numerical/categorical dictionary
        features = {}
        
        # Severity mapping
        severity = str(event.get("severity", "INFO")).upper()
        severity_map = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}
        features["severity_num"] = severity_map.get(severity, 0)
        
        # Numerical: Log scaled bytes
        bytes_val = float(event.get("bytes_transferred") or 0.0)
        features["log_bytes"] = np.log1p(bytes_val)
        
        # Binary: Failure status
        status = str(event.get("status") or "").lower()
        features["is_failure"] = 1.0 if status in ["failure", "failed", "denied", "blocked"] else 0.0
        
        # Binary: Administrative/Root user
        user = str(event.get("username") or "").lower()
        features["is_admin"] = 1.0 if any(admin in user for admin in ["admin", "root", "system"]) else 0.0
        
        # One-hot: log source
        source = event.get("log_source", "unknown")
        for src in self.log_sources:
            features[f"src_{src}"] = 1.0 if source == src else 0.0
            
        # One-hot: action type
        action = event.get("action_type", "unknown")
        for act in self.action_types:
            features[f"act_{act}"] = 1.0 if action == act else 0.0
            
        # Destination port groups
        port = event.get("destination_port")
        features["port_is_privileged"] = 1.0 if port is not None and port < 1024 else 0.0
        features["port_is_ssh"] = 1.0 if port == 22 else 0.0
        features["port_is_web"] = 1.0 if port in [80, 443, 8080] else 0.0
        features["port_is_database"] = 1.0 if port in [1433, 3306, 5432, 1521] else 0.0
        
        return features

    def fit(self, events: List[Dict[str, Any]]):
        if not events:
            logger.warn("Cannot fit feature extractor on empty list")
            return self
            
        feature_dicts = [self._extract_event_features(e) for e in events]
        df = pd.DataFrame(feature_dicts)
        
        # Fit scaler on numerical dimensions
        self.scaler.fit(df.values)
        self.fitted = True
        logger.info("Feature extractor fitted successfully", features_count=df.shape[1], training_samples=df.shape[0])
        return self

    def transform(self, events: List[Dict[str, Any]]) -> np.ndarray:
        if not self.fitted:
            raise ValueError("Feature extractor is not yet fitted. Run fit() first.")
        if not events:
            return np.empty((0, self.scaler.n_features_in_))
            
        feature_dicts = [self._extract_event_features(e) for e in events]
        df = pd.DataFrame(feature_dicts)
        
        # Ensure all columns match fit schema (just in case)
        expected_cols = df.columns
        # Scale
        scaled_data = self.scaler.transform(df.values)
        return scaled_data

    def fit_transform(self, events: List[Dict[str, Any]]) -> np.ndarray:
        return self.fit(events).transform(events)
