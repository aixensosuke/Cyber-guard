import numpy as np
from typing import List, Dict, Any, Tuple
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from src.config import Config
from src.utils.logging import get_logger

logger = get_logger("detector")

class CyberGuardDetector:
    def __init__(self, contamination: float = Config.CONTAMINATION_RATE):
        self.contamination = contamination
        self.iforest = IForest(contamination=self.contamination, random_state=42, n_jobs=-1)
        self.lof = None  # LOF will be initialized during fit based on sample size
        self.fitted = False

    def fit(self, X: np.ndarray):
        num_samples = X.shape[0]
        if num_samples < 5:
            logger.warn("Extremely small dataset size for training. Anomaly detection might be unstable.", count=num_samples)
            
        # Dynamically set n_neighbors for LOF (must be less than number of samples)
        n_neighbors = min(20, max(2, num_samples - 1))
        self.lof = LOF(contamination=self.contamination, n_neighbors=n_neighbors, n_jobs=-1)

        logger.info("Fitting Anomaly Detection Models...", samples=num_samples, contamination=self.contamination)
        
        try:
            self.iforest.fit(X)
            self.lof.fit(X)
            self.fitted = True
            logger.info("Anomaly detection models fitted successfully.")
        except Exception as e:
            logger.error("Error occurred while fitting PyOD models", error=str(e))
            self.fitted = False
            
        return self

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Runs inference on features X.
        Returns:
            - anomaly_labels: binary array (1 = anomaly, 0 = normal)
            - anomaly_scores: composite anomaly score normalized to [0, 1]
        """
        if not self.fitted:
            logger.error("Attempted to predict using unfitted models.")
            # Default to all normal if not fitted
            return np.zeros(X.shape[0]), np.zeros(X.shape[0])

        try:
            # Get raw anomaly scores (higher is more anomalous)
            iforest_scores = self.iforest.decision_function(X)
            lof_scores = self.lof.decision_function(X)

            # PyOD normalization of scores to [0, 1] range using training baselines
            # decision_function outputs values where offset_ is the threshold
            # We will scale scores by subtracting thresholds and normalizing
            iforest_norm = (iforest_scores - self.iforest.threshold_) / (np.max(self.iforest.decision_scores_) - self.iforest.threshold_ + 1e-6)
            lof_norm = (lof_scores - self.lof.threshold_) / (np.max(self.lof.decision_scores_) - self.lof.threshold_ + 1e-6)
            
            # Clip to [0, 1]
            iforest_norm = np.clip(iforest_norm, 0, 1)
            lof_norm = np.clip(lof_norm, 0, 1)

            # Combined Score: Average of the normalized scores
            composite_scores = (iforest_norm + lof_norm) / 2.0
            
            # Binary prediction: active if score > threshold (which is 0 after shifting)
            # Or we can check if either model flagged it as outlier (label == 1)
            iforest_labels = self.iforest.predict(X)
            lof_labels = self.lof.predict(X)
            
            # Flag if either model strongly classifies it as an outlier
            composite_labels = np.bitwise_or(iforest_labels, lof_labels)

            return composite_labels, composite_scores

        except Exception as e:
            logger.error("Prediction failed in detection ensemble", error=str(e))
            return np.zeros(X.shape[0]), np.zeros(X.shape[0])
