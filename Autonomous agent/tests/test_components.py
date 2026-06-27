import pytest
import numpy as np
from datetime import datetime
from src.ingestion.schema import CanonicalEvent
from src.ingestion.normalizer import LogNormalizer
from src.detection.preprocessor import LogFeatureExtractor
from src.detection.detector import CyberGuardDetector
from src.ueba.analytics import UEBAEngine
from src.correlation.graph import ThreatCorrelator, map_mitre_attack_stage
from src.correlation.CFR import CFRCalculator

def test_normalization_and_deduplication():
    normalizer = LogNormalizer(deduplication_window_seconds=2)
    raw_log = {
        "timestamp": "2026-05-20T21:22:29Z",
        "log_source": "ssh",
        "username": "admin",
        "source_ip": "192.168.1.18",
        "action_type": "login_attempt",
        "status": "failure"
    }

    # First normalization should succeed
    event1 = normalizer.normalize(raw_log)
    assert event1 is not None
    assert event1.username == "admin"
    assert event1.source_ip == "192.168.1.18"
    assert event1.severity == "INFO" # Default mapping

    # Second immediate normalization of the exact same event should be deduplicated
    event2 = normalizer.normalize(raw_log)
    assert event2 is None


def test_feature_preprocessor():
    extractor = LogFeatureExtractor()
    events = [
        {"severity": "INFO", "bytes_transferred": 100, "status": "success", "username": "user1", "log_source": "ssh", "action_type": "login_attempt"},
        {"severity": "WARNING", "bytes_transferred": 500, "status": "failure", "username": "admin", "log_source": "windows_event", "action_type": "process_spawn"},
        {"severity": "CRITICAL", "bytes_transferred": 10000, "status": "failure", "username": "root", "log_source": "proxy", "action_type": "network_connect"}
    ]
    
    extractor.fit(events)
    X = extractor.transform(events)
    
    assert X.shape[0] == 3
    # Check that scaled values are floating point arrays
    assert isinstance(X, np.ndarray)


def test_detector_ensemble():
    extractor = LogFeatureExtractor()
    detector = CyberGuardDetector(contamination=0.1)

    # Generate normal baseline features
    baseline_events = [
        {"severity": "INFO", "bytes_transferred": 100, "status": "success", "username": "user1", "log_source": "ssh", "action_type": "login_attempt"}
        for _ in range(20)
    ]
    extractor.fit(baseline_events)
    X_baseline = extractor.transform(baseline_events)

    detector.fit(X_baseline)
    assert detector.fitted is True

    # Test prediction on normal vs anomalous
    test_events = [
        {"severity": "INFO", "bytes_transferred": 100, "status": "success", "username": "user1", "log_source": "ssh", "action_type": "login_attempt"},
        {"severity": "CRITICAL", "bytes_transferred": 9999999, "status": "failure", "username": "root", "log_source": "proxy", "action_type": "network_connect"}
    ]
    X_test = extractor.transform(test_events)
    labels, scores = detector.predict(X_test)
    
    assert len(labels) == 2
    assert len(scores) == 2
    # Anomalous (index 1) should have a higher score than normal (index 0)
    assert scores[1] >= scores[0]


def test_ueba_deviation():
    ueba = UEBAEngine()
    baseline_events = [
        {"timestamp": "2026-05-20T10:00:00Z", "username": "jdoe", "source_ip": "192.168.1.5", "bytes_transferred": 10.0, "event_id": "1"},
        {"timestamp": "2026-05-20T11:00:00Z", "username": "jdoe", "source_ip": "192.168.1.5", "bytes_transferred": 15.0, "event_id": "2"},
        {"timestamp": "2026-05-20T12:00:00Z", "username": "jdoe", "source_ip": "192.168.1.5", "bytes_transferred": 20.0, "event_id": "3"}
    ]
    
    ueba.build_baselines(baseline_events)
    assert "jdoe" in ueba.baselines
    
    # 1. Normal event should return low/zero deviation
    normal_event = {"username": "jdoe", "source_ip": "192.168.1.5", "bytes_transferred": 15.0}
    normal_dev = ueba.evaluate_event(normal_event)
    assert normal_dev < 0.5
    
    # 2. Large data transfer should trigger high Z-score deviation
    huge_event = {"username": "jdoe", "source_ip": "192.168.1.5", "bytes_transferred": 1000000.0}
    huge_dev = ueba.evaluate_event(huge_event)
    assert huge_dev > 0.8


def test_threat_correlator_and_cfr():
    correlator = ThreatCorrelator()
    cfr_calc = CFRCalculator()

    # Create anomalous events
    events = [
        {"event_id": "EV-1", "timestamp": "2026-05-20T21:22:00Z", "username": "admin", "source_ip": "192.168.99.180", "log_source": "ssh", "action_type": "login_attempt", "status": "failure"},
        {"event_id": "EV-2", "timestamp": "2026-05-20T21:23:00Z", "username": "admin", "source_ip": "192.168.99.180", "destination_ip": "10.0.0.15", "log_source": "ssh", "action_type": "login_attempt", "status": "success"},
        {"event_id": "EV-3", "timestamp": "2026-05-20T21:24:00Z", "username": "admin", "source_ip": "10.0.0.15", "destination_ip": "203.0.113.88", "bytes_transferred": 50000000.0, "log_source": "proxy", "action_type": "network_connect", "status": "success"}
    ]

    # Collapse anomalous alerts
    incidents = correlator.collapse_into_incidents(events)
    assert len(incidents) == 1
    
    incident = incidents[0]
    assert "admin" in incident["entities"]
    assert "192.168.99.180" in incident["entities"]
    assert incident["correlation_breadth"] >= 3
    assert incident["highest_mitre_stage"] == "Exfiltration"

    # Evaluate CFR score
    event_scores = {
        "EV-1": (0.6, 0.4),
        "EV-2": (0.7, 0.5),
        "EV-3": (0.9, 0.9)
    }
    
    score = cfr_calc.calculate_score(incident, event_scores)
    assert score > 5.0 # Highly correlated high stages should score high
