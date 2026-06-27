import os
from pathlib import Path
from typing import Dict, Any

class Config:
    # Base paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    PLAYBOOK_DIR: Path = BASE_DIR / "playbooks"

    # Databases
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    SQLITE_PATH: Path = BASE_DIR / "cyberguard.db"

    # LLM Settings
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")

    # Detection Thresholds
    CONTAMINATION_RATE: float = 0.05  # PyOD contamination percentage (expected outliers)
    UEBA_Z_SCORE_THRESHOLD: float = 3.0  # Threshold for Z-score UEBA anomaly

    # CFR Weights (Composite Fidelity Ranking)
    # CFR = w_anomaly * AnomalyScore + w_ueba * UEBADeviation + w_correlation * CorrelationBreadth + w_attack * AttackStageWeight + w_entity * EntityTier
    CFR_WEIGHTS: Dict[str, float] = {
        "anomaly": 0.25,
        "ueba": 0.25,
        "correlation": 0.20,
        "attack_stage": 0.15,
        "entity_tier": 0.15
    }

    # Entity Tiers (criticality weight)
    ENTITY_TIERS: Dict[str, int] = {
        "domain_controller": 3,
        "database_server": 3,
        "web_proxy": 2,
        "internal_workstation": 1,
        "administrator": 3,
        "user_account": 1
    }

    # MITRE ATT&CK Stages Weights (high stage = higher threat progress)
    ATTACK_STAGE_WEIGHTS: Dict[str, float] = {
        "Reconnaissance": 0.1,
        "Initial Access": 0.3,
        "Execution": 0.5,
        "Persistence": 0.6,
        "Privilege Escalation": 0.7,
        "Credential Access": 0.8,
        "Discovery": 0.4,
        "Lateral Movement": 0.8,
        "Collection": 0.6,
        "Command and Control": 0.9,
        "Exfiltration": 1.0,
        "Impact": 0.9,
        "Unknown": 0.0
    }

# Create required directories
Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
Config.PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
